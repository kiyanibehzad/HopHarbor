#!/usr/bin/env python3
"""Opt-in actual macOS panel authentication recovery checks, with no real SSH.

Builds a unique test-only AppKit bundle in native TEMP, runs an ephemeral-store
WKWebView against a generated loopback service, then removes only this fixture.
This is not discovered by unittest and never opens the installed HopHarbor app.
"""
import argparse
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import plistlib
import secrets
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[1]


class Fixture:
    def __init__(self, data):
        self.data = data
        self.token = secrets.token_urlsafe(32)
        self.sessions = set()
        self.always_unauthorized = False
        self.logins = 0
        self.rejected_bootstraps = 0
        self.frame_requests = {}
        self.lock = threading.RLock()
        self.port = None

    def write_control(self, valid=True):
        temporary = self.data / ('control-' + uuid.uuid4().hex + '.json')
        temporary.write_text(json.dumps({'port': self.port,
            'token': self.token if valid else 'wrong-synthetic-' + uuid.uuid4().hex}))
        temporary.chmod(0o600)
        os.replace(temporary, self.data / 'control.json')

    def stats(self):
        return {'logins': self.logins, 'rejected_bootstraps': self.rejected_bootstraps,
                'frame_requests': dict(self.frame_requests)}


class Handler(BaseHTTPRequestHandler):
    fixture = None

    def log_message(self, *args):
        pass

    def reply(self, status, body, content_type='application/json; charset=utf-8', headers=None,
              fixture_frame=False):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'"
        # Permit framing only for attack fixtures, so the native navigation
        # decision, rather than frame-ancestors, must stop their scripts.
        if not fixture_frame:
            policy += "; frame-ancestors 'none'"
        self.send_header('Content-Security-Policy', policy)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        f = self.fixture
        if self.headers.get('Host') != '127.0.0.1:' + str(f.port):
            return self.reply(403, {'error': 'Host rejected by synthetic fixture.'})
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if query.get('fixture') == ['frame']:
            case = query.get('case', [''])[0]
            scripts = {
                'direct': 'window.webkit.messageHandlers.hopharborPanel.postMessage',
                'parent-native': 'parent.webkit.messageHandlers.hopharborPanel.postMessage',
                'parent-wrapper': 'parent.postNativePanelMessage',
                'popup': 'window.webkit.messageHandlers.hopharborPanel.postMessage',
            }
            if case not in scripts:
                return self.reply(404, {'error': 'Unknown synthetic frame case.'})
            with f.lock:
                f.frame_requests[case] = f.frame_requests.get(case, 0) + 1
            child = ('<script>parent.document.documentElement.dataset.fixtureFrameAttempted="true";'
                     + scripts[case] + '({action:"reauthenticate",reason:"authentication"});'
                     'parent.document.documentElement.dataset.fixtureFrameDone="true";</script>')
            return self.reply(200, child.encode(), 'text/html; charset=utf-8', fixture_frame=True)
        if self.path.split('?', 1)[0] == '/api/state':
            with f.lock:
                cookie = SimpleCookie(self.headers.get('Cookie', ''))
                session = cookie.get('pm_session')
                valid = not f.always_unauthorized and session is not None and session.value in f.sessions
            if not valid:
                return self.reply(401, {'error': 'Panel authentication is required. Reopen the app.'})
            return self.reply(200, {'servers': [], 'tunnels': [], 'logs': [],
                'service': {'platform': 'darwin', 'version': 'synthetic', 'build': 0}, 'migration': {}})
        path = self.path.split('?', 1)[0]
        if path in ('/', '/index.html', '/app.js'):
            name = 'app.js' if path == '/app.js' else 'index.html'
            kind = 'application/javascript; charset=utf-8' if name.endswith('.js') else 'text/html; charset=utf-8'
            return self.reply(200, (ROOT / 'web' / name).read_bytes(), kind)
        return self.reply(404, {'error': 'Fixture route unavailable.'})

    def do_POST(self):
        f = self.fixture
        if self.headers.get('Host') != '127.0.0.1:' + str(f.port):
            return self.reply(403, {'error': 'Host rejected by synthetic fixture.'})
        length = int(self.headers.get('Content-Length', '-1'))
        if not 0 <= length <= 1024 or self.headers.get('Content-Type') != 'application/json':
            return self.reply(400, {'error': 'Invalid fixture input.'})
        try:
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError()
        except (ValueError, json.JSONDecodeError):
            return self.reply(400, {'error': 'Invalid fixture input.'})
        with f.lock:
            if self.path == '/api/session':
                if (self.headers.get('Origin') != 'http://127.0.0.1:' + str(f.port)
                        or self.headers.get('X-Requested-With') != 'ProxyManager'):
                    return self.reply(403, {'error': 'Origin rejected by synthetic fixture.'})
                if body.get('token') != f.token:
                    f.rejected_bootstraps += 1
                    return self.reply(401, {'error': 'Invalid panel access token.'})
                session = secrets.token_urlsafe(24)
                f.sessions.add(session)
                f.logins += 1
                return self.reply(200, {'ok': True}, headers={'Set-Cookie':
                    'pm_session=' + session + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200'})
            if self.path == '/fixture/invalidate':
                f.sessions.clear()
            elif self.path == '/fixture/control-token':
                f.write_control(valid=body.get('valid') is True)
            elif self.path == '/fixture/state-mode':
                f.always_unauthorized = body.get('always_unauthorized') is True
            elif self.path != '/fixture/stats':
                return self.reply(404, {'error': 'Fixture route unavailable.'})
            return self.reply(200, f.stats())


def stop_owned_test_process(process):
    """Reap only the Popen created by this test, including on interruption."""
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True, type=Path,
                        help='Fresh absolute report path outside tracked source.')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('This opt-in test requires macOS and Apple command-line tools.')
    report = args.report.expanduser()
    if not report.is_absolute() or report.exists() or not report.parent.is_dir():
        parser.error('Choose a fresh absolute report in an existing private folder.')
    try:
        report.resolve().relative_to(ROOT)
    except ValueError:
        pass
    else:
        parser.error('The private native report must remain outside tracked source.')
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='hopharbor-mac-panel-test-') as scratch:
        scratch = Path(scratch)
        data = scratch / 'data'
        data.mkdir()
        fixture = Fixture(data)
        Handler.fixture = fixture
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.daemon_threads = True
        fixture.port = server.server_address[1]
        fixture.write_control()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        process = None
        try:
            app = scratch / 'HopHarbor Panel Test.app'
            contents = app / 'Contents'
            executable = contents / 'MacOS' / 'HopHarborPanelTest'
            executable.parent.mkdir(parents=True)
            info = {'CFBundleExecutable': executable.name,
                'CFBundleIdentifier': 'local.hopharbor.panel-auth-test.' + uuid.uuid4().hex,
                'CFBundleName': 'HopHarbor Panel Test', 'CFBundlePackageType': 'APPL',
                'CFBundleShortVersionString': '0.0.0', 'CFBundleVersion': '0',
                'LSMinimumSystemVersion': '13.0', 'NSHighResolutionCapable': True,
                'HopHarborDataDirectory': str(data),
                'NSAppTransportSecurity': {'NSAllowsLocalNetworking': True}}
            (contents / 'Info.plist').write_bytes(plistlib.dumps(info))
            subprocess.run(['xcrun', 'swiftc', '-swift-version', '5', '-parse-as-library',
                '-D', 'HOPHARBOR_PANEL_TESTING', '-O', '-framework', 'AppKit',
                '-framework', 'WebKit', str(ROOT / 'packaging/PanelRecovery.swift'),
                str(ROOT / 'packaging/main.swift'), str(ROOT / 'tests/macos_panel_auth_smoke.swift'),
                '-o', str(executable)], check=True, timeout=120)
            subprocess.run(['codesign', '--force', '--sign', '-', '--identifier',
                            info['CFBundleIdentifier'], str(app)], check=True,
                           capture_output=True, timeout=30)
            environment = dict(os.environ, HOPHARBOR_TEST_FIXTURE='http://127.0.0.1:' + str(fixture.port),
                               HOPHARBOR_TEST_REPORT=str(report), HOPHARBOR_TEST_DATA=str(data))
            process = subprocess.Popen([str(executable)], env=environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                stdout, stderr = process.communicate(timeout=100)
            except subprocess.TimeoutExpired:
                raise RuntimeError('The isolated panel test exceeded its deadline.')
            if not report.is_file():
                raise RuntimeError('The isolated panel test did not return a report: '
                                   + stderr.decode('utf-8', 'replace')[-2000:])
            result = json.loads(report.read_text())
            if process.returncode or not result.get('ok'):
                raise RuntimeError('The isolated panel test failed; inspect its private report.')
        finally:
            try:
                stop_owned_test_process(process)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
    result['fixture_cleanup'] = 'owned loopback server and temporary test bundle removed'
    report.write_text(json.dumps(result, indent=2) + '\n')
    print(stdout.decode('utf-8', 'replace'))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
