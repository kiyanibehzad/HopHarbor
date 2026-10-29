#!/usr/bin/env python3
"""Opt-in real Windows WebView2 recovery fixture; no production data or SSH.

Run with a private x64 payload whose Desktop was compiled with PANEL_AUTH_TESTS.
All endpoints below belong only to this disposable loopback test server. The
normal Manager/Handler handles bootstrap and authenticated state unchanged.
"""
import argparse
import hashlib
import hmac
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app-root', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'win32':
        parser.error('A real Windows desktop is required.')
    app = args.app_root.resolve()
    if Path(sys.executable).resolve() != (app / 'runtime/python.exe').resolve():
        parser.error('Use the fixture payload runtime/python.exe.')
    sys.path.insert(0, str(app))
    native = importlib.import_module('windows_platform')
    pm = importlib.import_module('manager')
    # Do not inherit an unprotected tempfile directory: let the native helper
    # create this fresh path with its current-user ACL.
    data = Path(tempfile.gettempdir()) / ('HopHarbor-Smoke-auth-' + __import__('uuid').uuid4().hex)
    native.ensure_private_directory(data)
    state = {'mode': 'normal', 'mutations': 0, 'logins': 0, 'rejected_bootstraps': 0}
    manager = server = None
    report = {'ok': False, 'real_windows': True, 'real_manager_handler': True,
              'production_data_used': False, 'ssh_started': False}

    class Handler(pm.Handler):
        def do_GET(self):
            if not self.trusted_host():
                return super().do_GET()
            if self.path == '/__fixture/frame':
                body = b'''<script>window.chrome.webview.postMessage({action:'ready'});window.chrome.webview.postMessage({action:'reauthenticate',reason:'retry'});parent.document.documentElement.dataset.fixtureFrameDone='yes';</script>'''
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers(); self.wfile.write(body)
                return
            if self.path == '/api/state' and state['mode'] in ('state401', 'state403'):
                return self.reply(int(state['mode'][5:]), {'error': 'Synthetic rejection.'})
            return super().do_GET()

        def do_POST(self):
            if self.path.startswith('/__fixture/'):
                if not self.trusted_host() or not hmac.compare_digest(self.headers.get('X-HopHarbor-Test', ''), self.manager.token):
                    return self.reply(403, {'error': 'Fixture control rejected.'})
                self.read_json()
                command = self.path.split('/')[-1]
                if command == 'expire-session':
                    for cookie in list(self.manager.cookies):
                        self.manager.cookies[cookie] = time.monotonic() - 1
                elif command in ('normal', 'state401', 'state403', 'bootstrap401'):
                    state['mode'] = command
                elif command != 'stats':
                    return self.reply(400, {'error': 'Unknown fixture command.'})
                return self.reply(200, state)
            if self.path == '/api/__fixture-mutation':
                self.read_json()
                state['mutations'] += 1
                return self.reply(401, {'error': 'Synthetic mutation rejection.'})
            if self.path == '/api/session':
                if state['mode'] == 'bootstrap401':
                    self.read_json(); state['rejected_bootstraps'] += 1
                    return self.reply(401, {'error': 'Synthetic bootstrap rejection.'})
                state['logins'] += 1
            return super().do_POST()

    try:
        server = pm.http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.daemon_threads = True
        manager = pm.Manager(data, app, server.server_address[1])
        server.manager = manager
        initial_control = (data / 'control.json').read_bytes()
        worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .1}, daemon=True)
        worker.start()
        # Validate app ACLs before launching its actual Desktop and native helper.
        native.validate_private_directory(app)
        for path in app.rglob('*'):
            if path.is_file(): native.validate_private_file(path)
        result = subprocess.run([str(app/'ui/HopHarbor.exe'), '--smoke-test', '--data-dir', str(data)], timeout=180, capture_output=True)
        native_result = data / 'panel-auth-smoke-results.json'
        if not native_result.exists():
            raise RuntimeError('Native panel fixture did not return its report.')
        report.update(json.loads(native_result.read_text(encoding='utf-8')))
        report['exit_code'] = result.returncode
        report['control_unchanged'] = initial_control == (data/'control.json').read_bytes()
        report['stats'] = state
        report['version'] = pm.VERSION; report['build'] = pm.BUILD
        report['architecture'] = __import__('platform').machine()
        # Never write synthetic tokens to reports, even on failure.
        for path in data.rglob('*'):
            if path.is_file() and path.suffix in ('.log', '.txt') and manager.token.encode() in path.read_bytes():
                raise RuntimeError('Synthetic access token leaked to a text log.')
        report['ok'] = bool(report.get('ok') and result.returncode == 0 and report['control_unchanged'])
    except Exception as error:
        report['ok'] = False
        report['runner_error'] = type(error).__name__
    finally:
        if server:
            server.shutdown(); server.server_close()
        if manager:
            manager.shutdown()
        # WebView2 child exits can lag Desktop disposal. Delete only this random
        # fixture, and report a cleanup failure rather than ignoring it.
        for attempt in range(20):
            try:
                shutil.rmtree(data); report['cleanup_ok'] = True; break
            except OSError:
                time.sleep(.3)
        else:
            report['cleanup_ok'] = False; report['ok'] = False
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
