#!/usr/bin/python3
"""Opt-in real GTK/WebKitGTK recovery checks; synthetic loopback data only.

Run: dbus-run-session -- xvfb-run -a python3 tests/test_ubuntu_panel_auth_native.py
Not a unittest test class: importing this module does not start GTK or a service.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if sys.platform != 'linux':
        raise SystemExit('Requires a disposable Ubuntu GTK/WebKitGTK environment.')
    import gi
    gi.require_version('Gtk', '3.0')
    gi.require_version('WebKit2', '4.1')
    from gi.repository import GLib, WebKit2
    import linux_desktop as panel
    import manager as core

    class Checks(list):
        def append(self, value):
            super().append(value)
            print("PASS: " + value, flush=True)

    checks = Checks()
    context = GLib.MainContext.default()

    def spin(seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            while context.pending():
                context.iteration(False)
            time.sleep(.01)

    def wait(predicate, label, timeout=25):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            while context.pending():
                context.iteration(False)
            value = predicate()
            if value:
                return value
            time.sleep(.02)
        raise AssertionError('Timed out: ' + label)

    def evaluate(view, expression):
        outcome = []

        def done(browser, result, _data):
            try:
                value = browser.run_javascript_finish(result).get_js_value()
                outcome.append((True, json.loads(value.to_string())))
            except Exception as error:
                outcome.append((False, type(error).__name__))

        view.run_javascript('JSON.stringify((' + expression + '))', None, done, None)
        wait(lambda: outcome, 'JavaScript completion')
        assert outcome[0][0], outcome[0][1]
        return outcome[0][1]

    def online():
        view = app.browser
        if view is None or view.is_loading():
            return False
        try:
            return evaluate(view, 'document.getElementById("serviceLabel")?.textContent') == 'Local service online'
        except AssertionError:
            return False

    def recovered(old):
        wait(lambda: app.browser is not old and online(), 'fresh authenticated WebView')
        wait(lambda: app.load_timeout_source is None and app.recovery_source is None, 'ready cleanup')

    class FixtureHandler(core.Handler):
        def do_GET(self):
            if self.path == '/synthetic-frame':
                # Deliberately no X-Frame-Options or CSP in this test-only
                # response: rejection must come from the native shell.
                self.server.frame_requests += 1
                body = ('<script>' + self.server.frame_payload + '</script>').encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == '/api/state' and self.server.mode in (401, 403):
                return self.reply(self.server.mode, {'error': 'Synthetic access rejection.'})
            return super().do_GET()

        def do_POST(self):
            if self.path == '/api/session':
                self.server.sign_ins.append(time.monotonic())
                if self.server.mode == 'bootstrap':
                    self.read_json()
                    return self.reply(401, {'error': 'Synthetic bootstrap rejection.'})
            if self.path == '/api/synthetic-mutation':
                self.read_json()
                self.server.mutations += 1
                return self.reply(401, {'error': 'Synthetic expired mutation.'})
            return super().do_POST()

    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='hopharbor-native-recovery-') as scratch:
        data = Path(scratch) / 'private'
        data.mkdir(mode=0o700)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), FixtureHandler)
        server.daemon_threads = True
        server.mode = None
        server.sign_ins = []
        server.mutations = 0
        server.frame_requests = 0
        server.frame_payload = ""
        server.manager = core.Manager(data, ROOT, server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        control_hash = hashlib.sha256((data / 'control.json').read_bytes()).hexdigest()
        app = panel.desktop_application(data, ROOT)
        try:
            assert app.register(None)
            app.activate()
            wait(online, 'initial authenticated page')
            wait(lambda: app.load_timeout_source is None, 'initial ready')
            assert evaluate(app.browser, 'location.hash') == ''
            assert evaluate(app.browser, 'Object.keys(localStorage).some(k=>/token|cookie|session/i.test(k))') is False
            assert evaluate(app.browser, '!!window.webkit?.messageHandlers?.hopharborPanelReceiver') is False
            checks.append('actual panel bootstrap clears fragment; isolated native receiver unavailable to page')

            old, count = app.browser, len(server.sign_ins)
            app.recovery_budget.last_scheduled = time.monotonic()
            # Use the actual helper from the unchanged shared app.js. Each
            # attempted child payload marks its first executed instruction.
            assert evaluate(old, "typeof postNativePanelMessage==='function'")
            assert app.browser.get_default_content_security_policy() == panel.PANEL_CONTENT_POLICY
            frame_calls = {
                'direct': "window.webkit.messageHandlers.hopharborPanel.postMessage({action:'reauthenticate',reason:'retry'})",
                'parent_bridge': "parent.webkit.messageHandlers.hopharborPanel.postMessage({action:'reauthenticate',reason:'retry'})",
                'parent_helper': "parent.postNativePanelMessage({action:'reauthenticate',reason:'retry'})",
            }
            for vector, call in frame_calls.items():
                payload = "parent.testFrameRuns.push(%s);%s;" % (json.dumps(vector), call)
                for method in ('append', 'write', 'srcdoc', 'url'):
                    server.frame_payload = payload
                    before = server.frame_requests
                    expression = """(()=>{
                      window.testFrameRuns=[];
                      const f=document.createElement('iframe');
                      document.body.append(f);
                      const code=%s, mode=%s;
                      const markup='<script>'+code+'</scr'+'ipt>';
                      if(mode==='append'){
                        const s=f.contentWindow.document.createElement('script');
                        s.textContent=code;f.contentWindow.document.body.append(s);
                      }else if(mode==='write'){
                        f.contentWindow.document.open();
                        f.contentWindow.document.write(markup);f.contentWindow.document.close();
                      }else if(mode==='srcdoc'){f.srcdoc=markup;}
                      else{f.src='/synthetic-frame';}
                      window.testFrame=f;return true;
                    })()""" % (json.dumps(payload), json.dumps(method))
                    evaluate(old, expression)
                    spin(.25)
                    assert evaluate(old, 'window.testFrameRuns') == [], (vector, method)
                    assert server.frame_requests == before, (vector, method)
                    assert app.browser is old and app.recovery_source is None and len(server.sign_ins) == count
                    evaluate(old, '(window.testFrame.remove(),true)')
                checks.append('native CSP prevents child scripts/navigation for ' + vector +
                              ' (append/write/srcdoc/HTTP); real shared helper retained')

            # Expire the actual HTTP-only WebKit cookie, retaining control.json.
            cookies = app.web_context().get_cookie_manager()
            found = []

            def got_cookies(cm, result, _data):
                found.extend(cm.get_cookies_finish(result))

            origin = 'http://127.0.0.1:%d/' % server.server_address[1]
            cookies.get_cookies(origin, None, got_cookies, None)
            wait(lambda: found, 'real session cookie')
            cookie = next(c for c in found if c.get_name() == 'pm_session')
            cookie.set_max_age(1)
            added = []
            cookies.add_cookie(cookie, None,
                               lambda cm, result, _: added.append(cm.add_cookie_finish(result)), None)
            wait(lambda: added, 'short cookie expiry installed')
            assert added[0]
            spin(1.3)
            old = app.browser
            evaluate(old, '(refresh(true),true)')
            recovered(old)
            assert hashlib.sha256((data / 'control.json').read_bytes()).hexdigest() == control_hash
            checks.append('real WebKit cookie expiry recovers with unchanged private control file')

            server.manager.cookies.clear()
            old = app.browser
            evaluate(old, '(refresh(true),true)')
            recovered(old)
            checks.append('actual server session invalidation recovers automatically')

            old = app.browser
            evaluate(old, '(request("/api/synthetic-mutation",{method:"POST",body:{synthetic:true}}).catch(()=>{}),true)')
            recovered(old)
            spin(.3)
            assert server.mutations == 1
            checks.append('failed actual POST triggers recovery without replay')

            server.mode = 403
            old, count = app.browser, len(server.sign_ins)
            evaluate(old, '(refresh(true),true)')
            spin(2.3)
            assert app.browser is old and len(server.sign_ins) == count and app.recovery_source is None
            assert evaluate(old, '!document.getElementById("lockedScreen").hidden')
            server.mode = None
            evaluate(old, '(document.getElementById("lockedRetry").click(),true)')
            recovered(old)
            checks.append('403 stays locked without automatic recovery; explicit Retry succeeds')

            server.mode = 401
            old, count = app.browser, len(server.sign_ins)
            evaluate(old, '(refresh(true),true)')
            wait(lambda: len(server.sign_ins) == count + 3 and app.browser is not old,
                 'three automatic attempts')
            spin(2.5)
            assert len(server.sign_ins) == count + 3 and app.recovery_source is None
            timings = server.sign_ins[-3:]
            assert all(b - a >= 1.8 for a, b in zip(timings, timings[1:])), timings
            assert len(app.recovery_budget.attempts) == 3
            server.mode = None
            old = app.browser
            evaluate(old, '(document.getElementById("lockedRetry").click(),true)')
            recovered(old)
            checks.append('persistent 401 stops at three spaced attempts; Retry bypasses exhausted budget')

            # No automatic retry after the initial session exchange is rejected.
            server.mode = 'bootstrap'
            count = len(server.sign_ins)
            app.reload_panel()
            wait(lambda: len(server.sign_ins) == count + 1, 'rejected initial exchange')
            spin(21)
            assert len(server.sign_ins) == count + 1 and app.recovery_source is None
            server.mode = None
            old = app.browser
            evaluate(old, '(document.getElementById("lockedRetry").click(),true)')
            recovered(old)
            checks.append('rejected bootstrap stays bounded beyond load-watchdog deadline; Retry works')

            old, count = app.browser, len(server.sign_ins)
            evaluate(old, '''(()=>{
              const h=window.webkit.messageHandlers.hopharborPanel;
              h.postMessage({action:'ready',token:'synthetic'});
              h.postMessage({action:'reauthenticate',reason:'retry',port:1});
              window.dispatchEvent(new MessageEvent('message',{source:window,
                origin:location.origin,data:{action:'reauthenticate',reason:'retry'}}));
              return true;
            })()''')
            spin(.3)
            assert app.browser is old and len(server.sign_ins) == count and app.recovery_source is None
            checks.append('malformed payload and forged MessageEvent rejected in actual WebKitGTK')

            for uri in ('http://localhost:%d/' % server.server_address[1],
                        'http://127.0.0.1:%d/' % (server.server_address[1] + 1)):
                old.load_uri(uri)
                spin(.2)
                assert app.browser is old and online() and app.recovery_source is None
                assert len(server.sign_ins) == count
            checks.append('actual navigation to foreign hostname or port cannot replace trusted page')

            # Wrong path cannot send either reauthentication or a budget-reset ready.
            evaluate(old, '(history.replaceState(null,"","/api/state"),true)')
            app.recovery_budget.attempts = [time.monotonic()]
            evaluate(old, '(window.webkit.messageHandlers.hopharborPanel.postMessage({action:"ready"}),true)')
            evaluate(old, '(window.webkit.messageHandlers.hopharborPanel.postMessage({action:"reauthenticate",reason:"retry"}),true)')
            spin(.3)
            assert app.browser is old and app.recovery_source is None
            assert len(app.recovery_budget.attempts) == 1
            evaluate(old, '(history.replaceState(null,"","/"),true)')
            checks.append('foreign panel path cannot request recovery or reset budget with ready')

            # Pending recovery is coalesced; stale view/generation/ready cannot affect it.
            generation = app.generation
            app.recovery_budget.last_scheduled = time.monotonic()
            assert app.schedule_recovery(old, generation)
            pending = app.recovery_source
            assert not app.schedule_recovery(old, generation)
            app.load_panel()
            recovered(old)
            current = app.browser
            assert not app.schedule_recovery(old, generation)
            assert not app.current_page(current, generation)
            class StaleResult:
                def get_js_value(self):
                    raise AssertionError('Stale result must be rejected before parsing.')

            app.panel_message(old, generation, StaleResult())
            app.panel_message(current, generation, StaleResult())
            assert app.recovery_source is None
            checks.append('one pending recovery; stale view and document generation rejected')

            current = app.browser
            app.recovery_budget.last_scheduled = time.monotonic()
            assert app.schedule_recovery(current, app.generation)
            evaluate(current, '(window.webkit.messageHandlers.hopharborPanel.postMessage({action:"ready"}),true)')
            wait(lambda: app.recovery_source is None, 'current ready cancels queued work')
            spin(2.1)
            assert app.browser is current
            checks.append('current trusted ready cancels pending recovery')

            app.recovery_budget.last_scheduled = time.monotonic()
            assert app.schedule_recovery(current, app.generation)
            app.close_panel()
            assert app.recovery_source is None
            spin(2.1)
            app.activate()
            recovered(current)
            checks.append('hide cancels pending work; reopen authenticates a fresh page')

            old = app.browser
            old.terminate_web_process()
            recovered(old)
            checks.append('real isolated WebKit renderer termination rebuilds authenticated panel')

            old = app.browser
            app.load_timed_out(old, app.generation)
            recovered(old)
            checks.append('controlled native loading-timeout callback uses bounded fresh-page recovery')

            assert server.manager.config['servers'] == [] and server.manager.config['tunnels'] == []
            assert hashlib.sha256((data / 'control.json').read_bytes()).hexdigest() == control_hash
            assert server.manager.runtime == {}
            checks.append('all checks preserve empty settings/control and start no SSH transports')
        finally:
            app.quit_panel()
            spin(.1)
            server.shutdown()
            server.server_close()
            server.manager.shutdown()
            thread.join(timeout=3)
    report = {'ok': True, 'platform': sys.platform, 'webkit': '%d.%d.%d' % (
        WebKit2.get_major_version(), WebKit2.get_minor_version(), WebKit2.get_micro_version()),
        'version': panel.VERSION, 'build': panel.BUILD, 'count': len(checks), 'checks': checks}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
