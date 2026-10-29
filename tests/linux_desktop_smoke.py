#!/usr/bin/python3
"""Opt-in Ubuntu desktop integration, using only a disposable empty controller.

Run inside a disposable Ubuntu desktop or Xvfb + dbus-run-session. This file is
not discovered by unittest and never contacts a real SSH server or user service.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--screenshot', type=Path, help='Save an optional synthetic panel PNG')
    args = parser.parse_args()
    if sys.platform != 'linux':
        raise SystemExit('This opt-in integration requires an isolated Linux desktop.')
    import gi
    gi.require_version('Gtk', '3.0')
    gi.require_version('WebKit2', '4.1')
    from gi.repository import GLib, Gtk, WebKit2
    import linux_desktop

    context = GLib.MainContext.default()

    def wait_for(predicate, description, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            while context.pending():
                context.iteration(False)
            value = predicate()
            if value:
                return value
            time.sleep(.02)
        raise AssertionError('Timed out: ' + description)

    def evaluate(browser, expression):
        result = []

        def done(view, outcome, _data):
            try:
                javascript = view.run_javascript_finish(outcome)
                result.append((True, json.loads(javascript.get_js_value().to_string())))
            except Exception as error:
                result.append((False, type(error).__name__))

        browser.run_javascript('JSON.stringify((' + expression + '))', None, done, None)
        wait_for(lambda: result, 'JavaScript completion')
        if not result[0][0]:
            raise AssertionError('Panel JavaScript failed: ' + result[0][1])
        return result[0][1]

    def loaded(app):
        try:
            return (app.browser is not None and not app.browser.is_loading()
                    and evaluate(app.browser,
                                 'document.getElementById("serviceLabel")?.textContent')
                    == 'Local service online')
        except AssertionError:
            return False

    checks = []
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='hopharbor-linux-ui-test-') as scratch:
        data = Path(scratch) / 'private'
        data.mkdir(mode=0o700)
        config = data / 'config.json'
        config.write_text(json.dumps({'servers': [], 'tunnels': [], 'migration': {}}))
        config.chmod(0o600)
        (data / 'known_hosts').touch(mode=0o600)
        with socket.socket() as allocation:
            allocation.bind(('127.0.0.1', 0))
            port = allocation.getsockname()[1]
        process = subprocess.Popen(
            [sys.executable, str(ROOT / 'manager.py'), '--data-dir', str(data),
             '--app-dir', str(ROOT), '--port', str(port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        app = None
        try:
            wait_for(lambda: (data / 'control.json').is_file() or process.poll() is not None,
                     'isolated controller startup')
            if process.poll() is not None:
                raise AssertionError('Isolated controller did not start.')
            app = linux_desktop.desktop_application(data, ROOT)
            assert app.register(None)
            app.activate()
            wait_for(lambda: loaded(app), 'authenticated Overview')
            overview = evaluate(app.browser, '({title:document.getElementById("pageTitle").textContent,'
                                'version:document.getElementById("appVersion").textContent,'
                                'platform:window.HopHarborPlatform,'
                                'fragment:location.hash,locked:document.getElementById("lockedScreen").hidden})')
            assert overview['title'] == 'Overview', overview
            assert overview['platform'] == 'linux', overview
            assert 'v' + linux_desktop.VERSION in overview['version'] and 'build ' + linux_desktop.BUILD in overview['version'], overview
            assert overview['fragment'] == '' and overview['locked'], 'Bootstrap token was not cleared.'
            checks.append('authenticated Overview, version, Linux platform and cleared token fragment')

            evaluate(app.browser, '(goView("servers"),document.getElementById("primaryAction").click(),true)')
            form = evaluate(app.browser,
                            '({open:document.getElementById("serverDialog").open,'
                            'title:document.getElementById("serverDialogTitle").textContent,'
                            'auth:Array.from(document.getElementById("serverAuth").options).map(o=>o.value),'
                            'keepalive:document.getElementById("serverKeepaliveInterval").value,'
                            'text:document.getElementById("serverDialog").textContent})')
            assert form['open'] and form['title'] == 'New session', form
            assert set(form['auth']) == {'agent', 'key', 'password', 'key_password'}, form
            assert form['keepalive'] == '30' and 'GNOME Keyring' in form['text'], form
            checks.append('same Session editor, all authentication methods, Linux credential labels and keepalive')
            evaluate(app.browser, '(document.getElementById("serverDialog").close(),goView("dashboard"),true)')

            evaluate(app.browser, '(changeAppearance("system"),true)')
            for dark in (True, False):
                app.dark = dark
                app.update_web_appearance()
                wait_for(lambda: evaluate(app.browser, 'document.documentElement.dataset.theme')
                         == ('dark' if dark else 'light'), 'System appearance update')
            evaluate(app.browser, '(changeAppearance("light"),true)')
            app.dark = True
            app.update_web_appearance()
            assert evaluate(app.browser, 'document.documentElement.dataset.theme') == 'light'
            evaluate(app.browser, '(changeAppearance("dark"),true)')
            app.dark = False
            app.update_web_appearance()
            assert evaluate(app.browser, 'document.documentElement.dataset.theme') == 'dark'
            checks.append('System appearance follows native updates; explicit Light and Dark override it')

            old_browser = app.browser
            app.close_panel()
            if app.indicator is not None:
                assert app.browser is None and not app.window.get_visible()
                app.activate()
                wait_for(lambda: loaded(app), 'reopened authenticated panel')
                assert app.browser is not old_browser
                assert evaluate(app.browser, 'document.documentElement.dataset.theme') == 'dark'
                checks.append('close releases WebView, tray retains application, reopen reauthenticates and keeps preference')
            else:
                assert app.browser is old_browser
                app.activate()
                checks.append('missing indicator safely retains accessible minimized window')

            attempted = []

            original_policy = linux_desktop.navigation_allowed

            def observe(uri, active_port):
                allowed = original_policy(uri, active_port)
                if uri == 'https://example.invalid/':
                    attempted.append(allowed)
                return allowed

            # Observe the actual policy predicate called by the connected GTK
            # handler. No extra signal handler can consume or bypass its result.
            with mock.patch.object(linux_desktop, 'navigation_allowed', side_effect=observe):
                app.browser.load_uri('https://example.invalid/')
                wait_for(lambda: attempted, 'external navigation decision')
                assert attempted == [False]
                wait_for(lambda: not app.browser.is_loading(), 'cancelled external navigation')
                assert evaluate(app.browser, 'document.getElementById("pageTitle")?.textContent') == 'Overview'
            checks.append('external navigation does not replace the trusted panel')

            if args.screenshot:
                evaluate(app.browser, '(changeAppearance("dark"),true)')
                # A short bounded frame wait allows styles and fonts to settle.
                deadline = time.monotonic() + .4
                wait_for(lambda: time.monotonic() >= deadline, 'final panel frame', timeout=2)
                completed = []

                def captured(view, outcome, _data):
                    try:
                        surface = view.get_snapshot_finish(outcome)
                        args.screenshot.parent.mkdir(parents=True, exist_ok=True)
                        surface.write_to_png(str(args.screenshot))
                        completed.append(True)
                    except Exception as error:
                        completed.append(type(error).__name__ + ': ' + str(error)[:300])

                app.browser.get_snapshot(WebKit2.SnapshotRegion.VISIBLE, WebKit2.SnapshotOptions.NONE,
                                         None, captured, None)
                wait_for(lambda: completed, 'synthetic screenshot')
                assert completed[0] is True, 'Synthetic screenshot failed: ' + str(completed[0])
            assert json.loads(config.read_text())['servers'] == []
            assert json.loads(config.read_text())['tunnels'] == []
            assert process.poll() is None
            checks.append('UI actions leave disposable controller running and configuration empty')
            app.quit_panel()
            while context.pending():
                context.iteration(False)
            assert process.poll() is None
            checks.append('Quit Panel leaves the independent controller running')
        finally:
            if app is not None:
                app.quit_panel()
                while context.pending():
                    context.iteration(False)
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
    print(json.dumps({'ok': True, 'checks': checks}, indent=2))


if __name__ == '__main__':
    main()
