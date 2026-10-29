#!/usr/bin/python3
"""Ubuntu desktop shell for the existing, loopback-only HopHarbor panel.

The shell never starts or stops SSH or the controller. GTK and WebKit are loaded
only by main(), so the input validation can also be tested without a desktop.
"""
import argparse
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import stat
import sys
import time
from urllib.parse import quote, urlsplit


VERSION = '1.3.2'
BUILD = '12'
REPOSITORY_URL = 'https://github.com/kiyanibehzad/HopHarbor'
PANEL_CONTENT_POLICY = "script-src 'none'; frame-src 'none'; child-src 'none'"


def default_data_dir(environ=None, home=None):
    env = os.environ if environ is None else environ
    home = Path.home() if home is None else Path(home)
    value = env.get('XDG_DATA_HOME', '')
    base = Path(value) if value and Path(value).is_absolute() else home / '.local/share'
    return base / 'hopharbor'


def application_id(data_dir):
    # Separate explicitly isolated test installations, without exposing paths.
    if Path(data_dir).resolve() == default_data_dir().resolve():
        return 'io.github.kiyanibehzad.HopHarbor'
    suffix = hashlib.sha256(str(Path(data_dir).resolve()).encode()).hexdigest()[:16]
    return 'io.github.kiyanibehzad.HopHarbor.p' + suffix


def read_control(data_dir):
    """Read only a small, private, regular access file owned by this user."""
    path = Path(data_dir) / 'control.json'
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or not 0 < info.st_size <= 16384):
            raise ValueError('The panel access file is not private or is invalid.')
        with os.fdopen(descriptor, 'r', encoding='utf-8') as handle:
            descriptor = None
            content = handle.read(16385)
        if len(content.encode('utf-8')) > 16384:
            raise ValueError('The panel access file is too large.')
        control = json.loads(content)
        port, token = control.get('port'), control.get('token')
        if (type(port) is not int or not 1024 <= port <= 65535
                or not isinstance(token, str) or not 16 <= len(token.encode('utf-8')) <= 4096):
            raise ValueError('The panel connection settings are invalid.')
        return port, token
    finally:
        if descriptor is not None:
            os.close(descriptor)


def panel_url(port, token):
    return 'http://127.0.0.1:%d/#token=%s' % (port, quote(token, safe=''))


def navigation_allowed(uri, port):
    try:
        parsed = urlsplit(uri)
        return (parsed.scheme == 'http' and parsed.hostname == '127.0.0.1'
                and parsed.port == port and parsed.username is None and parsed.password is None)
    except (ValueError, TypeError):
        return False


def appearance_script(dark):
    # The panel owns the stored choice and applies this only in System mode.
    return ('window.HopHarborSystemDark=%s;'
            'window.dispatchEvent(new Event("hopharbor-system-appearance"));'
            % json.dumps(bool(dark)))


def bootstrap_script(dark):
    metadata = json.dumps({'version': VERSION, 'build': BUILD}, separators=(',', ':'))
    return ('window.HopHarborNativeVersion=%s;window.HopHarborPlatform="linux";'
            'window.HopHarborSystemDark=%s;' % (metadata, json.dumps(bool(dark))))


def panel_location_allowed(uri, port):
    return navigation_allowed(uri, port) and urlsplit(uri).path in ('/', '/index.html')


def recovery_message(value):
    if not isinstance(value, dict):
        return None
    if value == {'action': 'ready'}:
        return 'ready'
    if (set(value) == {'action', 'reason'} and value['action'] == 'reauthenticate'
            and value['reason'] in ('authentication', 'retry')):
        return value['reason']
    return None


class RecoveryBudget:
    """One application-wide rolling budget, retained across destroyed pages."""
    def __init__(self):
        self.attempts = []
        self.last_scheduled = None

    def delay(self, manual=False, now=None):
        now = time.monotonic() if now is None else now
        self.attempts = [stamp for stamp in self.attempts if now - stamp < 60]
        if not manual and len(self.attempts) >= 3:
            return None
        delay = max(0, 2 - (now - self.last_scheduled)) if self.last_scheduled is not None else 0
        self.last_scheduled = now + delay
        if not manual:
            self.attempts.append(now + delay)
        return delay

    def authenticated(self):
        self.attempts.clear()


def recovery_scripts(port):
    """Public fixed-command facade; native handler exists ONLY in an isolated world.

    GTK's message callback lacks sender frame metadata. The isolated TOP_FRAME
    receiver verifies browser-generated MessageEvents from its own window and
    exact origin, rather than trusting fields supplied by the page. The public
    facade has no access to the native receiver or any control-file credentials.
    """
    origin = json.dumps('http://127.0.0.1:%d' % port)
    guard = ('if(window!==window.top||location.origin!==%s||'
             "!['/','/index.html'].includes(location.pathname))return;" % origin)
    validate = """const valid=m=>m&&typeof m==='object'&&!Array.isArray(m)&&(
      (Object.keys(m).length===1&&m.action==='ready')||
      (Object.keys(m).length===2&&m.action==='reauthenticate'&&
       ['authentication','retry'].includes(m.reason)));"""
    facade = ('(()=>{' + guard + """
      // Keep the original WindowProxy as the method receiver. A wrapper OR a
      // bound function changes the incumbent realm for a child calling its
      // parent's facade, incorrectly giving that child a top-window identity.
      Object.defineProperty(window,'webkit',{value:Object.freeze({messageHandlers:
        Object.freeze({hopharborPanel:window})}),configurable:false,writable:false});
    })();""")
    receiver = ('(()=>{' + guard + validate + """
      const send=window.webkit.messageHandlers.hopharborPanelReceiver.postMessage.bind(
        window.webkit.messageHandlers.hopharborPanelReceiver);
      window.addEventListener('message',event=>{
        if(!event.isTrusted||event.source!==window||event.origin!==""" + origin + """||
           location.origin!==""" + origin + """||!['/','/index.html'].includes(location.pathname))return;
        try{const m=event.data;if(valid(m)){
          const text=JSON.stringify(m);if(text.length<=160)send(text);
        }}catch{}
      });
    })();""")
    return facade, receiver


def trusted_panel_scripts(app_dir):
    """Run reviewed installed scripts only in TOP_FRAME, never child markup.

    WebView's native default CSP disables every content script and child load.
    UserContentManager bypasses CSP, so the unchanged installed panel scripts can
    be injected into the main document only. The controller's policy still adds
    its Host/Origin/CSRF and other content restrictions independently.
    """
    root = Path(app_dir) / 'web'

    class PanelScripts(HTMLParser):
        def __init__(self):
            super().__init__()
            self.active = None
            self.scripts = []
            self.external_count = 0

        def handle_starttag(self, tag, attrs):
            if tag == 'script':
                if self.active is not None or any(key != 'src' for key, _ in attrs):
                    raise ValueError('Unsupported panel script.')
                source = dict(attrs).get('src')
                if source not in (None, '/app.js'):
                    raise ValueError('Unsupported panel script source.')
                self.active = (source, [])

        def handle_data(self, text):
            if self.active is not None:
                self.active[1].append(text)

        def handle_endtag(self, tag):
            if tag == 'script' and self.active is not None:
                source, parts = self.active
                if source:
                    self.external_count += 1
                    self.scripts.append((root / 'app.js').read_text(encoding='utf-8'))
                else:
                    self.scripts.append(''.join(parts))
                self.active = None

    parser = PanelScripts()
    parser.feed((root / 'index.html').read_text(encoding='utf-8'))
    parser.close()
    if parser.active is not None or parser.external_count != 1:
        raise ValueError('The panel scripts are incomplete.')
    return tuple(parser.scripts)


def icon_directory(app_dir):
    root = Path(app_dir)
    for directory in (root / 'assets', root / 'packaging/assets'):
        if (directory / 'HopHarbor.svg').is_file():
            return directory
    return None


def desktop_application(data_dir, app_dir):
    """Build the GTK application after dependencies have been imported."""
    import gi
    gi.require_version('Gtk', '3.0')
    gi.require_version('WebKit2', '4.1')
    from gi.repository import Gio, GLib, Gtk, WebKit2
    try:
        gi.require_version('AyatanaAppIndicator3', '0.1')
        from gi.repository import AyatanaAppIndicator3 as AppIndicator
    except (ImportError, ValueError):
        AppIndicator = None

    class HopHarborApplication(Gtk.Application):
        def __init__(self):
            super().__init__(application_id=application_id(data_dir),
                             flags=Gio.ApplicationFlags.HANDLES_COMMAND_LINE)
            self.add_main_option('background', 0, GLib.OptionFlags.NONE, GLib.OptionArg.NONE,
                                 'Start with only the tray indicator', None)
            self.window = None
            self.content = None
            self.browser = None
            self.active_port = None
            self.indicator = None
            self.interface_settings = None
            self.dark = False
            self.held = False
            self.assets = icon_directory(app_dir)
            self.context = None
            self.generation = 0
            self.recovery_budget = RecoveryBudget()
            self.recovery_source = None
            self.load_timeout_source = None
            self.panel_active = False

        def do_startup(self):
            Gtk.Application.do_startup(self)
            self.hold()
            self.held = True
            self.window = Gtk.ApplicationWindow(application=self, title='HopHarbor')
            self.window.set_default_size(1120, 760)
            self.window.set_size_request(780, 560)
            self.window.set_wmclass('hopharbor', 'HopHarbor')
            self.window.connect('delete-event', self.close_panel)
            self.window.connect('key-press-event', self.key_pressed)
            if self.assets:
                icon = self.assets / 'HopHarbor-1024.png'
                self.window.set_icon_from_file(str(icon if icon.is_file() else self.assets / 'HopHarbor.svg'))
            self.content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            self.window.add(self.content)
            self.configure_appearance()
            self.create_indicator()

        def do_command_line(self, command_line):
            # Only the presentation request is accepted from another invocation.
            arguments = command_line.get_arguments()
            if '--background' not in arguments or self.indicator is None:
                self.activate()
            return 0

        def do_activate(self):
            if not self.panel_active and self.browser is not None:
                self.discard_page()
            self.panel_active = True
            if self.browser is None:
                self.load_panel()
            self.window.show_all()
            self.window.present()

        def configure_appearance(self):
            source = Gio.SettingsSchemaSource.get_default()
            schema = source.lookup('org.gnome.desktop.interface', True) if source else None
            if schema and schema.has_key('color-scheme'):
                self.interface_settings = Gio.Settings.new_full(schema, None, None)
                self.interface_settings.connect('changed::color-scheme', self.appearance_changed)
            settings = Gtk.Settings.get_default()
            settings.connect('notify::gtk-theme-name', self.appearance_changed)
            settings.connect('notify::gtk-application-prefer-dark-theme', self.gtk_appearance_changed)
            self.appearance_changed()

        def gtk_appearance_changed(self, *_args):
            if self.interface_settings is None:
                self.dark = bool(Gtk.Settings.get_default().get_property('gtk-application-prefer-dark-theme'))
                self.update_web_appearance()

        def appearance_changed(self, *_args):
            settings = Gtk.Settings.get_default()
            if self.interface_settings:
                self.dark = self.interface_settings.get_string('color-scheme') == 'prefer-dark'
                settings.set_property('gtk-application-prefer-dark-theme', self.dark)
            else:
                theme = settings.get_property('gtk-theme-name') or ''
                self.dark = ('dark' in theme.lower()
                             or bool(settings.get_property('gtk-application-prefer-dark-theme')))
            self.update_web_appearance()

        def update_web_appearance(self):
            if self.browser is not None:
                self.browser.run_javascript(appearance_script(self.dark), None, None, None)

        def create_indicator(self):
            if AppIndicator is None:
                return
            icon = 'hopharbor-symbolic' if self.assets else 'network-transmit-receive-symbolic'
            self.indicator = AppIndicator.Indicator.new(
                self.get_application_id(), icon, AppIndicator.IndicatorCategory.APPLICATION_STATUS)
            if self.assets:
                self.indicator.set_icon_theme_path(str(self.assets))
                if not (self.assets / 'hopharbor-symbolic.svg').is_file():
                    self.indicator.set_icon_full(str(self.assets / 'HopHarbor.svg'), 'HopHarbor')
            self.indicator.set_title('HopHarbor')
            menu = Gtk.Menu()
            for title, action in (
                ('Open HopHarbor', lambda *_: self.activate()),
                ('Reload Panel', self.reload_panel),
                ('Keep in Background', self.close_panel),
            ):
                item = Gtk.MenuItem(label=title)
                item.connect('activate', action)
                menu.append(item)
            menu.append(Gtk.SeparatorMenuItem())
            hint = Gtk.MenuItem(label='Connections run independently of the panel')
            hint.set_sensitive(False)
            menu.append(hint)
            quit_item = Gtk.MenuItem(label='Quit Panel')
            quit_item.connect('activate', self.quit_panel)
            menu.append(quit_item)
            menu.show_all()
            self.indicator.set_menu(menu)
            self.indicator.set_status(AppIndicator.IndicatorStatus.ACTIVE)

        def key_pressed(self, _window, event):
            from gi.repository import Gdk
            if event.state & Gdk.ModifierType.CONTROL_MASK:
                key = Gdk.keyval_name(event.keyval)
                if key in ('q', 'Q', 'w', 'W'):
                    self.close_panel()
                    return True
                if key in ('r', 'R'):
                    self.reload_panel()
                    return True
            return False

        def discard_page(self):
            self.generation += 1
            self.cancel_recovery()
            self.cancel_load_timeout()
            if self.browser is not None:
                browser, self.browser = self.browser, None
                scripts = browser.get_user_content_manager()
                scripts.unregister_script_message_handler_in_world(
                    'hopharborPanelReceiver', 'HopHarborPanel')
                browser.stop_loading()
                browser.destroy()
            self.active_port = None
            for child in self.content.get_children():
                child.destroy()

        def close_panel(self, *_args):
            self.panel_active = False
            self.cancel_recovery()
            self.cancel_load_timeout()
            if self.indicator is not None:
                self.discard_page()
                self.window.hide()
            else:
                # Without an indicator host, leave a usable route back to the UI.
                self.window.iconify()
            return True

        def reload_panel(self, *_args):
            self.discard_page()
            self.activate()

        def quit_panel(self, *_args):
            self.discard_page()
            if self.indicator:
                self.indicator.set_status(AppIndicator.IndicatorStatus.PASSIVE)
            if self.held:
                self.release()
                self.held = False
            self.quit()

        def show_error(self, title, detail):
            self.discard_page()
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
            box.set_halign(Gtk.Align.CENTER)
            box.set_valign(Gtk.Align.CENTER)
            heading = Gtk.Label(label=title)
            heading.get_style_context().add_class('title')
            description = Gtk.Label(label=detail)
            description.set_line_wrap(True)
            description.set_max_width_chars(75)
            description.set_justify(Gtk.Justification.CENTER)
            retry = Gtk.Button(label='Try Again')
            retry.set_halign(Gtk.Align.CENTER)
            retry.connect('clicked', self.reload_panel)
            for widget in (heading, description, retry):
                box.pack_start(widget, False, False, 0)
            self.content.pack_start(box, True, True, 24)
            self.content.show_all()

        def web_context(self):
            if self.context is None:
                storage = Path(data_dir) / 'panel'
                storage.mkdir(mode=0o700, parents=True, exist_ok=True)
                storage.chmod(0o700)
                manager = WebKit2.WebsiteDataManager(
                    base_data_directory=str(storage / 'data'),
                    base_cache_directory=str(storage / 'cache'))
                self.context = WebKit2.WebContext.new_with_website_data_manager(manager)
                # A system proxy must never route the local controller through SSH.
                self.context.set_network_proxy_settings(WebKit2.NetworkProxyMode.NO_PROXY, None)
                self.context.set_cache_model(WebKit2.CacheModel.DOCUMENT_VIEWER)
            return self.context

        def load_panel(self):
            self.discard_page()
            try:
                panel_scripts = trusted_panel_scripts(app_dir)
            except (OSError, ValueError, UnicodeError):
                self.show_error('The panel files are not ready.',
                                'Restore the reviewed HopHarbor application files and try again.')
                return
            try:
                port, token = read_control(data_dir)
            except (OSError, ValueError, TypeError, AttributeError, UnicodeError):
                self.show_error('The background service is not ready.',
                                'Start the HopHarbor user service, then choose Try Again.')
                return
            self.active_port = port
            scripts = WebKit2.UserContentManager()
            generation = self.generation
            scripts.connect('script-message-received::hopharborPanelReceiver',
                            lambda manager, value: self.panel_message(
                                browser, generation, value))
            if not scripts.register_script_message_handler_in_world(
                    'hopharborPanelReceiver', 'HopHarborPanel'):
                self.show_error('Unable to open the panel.', 'Try opening HopHarbor again.')
                return
            facade, receiver = recovery_scripts(port)
            scripts.add_script(WebKit2.UserScript.new_for_world(
                receiver, WebKit2.UserContentInjectedFrames.TOP_FRAME,
                WebKit2.UserScriptInjectionTime.START, 'HopHarborPanel', None, None))
            scripts.add_script(WebKit2.UserScript.new(
                bootstrap_script(self.dark) + facade, WebKit2.UserContentInjectedFrames.TOP_FRAME,
                WebKit2.UserScriptInjectionTime.START, None, None))
            for source in panel_scripts:
                scripts.add_script(WebKit2.UserScript.new(
                    source, WebKit2.UserContentInjectedFrames.TOP_FRAME,
                    WebKit2.UserScriptInjectionTime.END, None, None))
            browser = WebKit2.WebView(web_context=self.web_context(), user_content_manager=scripts,
                                     default_content_security_policy=PANEL_CONTENT_POLICY)
            self.browser = browser
            self.initial_navigation = True
            settings = browser.get_settings()
            settings.set_property('javascript-can-open-windows-automatically', False)
            settings.set_property('allow-file-access-from-file-urls', False)
            settings.set_property('allow-universal-access-from-file-urls', False)
            browser.connect('decide-policy', self.decide_policy)
            browser.connect('create', lambda *_: None)
            browser.connect('permission-request', self.deny_permission)
            browser.connect('run-file-chooser', self.deny_file_chooser)
            browser.connect('load-failed', self.load_failed)
            browser.connect('load-changed', self.load_changed)
            browser.connect('web-process-terminated', self.renderer_terminated)
            self.content.pack_start(browser, True, True, 0)
            browser.show()
            browser.load_uri(panel_url(port, token))
            self.load_timeout_source = GLib.timeout_add_seconds(
                20, self.load_timed_out, browser, generation)

        def owned_page(self, browser, generation):
            return (browser is self.browser and generation == self.generation
                    and self.panel_active and self.active_port is not None)

        def current_page(self, browser, generation):
            return (self.owned_page(browser, generation)
                    and panel_location_allowed(browser.get_uri(), self.active_port))

        def panel_message(self, browser, generation, result):
            if not self.current_page(browser, generation):
                return
            try:
                value = result.get_js_value()
                if not value.is_string():
                    return
                text = value.to_string()
                if len(text) > 160:
                    return
                action = recovery_message(json.loads(text))
            except (ValueError, TypeError, AttributeError):
                return
            if action == 'ready':
                self.cancel_recovery()
                self.cancel_load_timeout()
                self.recovery_budget.authenticated()
            elif action in ('authentication', 'retry'):
                self.cancel_load_timeout()
                self.schedule_recovery(browser, generation, manual=action == 'retry')

        def cancel_recovery(self):
            if self.recovery_source is not None:
                GLib.source_remove(self.recovery_source)
                self.recovery_source = None

        def cancel_load_timeout(self):
            if self.load_timeout_source is not None:
                GLib.source_remove(self.load_timeout_source)
                self.load_timeout_source = None

        def schedule_recovery(self, browser, generation, manual=False, native_failure=False):
            # A terminated renderer may have no URI. Native failure signals have
            # browser identity; script messages additionally require a live URL.
            valid = self.owned_page if native_failure else self.current_page
            if (not valid(browser, generation)
                    or self.recovery_source is not None):
                return False
            delay = self.recovery_budget.delay(manual)
            if delay is None:
                return False

            def recover():
                self.recovery_source = None
                if valid(browser, generation):
                    self.load_panel()
                return GLib.SOURCE_REMOVE

            self.recovery_source = GLib.timeout_add(max(1, int(delay * 1000) + 1), recover)
            return True

        def load_timed_out(self, browser, generation):
            self.load_timeout_source = None
            if self.owned_page(browser, generation) and self.recovery_source is None:
                if not self.schedule_recovery(browser, generation, native_failure=True):
                    self.panel_failure(browser)
            return GLib.SOURCE_REMOVE

        def renderer_terminated(self, browser, _reason):
            if browser is self.browser:
                self.cancel_load_timeout()
                if (self.recovery_source is None
                        and not self.schedule_recovery(browser, self.generation, native_failure=True)):
                    self.panel_failure(browser)

        def deny_permission(self, _browser, request):
            request.deny()
            return True

        def deny_file_chooser(self, _browser, request):
            request.cancel()
            return True

        def decide_policy(self, browser, decision, kind):
            if browser is not self.browser:
                decision.ignore()
                return True
            if kind in (WebKit2.PolicyDecisionType.NAVIGATION_ACTION,
                        WebKit2.PolicyDecisionType.NEW_WINDOW_ACTION):
                action = decision.get_navigation_action()
                uri = action.get_request().get_uri()
                if (uri == REPOSITORY_URL and action.is_user_gesture()
                        and kind == WebKit2.PolicyDecisionType.NAVIGATION_ACTION):
                    # The only supported external destination; never include a token.
                    Gio.AppInfo.launch_default_for_uri(REPOSITORY_URL, None)
                    decision.ignore()
                    return True
                allowed = (kind == WebKit2.PolicyDecisionType.NAVIGATION_ACTION
                           and self.initial_navigation
                           and panel_location_allowed(uri, self.active_port))
                if allowed:
                    # One document per WebView. Native reload creates a new view;
                    # old documents cannot send late ready/recovery messages.
                    self.initial_navigation = False
            elif kind == WebKit2.PolicyDecisionType.RESPONSE:
                uri = decision.get_response().get_uri()
                allowed = navigation_allowed(uri, self.active_port) and decision.is_mime_type_supported()
            else:
                allowed = False
            decision.use() if allowed else decision.ignore()
            return True

        def load_failed(self, browser, _event, _uri, error):
            if browser is not self.browser:
                return True
            if error.matches(WebKit2.NetworkError.quark(), WebKit2.NetworkError.CANCELLED):
                return True
            # Do not copy failed URLs or WebKit errors: bootstrap fragments hold tokens.
            GLib.idle_add(self.recover_load_failure, browser, self.generation)
            return True

        def recover_load_failure(self, browser, generation):
            if self.owned_page(browser, generation):
                self.cancel_load_timeout()
                if (self.recovery_source is None
                        and not self.schedule_recovery(browser, generation, native_failure=True)):
                    self.panel_failure(browser)
            return GLib.SOURCE_REMOVE

        def panel_failure(self, browser):
            if browser is self.browser and self.panel_active:
                self.show_error('Unable to connect to the panel.',
                                'Check that the HopHarbor user service is running and try again.')
            return GLib.SOURCE_REMOVE

        def load_changed(self, browser, event):
            if browser is self.browser and event == WebKit2.LoadEvent.FINISHED:
                # This watchdog covers document loading, not authentication.
                # A rejected bootstrap or 403 must stay locked until Retry.
                self.cancel_load_timeout()
                self.update_web_appearance()

        def do_shutdown(self):
            if self.content is not None:
                self.discard_page()
            Gtk.Application.do_shutdown(self)

    return HopHarborApplication()


def main():
    parser = argparse.ArgumentParser(description='Open the HopHarbor Ubuntu panel')
    parser.add_argument('--data-dir', type=Path, default=default_data_dir())
    parser.add_argument('--app-dir', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--background', action='store_true', help='Start with only the tray indicator')
    args = parser.parse_args()
    if sys.platform != 'linux':
        raise SystemExit('This launcher is for Linux; the macOS application is separate.')
    if os.getuid() == 0:
        raise SystemExit('Open HopHarbor as your desktop user, without sudo.')
    os.umask(0o077)
    try:
        app = desktop_application(args.data_dir.expanduser().resolve(), args.app_dir.expanduser().resolve())
    except (ImportError, ValueError):
        raise SystemExit('Install the Ubuntu GTK, WebKitGTK and libsecret dependencies listed in docs/ubuntu.md.')
    return app.run([sys.argv[0]] + (['--background'] if args.background else []))


if __name__ == '__main__':
    sys.exit(main())
