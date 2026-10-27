#!/usr/bin/python3
"""Ubuntu desktop shell for the existing, loopback-only HopHarbor panel.

The shell never starts or stops SSH or the controller. GTK and WebKit are loaded
only by main(), so the input validation can also be tested without a desktop.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from urllib.parse import quote, urlsplit


VERSION = '1.2.0'
BUILD = '8'
REPOSITORY_URL = 'https://github.com/kiyanibehzad/HopHarbor'


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
            if self.browser is not None:
                browser, self.browser = self.browser, None
                browser.stop_loading()
                browser.destroy()
            self.active_port = None
            for child in self.content.get_children():
                child.destroy()

        def close_panel(self, *_args):
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
                port, token = read_control(data_dir)
            except (OSError, ValueError, TypeError, AttributeError, UnicodeError):
                self.show_error('The background service is not ready.',
                                'Start the HopHarbor user service, then choose Try Again.')
                return
            self.active_port = port
            scripts = WebKit2.UserContentManager()
            scripts.add_script(WebKit2.UserScript.new(
                bootstrap_script(self.dark), WebKit2.UserContentInjectedFrames.TOP_FRAME,
                WebKit2.UserScriptInjectionTime.START, None, None))
            browser = WebKit2.WebView(web_context=self.web_context(), user_content_manager=scripts)
            self.browser = browser
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
            self.content.pack_start(browser, True, True, 0)
            browser.show()
            browser.load_uri(panel_url(port, token))

        def deny_permission(self, _browser, request):
            request.deny()
            return True

        def deny_file_chooser(self, _browser, request):
            request.cancel()
            return True

        def decide_policy(self, _browser, decision, kind):
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
                           and navigation_allowed(uri, self.active_port))
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
            GLib.idle_add(self.panel_failure, browser)
            return True

        def panel_failure(self, browser):
            if browser is self.browser:
                self.show_error('Unable to connect to the panel.',
                                'Check that the HopHarbor user service is running and try again.')
            return GLib.SOURCE_REMOVE

        def load_changed(self, browser, event):
            if browser is self.browser and event == WebKit2.LoadEvent.FINISHED:
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
