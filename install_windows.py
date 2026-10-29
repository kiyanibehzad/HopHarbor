#!/usr/bin/env python3
"""Per-user Windows launcher, background supervisor and installer registration.

The package builder imports only the metadata helpers on other operating systems.
No function starts or stops a service merely by importing this module.
"""
import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

if sys.platform == 'win32':
    # Keep the immutable package clean for upgrades and recorded-file uninstall.
    sys.dont_write_bytecode = True

APP_ID = 'io.github.kiyanibehzad.HopHarbor'
REGISTRY_KEY = r'Software\HopHarbor'
RUN_KEY = r'Software\Microsoft\Windows\CurrentVersion\Run'
INSTALL_MARKER = '.hopharbor-windows-install.json'
PACKAGE_MARKER = 'hopharbor-package.json'
STOP_MARKER = '.hopharbor-supervisor-stop.json'
# The controller publishes its actual loopback port in its private control file.
DEFAULT_PORT = 0
ROOT = Path(__file__).resolve().parent


def architecture(machine=None):
    value = (platform.machine() if machine is None else machine).lower()
    names = {'amd64': 'x64', 'x86_64': 'x64', 'arm64': 'arm64', 'aarch64': 'arm64'}
    if value not in names:
        raise ValueError('HopHarbor for Windows supports x64 and ARM64 only.')
    return names[value]


def local_appdata():
    value = os.environ.get('LOCALAPPDATA', '')
    path = Path(value) if value else Path.home() / 'AppData' / 'Local'
    if not path.is_absolute():
        raise ValueError('LOCALAPPDATA must be an absolute private path.')
    return path


def default_app_dir():
    return local_appdata() / 'Programs' / 'HopHarbor'


def default_data_dir():
    return local_appdata() / 'HopHarbor'


def native():
    if sys.platform != 'win32':
        raise ValueError('This launcher runs on Windows only.')
    import windows_platform
    return windows_platform


def require_windows():
    if sys.platform != 'win32':
        raise ValueError('HopHarbor requires Windows.')
    arch = architecture()
    minimum = 22000 if arch == 'arm64' else 19045
    if sys.getwindowsversion().build < minimum:
        raise ValueError('HopHarbor requires Windows 10 22H2 or later on x64, or Windows 11 or later on ARM64.')


def installation_identity(app, data):
    return {'app_dir': str(Path(app).absolute()), 'data_dir': str(Path(data).absolute())}


def verify_package(app):
    """Require an intentional package root, never an arbitrary directory."""
    n = native()
    app = Path(app).absolute()
    if os.path.normcase(str(app)) != os.path.normcase(str(default_app_dir().absolute())):
        raise ValueError('Use the fixed private LocalAppData Programs HopHarbor installation directory.')
    n.validate_private_directory(app)
    marker = n.read_private_json(app / PACKAGE_MARKER, max_bytes=4096)
    if (not isinstance(marker, dict) or marker.get('name') != 'HopHarbor'
            or marker.get('architecture') not in ('x64', 'arm64')
            or marker.get('architecture') != architecture()):
        raise ValueError('This HopHarbor package does not match the Windows processor architecture.')
    for name in ('manager.py', 'install_windows.py', 'runtime/python.exe', 'runtime/pythonw.exe',
                 'windows_proxy.py', 'bin/HopHarborHelper.exe', 'ui/HopHarbor.exe'):
        n.validate_private_file(app / name)
    if (app / 'bin/gost.exe').exists():
        raise ValueError('Use the Windows package containing the project-native proxy frontend.')
    return app


def guard_installation(app, data, create=False):
    """Scope every operation to the exact app/data pair recorded privately."""
    n = native()
    app, data = Path(app).absolute(), Path(data).absolute()
    n.validate_private_directory(app)
    n.validate_private_directory(data)
    path = data / INSTALL_MARKER
    identity = installation_identity(app, data)
    if path.exists():
        current = n.read_private_json(path, max_bytes=4096)
        if current != identity:
            raise ValueError('Another HopHarbor installation uses this data directory. Use its matching launcher or uninstall it first.')
    elif create:
        n.atomic_json(path, identity)
    else:
        raise ValueError('No matching HopHarbor installation was found for this data directory.')
    return identity


def checked_remove(path):
    path = Path(path)
    if path.exists():
        native().validate_private_file(path)
        path.unlink()


def stop_requested(app, data):
    path = Path(data) / STOP_MARKER
    if not path.exists():
        return False
    value = native().read_private_json(path, max_bytes=4096)
    if value != installation_identity(app, data):
        raise ValueError('The local stop request belongs to another installation.')
    return True


class ServiceClient:
    """Private loopback cookie session; no credentials or token in argv/logs."""
    def __init__(self, data):
        control = native().read_private_json(Path(data) / 'control.json', max_bytes=16384)
        if not isinstance(control, dict):
            raise ValueError('The private controller access file is invalid.')
        port, token = control.get('port'), control.get('token')
        if (type(port) is not int or not 1024 <= port <= 65535
                or not isinstance(token, str) or not 16 <= len(token.encode('utf-8')) <= 4096):
            raise ValueError('The private controller access file is invalid.')
        self.origin = 'http://127.0.0.1:%d' % port
        class NoRedirects(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_args, **_kwargs):
                raise ValueError('The local controller must not redirect requests.')
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirects())
        self.request('/api/session', {'token': token})

    def request(self, path, body=None):
        request = urllib.request.Request(self.origin + path,
            data=None if body is None else json.dumps(body).encode('utf-8'),
            headers={'Origin': self.origin, 'Content-Type': 'application/json',
                     'X-Requested-With': 'ProxyManager'})
        with self.opener.open(request, timeout=2) as response:
            raw = response.read(32769)
        if len(raw) > 32768:
            raise ValueError('The local service returned an invalid response.')
        return json.loads(raw)

    def health(self):
        reply = self.request('/api/service/health')
        if not isinstance(reply, dict) or reply.get('ok') is not True or reply.get('platform') != 'win32':
            raise ValueError('The local service is not the expected Windows controller.')
        return reply


def connect_service(data):
    # A stale control file is not evidence that its old port still belongs to us.
    if not (Path(data) / 'control.json').exists() or backend_lock_free(data):
        return None
    try:
        client = ServiceClient(data)
        client.health()
        return client
    except urllib.error.HTTPError as error:
        raise ValueError('The local controller identity could not be verified; no service was changed.') from error
    except (urllib.error.URLError, ConnectionError, TimeoutError, socket.timeout):
        return None


def backend_lock_free(data):
    try:
        lock = native().ServiceLock(Path(data) / '.service.lock')
    except (RuntimeError, BlockingIOError):
        return False
    lock.close()
    return True


def stop_service(app, data, timeout=20):
    guard_installation(app, data)
    with native().ServiceLock(Path(data) / '.launch.lock'):
        _stop_service_locked(app, data, timeout)


def _stop_service_locked(app, data, timeout=20):
    """Caller holds the shared start/register/stop lock for this data scope."""
    guard_installation(app, data)
    native().atomic_json(Path(data) / STOP_MARKER, installation_identity(app, data))
    client = connect_service(data)
    if client is not None:
        try:
            client.request('/api/service/stop', {})
        except (urllib.error.URLError, ConnectionError, TimeoutError, socket.timeout):
            pass  # Reply can disappear while the matching controller shuts down.
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if backend_lock_free(data):
            try:
                supervisor = native().ServiceLock(Path(data) / '.supervisor.lock')
            except (RuntimeError, BlockingIOError):
                time.sleep(.2)
                continue
            supervisor.close()
            return
        time.sleep(.2)
    raise ValueError('The matching service could not finish stopping. Application files and private settings were preserved.')


def supervisor(app, data):
    """Independent per-user supervision; a UI exit does not own this process."""
    n = native()
    guard_installation(app, data)
    try:
        lock = n.ServiceLock(Path(data) / '.supervisor.lock')
    except (RuntimeError, BlockingIOError):
        return
    process = None
    failures = 0
    client = None
    started = 0
    try:
        while not stop_requested(app, data):
            if process is not None and process.poll() is None:
                if time.monotonic() - started >= 60:
                    failures = 0
                time.sleep(1)
                continue
            if process is not None:
                process.wait()
                process = None
                failures += 1
                # Avoid a tight loop for invalid credentials/config/executable errors.
                delay = min(60, 2 ** min(failures, 6))
                end = time.monotonic() + delay
                while time.monotonic() < end and not stop_requested(app, data):
                    time.sleep(.25)
                if stop_requested(app, data):
                    break
            if client is not None:
                try:
                    if not backend_lock_free(data):
                        client.health()
                        time.sleep(1)
                        continue
                except (OSError, ValueError, urllib.error.URLError):
                    pass
                client = None
            if not backend_lock_free(data):
                client = connect_service(data)
                time.sleep(1 if client is not None else .5)
                continue
            env = dict(os.environ, HOPHARBOR_APP=str(app), PM_DATA_DIR=str(data))
            process = subprocess.Popen([str(Path(app) / 'runtime/python.exe'), str(Path(app) / 'manager.py'),
                '--app-dir', str(app), '--data-dir', str(data), '--port', str(DEFAULT_PORT)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=env, cwd=str(app), close_fds=True, creationflags=subprocess.CREATE_NO_WINDOW)
            started = time.monotonic()
    finally:
        try:
            # Stop only this data scope through its private authenticated API.
            if stop_requested(app, data):
                try:
                    client = connect_service(data)
                    if client is not None:
                        client.request('/api/service/stop', {})
                except (OSError, ValueError, urllib.error.URLError):
                    pass
                if process is not None:
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        # This is the Popen instance we created, never a PID from disk.
                        process.terminate()
                        process.wait(timeout=5)
        finally:
            lock.close()


def launch_service(app, data):
    n = native()
    app = verify_package(app)
    data = n.ensure_private_directory(Path(data).absolute())
    with n.ServiceLock(data / '.launch.lock'):
        guard_installation(app, data, create=True)
        checked_remove(data / STOP_MARKER)
        if not (data / 'config.json').exists():
            n.atomic_json(data / 'config.json', {'servers': [], 'tunnels': [], 'migration': {
                'phase': 'setup', 'message': 'Add Sessions and port forwarding entries. Credentials use Windows Credential Manager.'}})
        # Failing before launch is preferable to an endless unavailable-SSH loop.
        n.ssh_executable()
        try:
            supervisor_lock = n.ServiceLock(data / '.supervisor.lock')
        except (RuntimeError, BlockingIOError):
            supervisor_lock = None
        if supervisor_lock is not None:
            supervisor_lock.close()
            flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            subprocess.Popen([str(app / 'runtime/pythonw.exe'), str(app / 'install_windows.py'),
                '--run-supervisor', '--app-dir', str(app), '--data-dir', str(data)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                cwd=str(app), env=dict(os.environ, HOPHARBOR_APP=str(app), PM_DATA_DIR=str(data)),
                close_fds=True, creationflags=flags)
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            client = connect_service(data)
            if client is not None:
                return client.health()
            time.sleep(.25)
    raise ValueError('The local Windows controller did not become ready. Check OpenSSH Client and the private configuration.')


def startup_command(app, data):
    return subprocess.list2cmdline([str(Path(app) / 'ui/HopHarbor.exe'), '--background', '--data-dir', str(Path(data))])


def register(app, data, autostart=True):
    import winreg
    n = native()
    app = verify_package(app)
    data = n.ensure_private_directory(Path(data).absolute())
    with n.ServiceLock(data / '.launch.lock'):
        identity = installation_identity(app, data)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REGISTRY_KEY) as key:
            for name, value in identity.items():
                try:
                    existing, _ = winreg.QueryValueEx(key, name)
                except FileNotFoundError:
                    existing = value
                if existing != value:
                    raise ValueError('A different registered HopHarbor installation exists. Remove it with its matching uninstaller first.')
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            try:
                previous, _ = winreg.QueryValueEx(key, 'HopHarbor')
            except FileNotFoundError:
                previous = None
            if previous is not None and previous != startup_command(app, data):
                raise ValueError('A different HopHarbor startup entry already exists. No registration was changed.')
        guard_installation(app, data, create=True)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REGISTRY_KEY) as key:
            for name, value in identity.items():
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            if autostart:
                winreg.SetValueEx(key, 'HopHarbor', 0, winreg.REG_SZ, startup_command(app, data))
            else:
                try:
                    previous, _ = winreg.QueryValueEx(key, 'HopHarbor')
                    if previous == startup_command(app, data):
                        winreg.DeleteValue(key, 'HopHarbor')
                except FileNotFoundError:
                    pass
        checked_remove(data / STOP_MARKER)


def uninstall(app, data):
    app, data = Path(app).absolute(), Path(data).absolute()
    guard_installation(app, data)
    with native().ServiceLock(data / '.launch.lock'):
        _uninstall_locked(app, data)


def _uninstall_locked(app, data):
    import winreg
    guard_installation(app, data)
    # Validate registration before stopping anything.
    try:
        registration = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_KEY)
    except FileNotFoundError:
        registration = None  # An intentional portable install has no key.
    if registration is not None:
        with registration as key:
            for name, value in installation_identity(app, data).items():
                try:
                    existing = winreg.QueryValueEx(key, name)[0]
                except FileNotFoundError as error:
                    raise ValueError('The registered installation is incomplete. No service or registration was changed.') from error
                if existing != value:
                    raise ValueError('The registered installation does not match this app and data directory.')
    _stop_service_locked(app, data)
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
        try:
            if winreg.QueryValueEx(key, 'HopHarbor')[0] == startup_command(app, data):
                winreg.DeleteValue(key, 'HopHarbor')
        except FileNotFoundError:
            pass
    if registration is not None:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, REGISTRY_KEY)
        except FileNotFoundError:
            pass
    checked_remove(data / INSTALL_MARKER)
    checked_remove(data / STOP_MARKER)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--launch', action='store_true', help='Start or verify the independent user backend.')
    action.add_argument('--run-supervisor', action='store_true')
    action.add_argument('--register', action='store_true')
    action.add_argument('--stop', action='store_true')
    action.add_argument('--uninstall', action='store_true', help='Stop/unregister; preserve settings and credentials.')
    parser.add_argument('--app-dir', type=Path, default=ROOT)
    parser.add_argument('--data-dir', type=Path, default=None)
    parser.add_argument('--no-autostart', action='store_true')
    args = parser.parse_args()
    try:
        require_windows()
        app = args.app_dir.absolute()
        data = default_data_dir() if args.data_dir is None else args.data_dir.absolute()
        if args.launch:
            result = launch_service(app, data)
        elif args.run_supervisor:
            verify_package(app); supervisor(app, data); result = {'ok': True}
        elif args.register:
            register(app, data, not args.no_autostart); result = {'ok': True}
        elif args.stop:
            stop_service(app, data); result = {'ok': True}
        else:
            uninstall(app, data); result = {'ok': True, 'settings_preserved': True}
        if not args.run_supervisor:
            print(json.dumps(result))
        return 0
    except (OSError, ValueError, RuntimeError, urllib.error.URLError):
        # Native components may include paths in exceptions; never echo stdout,
        # access tokens, credentials or arbitrary component output here.
        print(json.dumps({'ok': False, 'error': 'The matching private Windows installation could not complete this action. Check OpenSSH Client and installation scope.'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
