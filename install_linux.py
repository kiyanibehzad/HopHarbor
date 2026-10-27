#!/usr/bin/python3
"""Ubuntu per-user installer and packaged-service entry point. Never uses launchd."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent
SERVICE = 'local.hopharbor.manager.service'
DESKTOP_FILE = 'io.github.kiyanibehzad.HopHarbor.desktop'
GOST_VERSION = '3.3.1'
# Official v3.3.1 checksums.txt. Pin each architecture independently.
GOST_SHA256 = {
    'amd64': 'e0e3a2c9116e2f025e962bba340749f80696bda318613d45e5ae96dd0bcae37c',
    'arm64': 'c58af4a74362a95caa7f580817ad624497d192dfeb60468dc8a4c70c293c6b01',
}
APP_FILES = ('manager.py', 'ssh_hop.py', 'askpass.py', 'log_policy.py',
             'wake_monitor.py', 'credentials.py', 'agent_environment.py', 'linux_desktop.py', 'install_linux.py')
DEPENDENCIES = ('python3', 'python3-gi', 'gir1.2-gtk-3.0', 'gir1.2-webkit2-4.1',
                'gir1.2-ayatanaappindicator3-0.1', 'gir1.2-secret-1', 'gnome-keyring',
                'openssh-client', 'curl', 'dbus-user-session')
MARKER = '.hopharbor-linux-install'
PACKAGED_APP = Path('/usr/lib/hopharbor')
PACKAGED_UNITS = (Path('/usr/lib/systemd/user') / SERVICE, Path('/lib/systemd/user') / SERVICE)


def xdg_path(variable, fallback):
    value = os.environ.get(variable)
    return Path(value) if value and Path(value).is_absolute() else Path.home() / fallback


def default_data_dir():
    return xdg_path('XDG_DATA_HOME', '.local/share') / 'hopharbor'


def user_unit_path():
    return xdg_path('XDG_CONFIG_HOME', '.config') / 'systemd' / 'user' / SERVICE


def service_properties():
    """Inspect this user unit without starting, stopping or enabling anything."""
    result = run(['systemctl', '--user', 'show', SERVICE, '--property=FragmentPath',
                  '--property=LoadState', '--property=MainPID'], check=False)
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if result.returncode or values.get('LoadState') not in ('loaded', 'not-found'):
        raise ValueError('Cannot verify the current HopHarbor user service. Check your desktop user systemd session.')
    fragment = values.get('FragmentPath', '')
    if values['LoadState'] == 'loaded' and not fragment:
        raise ValueError('The selected HopHarbor service has no verifiable unit file.')
    return {'fragment': Path(fragment).resolve() if fragment else None,
            'pid': int(values.get('MainPID', '0'))}


def manager_default_data_dir():
    """Resolve the packaged service's future XDG path from its user manager."""
    result = run(['systemctl', '--user', 'show-environment'])
    value = None
    for line in result.stdout.splitlines():
        if line.startswith('XDG_DATA_HOME='):
            try:
                words = shlex.split(line)
            except ValueError:
                raise ValueError('Cannot verify the user manager XDG data directory.')
            if len(words) != 1:
                raise ValueError('Cannot verify the user manager XDG data directory.')
            value = words[0].split('=', 1)[1]
    base = Path(value) if value and Path(value).is_absolute() else Path.home() / '.local/share'
    return (base / 'hopharbor').resolve()


def verify_running_identity(pid, app, data):
    if not pid:
        return
    try:
        words = (Path('/proc') / str(pid) / 'cmdline').read_bytes().decode().split('\0')
        actual_app = Path(words[words.index('--app-dir') + 1]).resolve()
        actual_data = Path(words[words.index('--data-dir') + 1]).resolve()
        entry = Path(words[1]).resolve()
    except (OSError, ValueError, IndexError, UnicodeError) as error:
        raise ValueError('The running HopHarbor controller identity cannot be verified; no service was changed.') from error
    if entry != app / 'manager.py' or actual_app != app or actual_data != data:
        raise ValueError('The running HopHarbor controller uses a different application or data directory; no service was changed.')


def guard_installation(app, data, purpose, properties=None):
    """Require the exact installation scope and configuration before any mutation."""
    app, data = Path(app).resolve(), Path(data).resolve()
    properties = service_properties() if properties is None else properties
    fragment = Path(properties['fragment']).resolve() if properties['fragment'] else None
    unit = user_unit_path()
    packaged = app == PACKAGED_APP.resolve()
    if purpose == 'install' and (packaged or fragment in {path.resolve() for path in PACKAGED_UNITS}
                                 or any(path.exists() for path in PACKAGED_UNITS)):
        raise ValueError('A packaged HopHarbor installation is present. Use apt to update/remove it before installing from source.')
    if packaged:
        if purpose not in ('launch', 'run-service'):
            raise ValueError('Manage the packaged application with apt; no service was changed.')
        if unit.exists() or fragment not in {path.resolve() for path in PACKAGED_UNITS}:
            raise ValueError('A per-user or different service overrides the packaged installation. Use its matching launcher or remove it first.')
        if data != default_data_dir().resolve() or data != manager_default_data_dir().resolve():
            raise ValueError('The packaged service and launcher use different XDG data directories. Align their desktop-session environment first.')
        expected = service_text()
        selected = fragment
    else:
        expected = service_text(app, data)
        selected = unit
        if unit.is_symlink():
            raise ValueError('Refusing to manage a symlinked user service unit.')
        if fragment is not None and fragment != unit.resolve():
            raise ValueError('A different HopHarbor service is selected. Remove that installation before changing installation scope.')
        if not unit.exists():
            if purpose != 'install' or fragment is not None:
                raise ValueError('No matching per-user service exists for this application and data directory.')
            if properties.get('pid'):
                raise ValueError('A running HopHarbor controller has no matching user unit; no service was changed.')
            return
    if selected is None or not selected.is_file() or selected.read_text() != expected:
        raise ValueError('The HopHarbor user service belongs to a different application/data directory or has been modified. Use its matching installation; no service was changed.')
    if not packaged and purpose in ('launch', 'uninstall') and not (app / MARKER).is_file():
        raise ValueError('No recognized per-user application exists for this data directory.')
    if not (purpose == 'run-service' and properties.get('pid') == os.getpid()):
        verify_running_identity(properties.get('pid', 0), app, data)


def architecture(machine=None):
    value = machine or platform.machine()
    aliases = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}
    if value not in aliases:
        raise ValueError('Ubuntu builds support amd64 and arm64 only.')
    return aliases[value]


def run(command, check=True):
    return subprocess.run([str(item) for item in command], check=check,
                          capture_output=True, text=True, timeout=45)


def fetch_gost(target, arch, archive_path=None):
    """Verify all bytes before extracting only the executable and license."""
    if arch not in GOST_SHA256:
        raise ValueError('Unsupported GOST architecture.')
    artifact = 'gost_%s_linux_%s.tar.gz' % (GOST_VERSION, arch)
    url = 'https://github.com/go-gost/gost/releases/download/v%s/%s' % (GOST_VERSION, artifact)
    data = Path(archive_path).read_bytes() if archive_path else urllib.request.urlopen(url, timeout=60).read()
    if hashlib.sha256(data).hexdigest() != GOST_SHA256[arch]:
        raise ValueError('GOST release digest does not match the pinned official release.')
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    found = False
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            name = Path(member.name).name
            if name == 'gost':
                target.write_bytes(archive.extractfile(member).read())
                target.chmod(0o755)
                found = True
            elif name.lower().startswith('license'):
                (target.parent / 'GOST-LICENSE').write_bytes(archive.extractfile(member).read())
    if not found:
        raise ValueError('The verified GOST archive contains no executable.')
    return {'name': 'GOST', 'version': GOST_VERSION, 'url': url, 'sha256': GOST_SHA256[arch]}


def copy_app(destination, prepared_gost, provenance, public=False):
    """Copy an explicit public allowlist; never include the checkout or runtime."""
    destination = Path(destination)
    destination.mkdir(parents=True, mode=0o755 if public else 0o700)
    for name in APP_FILES:
        shutil.copyfile(ROOT / name, destination / name)
        (destination / name).chmod(0o755)
    for folder in ('web', 'assets', 'bin'):
        (destination / folder).mkdir(mode=0o755)
    for name in ('index.html', 'app.js'):
        shutil.copyfile(ROOT / 'web' / name, destination / 'web' / name)
        (destination / 'web' / name).chmod(0o644)
    for name in ('HopHarbor.svg', 'HopHarbor-1024.png', 'hopharbor-symbolic.svg'):
        source = ROOT / 'packaging' / 'assets' / name
        if source.is_file():
            shutil.copyfile(source, destination / 'assets' / name)
            (destination / 'assets' / name).chmod(0o644)
    shutil.copyfile(prepared_gost, destination / 'bin' / 'gost')
    (destination / 'bin' / 'gost').chmod(0o755)
    license_path = Path(prepared_gost).parent / 'GOST-LICENSE'
    if license_path.is_file():
        shutil.copyfile(license_path, destination / 'bin' / 'GOST-LICENSE')
        (destination / 'bin' / 'GOST-LICENSE').chmod(0o644)
    (destination / 'THIRD-PARTY.json').write_text(json.dumps(provenance, indent=2) + '\n')
    (destination / 'THIRD-PARTY.json').chmod(0o644)
    (destination / MARKER).write_text('HopHarbor Linux application files\n')
    (destination / MARKER).chmod(0o644)


def unit_arg(value):
    value = str(value)
    if any(char in value for char in '\r\n\0'):
        raise ValueError('An installation path contains invalid characters.')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'


def service_text(app=None, data=None):
    if app is None:
        command = '/usr/bin/python3 /usr/lib/hopharbor/install_linux.py --run-service'
    else:
        app, data = Path(app).resolve(), Path(data).resolve()
        command = '/usr/bin/python3 %s --data-dir %s --app-dir %s --port 17777' % (
            unit_arg(Path(app) / 'manager.py'), unit_arg(data), unit_arg(app))
    return '''# HopHarbor Linux user service
[Unit]
Description=HopHarbor SSH proxy manager
After=graphical-session-pre.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
KillMode=control-group
UMask=0077
LimitNOFILE=8192
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=%%t/bus
StandardOutput=null
StandardError=null

[Install]
WantedBy=default.target
''' % command


def desktop_arg(value):
    value = str(value)
    if any(char in value for char in '\r\n\0'):
        raise ValueError('An installation path contains invalid characters.')
    for char in ('\\', '"', '`', '$'):
        value = value.replace(char, '\\' + char)
    return '"' + value.replace('%', '%%') + '"'


def desktop_text(command, background=False, icon='hopharbor'):
    return '''[Desktop Entry]
Type=Application
Name=HopHarbor
Comment=SSH SOCKS and HTTP port forwarding
Exec=%s%s
Icon=%s
Terminal=false
Categories=Network;Utility;
StartupWMClass=HopHarbor
X-GNOME-Autostart-enabled=true
''' % (command, ' --background' if background else '', icon)


def initialize_data(data):
    data = Path(data)
    data.mkdir(parents=True, exist_ok=True, mode=0o700)
    data.chmod(0o700)
    config = data / 'config.json'
    if not config.exists():
        with config.open('x') as handle:
            json.dump({'servers': [], 'tunnels': [], 'migration': {
                'phase': 'setup', 'message': 'Add Sessions and Port Forwarding. Credentials use the desktop keyring.'}}, handle, indent=2)
    config.chmod(0o600)
    known = data / 'known_hosts'
    known.touch(mode=0o600, exist_ok=True)
    known.chmod(0o600)


def require_desktop_dependencies():
    probe = '''import gi
gi.require_version('Gtk', '3.0')
gi.require_version('WebKit2', '4.1')
gi.require_version('AyatanaAppIndicator3', '0.1')
gi.require_version('Secret', '1')
from gi.repository import Gtk, WebKit2, AyatanaAppIndicator3, Secret
'''
    try:
        run(['/usr/bin/python3', '-c', probe])
        for program in ('ssh', 'curl', 'systemctl'):
            if not shutil.which(program):
                raise OSError('Missing command: ' + program)
        run(['systemctl', '--user', 'show-environment'])
    except (OSError, subprocess.SubprocessError) as error:
        raise SystemExit('Install the Ubuntu dependencies first: sudo apt install ' +
                         ' '.join(DEPENDENCIES) + '\nRun the installer from your logged-in desktop session.') from error


def launch_panel(data, app, background=False):
    guard_installation(app, data, 'launch')
    from agent_environment import write_agent_environment
    write_agent_environment(data, os.environ)
    # Refresh only this user manager's graphical/agent environment, without logging values.
    names = [name for name in ('DISPLAY', 'WAYLAND_DISPLAY', 'SSH_AUTH_SOCK', 'XAUTHORITY') if name in os.environ]
    if names:
        run(['systemctl', '--user', 'import-environment'] + names)
    run(['systemctl', '--user', 'start', SERVICE])
    command = ['/usr/bin/python3', str(app / 'linux_desktop.py'), '--data-dir', str(data), '--app-dir', str(app)]
    if background:
        command.append('--background')
    os.execv(command[0], command)


def install(data, no_start=False, no_autostart=False, archive_path=None):
    app = data / 'app'
    guard_installation(app, data, 'install')
    if app.exists() and not (app / MARKER).is_file():
        raise ValueError('Refusing to replace an unrecognized application directory.')
    require_desktop_dependencies()
    arch = architecture()
    # Complete download, verification and staging before stopping an existing Linux service.
    with tempfile.TemporaryDirectory(prefix='hopharbor-linux-') as temporary:
        staged = Path(temporary)
        provenance = fetch_gost(staged / 'gost', arch, archive_path)
        copy_app(staged / 'app', staged / 'gost', provenance)
        initialize_data(data)
        unit = user_unit_path()
        new_app = data / '.app-prepared'
        old_app = data / '.app-previous'
        if new_app.exists() or old_app.exists():
            raise ValueError('A previous update staging directory remains; inspect it before updating.')
        shutil.copytree(staged / 'app', new_app, copy_function=shutil.copyfile)
        old_unit = unit.read_bytes() if unit.exists() else None
        active = run(['systemctl', '--user', 'is-active', '--quiet', SERVICE], check=False).returncode == 0
        moved_old = installed_new = False
        try:
            if active:
                run(['systemctl', '--user', 'stop', SERVICE])
            if app.exists():
                app.rename(old_app)
                moved_old = True
            new_app.rename(app)
            installed_new = True
            unit.parent.mkdir(parents=True, exist_ok=True)
            unit.write_text(service_text(app, data))
            unit.chmod(0o600)
            run(['systemctl', '--user', 'daemon-reload'])
            if not no_start:
                run(['systemctl', '--user', 'enable', '--now', SERVICE])
        except Exception:
            if installed_new and app.exists() and (app / MARKER).exists():
                shutil.rmtree(app)
            if moved_old and old_app.exists():
                old_app.rename(app)
            if old_unit is not None:
                unit.write_bytes(old_unit)
            else:
                unit.unlink(missing_ok=True)
            run(['systemctl', '--user', 'daemon-reload'], check=False)
            if active:
                run(['systemctl', '--user', 'start', SERVICE], check=False)
            raise
        finally:
            if new_app.exists():
                shutil.rmtree(new_app)
        if old_app.exists():
            shutil.rmtree(old_app)
    command = '/usr/bin/python3 %s --launch --data-dir %s' % (
        desktop_arg(app / 'install_linux.py'), desktop_arg(data))
    desktop = xdg_path('XDG_DATA_HOME', '.local/share') / 'applications' / DESKTOP_FILE
    desktop.parent.mkdir(parents=True, exist_ok=True)
    desktop.write_text(desktop_text(command))
    icons = xdg_path('XDG_DATA_HOME', '.local/share') / 'icons' / 'hicolor' / 'scalable' / 'apps'
    icons.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(app / 'assets' / 'HopHarbor.svg', icons / 'hopharbor.svg')
    autostart = xdg_path('XDG_CONFIG_HOME', '.config') / 'autostart' / DESKTOP_FILE
    if not no_autostart:
        autostart.parent.mkdir(parents=True, exist_ok=True)
        autostart.write_text(desktop_text(command, background=True))
    print('Installed HopHarbor for this Ubuntu user. Open HopHarbor from Applications.')
    print('Private data:', data)
    if no_start:
        print('The service has not been started (--no-start). Opening the app starts it.')


def uninstall(data):
    app = data / 'app'
    guard_installation(app, data, 'uninstall')
    unit = user_unit_path()
    run(['systemctl', '--user', 'disable', '--now', SERVICE])
    unit.unlink()
    run(['systemctl', '--user', 'daemon-reload'])
    shutil.rmtree(app)
    for target in (xdg_path('XDG_DATA_HOME', '.local/share') / 'applications' / DESKTOP_FILE,
                   xdg_path('XDG_CONFIG_HOME', '.config') / 'autostart' / DESKTOP_FILE,
                   xdg_path('XDG_DATA_HOME', '.local/share') / 'icons/hicolor/scalable/apps/hopharbor.svg'):
        target.unlink(missing_ok=True)
    print('Application and user service removed. Private configuration and keyring items are preserved.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', type=Path, default=default_data_dir())
    parser.add_argument('--no-start', action='store_true')
    parser.add_argument('--no-autostart', action='store_true')
    parser.add_argument('--gost-archive', type=Path, help='Use a local archive, with the same pinned checksum verification')
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--uninstall', action='store_true')
    actions.add_argument('--run-service', action='store_true', help=argparse.SUPPRESS)
    actions.add_argument('--launch', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--background', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not sys.platform.startswith('linux'):
        raise SystemExit('This installer runs on Ubuntu Linux only. The macOS installation is unchanged.')
    if os.getuid() == 0:
        raise SystemExit('Run this command as your logged-in desktop user, without sudo.')
    os.umask(0o077)
    data = args.data_dir.expanduser().resolve()
    if args.run_service:
        guard_installation(ROOT, data, 'run-service')
        initialize_data(data)
        os.execv('/usr/bin/python3', ['/usr/bin/python3', str(ROOT / 'manager.py'),
                 '--data-dir', str(data), '--app-dir', str(ROOT), '--port', '17777'])
    elif args.launch:
        launch_panel(data, ROOT, args.background)
    elif args.uninstall:
        uninstall(data)
    else:
        install(data, args.no_start, args.no_autostart, args.gost_archive)


if __name__ == '__main__':
    main()
