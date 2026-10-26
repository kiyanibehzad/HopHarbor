#!/usr/bin/python3
"""Install HopHarbor for the current macOS user, without sudo."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import resource
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parent
LABEL = 'local.hopharbor.manager'
GOST_VERSION = '3.3.1'
GOST_SHA256 = '6b87b8c5fd728536d1b208382fc6b93a7bb04111d633a9f1e4651cd1ce62886d'


def run(args, check=True):
    return subprocess.run([str(x) for x in args], check=check)


def bootstrap_service(domain, agent):
    """Allow launchd's transient exit 5 to settle, with five seconds of retry delays."""
    command = ['/bin/launchctl', 'bootstrap', domain, str(agent)]
    for delay in (0, .5, 1, 1.5, 2):
        if delay:
            time.sleep(delay)
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=10)
        if result.returncode != 5:
            break
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    result.check_returncode()
    return result


def file_limit_plan(hard_limit, kernel_limit):
    """Request a larger soft limit without changing the inherited hard limit."""
    if (isinstance(hard_limit, bool) or not isinstance(hard_limit, int)
            or isinstance(kernel_limit, bool) or not isinstance(kernel_limit, int)
            or kernel_limit < 1):
        return {}
    ceilings = [8192, kernel_limit]
    if hard_limit != resource.RLIM_INFINITY:
        if hard_limit < 1:
            return {}
        ceilings.append(hard_limit)
    return {'SoftResourceLimits': {'NumberOfFiles': min(ceilings)}}


def launch_agent_resource_limits():
    """Discover local ceilings read-only; omit an uncertain launchd setting."""
    try:
        _, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        result = subprocess.run(['/usr/sbin/sysctl', '-n', 'kern.maxfilesperproc'],
                                capture_output=True, text=True, check=True, timeout=5)
        return file_limit_plan(hard_limit, int(result.stdout.strip()))
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}


def refresh_app_registration(bundle):
    """Refresh only this installed bundle; leave Finder, Dock and global caches alone."""
    os.utime(bundle, None)
    registrar = Path('/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister')
    if registrar.is_file():
        result = run([registrar, '-f', bundle], check=False)
        if result.returncode:
            print('The app was installed, but its LaunchServices registration could not be refreshed.')
    os.utime(bundle, None)


def fetch_gost(target):
    artifact = 'gost_%s_darwin_arm64.tar.gz' % GOST_VERSION
    url = 'https://github.com/go-gost/gost/releases/download/v%s/%s' % (GOST_VERSION, artifact)
    cached = ROOT / 'vendor' / artifact
    data = cached.read_bytes() if cached.exists() else urllib.request.urlopen(url, timeout=60).read()
    if hashlib.sha256(data).hexdigest() != GOST_SHA256:
        raise RuntimeError('GOST release digest does not match the pinned official release')
    import io
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive.getmembers():
            name = Path(member.name).name
            if not member.isfile():
                continue
            if name == 'gost':
                target.write_bytes(archive.extractfile(member).read())
                target.chmod(0o700)
            elif name.lower().startswith('license'):
                (target.parent / 'GOST-LICENSE').write_bytes(archive.extractfile(member).read())
    if not target.exists():
        raise RuntimeError('The official release contains no GOST executable')
    return {'name': 'GOST', 'version': GOST_VERSION, 'url': url, 'sha256': GOST_SHA256}


@contextmanager
def prepare_upgrade(target):
    """Finish the verified download before stopping a service providing Internet."""
    with tempfile.TemporaryDirectory(prefix='hopharbor-upgrade-') as directory:
        prepared = Path(directory)
        provenance = fetch_gost(prepared / 'gost')
        run(['/bin/launchctl', 'bootout', target], check=False)
        yield prepared, provenance


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-start', action='store_true')
    parser.add_argument('--uninstall', action='store_true')
    parser.add_argument('--data-dir', type=Path, default=Path.home() / 'Library/Application Support/HopHarbor')
    args = parser.parse_args()
    if sys.platform != 'darwin' or platform.machine() != 'arm64':
        raise SystemExit('This first release supports Apple Silicon macOS only.')
    if os.getuid() == 0:
        raise SystemExit('Run this installer as your ordinary macOS user, without sudo.')
    os.umask(0o077)
    data = args.data_dir.expanduser().resolve()
    agent = Path.home() / 'Library/LaunchAgents' / (LABEL + '.plist')
    bundle = Path.home() / 'Applications/HopHarbor.app'
    target = 'gui/%s/%s' % (os.getuid(), LABEL)
    if args.uninstall:
        run(['/bin/launchctl', 'bootout', target], check=False)
        agent.unlink(missing_ok=True)
        if bundle.exists():
            info = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
            if info.get('CFBundleIdentifier') != LABEL:
                raise SystemExit('Refusing to remove an unrelated app bundle')
            shutil.rmtree(bundle)
        print('HopHarbor service and app removed. Configuration and Keychain entries are preserved.')
        return
    if not Path('/usr/bin/python3').exists() or not Path('/usr/bin/xcrun').exists():
        raise SystemExit('Install Apple Command Line Tools first: xcode-select --install')
    run(['/usr/bin/xcrun', '--find', 'swiftc'])
    with prepare_upgrade(target) as (prepared, provenance):
        data.mkdir(parents=True, exist_ok=True, mode=0o700)
        data.chmod(0o700)
        app = data / 'app'
        app.mkdir(mode=0o700, exist_ok=True)
        for name in ('manager.py', 'ssh_hop.py', 'askpass.py', 'log_policy.py', 'wake_monitor.py'):
            shutil.copyfile(ROOT / name, app / name)
            (app / name).chmod(0o700)
        (app / 'web').mkdir(mode=0o700, exist_ok=True)
        for name in ('index.html', 'app.js'):
            shutil.copyfile(ROOT / 'web' / name, app / 'web' / name)
            (app / 'web' / name).chmod(0o600)
        (app / 'bin').mkdir(mode=0o700, exist_ok=True)
        shutil.copyfile(prepared / 'gost', app / 'bin/gost')
        (app / 'bin/gost').chmod(0o700)
        if (prepared / 'GOST-LICENSE').is_file():
            shutil.copyfile(prepared / 'GOST-LICENSE', app / 'bin/GOST-LICENSE')
        (app / 'THIRD-PARTY.json').write_text(json.dumps(provenance, indent=2))
    # The builder preserves an unchanged verified helper and its Keychain access approval.
    run(['/usr/bin/python3', ROOT / 'packaging/build_helper.py', '--output', app / 'bin/keychain-helper'])
    run(['/usr/bin/python3', ROOT / 'packaging/build_app.py', '--output', bundle, '--data-dir', data])
    refresh_app_registration(bundle)
    if not (data / 'config.json').exists():
        (data / 'config.json').write_text(json.dumps({'servers': [], 'tunnels': [], 'migration': {
            'phase': 'setup', 'message': 'Add sessions and port forwards. Credentials are stored in macOS Keychain.'}}, ensure_ascii=False, indent=2))
    (data / 'config.json').chmod(0o600)
    if not (data / 'known_hosts').exists():
        (data / 'known_hosts').touch(mode=0o600)
    logs = data / 'logs'
    logs.mkdir(mode=0o700, exist_ok=True)
    agent.parent.mkdir(parents=True, exist_ok=True)
    definition = {
        'Label': LABEL,
        'ProgramArguments': ['/usr/bin/python3', str(app / 'manager.py'), '--data-dir', str(data), '--app-dir', str(app), '--port', '17777'],
        'RunAtLoad': True, 'KeepAlive': True, 'ThrottleInterval': 10,
        'ProcessType': 'Background', 'LowPriorityIO': True, 'Umask': 63,
        # The controller installs its own bounded streams; inherited FD writes are discarded.
        'StandardOutPath': '/dev/null',
        'StandardErrorPath': '/dev/null',
    }
    definition.update(launch_agent_resource_limits())
    agent.write_bytes(plistlib.dumps(definition))
    agent.chmod(0o600)
    run(['/usr/bin/plutil', '-lint', agent])
    if not args.no_start:
        bootstrap_service('gui/%s' % os.getuid(), agent)
    print('Installed:', bundle)
    print('Private configuration:', data)
    print('Background service:', agent)
    if args.no_start:
        print('Service was not started (--no-start).')
    else:
        print('Open HopHarbor from your Applications folder. No tunnel is created by the public default configuration.')


if __name__ == '__main__':
    main()
