#!/usr/bin/python3
"""Run real Linux forwarding/recovery against disposable loopback SSH servers.

Requires an ordinary user in a disposable Ubuntu test VM, openssh-server,
openssl, curl, and a separately checksum-verified Linux GOST executable. Never
runs an installer or uses installed HopHarbor data, server accounts or keys.
"""
import argparse
import importlib.util
import os
import pwd
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gost', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.getuid() == 0:
        raise SystemExit('Run only as an ordinary user in a disposable Linux VM.')
    if not args.gost.is_file() or not os.access(args.gost, os.X_OK):
        raise SystemExit('Supply the separately verified Linux GOST executable.')
    os.umask(0o077)
    spec = importlib.util.spec_from_file_location('linux_forwarding_test', ROOT / 'tests/local_smoke.py')
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    # sshd StrictModes checks every ancestor of AuthorizedKeysFile; /tmp is
    # intentionally world-writable, so keep only these disposable fixtures in
    # the test account's private cache, never its existing SSH directory.
    cache = Path(pwd.getpwuid(os.getuid()).pw_dir) / '.cache'
    cache.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='hopharbor-forwarding-test-', dir=cache) as temporary:
        app = Path(temporary)
        for name in ('manager.py', 'ssh_hop.py', 'askpass.py', 'log_policy.py',
                     'wake_monitor.py', 'credentials.py', 'agent_environment.py'):
            shutil.copyfile(ROOT / name, app / name)
            (app / name).chmod(0o700)
        shutil.copytree(ROOT / 'web', app / 'web')
        (app / 'bin').mkdir()
        shutil.copyfile(args.gost, app / 'bin/gost')
        (app / 'bin/gost').chmod(0o700)
        smoke.ROOT = app
        smoke.RESULT_PATH = args.report.resolve()
        smoke.RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
        return smoke.main()


if __name__ == '__main__':
    sys.exit(main())
