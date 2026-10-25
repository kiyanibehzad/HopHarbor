#!/usr/bin/python3
"""Give each native OpenSSH jump process the correct local Keychain identity."""
import argparse
import os
from pathlib import Path
import re

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--data-dir', required=True)
    p.add_argument('--app-dir', required=True)
    p.add_argument('--server', required=True)
    p.add_argument('--host', required=True)
    p.add_argument('--port', required=True, type=int)
    a = p.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', a.server) or not 1 <= a.port <= 65535:
        raise SystemExit(1)
    if any(c.isspace() or ord(c) < 33 for c in a.host) or a.host.startswith('-'):
        raise SystemExit(1)
    os.environ.update(PM_SERVER_ID=a.server, PM_DATA_DIR=str(Path(a.data_dir).resolve()),
                      SSH_ASKPASS=str(Path(a.app_dir).resolve() / 'askpass.py'),
                      SSH_ASKPASS_REQUIRE='force', DISPLAY='HopHarbor', LC_ALL='C')
    target = '[%s]:%s' % (a.host, a.port) if ':' in a.host else '%s:%s' % (a.host, a.port)
    os.execv('/usr/bin/ssh', ['/usr/bin/ssh', '-F', str(Path(a.data_dir).resolve() / 'ssh_config'),
                             '-W', target, 'pm_' + a.server])

if __name__ == '__main__':
    main()
