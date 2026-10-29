#!/usr/bin/python3
"""OpenSSH invokes this helper directly; credentials never pass through a shell."""
import os
from pathlib import Path
import sys
if sys.platform == 'win32':
    import subprocess
    helper = str(Path(__file__).resolve().parent / 'bin' / 'HopHarborHelper.exe')
    raise SystemExit(subprocess.run([helper, 'askpass'] + sys.argv[1:]).returncode)
if sys.platform.startswith('linux'):
    helper = str(Path(__file__).resolve().parent / 'credentials.py')
    os.execv(sys.executable, [sys.executable, helper, 'askpass'] + sys.argv[1:])
helper = str(Path(__file__).resolve().parent / 'bin' / 'keychain-helper')
os.execv(helper, [helper, 'askpass'] + sys.argv[1:])
