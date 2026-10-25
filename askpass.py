#!/usr/bin/python3
"""OpenSSH invokes this helper directly; credentials never pass through a shell."""
import os
from pathlib import Path
import sys
helper = str(Path(__file__).resolve().parent / 'bin' / 'keychain-helper')
os.execv(helper, [helper, 'askpass'] + sys.argv[1:])
