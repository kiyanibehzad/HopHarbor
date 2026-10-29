#!/usr/bin/env python3
"""Opt-in Windows native boundary test with disposable data and credentials only.

Requires a built HopHarborHelper.exe and a Windows Python interpreter. Does not
use personal Sessions, production servers, an existing keyring item, network
listeners, service settings or user SSH keys. Every credential ID is random.
"""
import argparse
import base64
import contextlib
import ctypes
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import threading
import time
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', required=True, type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if os.name != 'nt':
        raise SystemExit('Run only inside the isolated Windows test environment.')
    import windows_platform as native
    helper = args.helper.resolve()
    if not helper.is_file():
        raise SystemExit('Supply the separately built native helper.')
    marker = uuid.uuid4().hex
    ident = 'native_test_' + marker
    directory = Path(os.environ['LOCALAPPDATA']) / ('HopHarborNativeTest-' + marker)
    checks = []
    report = {'test': 'windows-native-boundaries', 'personal_settings_used': False,
              'remote_connections': False, 'checks': checks, 'ok': False}

    def call(mode, body=None, extra=(), env=None):
        return subprocess.run([str(helper), mode, *extra],
                              input=None if body is None else json.dumps(body, ensure_ascii=False),
                              capture_output=True, text=True, encoding='utf-8', timeout=15,
                              env=env, creationflags=subprocess.CREATE_NO_WINDOW)

    def json_call(mode, body=None, extra=()):
        reply = call(mode, body, extra)
        if reply.returncode:
            raise AssertionError('Native helper operation failed: ' + mode)
        value = json.loads(reply.stdout)
        assert value.get('ok') is True
        return value

    def reject(operation):
        try:
            operation()
        except (OSError, ValueError, RuntimeError):
            return
        raise AssertionError('Unsafe fixture was accepted')

    def running(pid):
        api = ctypes.WinDLL('kernel32', use_last_error=True)
        api.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int32, ctypes.c_uint32]
        api.OpenProcess.restype = ctypes.c_void_p
        api.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        api.WaitForSingleObject.restype = ctypes.c_uint32
        api.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = api.OpenProcess(0x100000, False, pid)
        if not handle:
            if ctypes.get_last_error() == 87:
                return False
            raise OSError('Could not verify the synthetic process state')
        try:
            return api.WaitForSingleObject(handle, 0) == 0x102
        finally:
            api.CloseHandle(handle)

    try:
        native.ensure_private_directory(directory)
        prepared = directory / 'prepared'
        json_call('prepare', extra=('--data-dir', str(prepared)))
        native.validate_private_directory(prepared)
        control = {'port': 21897, 'token': 'synthetic-control-token-' + marker}
        native.atomic_json(prepared / 'control.json', control)
        assert native.read_private_json(prepared / 'control.json') == control
        checked = json_call('control', extra=('--data-dir', str(prepared)))
        assert checked['port'] == control['port'] and checked['token'] == control['token']
        checks.append('private directory, atomic JSON and native control bootstrap')
        with native.ServiceLock(prepared / '.service.lock'):
            reject(lambda: native.ServiceLock(prepared / '.service.lock'))
        with native.ServiceLock(prepared / '.service.lock'):
            pass
        checks.append('exclusive lock rejects a second controller and releases cleanly')

        public = prepared / 'public-fixture.txt'
        native.atomic_write(public, 'Synthetic nonsecret ACL test fixture')
        icacls = Path(native.system_executable('curl')).with_name('icacls.exe')
        result = subprocess.run([str(icacls), str(public), '/grant', '*S-1-1-0:(R)'],
                                capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode == 0
        reject(lambda: native.validate_private_file(public))
        public.unlink()
        checks.append('an Everyone-readable synthetic file is rejected')

        first, second = prepared / 'first.txt', prepared / 'second.txt'
        native.atomic_write(first, 'Synthetic hardlink fixture')
        os.link(first, second)
        reject(lambda: native.validate_private_file(first))
        second.unlink(); first.unlink()
        checks.append('additional hardlinks are rejected')

        target, junction = prepared / 'junction-target', prepared / 'junction'
        native.ensure_private_directory(target)
        script = 'New-Item -ItemType Junction -Path $env:HH_TEST_LINK -Target $env:HH_TEST_TARGET -ErrorAction Stop | Out-Null'
        encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
        powershell = Path(native.system_executable('curl')).parent / 'WindowsPowerShell/v1.0/powershell.exe'
        env = dict(os.environ, HH_TEST_LINK=str(junction), HH_TEST_TARGET=str(target))
        result = subprocess.run([str(powershell), '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                                env=env, capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode == 0
        reject(lambda: native.validate_private_directory(junction))
        junction.rmdir(); target.rmdir()
        checks.append('a directory junction is rejected without following it')

        empty = json_call('has', {'server_id': ident})
        assert not empty['has_password'] and not empty['has_key_passphrase']
        password, passphrase = 'synthetic-password-' + marker, 'synthetic-passphrase-آزمون-' + marker
        stored = json_call('put', {'server_id': ident, 'password': password, 'key_passphrase': passphrase})
        assert stored['has_password'] and stored['has_key_passphrase']
        assert password not in json.dumps(stored) and passphrase not in json.dumps(stored)
        env = dict(os.environ, PM_SERVER_ID=ident)
        for mode, prompt, expected in [('askpass', 'SSH password:', password),
                                        ('askpass', 'Enter passphrase for synthetic key:', passphrase)]:
            reply = call(mode, extra=(prompt,), env=env)
            assert reply.returncode == 0 and reply.stdout == expected + '\n'
        default = call('SSH password:', env=env)
        assert default.returncode == 0 and default.stdout == password + '\n'
        checks.append('Credential Manager separation, Unicode passphrase and native/default askpass')

        boundary = 'x' * 1022
        json_call('put', {'server_id': ident, 'password': boundary})
        reply = call('askpass', extra=('SSH password:',), env=env)
        assert reply.returncode == 0 and reply.stdout == boundary + '\n'
        json_call('put', {'server_id': ident, 'password': password})
        for value in ['bad\nsecret', 'bad\x00secret', 'a' * 1023, 'آ' * 512, 'a' * 2561]:
            assert call('put', {'server_id': ident, 'password': value}).returncode != 0
        for prompt in ['Host key verification (yes/no)?', 'Verification code:', 'OTP password:']:
            reply = call('askpass', extra=(prompt,), env=env)
            assert reply.returncode != 0 and reply.stdout == ''
        unchanged = call('askpass', extra=('SSH password:',), env=env)
        assert unchanged.stdout == password + '\n'
        assert not any(password.encode() in path.read_bytes() or passphrase.encode() in path.read_bytes()
                       for path in prepared.rglob('*') if path.is_file())
        checks.append('invalid/oversized secrets and host/OTP prompts fail closed; no plaintext files')
        deleted = json_call('delete', {'server_id': ident})
        assert not deleted['has_password'] and not deleted['has_key_passphrase']
        assert call('askpass', extra=('SSH password:',), env=env).stdout == ''
        checks.append('deletion removes only the random test credential namespace')

        program = ('import subprocess,sys,time;'
                   'p=subprocess.Popen([sys.executable,"-B","-c","import time;time.sleep(60)"]);'
                   'print(p.pid,flush=True);time.sleep(60)')
        owned = native.spawn_owned([sys.executable, '-B', '-c', program], env=dict(os.environ))
        read = queue.Queue()
        threading.Thread(target=lambda: read.put(owned.stdout.readline(100)), daemon=True).start()
        try:
            descendant = int(read.get(timeout=10).strip())
            assert running(descendant)
            owned.terminate_group(); owned.wait(timeout=5); owned.close()
            deadline = time.monotonic() + 3
            while running(descendant) and time.monotonic() < deadline:
                time.sleep(.05)
            assert not running(descendant)
        finally:
            with contextlib.suppress(Exception):
                owned.kill_group(); owned.wait(timeout=3); owned.close()
            owned.stdout.close()
        checks.append('owned Job stops its parent and descendant without arbitrary PID killing')

        code = ('import sys,os;sys.path.insert(0,sys.argv[1]);import windows_platform as w;'
                'p=w.spawn_owned([sys.executable,"-B","-c","import time;time.sleep(60)"]);'
                'print(p.pid,flush=True);os._exit(0)')
        crashed = subprocess.run([sys.executable, '-B', '-c', code, str(ROOT)], capture_output=True,
                                 text=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
        assert crashed.returncode == 0
        managed_pid = int(crashed.stdout.strip())
        deadline = time.monotonic() + 3
        while running(managed_pid) and time.monotonic() < deadline:
            time.sleep(.05)
        assert not running(managed_pid)
        checks.append('controller exit closes the Job and leaves no managed process')
        report['ok'] = True
    except Exception as error:
        report['error'] = type(error).__name__
        # This opt-in harness uses random, synthetic data only; its report is a
        # private local diagnostic, never an application log or release asset.
        report['message'] = str(error)
        report['traceback'] = traceback.format_exc(limit=8)
    finally:
        with contextlib.suppress(Exception):
            call('delete', {'server_id': ident})
        with contextlib.suppress(Exception):
            shutil.rmtree(directory)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
