"""Windows boundary/order tests without touching native APIs on a Unix host."""
import ctypes
import io
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import threading
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import windows_platform as win


class WindowsPathTests(unittest.TestCase):
    def test_local_unicode_spaces_and_forward_slashes_are_unambiguous(self):
        self.assertEqual(win._path('C:/Users/Example User/AppData/Local/HopHarbor'),
                         'C:\\Users\\Example User\\AppData\\Local\\HopHarbor')
        self.assertEqual(win._path('D:\\آزمایش\\data'), 'D:\\آزمایش\\data')

    def test_network_device_ads_and_ambiguous_paths_are_rejected(self):
        values = ['relative', 'C:relative', '\\\\server\\share\\data', '\\\\?\\C:\\data',
                  '\\\\.\\pipe\\data', 'C:\\data\\..\\secret', 'C:\\data\\.\\secret',
                  'C:\\data\\control.json:stream', 'C:\\data\\last.','C:\\data\\last ',
                  'C:\\NUL', 'C:\\data\\CON.txt', 'C:\\COM1.txt', 'C:\\bad\x00file']
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                win._path(value)

    def test_environment_block_is_sorted_unicode_and_rejects_ambiguity(self):
        self.assertEqual(win._environment_block({'Z': 'last', 'A': 'آزمون'}),
                         'A=آزمون\0Z=last\0\0')
        for value in [{'PATH': 'one', 'Path': 'two'}, {'A=B': 'x'}, {'': 'x'},
                      {'A': 'bad\0value'}, {'A\0B': 'x'}, {'A': 42}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                win._environment_block(value)

    @unittest.skipIf(os.name == 'nt', 'Non-Windows inert import contract only')
    def test_native_apis_fail_closed_on_non_windows(self):
        with mock.patch.object(win, '_api_instance', None), self.assertRaises(OSError):
            win._api()

    def test_only_expected_system_executable_names_are_accepted(self):
        with self.assertRaises(ValueError):
            win.system_executable('powershell')


class AclApi:
    def __init__(self, owner='S-1-5-21-test', entries=()):
        self.sid = 'S-1-5-21-test'
        self.owner = owner
        self.entries = []
        self.buffers = []
        for sid, mask, kind, flags in entries:
            raw = ctypes.create_string_buffer(struct.pack('<BBHI', kind, flags, 12, mask) + b'fake')
            self.buffers.append(raw)
            self.entries.append((sid, ctypes.addressof(raw)))
        self.k = types.SimpleNamespace(LocalFree=mock.Mock())
        self.a = types.SimpleNamespace(GetSecurityInfo=self.security, GetAclInformation=self.sizes,
                                       GetAce=self.ace)

    def security(self, handle, kind, bits, owner, group, dacl, sacl, descriptor):
        owner._obj.value = 1; dacl._obj.value = 2; descriptor._obj.value = 3
        return 0

    def sizes(self, dacl, out, size, kind):
        out._obj.AceCount = len(self.entries)
        return 1

    def ace(self, dacl, index, out):
        out._obj.value = self.entries[index][1]
        return 1

    def sid_text(self, pointer):
        if isinstance(pointer, ctypes.c_void_p):
            pointer = pointer.value
        if pointer == 1:
            return self.owner
        return next(sid for sid, address in self.entries if address + 8 == pointer)

    def check(self, value, operation):
        if not value:
            raise OSError(operation)

    def fail(self, operation, code=None):
        raise OSError(operation)


class WindowsAclTests(unittest.TestCase):
    def check_acl(self, entries, private=True, owner='S-1-5-21-test', anchored=False):
        api = AclApi(owner=owner, entries=entries)
        with mock.patch.object(win, '_api', return_value=api):
            win._acl(123, private, anchored_volume_root=anchored)
        api.k.LocalFree.assert_called_once()

    def test_only_user_and_privileged_principals_can_read_private_data(self):
        self.check_acl([('S-1-5-21-test', 0x1F01FF, 0, 0),
                        ('S-1-5-18', 0x1F01FF, 0, 0), ('S-1-5-32-544', 0x1F01FF, 0, 0)])
        with self.assertRaises(ValueError):
            self.check_acl([('S-1-5-21-test', 0x1F01FF, 0, 0), ('S-1-1-0', 0x120089, 0, 0)])

    def test_foreign_owner_and_missing_user_entry_are_rejected(self):
        with self.assertRaises(ValueError):
            self.check_acl([('S-1-5-21-test', 0x1F01FF, 0, 0)], owner='S-1-5-21-other')
        with self.assertRaises(ValueError):
            self.check_acl([('S-1-5-18', 0x1F01FF, 0, 0)])

    def test_parent_traversal_is_allowed_but_external_write_and_ownership_are_rejected(self):
        self.check_acl([('S-1-5-32-545', 0x1200A9, 0, 0)], private=False, owner=win.TRUSTED_INSTALLER)
        for mask in [0x10000, 0x40000, 0x80000, 0x100, 0x10, 0x40, 0x40000000, 0x10000000]:
            with self.subTest(mask=mask), self.assertRaises(ValueError):
                self.check_acl([('S-1-5-32-545', mask, 0, 0)], private=False, owner='S-1-5-18')
        with self.assertRaises(ValueError):
            self.check_acl([], private=False, owner='S-1-5-21-other')

    def test_inherit_only_entries_do_not_grant_current_object_access(self):
        self.check_acl([('S-1-5-21-test', 0x1F01FF, 0, 0), ('S-1-1-0', 0x1F01FF, 0, 8)])

    def test_unknown_ace_type_is_not_assumed_private(self):
        with self.assertRaises(ValueError):
            self.check_acl([('S-1-5-21-test', 0x1F01FF, 9, 0)])

    def test_anchored_root_allows_only_its_metadata_rights(self):
        actual = [('S-1-5-11', 0x1301BF, 0, 0x10)]
        self.check_acl(actual, private=False, owner='S-1-5-18', anchored=True)
        with self.assertRaises(ValueError):
            self.check_acl(actual, private=False, owner='S-1-5-18')
        for mask in [0x40, 0x40000, 0x80000, 0x40000000, 0x10000000]:
            with self.subTest(mask=mask), self.assertRaises(ValueError):
                self.check_acl([('S-1-5-11', mask, 0, 0)], private=False, owner='S-1-5-18', anchored=True)
        with self.assertRaises(ValueError):
            self.check_acl(actual, private=True, anchored=True)


class WindowsVolumeAnchorTests(unittest.TestCase):
    volume = '\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\'

    def api(self, drive_type=3, root=None, child=None):
        values = {10: self.volume if root is None else root,
                  11: self.volume + 'Users' if child is None else child}
        def volume_name(path, target, size):
            target.value = self.volume; return 1
        def final_path(handle, target, size, flags):
            self.assertEqual(flags, 1)
            target.value = values[handle]; return len(target.value)
        return types.SimpleNamespace(
            k=types.SimpleNamespace(GetDriveTypeW=lambda *_: drive_type,
                GetVolumeNameForVolumeMountPointW=volume_name, GetFinalPathNameByHandleW=final_path,
                CompareStringOrdinal=lambda a, _al, b, _bl, _ignore: 2 if a.lower() == b.lower() else 1),
            check=lambda value, _op: self.assertTrue(value), fail=lambda op: self.fail(op))

    def test_fixed_actual_volume_and_exact_direct_child_are_required(self):
        info = types.SimpleNamespace(dwFileAttributes=win.FILE_ATTRIBUTE_DIRECTORY)
        with mock.patch.object(win, '_api', return_value=self.api()), mock.patch.object(win, '_info', return_value=info) as query:
            win._verify_root_anchor(10, 'C:\\', 11, 'Users')
            query.assert_called_once_with(10)
        for options in [{'drive_type': 4}, {'root': self.volume + 'SubstFolder'},
                        {'child': self.volume + 'Elsewhere\\Users'},
                        {'child': '\\\\?\\Volume{abcdefab-1234-1234-1234-123456789abc}\\Users'}]:
            with self.subTest(options=options), mock.patch.object(win, '_api', return_value=self.api(**options)), \
                    mock.patch.object(win, '_info', return_value=info), self.assertRaises(ValueError):
                win._verify_root_anchor(10, 'C:\\', 11, 'Users')
        with mock.patch.object(win, '_api', return_value=self.api()), \
                mock.patch.object(win, '_info', side_effect=ValueError('Reparse point')), self.assertRaises(ValueError):
            win._verify_root_anchor(10, 'C:\\', 11, 'Users')

    def context(self, path, bad_child=False):
        closed, events = [], []
        api = types.SimpleNamespace(k=types.SimpleNamespace(CloseHandle=closed.append))
        def acl(handle, private, anchored_volume_root=False):
            events.append(('acl', handle, anchored_volume_root))
            if handle == 'C:\\' and not anchored_volume_root:
                raise ValueError('Root metadata grant')
            if bad_child and handle != 'C:\\':
                raise ValueError('Unsafe child')
        return api, acl, closed, events

    def test_root_relaxation_waits_for_strict_retained_first_child(self):
        path = 'C:\\Users\\Example\\config.json'
        api, acl, closed, events = self.context(path)
        def verify(root, root_path, child, component):
            events.append(('proof', child))
            self.assertEqual((root, root_path, child, component), ('C:\\', 'C:\\', 'C:\\Users', 'Users'))
            self.assertEqual(closed, [])
        with mock.patch.object(win, '_api', return_value=api), \
                mock.patch.object(win, '_open_handle', side_effect=lambda path: path), \
                mock.patch.object(win, '_info', return_value=types.SimpleNamespace(dwFileAttributes=0x10)), \
                mock.patch.object(win, '_acl', side_effect=acl), mock.patch.object(win, '_verify_root_anchor', side_effect=verify):
            with win._parents(path):
                self.assertEqual(closed, [])
            self.assertEqual(closed, ['C:\\Users\\Example', 'C:\\Users', 'C:\\'])
        self.assertLess(events.index(('acl', 'C:\\Users', False)), events.index(('proof', 'C:\\Users')))
        self.assertLess(events.index(('proof', 'C:\\Users')), events.index(('acl', 'C:\\', True)))
        self.assertIn(('acl', 'C:\\Users\\Example', False), events)

    def test_absent_direct_root_or_unsafe_child_anchor_never_relaxes_acl(self):
        for path, bad_child in [('C:\\new-directory', False), ('C:\\', False), ('C:\\Users\\data', True)]:
            api, acl, closed, events = self.context(path, bad_child)
            with self.subTest(path=path), mock.patch.object(win, '_api', return_value=api), \
                    mock.patch.object(win, '_open_handle', side_effect=lambda path: path), \
                    mock.patch.object(win, '_info', return_value=types.SimpleNamespace(dwFileAttributes=0x10)), \
                    mock.patch.object(win, '_acl', side_effect=acl), mock.patch.object(win, '_verify_root_anchor') as verify:
                with self.assertRaises(ValueError), win._parents(path):
                    self.fail('An unanchored root was accepted.')
                verify.assert_not_called()
                self.assertNotIn(('acl', 'C:\\', True), events)
                self.assertTrue(closed)


class ProcessApi:
    def __init__(self, assignment=True):
        self.events = []; self.assignment = assignment; self.exited = False
        self.k = types.SimpleNamespace(
            CreateJobObjectW=self.create_job, SetInformationJobObject=self.policy,
            CreatePipe=self.pipe, SetHandleInformation=lambda *_: 1,
            CreateFileW=lambda *_: 30, InitializeProcThreadAttributeList=self.attributes,
            UpdateProcThreadAttribute=lambda *_: 1, DeleteProcThreadAttributeList=lambda *_: self.events.append('delete-attributes'),
            CreateProcessW=self.create, AssignProcessToJobObject=self.assign,
            ResumeThread=self.resume, CloseHandle=self.close,
            TerminateProcess=self.terminate, WaitForSingleObject=self.wait,
            GetExitCodeProcess=self.code, TerminateJobObject=self.terminate_job)

    def create_job(self, *_):
        self.events.append('create-job'); return 10

    def policy(self, handle, kind, pointer, size):
        self.events.append('policy'); self.limit_flags = pointer._obj.BasicLimitInformation.LimitFlags
        return 1

    def pipe(self, read, write, *_):
        read._obj.value = 20; write._obj.value = 21; return 1

    def attributes(self, target, count, flags, size):
        size._obj.value = 256; return bool(target)

    def create(self, application, command, pa, ta, inherit, flags, env, cwd, startup, info):
        self.events.append('create-suspended'); self.creation_flags = flags
        self.command = command.value
        info._obj.hProcess = 40; info._obj.hThread = 41
        info._obj.dwProcessId = 12345; info._obj.dwThreadId = 12346
        return 1

    def assign(self, *_):
        self.events.append('assign-job'); return self.assignment

    def resume(self, *_):
        self.events.append('resume'); return 1

    def close(self, handle):
        self.events.append(('close', handle.value if isinstance(handle, ctypes.c_void_p) else handle))
        return 1

    def terminate(self, *_):
        self.events.append('terminate-process'); self.exited = True; return 1

    def terminate_job(self, *_):
        self.events.append('terminate-job'); self.exited = True; return 1

    def wait(self, *_):
        return 0 if self.exited else 0x102

    def code(self, handle, out):
        out._obj.value = 7; return 1

    def check(self, value, operation):
        if not value:
            raise OSError(operation)

    def fail(self, operation, code=None):
        raise OSError(operation)


class WindowsProcessTests(unittest.TestCase):
    def spawn(self, api):
        read, write = os.pipe(); os.close(write)
        self.addCleanup(lambda: self.close_fd(read))
        module = types.SimpleNamespace(open_osfhandle=lambda *_: read)
        with mock.patch.object(win, '_api', return_value=api), \
                mock.patch.object(win.os.path, 'isfile', return_value=True), \
                mock.patch.dict(sys.modules, {'msvcrt': module}), \
                mock.patch.object(win.os, 'O_BINARY', 0, create=True):
            return win.spawn_owned(['C:\\Example App\\ssh.exe', '-F', 'C:\\Private Data\\ssh_config'], env={'A': 'value'})

    @staticmethod
    def close_fd(fd):
        try: os.close(fd)
        except OSError: pass

    def test_child_is_assigned_before_resume_and_job_is_kill_on_close(self):
        api = ProcessApi(); child = self.spawn(api)
        self.addCleanup(child.stdout.close)
        self.assertLess(api.events.index('create-suspended'), api.events.index('assign-job'))
        self.assertLess(api.events.index('assign-job'), api.events.index('resume'))
        self.assertEqual(api.limit_flags, 0x2000)
        self.assertTrue(api.creation_flags & 4)
        self.assertTrue(api.creation_flags & 0x80000)
        self.assertIn('"C:\\Example App\\ssh.exe"', api.command)
        self.assertEqual(child.pid, 12345)
        with mock.patch.object(win, '_api', return_value=api):
            self.assertIsNone(child.poll())
            with self.assertRaises(subprocess.TimeoutExpired): child.wait(.1)
            with self.assertRaises(RuntimeError): child.close()
            child.terminate_group(); self.assertEqual(child.wait(1), 7); child.close()
        self.assertFalse(child.stdout.closed, 'The stderr reader owns its pipe lifetime.')
        self.assertIn(('close', 10), api.events)

    def test_job_assignment_failure_kills_suspended_child_without_resuming(self):
        api = ProcessApi(assignment=False)
        with self.assertRaises(OSError): self.spawn(api)
        self.assertNotIn('resume', api.events)
        self.assertIn('terminate-process', api.events)
        self.assertIn(('close', 10), api.events)

    def test_another_thread_can_terminate_a_job_while_wait_is_blocked(self):
        api = ProcessApi(); child = self.spawn(api)
        self.addCleanup(child.stdout.close)
        entered, release = threading.Event(), threading.Event()
        original_wait, original_terminate = api.k.WaitForSingleObject, api.k.TerminateJobObject
        def wait(handle, milliseconds):
            if milliseconds == 0xFFFFFFFF:
                entered.set(); release.wait(2)
            return original_wait(handle, milliseconds)
        def terminate(*args):
            result = original_terminate(*args); release.set(); return result
        api.k.WaitForSingleObject = wait
        api.k.TerminateJobObject = terminate
        result = []
        with mock.patch.object(win, '_api', return_value=api):
            waiter = threading.Thread(target=lambda: result.append(child.wait()), daemon=True)
            stopper = threading.Thread(target=child.terminate_group, daemon=True)
            waiter.start()
            try:
                self.assertTrue(entered.wait(1))
                stopper.start(); stopper.join(1)
                self.assertFalse(stopper.is_alive(), 'Waiting must not block Job termination.')
                waiter.join(1)
                self.assertEqual(result, [7])
            finally:
                release.set(); waiter.join(3)
                if stopper.ident is not None: stopper.join(3)
                child.kill_group(); child.wait(1); child.close()

    def test_unsupported_stdio_or_shell_style_commands_are_rejected(self):
        with self.assertRaises(ValueError): win.spawn_owned('ssh.exe -N server')
        with self.assertRaises(ValueError): win.spawn_owned(['C:\\ssh.exe'], stdin=subprocess.PIPE)
        with self.assertRaises(ValueError): win.spawn_owned(['C:\\ssh.exe'], close_fds=False)


if __name__ == '__main__':
    unittest.main()
