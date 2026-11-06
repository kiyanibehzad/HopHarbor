"""Authentication evidence must belong to the current owned SSH generation."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from windows_session import WindowsAuthenticationProof
import windows_session as target


class AuthenticationDirectoryTests(unittest.TestCase):
    def test_collision_does_not_repair_existing_directory(self):
        with tempfile.TemporaryDirectory() as root:
            occupied = Path(root) / ('hh-session-' + 'a' * 32)
            occupied.mkdir(); (occupied / 'keep').write_text('existing')
            def create(path, *, exist_ok):
                self.assertFalse(exist_ok)
                path.mkdir(exist_ok=exist_ok)
            with mock.patch.object(target.native, 'validate_private_directory'), \
                 mock.patch.object(target.native, 'ensure_private_directory', side_effect=create), \
                 mock.patch.object(target.secrets, 'token_hex', side_effect=['a'*32, 'b'*32]):
                directory = target.AuthenticationDirectory(root, 'hh-session-')
                self.assertEqual(Path(directory.name).name, 'hh-session-' + 'b'*32)
                directory.cleanup(); directory.cleanup()
                self.assertEqual((occupied/'keep').read_text(), 'existing')

    def test_failed_cleanup_retains_ownership_for_retry(self):
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.object(target.native, 'validate_private_directory'), \
                 mock.patch.object(target.native, 'ensure_private_directory', side_effect=lambda p, **kw: p.mkdir()):
                directory = target.AuthenticationDirectory(root, 'hh-proof-')
                with mock.patch.object(target.shutil, 'rmtree', side_effect=PermissionError):
                    with self.assertRaises(PermissionError): directory.cleanup()
                self.assertTrue(directory._finalizer.alive)
                directory.cleanup()
                self.assertFalse(Path(directory.name).exists())


class WindowsAuthenticationProofTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.marker = Path(self.temp.name) / 'control'
        self.proof = WindowsAuthenticationProof(self.marker)
        self.child = SimpleNamespace(generation=1, blocked=False, proc=mock.Mock())
        self.child.proc.poll.return_value = None
        for name in ('validate_private_directory', 'validate_private_file'):
            patch = mock.patch.object(target.native, name)
            patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(target.native, 'read_private_json', side_effect=lambda p, max_bytes: json.loads(p.read_bytes()))
        patch.start(); self.addCleanup(patch.stop)

    def marker_for_current(self):
        self.marker.write_text(json.dumps({'nonce': self.proof.nonce, 'generation': self.child.generation}))

    def test_alive_process_and_banner_are_not_authentication(self):
        self.proof.begin(self.child)
        self.child.error = 'Authenticated to target with publickey'
        self.assertFalse(self.proof.ready(self.child))
        self.marker.write_text('{"nonce":"wrong","generation":1}')
        self.assertFalse(self.proof.ready(self.child))

    def test_current_private_nonce_accepted_once_and_removed(self):
        env = self.proof.begin(self.child)
        self.assertEqual(env['HOPHARBOR_AUTH_GENERATION'], '1')
        self.assertEqual(len(env['HOPHARBOR_AUTH_NONCE']), 64)
        self.marker_for_current()
        self.assertTrue(self.proof.ready(self.child))
        self.assertFalse(self.marker.exists())
        self.assertTrue(self.proof.ready(self.child))

    def test_restart_rotates_nonce_and_rejects_late_old_marker(self):
        old = self.proof.begin(self.child)
        self.marker_for_current()
        self.child.generation += 1
        new = self.proof.begin(self.child)
        self.assertNotEqual(old['HOPHARBOR_AUTH_NONCE'], new['HOPHARBOR_AUTH_NONCE'])
        self.assertFalse(self.marker.exists())
        self.marker.write_text(json.dumps({'nonce': old['HOPHARBOR_AUTH_NONCE'], 'generation': 1}))
        self.assertFalse(self.proof.ready(self.child))
        self.marker_for_current()
        self.assertTrue(self.proof.ready(self.child))

    def test_child_death_failure_or_generation_change_revokes_cached_success(self):
        self.proof.begin(self.child); self.marker_for_current()
        self.assertTrue(self.proof.ready(self.child))
        self.child.proc.poll.return_value = 0
        self.assertFalse(self.proof.ready(self.child))
        self.child.proc.poll.return_value = None; self.child.blocked = True
        self.assertFalse(self.proof.ready(self.child))
        self.child.blocked = False; self.child.generation += 1
        self.assertFalse(self.proof.ready(self.child))

    def test_wrong_generation_extra_fields_and_malformed_marker_fail_closed(self):
        self.proof.begin(self.child)
        for value in [{'nonce':self.proof.nonce,'generation':True},
                      {'nonce':'é','generation':1},
                      {'nonce':self.proof.nonce,'generation':2},
                      {'nonce':self.proof.nonce,'generation':1,'path':'anything'}, []]:
            self.marker.write_text(json.dumps(value))
            self.assertFalse(self.proof.ready(self.child))
        self.marker.write_text('{')
        self.assertFalse(self.proof.ready(self.child))

    def test_private_file_validation_failure_rejects_marker(self):
        self.proof.begin(self.child); self.marker_for_current()
        with mock.patch.object(target.native, 'read_private_json', side_effect=ValueError('untrusted ACL/reparse')):
            self.assertFalse(self.proof.ready(self.child))
        with mock.patch.object(target.native, 'validate_private_file', side_effect=ValueError('untrusted ACL/reparse')):
            with self.assertRaises(ValueError): self.proof.begin(self.child)
        self.assertFalse(self.proof.accepted)

    def test_hook_has_no_connection_fields_remote_command_or_listener(self):
        self.assertEqual(WindowsAuthenticationProof.options(), ['-o','PermitLocalCommand=yes','-o',
            'LocalCommand=""%%HOPHARBOR_APP%%\\bin\\HopHarborHelper.exe" session-ready"'])


if __name__ == '__main__': unittest.main()
