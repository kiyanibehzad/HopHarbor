"""Platform boundaries and Linux credential protocol; never touches a real keyring."""
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_security import bare_manager, pm
import credentials
import wake_monitor


class MemoryStore:
    def __init__(self):
        self.values = {}

    def has(self, kind, ident):
        return (kind, ident) in self.values

    def read(self, kind, ident):
        return self.values[(kind, ident)]

    def put(self, kind, ident, value):
        self.values[(kind, ident)] = value

    def delete(self, kind, ident):
        self.values.pop((kind, ident), None)


class CredentialProtocolTests(unittest.TestCase):
    def invoke(self, argv, body=None, store=None, environ=None):
        output = io.StringIO()
        code = credentials.main(argv=argv,
                                stdin=io.BytesIO(json.dumps(body).encode() if body is not None else b''),
                                stdout=output, store_factory=lambda: store,
                                environ=environ or {})
        return code, output.getvalue()

    def test_password_and_key_passphrase_have_separate_items_and_never_appear_in_status(self):
        store = MemoryStore()
        body = {'server_id': 'demo', 'password': 'synthetic-server-secret',
                'key_passphrase': 'synthetic-key-secret'}
        code, output = self.invoke(['put'], body, store)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output), {'ok': True, 'has_password': True,
                                             'has_key_passphrase': True})
        self.assertNotIn('synthetic', output)
        for prompt, expected in [("demo@example.invalid's password: ", body['password']),
                                 ('Enter passphrase for key /synthetic/key: ', body['key_passphrase'])]:
            code, output = self.invoke(['askpass', prompt], store=store,
                                       environ={'PM_SERVER_ID': 'demo'})
            self.assertEqual(code, 0)
            self.assertEqual(output, expected + '\n')
        code, output = self.invoke(['delete'], {'server_id': 'demo'}, store)
        self.assertEqual(code, 0)
        self.assertEqual(store.values, {})
        self.assertFalse(json.loads(output)['has_password'])

    def test_invalid_requests_are_rejected_before_contacting_the_keyring(self):
        cases = [{'server_id': '../other', 'password': 'value'},
                 {'server_id': 'demo', 'password': ''},
                 {'server_id': 'demo', 'password': 'a\nb'},
                 {'server_id': 'demo', 'password': 'a\0b'},
                 {'server_id': 'demo', 'key_passphrase': 'é' * 4097},
                 {'server_id': 'demo'}, ['not-an-object']]
        for body in cases:
            with self.subTest(body=repr(body)[:80]):
                factory = mock.Mock(side_effect=AssertionError('Keyring must not be contacted'))
                output = io.StringIO()
                code = credentials.main(['put'], io.BytesIO(json.dumps(body).encode()),
                                        output, factory, {})
                self.assertEqual(code, 1)
                self.assertFalse(json.loads(output.getvalue())['ok'])
                factory.assert_not_called()

    def test_host_confirmation_and_otp_prompts_are_never_answered(self):
        for prompt in ['Are you sure you want to continue connecting (yes/no/[fingerprint])?',
                       'Enter verification code:', 'Host key password confirmation:', '']:
            with self.subTest(prompt=prompt):
                factory = mock.Mock()
                output = io.StringIO()
                code = credentials.main(['askpass', prompt], io.BytesIO(), output,
                                        factory, {'PM_SERVER_ID': 'demo'})
                self.assertEqual(code, 1)
                self.assertEqual(output.getvalue(), '')
                factory.assert_not_called()

    def test_unavailable_keyring_does_not_print_prompt_or_exception(self):
        factory = mock.Mock(side_effect=RuntimeError('private diagnostic must not be printed'))
        for mode, argv in [('askpass', ['askpass', 'private-host password:']), ('has', ['has'])]:
            output = io.StringIO()
            code = credentials.main(argv, io.BytesIO(b'{"server_id":"demo"}'), output,
                                    factory, {'PM_SERVER_ID': 'demo'})
            self.assertEqual(code, 1)
            self.assertNotIn('private', output.getvalue())
            if mode == 'askpass':
                self.assertEqual(output.getvalue(), '')

    def test_locked_items_are_never_read_or_deleted(self):
        store = credentials.SecretStore.__new__(credentials.SecretStore)
        item = SimpleNamespace(get_locked=mock.Mock(return_value=True),
                               load_secret_sync=mock.Mock(), delete_sync=mock.Mock())
        store.items = mock.Mock(return_value=[item])
        with self.assertRaises(credentials.CredentialError):
            store.read('password', 'demo')
        with self.assertRaises(credentials.CredentialError):
            store.delete('password', 'demo')
        item.load_secret_sync.assert_not_called()
        item.delete_sync.assert_not_called()

    def test_metadata_search_does_not_request_unlock_or_load_secrets(self):
        store = credentials.SecretStore.__new__(credentials.SecretStore)
        store.schema, store.cancel = object(), object()
        store.secret = SimpleNamespace(SearchFlags=SimpleNamespace(ALL=1))
        store.service = SimpleNamespace(search_sync=mock.Mock(return_value=[]))
        self.assertFalse(store.has('password', 'demo'))
        store.service.search_sync.assert_called_once_with(
            store.schema, {'application': 'HopHarbor', 'server_id': 'demo', 'kind': 'password'},
            1, store.cancel)


class LinuxManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = bare_manager(self.temp.name)
        self.manager.write_ssh_config()

    def test_linux_ssh_config_omits_apple_option_but_preserves_strict_trust_and_chain(self):
        for platform in ('linux', 'darwin'):
            with self.subTest(platform=platform), mock.patch.object(pm.sys, 'platform', platform):
                self.manager.write_ssh_config()
                text = (self.manager.data / 'ssh_config').read_text()
                self.assertEqual('UseKeychain yes' in text, platform == 'darwin')
                self.assertIn('StrictHostKeyChecking yes', text)
                self.assertIn('--server iran', text)
                self.assertIn('ForwardAgent no', text)

    def test_linux_credentials_use_stdin_only_and_return_presence_only(self):
        reply = SimpleNamespace(returncode=0, stdout='{"ok":true,"has_password":true,"has_key_passphrase":false}')
        with mock.patch.object(pm.sys, 'platform', 'linux'), \
                mock.patch.object(pm.subprocess, 'run', return_value=reply) as run:
            result = self.manager.keychain('put', {'server_id': 'demo', 'password': 'synthetic-secret'})
        argv = run.call_args.args[0]
        self.assertEqual(argv[-1], 'put')
        self.assertTrue(argv[-2].endswith('credentials.py'))
        self.assertNotIn('synthetic-secret', str(argv))
        self.assertIn('synthetic-secret', run.call_args.kwargs['input'])
        self.assertTrue(result['has_password'])

    def test_linux_keyring_error_does_not_reveal_subprocess_output(self):
        reply = SimpleNamespace(returncode=1, stdout='private text', stderr='private text')
        with mock.patch.object(pm.sys, 'platform', 'linux'), \
                mock.patch.object(pm.subprocess, 'run', return_value=reply):
            with self.assertRaisesRegex(ValueError, 'unlock the login keyring') as error:
                self.manager.keychain('has', {'server_id': 'demo'})
        self.assertNotIn('private text', str(error.exception))

    def test_service_reports_platform_without_changing_mac_credential_provider(self):
        for platform, name in [('darwin', 'Keychain'), ('linux', 'GNOME Keyring')]:
            with self.subTest(platform=platform), mock.patch.object(pm.sys, 'platform', platform):
                service = self.manager.state()['service']
                self.assertEqual(service['platform'], platform)
                self.assertEqual(service['credential_store'], name)
                self.assertEqual(service['version'], '1.1.4' if platform == 'darwin' else '1.2.0')
                self.assertEqual(service['build'], 7 if platform == 'darwin' else 8)


class LinuxWakeTests(unittest.TestCase):
    def monitor(self, offsets, spans=None):
        values = []
        spans = spans or [0] * len(offsets)
        for index, (offset, span) in enumerate(zip(offsets, spans)):
            values.extend([1000 + index + offset - span / 2,
                           1000 + index + offset + span / 2])
        return wake_monitor.WakeMonitor(reader=wake_monitor._LinuxWakeReader(
            boot_clock=mock.Mock(side_effect=values),
            monotonic_clock=mock.Mock(side_effect=[1000 + i for i in range(len(offsets))])))

    def test_regular_clock_jitter_never_refreshes_connections(self):
        monitor = self.monitor([10, 10.00002, 9.99999, 10.00001, 10])
        self.assertEqual([monitor.resumed() for _ in range(4)], [False] * 4)

    def test_suspend_time_changes_the_token_once_per_resume(self):
        monitor = self.monitor([10, 10, 70, 70.00001, 70, 75, 75])
        self.assertEqual([monitor.resumed() for _ in range(6)],
                         [False, True, False, False, True, False])

    def test_descheduled_sample_is_rejected_then_next_sample_detects_the_wake(self):
        monitor = self.monitor([10, 40, 70, 70], spans=[0, 1, 0, 0])
        self.assertEqual([monitor.resumed() for _ in range(3)], [False, True, False])


if __name__ == '__main__':
    unittest.main()
