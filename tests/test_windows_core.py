"""Windows controller contracts using synthetic native adapters, never live settings."""
import copy
import builtins
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import test_security as security

pm = security.pm


class WindowsCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hopharbor-windows-core-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manager = security.bare_manager(self.root / 'private')
        self.manager.app = self.root / 'application with spaces'
        (self.manager.app / 'bin').mkdir(parents=True)
        self.native = mock.Mock()

        def ensure(path):
            Path(path).mkdir(parents=True, exist_ok=True, mode=0o700)

        def write(path, value):
            Path(path).write_text(value, encoding='utf-8')

        self.native.ensure_private_directory.side_effect = ensure
        self.native.open_private_file.side_effect = lambda path, flags, mode=0o600: os.open(path, flags, mode)
        self.native.atomic_write.side_effect = write
        self.native.atomic_json.side_effect = lambda path, value: write(path, json.dumps(value, ensure_ascii=False))
        self.native.system_executable.side_effect = lambda name: (
            'C:/Windows/System32/OpenSSH/ssh.exe' if name == 'ssh' else 'C:/Windows/System32/curl.exe')
        native = mock.patch.object(pm, 'windows_support', return_value=self.native)
        native.start()
        self.addCleanup(native.stop)
        platform = mock.patch.object(pm.sys, 'platform', 'win32')
        platform.start()
        self.addCleanup(platform.stop)

    def process(self, pid=930001):
        stream = io.BytesIO()
        self.addCleanup(stream.close)
        return SimpleNamespace(pid=pid, stdout=stream, returncode=None,
                               poll=mock.Mock(return_value=None), wait=mock.Mock(return_value=0),
                               close=mock.Mock(), terminate_group=mock.Mock(), kill_group=mock.Mock())

    def child(self, pid=930001):
        child = pm.Child(['synthetic-ssh.exe'], 'Synthetic SSH', self.manager,
                         'socks_uk', 'uk')
        child.proc = self.process(pid)
        return child

    def test_windows_handle_limits_do_not_call_posix_resource_apis(self):
        with mock.patch.object(pm.resource, 'getrlimit') if pm.resource else mock.patch.object(pm, 'resource') as limits:
            result = pm.raise_file_limit()
        self.assertEqual(result, {'soft': None, 'hard': None, 'warning': ''})
        limits.assert_not_called()

    def test_windows_import_does_not_require_posix_modules(self):
        original = builtins.__import__

        def importing(name, *args, **kwargs):
            if name in ('fcntl', 'resource'):
                raise ImportError('Synthetic Windows has no POSIX module')
            return original(name, *args, **kwargs)

        spec = importlib.util.spec_from_file_location('synthetic_windows_manager', security.ROOT / 'manager.py')
        module = importlib.util.module_from_spec(spec)
        with mock.patch.object(builtins, '__import__', side_effect=importing), \
                mock.patch.object(pm.sys, 'dont_write_bytecode', False):
            spec.loader.exec_module(module)
            self.assertTrue(pm.sys.dont_write_bytecode)
        self.assertIsNone(module.fcntl)
        self.assertIsNone(module.resource)

    def test_startup_uses_exclusive_native_lock_and_private_unicode_files(self):
        data = self.root / 'new private data'
        with mock.patch.object(pm.threading, 'Thread'):
            manager = pm.Manager(data, self.manager.app, 23999)
        self.addCleanup(manager.shutdown)
        self.native.ServiceLock.assert_called_once_with(data.resolve() / '.service.lock')
        self.native.ensure_private_directory.assert_any_call(data)
        self.native.ensure_private_directory.assert_any_call(data.resolve() / 'runtime')
        self.assertEqual(manager.child_env['SSH_ASKPASS'], str(self.manager.app.resolve() / 'bin/HopHarborHelper.exe'))
        self.assertEqual(manager.child_env['HOPHARBOR_APP'], str(self.manager.app.resolve()))
        self.assertTrue(manager.child_env['PATH'].startswith(str(self.manager.app.resolve() / 'bin') + os.pathsep))
        self.assertEqual(manager.state()['service']['credential_store'], 'Windows Credential Manager')
        pm.atomic_json(data / 'unicode.json', {'name': 'نمایشی'})
        self.assertEqual(json.loads((data / 'unicode.json').read_text(encoding='utf-8')), {'name': 'نمایشی'})
        manager.shutdown()
        self.native.ServiceLock.return_value.close.assert_called_once()

    def test_config_uses_native_hop_without_private_path_in_shell_command(self):
        self.manager.write_ssh_config()
        config = (self.manager.data / 'ssh_config').read_text(encoding='utf-8')
        self.assertIn('GlobalKnownHostsFile NUL', config)
        self.assertNotIn('UseKeychain', config)
        self.assertIn('ProxyCommand HopHarborHelper.exe hop --server iran --host %h --port %p', config)
        self.assertNotIn('/usr/bin/python3', config)
        self.assertNotIn(str(self.manager.app), config)
        self.assertEqual(pm.ssh_path('C:\\Users\\Example User%name\\key'),
                         '"C:/Users/Example User%%name/key"')

    def test_windows_forwarding_launches_owned_native_module_with_port_only_config(self):
        with mock.patch.object(pm, 'port_open', return_value=False), \
                mock.patch.object(pm, 'reserve_port', return_value=23991), \
                mock.patch.object(pm.Child, 'spawn'):
            self.manager.start('socks_uk')
        runtime = self.manager.runtime['socks_uk']
        proxy = runtime['gost']
        cfg = self.manager.data / 'runtime/socks_uk.json'
        self.assertEqual(proxy.argv, [pm.sys.executable, '-B', str(self.manager.app / 'windows_proxy.py'), '--config', str(cfg)])
        self.assertTrue(proxy.is_native_proxy)
        self.assertFalse(proxy.is_gost)
        descriptor = json.loads(cfg.read_text(encoding='utf-8'))
        self.assertEqual(descriptor, {'schema': 1, 'id': 'socks_uk', 'kind': 'socks',
                                      'listen_port': 20830, 'backend_ports': [23991]})
        self.assertNotIn('192.0.2.10', cfg.read_text())
        self.assertNotIn('gost.exe', repr(proxy.argv))

    def test_windows_cleanup_removes_only_valid_inactive_native_descriptors(self):
        directory = self.manager.data / 'runtime'
        good = pm.windows_proxy_descriptor({'id': 'old', 'kind': 'http', 'local_port': 23980}, [23981,23982])
        (directory / 'old.json').write_text(json.dumps(good))
        unsafe = dict(good, id='unknown', extra='personal settings must stay')
        (directory / 'unknown.json').write_text(json.dumps(unsafe))
        self.manager.maintain_local_files()
        self.assertFalse((directory / 'old.json').exists())
        self.assertTrue((directory / 'unknown.json').exists())

    def test_identity_validation_uses_native_ownership_and_acl_rules(self):
        key = self.root / 'synthetic private identity'
        key.write_text('test fixture, not a key')
        config = copy.deepcopy(self.manager.config)
        config['servers'][0]['identity_file'] = str(key)
        with mock.patch.object(pm.os, 'getuid', create=True,
                               side_effect=AssertionError('Windows must not ask for POSIX uid')):
            self.manager.validate_all(config)
        self.native.validate_identity_file.assert_called_once_with(key)
        self.native.validate_identity_file.side_effect = ValueError('Untrusted identity ACL')
        with self.assertRaisesRegex(ValueError, 'Untrusted identity ACL'):
            self.manager.validate_all(config)

    def test_native_spawn_owns_tree_before_execution_and_preserves_credentials_in_environment(self):
        proc = self.process()
        self.native.spawn_owned.return_value = proc
        child = pm.Child(['synthetic-ssh.exe'], 'Synthetic SSH', self.manager,
                         'socks_uk', 'uk')
        with mock.patch.object(pm.subprocess, 'Popen', side_effect=AssertionError('Unsafe direct spawn')), \
                mock.patch.object(pm.threading, 'Thread'):
            child.spawn()
        self.assertIs(child.proc, proc)
        args, kwargs = self.native.spawn_owned.call_args
        self.assertEqual(args, (['synthetic-ssh.exe'],))
        self.assertEqual(kwargs['env']['PM_SERVER_ID'], 'uk')
        self.assertEqual(kwargs['stdin'], pm.subprocess.DEVNULL)
        self.assertEqual(kwargs['stderr'], pm.subprocess.STDOUT)
        self.assertNotIn('start_new_session', kwargs)

    def test_stop_and_restart_release_only_the_owned_job_tree(self):
        child = self.child()
        proc, generation = child.proc, child.generation
        with mock.patch.object(pm.os, 'killpg', create=True,
                               side_effect=AssertionError('No POSIX kill on Windows')):
            child.stop()
        proc.terminate_group.assert_called_once()
        proc.close.assert_called_once()
        self.assertIsNone(child.proc)
        self.assertGreater(child.generation, generation)

    def test_batch_stops_signal_all_windows_jobs_before_waiting(self):
        children = [self.child(930001 + i) for i in range(3)]
        events = []
        for child in children:
            proc = child.proc
            proc.terminate_group.side_effect = lambda pid=proc.pid: events.append(('terminate', pid))
            proc.wait.side_effect = lambda timeout, pid=proc.pid: events.append(('wait', pid))
        with self.manager.lock:
            errors = pm.Child.stop_many(children)
        self.assertEqual(errors, [])
        self.assertEqual([event[0] for event in events[:3]], ['terminate'] * 3)
        self.assertTrue(all(child.proc is None for child in children))

    def test_failed_native_stop_preserves_job_and_generation(self):
        child = self.child()
        proc, generation = child.proc, child.generation
        proc.terminate_group.side_effect = OSError('Synthetic job termination failure')
        with self.assertRaises(OSError):
            child.stop()
        self.assertIs(child.proc, proc)
        self.assertEqual(child.generation, generation)
        proc.close.assert_not_called()

    def test_exited_parent_closes_job_for_lingering_hop_descendants(self):
        child = self.child()
        proc = child.proc
        proc.poll.return_value = 255
        proc.returncode = 255
        child.last_start = 99
        with mock.patch.object(pm.time, 'monotonic', return_value=100):
            child.tick()
        proc.close.assert_called_once()
        self.assertIsNone(child.proc)
        self.assertEqual(child.next_start, 105)

    def test_stale_runtime_record_never_kills_a_reused_windows_pid(self):
        record = self.manager.data / 'runtime/child-930001.json'
        record.write_text(json.dumps({'pid': 930001, 'argv': ['a reused process']}))
        with mock.patch.object(pm.subprocess, 'run', side_effect=AssertionError('No process probing')), \
                mock.patch.object(pm.os, 'killpg', create=True,
                                  side_effect=AssertionError('Never kill a record PID')):
            self.manager.reap_owned_children()
        self.assertFalse(record.exists())
        self.native.validate_private_file.assert_called_once_with(record)

    def test_native_credential_helper_receives_secret_only_over_stdin(self):
        helper = self.manager.app / 'bin/HopHarborHelper.exe'
        helper.touch()
        result = SimpleNamespace(returncode=0, stdout='{"ok":true,"has_password":true}')
        with mock.patch.object(pm.subprocess, 'run', return_value=result) as run:
            reply = self.manager.keychain('put', {'server_id': 'uk', 'password': 'synthetic-secret'})
        argv = run.call_args.args[0]
        self.assertEqual(argv, [str(helper), 'put'])
        self.assertNotIn('synthetic-secret', repr(argv))
        self.assertIn('synthetic-secret', run.call_args.kwargs['input'])
        self.assertEqual(run.call_args.kwargs['encoding'], 'utf-8')
        self.assertTrue(reply['has_password'])

    def test_windows_credential_cap_is_utf8_bytes_and_invalid_values_never_reach_helper(self):
        for value in ['x' * 1023, 'é' * 512, 'bad\nvalue', 'bad\rvalue', 'bad\0value', '\ud800']:
            with self.subTest(value_size=len(value)):
                self.manager.keychain = mock.Mock()
                with self.assertRaises(ValueError):
                    self.manager.mutate('servers', 'iran', {'password': value})
                self.manager.keychain.assert_not_called()
        self.manager.keychain = mock.Mock(return_value={'ok': True})
        value = 'é' * 511
        self.manager.mutate('servers', 'iran', {'password': value})
        self.manager.keychain.assert_any_call('put', {'server_id': 'iran', 'password': value})
        self.assertNotIn(value, self.manager.config_path.read_text(encoding='utf-8'))

    def test_windows_dynamic_controller_port_uses_actual_bound_port(self):
        server = mock.Mock(server_address=('127.0.0.1', 34991))
        streams = (pm.sys.stdout, pm.sys.stderr)
        argv = ['manager.py', '--data-dir', str(self.root / 'dynamic data'),
                '--app-dir', str(self.manager.app), '--port', '0']
        with mock.patch.object(pm.sys, 'argv', argv), \
                mock.patch.object(pm, 'install_service_streams', return_value=streams), \
                mock.patch.object(pm.http.server, 'ThreadingHTTPServer', return_value=server) as bind, \
                mock.patch.object(pm, 'Manager') as manager, \
                mock.patch.object(pm.signal, 'signal'):
            pm.main()
        bind.assert_called_once_with(('127.0.0.1', 0), pm.Handler)
        manager.assert_called_once_with(str(self.root / 'dynamic data'), str(self.manager.app),
                                        34991, service_streams=streams)
        manager.return_value.shutdown.assert_called_once_with()
        server.server_close.assert_called_once_with()

    def test_windows_logs_use_native_acl_open_without_posix_uid_or_directory_flags(self):
        directory = self.root / 'bounded logs'
        with mock.patch.dict(pm.sys.modules, {'windows_platform': self.native}), \
                mock.patch.object(pm.os, 'getuid', create=True,
                                  side_effect=AssertionError('No POSIX uid on Windows')):
            stdout, stderr = pm.install_service_streams(directory)
            try:
                for _ in range(25):
                    stdout.write('🚀' * 4096)
                    stderr.write('synthetic error\n')
                self.assertLessEqual(Path(stdout.name).stat().st_size, 262144)
                self.assertEqual(Path(stderr.name).read_text(encoding='utf-8'), 'synthetic error\n' * 25)
            finally:
                stdout.close()
                stderr.close()
        self.native.ensure_private_directory.assert_any_call(str(directory))
        self.assertEqual({path.name for path in directory.iterdir()},
                         {'service.stdout.log', 'service.stderr.log'})

    def test_windows_log_acl_rejection_never_falls_back_to_permissive_open(self):
        self.native.open_private_file.side_effect = ValueError('Synthetic unsafe ACL')
        directory = self.root / 'unsafe logs'
        with mock.patch.dict(pm.sys.modules, {'windows_platform': self.native}), \
                self.assertRaisesRegex(ValueError, 'Synthetic unsafe ACL'):
            pm.install_service_streams(directory)
        self.assertFalse(list(directory.iterdir()))


class WindowsServiceHTTPTests(unittest.TestCase):
    def setUp(self):
        self.boundary = security.HTTPBoundaryTests('test_state_requires_authentication')
        self.boundary.setUp()
        self.addCleanup(self.boundary.doCleanups)
        platform = mock.patch.object(pm.sys, 'platform', 'win32')
        platform.start()
        self.addCleanup(platform.stop)

    def test_health_requires_cookie_and_does_not_collect_private_state(self):
        b = self.boundary
        self.assertEqual(b.request('GET', '/api/service/health')[0], 401)
        cookie = b.login_cookie()
        b.manager.state = mock.Mock(side_effect=AssertionError('Health must not collect session/log state'))
        code, _, body = b.request('GET', '/api/service/health', headers={'Cookie': cookie})
        self.assertEqual(code, 200)
        self.assertEqual(set(json.loads(body)), {'ok', 'version', 'build', 'platform'})
        self.assertEqual(json.loads(body)['platform'], 'win32')
        self.assertEqual(b.request('GET', '/api/service/health', headers={'Cookie': cookie, 'Host': 'localhost'})[0], 403)

    def test_stop_requires_authentication_and_exact_origin(self):
        b = self.boundary
        self.assertEqual(b.request('POST', '/api/service/stop', {})[0], 401)
        cookie = b.login_cookie()
        self.assertEqual(b.request('POST', '/api/service/stop', {},
                                   headers={'Cookie': cookie, 'Origin': 'https://outside.invalid'})[0], 403)
        self.assertTrue(b.thread.is_alive())
        self.assertEqual(b.request('POST', '/api/service/stop', {}, headers={'Cookie': cookie})[0], 200)
        b.thread.join(timeout=2)
        self.assertFalse(b.thread.is_alive())

    def test_service_endpoints_are_not_added_to_unix(self):
        b = self.boundary
        cookie = b.login_cookie()
        with mock.patch.object(pm.sys, 'platform', 'darwin'):
            self.assertEqual(b.request('GET', '/api/service/health', headers={'Cookie': cookie})[0], 404)
            self.assertEqual(b.request('POST', '/api/service/stop', {}, headers={'Cookie': cookie})[0], 404)


class WindowsWakeClockTests(unittest.TestCase):
    def monitor(self, offsets, spans=None):
        import wake_monitor
        spans = spans or [0] * len(offsets)
        values = []
        for i, (offset, span) in enumerate(zip(offsets, spans)):
            values += [1000 + i + offset - span / 2, 1000 + i + offset + span / 2]
        return wake_monitor.WakeMonitor(reader=wake_monitor._WindowsWakeReader(
            boot_clock=mock.Mock(side_effect=values),
            monotonic_clock=mock.Mock(side_effect=[1000 + i for i in range(len(offsets))])))

    def test_real_suspend_changes_offset_once_but_jitter_does_not(self):
        monitor = self.monitor([10, 10.015, 10, 80, 80.015, 80])
        self.assertEqual([monitor.resumed() for _ in range(5)], [False, False, True, False, False])

    def test_delayed_clock_sample_is_inert_and_next_sample_detects_resume(self):
        monitor = self.monitor([10, 40, 80, 80], spans=[0, 1, 0, 0])
        self.assertEqual([monitor.resumed() for _ in range(3)], [False, True, False])


if __name__ == '__main__':
    unittest.main()
