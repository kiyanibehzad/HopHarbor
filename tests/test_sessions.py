"""Session controls and native SSH configuration tests; no SSH connection is opened."""
import copy
import json
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_security import ROOT, bare_manager, base_config
import test_security as fixtures


def grouped_config():
    config = base_config()
    config['servers'].append({'id': 'other', 'name': 'Other', 'host': '192.0.2.30',
                              'port': 22, 'username': 'alice', 'jump_id': None})
    config['tunnels'] += [
        {'id': 'iran_socks', 'name': 'Iran SOCKS', 'kind': 'socks', 'server_id': 'iran',
         'local_port': 20810, 'pool_size': 2, 'autostart': False},
        {'id': 'iran_http', 'name': 'Iran HTTP', 'kind': 'http', 'server_id': 'iran',
         'local_port': 17090, 'pool_size': 1, 'autostart': False},
        {'id': 'other_socks', 'name': 'Other SOCKS', 'kind': 'socks', 'server_id': 'other',
         'local_port': 20860, 'pool_size': 1, 'autostart': False},
    ]
    return config


def runtime(status='connected', healthy=1, active=1):
    children = [SimpleNamespace(proc=SimpleNamespace(poll=lambda: None, pid=900000 + n), error='')
                for n in range(active)]
    return {'ssh': children, 'gost': SimpleNamespace(proc=None, error=''), 'ports': [],
            'status': status, 'healthy': healthy, 'last_test': None}


class SessionTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / 'tests' / 'tmp'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.manager = bare_manager(self.temp.name, grouped_config())
        self.manager.validate_all(self.manager.config)
        self.manager.write_ssh_config()

    def rows(self):
        return {row['id']: row for row in self.manager.state()['servers']}

    def test_group_actions_only_control_own_forwards_and_hold_the_lock(self):
        manager = self.manager
        dependent = runtime()
        unrelated = runtime()
        manager.runtime = {'socks_uk': dependent, 'other_socks': unrelated}
        calls = []

        def start(tid):
            self.assertTrue(manager.lock._is_owned())
            calls.append(('start', tid))
            manager.runtime.setdefault(tid, runtime())

        def stop(tid):
            self.assertTrue(manager.lock._is_owned())
            calls.append(('stop', tid))
            manager.runtime.pop(tid, None)

        with mock.patch.object(manager, 'start', side_effect=start), \
                mock.patch.object(manager, 'stop', side_effect=stop):
            connected = manager.session_action('iran', 'connect')
            self.assertEqual(connected['summary'], {'requested': 2, 'succeeded': 2, 'failed': 0})
            self.assertEqual(calls, [('start', 'iran_socks'), ('start', 'iran_http')])
            calls.clear()
            manager.session_action('iran', 'reconnect')
            self.assertEqual(calls, [('stop', 'iran_socks'), ('start', 'iran_socks'),
                                     ('stop', 'iran_http'), ('start', 'iran_http')])
            calls.clear()
            manager.session_action('iran', 'disconnect')
            self.assertEqual(calls, [('stop', 'iran_socks'), ('stop', 'iran_http')])
        self.assertIs(manager.runtime['socks_uk'], dependent)
        self.assertIs(manager.runtime['other_socks'], unrelated)
        self.assertEqual(set(manager.runtime), {'socks_uk', 'other_socks'})
        row = self.rows()['iran']
        self.assertEqual(row['connection_status'], 'in_use_as_firewall')
        self.assertEqual(row['active_ssh_count'], 0)
        self.assertEqual(row['dependent_forward_count'], 1)

    def test_partial_connect_failure_keeps_other_forwards_and_continues(self):
        manager = self.manager
        dependent, working = runtime(), runtime()
        manager.runtime = {'socks_uk': dependent, 'iran_http': working}
        calls = []

        def start(tid):
            calls.append(tid)
            if tid == 'iran_socks':
                raise ValueError('A test process already owns this local port.')
            manager.runtime.setdefault(tid, runtime())

        with mock.patch.object(manager, 'start', side_effect=start), \
                mock.patch.object(manager, 'stop') as stop:
            result = manager.session_action('iran', 'connect')
        self.assertFalse(result['ok'])
        self.assertEqual(result['summary'], {'requested': 2, 'succeeded': 1, 'failed': 1})
        self.assertEqual(calls, ['iran_socks', 'iran_http'])
        self.assertEqual(result['results'][0]['tunnel_id'], 'iran_socks')
        self.assertIn('already owns', result['results'][0]['error'])
        self.assertTrue(result['results'][1]['ok'])
        self.assertIs(manager.runtime['socks_uk'], dependent)
        self.assertIs(manager.runtime['iran_http'], working)
        stop.assert_not_called()

    def test_no_forward_and_invalid_session_actions_never_touch_processes(self):
        manager = self.manager
        manager.config = base_config()  # Iran has no own forwards, but UK depends on it.
        with mock.patch.object(manager, 'start') as start, mock.patch.object(manager, 'stop') as stop:
            for action in ['connect', 'disconnect', 'reconnect']:
                with self.subTest(action=action), self.assertRaisesRegex(ValueError, 'no port forwarding entries'):
                    manager.session_action('iran', action)
            with self.assertRaises(KeyError):
                manager.session_action('missing', 'connect')
            with self.assertRaises(KeyError):
                manager.session_action('uk', 'start')
        start.assert_not_called()
        stop.assert_not_called()

    def test_status_counts_own_processes_and_transitive_firewall_use(self):
        manager = self.manager
        manager.config['servers'].append({'id': 'leaf', 'name': 'Leaf', 'host': '192.0.2.40',
                                          'port': 22, 'username': 'alice', 'jump_id': 'uk'})
        manager.config['tunnels'].append({'id': 'leaf_socks', 'name': 'Leaf SOCKS', 'kind': 'socks',
                                          'server_id': 'leaf', 'local_port': 20840, 'pool_size': 2})
        manager.validate_all(manager.config)
        manager.runtime = {'socks_uk': runtime(), 'leaf_socks': runtime(active=2, healthy=2)}
        rows = self.rows()
        self.assertEqual(rows['iran']['connection_status'], 'in_use_as_firewall')
        self.assertTrue(rows['iran']['firewall_in_use'])
        self.assertEqual(rows['iran']['dependent_forward_count'], 2)
        self.assertEqual(rows['iran']['own_forward_count'], 2)
        self.assertEqual(rows['iran']['active_forward_count'], 0)
        self.assertEqual(rows['iran']['active_ssh_count'], 0)
        self.assertEqual(rows['uk']['connection_status'], 'connected')
        self.assertEqual(rows['uk']['dependent_forward_count'], 1)
        self.assertEqual(rows['uk']['active_ssh_count'], 1)
        self.assertEqual(rows['leaf']['healthy_ssh_count'], 2)
        self.assertEqual(rows['other']['connection_status'], 'disconnected')

    def test_status_distinguishes_connecting_error_and_partial_pool_health(self):
        manager = self.manager
        cases = [
            ({'iran_socks': runtime('starting', healthy=0, active=2)}, 'connecting', 0),
            ({'iran_socks': runtime('error', healthy=0, active=0)}, 'error', 0),
            ({'iran_socks': runtime('degraded', healthy=1, active=2)}, 'degraded', 1),
            ({'iran_socks': runtime(), 'iran_http': runtime('starting', healthy=0)}, 'degraded', 1),
            ({'iran_socks': runtime(active=2, healthy=2)}, 'connected', 1),
        ]
        for current, status, healthy_forwards in cases:
            with self.subTest(status=status, active=list(current)):
                manager.runtime = current
                row = self.rows()['iran']
                self.assertEqual(row['connection_status'], status)
                self.assertEqual(row['active_forward_count'], len(current))
                self.assertEqual(row['healthy_forward_count'], healthy_forwards)
        # A process that exits between monitor ticks cannot inflate healthy SSH count.
        manager.runtime = {'iran_socks': runtime('connected', healthy=2, active=0)}
        row = self.rows()['iran']
        self.assertEqual(row['healthy_ssh_count'], 0)
        self.assertEqual(row['healthy_forward_count'], 0)
        self.assertEqual(row['connection_status'], 'connecting')

    def test_failed_stop_retains_ownership_attempts_all_children_and_never_respawns(self):
        manager = self.manager
        for failing_component in ['gost', 'ssh']:
            with self.subTest(failing_component=failing_component):
                gost = SimpleNamespace(stop=mock.Mock(), tick=mock.Mock())
                ssh = [SimpleNamespace(stop=mock.Mock(), tick=mock.Mock()) for _ in range(2)]
                failed = gost if failing_component == 'gost' else ssh[0]
                failed.stop.side_effect = OSError('Test-only termination failure')
                current = {'gost': gost, 'ssh': ssh, 'ports': [], 'status': 'connected', 'healthy': 2}
                manager.runtime = {'iran_socks': current}
                with self.assertRaisesRegex(RuntimeError, 'Could not stop all components'):
                    manager.stop('iran_socks')
                self.assertIs(manager.runtime['iran_socks'], current)
                self.assertTrue(current['stopping'])
                self.assertEqual(current['status'], 'error')
                gost.stop.assert_called_once()
                for child in ssh:
                    child.stop.assert_called_once()
                manager.halt = SimpleNamespace(wait=mock.Mock(side_effect=[False, True]))
                manager.watch()  # One synthetic monitor iteration retries stopping only.
                gost.tick.assert_not_called()
                for child in ssh:
                    child.tick.assert_not_called()
                failed.stop.side_effect = None
                manager.stop('iran_socks')
                self.assertNotIn('iran_socks', manager.runtime)

    def test_native_child_retains_process_reference_when_termination_fails(self):
        child = fixtures.pm.Child(['/test-only-ssh'], 'Test SSH', self.manager, 'iran_socks')
        process = SimpleNamespace(poll=lambda: None, pid=900000, wait=mock.Mock())
        child.proc = process
        with mock.patch.object(fixtures.pm.os, 'killpg', side_effect=OSError('Test-only signal failure')):
            with self.assertRaises(OSError):
                child.stop()
        self.assertIs(child.proc, process)
        process.wait.assert_not_called()

    def test_failed_proxy_test_surfaces_bounded_curl_error_with_http_code_and_time(self):
        self.manager.runtime = {'iran_http': runtime()}
        error = 'curl: (56) CONNECT tunnel failed, response 403'
        result = subprocess.CompletedProcess(['/test-only-curl'], 56, '000 0.001234', 'x' * 1000 + error)
        with mock.patch.object(fixtures.pm.subprocess, 'run', return_value=result):
            probe = self.manager.test('iran_http')
        self.assertFalse(probe['ok'])
        self.assertIn('000 0.001234', probe['message'])
        self.assertIn(error, probe['message'])
        self.assertLessEqual(len(probe['message']), 620)


class KeepaliveTests(unittest.TestCase):
    setUp = SessionTests.setUp

    def test_defaults_and_per_session_values_expand_in_native_openssh(self):
        manager = self.manager
        self.assertEqual(manager.config['servers'][0]['keepalive_interval'], 30)
        self.assertEqual(manager.config['servers'][0]['keepalive_count'], 3)
        manager.config['servers'][0].update(keepalive_interval=0, keepalive_count=1)
        manager.config['servers'][1].update(keepalive_interval=600, keepalive_count=10)
        manager.validate_all(manager.config)
        manager.write_ssh_config()
        path = manager.data / 'ssh_config'
        # ssh -G expands local configuration only, including each Firewall hop alias.
        for alias, interval, count in [('pm_iran', 0, 1), ('pm_uk', 600, 10), ('pm_other', 30, 3)]:
            with self.subTest(alias=alias):
                result = subprocess.run(['/usr/bin/ssh', '-G', '-F', str(path), alias],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                expanded = dict(line.split(' ', 1) for line in result.stdout.splitlines())
                self.assertEqual(expanded['serveraliveinterval'], str(interval))
                self.assertEqual(expanded['serveralivecountmax'], str(count))
                self.assertEqual(expanded['tcpkeepalive'], 'yes')

    def test_invalid_ranges_types_and_configuration_injection_are_rejected(self):
        for field, invalid in [('keepalive_interval', [-1, 601, True, 1.5, None, '30\nProxyCommand true']),
                               ('keepalive_count', [0, 11, False, 1.5, None, '3\rHost injected'])]:
            for value in invalid:
                with self.subTest(field=field, value=value):
                    config = grouped_config()
                    config['servers'][0][field] = value
                    with self.assertRaises(ValueError):
                        self.manager.validate_all(config)

    def test_mutation_persists_only_valid_keepalive_values_and_ignores_runtime_fields(self):
        manager = self.manager
        with mock.patch.object(manager, 'refresh_secret_status'):
            manager.mutate('servers', 'iran', {'keepalive_interval': 45, 'keepalive_count': 5,
                                               'connection_status': 'connected', 'active_ssh_count': 999})
        saved = next(s for s in json.loads(manager.config_path.read_text())['servers'] if s['id'] == 'iran')
        self.assertEqual((saved['keepalive_interval'], saved['keepalive_count']), (45, 5))
        self.assertNotIn('connection_status', saved)
        self.assertNotIn('active_ssh_count', saved)
        before_config, before_disk = copy.deepcopy(manager.config), manager.config_path.read_bytes()
        with self.assertRaises(ValueError):
            manager.mutate('servers', 'iran', {'keepalive_interval': '0\nProxyCommand injected'})
        self.assertEqual(manager.config, before_config)
        self.assertEqual(manager.config_path.read_bytes(), before_disk)

    def test_keepalive_edit_is_blocked_while_own_or_firewall_dependents_are_active(self):
        for tid in ['iran_socks', 'socks_uk']:
            with self.subTest(active_forward=tid):
                self.manager.runtime = {tid: runtime()}
                with self.assertRaisesRegex(ValueError, 'depend on this session'):
                    self.manager.mutate('servers', 'iran', {'keepalive_interval': 60})
                self.assertEqual(self.manager.config['servers'][0]['keepalive_interval'], 30)


class SessionHTTPTests(unittest.TestCase):
    close_server = fixtures.HTTPBoundaryTests.close_server
    request = fixtures.HTTPBoundaryTests.request
    login_cookie = fixtures.HTTPBoundaryTests.login_cookie

    def setUp(self):
        fixtures.HTTPBoundaryTests.setUp(self)
        self.manager.session_action = mock.Mock(return_value={'ok': True, 'results': []})

    def test_group_routes_preserve_authentication_csrf_and_action_arguments(self):
        status, _, _ = self.request('POST', '/api/servers/iran/connect')
        self.assertEqual(status, 401)
        cookie = self.login_cookie()
        status, _, _ = self.request('POST', '/api/servers/iran/connect',
                                    headers={'Cookie': cookie, 'Origin': 'https://attacker.invalid'})
        self.assertEqual(status, 403)
        self.manager.session_action.assert_not_called()
        for action in ['connect', 'disconnect', 'reconnect']:
            status, _, _ = self.request('POST', '/api/servers/iran/' + action,
                                        headers={'Cookie': cookie})
            self.assertEqual(status, 200)
            self.manager.session_action.assert_called_with('iran', action)


if __name__ == '__main__':
    unittest.main()
