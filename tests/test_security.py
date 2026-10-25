"""Local-only controller boundary tests; never starts SSH or contacts a server."""
import collections
import copy
import http.client
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('proxy_manager_review', ROOT / 'manager.py')
pm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pm)


def base_config():
    return {
        'servers': [
            {'id': 'iran', 'name': 'Iran', 'host': '192.0.2.10', 'port': 22,
             'username': 'alice', 'identity_file': '', 'jump_id': None},
            {'id': 'uk', 'name': 'UK', 'host': '2001:db8::20', 'port': 2210,
             'username': 'root', 'identity_file': '', 'jump_id': 'iran'},
        ],
        'tunnels': [
            {'id': 'socks_uk', 'name': 'UK SOCKS', 'kind': 'socks', 'server_id': 'uk',
             'local_port': 20830, 'pool_size': 1, 'autostart': False},
        ],
    }


def bare_manager(data, config=None):
    m = pm.Manager.__new__(pm.Manager)
    m.data = Path(data)
    m.data.mkdir(parents=True, exist_ok=True)
    (m.data / 'runtime').mkdir(exist_ok=True)
    m.app = ROOT
    m.port = 17777
    m.started_at = pm.now()
    m.lock = threading.RLock()
    m.config = copy.deepcopy(config or base_config())
    m.config_path = m.data / 'config.json'
    m.logs = collections.deque(maxlen=300)
    m.runtime = {}
    m.halt = threading.Event()
    m.child_env = dict(os.environ)
    m.cookies = {}
    m.secret_status = {}
    return m


class ValidationTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / 'tests' / 'tmp'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.manager = bare_manager(self.temp.name)

    def test_rejects_config_injection_in_scoped_ipv6(self):
        # ipaddress accepts arbitrary scope strings, including line separators.
        payloads = [
            'fe80::1%en0\nProxyCommand true',
            'fe80::1%x\rHost injected',
            'fe80::1%x\tProxyCommand true',
            '::1%a\x00b',
        ]
        for value in payloads:
            with self.subTest(value=repr(value)):
                self.assertFalse(pm.host_ok(value))
                config = base_config()
                config['servers'][0]['host'] = value
                with self.assertRaises(ValueError):
                    self.manager.validate_all(config)

    def test_rejects_plain_host_option_and_newline_injection(self):
        for value in ['-oProxyCommand=true', 'example.com\nUser root',
                      'example.com\rHost *', 'example.com\x00suffix']:
            with self.subTest(value=repr(value)):
                self.assertFalse(pm.host_ok(value))

    def test_rejects_remote_forward_host_injection(self):
        config = base_config()
        config['tunnels'][0].update(kind='local', remote_host='fe80::1%x\nProxyCommand true',
                                    remote_port=80)
        with self.assertRaises(ValueError):
            self.manager.validate_all(config)

    def test_rejects_jump_cycle_and_missing_jump(self):
        for missing in [False, True]:
            with self.subTest(missing=missing):
                config = base_config()
                config['servers'][0]['jump_id'] = 'missing' if missing else 'uk'
                with self.assertRaises(ValueError):
                    self.manager.validate_all(config)

    def test_rejects_conflicting_and_invalid_ports(self):
        for value in [17777, 0, 65536, True, 20830.5, '20830\nProxyCommand true']:
            with self.subTest(value=value):
                config = base_config()
                config['tunnels'][0]['local_port'] = value
                with self.assertRaises(ValueError):
                    self.manager.validate_all(config)
        config = base_config()
        config['tunnels'].append(dict(config['tunnels'][0], id='duplicate'))
        with self.assertRaises(ValueError):
            self.manager.validate_all(config)

    def test_failed_mutation_does_not_commit_invalid_config(self):
        before = copy.deepcopy(self.manager.config)
        self.manager.save()
        disk_before = self.manager.config_path.read_bytes()
        with self.assertRaises(ValueError):
            self.manager.mutate('servers', 'iran', dict(before['servers'][0], jump_id='uk'))
        self.assertEqual(self.manager.config, before)
        self.assertEqual(self.manager.config_path.read_bytes(), disk_before)

    def test_rejects_running_transitive_dependency_edit(self):
        self.manager.runtime = {'socks_uk': {}}
        with self.assertRaises(ValueError):
            self.manager.mutate('servers', 'iran', dict(self.manager.config['servers'][0]))

    def test_generated_ssh_config_preserves_per_host_user_and_jump(self):
        self.manager.validate_all(self.manager.config)
        self.manager.write_ssh_config()
        path = self.manager.data / 'ssh_config'
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        # -G expands configuration without opening any SSH network connection.
        for alias, user, port, jump in [('pm_iran', 'alice', '22', None),
                                         ('pm_uk', 'root', '2210', 'pm_iran')]:
            with self.subTest(alias=alias):
                result = subprocess.run(['/usr/bin/ssh', '-G', '-F', str(path), alias],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                parsed = dict(line.split(' ', 1) for line in result.stdout.splitlines())
                self.assertEqual(parsed['user'], user)
                self.assertEqual(parsed['port'], port)
                self.assertEqual(parsed['stricthostkeychecking'], 'true')
                self.assertEqual(parsed['forwardagent'], 'no')
                
                if jump:
                    self.assertIn('--server iran', parsed.get('proxycommand', ''))
                    self.assertIn('ssh_hop.py', parsed.get('proxycommand', ''))
                else:
                    self.assertNotIn('proxycommand', parsed)


class FakeManager:
    def __init__(self):
        self.port = None
        self.token = 'test-only-token-that-never-authenticates-a-real-service'
        self.cookies = {}
        self.calls = []

    def state(self):
        return {'servers': [], 'tunnels': [], 'logs': []}

    def mutate(self, collection, ident, data, delete=False):
        self.calls.append((collection, ident, data, delete))
        return {'ok': True, 'id': ident or 'created'}

    def log(self, *args):
        self.calls.append(('log', args))


class HTTPBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.manager = FakeManager()
        self.server = pm.http.server.ThreadingHTTPServer(('127.0.0.1', 0), pm.Handler)
        self.server.daemon_threads = True
        self.manager.port = self.server.server_address[1]
        self.server.manager = self.manager
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, data=None, headers=None, raw=None):
        h = {'Host': f'127.0.0.1:{self.manager.port}',
             'Origin': f'http://127.0.0.1:{self.manager.port}',
             'X-Requested-With': 'ProxyManager', 'Content-Type': 'application/json'}
        h.update(headers or {})
        h = {k: v for k, v in h.items() if v is not None}
        body = raw if raw is not None else json.dumps(data if data is not None else {})
        con = http.client.HTTPConnection('127.0.0.1', self.manager.port, timeout=2)
        try:
            con.request(method, path, body=body if method != 'GET' else None, headers=h)
            reply = con.getresponse()
            return reply.status, dict(reply.getheaders()), reply.read()
        finally:
            con.close()

    def login_cookie(self):
        status, headers, _ = self.request('POST', '/api/session', {'token': self.manager.token})
        self.assertEqual(status, 200)
        cookie = headers['Set-Cookie']
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=Strict', cookie)
        return cookie.split(';', 1)[0]

    def test_state_requires_authentication(self):
        status, _, _ = self.request('GET', '/api/state')
        self.assertEqual(status, 401)

    def test_valid_session_can_read_state_and_mutate(self):
        cookie = self.login_cookie()
        status, headers, _ = self.request('GET', '/api/state', headers={'Cookie': cookie})
        self.assertEqual(status, 200)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(headers['X-Frame-Options'], 'DENY')
        status, _, _ = self.request('POST', '/api/servers', {'name': 'test'}, {'Cookie': cookie})
        self.assertEqual(status, 201)
        self.assertEqual(len(self.manager.calls), 1)

    def test_foreign_host_is_rejected_even_with_cookie(self):
        cookie = self.login_cookie()
        for method, path in [('GET', '/api/state'), ('POST', '/api/servers')]:
            with self.subTest(method=method):
                status, _, _ = self.request(method, path, {},
                                             {'Cookie': cookie, 'Host': 'attacker.invalid'})
                self.assertEqual(status, 403)
        self.assertEqual(self.manager.calls, [])

    def test_csrf_rejected_for_missing_foreign_origin_or_custom_header(self):
        cookie = self.login_cookie()
        for changes in [{'Origin': None}, {'Origin': 'https://attacker.invalid'},
                        {'X-Requested-With': None}]:
            with self.subTest(changes=changes):
                status, _, _ = self.request('POST', '/api/servers', {},
                                             {'Cookie': cookie, **changes})
                self.assertEqual(status, 403)
        self.assertEqual(self.manager.calls, [])

    def test_wrong_bootstrap_token_and_bad_json_are_rejected(self):
        status, _, _ = self.request('POST', '/api/session', {'token': 'incorrect'})
        self.assertEqual(status, 401)
        for body in ['[]', '{broken', json.dumps({'token': self.manager.token})]:
            with self.subTest(body=body):
                headers = {'Content-Type': 'text/plain'} if body.startswith('{"token"') else {}
                status, _, _ = self.request('POST', '/api/session', headers=headers, raw=body)
                self.assertEqual(status, 400)


class ChildRecoveryTests(unittest.TestCase):
    def test_process_spawn_failure_is_reported_and_backed_off(self):
        manager = FakeManager()
        manager.child_env = dict(os.environ)
        child = pm.Child(['/missing/test-only-gost'], 'test child', manager, 'test')
        with mock.patch.object(pm.subprocess, 'Popen', side_effect=FileNotFoundError('test-only missing executable')):
            child.tick()
        self.assertIsNone(child.proc)
        self.assertTrue(child.error)
        self.assertGreater(child.next_start, time.monotonic())


class ControllerOwnershipTests(unittest.TestCase):
    def test_duplicate_controller_rejected_before_reaping_and_shutdown_releases_lock(self):
        scratch = ROOT / 'tests' / 'tmp'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as folder:
            # Empty temporary configuration: no SSH or GOST processes start.
            with mock.patch.object(pm.Manager, 'reap_owned_children') as reaper:
                first = pm.Manager(folder, ROOT, 17777)
                try:
                    self.assertEqual(reaper.call_count, 1)
                    with self.assertRaises(RuntimeError):
                        pm.Manager(folder, ROOT, 17778)
                    self.assertEqual(reaper.call_count, 1,
                                     'A second controller must not reap live controller children')
                finally:
                    first.shutdown()
                replacement = pm.Manager(folder, ROOT, 17777)
                try:
                    self.assertEqual(reaper.call_count, 2)
                finally:
                    replacement.shutdown()


if __name__ == '__main__':
    unittest.main()
