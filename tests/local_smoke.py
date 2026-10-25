#!/usr/bin/env python3
"""Bounded native OpenSSH/GOST integration test, entirely on loopback.

Creates its own temporary SSH servers, keys, HTTP origin, and private TLS CA.
It does not use a user's SSH agent, Keychain credentials, remote servers,
installed HopHarbor service, proxy settings, or production tunnel ports.
"""
import contextlib
import getpass
import http.server
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import traceback
import uuid


ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / 'tests' / 'local-smoke-results.json'
SPEC = importlib.util.spec_from_file_location('hopharbor_local_smoke', ROOT / 'manager.py')
pm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pm)


def command(argv, timeout=15):
    q = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if q.returncode:
        raise RuntimeError('Local command failed: %s; %s' %
                           (Path(argv[0]).name, q.stderr[-1500:]))
    return q


def free_port(excluded):
    while True:
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        if port not in excluded and port != 17777:
            excluded.add(port)
            return port


def port_open(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=.2):
            return True
    except OSError:
        return False


def wait_for(predicate, timeout=35, description='condition'):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.15)
    raise RuntimeError('Timed out waiting for ' + description)


def redact(text, temporary):
    return str(text).replace(str(temporary), '<local-smoke>') \
        .replace(str(Path.home()), '<home>') \
        .replace(getpass.getuser(), '<local-user>')


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        body = ('HopHarbor local origin: ' + self.path + '\n').encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, *_):
        pass


class LocalManager(pm.Manager):
    def keychain(self, action, payload):
        # This test exercises unencrypted synthetic keys, not OS secret storage.
        if action == 'has':
            return {'has_password': False, 'has_key_passphrase': False}
        raise AssertionError('The local smoke test must not access Keychain secrets')


def make_ssh_server(folder, prefix, port, username, cleanup):
    host = folder / (prefix + '-host')
    client = folder / (prefix + '-client')
    for path, role in [(host, 'host'), (client, 'client')]:
        command(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                 '-C', 'hopharbor-local-smoke-' + role, '-f', str(path)])
    authorized = folder / (prefix + '-authorized_keys')
    authorized.write_text(client.with_suffix('.pub').read_text())
    authorized.chmod(0o600)
    config = folder / (prefix + '-sshd_config')
    config.write_text('\n'.join([
        'Port ' + str(port), 'ListenAddress 127.0.0.1',
        'HostKey ' + pm.quote(str(host)),
        'PidFile ' + pm.quote(str(folder / (prefix + '.pid'))),
        'AuthorizedKeysFile ' + pm.quote(str(authorized)),
        'PasswordAuthentication no', 'KbdInteractiveAuthentication no',
        'UsePAM no', 'PermitRootLogin no', 'AllowUsers ' + username,
        'StrictModes yes', 'AllowTcpForwarding yes', 'GatewayPorts no',
        'X11Forwarding no', 'PrintMotd no', 'PrintLastLog no',
        'MaxStartups 50', 'LogLevel ERROR', ''
    ]))
    config.chmod(0o600)
    command(['/usr/sbin/sshd', '-t', '-f', str(config)])
    log = (folder / (prefix + '-sshd.log')).open('ab')
    proc = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', str(config)],
                            stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                            start_new_session=True, close_fds=True)

    def stop():
        if proc.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=2)
        log.close()

    cleanup.append(stop)
    wait_for(lambda: proc.poll() is not None or port_open(port), timeout=5,
             description='local SSH listener')
    if proc.poll() is not None:
        raise RuntimeError('Local SSH server exited: ' +
                           (folder / (prefix + '-sshd.log')).read_text()[-1500:])
    return client, host.with_suffix('.pub')


def make_origin(cleanup, tls_context=None):
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    server.daemon_threads = True
    if tls_context:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever,
                              kwargs={'poll_interval': .05}, daemon=True)
    worker.start()

    def stop():
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

    cleanup.append(stop)
    return server.server_address[1]


def make_tls(folder):
    ca = folder / 'ca.crt'
    ca_key = folder / 'ca.key'
    key = folder / 'tls.key'
    cert = folder / 'tls.crt'
    csr = folder / 'tls.csr'
    ext = folder / 'tls-ext.cnf'
    ext.write_text('basicConstraints=critical,CA:FALSE\n'
                   'keyUsage=critical,digitalSignature,keyEncipherment\n'
                   'extendedKeyUsage=serverAuth\n'
                   'subjectAltName=DNS:localhost,IP:127.0.0.1\n')
    command(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
             '-keyout', str(ca_key), '-out', str(ca), '-days', '1', '-sha256',
             '-subj', '/CN=HopHarbor Local Smoke CA'])
    command(['/usr/bin/openssl', 'req', '-newkey', 'rsa:2048', '-nodes',
             '-keyout', str(key), '-out', str(csr), '-subj', '/CN=localhost'])
    command(['/usr/bin/openssl', 'x509', '-req', '-in', str(csr), '-CA', str(ca),
             '-CAkey', str(ca_key), '-CAcreateserial', '-out', str(cert),
             '-days', '1', '-sha256', '-extfile', str(ext)])
    for p in [ca_key, key]:
        p.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    return context, ca


def proxy_get(proxy_scheme, proxy_port, target, expected_path, ca=None):
    args = ['/usr/bin/curl', '--silent', '--show-error', '--fail',
            '--connect-timeout', '3', '--max-time', '6', '--noproxy', '',
            '--proxy', '%s://127.0.0.1:%s' % (proxy_scheme, proxy_port)]
    if ca:
        args += ['--cacert', str(ca)]
    args.append(target)
    q = command(args, timeout=8)
    expected = 'HopHarbor local origin: ' + expected_path + '\n'
    if q.stdout != expected:
        raise RuntimeError('Unexpected synthetic origin response')


def main():
    os.umask(0o077)
    started = time.monotonic()
    results = {'test': 'local-native-ssh-gost-smoke', 'external_connections': False,
               'production_settings_changed': False, 'checks': []}
    scratch = ROOT / 'tests' / 'tmp'
    scratch.mkdir(parents=True, exist_ok=True)
    cleanup = []
    manager = None
    ok = False
    with tempfile.TemporaryDirectory(prefix='local smoke ', dir=scratch) as temp:
        temporary = Path(temp).resolve()
        try:
            if not (ROOT / 'bin/gost').is_file():
                raise RuntimeError('Build or install the verified GOST binary first')
            excluded = set()
            jump_port, edge_port = free_port(excluded), free_port(excluded)
            jump_key, jump_host = make_ssh_server(temporary, 'jump', jump_port,
                                                  getpass.getuser(), cleanup)
            edge_key, edge_host = make_ssh_server(temporary, 'edge', edge_port,
                                                  getpass.getuser(), cleanup)
            results['checks'].append({'name': 'two-isolated-local-ssh-servers', 'ok': True})
            http_port = make_origin(cleanup)
            tls_context, ca = make_tls(temporary)
            tls_port = make_origin(cleanup, tls_context)
            excluded.update([http_port, tls_port])
            socks_port, proxy_port, local_port = [free_port(excluded) for _ in range(3)]
            panel_port = free_port(excluded)
            marker = uuid.uuid4().hex[:8]
            jump_id, edge_id = 'smoke_jump_' + marker, 'smoke_edge_' + marker
            data = temporary / 'manager data'
            data.mkdir(mode=0o700)
            config = {
                'servers': [
                    {'id': jump_id, 'name': 'Synthetic jump', 'host': '127.0.0.1',
                     'port': jump_port, 'username': getpass.getuser(), 'auth_mode': 'key',
                     'identity_file': str(jump_key), 'jump_id': None},
                    {'id': edge_id, 'name': 'Synthetic edge', 'host': '127.0.0.1',
                     'port': edge_port, 'username': getpass.getuser(), 'auth_mode': 'key',
                     'identity_file': str(edge_key), 'jump_id': jump_id},
                ],
                'tunnels': [
                    {'id': 'smoke_socks', 'name': 'Synthetic SOCKS pool', 'server_id': edge_id,
                     'kind': 'socks', 'local_port': socks_port, 'pool_size': 4, 'autostart': False},
                    {'id': 'smoke_http', 'name': 'Synthetic HTTP pool', 'server_id': edge_id,
                     'kind': 'http', 'local_port': proxy_port, 'pool_size': 2, 'autostart': False},
                    {'id': 'smoke_local', 'name': 'Synthetic TCP forward', 'server_id': edge_id,
                     'kind': 'local', 'local_port': local_port, 'pool_size': 1,
                     'remote_host': '127.0.0.1', 'remote_port': http_port, 'autostart': False},
                ],
            }
            pm.atomic_json(data / 'config.json', config)
            lines = []
            for port, public in [(jump_port, jump_host), (edge_port, edge_host)]:
                key_type, blob = public.read_text().split()[:2]
                lines.append('[127.0.0.1]:%s %s %s' % (port, key_type, blob))
            (data / 'known_hosts').write_text('\n'.join(lines) + '\n')
            (data / 'known_hosts').chmod(0o600)
            manager = LocalManager(data, ROOT, panel_port)
            # Keep the test independent of the user's existing agent and avoid
            # adding synthetic keys to it through AddKeysToAgent.
            manager.child_env.pop('SSH_AUTH_SOCK', None)
            ssh_config = data / 'ssh_config'
            ssh_config.write_text(ssh_config.read_text().replace(
                'Host *\n', 'Host *\n  IdentityAgent none\n', 1))
            for tid in ['smoke_socks', 'smoke_http', 'smoke_local']:
                manager.start(tid)

            expected = {'smoke_socks': 4, 'smoke_http': 2, 'smoke_local': 1}

            def all_ready():
                rows = {row['id']: row for row in manager.state()['tunnels']}
                return all(rows[tid]['status'] == 'connected' and
                           rows[tid]['healthy_sessions'] == count
                           for tid, count in expected.items())

            try:
                wait_for(all_ready, timeout=45, description='4/2/1 SSH pools through a jump')
            except Exception as e:
                raise RuntimeError(str(e) + '; ' + json.dumps(manager.state()['logs'][-10:]))
            results['checks'].append({'name': 'native-ssh-two-hop-pools', 'ok': True,
                                      'healthy_sessions': expected})
            target = 'http://127.0.0.1:%s' % http_port
            proxy_get('socks5h', socks_port, target + '/socks', '/socks')
            results['checks'].append({'name': 'socks-http-get', 'ok': True})
            proxy_get('http', proxy_port, target + '/http', '/http')
            results['checks'].append({'name': 'http-proxy-absolute-uri', 'ok': True})
            proxy_get('http', proxy_port, 'https://127.0.0.1:%s/connect-tls' % tls_port,
                      '/connect-tls', ca)
            results['checks'].append({'name': 'http-connect-tls-private-ca-verified', 'ok': True})
            proxy_get('socks5h', socks_port, 'https://127.0.0.1:%s/socks-tls' % tls_port,
                      '/socks-tls', ca)
            results['checks'].append({'name': 'socks-tls-private-ca-verified', 'ok': True})
            direct = command(['/usr/bin/curl', '--silent', '--show-error', '--fail',
                              '--connect-timeout', '3', '--max-time', '6', '--noproxy', '*',
                              'http://127.0.0.1:%s/local-forward' % local_port])
            if direct.stdout != 'HopHarbor local origin: /local-forward\n':
                raise RuntimeError('Unexpected local TCP forward response')
            results['checks'].append({'name': 'local-tcp-forward', 'ok': True})

            child = manager.runtime['smoke_socks']['ssh'][0]
            victim = child.proc
            assert victim and victim.poll() is None
            assert str(data / 'ssh_config') in child.argv
            original_pid = victim.pid
            os.killpg(original_pid, signal.SIGTERM)
            victim.wait(timeout=4)
            successes = 0
            for attempt in range(5):
                try:
                    proxy_get('socks5h', socks_port, target + '/surviving-pool', '/surviving-pool')
                    successes += 1
                except RuntimeError:
                    pass
                if successes >= 2:
                    break
                time.sleep(.2)
            if successes < 2:
                raise RuntimeError('Remaining SSH pool sessions did not carry local traffic')
            wait_for(lambda: bool(child.proc and child.proc.pid != original_pid and
                                  child.proc.poll() is None and
                                  port_open(manager.runtime['smoke_socks']['ports'][0])),
                     timeout=20, description='failed SSH pool child to reconnect')
            results['checks'].append({'name': 'one-child-failure-survival-and-reconnect',
                                      'ok': True, 'successful_requests_during_recovery': successes})
            for tid in list(expected):
                manager.stop(tid)
            wait_for(lambda: not any(port_open(p) for p in [socks_port, proxy_port, local_port]),
                     timeout=5, description='test tunnel ports to be released')
            results['checks'].append({'name': 'stop-releases-all-test-listeners', 'ok': True})
            ok = True
        except Exception as e:
            results['error'] = redact(e, temporary)
            results['traceback'] = redact(traceback.format_exc(), temporary)
        finally:
            if manager is not None:
                with contextlib.suppress(Exception):
                    manager.shutdown()
            for stop in reversed(cleanup):
                with contextlib.suppress(Exception):
                    stop()
    results['ok'] = ok
    results['duration_seconds'] = round(time.monotonic() - started, 2)
    pm.atomic_json(RESULT_PATH, results)
    print(json.dumps(results, indent=2))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
