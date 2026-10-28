#!/usr/bin/python3
"""Local-only controller. OpenSSH carries SSH; GOST handles proxy frontends."""
import argparse
import base64
import datetime
import fcntl
import hashlib
import hmac
import http.cookies
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid

from log_policy import EventLog, LogMaintenance, install_service_streams
from wake_monitor import WakeMonitor

VERSION = '1.2.1'
BUILD = 9
MAC_VERSION = '1.1.5'
MAC_BUILD = 8
ID_RE = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')
USER_RE = re.compile(r'^[a-zA-Z0-9_][a-zA-Z0-9_.@-]{0,63}$')


def kernel_file_limit():
    """Read macOS's per-process ceiling without modifying any system setting."""
    if sys.platform != 'darwin':
        return None
    try:
        result = subprocess.run(['/usr/sbin/sysctl', '-n', 'kern.maxfilesperproc'],
                                capture_output=True, text=True, timeout=2, check=True)
        ceiling = int(result.stdout.strip())
        return ceiling if ceiling > 0 else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def raise_file_limit(target=8192, kernel_ceiling=None):
    """Raise only this process's soft limit; children inherit it unchanged."""
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (OSError, ValueError) as error:
        return {'soft': None, 'hard': None, 'warning': str(error)}
    desired = min(target, hard) if hard != resource.RLIM_INFINITY else target
    if kernel_ceiling is not None:
        desired = min(desired, kernel_ceiling)
    if soft != resource.RLIM_INFINITY and soft < desired:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        except (OSError, ValueError) as error:
            return {'soft': soft, 'hard': hard, 'warning': str(error)}
    return {'soft': soft, 'hard': hard, 'warning': ''}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def atomic_json(path, value):
    path = Path(path)
    tmp = path.with_name(path.name + '.tmp')
    fd = os.open(str(tmp), os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))
    path.chmod(0o600)


def host_ok(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        return False
    if any(ord(c) < 33 or ord(c) > 126 for c in value) or any(c in value for c in '%\\/\"\''):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value))


def integer(value, low, high, title):
    if isinstance(value, bool):
        raise ValueError(title)
    try:
        n = int(value)
    except (ValueError, TypeError):
        raise ValueError(title)
    if str(n) != str(value) or not low <= n <= high:
        raise ValueError(title)
    return n


def quote(value):
    if '\n' in value or '\r' in value or '\0' in value:
        raise ValueError('Invalid value.')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def port_open(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=.2):
            return True
    except OSError:
        return False


def reserve_port(exclude):
    for _ in range(100):
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            p = s.getsockname()[1]
        if p not in exclude:
            return p
    raise ValueError('No available local port was found.')


class Child:
    def __init__(self, argv, label, manager, tunnel_id, server_id=None):
        self.argv, self.label, self.manager, self.tunnel_id = argv, label, manager, tunnel_id
        self.proc = None
        self.last_start = 0
        self.next_start = 0
        self.failures = 0
        self.ready = False
        self.error = ''
        self.error_time = 0
        self.blocked = False
        self.generation = 0
        self.server_id = server_id
        self.recovery_until = 0
        self.is_gost = (server_id is None and bool(argv) and getattr(manager, 'app', None) is not None
                        and argv[0] == str(manager.app / 'bin/gost'))

    def spawn(self):
        with self.manager.lock:
            self._spawn()

    def _spawn(self):
        self.generation += 1
        self.last_start = time.monotonic()
        self.ready = False
        try:
            env = dict(self.manager.child_env)
            if sys.platform.startswith('linux') and self.server_id:
                from agent_environment import child_environment
                env = child_environment(env, self.manager.data)
            if self.server_id:
                env['PM_SERVER_ID'] = self.server_id
            self.proc = subprocess.Popen(self.argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, start_new_session=True,
                                         env=env, close_fds=True)
        except OSError as e:
            self.error = 'Could not start component: ' + str(e)
            self.error_time = time.monotonic()
            self.next_start = time.monotonic() + 60
            self.manager.log('error', self.error, self.tunnel_id)
            return
        # A new process must not inherit errors or late stderr from its predecessor.
        self.error = ''
        self.error_time = 0
        self.blocked = False
        atomic_json(self.manager.data / 'runtime' / ('child-%s.json' % self.proc.pid),
                    {'pid': self.proc.pid, 'argv': self.argv})
        self.manager.log('info', self.label + ' started.', self.tunnel_id)
        threading.Thread(target=self.read_log, args=(self.proc, self.generation), daemon=True).start()

    def read_log(self, proc, generation=None):
        if generation is None:
            generation = self.generation
        for raw in iter(lambda: proc.stdout.readline(4096), b''):
            line = raw.decode('utf-8', 'replace').strip()[:1200]
            if not line:
                continue
            if self.is_gost and self.manager.is_front_probe_eof(line):
                continue
            request_error = False
            if self.is_gost:
                try:
                    details = json.loads(line)
                    if isinstance(details, dict) and isinstance(details.get('msg'), str):
                        line = details['msg']
                        # A failed client request is history, not a broken SSH component.
                        # Listener/startup/fatal errors still need persistent attention.
                        request_error = ((details.get('kind') in ('handler', 'dialer', 'connector')
                                          or (details.get('kind') == 'service'
                                              and isinstance(details.get('sid'), str) and bool(details['sid'])))
                                         and details.get('level') != 'fatal')
                except (ValueError, TypeError):
                    pass
            line = line[:800]
            # OpenSSH and GOST never receive a password through argv/config here.
            with self.manager.lock:
                if generation != self.generation:
                    continue
                if not request_error:
                    self.error = line
                    self.error_time = time.monotonic()
                    if any(x in line.lower() for x in ('permission denied', 'host key verification failed',
                                                       'remote host identification has changed',
                                                       'invalid format', 'no such identity')):
                        self.blocked = True
                self.manager.log('error', self.label + ': ' + line, self.tunnel_id)
        proc.stdout.close()

    def tick(self):
        with self.manager.lock:
            self._tick()

    def _tick(self):
        t = time.monotonic()
        if self.proc and self.proc.poll() is not None:
            code = self.proc.returncode
            (self.manager.data / 'runtime' / ('child-%s.json' % self.proc.pid)).unlink(missing_ok=True)
            self.proc = None
            self.ready = False
            self.failures = self.failures + 1 if t - self.last_start < 60 else 1
            delay = min(60, 5 * (2 ** min(self.failures - 1, 4)))
            if self.server_id and t < self.recovery_until:
                delay = 1
            self.next_start = t + delay
            if code and not self.error:
                self.error = 'Process exited with code %s.' % code
                self.error_time = t
                self.manager.log('error', self.label + ': ' + self.error, self.tunnel_id)
        if not self.proc and not self.blocked and t >= self.next_start:
            self.spawn()

    def stop(self, timeout=4):
        with self.manager.lock:
            self._stop(timeout)

    def _stop(self, timeout):
        p = self.proc
        self.ready = False
        if p and p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                p.wait(timeout=2)
        self._finish_stop(p)

    def _finish_stop(self, p):
        # Preserve ownership if terminating/waiting raised an error.
        self.generation += 1
        self.proc = None
        if p:
            (self.manager.data / 'runtime' / ('child-%s.json' % p.pid)).unlink(missing_ok=True)

    @staticmethod
    def stop_many(children, timeout=.5, kill_timeout=2):
        """Stop owned transports with shared deadlines, while the manager is locked."""
        pending, errors = [], []
        for child in children:
            child.ready = False
            proc = child.proc
            try:
                if proc and proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                pending.append((child, proc))
            except Exception as error:
                errors.append((child, error))
        deadline = time.monotonic() + timeout
        survivors = []
        for child, proc in pending:
            try:
                if proc and proc.poll() is None:
                    proc.wait(timeout=max(0, deadline - time.monotonic()))
                child._finish_stop(proc)
            except subprocess.TimeoutExpired:
                survivors.append((child, proc))
            except Exception as error:
                errors.append((child, error))
        killed = []
        # Signal every survivor before waiting for any of them a second time.
        for child, proc in survivors:
            try:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                killed.append((child, proc))
            except Exception as error:
                errors.append((child, error))
        deadline = time.monotonic() + kill_timeout
        for child, proc in killed:
            try:
                proc.wait(timeout=max(0, deadline - time.monotonic()))
                child._finish_stop(proc)
            except Exception as error:
                errors.append((child, error))
        return errors


class Manager:
    def __init__(self, data_dir, app_dir, port, service_streams=()):
        # Do this before spawning managed children or reader/monitor threads.
        self.fd_limits = raise_file_limit(kernel_ceiling=kernel_file_limit())
        self.data = Path(data_dir).resolve()
        self.app = Path(app_dir).resolve()
        self.port = port
        self.started_at = now()
        self.lock = threading.RLock()
        self.data.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.data.chmod(0o700)
        self.service_lock = os.open(str(self.data / '.service.lock'), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self.service_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.service_lock)
            raise RuntimeError('Another service instance is already using this configuration.')
        (self.data / 'runtime').mkdir(mode=0o700, exist_ok=True)
        self.reap_owned_children()
        self.config_path = self.data / 'config.json'
        self.config = json.loads(self.config_path.read_text()) if self.config_path.exists() else {
            'servers': [], 'tunnels': [], 'migration': {'phase': 'testing', 'message': 'Testing on separate local ports.'}}
        control = self.data / 'control.json'
        self.token = json.loads(control.read_text())['token'] if control.exists() else secrets.token_urlsafe(48)
        atomic_json(control, {'port': port, 'token': self.token})
        self.cookies = {}
        self.logs = EventLog()
        self.log_maintenance = LogMaintenance(self.logs, service_streams)
        self.next_maintenance = 0
        if self.fd_limits['warning']:
            self.log('error', 'Could not raise the open-file limit: ' + self.fd_limits['warning'])
        self.runtime = {}
        self.front_probe_lock = threading.Lock()
        self.front_probes = {}
        self.halt = threading.Event()
        self.wake_monitor = WakeMonitor()
        self.wake_recovery = None
        self.child_env = dict(os.environ)
        self.child_env['LC_ALL'] = 'C'
        self.child_env['SSH_ASKPASS'] = str(self.app / 'askpass.py')
        self.child_env['SSH_ASKPASS_REQUIRE'] = 'force'
        self.child_env['DISPLAY'] = 'HopHarbor'
        self.child_env['PM_DATA_DIR'] = str(self.data)
        self.secret_status = {}
        for server in self.config.get('servers', []):
            self.refresh_secret_status(server['id'])
        self.validate_all(self.config)
        self.write_ssh_config()
        for tunnel in self.config['tunnels']:
            if tunnel.get('autostart'):
                try:
                    self.start(tunnel['id'])
                except Exception as e:
                    self.log('error', str(e), tunnel['id'])
        threading.Thread(target=self.watch, daemon=True).start()

    def reap_owned_children(self):
        for f in (self.data / 'runtime').glob('child-*.json'):
            try:
                obj = json.loads(f.read_text())
                pid = int(obj['pid'])
                cmd = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'command='],
                                     capture_output=True, text=True, timeout=3).stdout
                # Only children whose exact dedicated configuration path is still present.
                owned = (cmd.startswith('/usr/bin/ssh -F ' + str(self.data / 'ssh_config') + ' ')
                         or (str(self.data / 'runtime') + '/') in cmd and '/bin/gost -C ' in cmd)
                if owned and os.getpgid(pid) == pid:
                    os.killpg(pid, signal.SIGTERM)
                f.unlink(missing_ok=True)
            except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
                f.unlink(missing_ok=True)

    def log(self, level, message, tunnel_id=None):
        with self.lock:
            self.logs.append({'time': now(), 'level': level, 'message': message,
                              'tunnel_id': tunnel_id})

    def maintain_local_files(self):
        """Bound diagnostics and discard only inactive, app-generated proxy configs."""
        self.log_maintenance.maintenance(force=True)
        for path in (self.data / 'runtime').glob('*.json'):
            ident = path.stem
            if (ident in self.runtime or ident.startswith('child-')
                    or not ID_RE.fullmatch(ident) or path.is_symlink()):
                continue
            try:
                if not path.is_file() or path.stat().st_size > 65536:
                    continue
                config = json.loads(path.read_text())
                services = config.get('services') if isinstance(config, dict) else None
                if (isinstance(services, list) and len(services) == 1
                        and isinstance(services[0], dict) and services[0].get('name') == ident
                        and config.get('log') == {'level': 'error', 'output': 'stderr'}
                        and str(services[0].get('addr', '')).startswith('127.0.0.1:')):
                    path.unlink(missing_ok=True)
            except (OSError, ValueError):
                continue

    def front_probe(self, port):
        """Check a frontend listener and record this exact empty TCP connection."""
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.2) as probe:
                local = '%s:%s' % probe.getpeername()[:2]
                remote = '%s:%s' % probe.getsockname()[:2]
                timestamp = time.monotonic()
                # Record before close, since close is what makes HTTP handlers log EOF.
                with self.front_probe_lock:
                    self.front_probes = {key: stamp for key, stamp in self.front_probes.items()
                                         if 0 <= timestamp - stamp <= 5}
                    self.front_probes[(local, remote)] = timestamp
            return True
        except OSError:
            return False

    def is_front_probe_eof(self, line):
        """Consume only an exact, recent self-probe EOF; preserve other GOST errors."""
        try:
            record = json.loads(line)
        except (ValueError, TypeError):
            return False
        if not isinstance(record, dict) or record.get('msg') != 'EOF' or record.get('kind') != 'handler':
            return False
        local, remote = record.get('local'), record.get('remote')
        if not isinstance(local, str) or not isinstance(remote, str):
            return False
        if record.get('client', remote) != remote:
            return False
        with self.front_probe_lock:
            timestamp = self.front_probes.pop((local, remote), None)
        return timestamp is not None and 0 <= time.monotonic() - timestamp <= 5

    def save(self):
        atomic_json(self.config_path, self.config)

    def keychain(self, action, payload):
        if sys.platform.startswith('linux'):
            helper = self.app / 'credentials.py'
            if not helper.is_file():
                raise ValueError('The GNOME Keyring component is unavailable. Install or update the app.')
            q = subprocess.run([sys.executable, str(helper), action], input=json.dumps(payload),
                               text=True, capture_output=True, timeout=15)
            if q.returncode:
                raise ValueError('Could not access GNOME Keyring. Sign in to the desktop and unlock the login keyring.')
            return json.loads(q.stdout)
        helper = self.app / 'bin/keychain-helper'
        if not helper.exists():
            if action == 'has':
                return {'has_password': False, 'has_key_passphrase': False}
            raise ValueError('The Keychain component is unavailable. Install or update the app.')
        q = subprocess.run([str(helper), action], input=json.dumps(payload), text=True,
                           capture_output=True, timeout=15)
        if q.returncode:
            raise ValueError('Could not read or save Keychain credentials. Check the app access permissions.')
        return json.loads(q.stdout)

    def refresh_secret_status(self, server_id):
        try:
            self.secret_status[server_id] = self.keychain('has', {'server_id': server_id})
        except (ValueError, subprocess.TimeoutExpired):
            self.secret_status[server_id] = {'has_password': False, 'has_key_passphrase': False}

    def validate_all(self, config):
        servers = config.get('servers', [])
        tunnels = config.get('tunnels', [])
        if len(servers) > 100 or len(tunnels) > 100:
            raise ValueError('Up to 100 sessions and 100 port forwarding entries are supported.')
        ids = set()
        for s in servers:
            if not ID_RE.fullmatch(s.get('id', '')) or s['id'] in ids:
                raise ValueError('Invalid session ID.')
            ids.add(s['id'])
            if not host_ok(s.get('host')) or not USER_RE.fullmatch(s.get('username', '')):
                raise ValueError('Invalid session hostname or username.')
            s['port'] = integer(s.get('port', 22), 1, 65535, 'Invalid SSH port.')
            s['keepalive_interval'] = integer(s.get('keepalive_interval', 30), 0, 600,
                                              'The keepalive interval must be between 0 and 600 seconds.')
            s['keepalive_count'] = integer(s.get('keepalive_count', 3), 1, 10,
                                           'The keepalive retry count must be between 1 and 10.')
            s['name'] = str(s.get('name') or s['id'])[:100]
            s['auth_mode'] = s.get('auth_mode') or ('key' if s.get('identity_file') else 'agent')
            if s['auth_mode'] not in ('agent', 'key', 'password', 'key_password'):
                raise ValueError('Invalid authentication method.')
            identity = s.get('identity_file') or ''
            if identity:
                p = Path(os.path.expanduser(identity))
                if not p.is_absolute() or not p.is_file() or p.stat().st_uid != os.getuid():
                    raise ValueError('The identity file must exist and belong to the current user.')
                quote(str(p))
                s['identity_file'] = str(p)
            jump = s.get('jump_id')
            if jump == '':
                s['jump_id'] = None
        by_id = {s['id']: s for s in servers}
        for s in servers:
            seen = {s['id']}
            j = s.get('jump_id')
            while j:
                if j not in by_id or j in seen:
                    raise ValueError('The firewall chain is invalid or contains a loop.')
                seen.add(j)
                j = by_id[j].get('jump_id')
        ports, ids = set(), set()
        for t in tunnels:
            if not ID_RE.fullmatch(t.get('id', '')) or t['id'] in ids:
                raise ValueError('Invalid port forwarding ID.')
            ids.add(t['id'])
            if t.get('server_id') not in by_id or t.get('kind') not in ('socks', 'local', 'http'):
                raise ValueError('Invalid port forwarding type or session.')
            t['local_port'] = integer(t.get('local_port'), 1024, 65535, 'Invalid local port.')
            if t['local_port'] == self.port or t['local_port'] in ports:
                raise ValueError('The local port is already assigned.')
            ports.add(t['local_port'])
            t['pool_size'] = integer(t.get('pool_size', 1), 1, 4, 'The SSH session count must be between 1 and 4.')
            t['autostart'] = bool(t.get('autostart', False))
            t['name'] = str(t.get('name') or t['id'])[:100]
            if t['kind'] == 'local':
                if not host_ok(t.get('remote_host')):
                    raise ValueError('Invalid port forwarding destination.')
                t['remote_port'] = integer(t.get('remote_port'), 1, 65535, 'Invalid destination port.')

    def write_ssh_config(self):
        known = self.data / 'known_hosts'
        if not known.exists():
            known.touch(mode=0o600)
        lines = ['Host *', '  BatchMode no', '  NumberOfPasswordPrompts 1', '  StrictHostKeyChecking yes',
                 '  UpdateHostKeys no', '  UserKnownHostsFile ' + quote(str(known)),
                 '  GlobalKnownHostsFile /dev/null', '  ControlMaster no', '  ControlPath none',
                 '  ConnectTimeout 12', '  ConnectionAttempts 1',
                 '  TCPKeepAlive yes', '  ExitOnForwardFailure yes',
                 '  RequestTTY no', '  Compression no', '  ForwardAgent no',
                 '  GSSAPIAuthentication no', '  AddKeysToAgent yes',
                 '  LogLevel ERROR', '']
        if sys.platform == 'darwin':
            # Apple's option is rejected by stock OpenSSH on Linux.
            lines.insert(-2, '  UseKeychain yes')
        for s in self.config['servers']:
            lines += ['Host pm_' + s['id'], '  HostName ' + s['host'],
                      '  User ' + s['username'], '  Port ' + str(s['port']),
                      '  ServerAliveInterval ' + str(s.get('keepalive_interval', 30)),
                      '  ServerAliveCountMax ' + str(s.get('keepalive_count', 3))]
            if s.get('identity_file'):
                lines += ['  IdentityFile ' + quote(s['identity_file']), '  IdentitiesOnly yes']
            mode = s.get('auth_mode', 'agent')
            lines += ['  PubkeyAuthentication ' + ('no' if mode == 'password' else 'yes'),
                      '  PasswordAuthentication ' + ('yes' if mode in ('password', 'key_password') else 'no'),
                      '  KbdInteractiveAuthentication ' + ('yes' if mode in ('password', 'key_password') else 'no')]
            if s.get('jump_id'):
                command = '/usr/bin/python3 ' + quote(str(self.app / 'ssh_hop.py'))
                command += ' --data-dir ' + quote(str(self.data)) + ' --app-dir ' + quote(str(self.app))
                command += ' --server ' + s['jump_id'] + ' --host %h --port %p'
                lines += ['  ProxyCommand ' + command]
            lines.append('')
        p = self.data / 'ssh_config'
        p.write_text('\n'.join(lines))
        p.chmod(0o600)

    def tunnel(self, tunnel_id):
        for t in self.config['tunnels']:
            if t['id'] == tunnel_id:
                return t
        raise KeyError('Port forwarding entry not found.')

    def gost_config(self, tunnel, backend_ports):
        # A failed loopback SSH backend can return as soon as Wi-Fi is ready.
        selector = {'strategy': 'round', 'maxFails': 1, 'failTimeout': '1s'}
        service = {'name': tunnel['id'], 'addr': '127.0.0.1:' + str(tunnel['local_port']),
                   'listener': {'type': 'tcp'}, 'handler': {'type': 'tcp'}}
        cfg = {'services': [service], 'log': {'level': 'error', 'output': 'stderr'}}
        if tunnel['kind'] == 'http':
            service['handler'] = {'type': 'http', 'chain': 'ssh-pool'}
            cfg['chains'] = [{'name': 'ssh-pool', 'hops': [{'name': 'pool', 'selector': selector,
                'nodes': [{'name': 'ssh-' + str(i), 'addr': '127.0.0.1:' + str(p),
                           'connector': {'type': 'socks5'}, 'dialer': {'type': 'tcp'}}
                          for i, p in enumerate(backend_ports)]}]}]
        else:
            service['forwarder'] = {'selector': selector, 'nodes': [
                {'name': 'ssh-' + str(i), 'addr': '127.0.0.1:' + str(p)}
                for i, p in enumerate(backend_ports)]}
        return cfg

    def start(self, tunnel_id):
        with self.lock:
            t = self.tunnel(tunnel_id)
            if tunnel_id in self.runtime:
                return
            if port_open(t['local_port']):
                raise ValueError('Another application is using this port. Choose a different local port.')
            used = {x['local_port'] for x in self.config['tunnels']} | {self.port}
            for r in self.runtime.values():
                used.update(r['ports'])
            ports = []
            for _ in range(t['pool_size']):
                p = reserve_port(used)
                used.add(p)
                ports.append(p)
            children = []
            for i, p in enumerate(ports):
                args = ['/usr/bin/ssh', '-F', str(self.data / 'ssh_config'), '-N', '-n']
                if t['kind'] == 'local':
                    target = t['remote_host']
                    if ':' in target:
                        target = '[' + target + ']'
                    args += ['-L', '127.0.0.1:%s:%s:%s' % (p, target, t['remote_port'])]
                else:
                    args += ['-D', '127.0.0.1:' + str(p)]
                args += ['pm_' + t['server_id']]
                children.append(Child(args, t['name'] + ' / SSH ' + str(i + 1), self, tunnel_id, t['server_id']))
            cfgpath = self.data / 'runtime' / (tunnel_id + '.json')
            atomic_json(cfgpath, self.gost_config(t, ports))
            gost = Child([str(self.app / 'bin/gost'), '-C', str(cfgpath)], t['name'] + ' / Proxy', self, tunnel_id)
            self.runtime[tunnel_id] = {'ports': ports, 'ssh': children, 'gost': gost,
                                       'status': 'starting', 'healthy': 0, 'last_test': None}
            for c in children:
                c.spawn()
            # Public listener is started only after at least one SSH session is ready.
            self.log('info', 'Connection requested: ' + t['name'], tunnel_id)

    def stop(self, tunnel_id):
        with self.lock:
            r = self.runtime.get(tunnel_id)
            if r:
                r['stopping'] = True
                errors = []
                for child in [r['gost']] + r['ssh']:
                    try:
                        child.stop()
                    except Exception as error:
                        errors.append(str(error))
                if errors:
                    r.update(status='error', healthy=0)
                    raise RuntimeError('Could not stop all components: ' + '; '.join(errors))
                self.runtime.pop(tunnel_id, None)
                self.log('info', 'Port forwarding stopped.', tunnel_id)

    def session_action(self, server_id, action):
        """Control a Session's own forwarding entries, preserving dependent Sessions."""
        with self.lock:
            if not any(s['id'] == server_id for s in self.config['servers']):
                raise KeyError('Session not found.')
            if action not in ('connect', 'disconnect', 'reconnect'):
                raise KeyError('Action not found.')
            own = [t for t in self.config['tunnels'] if t['server_id'] == server_id]
            if not own:
                raise ValueError('This session has no port forwarding entries. Add a port forwarding entry first.')
            results = []
            for tunnel in own:
                result = {'tunnel_id': tunnel['id'], 'name': tunnel['name'], 'ok': True}
                try:
                    if action in ('disconnect', 'reconnect'):
                        self.stop(tunnel['id'])
                    if action in ('connect', 'reconnect'):
                        self.start(tunnel['id'])
                except Exception as error:
                    # One occupied port or failed process must not roll back other forwards.
                    result.update(ok=False, error=str(error))
                    self.log('error', 'Session action failed: ' + str(error), tunnel['id'])
                results.append(result)
            succeeded = sum(result['ok'] for result in results)
            return {'ok': succeeded == len(results), 'server_id': server_id, 'action': action,
                    'results': results, 'summary': {'requested': len(results), 'succeeded': succeeded,
                                                  'failed': len(results) - succeeded}}

    def _session_runtime_state(self, server_id, tunnels):
        """Summarize existing forwarding runtimes; a Session has no separate transport."""
        own = [t for t in tunnels if t['server_id'] == server_id]
        active = [t for t in own if t['desired_running']]
        by_id = {s['id']: s for s in self.config['servers']}
        dependents = set()
        for session in self.config['servers']:
            seen = {session['id']}
            jump = session.get('jump_id')
            while jump and jump not in seen and jump in by_id:
                if jump == server_id:
                    dependents.add(session['id'])
                    break
                seen.add(jump)
                jump = by_id[jump].get('jump_id')
        dependent_count = sum(t['server_id'] in dependents and t['desired_running'] for t in tunnels)
        statuses = set()
        healthy_forward_count = 0
        for tunnel in active:
            status = tunnel['status']
            healthy_ssh = min(tunnel['healthy_sessions'], tunnel['active_sessions'])
            if status in ('connected', 'degraded'):
                if not healthy_ssh:
                    status = 'starting'
                else:
                    healthy_forward_count += 1
                    if healthy_ssh < tunnel['pool_size']:
                        status = 'degraded'
            statuses.add(status)
        if not active:
            status = 'in_use_as_firewall' if dependent_count else 'disconnected'
        elif statuses == {'connected'}:
            status = 'connected'
        elif statuses == {'starting'}:
            status = 'connecting'
        elif statuses == {'error'}:
            status = 'error'
        else:
            status = 'degraded'
        return {'connection_status': status, 'own_forward_count': len(own),
                'active_forward_count': len(active),
                'healthy_forward_count': healthy_forward_count,
                'active_ssh_count': sum(t['active_sessions'] for t in active),
                'healthy_ssh_count': sum(min(t['healthy_sessions'], t['active_sessions']) for t in active),
                'firewall_in_use': bool(dependent_count), 'dependent_forward_count': dependent_count}

    def recover_after_wake(self):
        """Rebuild stale transports once per confirmed kernel wake, on the same ports."""
        with self.lock:
            active = [r for r in self.runtime.values() if not r.get('stopping')]
            if not active:
                return
            self.log('info', ('Mac woke from sleep' if sys.platform == 'darwin' else 'Computer resumed from sleep')
                     + '; refreshing active SSH connections.')
            started = time.monotonic()
            children = [c for r in active for c in r['ssh'] if not c.blocked]
            self.wake_recovery = {'started': started, 'until': started + 90,
                                  'pending': set(), 'restored': set()}
            for tid, r in self.runtime.items():
                if not r.get('stopping'):
                    r.update(status='starting', healthy=0, last_test=None)
                    if any(not c.blocked for c in r['ssh']):
                        self.wake_recovery['pending'].add(tid)
            errors = Child.stop_many(children)
            failed = {id(c) for c, _error in errors}
            for c in children:
                if id(c) not in failed:
                    c.failures = 0
                    c.next_start = 0
                    c.recovery_until = started + 90
            for c, error in errors:
                self.log('error', 'Could not refresh SSH connection: ' + str(error), c.tunnel_id)

    def watch_interval(self):
        recovery = getattr(self, 'wake_recovery', None)
        if recovery and recovery['pending'] and time.monotonic() < recovery['until']:
            return .5
        return 3

    def record_wake_progress(self, tid, r):
        recovery = getattr(self, 'wake_recovery', None)
        if not recovery or tid not in recovery['pending']:
            return
        if r['status'] == 'connected':
            recovery['pending'].discard(tid)
            recovery['restored'].add(tid)
            self.log('info', 'SSH connections restored after wake in %.1f seconds.' %
                     (time.monotonic() - recovery['started']), tid)

    def watch(self):
        while not self.halt.wait(self.watch_interval()):
            with self.lock:
                if self.wake_monitor.resumed():
                    self.recover_after_wake()
                if time.monotonic() >= self.next_maintenance:
                    self.next_maintenance = time.monotonic() + 60
                    try:
                        self.maintain_local_files()
                    except Exception:
                        self.log('warning', 'Local diagnostic cleanup could not finish; it will retry.')
                for tid, r in list(self.runtime.items()):
                    if r.get('stopping'):
                        try:
                            self.stop(tid)
                        except Exception as error:
                            self.log('error', 'Could not finish stopping port forwarding: ' + str(error), tid)
                        continue
                    try:
                        for c in r['ssh']:
                            c.tick()
                    except Exception as e:
                        self.log('error', 'Port forwarding monitor error: ' + str(e), tid)
                        r['status'] = 'error'
                        continue
                    healthy = 0
                    for c, p in zip(r['ssh'], r['ports']):
                        ready = bool(c.proc and c.proc.poll() is None and port_open(p))
                        c.ready = ready
                        if ready:
                            c.recovery_until = 0
                            c.failures = 0
                            healthy += 1
                    r['healthy'] = healthy
                    if healthy < len(r['ssh']):
                        r['last_test'] = None
                    blocked = any(c.blocked for c in r['ssh'])
                    if healthy:
                        try:
                            r['gost'].tick()
                        except Exception as e:
                            self.log('error', 'Proxy process error: ' + str(e), tid)
                            r['status'] = 'error'
                            continue
                        front = r['gost'].proc and r['gost'].proc.poll() is None and self.front_probe(self.tunnel(tid)['local_port'])
                        r['status'] = ('connected' if healthy == len(r['ssh']) else 'degraded') if front else 'starting'
                    else:
                        r['status'] = 'error' if blocked else 'starting'
                    self.record_wake_progress(tid, r)
                recovery = getattr(self, 'wake_recovery', None)
                if recovery:
                    recovery['pending'].intersection_update(self.runtime)
                    if not recovery['pending'] or time.monotonic() >= recovery['until']:
                        remaining = len(recovery['pending'])
                        if remaining or recovery['restored']:
                            self.log('warning' if remaining else 'info',
                                     ('Wake recovery window ended; %s port forwarding entries are still reconnecting.' % remaining)
                                     if remaining else 'All active SSH connections restored after wake in %.1f seconds.' %
                                     (time.monotonic() - recovery['started']))
                        self.wake_recovery = None

    def test(self, tid):
        with self.lock:
            t = dict(self.tunnel(tid))
            r = self.runtime.get(tid)
            if not r or not r['healthy']:
                raise ValueError('Connect the port forwarding entry first.')
        kind = 'http' if t['kind'] == 'http' else t.get('probe_type', 'socks' if t['kind'] == 'socks' else 'tcp')
        if kind not in ('http', 'socks'):
            result = {'ok': self.front_probe(t['local_port']), 'message': 'TCP listener test only; internet access was not checked.', 'time': now()}
        else:
            proxy = ('socks5h' if kind == 'socks' else 'http') + '://127.0.0.1:' + str(t['local_port'])
            args = ['/usr/bin/curl', '--proxy', proxy, '--noproxy', '', '--connect-timeout', '6', '--max-time', '12',
                    '--silent', '--show-error', '--output', '/dev/null', '--write-out', '%{http_code} %{time_total}',
                    'https://example.com/']
            q = subprocess.run(args, capture_output=True, text=True, timeout=15)
            ok = q.returncode == 0 and q.stdout.startswith('200 ')
            details = q.stdout.strip()[-100:]
            if not ok and q.stderr.strip():
                details += ('; ' if details else '') + q.stderr.strip()[-500:]
            result = {'ok': ok, 'message': ('Internet access verified: ' if ok else 'Test failed: ') + details, 'time': now()}
        with self.lock:
            if tid in self.runtime:
                self.runtime[tid]['last_test'] = result
            self.log('info' if result['ok'] else 'error', result['message'], tid)
        return result

    def state(self):
        with self.lock:
            tunnels = []
            for t in self.config['tunnels']:
                row = dict(t)
                r = self.runtime.get(t['id'])
                errors = [c for c in r['ssh'] + [r['gost']] if c.error] if r else []
                latest_error = max(errors, key=lambda c: getattr(c, 'error_time', 0)).error if errors else ''
                row.update(status=r['status'] if r else 'stopped', desired_running=bool(r),
                           healthy_sessions=r['healthy'] if r else 0,
                           active_sessions=sum(bool(c.proc and c.proc.poll() is None) for c in r['ssh']) if r else 0,
                           connections=None, pid=r['gost'].proc.pid if r and r['gost'].proc else None,
                           last_error=latest_error, last_test=r['last_test'] if r else None)
                tunnels.append(row)
            known = (self.data / 'known_hosts').read_text().splitlines()
            servers = []
            for server in self.config['servers']:
                row = dict(server)
                host = server['host'] if server['port'] == 22 else '[%s]:%s' % (server['host'], server['port'])
                row['host_key_trusted'] = any(l.split() and host in l.split()[0].split(',') for l in known)
                row.update({k: bool(self.secret_status.get(server['id'], {}).get(k)) for k in ('has_password', 'has_key_passphrase')})
                row.update(self._session_runtime_state(server['id'], tunnels))
                servers.append(row)
            return {'servers': servers, 'tunnels': tunnels, 'logs': self.logs.snapshot(),
                    'service': {'version': MAC_VERSION if sys.platform == 'darwin' else VERSION,
                                'build': MAC_BUILD if sys.platform == 'darwin' else BUILD,
                                'port': self.port, 'started_at': self.started_at,
                                'platform': 'linux' if sys.platform.startswith('linux') else sys.platform,
                                'credential_store': 'GNOME Keyring' if sys.platform.startswith('linux') else 'Keychain',
                                'fd_soft_limit': self.fd_limits['soft'], 'fd_hard_limit': self.fd_limits['hard'],
                                'fd_limit_warning': self.fd_limits['warning'],
                                'log_policy': {'retention': 'local-day', 'max_events': 200,
                                               'max_message_chars': 800, 'repeat_window_seconds': 30,
                                               'disk_file_bytes': 262144, 'disk_files': 2,
                                               'cleanup_interval_seconds': 60, 'archives': 0},
                                'default_identity_file': self.config.get('default_identity_file', '')},
                    'migration': self.config.get('migration', {})}

    def mutate(self, collection, ident, data, delete=False):
        with self.lock:
            current = json.loads(json.dumps(self.config))
            items = current[collection]
            existing = next((x for x in items if x['id'] == ident), None) if ident else None
            if ident and not existing:
                raise KeyError('Item not found.')
            if collection == 'tunnels' and ident in self.runtime:
                raise ValueError('Stop this port forwarding entry before editing or deleting it.')
            if collection == 'servers' and ident:
                affected = {ident}
                for _ in self.config['servers']:
                    affected.update(s['id'] for s in self.config['servers'] if s.get('jump_id') in affected)
                if any(t['server_id'] in affected and t['id'] in self.runtime for t in self.config['tunnels']):
                    raise ValueError('Stop the port forwarding entries that depend on this session first.')
                if delete and (any(t['server_id'] == ident for t in self.config['tunnels']) or
                               any(s.get('jump_id') == ident for s in self.config['servers'])):
                    raise ValueError('This session is still used by a port forwarding entry or firewall chain.')
            if existing:
                items.remove(existing)
            if not delete:
                allowed = {'id', 'name', 'host', 'port', 'username', 'identity_file', 'jump_id', 'auth_mode',
                           'keepalive_interval', 'keepalive_count'} if collection == 'servers' else {
                    'id', 'name', 'server_id', 'kind', 'local_port', 'remote_host', 'remote_port', 'pool_size', 'autostart', 'probe_type'}
                record = dict(existing or {})
                record.update({k: v for k, v in data.items() if k in allowed})
                record['id'] = ident or uuid.uuid4().hex[:12]
                items.append(record)
            self.validate_all(current)
            credentials = {}
            if collection == 'servers' and not delete:
                for field in ('password', 'key_passphrase'):
                    value = data.get(field)
                    if value is not None and (not isinstance(value, str) or len(value) > 8192):
                        raise ValueError('Invalid authentication credentials.')
                    if value:
                        credentials[field] = value
            pin = None
            if collection == 'servers' and not delete and data.get('host_key'):
                key = data['host_key'].strip().split()
                if len(key) < 2 or key[0] not in ('ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'):
                    raise ValueError('The host key must be a valid OpenSSH public key.')
                try:
                    raw = base64.b64decode(key[1], validate=True)
                    n = int.from_bytes(raw[:4], 'big')
                    if raw[4:4+n].decode() != key[0] or len(raw) < n + 10:
                        raise ValueError()
                except Exception:
                    raise ValueError('Invalid host public key.')
                host = record['host'] if record['port'] == 22 else '[%s]:%s' % (record['host'], record['port'])
                pin = host + ' ' + key[0] + ' ' + key[1] + '\n'
            if credentials:
                self.keychain('put', dict(credentials, server_id=record['id']))
            if collection == 'servers' and delete:
                # Entries are owned by this app's service namespace only.
                self.keychain('delete', {'server_id': ident})
            self.config = current
            if pin:
                with (self.data / 'known_hosts').open('a') as f:
                    f.write(pin)
            self.save()
            self.write_ssh_config()
            if collection == 'servers' and not delete:
                self.refresh_secret_status(record['id'])
            return {'ok': True, 'id': ident or record['id']}

    def shutdown(self):
        self.halt.set()
        for tid in list(self.runtime):
            self.stop(tid)
        if self.service_lock is not None:
            fcntl.flock(self.service_lock, fcntl.LOCK_UN)
            os.close(self.service_lock)
            self.service_lock = None


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'LocalProxyManager'
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    @property
    def manager(self):
        return self.server.manager

    def trusted_host(self):
        return self.headers.get('Host') == '127.0.0.1:' + str(self.manager.port)

    def reply(self, status, data, content_type='application/json; charset=utf-8', headers=None):
        body = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def auth(self):
        try:
            c = http.cookies.SimpleCookie(self.headers.get('Cookie', ''))
            session = c['pm_session'].value
            expiry = self.manager.cookies.get(session, 0)
            if expiry > time.monotonic():
                self.manager.cookies[session] = time.monotonic() + 12 * 3600
                return True
        except (KeyError, http.cookies.CookieError):
            pass
        return False

    def read_json(self):
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            raise ValueError('The request content type must be JSON.')
        n = int(self.headers.get('Content-Length', 0))
        if not 0 <= n <= 65536:
            raise ValueError('The request is too large.')
        data = json.loads(self.rfile.read(n) or b'{}')
        if not isinstance(data, dict):
            raise ValueError('Invalid request.')
        return data

    def do_GET(self):
        if not self.trusted_host():
            return self.reply(403, {'error': 'Request host is not allowed.'})
        path = urllib.parse.urlsplit(self.path).path
        if path == '/api/state':
            return self.reply(200, self.manager.state()) if self.auth() else self.reply(401, {'error': 'Panel authentication is required. Reopen the app.'})
        if path.startswith('/api/'):
            return self.reply(404, {'error': 'Endpoint not found.'})
        if path not in ('/', '/index.html', '/app.js'):
            return self.reply(404, {'error': 'File not found.'})
        try:
            filename = 'app.js' if path == '/app.js' else 'index.html'
            ctype = 'application/javascript; charset=utf-8' if filename.endswith('.js') else 'text/html; charset=utf-8'
            self.reply(200, (self.manager.app / 'web' / filename).read_bytes(), ctype)
        except FileNotFoundError:
            self.reply(503, {'error': 'The management panel is not ready yet.'})

    def change(self):
        origin = 'http://127.0.0.1:' + str(self.manager.port)
        if not self.trusted_host() or self.headers.get('Origin') != origin or self.headers.get('X-Requested-With') != 'ProxyManager':
            return self.reply(403, {'error': 'Requests from outside this panel are not allowed.'})
        try:
            data = self.read_json()
            parts = urllib.parse.urlsplit(self.path).path.strip('/').split('/')
            if parts == ['api', 'session'] and self.command == 'POST':
                token = data.get('token', '')
                if not isinstance(token, str) or not hmac.compare_digest(token, self.manager.token):
                    return self.reply(401, {'error': 'Invalid panel access token.'})
                session = secrets.token_urlsafe(32)
                self.manager.cookies[session] = time.monotonic() + 12 * 3600
                return self.reply(200, {'ok': True}, headers={'Set-Cookie': 'pm_session=' + session + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200'})
            if not self.auth():
                return self.reply(401, {'error': 'Panel authentication is required.'})
            if len(parts) >= 2 and parts[0] == 'api' and parts[1] in ('servers', 'tunnels'):
                collection = parts[1]
                if len(parts) == 2 and self.command == 'POST':
                    return self.reply(201, self.manager.mutate(collection, None, data))
                if len(parts) == 3 and self.command in ('PUT', 'DELETE'):
                    return self.reply(200, self.manager.mutate(collection, parts[2], data, self.command == 'DELETE'))
                if len(parts) == 4 and collection == 'servers' and self.command == 'POST':
                    return self.reply(200, self.manager.session_action(parts[2], parts[3]))
                if len(parts) == 4 and collection == 'tunnels' and self.command == 'POST':
                    tid, action = parts[2:]
                    if action == 'test':
                        return self.reply(200, self.manager.test(tid))
                    if action not in ('start', 'stop', 'restart'):
                        raise KeyError('Action not found.')
                    if action in ('stop', 'restart'):
                        self.manager.stop(tid)
                    if action in ('start', 'restart'):
                        self.manager.start(tid)
                    return self.reply(200, {'ok': True})
            return self.reply(404, {'error': 'Endpoint not found.'})
        except KeyError as e:
            return self.reply(404, {'error': str(e).strip("'")})
        except (ValueError, json.JSONDecodeError) as e:
            return self.reply(400, {'error': str(e)})
        except subprocess.TimeoutExpired:
            return self.reply(504, {'error': 'The connection test timed out.'})
        except Exception:
            self.manager.log('error', 'Internal error while processing the request.')
            return self.reply(500, {'error': 'Internal error. Check the event log.'})

    do_POST = change
    do_PUT = change
    do_DELETE = change


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--data-dir', required=True)
    p.add_argument('--app-dir', default=str(Path(__file__).parent))
    p.add_argument('--port', type=int, default=17777)
    a = p.parse_args()
    os.umask(0o077)
    data_dir = Path(a.data_dir).expanduser().resolve()
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    data_dir.chmod(0o700)
    streams = install_service_streams(data_dir / 'logs')
    sys.stdout, sys.stderr = streams
    httpd = http.server.ThreadingHTTPServer(('127.0.0.1', a.port), Handler)
    httpd.daemon_threads = True
    try:
        manager = Manager(a.data_dir, a.app_dir, a.port, service_streams=streams)
    except Exception:
        httpd.server_close()
        raise
    httpd.manager = manager
    def stop(*_):
        threading.Thread(target=httpd.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    manager.log('info', 'HopHarbor background service is ready.')
    try:
        httpd.serve_forever(poll_interval=1)
    finally:
        manager.shutdown()
        httpd.server_close()


if __name__ == '__main__':
    main()
