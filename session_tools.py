"""Session-only transports, scoped bulk actions, and strict endpoint continuity proofs."""
import copy
import os
import secrets
import subprocess
import time
import tempfile
from pathlib import Path

from configuration_portability import digest


def endpoint(server):
    return server['host'] if server['port'] == 22 else '[%s]:%s' % (server['host'], server['port'])


class SessionTools:
    def server(self, ident):
        server = next((s for s in self.config['servers'] if s['id'] == ident), None)
        if server is None:
            raise KeyError('Session not found.')
        return server

    def firewall_paths(self):
        by_id = {s['id']: s for s in self.config['servers']}
        paths = {}
        def visit(ident, visiting):
            if ident in paths:
                return paths[ident]
            if ident in visiting or ident not in by_id:
                raise ValueError('Invalid Firewall chain.')
            parent = by_id[ident].get('jump_id')
            paths[ident] = visit(parent, visiting | {ident}) + [parent] if parent else []
            return paths[ident]
        for ident in by_id:
            visit(ident, set())
        return paths

    def firewall_path(self, ident):
        return self.firewall_paths()[ident]

    def ordered_servers(self):
        paths = self.firewall_paths()
        firewalls = {s['jump_id'] for s in self.config['servers'] if s.get('jump_id')}
        return sorted(self.config['servers'], key=lambda s: (s['id'] not in firewalls, len(paths[s['id']])))

    def ordered_tunnels(self):
        rank = {s['id']: i for i, s in enumerate(self.ordered_servers())}
        return sorted(self.config['tunnels'], key=lambda t: rank[t['server_id']])

    def control_ready(self, child, path):
        if not child.proc or child.proc.poll() is not None:
            return False
        if child.ready:
            return True  # Authentication is stable for this owned process generation.
        if not Path(path).exists():
            return False
        try:
            result = subprocess.run([self.ssh_executable(), '-F', str(self.data / 'ssh_config'),
                                     '-S', str(path), '-O', 'check', 'pm_' + child.server_id],
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=1)
            # OpenSSH opens this master socket only after strict host verification
            # and authentication. Check its owner PID as well as the exit status.
            return result.returncode == 0 and ('pid=%s)' % child.proc.pid).encode() in result.stderr
        except (OSError, subprocess.TimeoutExpired):
            return False

    def start_session_transport(self, ident):
        sessions = self.__dict__.setdefault('session_runtime', {})
        if ident in sessions:
            return
        server = self.server(ident)
        self.check_identity_setup(server)
        if os.name == 'nt':
            raise ValueError('Session-only transports require OpenSSH control sockets on this platform.')
        directory = tempfile.TemporaryDirectory(prefix='hh-session-', dir='/tmp')
        path = Path(directory.name) / 'control'
        args = [self.ssh_executable(), '-F', str(self.data / 'ssh_config'), '-N', '-n',
                '-M', '-S', str(path), '-o', 'ControlPersist=no', 'pm_' + ident]
        child = self.make_child(args, server['name'] + ' / SSH', 'session-' + ident, ident)
        sessions[ident] = {'child': child, 'path': path, 'directory': directory, 'status': 'connecting'}
        child.spawn()

    def stop_session_transport(self, ident):
        self.stop_session_transports([ident])

    def stop_session_transports(self, idents):
        with self.lock:
            sessions = self.__dict__.setdefault('session_runtime', {})
            for ident in idents:
                self.action_generation('session', ident, advance=True)
            records = [(ident, sessions[ident]) for ident in idents if ident in sessions]
            if not records:
                return
            for _, record in records:
                record['stopping'] = True
                record.pop('bulk_pending', None)
            errors = self.stop_owned_batch([record['child'] for _, record in records])
            failed = {id(child) for child, _ in errors}
            for ident, record in records:
                if id(record['child']) in failed:
                    record['status'] = 'error'
                    continue
                record['path'].unlink(missing_ok=True)
                record['directory'].cleanup()
                sessions.pop(ident, None)
            if errors:
                raise RuntimeError('Could not stop all Session transports; ownership was retained for retry.')

    def tick_session_transports(self, ident=None):
        sessions = getattr(self, 'session_runtime', {})
        for server in self.ordered_servers():
            if ident is not None and server['id'] != ident:
                continue
            record = sessions.get(server['id'])
            if not record or record.get('bulk_pending'):
                continue
            if record.get('stopping'):
                try:
                    self.stop_session_transport(server['id'])
                except Exception as error:
                    self.log('error', 'Could not finish stopping Session transport: ' + str(error), 'session-' + server['id'])
                continue
            child = record['child']
            # Retire stale sockets before starting a replacement master.
            if not child.proc or child.proc.poll() is not None:
                record['path'].unlink(missing_ok=True)
            child.tick()
            child.ready = self.control_ready(child, record['path'])
            record['status'] = 'connected' if child.ready else 'error' if child.blocked else 'connecting'
            if child.ready:
                child.failures = 0
                child.recovery_until = 0

    def check_identity_setup(self, server):
        path = self.firewall_path(server['id']) + [server['id']]
        by_id = {s['id']: s for s in self.config['servers']}
        if any(by_id[ident].get('identity_required') and not by_id[ident].get('identity_file') for ident in path):
            raise ValueError('Choose local identity files for imported sessions in this Firewall chain before connecting.')

    def action_generation(self, kind, ident, advance=False):
        generations = self.__dict__.setdefault('action_generations', {})
        key = (kind, ident)
        if advance:
            generations[key] = generations.get(key, 0) + 1
        return generations.get(key, 0)

    def bulk_action(self, scope, action):
        if scope not in ('servers', 'tunnels') or action not in ('connect', 'reconnect', 'disconnect'):
            raise KeyError('Bulk action not found.')
        if action == 'disconnect':
            return self.bulk_disconnect(scope)
        with self.lock:
            items = self.ordered_tunnels()
            tasks = [('tunnel', t['id'], t['server_id'], t['name']) for t in items]
            if scope == 'servers':
                tasks += [('session', s['id'], s['id'], s['name']) for s in self.config['servers']
                          if not any(t['server_id'] == s['id'] for t in items)]
            rank = {s['id']: i for i, s in enumerate(self.ordered_servers())}
            tasks.sort(key=lambda task: rank[task[2]])
            revision, token, selected = digest(self.config), secrets.token_hex(12), []
            for kind, ident, server_id, name in tasks:
                runtimes = self.runtime if kind == 'tunnel' else getattr(self, 'session_runtime', {})
                runtime = runtimes.get(ident)
                active = ident in runtimes
                if (action == 'connect' and active or action == 'reconnect' and not active
                        or runtime and runtime.get('bulk_pending')):
                    continue
                selected.append({'kind':kind, 'id':ident, 'server_id':server_id, 'name':name,
                                 'generation':self.action_generation(kind, ident), 'ok':True,
                                 'runtime':runtime})
            if action == 'reconnect':
                children = []
                for task in selected:
                    runtime = task['runtime']
                    runtime['bulk_pending'] = token
                    runtime['status'] = 'starting' if task['kind'] == 'tunnel' else 'connecting'
                    if task['kind'] == 'tunnel':
                        runtime.update(healthy=0,last_test=None)
                    children += (runtime.get('ssh', []) + ([runtime['gost']] if runtime.get('gost') else [])) if task['kind']=='tunnel' else [runtime['child']]
                children = list({id(child): child for child in children}.values())
                errors = self.stop_owned_batch(children) if children else []
                failed = {id(child) for child, _ in errors}
                for task in selected:
                    runtime = task['runtime']
                    owned = (runtime.get('ssh', []) + ([runtime['gost']] if runtime.get('gost') else [])) if task['kind']=='tunnel' else [runtime['child']]
                    if any(id(child) in failed for child in owned):
                        runtime.pop('bulk_pending', None)
                        runtime['status'] = 'error'
                        task.update(ok=False, error='Could not stop an owned component; ownership is retained for retry.')
        # A single bounded stop batch precedes ordered starts. Release the lock
        # between items so state/Stop can run; generations prevent resurrection.
        for task in selected:
            if not task['ok']:
                continue
            with self.lock:
                kind, ident = task['kind'], task['id']
                runtimes = self.runtime if kind == 'tunnel' else self.__dict__.setdefault('session_runtime', {})
                runtime = runtimes.get(ident)
                cancelled = (self.halt.is_set() or digest(self.config) != revision
                             or self.action_generation(kind, ident) != task['generation'])
                if cancelled:
                    if runtime is task['runtime'] and runtime and runtime.get('bulk_pending') == token:
                        runtimes.pop(ident, None)
                        if kind == 'session':
                            runtime['path'].unlink(missing_ok=True)
                            runtime['directory'].cleanup()
                    task.update(ok=False, cancelled=True, error='Stopped or changed while this request was queued; it was not restarted.')
                    continue
                try:
                    if action == 'reconnect':
                        if runtime is not task['runtime'] or runtime.get('bulk_pending') != token:
                            task.update(ok=False, cancelled=True, error='A newer action superseded this reconnect.')
                            continue
                        runtimes.pop(ident, None)
                    (self.start if kind == 'tunnel' else self.start_session_transport)(ident)
                    if action == 'reconnect' and kind == 'session':
                        runtime['path'].unlink(missing_ok=True)
                        runtime['directory'].cleanup()
                except Exception as error:
                    if action == 'reconnect' and ident not in runtimes:
                        runtime.pop('bulk_pending', None)
                        runtime['status'] = 'error'
                        runtimes[ident] = runtime
                    task.update(ok=False, error=str(error))
        results = [{k:v for k,v in task.items() if k not in ('runtime','generation','kind')} for task in selected]
        succeeded = sum(row['ok'] for row in results)
        return {'ok': succeeded == len(results), 'results': results,
                'summary': {'requested': len(results), 'succeeded': succeeded, 'failed': len(results)-succeeded}}

    def bulk_disconnect(self, scope):
        with self.lock:
            tasks = [('tunnel', t['id'], t['name']) for t in self.ordered_tunnels()]
            if scope == 'servers':
                names = {s['id']: s['name'] for s in self.config['servers']}
                # Cancel queued starts too, including a standalone transport
                # whose Session gained forwarding after it was connected.
                idents = dict.fromkeys([*names, *getattr(self, 'session_runtime', {})])
                tasks += [('session', ident, names.get(ident, ident)) for ident in idents]
            token, selected, children = secrets.token_hex(12), [], []
            for kind, ident, name in tasks:
                generation = self.action_generation(kind, ident, advance=True)
                runtimes = self.runtime if kind == 'tunnel' else getattr(self, 'session_runtime', {})
                record = runtimes.get(ident)
                if record is not None:
                    record.update(stopping=True, bulk_pending=token)
                    owned = (record.get('ssh', []) + ([record['gost']] if record.get('gost') else [])) if kind == 'tunnel' else [record['child']]
                    selected.append((kind, ident, name, record, generation, owned))
                    children.extend(owned)
            # Keep the established locked ownership contract, but signal every
            # child before waiting against ONE shared TERM/KILL deadline.
            children = list({id(child): child for child in children}.values())
            batch_error = None
            try:
                errors = self.stop_owned_batch(children) if children else []
            except Exception as error:
                errors, batch_error = [], type(error).__name__ + ': ' + str(error)
            failed = {id(child): type(error).__name__ + ': ' + str(error) for child, error in errors}
            results = []
            for kind, ident, name, record, generation, owned in reversed(selected):
                result = {'id': ident, 'name': name, 'ok': True, 'stopped': True}
                runtimes = self.runtime if kind == 'tunnel' else getattr(self, 'session_runtime', {})
                if (runtimes.get(ident) is not record or record.get('bulk_pending') != token
                        or self.action_generation(kind, ident) != generation):
                    if runtimes.get(ident) is record and record.get('bulk_pending') == token:
                        record.pop('bulk_pending', None)
                    result.update(ok=False, stopped=False, cancelled=True,
                                  error='A newer action superseded this disconnection; monitor its status.')
                    results.append(result)
                    continue
                record.pop('bulk_pending', None)
                try:
                    message = batch_error or '; '.join(failed[id(child)] for child in owned if id(child) in failed)
                    if message:
                        raise RuntimeError('Could not stop all owned components; ownership retained for retry: ' + message)
                    if kind == 'session':
                        record['path'].unlink(missing_ok=True)
                        record['directory'].cleanup()
                    runtimes.pop(ident)
                    self.log('info', 'Connection stopped: ' + name, ident)
                except Exception as error:
                    record['status'] = 'error'
                    if kind == 'tunnel':
                        record['healthy'] = 0
                    result.update(ok=False, stopped=False, error=str(error))
                results.append(result)
            succeeded = sum(row['ok'] for row in results)
            return {'ok': succeeded == len(results), 'results': results,
                    'summary': {'requested': len(results), 'succeeded': succeeded,
                                'failed': len(results)-succeeded}}

    def trusted_keys(self, server):
        result = []
        path = self.data / 'known_hosts'
        if not path.exists():
            return result
        for line in path.read_text().splitlines():
            fields = line.split()
            if len(fields) >= 3 and endpoint(server) in fields[0].split(',') and not fields[0].startswith('@'):
                result.append(' '.join(fields[1:3]))
        return result

    def prove_endpoint(self, ident, data):
        with self.lock:
            registry = self.__dict__.setdefault('proof_runtime', {})
            if self.halt.is_set():
                raise ValueError('The service is stopping; endpoint verification was cancelled.')
            if len(registry) >= 4 or any(r['server_id'] == ident for r in registry.values()):
                raise ValueError('An endpoint verification is already running. Wait for it to finish.')
            original = copy.deepcopy(self.server(ident))
            candidate = copy.deepcopy(original)
            candidate.update(host=data.get('host'), port=data.get('port'))
            config = copy.deepcopy(self.config)
            next(s for s in config['servers'] if s['id'] == ident).update(candidate)
            self.validate_all(config)
            revision = digest(self.config)
            old_host, new_host = endpoint(original), endpoint(candidate)
            keys = self.trusted_keys(original)
            if not keys:
                raise ValueError('This session has no previously trusted key. Obtain a trusted host public key first.')
            # Pin only the exact previously trusted key used by this proof, not
            # other algorithms which the new endpoint has not demonstrated.
            keys = keys[:1]
            key_type = keys[0].split()[0]
            algorithms = 'rsa-sha2-512,rsa-sha2-256' if key_type == 'ssh-rsa' else key_type
            self.check_identity_setup(original)
            directory = tempfile.TemporaryDirectory(prefix='hh-proof-', dir='/tmp' if os.name != 'nt' else None)
            known, control = Path(directory.name) / 'known', Path(directory.name) / 'control'
            self.write_private(known, ''.join(new_host + ' ' + key + '\n' for key in keys))
            args = [self.ssh_executable(), '-F', str(self.data / 'ssh_config'), '-N', '-n',
                    '-M', '-S', str(control), '-o', 'ControlPersist=no', '-o', 'ConnectTimeout=8',
                    '-o', 'HostKeyAlgorithms=' + algorithms,
                    '-o', 'UserKnownHostsFile=' + self.ssh_config_path(known), '-o', 'HostName=' + candidate['host'],
                    '-p', str(candidate['port']), 'pm_' + ident]
            child = self.make_child(args, 'Endpoint continuity check', 'proof-' + ident, ident)
            proof_id = secrets.token_hex(12)
            registry[proof_id] = {'child': child, 'directory': directory, 'server_id': ident}
        try:
            with self.lock:
                if self.halt.is_set():
                    raise ValueError('Endpoint verification was cancelled because the service is stopping.')
                child.spawn()
            deadline = time.monotonic() + 18
            while time.monotonic() < deadline:
                if self.halt.is_set() or registry.get(proof_id, {}).get('cancelled'):
                    raise ValueError('Endpoint verification was cancelled. Check the endpoint again.')
                if self.control_ready(child, control):
                    with self.lock:
                        if self.halt.is_set() or registry.get(proof_id, {}).get('cancelled') or digest(self.config) != revision:
                            raise ValueError('Session settings changed during verification. Check again.')
                        ticket = secrets.token_urlsafe(32)
                        self.__dict__.setdefault('trust_proofs', {})[ident] = {
                            'ticket': ticket, 'expires': time.monotonic()+120, 'revision': revision,
                            'host': candidate['host'], 'port': candidate['port'], 'original': original, 'keys': keys}
                        return {'ok': True, 'ticket': ticket,
                                'message': 'The new endpoint proved possession of the previously trusted key and authenticated successfully. Save to trust this endpoint.'}
                if not child.proc or child.proc.poll() is not None or child.blocked:
                    raise ValueError('The endpoint did not pass strict host-key verification and SSH authentication. No trust was changed.')
                time.sleep(.1)
            raise ValueError('Endpoint verification timed out. No trust was changed.')
        finally:
            with self.lock:
                if proof_id in registry:
                    registry[proof_id]['closing'] = True
                if not self.stop_endpoint_proofs(only_closing=True):
                    raise RuntimeError('Endpoint verification cleanup is pending; ownership was retained for retry.')

    def stop_endpoint_proofs(self, only_closing=False):
        with self.lock:
            records = [(ident, record) for ident, record in getattr(self, 'proof_runtime', {}).items()
                       if not only_closing or record.get('closing')]
            if not records:
                return True
            for _, record in records:
                record['cancelled'] = True
            errors = self.stop_owned_batch([r['child'] for _, r in records])
            failed = {id(child) for child, _ in errors}
            for ident, record in records:
                if id(record['child']) not in failed:
                    record['directory'].cleanup()
                    self.proof_runtime.pop(ident, None)
            if errors:
                if only_closing:
                    self.log('warning', 'Endpoint verification cleanup will retry; process ownership is retained.')
                    return False
                raise RuntimeError('Could not stop all endpoint checks; ownership was retained for retry.')
            return True

    def verified_pin(self, ident, record, ticket):
        proof = getattr(self, 'trust_proofs', {}).get(ident)
        if (not proof or not isinstance(ticket, str) or not secrets.compare_digest(ticket, proof['ticket'])
                or time.monotonic() > proof['expires'] or digest(self.config) != proof['revision']
                or any(record.get(k) != proof[k] for k in ('host', 'port'))
                or any(record.get(k) != proof['original'].get(k) for k in
                       ('username', 'jump_id', 'auth_mode', 'identity_file', 'keepalive_interval', 'keepalive_count'))):
            raise ValueError('Endpoint verification expired or settings changed. Check the endpoint again.')
        return ''.join(endpoint(record) + ' ' + key + '\n' for key in proof['keys'])
