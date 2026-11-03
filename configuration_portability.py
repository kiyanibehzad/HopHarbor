"""Strict portable configuration: no credentials, local key paths or host trust."""
import copy
import hashlib
import json
import re
import secrets
import time
import uuid

SESSION = {'id', 'name', 'host', 'port', 'username', 'jump_id', 'auth_mode',
           'keepalive_interval', 'keepalive_count', 'identity_required'}
FORWARD = {'id', 'name', 'server_id', 'kind', 'local_port', 'remote_host', 'remote_port',
           'pool_size', 'autostart', 'probe_type'}
FORMAT = 'HopHarbor configuration'
LIMIT = 262144


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def portable_session(server):
    result = {k: copy.deepcopy(v) for k, v in server.items() if k in SESSION and k != 'identity_required'}
    result['identity_required'] = bool(server.get('identity_file') or server.get('identity_required'))
    return result


def portable_forward(forward):
    return {k: copy.deepcopy(v) for k, v in forward.items() if k in FORWARD}


def export_configuration(config):
    return {'format': FORMAT, 'schema_version': 1, 'origin': config['portable_origin'],
            'sessions': [portable_session(s) for s in config['servers']],
            'forwards': [portable_forward(t) for t in config['tunnels']], 'settings': {}}


def exact_fields(value, allowed, required):
    if not isinstance(value, dict) or set(value) - allowed or not required <= set(value):
        raise ValueError('Missing or unknown configuration fields.')


def preview(manager, document):
    exact_fields(document, {'format', 'schema_version', 'origin', 'sessions', 'forwards', 'settings'},
                 {'format', 'schema_version', 'origin', 'sessions', 'forwards', 'settings'})
    if document['format'] != FORMAT or type(document['schema_version']) is not int or document['schema_version'] != 1:
        raise ValueError('Unsupported configuration format or schema version.')
    origin = document['origin']
    if not isinstance(origin, str) or not re.fullmatch('[a-f0-9]{32}', origin):
        raise ValueError('Invalid configuration origin.')
    if document['settings'] != {} or not isinstance(document['settings'], dict):
        raise ValueError('Unknown global settings. Device settings are not portable.')
    if any(not isinstance(document[k], list) or len(document[k]) > 100 for k in ('sessions', 'forwards')):
        raise ValueError('Invalid configuration collections.')
    if len(json.dumps(document).encode()) > LIMIT:
        raise ValueError('Configuration is too large.')
    for row in document['sessions']:
        exact_fields(row, SESSION, {'id', 'host', 'username', 'identity_required'})
        if type(row['identity_required']) is not bool:
            raise ValueError('Invalid identity requirement.')
    for row in document['forwards']:
        exact_fields(row, FORWARD, {'id', 'server_id', 'kind', 'local_port'})
    # Reject coercible wrong types, duplicate IDs, cycles and references before merge.
    for rows in (document['sessions'], document['forwards']):
        for row in rows:
            for key, value in row.items():
                if key in ('port', 'local_port', 'remote_port', 'pool_size', 'keepalive_interval', 'keepalive_count'):
                    if type(value) is not int:
                        raise ValueError('Numeric configuration fields must be integers.')
                elif key in ('autostart', 'identity_required'):
                    if type(value) is not bool:
                        raise ValueError('Invalid boolean setting.')
                elif key == 'jump_id' and value is None:
                    continue
                elif not isinstance(value, str) or len(value) > 1024:
                    raise ValueError('Invalid configuration text.')
    incoming = {'servers': copy.deepcopy(document['sessions']), 'tunnels': copy.deepcopy(document['forwards'])}
    manager.validate_all(incoming)
    current = copy.deepcopy(manager.config)
    counts = {'sessions_added': 0, 'forwards_added': 0, 'skipped': 0}
    mappings = {}
    existing_records = {}
    # Resolve every Session ID before comparing any reference. Session and
    # forwarding IDs intentionally occupy separate namespaces.
    for row in incoming['servers']:
        existing = next((x for x in current['servers']
                         if (x.get('portable_origin') == origin and x.get('portable_id') == row['id'])
                         or (origin == current['portable_origin'] and x['id'] == row['id'])), None)
        mappings[row['id']] = existing['id'] if existing else uuid.uuid4().hex[:12]
        existing_records[row['id']] = existing
    for collection, source, encode in (('servers', incoming['servers'], portable_session),
                                       ('tunnels', incoming['tunnels'], portable_forward)):
        for row in source:
            ident = row['id']
            existing = existing_records[ident] if collection == 'servers' else next((x for x in current[collection]
                         if (x.get('portable_origin') == origin and x.get('portable_id') == ident)
                         or (origin == current['portable_origin'] and x['id'] == ident)), None)
            expected = copy.deepcopy(row)
            if collection == 'servers':
                expected['jump_id'] = mappings.get(row.get('jump_id'))
            else:
                expected['server_id'] = mappings[row['server_id']]
            if existing:
                actual = encode(existing)
                actual['id'] = expected['id']
                if existing.get('portable_origin') == origin and collection == 'tunnels':
                    actual['autostart'] = expected.get('autostart', False)
                if actual != expected:
                    raise ValueError('An imported ID conflicts with saved configuration. No changes were applied.')
                counts['skipped'] += 1
                continue
            entry = expected
            entry.update(id=mappings[ident] if collection == 'servers' else uuid.uuid4().hex[:12],
                         portable_origin=origin, portable_id=ident)
            if collection == 'servers':
                entry['identity_file'] = ''
            else:
                entry['autostart'] = False
                if manager.port_is_open(entry['local_port']):
                    raise ValueError('An imported local port is occupied. No changes were applied.')
            current[collection].append(entry)
            counts['sessions_added' if collection == 'servers' else 'forwards_added'] += 1
    manager.validate_all(current)
    return current, counts


class ConfigurationTools:
    def export_configuration(self):
        with self.lock:
            return export_configuration(self.config)

    def preview_import(self, document):
        with self.lock:
            self.import_preview = None
            proposed, counts = preview(self, document)
            token = secrets.token_urlsafe(32)
            self.import_preview = (token, time.monotonic() + 300, digest(self.config), proposed)
            return dict(ok=True, ticket=token, summary=counts,
                        changes=['Session: %s (%s:%s)' % (s['name'], s['host'], s['port']) for s in proposed['servers'] if s['id'] not in {x['id'] for x in self.config['servers']}] + ['Forward: %s (127.0.0.1:%s)' % (t['name'], t['local_port']) for t in proposed['tunnels'] if t['id'] not in {x['id'] for x in self.config['tunnels']}],
                        warnings=['Imported entries stay disconnected and auto-connect is disabled.',
                                  'Host trust and credentials are not imported. Verify host keys and supply local credentials.',
                                  'Identity-file paths are omitted. Choose a local key before using key authentication.'])

    def apply_import(self, ticket):
        with self.lock:
            pending = getattr(self, 'import_preview', None)
            if (not pending or not isinstance(ticket, str) or not secrets.compare_digest(ticket, pending[0])
                    or time.monotonic() > pending[1] or digest(self.config) != pending[2]):
                raise ValueError('Import preview expired or configuration changed. Preview the file again.')
            self.validate_all(pending[3])
            old = self.config
            if digest(old) == digest(pending[3]):
                self.import_preview = None
                return {'ok': True, 'changed': False}
            # Persistent rollback contains only this device's private configuration.
            self.write_config_backup(old)
            self.config = pending[3]
            try:
                self.save()
                self.write_ssh_config()
            except Exception:
                self.config = old
                self.save()
                self.write_ssh_config()
                raise
            self.import_preview = None
            self.import_undo = (old, digest(self.config))
            return {'ok': True, 'changed': True}

    def undo_import(self):
        with self.lock:
            pending = getattr(self, 'import_undo', None)
            if not pending or digest(self.config) != pending[1]:
                raise ValueError('Configuration changed after import. The private pre-import backup remains available.')
            before = pending[0]
            added_sessions = {s['id'] for s in self.config['servers']} - {s['id'] for s in before['servers']}
            added_forwards = {t['id'] for t in self.config['tunnels']} - {t['id'] for t in before['tunnels']}
            if added_sessions.intersection(getattr(self, 'session_runtime', {})) or added_forwards.intersection(self.runtime):
                raise ValueError('Disconnect imported entries before undoing the import.')
            after = self.config
            self.config = before
            try:
                self.save()
                self.write_ssh_config()
            except Exception:
                self.config = after
                self.save()
                self.write_ssh_config()
                raise
            self.import_undo = None
            self.import_preview = None
            return {'ok': True}
