#!/usr/bin/python3
"""Linux Secret Service helper. Secrets travel through pipes, never command arguments.

The macOS build continues to use its signed native Keychain helper. This module
is loaded only by the Linux credential subprocess and does not provide a file or
plaintext fallback when the desktop keyring is unavailable.
"""
import json
import os
import re
import sys
import threading


MAX_INPUT = 65536
MAX_SECRET = 8192
ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')


class CredentialError(Exception):
    pass


def identifier(value):
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise CredentialError('invalid_request')
    return value


def secret_value(value):
    if (not isinstance(value, str) or not value or len(value.encode('utf-8')) > MAX_SECRET
            or any(char in value for char in ('\0', '\r', '\n'))):
        raise CredentialError('invalid_request')
    return value


def prompt_kind(prompt):
    text = prompt.lower()
    if (not text or len(text.encode('utf-8')) > 16384
            or any(value in text for value in ('yes/no', 'fingerprint', 'continue connecting',
                                               'host key', 'authenticity of host'))):
        raise CredentialError('invalid_request')
    if 'passphrase' in text:
        return 'passphrase'
    if 'password' in text:
        return 'password'
    raise CredentialError('invalid_request')


class SecretStore:
    """Access existing keyrings without unlocking them from an SSH subprocess."""
    def __init__(self):
        import gi
        gi.require_version('Secret', '1')
        from gi.repository import Gio, Secret
        self.secret = Secret
        self.cancel = Gio.Cancellable()
        # Every synchronous D-Bus operation has a bounded lifetime, including
        # askpass, whose stdout is reserved exclusively for the SSH response.
        self.timer = threading.Timer(10, self.cancel.cancel)
        self.timer.daemon = True
        self.timer.start()
        self.schema = Secret.Schema.new('io.github.kiyanibehzad.HopHarbor.Credentials',
                                        Secret.SchemaFlags.NONE,
                                        {key: Secret.SchemaAttributeType.STRING
                                         for key in ('application', 'server_id', 'kind')})
        self.service = Secret.Service.get_sync(Secret.ServiceFlags.OPEN_SESSION
                                              | Secret.ServiceFlags.LOAD_COLLECTIONS,
                                              self.cancel)
        if self.service is None:
            raise CredentialError('credential_store_unavailable')

    def close(self):
        self.timer.cancel()

    @staticmethod
    def attributes(kind, ident):
        return {'application': 'HopHarbor', 'server_id': ident, 'kind': kind}

    def items(self, kind, ident):
        # No UNLOCK or LOAD_SECRETS flags: listing status must never show a
        # dialog, and metadata attributes do not contain a password.
        return self.service.search_sync(self.schema, self.attributes(kind, ident),
                                        self.secret.SearchFlags.ALL, self.cancel) or []

    def has(self, kind, ident):
        return bool(self.items(kind, ident))

    def read(self, kind, ident):
        for item in self.items(kind, ident):
            if item.get_locked():
                continue
            # libsecret loads the secret only for an already unlocked item.
            if not item.load_secret_sync(self.cancel):
                continue
            value = item.get_secret()
            if value is not None:
                return secret_value(value.get_text())
        raise CredentialError('credential_store_unavailable')

    def put(self, kind, ident, value):
        collection = self.secret.Collection.for_alias_sync(self.service, 'default',
                                                          self.secret.CollectionFlags.NONE,
                                                          self.cancel)
        if collection is None or collection.get_locked():
            raise CredentialError('credential_store_unavailable')
        self.secret.Item.create_sync(collection, self.schema, self.attributes(kind, ident),
                                     'HopHarbor · ' + ident,
                                     self.secret.Value.new(value, -1, 'text/plain'),
                                     self.secret.ItemCreateFlags.REPLACE, self.cancel)

    def delete(self, kind, ident):
        items = self.items(kind, ident)
        if any(item.get_locked() for item in items):
            raise CredentialError('credential_store_unavailable')
        for item in items:
            item.delete_sync(self.cancel)


def handle(action, body, store):
    if not isinstance(body, dict):
        raise CredentialError('invalid_request')
    ident = identifier(body.get('server_id'))
    if action == 'put':
        values = [(kind, secret_value(body[key]))
                  for kind, key in [('password', 'password'), ('passphrase', 'key_passphrase')]
                  if body.get(key) is not None]
        if not values:
            raise CredentialError('invalid_request')
        for kind, value in values:
            store.put(kind, ident, value)
    elif action == 'delete':
        store.delete('password', ident)
        store.delete('passphrase', ident)
        return {'ok': True, 'has_password': False, 'has_key_passphrase': False}
    elif action != 'has':
        raise CredentialError('invalid_request')
    return {'ok': True, 'has_password': store.has('password', ident),
            'has_key_passphrase': store.has('passphrase', ident)}


def main(argv=None, stdin=None, stdout=None, store_factory=SecretStore, environ=None):
    argv = sys.argv[1:] if argv is None else argv
    stdin = sys.stdin.buffer if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    environ = os.environ if environ is None else environ
    action = argv[0] if argv else ''
    store = None
    try:
        if action == 'askpass':
            ident = identifier(environ.get('PM_SERVER_ID'))
            kind = prompt_kind(' '.join(argv[1:]))
            store = store_factory()
            stdout.write(secret_value(store.read(kind, ident)) + '\n')
        else:
            if len(argv) != 1 or action not in ('has', 'put', 'delete'):
                raise CredentialError('invalid_request')
            raw = stdin.read(MAX_INPUT + 1)
            if not raw or len(raw) > MAX_INPUT:
                raise CredentialError('invalid_request')
            body = json.loads(raw)
            # Validate the request before contacting or activating a keyring.
            if not isinstance(body, dict):
                raise CredentialError('invalid_request')
            identifier(body.get('server_id'))
            if action == 'put':
                supplied = [secret_value(body[key]) for key in ('password', 'key_passphrase')
                            if body.get(key) is not None]
                if not supplied:
                    raise CredentialError('invalid_request')
            store = store_factory()
            stdout.write(json.dumps(handle(action, body, store), sort_keys=True) + '\n')
        return 0
    except Exception:
        # Do not expose D-Bus errors, item data or the SSH prompt in output.
        if action != 'askpass':
            stdout.write('{"ok": false, "error": "credential_store_unavailable"}\n')
        return 1
    finally:
        if store is not None:
            close = getattr(store, 'close', None)
            if close is not None:
                close()


if __name__ == '__main__':
    sys.exit(main())
