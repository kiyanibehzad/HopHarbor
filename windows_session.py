"""Windows OpenSSH post-authentication proof, without a listener or remote command."""
import secrets
import re
import shutil
import weakref
from pathlib import Path

import windows_platform as native


class AuthenticationDirectory:
    """Create a fresh directory with explicit current-user ownership, even elevated."""
    def __init__(self, runtime, prefix):
        if prefix not in ('hh-session-', 'hh-proof-'):
            raise ValueError('Invalid authentication directory prefix.')
        native.validate_private_directory(runtime)
        for _ in range(16):
            path = Path(runtime) / (prefix + secrets.token_hex(16))
            try:
                native.ensure_private_directory(path, exist_ok=False)
                break
            except FileExistsError:
                continue
        else:
            raise FileExistsError('Could not allocate a private authentication directory.')
        self.name = str(path)
        self._finalizer = weakref.finalize(self, self._remove, self.name)

    @staticmethod
    def _remove(name):
        native.validate_private_directory(name)
        shutil.rmtree(name)

    def cleanup(self):
        if self._finalizer.alive:
            self._remove(self.name)
            self._finalizer.detach()


class WindowsAuthenticationProof:
    def __init__(self, marker):
        self.marker = Path(marker)
        self.nonce = None
        self.generation = None
        self.accepted = False

    @staticmethod
    def options():
        # OpenSSH expands %% to %, then Windows expands the trusted environment
        # variable once. cmd /c consumes the outer quote pair; the inner pair
        # protects spaces and metacharacters in the expanded executable path.
        # No hostname, username, path or nonce is shell-interpolated.
        return ['-o', 'PermitLocalCommand=yes', '-o',
                'LocalCommand=""%%HOPHARBOR_APP%%\\bin\\HopHarborHelper.exe" session-ready"']

    def begin(self, child):
        self.accepted = False
        self.nonce = secrets.token_hex(32)
        self.generation = child.generation
        native.validate_private_directory(self.marker.parent)
        if self.marker.exists():
            native.validate_private_file(self.marker)
            self.marker.unlink()
        return {'HOPHARBOR_AUTH_MARKER': str(self.marker),
                'HOPHARBOR_AUTH_NONCE': self.nonce,
                'HOPHARBOR_AUTH_GENERATION': str(self.generation)}

    def ready(self, child):
        if (self.nonce is None or self.generation != child.generation or child.blocked
                or not child.proc or child.proc.poll() is not None):
            return False
        if self.accepted:
            return True
        try:
            value = native.read_private_json(self.marker, max_bytes=512)
            if (not isinstance(value, dict) or set(value) != {'nonce', 'generation'}
                    or type(value['generation']) is not int or value['generation'] != self.generation
                    or not isinstance(value['nonce'], str) or not re.fullmatch('[a-f0-9]{64}', value['nonce'])
                    or not secrets.compare_digest(value['nonce'], self.nonce)):
                return False
            self.marker.unlink()
            self.accepted = True
            return True
        except (OSError, ValueError):
            return False
