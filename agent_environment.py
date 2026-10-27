"""Pass only the current desktop's SSH-agent socket to future Linux SSH children.

The user service can start before the graphical session's SSH agent. This tiny
private handoff avoids restarting working tunnels or importing arbitrary desktop
environment variables into the service.
"""
import json
import os
from pathlib import Path
import stat
import tempfile


FILENAME = '.desktop-agent.json'
MAX_BYTES = 4096


def _directory(data, create=False):
    path = Path(data)
    if create:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('The SSH-agent handoff requires a private application directory.')
    return path


def _socket(value):
    if (not isinstance(value, str) or not value or len(value) > 2048
            or '\0' in value or not os.path.isabs(value)):
        return None
    try:
        info = os.lstat(value)
    except (OSError, ValueError):
        return None
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
        return None
    return value


def write_agent_environment(data, environ=None):
    """Publish an owned socket, or explicit absence to clear a previous agent."""
    path = _directory(data, create=True)
    value = _socket((os.environ if environ is None else environ).get('SSH_AUTH_SOCK'))
    descriptor, temporary = tempfile.mkstemp(prefix='.desktop-agent-', dir=path)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            json.dump({'ssh_auth_sock': value}, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path / FILENAME)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def child_environment(base, data):
    """Refresh only SSH_AUTH_SOCK; absence preserves the service's own context."""
    result = dict(base)
    descriptor = None
    try:
        path = _directory(data) / FILENAME
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | getattr(os, 'O_CLOEXEC', 0))
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or not 0 < info.st_size <= MAX_BYTES):
            raise ValueError('Invalid SSH-agent handoff.')
        with os.fdopen(descriptor, 'rb') as source:
            descriptor = None
            raw = source.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError('Invalid SSH-agent handoff.')
        body = json.loads(raw)
        if not isinstance(body, dict) or set(body) != {'ssh_auth_sock'}:
            raise ValueError('Invalid SSH-agent handoff.')
        value = _socket(body['ssh_auth_sock'])
        if value:
            result['SSH_AUTH_SOCK'] = value
        else:
            result.pop('SSH_AUTH_SOCK', None)
    except FileNotFoundError:
        # Before any desktop launch, an already valid service environment may
        # provide agent access. A published but stale socket clears it below.
        pass
    except (OSError, ValueError, TypeError, UnicodeError):
        result.pop('SSH_AUTH_SOCK', None)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return result
