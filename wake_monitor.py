"""Detect confirmed macOS wake changes without subprocesses or a GUI dependency."""
import ctypes
import sys


class _Timeval(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long), ('tv_usec', ctypes.c_int)]


class _NativeWakeReader:
    def __init__(self):
        self.library = ctypes.CDLL(None, use_errno=True)
        self.query = self.library.sysctlbyname
        self.query.argtypes = [ctypes.c_char_p, ctypes.c_void_p,
                               ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
        self.query.restype = ctypes.c_int

    def __call__(self):
        value = _Timeval()
        size = ctypes.c_size_t(ctypes.sizeof(value))
        result = self.query(b'kern.waketime', ctypes.byref(value), ctypes.byref(size), None, 0)
        if result != 0 or size.value != ctypes.sizeof(value):
            return None
        # Compare fields rather than padding bytes in the native structure.
        return value.tv_sec, value.tv_usec


def _native_reader():
    if sys.platform != 'darwin':
        return None
    try:
        return _NativeWakeReader()
    except (AttributeError, OSError):
        return None


def _valid_token(value):
    return (isinstance(value, tuple) and len(value) == 2
            and type(value[0]) is int and value[0] >= 0
            and type(value[1]) is int and 0 <= value[1] < 1_000_000)


class WakeMonitor:
    """Emit one resume event per changed kernel wake token; read failures are inert."""
    def __init__(self, reader=None):
        self._reader = reader if reader is not None else _native_reader()
        self._last_token = self._read()

    def _read(self):
        if self._reader is None:
            return None
        try:
            value = self._reader()
        except Exception:
            return None
        return value if _valid_token(value) else None

    def resumed(self):
        token = self._read()
        if token is None:
            return False
        previous = self._last_token
        self._last_token = token
        return previous is not None and token != previous
