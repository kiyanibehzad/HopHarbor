"""Detect kernel sleep/wake changes without subprocesses or a GUI dependency."""
import ctypes
import math
import sys
import time


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


class _LinuxWakeReader:
    """BOOTTIME includes suspend; MONOTONIC does not. Neither uses wall time."""
    def __init__(self, boot_clock=None, monotonic_clock=None):
        if boot_clock is None:
            clock_id = time.CLOCK_BOOTTIME
            boot_clock = lambda: time.clock_gettime(clock_id)
        self.boot_clock = boot_clock
        self.monotonic_clock = monotonic_clock or time.monotonic
        self.offset = None
        self.generation = 0

    def __call__(self):
        before = self.boot_clock()
        mono = self.monotonic_clock()
        after = self.boot_clock()
        # Discard a sample if scheduling delay could resemble a suspend. The
        # next fast sample establishes the actual cumulative suspend offset.
        if (not all(math.isfinite(value) for value in (before, mono, after))
                or after < before or after - before > .05):
            return None
        offset = (before + after) / 2 - mono
        if self.offset is None:
            self.offset = offset
        elif offset - self.offset >= .25:
            self.offset = offset
            self.generation += 1
        # A stable token absorbs clock-read jitter instead of treating a few
        # nanoseconds of offset noise as a fresh wake on every monitor tick.
        return self.generation, 0


class _WindowsWakeReader(_LinuxWakeReader):
    """Windows boot ticks include suspend; unbiased interrupt time excludes it."""
    def __init__(self, boot_clock=None, monotonic_clock=None):
        if boot_clock is None or monotonic_clock is None:
            self.library = ctypes.WinDLL('kernel32', use_last_error=True)
            self.ticks = self.library.GetTickCount64
            self.ticks.argtypes = []
            self.ticks.restype = ctypes.c_ulonglong
            self.unbiased = self.library.QueryUnbiasedInterruptTime
            self.unbiased.argtypes = [ctypes.POINTER(ctypes.c_ulonglong)]
            self.unbiased.restype = ctypes.c_int
            boot_clock = boot_clock or (lambda: self.ticks() / 1000)
            monotonic_clock = monotonic_clock or self.awake_seconds
        super().__init__(boot_clock=boot_clock, monotonic_clock=monotonic_clock)

    def awake_seconds(self):
        value = ctypes.c_ulonglong()
        if not self.unbiased(ctypes.byref(value)):
            raise OSError('The Windows unbiased clock could not be read.')
        return value.value / 10_000_000


def _native_reader():
    try:
        if sys.platform == 'darwin':
            return _NativeWakeReader()
        if sys.platform.startswith('linux'):
            return _LinuxWakeReader()
        if sys.platform == 'win32':
            return _WindowsWakeReader()
    except (AttributeError, OSError):
        pass
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
