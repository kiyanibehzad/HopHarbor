"""Private, bounded logging for the current local calendar day; no archives."""
import datetime
import hashlib
import io
import os
from pathlib import Path
import stat
import threading
import time


EVENT_LIMIT = 200
MESSAGE_LIMIT = 800
DEDUP_SECONDS = 30
STREAM_LIMIT = 256 * 1024
WRITE_LIMIT = 4096
STREAM_NAMES = ('service.stdout.log', 'service.stderr.log')


def _local_now(clock):
    return clock().astimezone()


class EventLog:
    """A deque-compatible snapshot of at most 200 small, same-day events."""
    maxlen = EVENT_LIMIT

    def __init__(self, clock=None, monotonic_clock=None):
        self._clock = clock or datetime.datetime.now
        self._monotonic = monotonic_clock or time.monotonic
        self._lock = threading.RLock()
        self._entries = []
        self._dedup = {}

    def _prune(self, day):
        self._entries = [entry for entry in self._entries if entry['_day'] == day]
        self._dedup = {entry['_key']: entry for entry in self._entries}

    def append(self, event):
        if not isinstance(event, dict):
            event = {'message': event}
        level = str(event.get('level', 'info'))[:24]
        original_message = str(event.get('message', ''))
        message = original_message[:MESSAGE_LIMIT]
        tunnel = event.get('tunnel_id')
        tunnel = None if tunnel is None else str(tunnel)[:64]
        key = (level, hashlib.sha256(original_message.encode('utf-8', 'replace')).digest(), tunnel)
        with self._lock:
            stamp = _local_now(self._clock)
            tick = self._monotonic()
            self._prune(stamp.date())
            previous = self._dedup.get(key)
            if previous is not None and 0 <= tick - previous['_tick'] <= DEDUP_SECONDS:
                previous.update(time=stamp.isoformat(), repeats=previous['repeats'] + 1, _tick=tick)
                self._entries.remove(previous)
                self._entries.append(previous)
            else:
                entry = {'time': stamp.isoformat(), 'level': level, 'message': message,
                         'tunnel_id': tunnel, 'repeats': 1, '_day': stamp.date(), '_tick': tick, '_key': key}
                self._entries.append(entry)
                if len(self._entries) > EVENT_LIMIT:
                    self._entries.pop(0)
                self._dedup = {entry['_key']: entry for entry in self._entries}

    def snapshot(self):
        with self._lock:
            self._prune(_local_now(self._clock).date())
            return [{key: entry[key] for key in ('time', 'level', 'message', 'tunnel_id', 'repeats')}
                    for entry in self._entries]

    def maintenance(self):
        with self._lock:
            self._prune(_local_now(self._clock).date())

    def clear(self):
        with self._lock:
            self._entries.clear()
            self._dedup.clear()

    def __iter__(self):
        return iter(self.snapshot())

    def __len__(self):
        with self._lock:
            self._prune(_local_now(self._clock).date())
            return len(self._entries)

    def __bool__(self):
        return len(self) != 0

    def __getitem__(self, index):
        return self.snapshot()[index]


class DailyBoundedStream(io.TextIOBase):
    """Unbuffered text output to one exact, private log file, truncated in place."""
    def __init__(self, logs_dir, filename, clock=None):
        super().__init__()
        self._lock = threading.RLock()
        self._fd = self._dir_fd = None
        if filename not in STREAM_NAMES:
            raise ValueError('Only the two HopHarbor service log filenames are allowed.')
        self._clock = clock or datetime.datetime.now
        self.name = str(Path(logs_dir) / filename)
        self._day = _local_now(self._clock).date()
        directory = os.path.abspath(os.path.expanduser(os.fspath(logs_dir)))
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            pass
        try:
            self._dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = os.fstat(self._dir_fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError('The log directory must be private and owned by the current user.')
            self._fd = os.open(filename, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                               0o600, dir_fd=self._dir_fd)
            info = os.fstat(self._fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError('The log file must be owned by the current user and have no additional hard links.')
            # Older launchd-created files may be 0644 inside the private directory.
            # Tighten this validated file in place so upgrades keep working safely.
            os.fchmod(self._fd, 0o600)
            existing_day = datetime.datetime.fromtimestamp(info.st_mtime).astimezone().date()
            if existing_day != self._day or info.st_size > STREAM_LIMIT:
                os.ftruncate(self._fd, 0)
        except BaseException:
            self.close()
            raise

    @property
    def encoding(self):
        return 'utf-8'

    @property
    def errors(self):
        return 'replace'

    def writable(self):
        return not self.closed

    def isatty(self):
        return False

    def maintenance(self):
        with self._lock:
            if self.closed or self._fd is None:
                return
            day = _local_now(self._clock).date()
            if day != self._day or os.fstat(self._fd).st_size > STREAM_LIMIT:
                os.ftruncate(self._fd, 0)
                self._day = day

    def write(self, text):
        if not isinstance(text, str):
            raise TypeError('A text stream requires a string.')
        with self._lock:
            if self.closed or self._fd is None:
                raise ValueError('I/O operation on a closed log stream.')
            self.maintenance()
            consumed = len(text)
            text = text[:WRITE_LIMIT]
            data = text.encode(self.encoding, self.errors)
            if os.fstat(self._fd).st_size + len(data) > STREAM_LIMIT:
                os.ftruncate(self._fd, 0)
            remaining = memoryview(data)
            while remaining:
                written = os.write(self._fd, remaining)
                if written <= 0:
                    raise OSError('The log write made no progress.')
                remaining = remaining[written:]
            return consumed

    def flush(self):
        # os.write is unbuffered; deliberately avoid disk fsync on every print.
        return None

    def close(self):
        with self._lock:
            try:
                if self._fd is not None:
                    os.close(self._fd)
                    self._fd = None
            finally:
                if self._dir_fd is not None:
                    os.close(self._dir_fd)
                    self._dir_fd = None
                super().close()


def install_service_streams(logs_dir, clock=None):
    """Return stdout/stderr sinks; the caller decides when to replace sys streams."""
    stdout = DailyBoundedStream(logs_dir, STREAM_NAMES[0], clock=clock)
    try:
        stderr = DailyBoundedStream(logs_dir, STREAM_NAMES[1], clock=clock)
    except BaseException:
        stdout.close()
        raise
    return stdout, stderr


class LogMaintenance:
    """Call from an existing loop to clear idle logs after local midnight."""
    def __init__(self, events, streams=(), interval=60, monotonic_clock=None):
        self.events = events
        self.streams = tuple(streams)
        self.interval = interval
        self._monotonic = monotonic_clock or time.monotonic
        self._next = None
        self._lock = threading.Lock()

    def maintenance(self, force=False):
        with self._lock:
            tick = self._monotonic()
            if not force and self._next is not None and tick < self._next:
                return
            self.events.maintenance()
            for stream in self.streams:
                stream.maintenance()
            self._next = tick + self.interval
