"""Logging bounds, local-day retention and private-file safety; no live service."""
import datetime
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('hopharbor_log_policy_test', ROOT / 'log_policy.py')
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


class Clock:
    def __init__(self):
        self.value = datetime.datetime.now().astimezone().replace(hour=23, minute=59, second=45, microsecond=0)
        self.tick = 0

    def __call__(self):
        return self.value

    def monotonic(self):
        return self.tick

    def advance(self, seconds):
        self.value += datetime.timedelta(seconds=seconds)
        self.tick += seconds


class EventLogTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.clock.value = self.clock.value.replace(hour=12)
        self.log = policy.EventLog(clock=self.clock, monotonic_clock=self.clock.monotonic)

    def event(self, message='test event', level='info', tunnel_id='synthetic'):
        self.log.append({'level': level, 'message': message, 'tunnel_id': tunnel_id})

    def test_latest_200_and_dedup_state_are_bounded(self):
        for index in range(500):
            self.event(str(index))
        self.assertEqual(len(self.log), 200)
        self.assertEqual(len(self.log._dedup), 200)
        self.assertEqual(self.log[0]['message'], '300')
        self.assertEqual(self.log[-1]['message'], '499')
        self.log.clear()
        self.assertFalse(self.log)
        self.assertFalse(self.log._dedup)

    def test_repeats_update_time_and_recency_but_other_keys_stay_distinct(self):
        self.event('repeated')
        first_time = self.log[0]['time']
        self.clock.advance(5)
        self.event('other')
        self.clock.advance(5)
        self.event('repeated')
        self.assertEqual([entry['message'] for entry in self.log], ['other', 'repeated'])
        self.assertEqual(self.log[-1]['repeats'], 2)
        self.assertNotEqual(self.log[-1]['time'], first_time)
        self.event('repeated', level='error')
        self.event('repeated', tunnel_id='another')
        self.clock.advance(31)
        self.event('repeated')
        self.assertEqual(len(self.log), 5)
        self.assertEqual(self.log[-1]['repeats'], 1)

    def test_message_cap_applies_to_all_inputs_and_does_not_merge_different_tails(self):
        self.event('x' * 900)
        self.log.append('y' * 900)
        self.log.append({'message': 12345, 'extra_unbounded_field': 'z' * 10000})
        self.event('x' * 900 + 'different tail')
        self.assertEqual([len(entry['message']) for entry in self.log], [800, 800, 5, 800])
        self.assertEqual(len(self.log), 4)
        self.assertTrue(all('extra_unbounded_field' not in entry for entry in self.log))
        detached = self.log.snapshot()
        detached[0]['message'] = 'modified copy'
        self.assertEqual(self.log[0]['message'], 'x' * 800)

    def test_each_access_path_prunes_a_previous_local_day(self):
        for method in ['append', 'snapshot', 'maintenance']:
            with self.subTest(method=method):
                self.log.clear()
                self.clock.value = self.clock.value.replace(hour=23, minute=59, second=59)
                self.event('yesterday')
                self.clock.advance(2)
                if method == 'append':
                    self.event('today')
                    self.assertEqual([entry['message'] for entry in self.log], ['today'])
                else:
                    getattr(self.log, method)()
                    self.assertEqual(self.log._entries, [])
                    self.assertEqual(self.log._dedup, {})

    def test_concurrent_append_and_snapshot_do_not_lose_repeat_counts(self):
        threads = [threading.Thread(target=lambda: [self.event('same') for _ in range(100)]) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(self.log), 1)
        self.assertEqual(self.log[0]['repeats'], 400)


class StreamTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.logs = self.root / 'logs'
        self.clock = Clock()

    def sinks(self):
        streams = policy.install_service_streams(self.logs, clock=self.clock)
        for stream in streams:
            self.addCleanup(stream.close)
        return streams

    def test_exact_two_private_files_and_single_write_character_cap(self):
        stdout, stderr = self.sinks()
        self.assertEqual({path.name for path in self.logs.iterdir()}, set(policy.STREAM_NAMES))
        self.assertEqual(stat.S_IMODE(self.logs.stat().st_mode), 0o700)
        text = '\U0001f680' * 10000
        self.assertEqual(stdout.write(text), len(text))
        self.assertEqual((self.logs / policy.STREAM_NAMES[0]).read_text(), text[:4096])
        stderr.write('error')
        for path in self.logs.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_both_streams_never_exceed_256_kib_and_truncate_same_inode_before_append(self):
        streams = self.sinks()
        original_inodes = [Path(stream.name).stat().st_ino for stream in streams]
        for _ in range(20):
            for stream in streams:
                stream.write('\U0001f680' * 4096)
                self.assertLessEqual(Path(stream.name).stat().st_size, 256 * 1024)
        self.assertLessEqual(sum(Path(stream.name).stat().st_size for stream in streams), 512 * 1024)
        self.assertEqual([Path(stream.name).stat().st_ino for stream in streams], original_inodes)
        self.assertEqual({path.name for path in self.logs.iterdir()}, set(policy.STREAM_NAMES))

    def test_startup_prunes_previous_day_or_oversized_files_without_backups(self):
        self.logs.mkdir(mode=0o700)
        for filename in policy.STREAM_NAMES:
            path = self.logs / filename
            path.write_bytes(b'old private output')
            path.chmod(0o600)
            yesterday = self.clock().timestamp() - 86400
            os.utime(path, (yesterday, yesterday))
        streams = self.sinks()
        self.assertTrue(all(Path(stream.name).stat().st_size == 0 for stream in streams))
        for stream in streams:
            stream.close()
        (self.logs / policy.STREAM_NAMES[0]).write_bytes(b'x' * (policy.STREAM_LIMIT + 1))
        stdout, _ = self.sinks()
        self.assertEqual(Path(stdout.name).stat().st_size, 0)

    def test_idle_midnight_maintenance_clears_events_and_both_files(self):
        streams = self.sinks()
        events = policy.EventLog(clock=self.clock, monotonic_clock=self.clock.monotonic)
        events.append({'message': 'previous local day'})
        for stream in streams:
            stream.write('previous local day')
        maintenance = policy.LogMaintenance(events, streams, monotonic_clock=self.clock.monotonic)
        maintenance.maintenance()
        self.clock.advance(61)
        maintenance.maintenance()  # No event or stream writes since before midnight.
        self.assertFalse(events._entries)
        self.assertTrue(all(Path(stream.name).stat().st_size == 0 for stream in streams))
        self.assertFalse(any(path.suffix in ('.1', '.gz') for path in self.logs.iterdir()))

    def test_cleanup_is_scoped_and_refuses_file_directory_symlinks_and_hardlinks(self):
        outside = self.root / 'outside.txt'
        outside.write_text('must remain untouched')
        outside.chmod(0o600)
        self.logs.mkdir(mode=0o700)
        unrelated = self.logs / 'unrelated.txt'
        unrelated.write_text('leave this file alone')
        target = self.logs / policy.STREAM_NAMES[0]
        target.symlink_to(outside)
        with self.assertRaises(OSError):
            policy.DailyBoundedStream(self.logs, policy.STREAM_NAMES[0], clock=self.clock)
        target.unlink()
        os.link(outside, target)
        with self.assertRaises(ValueError):
            policy.DailyBoundedStream(self.logs, policy.STREAM_NAMES[0], clock=self.clock)
        target.unlink()
        symlink_dir = self.root / 'linked-logs'
        symlink_dir.symlink_to(self.logs)
        with self.assertRaises(OSError):
            policy.DailyBoundedStream(symlink_dir, policy.STREAM_NAMES[0], clock=self.clock)
        for invalid in ['../outside.txt', 'history.log', str(outside)]:
            with self.subTest(filename=invalid), self.assertRaises(ValueError):
                policy.DailyBoundedStream(self.logs, invalid, clock=self.clock)
        self.sinks()
        self.assertEqual(outside.read_text(), 'must remain untouched')
        self.assertEqual(unrelated.read_text(), 'leave this file alone')

    def test_unprivate_directory_is_refused(self):
        self.logs.mkdir(mode=0o755)
        with self.assertRaises(ValueError):
            policy.DailyBoundedStream(self.logs, policy.STREAM_NAMES[0], clock=self.clock)

    def test_legacy_launchd_file_is_safely_tightened_without_losing_today(self):
        self.logs.mkdir(mode=0o700)
        path = self.logs / policy.STREAM_NAMES[0]
        path.write_text('keep')
        path.chmod(0o644)
        original_inode = path.stat().st_ino
        stream = policy.DailyBoundedStream(self.logs, policy.STREAM_NAMES[0], clock=self.clock)
        self.addCleanup(stream.close)
        self.assertEqual(path.read_text(), 'keep')
        self.assertEqual(path.stat().st_ino, original_inode)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


if __name__ == '__main__':
    unittest.main()
