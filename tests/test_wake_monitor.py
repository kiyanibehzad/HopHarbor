"""Wake detection with injected tokens; never sleeps or changes power/network state."""
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import wake_monitor


class WakeMonitorTests(unittest.TestCase):
    def test_unchanged_token_never_emits_resume(self):
        reader = mock.Mock(return_value=(100, 42))
        monitor = wake_monitor.WakeMonitor(reader=reader)
        self.assertFalse(monitor.resumed())
        self.assertFalse(monitor.resumed())
        self.assertEqual(reader.call_count, 3)

    def test_each_confirmed_change_emits_only_once(self):
        reader = mock.Mock(side_effect=[(100, 42), (101, 43), (101, 43), (102, 44), (102, 44)])
        monitor = wake_monitor.WakeMonitor(reader=reader)
        self.assertEqual([monitor.resumed() for _ in range(4)], [True, False, True, False])

    def test_microsecond_change_is_a_new_token(self):
        monitor = wake_monitor.WakeMonitor(reader=mock.Mock(side_effect=[(100, 1), (100, 2), (100, 2)]))
        self.assertTrue(monitor.resumed())
        self.assertFalse(monitor.resumed())

    def test_read_failures_preserve_the_previous_baseline(self):
        reader = mock.Mock(side_effect=[(100, 42), None, OSError('Test-only unavailable sysctl'),
                                       ValueError('Test-only read failure'), (100, 42), (101, 43)])
        monitor = wake_monitor.WakeMonitor(reader=reader)
        self.assertEqual([monitor.resumed() for _ in range(5)], [False, False, False, False, True])

    def test_first_success_after_initial_failure_only_establishes_baseline(self):
        reader = mock.Mock(side_effect=[None, None, (100, 42), (100, 42), (101, 43)])
        monitor = wake_monitor.WakeMonitor(reader=reader)
        self.assertEqual([monitor.resumed() for _ in range(4)], [False, False, False, True])

    def test_invalid_tokens_never_replace_a_valid_baseline(self):
        invalid = [(), (1,), (1, 2, 3), [1, 2], '100:42', {'sec': 100},
                   (-1, 0), (100, -1), (100, 1_000_000), (True, 0),
                   (100, False), (100.0, 0), (100, 0.0)]
        for value in invalid:
            with self.subTest(token=value):
                reader = mock.Mock(side_effect=[(100, 42), value, (100, 42), (101, 43)])
                monitor = wake_monitor.WakeMonitor(reader=reader)
                self.assertEqual([monitor.resumed() for _ in range(3)], [False, False, True])

    def test_non_macos_import_and_default_monitor_are_inert(self):
        with mock.patch.object(wake_monitor.sys, 'platform', 'linux'), \
                mock.patch.object(wake_monitor.ctypes, 'CDLL') as library:
            monitor = wake_monitor.WakeMonitor()
            self.assertFalse(monitor.resumed())
        library.assert_not_called()

    def test_unavailable_native_api_disables_the_default_reader(self):
        with mock.patch.object(wake_monitor.sys, 'platform', 'darwin'), \
                mock.patch.object(wake_monitor.ctypes, 'CDLL', side_effect=OSError('Test-only missing API')):
            monitor = wake_monitor.WakeMonitor()
            self.assertFalse(monitor.resumed())
            self.assertFalse(monitor.resumed())


if __name__ == '__main__':
    unittest.main()
