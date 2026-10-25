"""Resource-limit planning tests; all limit queries and mutations are mocked."""
import unittest
from unittest import mock

from test_security import pm


class FileLimitTests(unittest.TestCase):
    def test_soft_limit_is_raised_without_changing_hard_limit(self):
        for hard, expected in [(65536, 8192), (4096, 4096), (pm.resource.RLIM_INFINITY, 8192)]:
            with self.subTest(hard=hard), \
                    mock.patch.object(pm.resource, 'getrlimit', side_effect=[(256, hard), (expected, hard)]), \
                    mock.patch.object(pm.resource, 'setrlimit') as setter:
                result = pm.raise_file_limit(kernel_ceiling=61440)
                setter.assert_called_once_with(pm.resource.RLIMIT_NOFILE, (expected, hard))
                self.assertEqual(result, {'soft': expected, 'hard': hard, 'warning': ''})

    def test_existing_higher_or_unlimited_soft_limit_is_preserved(self):
        for soft in [1048575, pm.resource.RLIM_INFINITY]:
            with self.subTest(soft=soft), \
                    mock.patch.object(pm.resource, 'getrlimit', return_value=(soft, pm.resource.RLIM_INFINITY)), \
                    mock.patch.object(pm.resource, 'setrlimit') as setter:
                result = pm.raise_file_limit(kernel_ceiling=61440)
                setter.assert_not_called()
                self.assertEqual(result['soft'], soft)
                self.assertEqual(result['hard'], pm.resource.RLIM_INFINITY)

    def test_kernel_ceiling_is_respected_without_lowering_a_current_limit(self):
        with mock.patch.object(pm.resource, 'getrlimit', side_effect=[(256, 65536), (2048, 65536)]), \
                mock.patch.object(pm.resource, 'setrlimit') as setter:
            self.assertEqual(pm.raise_file_limit(kernel_ceiling=2048)['soft'], 2048)
            setter.assert_called_once_with(pm.resource.RLIMIT_NOFILE, (2048, 65536))
        with mock.patch.object(pm.resource, 'getrlimit', return_value=(4096, 65536)), \
                mock.patch.object(pm.resource, 'setrlimit') as setter:
            self.assertEqual(pm.raise_file_limit(kernel_ceiling=2048)['soft'], 4096)
            setter.assert_not_called()

    def test_raise_failure_is_recoverable_and_reports_actual_limits(self):
        with mock.patch.object(pm.resource, 'getrlimit', return_value=(256, 65536)), \
                mock.patch.object(pm.resource, 'setrlimit', side_effect=OSError('Test-only limit failure')):
            result = pm.raise_file_limit(kernel_ceiling=61440)
        self.assertEqual((result['soft'], result['hard']), (256, 65536))
        self.assertIn('Test-only limit failure', result['warning'])


if __name__ == '__main__':
    unittest.main()
