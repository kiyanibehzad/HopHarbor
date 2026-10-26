"""Bounded launchd retry behavior; commands and delays are entirely mocked."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('hopharbor_install_bootstrap_test', ROOT / 'install.py')
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


def result(code, stderr='', stdout=''):
    return subprocess.CompletedProcess(['/test-only-launchctl'], code, stdout, stderr)


class BootstrapRetryTests(unittest.TestCase):
    def test_transient_exit_five_retries_then_succeeds(self):
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(installer.subprocess, 'run', side_effect=[result(5, 'Transient\n'), result(0, stdout='Ready\n')]) as command, \
                mock.patch.object(installer.time, 'sleep') as pause, \
                redirect_stdout(output), redirect_stderr(errors):
            completed = installer.bootstrap_service('gui/test-only', Path('/test-only/agent.plist'))
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(command.call_count, 2)
        pause.assert_called_once_with(.5)
        self.assertEqual(output.getvalue(), 'Ready\n')
        self.assertEqual(errors.getvalue(), '')

    def test_other_failure_is_immediate_and_reports_stderr(self):
        errors = io.StringIO()
        with mock.patch.object(installer.subprocess, 'run', return_value=result(78, 'Invalid test configuration\n')) as command, \
                mock.patch.object(installer.time, 'sleep') as pause, redirect_stderr(errors):
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                installer.bootstrap_service('gui/test-only', Path('/test-only/agent.plist'))
        self.assertEqual(raised.exception.returncode, 78)
        self.assertEqual(raised.exception.stderr, 'Invalid test configuration\n')
        command.assert_called_once()
        pause.assert_not_called()
        self.assertEqual(errors.getvalue(), 'Invalid test configuration\n')

    def test_exit_five_exhaustion_stops_after_five_attempts(self):
        errors = io.StringIO()
        with mock.patch.object(installer.subprocess, 'run', return_value=result(5, 'Still unavailable\n')) as command, \
                mock.patch.object(installer.time, 'sleep') as pause, redirect_stderr(errors):
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                installer.bootstrap_service('gui/test-only', Path('/test-only/agent.plist'))
        self.assertEqual(raised.exception.returncode, 5)
        self.assertEqual(command.call_count, 5)
        self.assertEqual(pause.call_args_list, [mock.call(.5), mock.call(1), mock.call(1.5), mock.call(2)])
        self.assertEqual(errors.getvalue(), 'Still unavailable\n')


if __name__ == '__main__':
    unittest.main()
