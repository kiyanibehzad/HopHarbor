"""Read-only installer limit planning; never installs an app or calls launchd."""
import importlib.util
from pathlib import Path
import resource
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('hopharbor_install_limit_test', ROOT / 'install.py')
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallerLimitTests(unittest.TestCase):
    def test_soft_target_is_bounded_by_hard_and_kernel_limits(self):
        for hard, kernel, expected in [(resource.RLIM_INFINITY, 24576, 8192),
                                       (4096, 24576, 4096), (65536, 2048, 2048),
                                       (8192, 8192, 8192)]:
            with self.subTest(hard=hard, kernel=kernel):
                plan = installer.file_limit_plan(hard, kernel)
                self.assertEqual(plan, {'SoftResourceLimits': {'NumberOfFiles': expected}})
                self.assertNotIn('HardResourceLimits', plan)

    def test_invalid_or_unknown_ceilings_omit_the_launchd_setting(self):
        for hard, kernel in [(None, 24576), (True, 24576), (0, 24576),
                             (-2, 24576), (8192, None), (8192, 0),
                             (8192, -1), (8192, True), (8192, '24576')]:
            with self.subTest(hard=hard, kernel=kernel):
                self.assertEqual(installer.file_limit_plan(hard, kernel), {})

    def test_discovery_only_reads_local_limits(self):
        with mock.patch.object(installer.resource, 'getrlimit', return_value=(256, resource.RLIM_INFINITY)), \
                mock.patch.object(installer.resource, 'setrlimit') as setter, \
                mock.patch.object(installer.subprocess, 'run', return_value=SimpleNamespace(stdout='24576\n')) as command:
            self.assertEqual(installer.launch_agent_resource_limits(),
                             {'SoftResourceLimits': {'NumberOfFiles': 8192}})
        setter.assert_not_called()
        command.assert_called_once_with(['/usr/sbin/sysctl', '-n', 'kern.maxfilesperproc'],
                                        capture_output=True, text=True, check=True, timeout=5)

    def test_failed_or_malformed_sysctl_does_not_guess_a_limit(self):
        for result, error in [(SimpleNamespace(stdout='unknown'), None),
                              (None, OSError('Test-only missing sysctl')),
                              (None, subprocess.TimeoutExpired('/test-only-sysctl', 5)),
                              (None, subprocess.CalledProcessError(1, '/test-only-sysctl'))]:
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(installer.resource, 'getrlimit', return_value=(256, resource.RLIM_INFINITY)), \
                        mock.patch.object(installer.subprocess, 'run', return_value=result, side_effect=error):
                    self.assertEqual(installer.launch_agent_resource_limits(), {})


if __name__ == '__main__':
    unittest.main()
