"""Compile and exercise the actual native policy without starting AppKit or SSH."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('xcrun'),
                     'Apple Swift command-line tools are required')
class MacPanelRecoveryTests(unittest.TestCase):
    def test_native_recovery_budget_and_origin_guards(self):
        with tempfile.TemporaryDirectory(prefix='hopharbor-panel-policy-') as scratch:
            binary = Path(scratch) / 'panel-policy-checks'
            result = subprocess.run([
                'xcrun', 'swiftc', '-swift-version', '5', '-parse-as-library',
                str(ROOT / 'packaging/PanelRecovery.swift'),
                str(ROOT / 'tests/panel_recovery_policy.swift'), '-o', str(binary),
            ], capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(result.stdout)
            self.assertTrue(report['ok'])
            self.assertEqual(report['count'], 28)


if __name__ == '__main__':
    unittest.main()
