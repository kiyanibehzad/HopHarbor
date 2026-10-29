"""Run the actual panel JavaScript against a synthetic cookie service and DOM."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which('node')


@unittest.skipUnless(NODE, 'Node.js is needed for browser behavior checks')
class PanelAuthenticationTests(unittest.TestCase):
    def run_case(self, name):
        for transport in ('webkit', 'webview2'):
            with self.subTest(transport=transport):
                result = subprocess.run(
                    [NODE, str(ROOT / 'tests/panel_auth_behavior.js'),
                     str(ROOT / 'web/app.js'), name, transport],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_expired_cookie_requests_one_native_recovery(self):
        self.run_case('expired_cookie_requests_one_native_recovery')

    def test_manual_retry_requests_fresh_native_bootstrap(self):
        self.run_case('manual_retry_requests_fresh_native_bootstrap')

    def test_csrf_rejection_never_recovers_automatically(self):
        self.run_case('csrf_rejection_never_recovers_automatically')

    def test_rejected_bootstrap_never_starts_automatic_recovery(self):
        self.run_case('rejected_bootstrap_never_starts_automatic_recovery')

    def test_ready_follows_authenticated_state_and_render(self):
        self.run_case('ready_follows_authenticated_state_and_render')

    def test_rejected_mutation_is_not_replayed(self):
        self.run_case('rejected_mutation_is_not_replayed')

    def test_plain_browser_keeps_cookie_retry_without_native_access(self):
        self.run_case('plain_browser_keeps_cookie_retry_without_native_access')


if __name__ == '__main__':
    unittest.main()
