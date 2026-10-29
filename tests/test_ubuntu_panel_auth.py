"""Trust and rolling retry limits without a GTK desktop dependency."""
import unittest
from pathlib import Path
import tempfile

from linux_desktop import RecoveryBudget, panel_location_allowed, recovery_message, trusted_panel_scripts


class UbuntuPanelRecoveryTests(unittest.TestCase):
    def test_only_reviewed_local_scripts_are_injected_in_original_order(self):
        with tempfile.TemporaryDirectory() as scratch:
            web = Path(scratch) / 'web'
            web.mkdir()
            (web / 'app.js').write_text('function postNativePanelMessage(m){return m;}')
            (web / 'index.html').write_text('<script>window.first=1;</script>'
                                           '<script src="/app.js"></script>'
                                           '<script>window.last=2;</script>')
            self.assertEqual(trusted_panel_scripts(scratch),
                             ('window.first=1;', 'function postNativePanelMessage(m){return m;}', 'window.last=2;'))
            for markup in ('<script src="https://example.invalid/evil.js"></script>',
                           '<script src="/app.js" type="module"></script>',
                           '<script>unfinished', '<script>no app script</script>',
                           '<script src="/app.js"></script><script src="/app.js"></script>'):
                (web / 'index.html').write_text(markup)
                with self.assertRaises(ValueError):
                    trusted_panel_scripts(scratch)

    def test_budget_survives_page_replacement_and_manual_retry_is_spaced(self):
        budget = RecoveryBudget()
        self.assertEqual(budget.delay(now=10), 0)
        self.assertEqual(budget.delay(now=10.5), 1.5)
        self.assertEqual(budget.delay(now=12), 2)
        self.assertIsNone(budget.delay(now=16))
        self.assertEqual(budget.delay(manual=True, now=15), 1)
        self.assertIsNone(budget.delay(now=17))
        self.assertEqual(budget.delay(now=70), 0)

    def test_authenticated_reset_retains_spacing(self):
        budget = RecoveryBudget()
        for stamp in (0, 2, 4):
            budget.delay(now=stamp)
        budget.authenticated()
        self.assertEqual(budget.delay(now=5), 1)

    def test_only_exact_fixed_commands_are_accepted(self):
        for payload, expected in (({'action': 'ready'}, 'ready'),
                                  ({'action': 'reauthenticate', 'reason': 'retry'}, 'retry'),
                                  ({'action': 'reauthenticate', 'reason': 'authentication'}, 'authentication')):
            self.assertEqual(recovery_message(payload), expected)
        for payload in (None, [], 'ready', True, {'action': 'ready', 'token': 'synthetic'},
                        {'action': 'reauthenticate'}, {'action': 'reauthenticate', 'reason': '403'},
                        {'action': 'reauthenticate', 'reason': []},
                        {'action': 'reauthenticate', 'reason': 'retry', 'port': 12345}):
            self.assertIsNone(recovery_message(payload), payload)

    def test_panel_path_is_exact_encoded_path_and_native_port(self):
        for path in ('/', '/index.html', '/#token=synthetic'):
            self.assertTrue(panel_location_allowed('http://127.0.0.1:23456' + path, 23456))
        for uri in ('http://127.0.0.1:23456/api/state', 'http://127.0.0.1:23456/%69ndex.html',
                    'http://127.0.0.1:23456/panel', 'http://127.0.0.1:23457/',
                    'http://localhost:23456/', 'https://127.0.0.1:23456/',
                    'http://a@127.0.0.1:23456/', None):
            self.assertFalse(panel_location_allowed(uri, 23456), uri)
