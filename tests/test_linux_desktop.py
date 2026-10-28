"""Validate the Linux shell's trust boundary without importing GTK on macOS."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import linux_desktop as panel


class LinuxDesktopTests(unittest.TestCase):
    def test_xdg_directory_ignores_relative_environment_values(self):
        self.assertEqual(panel.default_data_dir({}, '/tmp/user'), Path('/tmp/user/.local/share/hopharbor'))
        self.assertEqual(panel.default_data_dir({'XDG_DATA_HOME': 'relative'}, '/tmp/user'),
                         Path('/tmp/user/.local/share/hopharbor'))
        self.assertEqual(panel.default_data_dir({'XDG_DATA_HOME': '/tmp/data'}, '/tmp/user'),
                         Path('/tmp/data/hopharbor'))

    def test_control_file_private_valid_and_fragment_encoded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'control.json'
            token = 'synthetic token &=%+#/?' + 'a' * 20
            path.write_text(json.dumps({'port': 21899, 'token': token}))
            path.chmod(0o600)
            self.assertEqual(panel.read_control(directory), (21899, token))
            uri = panel.panel_url(21899, token)
            self.assertIn('/#token=synthetic%20token%20%26%3D%25%2B%23%2F%3F', uri)
            self.assertTrue(panel.navigation_allowed(uri, 21899))

    def test_control_rejects_world_readable_file_symlink_and_wrong_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'control.json'
            path.write_text(json.dumps({'port': 17777, 'token': 'synthetic' * 4}))
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                panel.read_control(directory)
            path.chmod(0o600)
            with mock.patch.object(panel.os, 'getuid', return_value=os.getuid() + 1):
                with self.assertRaises(ValueError):
                    panel.read_control(directory)
            target = path.with_name('real.json')
            path.rename(target)
            path.symlink_to(target)
            with self.assertRaises(OSError):
                panel.read_control(directory)

    def test_control_rejects_bad_port_token_and_oversized_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'control.json'
            for port, token in ((True, 'a' * 20), (1023, 'a' * 20),
                                (65536, 'a' * 20), (17777, 'short'), (17777, 'a' * 4097)):
                path.write_text(json.dumps({'port': port, 'token': token}))
                path.chmod(0o600)
                with self.assertRaises(ValueError):
                    panel.read_control(directory)
            path.write_text('a' * 16385)
            with self.assertRaises(ValueError):
                panel.read_control(directory)

    def test_navigation_blocks_external_and_malformed_locations(self):
        self.assertTrue(panel.navigation_allowed('http://127.0.0.1:17777/api/state', 17777))
        for uri in ('https://127.0.0.1:17777/', 'http://localhost:17777/',
                    'http://127.0.0.1:17778/', 'http://127.0.0.1:bad/',
                    'http://user@127.0.0.1:17777/', 'file:///etc/passwd',
                    'javascript:alert(1)', panel.REPOSITORY_URL, 'http://[::1]:17777/'):
            self.assertFalse(panel.navigation_allowed(uri, 17777), uri)
        self.assertFalse(panel.navigation_allowed('http://127.0.0.1:17777/', None))

    def test_native_bootstrap_contains_only_public_metadata(self):
        script = panel.bootstrap_script(True)
        self.assertIn('"version":"1.2.1"', script)
        self.assertIn('window.HopHarborPlatform="linux"', script)
        self.assertIn('window.HopHarborSystemDark=true', script)
        self.assertNotIn('token', script)
        self.assertNotIn('postMessage', script)
        self.assertIn('HopHarborSystemDark=true', panel.appearance_script(True))
        self.assertIn('HopHarborSystemDark=false', panel.appearance_script(False))
        self.assertIn('hopharbor-system-appearance', panel.appearance_script(False))

    def test_custom_installations_have_stable_separate_app_ids(self):
        self.assertEqual(panel.application_id(panel.default_data_dir()),
                         'io.github.kiyanibehzad.HopHarbor')
        self.assertEqual(panel.application_id('/tmp/alpha'), panel.application_id('/tmp/alpha'))
        self.assertNotEqual(panel.application_id('/tmp/alpha'), panel.application_id('/tmp/bravo'))
        self.assertNotIn('/tmp', panel.application_id('/tmp/alpha'))


if __name__ == '__main__':
    unittest.main()
