"""Upgrade preparation ordering with mocked downloads and service commands."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('hopharbor_install_upgrade_test', ROOT / 'install.py')
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class UpgradePreparationTests(unittest.TestCase):
    def test_download_failure_never_stops_the_service(self):
        prepared = []

        def fail(target):
            prepared.append(target.parent)
            raise RuntimeError('Test-only download or verification failure')

        with mock.patch.object(installer, 'fetch_gost', side_effect=fail), \
                mock.patch.object(installer, 'run') as command:
            with self.assertRaisesRegex(RuntimeError, 'verification failure'):
                with installer.prepare_upgrade('gui/test-only/service'):
                    self.fail('An unsuccessful preparation must never yield')
        command.assert_not_called()
        self.assertEqual(len(prepared), 1)
        self.assertFalse(prepared[0].exists(), 'Failed private staging must be cleaned up')

    def test_verified_preparation_completes_before_bootout(self):
        events = []
        expected = {'name': 'GOST', 'sha256': 'test-only-verified-release'}
        prepared = []

        def fetch(target):
            self.assertEqual(target.parent.stat().st_mode & 0o777, 0o700)
            target.write_bytes(b'test-only executable fixture')
            (target.parent / 'GOST-LICENSE').write_text('Test-only license fixture')
            prepared.append(target.parent)
            events.append('verified-preparation')
            return expected

        def command(args, check=True):
            self.assertEqual(args, ['/bin/launchctl', 'bootout', 'gui/test-only/service'])
            self.assertFalse(check)
            self.assertEqual(events, ['verified-preparation'])
            self.assertTrue((prepared[0] / 'gost').is_file())
            self.assertTrue((prepared[0] / 'GOST-LICENSE').is_file())
            events.append('bootout')

        with mock.patch.object(installer, 'fetch_gost', side_effect=fetch), \
                mock.patch.object(installer, 'run', side_effect=command) as run:
            with installer.prepare_upgrade('gui/test-only/service') as (directory, provenance):
                self.assertEqual(events, ['verified-preparation', 'bootout'])
                self.assertEqual(directory, prepared[0])
                self.assertEqual(provenance, expected)
                self.assertTrue(directory.exists())
        run.assert_called_once()
        self.assertFalse(prepared[0].exists(), 'Successful private staging must be cleaned up')


if __name__ == '__main__':
    unittest.main()
