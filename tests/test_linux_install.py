"""Isolated Linux install/package tests. Never execute an installer or service."""
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import install_linux as linux

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('hopharbor_deb_test', ROOT / 'packaging/build_deb.py')
deb = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(deb)


def archive_fixture(entries):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w:gz') as package:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            package.addfile(info, io.BytesIO(data))
    return result.getvalue()


class LinuxInstallerTests(unittest.TestCase):
    def test_macos_guard_never_calls_installer_or_service(self):
        with mock.patch.object(linux.sys, 'platform', 'darwin'), \
                mock.patch.object(linux.sys, 'argv', ['install_linux.py']), \
                mock.patch.object(linux, 'run') as command, \
                mock.patch.object(linux, 'install') as install:
            with self.assertRaisesRegex(SystemExit, 'Ubuntu Linux only'):
                linux.main()
        command.assert_not_called()
        install.assert_not_called()

    def test_supported_architectures_are_explicit(self):
        self.assertEqual(linux.architecture('x86_64'), 'amd64')
        self.assertEqual(linux.architecture('aarch64'), 'arm64')
        with self.assertRaises(ValueError):
            linux.architecture('i386')
        self.assertNotEqual(linux.GOST_SHA256['amd64'], linux.GOST_SHA256['arm64'])

    def test_tampered_download_does_not_extract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / 'download.tar.gz'
            archive.write_bytes(b'untrusted fixture')
            with self.assertRaisesRegex(ValueError, 'digest'):
                linux.fetch_gost(root / 'bin/gost', 'amd64', archive)
            self.assertFalse((root / 'bin').exists())

    def test_verified_tar_never_extracts_paths_or_links(self):
        payload = archive_fixture([('../../outside', b'private fixture'),
                                   ('nested/gost', b'ELF fixture'), ('nested/LICENSE', b'fixture license')])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / 'gost.tar.gz'
            archive.write_bytes(payload)
            with mock.patch.dict(linux.GOST_SHA256, {'amd64': hashlib.sha256(payload).hexdigest()}):
                linux.fetch_gost(root / 'bin/gost', 'amd64', archive)
            self.assertEqual((root / 'bin/gost').read_bytes(), b'ELF fixture')
            self.assertEqual({path.name for path in (root / 'bin').iterdir()}, {'gost', 'GOST-LICENSE'})
            self.assertFalse((root / 'outside').exists())

    def test_failed_preparation_never_stops_existing_service(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(linux, 'guard_installation'), \
                mock.patch.object(linux, 'require_desktop_dependencies'), \
                mock.patch.object(linux, 'fetch_gost', side_effect=ValueError('digest mismatch')), \
                mock.patch.object(linux, 'run') as command:
            with self.assertRaisesRegex(ValueError, 'digest'):
                linux.install(Path(directory) / 'data')
            command.assert_not_called()

    def test_update_rolls_back_application_and_unit_after_start_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / 'data'
            app = data / 'app'
            app.mkdir(parents=True)
            (app / linux.MARKER).write_text('original')
            (app / 'old-file').write_text('preserve me')
            config = root / 'config'
            unit = config / 'systemd/user' / linux.SERVICE
            unit.parent.mkdir(parents=True)
            old_text = '# HopHarbor Linux user service\noriginal fixture'
            unit.write_text(old_text)
            events = []

            def fetch(target, arch, archive):
                events.append('verified')
                target.write_bytes(b'fixture')
                return {}

            def copy(destination, gost, provenance):
                destination.mkdir()
                (destination / linux.MARKER).write_text('new')

            def command(argv, check=True):
                events.append(argv[2])
                if argv[2] == 'enable':
                    raise subprocess.CalledProcessError(1, argv)
                return subprocess.CompletedProcess(argv, 0, '', '')

            with mock.patch.dict(os.environ, {'XDG_CONFIG_HOME': str(config)}), \
                    mock.patch.object(linux, 'guard_installation'), \
                    mock.patch.object(linux, 'require_desktop_dependencies'), \
                    mock.patch.object(linux, 'fetch_gost', side_effect=fetch), \
                    mock.patch.object(linux, 'copy_app', side_effect=copy), \
                    mock.patch.object(linux, 'run', side_effect=command):
                with self.assertRaises(subprocess.CalledProcessError):
                    linux.install(data)
            self.assertLess(events.index('verified'), events.index('stop'))
            self.assertEqual((app / 'old-file').read_text(), 'preserve me')
            self.assertEqual(unit.read_text(), old_text)
            self.assertEqual(events[-1], 'start', 'Restore the previously active controller on rollback')
            self.assertFalse((data / '.app-previous').exists())

    def test_initialize_preserves_existing_configuration_and_empty_new_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory) / 'private'
            linux.initialize_data(data)
            self.assertEqual(json.loads((data / 'config.json').read_text())['servers'], [])
            (data / 'config.json').write_text('{"fixture": "retain"}')
            linux.initialize_data(data)
            self.assertEqual(json.loads((data / 'config.json').read_text()), {'fixture': 'retain'})
            self.assertEqual(data.stat().st_mode & 0o777, 0o700)
            self.assertEqual((data / 'config.json').stat().st_mode & 0o777, 0o600)

    def test_service_is_user_scoped_and_bounded(self):
        unit = linux.service_text('/tmp/public fixture/100%/app', '/tmp/public fixture/100%/private')
        self.assertIn('100%%', unit)
        self.assertIn('LimitNOFILE=8192', unit)
        self.assertIn('StandardError=null', unit)
        self.assertIn('Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus', unit)
        self.assertNotIn('launchctl', unit)
        self.assertNotIn('User=root', unit)
        with self.assertRaises(ValueError):
            linux.unit_arg('/tmp/bad\npath')

    def test_absolute_xdg_paths_and_relative_values_ignored(self):
        with mock.patch.dict(os.environ, {'XDG_DATA_HOME': '/tmp/isolated-data'}):
            self.assertEqual(linux.default_data_dir(), Path('/tmp/isolated-data/hopharbor'))
        with mock.patch.dict(os.environ, {'XDG_DATA_HOME': 'relative-untrusted'}):
            self.assertEqual(linux.default_data_dir(), Path.home() / '.local/share/hopharbor')

    def test_service_properties_accepts_missing_unit_without_starting_it(self):
        response = subprocess.CompletedProcess([], 0, 'LoadState=not-found\nFragmentPath=\nMainPID=0\n', '')
        with mock.patch.object(linux, 'run', return_value=response) as command:
            self.assertEqual(linux.service_properties(), {'fragment': None, 'pid': 0})
        self.assertIn('--property=FragmentPath', command.call_args[0][0])
        self.assertNotIn('start', command.call_args[0][0])

    def test_source_install_rejects_packaged_scope_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            packaged = root / 'usr/lib/systemd/user' / linux.SERVICE
            packaged.parent.mkdir(parents=True)
            packaged.write_text(linux.service_text())
            data = root / 'private-new'
            with mock.patch.object(linux, 'PACKAGED_UNITS', (packaged,)), \
                    mock.patch.object(linux, 'service_properties', return_value={'fragment': packaged, 'pid': 0}), \
                    mock.patch.object(linux, 'initialize_data') as initialize, \
                    mock.patch.object(linux, 'fetch_gost') as download, \
                    mock.patch.object(linux, 'run') as command:
                with self.assertRaisesRegex(ValueError, 'packaged'):
                    linux.install(data)
                initialize.assert_not_called()
                download.assert_not_called()
                command.assert_not_called()
                self.assertFalse(data.exists())

    def test_custom_data_mismatch_cannot_uninstall_or_launch_other_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_data, current_data = root / 'old-data', root / 'current-data'
            for data in (old_data, current_data):
                (data / 'app').mkdir(parents=True)
                (data / 'app' / linux.MARKER).write_text('synthetic marker')
            unit = root / 'user-unit'
            unit.write_text(linux.service_text(current_data / 'app', current_data))
            with mock.patch.object(linux, 'user_unit_path', return_value=unit), \
                    mock.patch.object(linux, 'PACKAGED_UNITS', (root / 'no-package-unit',)), \
                    mock.patch.object(linux, 'service_properties', return_value={'fragment': unit, 'pid': 0}), \
                    mock.patch.object(linux, 'run') as command, \
                    mock.patch.object(linux.os, 'execv') as execute:
                with self.assertRaisesRegex(ValueError, 'different application/data'):
                    linux.uninstall(old_data)
                with self.assertRaisesRegex(ValueError, 'different application/data'):
                    linux.launch_panel(old_data, old_data / 'app')
                command.assert_not_called()
                execute.assert_not_called()
            self.assertTrue(unit.exists())
            self.assertTrue((old_data / 'app' / linux.MARKER).exists())
            self.assertTrue((current_data / 'app' / linux.MARKER).exists())

    def test_new_and_matching_user_update_scope_are_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / 'private'
            app = data / 'app'
            unit = root / 'user-unit'
            with mock.patch.object(linux, 'user_unit_path', return_value=unit), \
                    mock.patch.object(linux, 'PACKAGED_UNITS', (root / 'no-package-unit',)):
                linux.guard_installation(app, data, 'install', {'fragment': None, 'pid': 0})
                self.assertFalse(data.exists())
                app.mkdir(parents=True)
                (app / linux.MARKER).write_text('synthetic marker')
                unit.write_text(linux.service_text(app, data))
                for purpose in ('install', 'launch', 'uninstall'):
                    linux.guard_installation(app, data, purpose, {'fragment': unit, 'pid': 0})

    def test_packaged_launcher_rejects_per_user_override_and_wrong_xdg_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app, data = root / 'packaged-app', root / 'data'
            packaged, user_unit = root / 'packaged-unit', root / 'user-unit'
            packaged.write_text(linux.service_text())
            with mock.patch.object(linux, 'PACKAGED_APP', app), \
                    mock.patch.object(linux, 'PACKAGED_UNITS', (packaged,)), \
                    mock.patch.object(linux, 'user_unit_path', return_value=user_unit), \
                    mock.patch.object(linux, 'default_data_dir', return_value=data), \
                    mock.patch.object(linux, 'manager_default_data_dir', return_value=data):
                linux.guard_installation(app, data, 'launch', {'fragment': packaged, 'pid': 0})
                with self.assertRaisesRegex(ValueError, 'different XDG'):
                    linux.guard_installation(app, root / 'other-data', 'launch', {'fragment': packaged, 'pid': 0})
                user_unit.write_text(linux.service_text(root / 'other-app', data))
                with self.assertRaisesRegex(ValueError, 'overrides'):
                    linux.guard_installation(app, data, 'launch', {'fragment': user_unit, 'pid': 0})

    def test_running_controller_data_identity_is_verified(self):
        app, data = Path('/tmp/hopharbor-fixture-app').resolve(), Path('/tmp/hopharbor-fixture-data').resolve()
        words = ['/usr/bin/python3', str(app / 'manager.py'), '--data-dir', str(data), '--app-dir', str(app), '']
        with mock.patch.object(Path, 'read_bytes', return_value='\0'.join(words).encode()):
            linux.verify_running_identity(123, app, data)
            with self.assertRaisesRegex(ValueError, 'different application or data'):
                linux.verify_running_identity(123, app, data / 'other')

    def test_unavailable_user_manager_is_not_treated_as_new_installation(self):
        response = subprocess.CompletedProcess([], 1, '', 'Failed to connect to user bus')
        with mock.patch.object(linux, 'run', return_value=response):
            with self.assertRaisesRegex(ValueError, 'Cannot verify'):
                linux.service_properties()

    def test_uninstall_stop_failure_preserves_unit_and_application(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data, unit = root / 'data', root / 'user-unit'
            app = data / 'app'
            app.mkdir(parents=True)
            (app / linux.MARKER).write_text('synthetic marker')
            unit.write_text(linux.service_text(app, data))
            with mock.patch.object(linux, 'user_unit_path', return_value=unit), \
                    mock.patch.object(linux, 'PACKAGED_UNITS', (root / 'no-package-unit',)), \
                    mock.patch.object(linux, 'service_properties', return_value={'fragment': unit, 'pid': 0}), \
                    mock.patch.object(linux, 'run', side_effect=subprocess.CalledProcessError(1, ['systemctl'])):
                with self.assertRaises(subprocess.CalledProcessError):
                    linux.uninstall(data)
            self.assertTrue(unit.exists())
            self.assertTrue((app / linux.MARKER).exists())


class DebArchiveTests(unittest.TestCase):
    def test_complete_package_contains_public_allowlist_and_never_runs_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'source'
            root.mkdir()
            for name in linux.APP_FILES:
                (root / name).write_text('VERSION = "9.9.9"\n' if name == 'manager.py' else '# synthetic app fixture\n')
            for folder in ('web', 'packaging/assets', 'docs'):
                (root / folder).mkdir(parents=True, exist_ok=True)
            for name in ('index.html', 'app.js'):
                (root / 'web' / name).write_text('synthetic web fixture')
            (root / 'packaging/assets/HopHarbor.svg').write_text('<svg/>')
            (root / 'docs/ubuntu.md').write_text('synthetic docs fixture')
            (root / 'docs/ubuntu-testing.md').write_text('synthetic verification fixture')
            (root / 'LICENSE').write_text('synthetic project license')
            (root / 'THIRD-PARTY-NOTICES.md').write_text('synthetic third party notice')
            (root / 'config.json').write_text('NEVER-PACKAGE-THIS-PRIVATE-FIXTURE')
            (root / 'personal.key').write_text('NEVER-PACKAGE-THIS-PRIVATE-FIXTURE')

            def fetch(target, arch, archive):
                target.write_bytes(b'ELF synthetic fixture')
                (target.parent / 'GOST-LICENSE').write_text('synthetic GOST license')
                return {'name': 'GOST', 'version': 'fixture', 'sha256': 'fixture'}

            output = Path(directory) / 'package.deb'
            with mock.patch.object(linux, 'ROOT', root), mock.patch.object(deb, 'ROOT', root), \
                    mock.patch.object(linux, 'fetch_gost', side_effect=fetch), \
                    mock.patch.object(linux, 'run') as command:
                deb.build('amd64', output)
            command.assert_not_called()
            contents = output.read_bytes()
            self.assertEqual(contents[:8], b'!<arch>\n')
            offset, members = 8, {}
            while offset < len(contents):
                header = contents[offset:offset + 60]
                size = int(header[48:58].decode().strip())
                name = header[:16].decode().strip().rstrip('/')
                members[name] = contents[offset + 60:offset + 60 + size]
                offset += 60 + size + size % 2
            self.assertEqual(set(members), {'debian-binary', 'control.tar.gz', 'data.tar.gz'})
            with tarfile.open(fileobj=io.BytesIO(members['control.tar.gz']), mode='r:gz') as archive:
                control = archive.extractfile('./control').read().decode()
                self.assertIn('Version: 9.9.9', control)
                self.assertIn('Architecture: amd64', control)
                self.assertEqual({item.name for item in archive.getmembers()}, {'./control'})
            with tarfile.open(fileobj=io.BytesIO(members['data.tar.gz']), mode='r:gz') as archive:
                names = {item.name for item in archive.getmembers()}
                self.assertIn('./usr/lib/hopharbor/manager.py', names)
                self.assertIn('./usr/lib/systemd/user/' + linux.SERVICE, names)
                self.assertIn('./usr/share/applications/' + linux.DESKTOP_FILE, names)
                self.assertFalse(any('config.json' in name or 'personal.key' in name for name in names))
                for member in archive.getmembers():
                    if member.isfile():
                        self.assertNotIn(b'NEVER-PACKAGE-THIS-PRIVATE-FIXTURE', archive.extractfile(member).read())

    def test_tar_omits_build_metadata_and_is_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'usr/lib').mkdir(parents=True)
            (root / 'usr/lib/fixture').write_text('synthetic fixture')
            first = deb.compressed_tar(root)
            second = deb.compressed_tar(root)
            self.assertEqual(first, second)
            with tarfile.open(fileobj=io.BytesIO(first), mode='r:gz') as archive:
                for member in archive.getmembers():
                    self.assertTrue(member.name.startswith('./'))
                    self.assertEqual(member.uid, 0)
                    self.assertEqual(member.gid, 0)
                    self.assertEqual(member.mtime, 0)
                    self.assertNotIn(directory, member.name)

    def test_ar_header_and_padding_match_debian_container(self):
        item = deb.ar_member('debian-binary', b'2.0\n')
        self.assertEqual(len(item[:60]), 60)
        self.assertEqual(item[:16], b'debian-binary/  ')
        self.assertEqual(item[58:60], b'`\n')
        self.assertEqual(len(deb.ar_member('odd', b'a')), 62)


if __name__ == '__main__':
    unittest.main()
