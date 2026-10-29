"""Packaging and installer boundaries, runnable without touching a live service."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import stat
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load_module('windows_package_builder', ROOT / 'packaging/build_windows.py')
launcher = load_module('windows_package_launcher', ROOT / 'install_windows.py')


class FakeNative:
    def __init__(self):
        self.checked = []

    def validate_private_directory(self, path):
        self.checked.append(Path(path))
        return Path(path)

    def validate_private_file(self, path):
        self.checked.append(Path(path))
        return Path(path)

    def read_private_json(self, path, max_bytes=65536):
        raw = Path(path).read_bytes()
        if len(raw) > max_bytes:
            raise ValueError('too large')
        return json.loads(raw)

    def atomic_json(self, path, value):
        Path(path).write_text(json.dumps(value))

    def ensure_private_directory(self, path):
        Path(path).mkdir(parents=True, exist_ok=True)
        return Path(path)

    class ServiceLock:
        def __init__(self, _path):
            pass
        def close(self):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            self.close()


class FakeRegistry(types.ModuleType):
    HKEY_CURRENT_USER = 1
    REG_SZ = 1

    def __init__(self):
        super().__init__('winreg')
        self.values = {}
        self.keys = set()
        self.deleted_keys = []

    class Key:
        def __init__(self, name):
            self.name = name
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            pass

    def CreateKey(self, _root, name):
        self.keys.add(name)
        return self.Key(name)

    def OpenKey(self, _root, name):
        if name not in self.keys and not any(key[0] == name for key in self.values):
            raise FileNotFoundError
        return self.Key(name)

    def QueryValueEx(self, key, name):
        try:
            return self.values[key.name, name], self.REG_SZ
        except KeyError:
            raise FileNotFoundError

    def SetValueEx(self, key, name, _reserved, _kind, value):
        self.values[key.name, name] = value

    def DeleteValue(self, key, name):
        del self.values[key.name, name]

    def DeleteKey(self, _root, name):
        self.OpenKey(_root, name)
        self.deleted_keys.append(name)
        for key in list(self.values):
            if key[0] == name:
                del self.values[key]
        self.keys.discard(name)


class WindowsPackageBoundaries(unittest.TestCase):
    def test_windows_frontend_policy_requires_source_and_rejects_external_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            stage = Path(temp)
            with self.assertRaises(ValueError):
                builder.validate_windows_payload(stage)
            (stage / 'windows_proxy.py').write_text('# synthetic frontend')
            builder.validate_windows_payload(stage)
            (stage / 'bin').mkdir()
            for name in ('gost.exe', 'GOST-LICENSE', 'other-frontend.exe'):
                path = stage / 'bin' / name
                path.write_bytes(b'synthetic')
                with self.subTest(name=name), self.assertRaises(ValueError):
                    builder.validate_windows_payload(stage)
                path.unlink()

    def test_windows_build_downloads_only_python_and_ships_own_frontend(self):
        def executable():
            value = bytearray(80)
            value[:2] = b'MZ'; struct.pack_into('<I', value, 0x3c, 64)
            value[64:68] = b'PE\0\0'; struct.pack_into('<H', value, 68, 0x8664)
            return value
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); source = base / 'reviewed'; source.mkdir()
            for name in builder.APP_FILES + builder.WEB_FILES + builder.VENDOR_FILES:
                path = source / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('# synthetic public fixture\n')
            (source / 'manager.py').write_text("VERSION='1.3.0'\nBUILD=10\n")
            for name in ('LICENSE', 'THIRD-PARTY-NOTICES.md', 'packaging/windows/assets/HopHarbor.ico'):
                path = source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('synthetic notice/icon')
            python = base / 'embedded-python.zip'
            with zipfile.ZipFile(python, 'w') as archive:
                for name in ('python.exe', 'pythonw.exe'):
                    archive.writestr(name, executable())
                archive.writestr('python314._pth', 'python314.zip\n.\n')
                archive.writestr('python314.zip', b'synthetic standard library')
            helper, desktop = base / 'helper', base / 'desktop'
            helper.mkdir(); desktop.mkdir()
            (helper / 'HopHarborHelper.exe').write_bytes(executable())
            (desktop / 'HopHarbor.exe').write_bytes(executable())
            (desktop / 'createdump.exe').write_bytes(executable())
            with mock.patch.object(builder, 'ROOT', source), \
                    mock.patch.object(builder.subprocess, 'check_output', return_value=builder.SDK_VERSION + '\n'), \
                    mock.patch.object(builder, 'checked_archive', return_value=python) as download:
                result = builder.build('x64', base / 'outputs', base / 'dotnet', base / 'cache', helper, desktop)
                download.assert_called_once()
                self.assertTrue(download.call_args.args[0].startswith('https://www.python.org/'))
                with zipfile.ZipFile(base / 'outputs' / result['portable_zip']) as archive:
                    names = archive.namelist()
                    self.assertIn('HopHarbor/windows_proxy.py', names)
                    self.assertFalse(any(PurePosixPath(name).name.lower().startswith('gost') for name in names))
                    provenance = json.loads(archive.read('HopHarbor/THIRD-PARTY-WINDOWS.json'))
                    self.assertNotIn('GOST', {item['name'] for item in provenance['dependencies']})
                    manifest = json.loads(archive.read('HopHarbor/PACKAGE-SHA256.json'))
                    self.assertIn('windows_proxy.py', manifest)
                    self.assertNotIn('bin/gost.exe', manifest)
                (helper / 'external-frontend.exe').write_bytes(executable())
                with self.assertRaises(ValueError):
                    builder.build('x64', base / 'rejected-output', base / 'dotnet', base / 'cache', helper, desktop)

    def test_redistributed_notices_match_reviewed_upstream_hashes(self):
        vendor = ROOT / 'vendor/windows'
        provenance = json.loads((vendor / 'provenance.json').read_text(encoding='utf-8'))
        required = {path.split('/')[-1] for path in builder.VENDOR_FILES if not path.endswith('provenance.json')}
        checked = set()
        for package in provenance['packages']:
            for notice in package['notices']:
                self.assertEqual(builder.sha256(vendor / notice['file']), notice['sha256'])
                checked.add(notice['file'])
        self.assertEqual(checked, required)

    def archive(self, names):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, 'w') as output:
            for name in names:
                output.writestr(name, b'fixture')
        raw.seek(0)
        return zipfile.ZipFile(raw)

    def test_archive_rejects_windows_aliases_and_traversal(self):
        names = ('../escape.exe', '/escape.exe', r'c:\escape.exe', r'foo\..\escape.exe',
                 'folder/file.exe:stream', 'folder./file.exe', 'folder/file.exe ',
                 'CON', 'folder/lpt1.txt', 'folder//file.exe', './file.exe')
        for name in names:
            with self.subTest(name=name), self.archive([name]) as source:
                with self.assertRaises(ValueError):
                    list(builder.safe_zip_members(source))

    def test_archive_rejects_case_alias_and_links(self):
        with self.archive(['bin/file.exe', 'BIN/FILE.EXE']) as source:
            with self.assertRaises(ValueError):
                list(builder.safe_zip_members(source))
        info = zipfile.ZipInfo('link')
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.archive([info]) as source:
            with self.assertRaises(ValueError):
                list(builder.safe_zip_members(source))

    def test_good_archive_preserves_relative_names(self):
        with self.archive(['folder/', 'folder/python.exe', 'python314._pth']) as source:
            self.assertEqual([name for _, name in builder.safe_zip_members(source)],
                             ['folder/python.exe', 'python314._pth'])

    def test_cached_archive_must_match_digest_without_network(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'fixture.zip'
            target.write_bytes(b'bad')
            with mock.patch.object(builder.urllib.request, 'urlopen') as network:
                with self.assertRaises(ValueError):
                    builder.checked_archive('https://example.invalid/archive', '0' * 64, temp, target.name)
                network.assert_not_called()
                digest = hashlib.sha256(b'bad').hexdigest()
                self.assertEqual(builder.checked_archive('https://example.invalid/archive', digest, temp, target.name), target)

    def test_pe_architecture_and_truncated_headers(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'fixture.exe'
            for machine in (0x8664, 0xAA64):
                raw = bytearray(80)
                raw[:2] = b'MZ'; struct.pack_into('<I', raw, 0x3c, 64)
                raw[64:68] = b'PE\0\0'; struct.pack_into('<H', raw, 68, machine)
                path.write_bytes(raw)
                self.assertEqual(builder.pe_machine(path), machine)
            path.write_bytes(b'MZ')
            with self.assertRaises(ValueError):
                builder.pe_machine(path)

    def test_portable_zip_is_deterministic_and_excludes_live_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'stage'; root.mkdir()
            (root / 'public.txt').write_text('synthetic')
            first, second = Path(temp) / 'first.zip', Path(temp) / 'second.zip'
            builder.make_zip(root, first); builder.make_zip(root, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as output:
                self.assertEqual(output.namelist(), ['HopHarbor/public.txt'])
            (root / 'link').symlink_to(root / 'public.txt')
            with self.assertRaises(ValueError):
                builder.make_zip(root, first)
            self.assertEqual(zipfile.ZipFile(first).namelist(), ['HopHarbor/public.txt'])

    def test_distribution_allowlist_contains_no_private_state(self):
        allowed = set(builder.APP_FILES + builder.WEB_FILES)
        self.assertTrue({'manager.py', 'windows_platform.py', 'install_windows.py'} <= allowed)
        self.assertFalse({'config.json', 'control.json', 'known_hosts', 'runtime.json', 'state.json'} & allowed)
        self.assertTrue(all(not name.startswith(('work/', 'outputs/')) for name in allowed))


class WindowsInstallationScope(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = Path(self.temp.name).resolve() / 'HopHarbor'; self.app.mkdir()
        self.data = Path(self.temp.name).resolve() / 'data'; self.data.mkdir()
        self.native = FakeNative()
        patcher = mock.patch.object(launcher, 'native', return_value=self.native)
        patcher.start(); self.addCleanup(patcher.stop)

    def test_marker_is_exact_app_and_data_pair(self):
        launcher.guard_installation(self.app, self.data, create=True)
        launcher.guard_installation(self.app, self.data)
        with self.assertRaises(ValueError):
            launcher.guard_installation(self.app / 'different', self.data)
        with mock.patch.object(launcher, 'connect_service') as connection:
            with self.assertRaises(ValueError):
                launcher.stop_service(self.app / 'different', self.data)
            connection.assert_not_called()
        self.assertFalse((self.data / launcher.STOP_MARKER).exists())

    def test_stop_without_matching_marker_is_rejected(self):
        with self.assertRaises(ValueError):
            launcher.stop_service(self.app, self.data)
        self.assertEqual(list(self.data.iterdir()), [])

    def test_stop_and_uninstall_hold_the_shared_start_lock(self):
        launcher.guard_installation(self.app, self.data, create=True)
        held = []
        class Lock:
            def __init__(self, path):
                self.path = Path(path)
            def __enter__(self):
                held.append(self.path)
                return self
            def __exit__(self, *_args):
                held.remove(self.path)
        with mock.patch.object(self.native, 'ServiceLock', Lock):
            for public, internal in ((launcher.stop_service, '_stop_service_locked'),
                                     (launcher.uninstall, '_uninstall_locked')):
                with self.subTest(action=internal):
                    def check(*_args):
                        self.assertEqual(held, [self.data / '.launch.lock'])
                    with mock.patch.object(launcher, internal, side_effect=check) as action:
                        public(self.app, self.data)
                        action.assert_called_once()
                    self.assertEqual(held, [])

    def test_package_cannot_run_from_an_arbitrary_path(self):
        with mock.patch.object(launcher, 'default_app_dir', return_value=self.app / 'different'):
            with self.assertRaises(ValueError):
                launcher.verify_package(self.app)
        self.assertEqual(self.native.checked, [])

    def test_launcher_requires_own_frontend_without_external_binary(self):
        (self.app / launcher.PACKAGE_MARKER).write_text(json.dumps({'name': 'HopHarbor', 'architecture': 'x64'}))
        for name in ('manager.py', 'install_windows.py', 'runtime/python.exe', 'runtime/pythonw.exe',
                     'bin/HopHarborHelper.exe', 'ui/HopHarbor.exe'):
            path = self.app / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('synthetic')
        def validate(path):
            if not Path(path).is_file():
                raise FileNotFoundError(path)
            self.native.checked.append(Path(path))
        with mock.patch.object(launcher, 'default_app_dir', return_value=self.app), \
                mock.patch.object(launcher, 'architecture', return_value='x64'), \
                mock.patch.object(self.native, 'validate_private_file', side_effect=validate):
            with self.assertRaises(FileNotFoundError):
                launcher.verify_package(self.app)
            (self.app / 'windows_proxy.py').write_text('# synthetic frontend')
            self.assertEqual(launcher.verify_package(self.app), self.app)
            self.assertIn(self.app / 'windows_proxy.py', self.native.checked)
            self.assertNotIn(self.app / 'bin/gost.exe', self.native.checked)
            (self.app / 'bin/gost.exe').write_text('obsolete synthetic frontend')
            with self.assertRaises(ValueError):
                launcher.verify_package(self.app)

    def test_foreign_stop_request_is_not_consumed(self):
        marker = self.data / launcher.STOP_MARKER
        marker.write_text(json.dumps(launcher.installation_identity(self.app / 'other', self.data)))
        with self.assertRaises(ValueError):
            launcher.stop_requested(self.app, self.data)
        self.assertTrue(marker.exists())

    def test_foreign_registry_or_startup_entry_cannot_be_overwritten(self):
        for registry_key, name, value in ((launcher.REGISTRY_KEY, 'app_dir', 'foreign'),
                                          (launcher.RUN_KEY, 'HopHarbor', 'foreign.exe')):
            with self.subTest(key=registry_key):
                registry = FakeRegistry(); registry.values[registry_key, name] = value
                with mock.patch.dict(sys.modules, {'winreg': registry}), mock.patch.object(launcher, 'verify_package', return_value=self.app):
                    before = dict(registry.values)
                    with self.assertRaises(ValueError):
                        launcher.register(self.app, self.data)
                    self.assertEqual(registry.values, before)
                    self.assertFalse((self.data / launcher.INSTALL_MARKER).exists())

    def test_registration_records_exact_scope_and_optional_logon(self):
        registry = FakeRegistry()
        with mock.patch.dict(sys.modules, {'winreg': registry}), mock.patch.object(launcher, 'verify_package', return_value=self.app):
            launcher.register(self.app, self.data)
            self.assertEqual(registry.values[launcher.RUN_KEY, 'HopHarbor'], launcher.startup_command(self.app, self.data))
            self.assertEqual(json.loads((self.data / launcher.INSTALL_MARKER).read_text()), launcher.installation_identity(self.app, self.data))
            launcher.register(self.app, self.data, autostart=False)
            self.assertNotIn((launcher.RUN_KEY, 'HopHarbor'), registry.values)

    def test_uninstall_rejects_partial_or_mismatched_registration_before_changes(self):
        identity = launcher.installation_identity(self.app, self.data)
        cases = ({}, {'data_dir': 'foreign-data'}, {'app_dir': identity['app_dir']},
                 dict(identity, data_dir='foreign-data'), dict(identity, app_dir='foreign-app'))
        launcher.guard_installation(self.app, self.data, create=True)
        for values in cases:
            registry = FakeRegistry(); registry.keys.add(launcher.REGISTRY_KEY)
            registry.values.update({(launcher.REGISTRY_KEY, name): value for name, value in values.items()})
            before = dict(registry.values)
            with self.subTest(values=values), mock.patch.dict(sys.modules, {'winreg': registry}), \
                    mock.patch.object(launcher, '_stop_service_locked') as stop:
                with self.assertRaises(ValueError):
                    launcher.uninstall(self.app, self.data)
                stop.assert_not_called()
            self.assertEqual(registry.values, before)
            self.assertEqual(registry.deleted_keys, [])
            self.assertTrue((self.data / launcher.INSTALL_MARKER).exists())

    def test_uninstall_accepts_matching_registration_or_truly_portable_scope(self):
        for registered in (True, False):
            registry = FakeRegistry()
            launcher.guard_installation(self.app, self.data, create=True)
            config = self.data / 'config.json'; config.write_text('synthetic settings to preserve')
            if registered:
                registry.values.update({(launcher.REGISTRY_KEY, name): value
                                       for name, value in launcher.installation_identity(self.app, self.data).items()})
                registry.values[launcher.RUN_KEY, 'HopHarbor'] = launcher.startup_command(self.app, self.data)
            else:
                registry.values[launcher.RUN_KEY, 'HopHarbor'] = 'foreign-startup.exe'
            registry.values[launcher.RUN_KEY, 'OtherApp'] = 'keep-other-app.exe'
            with self.subTest(registered=registered), mock.patch.dict(sys.modules, {'winreg': registry}), \
                    mock.patch.object(launcher, '_stop_service_locked') as stop:
                launcher.uninstall(self.app, self.data)
                stop.assert_called_once_with(self.app, self.data)
            self.assertEqual(config.read_text(), 'synthetic settings to preserve')
            self.assertEqual(registry.values[launcher.RUN_KEY, 'OtherApp'], 'keep-other-app.exe')
            self.assertFalse((self.data / launcher.INSTALL_MARKER).exists())
            if registered:
                self.assertNotIn((launcher.RUN_KEY, 'HopHarbor'), registry.values)
                self.assertEqual(registry.deleted_keys, [launcher.REGISTRY_KEY])
            else:
                self.assertEqual(registry.values[launcher.RUN_KEY, 'HopHarbor'], 'foreign-startup.exe')
                self.assertEqual(registry.deleted_keys, [])

    def test_unknown_architecture_and_host_os_do_not_run_installer(self):
        self.assertEqual(launcher.architecture('AMD64'), 'x64')
        self.assertEqual(launcher.architecture('aarch64'), 'arm64')
        with self.assertRaises(ValueError):
            launcher.architecture('i386')
        if sys.platform != 'win32':
            with self.assertRaises(ValueError):
                launcher.require_windows()

    def test_windows_version_floor_by_native_architecture(self):
        cases = (('x64', 19044, False), ('x64', 19045, True), ('x64', 22000, True),
                 ('arm64', 19045, False), ('arm64', 21999, False), ('arm64', 22000, True))
        for arch, build, allowed in cases:
            with self.subTest(arch=arch, build=build), mock.patch.object(launcher.sys, 'platform', 'win32'), \
                    mock.patch.object(launcher.sys, 'getwindowsversion', return_value=types.SimpleNamespace(build=build), create=True), \
                    mock.patch.object(launcher, 'architecture', return_value=arch):
                if allowed:
                    launcher.require_windows()
                else:
                    with self.assertRaises(ValueError):
                        launcher.require_windows()

    def test_control_rejects_invalid_shape_before_network(self):
        for value in ([], {'port': True, 'token': 'x' * 32}, {'port': 80, 'token': 'x' * 32},
                      {'port': 17777, 'token': 'short'}):
            (self.data / 'control.json').write_text(json.dumps(value))
            with self.subTest(value=value), mock.patch.object(launcher.urllib.request, 'build_opener') as network:
                with self.assertRaises(ValueError):
                    launcher.ServiceClient(self.data)
                network.assert_not_called()

    def test_stale_control_port_is_not_contacted_without_backend_lock(self):
        (self.data / 'control.json').write_text(json.dumps({'port': 17777, 'token': 'x' * 32}))
        with mock.patch.object(launcher, 'ServiceClient') as connection:
            self.assertIsNone(launcher.connect_service(self.data))
            connection.assert_not_called()


if __name__ == '__main__':
    unittest.main()
