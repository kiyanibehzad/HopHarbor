import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('signpath_ci', Path(__file__).resolve().parents[1] / 'packaging/signpath_ci.py')
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


class SignPathInputChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'packaging').mkdir()
        (self.root / 'packaging/build_windows.py').write_text("VERSION='1.4.2'\nBUILD=15\nraise RuntimeError('must not execute')\n")

    def test_metadata_does_not_execute_builder_and_binds_head(self):
        with patch.object(ci.subprocess, 'check_output', return_value='a' * 40 + '\n'):
            self.assertEqual(ci.metadata(self.root, 'a' * 40)['file_version'], '1.4.2.15')
            with self.assertRaises(ValueError):
                ci.metadata(self.root, 'b' * 40)

    def test_dispatch_injection_and_nonliteral_version_rejected(self):
        with self.assertRaises(ValueError):
            ci.metadata(self.root, 'a' * 40 + '\nextra=evil')
        (self.root / 'packaging/build_windows.py').write_text("VERSION=__import__('os').getcwd()\nBUILD=15\n")
        with patch.object(ci.subprocess, 'check_output', return_value='a' * 40):
            with self.assertRaises(ValueError):
                ci.metadata(self.root, 'a' * 40)

    def inventory(self, arch='arm64'):
        rows = []
        for name in ['Microsoft.NETCore.App.Runtime.win-' + arch,
                     'Microsoft.NETCore.App.Host.win-' + arch,
                     'Microsoft.WindowsDesktop.App.Runtime.win-' + arch,
                     'Microsoft.Web.WebView2']:
            data = ('synthetic:' + name).encode()
            row = dict(name=name, version='1.0.0', architecture=arch,
                       sha256=hashlib.sha256(data).hexdigest(),
                       sha512=base64.b64encode(hashlib.sha512(data).digest()).decode())
            rows.append(row)
            p = self.root / 'cache/tools/nuget' / name.lower() / '1.0.0' / (name.lower() + '.1.0.0.nupkg')
            p.parent.mkdir(parents=True)
            p.write_bytes(data)
        (self.root / 'vendor/windows').mkdir(parents=True)
        self.manifest = self.root / 'vendor/windows/provenance.json'
        self.manifest.write_text(json.dumps({'packages': rows}))
        return rows

    def test_all_target_inputs_match_without_network(self):
        self.inventory()
        self.assertEqual(len(ci.verify_inputs(self.root, self.root / 'cache', 'arm64')['packages']), 4)

    def test_changed_missing_and_linked_archives_fail(self):
        rows = self.inventory()
        p = self.root / 'cache/tools/nuget' / rows[0]['name'].lower() / '1.0.0' / (rows[0]['name'].lower() + '.1.0.0.nupkg')
        original = p.read_bytes()
        p.write_bytes(b'tampered')
        with self.assertRaises(ValueError):
            ci.verify_inputs(self.root, self.root / 'cache', 'arm64')
        p.unlink()
        with self.assertRaises(ValueError):
            ci.verify_inputs(self.root, self.root / 'cache', 'arm64')
        target = self.root / 'outside'; target.write_bytes(original); p.symlink_to(target)
        with self.assertRaises(ValueError):
            ci.verify_inputs(self.root, self.root / 'cache', 'arm64')

    def test_missing_or_duplicate_inventory_fails_even_valid_hashes(self):
        rows = self.inventory()
        for changed in [rows[:-1], rows + rows[:1]]:
            self.manifest.write_text(json.dumps({'packages': changed}))
            with self.assertRaises(ValueError):
                ci.verify_inputs(self.root, self.root / 'cache', 'arm64')

    def test_architecture_and_unsafe_identity_rejected(self):
        rows = self.inventory()
        with self.assertRaises(ValueError):
            ci.verify_inputs(self.root, self.root / 'cache', 'x64')
        rows[0]['name'] = '../injected'
        self.manifest.write_text(json.dumps({'packages': rows}))
        with self.assertRaises(ValueError):
            ci.verify_inputs(self.root, self.root / 'cache', 'arm64')

    def test_changed_notice_rejected(self):
        rows = self.inventory()
        notice = self.root / 'vendor/windows/LICENSE.txt'
        notice.write_bytes(b'synthetic notice')
        rows[0]['notices'] = [dict(file='LICENSE.txt', sha256=hashlib.sha256(notice.read_bytes()).hexdigest())]
        self.manifest.write_text(json.dumps({'packages': rows}))
        ci.verify_inputs(self.root, self.root / 'cache', 'arm64')
        notice.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            ci.verify_inputs(self.root, self.root / 'cache', 'arm64')

    def build_fixture(self):
        (self.root / 'packaging/build_windows.py').write_text("VERSION='1.4.2'\nBUILD=15\nAPP_FILES=('manager.py',)\nWEB_FILES=()\nVENDOR_FILES=()\ndef safe_zip_members(z):\n return [(m,m.filename) for m in z.infolist()]\n")
        for name in ['manager.py', 'LICENSE', 'THIRD-PARTY-NOTICES.md']:
            (self.root / name).write_text('synthetic ' + name)
        out = self.root / 'output'; out.mkdir()
        files = {name: (self.root / name).read_bytes() for name in ['manager.py', 'LICENSE', 'THIRD-PARTY-NOTICES.md']}
        files['hopharbor-package.json'] = json.dumps(dict(name='HopHarbor', version='1.4.2', build=15, architecture='arm64')).encode()
        files['PACKAGE-SHA256.json'] = json.dumps({n: hashlib.sha256(d).hexdigest() for n, d in files.items()}).encode()
        with zipfile.ZipFile(out / 'HopHarbor-1.4.2-windows-arm64-portable.zip', 'w') as z:
            for n, d in files.items(): z.writestr('HopHarbor/' + n, d)
        (out / 'HopHarbor-1.4.2-windows-arm64-setup.exe').write_bytes(b'synthetic not executable')
        report = dict(version='1.4.2', build=15, architecture='arm64', portable_zip='HopHarbor-1.4.2-windows-arm64-portable.zip',
                      sha256=hashlib.sha256((out / 'HopHarbor-1.4.2-windows-arm64-portable.zip').read_bytes()).hexdigest(), files=len(files))
        (out / 'HopHarbor-1.4.2-windows-arm64-build.json').write_text(json.dumps(report))
        (out / 'reviewed-inputs.json').write_text(json.dumps(dict(status='REVIEWED_NUGET_INPUTS_MATCH', architecture='arm64', packages=[])))
        pins = dict(dotnet_sdk=dict(version='10.0.403', sha512='a' * 128), inno=dict(version='7.1.0', sha256='b' * 64))
        (self.root / 'docs/signing').mkdir(parents=True)
        (self.root / 'docs/signing/tool-pins.json').write_text(json.dumps(pins))
        (out / 'sdk-verification.json').write_text(json.dumps(dict(version='10.0.403', sha512='a' * 128, executable_signature='Valid')))
        (out / 'inno-verification.json').write_text(json.dumps(dict(version='7.1.0', sha256='b' * 64)))
        return out

    def test_unsigned_provenance_records_manifest_and_checksums(self):
        out = self.build_fixture()
        with patch.object(ci.subprocess, 'check_output', return_value='a' * 40):
            result = ci.record_build(self.root, out, 'arm64', 'a' * 40)
        self.assertFalse(result['signing'])
        self.assertFalse(result['native_validation'])
        self.assertEqual(len(result['artifacts']), 2)
        self.assertEqual(len((out / 'SHA256SUMS.txt').read_text().splitlines()), 2)

    def test_unsigned_provenance_rejects_source_and_tool_mismatches(self):
        out = self.build_fixture()
        with patch.object(ci.subprocess, 'check_output', return_value='a' * 40):
            (self.root / 'manager.py').write_text('changed')
            with self.assertRaises(ValueError): ci.record_build(self.root, out, 'arm64', 'a' * 40)
            (self.root / 'manager.py').write_text('synthetic manager.py')
            (out / 'sdk-verification.json').write_text(json.dumps(dict(version='10.0.403', sha512='c' * 128, executable_signature='Valid')))
            with self.assertRaises(ValueError): ci.record_build(self.root, out, 'arm64', 'a' * 40)

    def test_unsigned_provenance_rejects_wrong_arch_and_extra_artifact(self):
        out = self.build_fixture()
        with patch.object(ci.subprocess, 'check_output', return_value='a' * 40):
            with self.assertRaises(ValueError): ci.record_build(self.root, out, 'x64', 'a' * 40)
            (out / 'HopHarbor-unreviewed.exe').write_bytes(b'unexpected')
            with self.assertRaises(ValueError): ci.record_build(self.root, out, 'arm64', 'a' * 40)

    def test_unsigned_provenance_requires_exact_builder_report(self):
        out = self.build_fixture()
        report = out / 'HopHarbor-1.4.2-windows-arm64-build.json'
        with patch.object(ci.subprocess, 'check_output', return_value='a' * 40):
            document = json.loads(report.read_text()); document['sha256'] = '0' * 64
            report.write_text(json.dumps(document))
            with self.assertRaises(ValueError): ci.record_build(self.root, out, 'arm64', 'a' * 40)
            report.unlink()
            with self.assertRaises(ValueError): ci.record_build(self.root, out, 'arm64', 'a' * 40)


if __name__ == '__main__':
    unittest.main()
