"""Offline boundary tests; synthetic certificate bytes never claim trust."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('signing_pipeline', HERE / 'pipeline.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)


def unsigned(overlay=b'BUNDLE\0\0'):
    data = bytearray(512)
    data[:2] = b'MZ'; struct.pack_into('<I', data, 60, 128)
    data[128:132] = b'PE\0\0'; struct.pack_into('<H', data, 132, 0x8664)
    struct.pack_into('<H', data, 148, 240)
    struct.pack_into('<H', data, 152, 0x20b)
    struct.pack_into('<I', data, 260, 16)
    return bytes(data) + overlay


def signed(data):
    out = bytearray(data + b'\0' * (-len(data) % 8))
    struct.pack_into('<II', out, 296, len(out), 16)
    struct.pack_into('<I', out, 216, 123)
    return bytes(out) + struct.pack('<IHH', 12, 0x200, 2) + b'TEST' + b'\0' * 4


class Boundaries(unittest.TestCase):
    def test_all_overlay_and_alignment_lengths_preserved(self):
        for length in range(16):
            before = unsigned(b'BUNDLE' + b'\0' * length)
            p.assert_signature_only(before, signed(before))

    def test_modified_bundle_rejected_even_with_certificate(self):
        before = unsigned(); after = bytearray(signed(before)); after[513] ^= 1
        with self.assertRaises(ValueError): p.assert_signature_only(before, after)

    def test_modified_header_rejected(self):
        before = unsigned(); after = bytearray(signed(before)); after[140] ^= 1
        with self.assertRaises(ValueError): p.assert_signature_only(before, after)

    def test_preexisting_upstream_signature_rejected(self):
        with self.assertRaises(ValueError): p.unsigned_pe(signed(unsigned()))

    def test_trailing_data_rejected(self):
        before = unsigned()
        with self.assertRaises(ValueError): p.assert_signature_only(before, signed(before) + b'EVIL')

    def test_fake_certificate_inside_original_data_rejected(self):
        before = unsigned(); after = bytearray(signed(before)); struct.pack_into('<I', after, 296, 512)
        with self.assertRaises(ValueError): p.assert_signature_only(before, after)

    def test_nonzero_alignment_rejected(self):
        before = unsigned(b'x'); after = bytearray(signed(before)); after[len(before)] = 1
        with self.assertRaises(ValueError): p.assert_signature_only(before, after)

    def test_invalid_certificate_type_rejected(self):
        before = unsigned(); after = bytearray(signed(before)); after[-10] = 3
        with self.assertRaises(ValueError): p.assert_signature_only(before, after)

    def test_truncated_pe_rejected(self):
        for data in (b'', b'MZ', unsigned()[:280]):
            with self.assertRaises(ValueError): p.pe_fields(data)

    def test_signed_apply_has_no_nonwindows_bypass(self):
        with patch.object(p.sys, 'platform', 'darwin'):
            with self.assertRaises(ValueError): p.verify(Path('unused.exe'), {}, SimpleNamespace())

    def test_duplicate_manifest_keys_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            f = Path(temp).resolve() / 'manifest.json'; f.write_text('{"a":1,"a":2}')
            with self.assertRaises(ValueError): p.load_json(f)

    def test_symlink_cannot_substitute_signing_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); (root / 'file').write_bytes(b'original')
            (root / 'link').symlink_to(root / 'file')
            with self.assertRaises(ValueError): p.regular(root / 'link')
            with self.assertRaises(ValueError): p.tree(root)

    def test_unsigned_baseline_mutation_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); (root / 'payload').mkdir(); (root / 'payload/file').write_bytes(b'original')
            p.write_json(root / 'baseline.json', dict(owned=list(p.OWNED), architecture='x64', files=p.tree(root / 'payload')))
            p.baseline(root)
            (root / 'payload/file').write_bytes(b'replaced')
            with self.assertRaises(ValueError): p.baseline(root)

    def test_apply_preserves_vendor_bytes_and_refreshes_signed_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); payload = root / 'payload'; payload.mkdir()
            returned = root / 'returned'; returned.mkdir()
            for name in p.OWNED:
                for base, data in ((payload, unsigned()), (returned, signed(unsigned()))):
                    target = base / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
            (payload / 'vendor.dll').write_bytes(signed(unsigned(b'UPSTREAM')))
            (payload / p.MANIFEST).write_text('{}')
            p.write_json(root / 'baseline.json', dict(owned=list(p.OWNED), architecture='x64', version='1.4.2', build=15, files=p.tree(payload)))
            args = SimpleNamespace(work_dir=root, signed_dir=returned, certificate_sha256='a'*64)
            with patch.object(p, 'verify') as verify:
                p.apply(args)
            self.assertEqual(verify.call_count, 3)
            self.assertEqual((root / 'signed-payload/vendor.dll').read_bytes(), (payload / 'vendor.dll').read_bytes())
            manifest = p.load_json(root / 'signed-payload' / p.MANIFEST)
            self.assertEqual(manifest['ui/HopHarbor.exe'], p.digest(signed(unsigned())))
            self.assertEqual(p.load_json(root / 'signed-payload.json')['sha256'], p.builder.sha256(root / 'HopHarbor-1.4.2-windows-x64-portable.zip'))

    def test_extra_vendor_file_in_signing_response_rejected_before_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); (root / 'returned').mkdir()
            (root / 'returned/vendor.dll').write_bytes(signed(unsigned()))
            args = SimpleNamespace(work_dir=root, signed_dir=root / 'returned')
            with patch.object(p, 'baseline'), patch.object(p, 'verify') as verify:
                with self.assertRaises(ValueError): p.apply(args)
                verify.assert_not_called()

    def test_uninstaller_verifies_pinned_engine_file_version(self):
        args = SimpleNamespace(certificate_sha256='a'*64, signtool=Path('signtool.exe'))
        b = dict(version='1.4.2', build=15)
        with patch.object(p.sys, 'platform', 'win32'), patch.object(p.subprocess, 'run') as run:
            p.verify(Path('uninstaller.exe'), b, args, uninstaller=True)
            argv = run.call_args.args[0]
            self.assertEqual(argv[argv.index('-FileVersion') + 1], '51.1055.0.0')
            self.assertEqual(argv[argv.index('-ProductVersion') + 1], '1.4.2')

    def test_xml_only_explicit_project_paths(self):
        ns = {'s': 'http://signpath.io/artifact-configuration/v1'}
        for name, expected in [('project-pe', set(p.OWNED)), ('uninstaller', {'uninstaller.exe'}), ('installer', {'installer.exe'})]:
            root = ET.parse(HERE / (name + '.xml')).getroot()
            files = root.findall('s:zip-file/s:pe-file', ns)
            self.assertEqual({f.attrib['path'] for f in files}, expected)
            for f in files:
                self.assertEqual(f.attrib['product-name'], 'HopHarbor')
                self.assertEqual(f.attrib['product-version'], '${productVersion}')
                self.assertEqual(f.attrib['file-version'], '${fileVersion}')
                self.assertEqual(f.find('s:authenticode-sign', ns).attrib['hash-algorithm'], 'sha256')
            self.assertEqual(len(root.findall('.//s:authenticode-sign', ns)), len(expected))

    def test_arbitrary_first_compile_failure_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); cache = root / 'cache'; cache.mkdir()
            (cache / 'uninst-7.1.0-1234567890.e64').write_bytes(unsigned())
            log = root / 'compiler.log'; log.write_text('Error: missing payload')
            args = SimpleNamespace(work_dir=root, cache_dir=cache, compiler_log=log, compiler_exit_code=2)
            with patch.object(p, 'baseline'), patch.object(p, 'signed_payload'):
                with self.assertRaises(ValueError): p.capture_uninstaller(args)
            self.assertFalse((root / 'uninstaller-request').exists())

    def test_expected_first_compile_captures_only_generated_cache(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); cache = root / 'cache'; cache.mkdir()
            name = 'uninst-7.1.0-1234567890.e64'; (cache / name).write_bytes(unsigned())
            log = root / 'compiler.log'; log.write_text('Error: Signed uninstaller mode is enabled.\n' + name + '\nand compile again')
            args = SimpleNamespace(work_dir=root, cache_dir=cache, compiler_log=log, compiler_exit_code=2)
            with patch.object(p, 'baseline'), patch.object(p, 'signed_payload'):
                p.capture_uninstaller(args)
            self.assertEqual(p.tree(root / 'uninstaller-request'), {'uninstaller.exe': p.digest(unsigned())})
            self.assertEqual(p.load_json(root / 'uninstaller.json')['name'], name)


if __name__ == '__main__':
    unittest.main()
