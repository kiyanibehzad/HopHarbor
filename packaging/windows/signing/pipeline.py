#!/usr/bin/env python3
"""Local signing boundaries; no API, key, certificate import or release upload.

CI must build the input in the same trusted workflow. A source SHA in a JSON
file is not an attestation. The service independently verifies CI origin.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('windows_builder', ROOT / 'packaging/build_windows.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)
OWNED = ('bin/HopHarborHelper.exe', 'ui/HopHarbor.exe', 'ui/HopHarbor.dll')
MANIFEST = 'PACKAGE-SHA256.json'
# Official Inno 7.1.0 Projects/Res/Setup.version.rc; not the app version.
UNINSTALLER_FILE_VERSION = '51.1055.0.0'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    path = Path(path)
    for p in (path, *path.parents):
        info = p.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Links/reparse points are not signing inputs')
    if not path.is_file():
        raise ValueError('Expected a regular file: ' + str(path))
    return path.read_bytes()


def tree(path):
    root = Path(path)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Expected an ordinary directory')
    result = {}
    for p in sorted(root.rglob('*')):
        info = p.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Unexpected link/reparse point')
        if p.is_file():
            result[p.relative_to(root).as_posix()] = digest(regular(p))
    return result


def write_json(path, data):
    with Path(path).open('x', encoding='utf-8') as f:
        json.dump(data, f, indent=2); f.write('\n')


def load_json(path):
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    return json.loads(regular(path), object_pairs_hook=unique)


def pe_fields(data):
    try:
        if data[:2] != b'MZ':
            raise ValueError('Expected PE image')
        pos = struct.unpack_from('<I', data, 60)[0]
        if data[pos:pos+4] != b'PE\0\0':
            raise ValueError('Invalid PE image')
        opt = pos + 24
        size = struct.unpack_from('<H', data, pos + 20)[0]
        magic = struct.unpack_from('<H', data, opt)[0]
        if magic not in (0x10b, 0x20b):
            raise ValueError('Unexpected optional header')
        directory = opt + (112 if magic == 0x20b else 96)
        if size < directory + 40 - opt or opt + size > len(data):
            raise ValueError('Truncated optional header')
        if struct.unpack_from('<I', data, directory - 4)[0] < 5:
            raise ValueError('Missing security directory')
        cert = directory + 32
        address, length = struct.unpack_from('<II', data, cert)
        return opt + 64, cert, address, length
    except struct.error as e:
        raise ValueError('Truncated PE') from e


def unsigned_pe(data):
    _, _, address, length = pe_fields(data)
    if address or length:
        raise ValueError('Refusing to replace an existing signature')


def assert_signature_only(unsigned, signed):
    """Preserve every byte except checksum, certificate directory and appended cert.

    This is NOT signature verification. Windows trust verification is mandatory
    afterwards. The strict comparison covers .NET bundle/installer overlays too.
    """
    unsigned_pe(unsigned)
    uc, ud, _, _ = pe_fields(unsigned)
    sc, sd, address, length = pe_fields(signed)
    expected_address = (len(unsigned) + 7) & ~7
    if (uc, ud) != (sc, sd) or address != expected_address or length < 8 or address + length != len(signed):
        raise ValueError('Signing changed the image layout or appended unexpected data')
    before = bytearray(unsigned + b'\0' * (address - len(unsigned)))
    after = bytearray(signed[:address])
    for value in (before, after):
        value[uc:uc+4] = b'\0' * 4
        value[ud:ud+8] = b'\0' * 8
    if before != after:
        raise ValueError('Signed image content differs from the original')
    offset = address
    while offset < len(signed):
        if offset + 8 > len(signed):
            raise ValueError('Truncated certificate table')
        size, revision, kind = struct.unpack_from('<IHH', signed, offset)
        end = offset + ((size + 7) & ~7)
        if size < 8 or revision != 0x200 or kind != 2 or end > len(signed) or any(signed[offset+size:end]):
            raise ValueError('Unexpected WIN_CERTIFICATE structure')
        offset = end


def baseline(work):
    b = load_json(work / 'baseline.json')
    if b['owned'] != list(OWNED) or b['architecture'] not in builder.ARCHITECTURES:
        raise ValueError('Invalid signing boundary')
    if tree(work / 'payload') != b['files']:
        raise ValueError('Unsigned baseline changed')
    return b


def verify(path, b, args, *, uninstaller=False):
    if sys.platform != 'win32':
        raise ValueError('Signed output requires Windows Authenticode verification')
    if not re.fullmatch('[0-9a-fA-F]{64}', args.certificate_sha256):
        raise ValueError('An approved SHA-256 certificate fingerprint is required')
    subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File',
        str(Path(__file__).with_name('verify-signature.ps1')), '-Path', str(path.resolve()),
        '-CertificateSha256', args.certificate_sha256, '-SignTool', str(args.signtool.resolve()),
        '-ProductVersion', b['version'], '-FileVersion',
        UNINSTALLER_FILE_VERSION if uninstaller else b['version'] + '.' + str(b['build'])],
        check=True, timeout=120)


def prepare(args):
    if not re.fullmatch('[0-9a-f]{40}', args.source_commit):
        raise ValueError('Expected exact source commit')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if head != args.source_commit:
        raise ValueError('Checkout does not match declared source')
    subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--'], cwd=ROOT, check=True)
    work = args.work_dir.resolve()
    if work == ROOT or ROOT in work.parents:
        raise ValueError('Keep outputs outside the checkout')
    work.mkdir(parents=True, exist_ok=False)
    payload = work / 'payload'; payload.mkdir()
    with zipfile.ZipFile(args.unsigned_zip) as z:
        members = list(builder.safe_zip_members(z))
        if len(members) > 2000 or sum(m.file_size for m, _ in members) > 1024**3:
            raise ValueError('Unexpected package bounds')
        for member, name in members:
            if not name.startswith('HopHarbor/'):
                raise ValueError('Unexpected portable root')
            target = payload / name[len('HopHarbor/'):]
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as f:
                f.write(z.read(member))
    files = tree(payload); recorded = load_json(payload / MANIFEST)
    if recorded != {k: v for k, v in files.items() if k != MANIFEST}:
        raise ValueError('Unsigned manifest is not complete and exact')
    marker = load_json(payload / 'hopharbor-package.json')
    if marker != dict(name='HopHarbor', version=builder.VERSION, build=builder.BUILD, architecture=args.arch):
        raise ValueError('Package version/architecture does not match source')
    for name in builder.APP_FILES + builder.WEB_FILES + builder.VENDOR_FILES + ('LICENSE', 'THIRD-PARTY-NOTICES.md'):
        if regular(payload / name) != regular(ROOT / name):
            raise ValueError('Source payload differs from current checkout: ' + name)
    builder.validate_windows_payload(payload)
    request = work / 'project-request'; request.mkdir()
    for name in OWNED:
        data = regular(payload / name); unsigned_pe(data)
        if builder.pe_machine(payload / name) != builder.ARCHITECTURES[args.arch][2]:
            raise ValueError('Wrong project PE architecture')
        target = request / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
    write_json(work / 'baseline.json', dict(schema=1, source_commit=head, version=builder.VERSION,
        build=builder.BUILD, architecture=args.arch, owned=list(OWNED), files=files,
        unsigned_archive_sha256=builder.sha256(args.unsigned_zip)))


def apply(args):
    work = args.work_dir.resolve(); b = baseline(work)
    if set(tree(args.signed_dir)) != set(OWNED):
        raise ValueError('Returned project artifact must contain exactly three owned files')
    signed = {}
    for name in OWNED:
        signed[name] = regular(args.signed_dir / name)
        assert_signature_only(regular(work / 'payload' / name), signed[name])
        verify(args.signed_dir / name, b, args)
        if regular(args.signed_dir / name) != signed[name]:
            raise ValueError('Signed input changed during verification')
    output = work / 'signed-payload'
    shutil.copytree(work / 'payload', output)
    for name, data in signed.items():
        (output / name).write_bytes(data)
    manifest = {k: v for k, v in tree(output).items() if k != MANIFEST}
    (output / MANIFEST).unlink(); write_json(output / MANIFEST, manifest)
    for name, original in b['files'].items():
        if name not in OWNED and name != MANIFEST and builder.sha256(output / name) != original:
            raise ValueError('A non-project file changed')
    archive = work / ('HopHarbor-%s-windows-%s-portable.zip' % (b['version'], b['architecture']))
    builder.make_zip(output, archive)
    write_json(work / 'signed-payload.json', dict(files=tree(output), archive=archive.name,
        sha256=builder.sha256(archive), certificate_sha256=args.certificate_sha256.lower()))


def signed_payload(work):
    r = load_json(work / 'signed-payload.json')
    if tree(work / 'signed-payload') != r['files']:
        raise ValueError('Signed payload changed before compilation')
    return r


def capture_uninstaller(args):
    work = args.work_dir.resolve(); baseline(work); signed_payload(work)
    files = tree(args.cache_dir)
    if len(files) != 1:
        raise ValueError('Require a fresh cache with exactly one generated uninstaller')
    name = next(iter(files))
    if not re.fullmatch(r'uninst-7\.1\.0-[0-9a-fA-F]{10}\.e64', name):
        raise ValueError('Unexpected Inno 7.1.0 x64 uninstaller cache filename')
    log = regular(args.compiler_log).decode('utf-8-sig', errors='replace')
    if args.compiler_exit_code != 2 or 'Signed uninstaller mode is enabled.' not in log or 'and compile again' not in log or name not in log:
        raise ValueError('First compile did not fail at the expected signing boundary')
    data = regular(args.cache_dir / name); unsigned_pe(data)
    if builder.pe_machine(args.cache_dir / name) != 0x8664:
        raise ValueError('Expected x64 Inno engine for both target architectures')
    request = work / 'uninstaller-request'; request.mkdir()
    (request / 'uninstaller.exe').write_bytes(data)
    write_json(work / 'uninstaller.json', dict(cache_dir=str(args.cache_dir.resolve()),
        name=name, sha256=digest(data), first_compile_exit=args.compiler_exit_code,
        first_compile_log_sha256=builder.sha256(args.compiler_log)))


def capture_installer(args):
    work = args.work_dir.resolve(); b = baseline(work); signed_payload(work)
    u = load_json(work / 'signed-uninstaller.json'); original = load_json(work / 'uninstaller.json')
    if builder.sha256(Path(original['cache_dir']) / original['name']) != u['sha256']:
        raise ValueError('Signed uninstaller cache changed')
    expected = 'HopHarbor-%s-windows-%s-setup.exe' % (b['version'], b['architecture'])
    if args.installer.name != expected or builder.pe_machine(args.installer) != 0x8664:
        raise ValueError('Unexpected installer identity')
    data = regular(args.installer); unsigned_pe(data)
    request = work / 'installer-request'; request.mkdir()
    (request / 'installer.exe').write_bytes(data)
    write_json(work / 'installer.json', dict(name=expected, sha256=digest(data)))


def apply_single(args, kind):
    work = args.work_dir.resolve(); b = baseline(work); signed_payload(work)
    name = kind + '.exe'
    if set(tree(args.signed_dir)) != {name}:
        raise ValueError('Unexpected files in returned signing artifact')
    before = regular(work / (kind + '-request') / name)
    record = load_json(work / (kind + '.json'))
    if digest(before) != record['sha256']:
        raise ValueError('Signing request changed')
    after = regular(args.signed_dir / name)
    assert_signature_only(before, after)
    verify(args.signed_dir / name, b, args, uninstaller=(kind == 'uninstaller'))
    if regular(args.signed_dir / name) != after:
        raise ValueError('Signed input changed during verification')
    if kind == 'uninstaller':
        destination = Path(record['cache_dir']) / record['name']
        if regular(destination) != before:
            raise ValueError('Uninstaller cache changed before replacement')
        destination.write_bytes(after)
    else:
        destination = work / record['name']
        with destination.open('xb') as f:
            f.write(after)
    write_json(work / ('signed-' + kind + '.json'), dict(name=destination.name,
        sha256=digest(after), certificate_sha256=args.certificate_sha256.lower()))


def main():
    p = argparse.ArgumentParser(description=__doc__); subs = p.add_subparsers(dest='command', required=True)
    for command in ('prepare', 'apply', 'capture-uninstaller', 'apply-uninstaller', 'capture-installer', 'apply-installer'):
        c = subs.add_parser(command); c.add_argument('--work-dir', type=Path, required=True)
        if command == 'prepare':
            c.add_argument('--unsigned-zip', type=Path, required=True); c.add_argument('--arch', choices=tuple(builder.ARCHITECTURES), required=True)
            c.add_argument('--source-commit', required=True)
        elif command.startswith('apply'):
            c.add_argument('--signed-dir', type=Path, required=True); c.add_argument('--certificate-sha256', required=True); c.add_argument('--signtool', type=Path, required=True)
        elif command == 'capture-uninstaller':
            c.add_argument('--cache-dir', type=Path, required=True); c.add_argument('--compiler-log', type=Path, required=True); c.add_argument('--compiler-exit-code', type=int, required=True)
        else:
            c.add_argument('--installer', type=Path, required=True)
    args = p.parse_args()
    if args.command.startswith('apply-'):
        apply_single(args, args.command[len('apply-'):])
    else:
        globals()[args.command.replace('-', '_')](args)


if __name__ == '__main__':
    main()
