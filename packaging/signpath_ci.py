#!/usr/bin/env python3
"""Offline checks for the dormant SignPath CI candidate; never signs or uploads."""
import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import importlib.util
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def metadata(root, source_commit):
    if not re.fullmatch(r'[0-9a-f]{40}', source_commit):
        raise ValueError('An exact lowercase source commit is required.')
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    if actual != source_commit:
        raise ValueError('Checked-out source differs from the dispatch commit.')
    values = {}
    for node in ast.parse((root / 'packaging/build_windows.py').read_text()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in ('VERSION', 'BUILD'):
                values[name] = ast.literal_eval(node.value)
    version, build = values.get('VERSION'), values.get('BUILD')
    if not isinstance(version, str) or not re.fullmatch(r'\d{1,5}\.\d{1,5}\.\d{1,5}', version):
        raise ValueError('Invalid product version.')
    if type(build) is not int or not 0 < build <= 65535:
        raise ValueError('Invalid build number.')
    if any(int(part) > 65535 for part in version.split('.')):
        raise ValueError('Product version exceeds PE version limits.')
    return {'version': version, 'build': str(build), 'file_version': version + '.' + str(build),
            'source_commit': source_commit}


def verify_inputs(root, cache, arch):
    if arch not in ('arm64', 'x64'):
        raise ValueError('Unsupported architecture.')
    cache = cache.resolve()
    document = json.loads((root / 'vendor/windows/provenance.json').read_text())
    rows = []
    for package in document['packages']:
        if arch not in package['architecture'].split(','):
            continue
        name, version = package['name'].lower(), package['version']
        if not re.fullmatch(r'[a-z0-9.-]+', name) or not re.fullmatch(r'[0-9][a-zA-Z0-9.+-]*', version):
            raise ValueError('Unsafe NuGet identity.')
        path = cache / 'tools/nuget' / name / version / (name + '.' + version + '.nupkg')
        if any(p.is_symlink() for p in [path, *path.parents]) or not path.is_file():
            raise ValueError('Reviewed NuGet archive missing or linked: ' + name)
        data = path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        sha512 = base64.b64encode(hashlib.sha512(data).digest()).decode('ascii')
        if sha256 != package['sha256'] or sha512 != package['sha512']:
            raise ValueError('Resolved NuGet archive differs from reviewed provenance: ' + name)
        for notice in package.get('notices', []):
            if not re.fullmatch(r'[A-Za-z0-9._-]+', notice['file']):
                raise ValueError('Unsafe notice filename.')
            notice_path = root / 'vendor/windows' / notice['file']
            if (notice_path.is_symlink() or not notice_path.is_file()
                    or hashlib.sha256(notice_path.read_bytes()).hexdigest() != notice['sha256']):
                raise ValueError('Committed dependency notice differs from provenance: ' + name)
        rows.append({'name': package['name'], 'version': version, 'sha256': sha256})
    expected = {'Microsoft.NETCore.App.Runtime.win-' + arch,
                'Microsoft.NETCore.App.Host.win-' + arch,
                'Microsoft.WindowsDesktop.App.Runtime.win-' + arch,
                'Microsoft.Web.WebView2'}
    if len(rows) != 4 or {row['name'] for row in rows} != expected:
        raise ValueError('Incomplete or duplicate reviewed target dependency inventory.')
    return {'architecture': arch, 'packages': rows, 'status': 'REVIEWED_NUGET_INPUTS_MATCH'}


def record_build(root, output, arch, source_commit):
    """Record unsigned candidates, not a signing attestation or native test result."""
    if arch not in ('arm64', 'x64'):
        raise ValueError('Unsupported architecture.')
    product = metadata(root, source_commit)
    spec = importlib.util.spec_from_file_location('reviewed_builder', root / 'packaging/build_windows.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    prefix = 'HopHarbor-' + product['version'] + '-windows-' + arch
    names = [prefix + '-portable.zip', prefix + '-setup.exe']
    report_name = prefix + '-build.json'
    if {p.name for p in output.glob('HopHarbor-*')} != set(names + [report_name]):
        raise ValueError('Require exactly one matching unsigned ZIP, Setup and builder report.')
    with zipfile.ZipFile(output / names[0]) as archive:
        members = list(builder.safe_zip_members(archive))
        if any(not name.startswith('HopHarbor/') for _, name in members):
            raise ValueError('Unexpected ZIP root.')
        files = {name[len('HopHarbor/'):]: archive.read(member) for member, name in members}
        manifest = json.loads(files['PACKAGE-SHA256.json'])
        actual = {name: hashlib.sha256(data).hexdigest() for name, data in files.items() if name != 'PACKAGE-SHA256.json'}
        if manifest != actual:
            raise ValueError('Unsigned portable manifest mismatch.')
        marker = json.loads(files['hopharbor-package.json'])
        if marker != dict(name='HopHarbor', version=product['version'], build=int(product['build']), architecture=arch):
            raise ValueError('Unsigned product marker mismatch.')
        for name in builder.APP_FILES + builder.WEB_FILES + builder.VENDOR_FILES + ('LICENSE', 'THIRD-PARTY-NOTICES.md'):
            if files[name] != (root / name).read_bytes():
                raise ValueError('Unsigned application/source mismatch: ' + name)
    reviewed = json.loads((output / 'reviewed-inputs.json').read_text())
    if reviewed['status'] != 'REVIEWED_NUGET_INPUTS_MATCH' or reviewed['architecture'] != arch:
        raise ValueError('Dependency verification receipt mismatch.')
    pins = json.loads((root / 'docs/signing/tool-pins.json').read_text())
    sdk = json.loads((output / 'sdk-verification.json').read_text(encoding='utf-8-sig'))
    inno = json.loads((output / 'inno-verification.json').read_text(encoding='utf-8-sig'))
    if (sdk['version'] != pins['dotnet_sdk']['version'] or sdk['sha512'] != pins['dotnet_sdk']['sha512']
            or sdk['executable_signature'] != 'Valid' or inno['version'] != pins['inno']['version']
            or inno['sha256'] != pins['inno']['sha256']):
        raise ValueError('Tool verification receipts differ from reviewed pins.')
    hashes = {}
    for name in names:
        path = output / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Expected ordinary candidate files.')
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    report = json.loads((output / report_name).read_text())
    expected_report = dict(version=product['version'], build=int(product['build']), architecture=arch,
                           portable_zip=names[0], sha256=hashes[names[0]], files=len(files))
    if report != expected_report:
        raise ValueError('Builder report does not match the checked portable artifact.')
    tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=root, text=True).strip()
    result = {'status': 'UNSIGNED_REVIEW_CANDIDATE', 'source_commit': source_commit, 'source_tree': tree,
              'version': product['version'], 'build': int(product['build']), 'architecture': arch,
              'artifacts': hashes, 'portable_files': len(files), 'portable_manifest_exact': True,
              'builder_report': report,
              'reviewed_dependencies': reviewed, 'tool_verification': {'sdk': sdk, 'inno': inno},
              'signing': False, 'native_validation': False,
              'github': {name: os.environ.get(name) for name in ('GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_SHA')},
              'runner_image': {name: os.environ.get(name) for name in ('ImageOS', 'ImageVersion')}}
    (output / 'build-provenance.json').write_text(json.dumps(result, indent=2) + '\n')
    (output / 'SHA256SUMS.txt').write_text(''.join(sha + '  ' + name + '\n' for name, sha in hashes.items()))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    m = sub.add_parser('metadata')
    m.add_argument('--source-commit', required=True)
    m.add_argument('--github-output', type=Path)
    v = sub.add_parser('verify-inputs')
    v.add_argument('--arch', choices=('arm64', 'x64'), required=True)
    v.add_argument('--cache-dir', type=Path, required=True)
    v.add_argument('--output', type=Path, required=True)
    r = sub.add_parser('record-build')
    r.add_argument('--arch', choices=('arm64', 'x64'), required=True)
    r.add_argument('--source-commit', required=True)
    r.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'metadata':
        result = metadata(ROOT, args.source_commit)
        if args.github_output:
            with args.github_output.open('a', encoding='utf-8') as output:
                for key, value in result.items():
                    output.write(key + '=' + value + '\n')
    elif args.command == 'verify-inputs':
        result = verify_inputs(ROOT, args.cache_dir, args.arch)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    else:
        result = record_build(ROOT, args.output_dir, args.arch, args.source_commit)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
