#!/usr/bin/env python3
"""Build reviewed Windows packages without running an installer or controller.

This builder runs on macOS or Windows. Its output contains only the application
allowlist, pinned vendor dependencies and published native project outputs.
"""
import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = '1.3.0'
BUILD = 10
SDK_VERSION = '10.0.403'
PYTHON_VERSION = '3.14.9'
WEBVIEW_VERSION = '1.0.4314.35'
WEBVIEW_SHA512 = 'cOaiVqP3BmQHMnxGpZzANM22tUXgycrisyJHjIGNzIaMsm8iXj7Kx+ceYg+RbYwJtzT009qfcFTocvVLY+ekMw=='
WEBVIEW_CONTENT_HASH = 'x5MFf2W03xueU1mMNvivXfHSsQ+ODo7vJ36qw/dLtU5Gs+8d7+7N7zzmNNDoT3ffosmcvZNBtUnlzyiDUuBkSQ=='
INNO_VERSION = '7.1.0'
INNO_URL = 'https://github.com/jrsoftware/issrc/releases/download/is-7_1_0/innosetup-7.1.0-x64.exe'
INNO_SHA256 = '0362a383ed217d4c4239b5933866dd96d3eb2102737da92f80f6057a4b40df2f'
ARCHITECTURES = {'arm64': ('win-arm64', 'arm64', 0xAA64), 'x64': ('win-x64', 'amd64', 0x8664)}
PYTHON_SHA256 = {
    'x64': '3c01d7cfc666f746a6f064f60fb2156ab0ec464d3d738ab796371a46a9bb24a2',
    'arm64': 'a8212664f7622ebc0cb0f9a42d7beee36cebedab97ff47c6bba668cfd85b676d',
}
APP_FILES = ('manager.py', 'log_policy.py', 'wake_monitor.py', 'ssh_hop.py',
             'askpass.py', 'windows_platform.py', 'windows_proxy.py', 'install_windows.py')
WEB_FILES = ('web/index.html', 'web/app.js')
VENDOR_FILES = tuple('vendor/windows/' + name for name in (
    'DOTNET-LICENSE.txt', 'DOTNET-THIRD-PARTY-NOTICES.txt',
    'WINDOWSDESKTOP-LICENSE.txt', 'WEBVIEW2-LICENSE.txt',
    'WEBVIEW2-NOTICE.txt', 'provenance.json'))
WINDOWS_EXECUTABLES = frozenset((
    'runtime/python.exe', 'runtime/pythonw.exe', 'bin/HopHarborHelper.exe',
    'ui/HopHarbor.exe', 'ui/createdump.exe'))


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def checked_archive(url, expected, cache, name):
    """Download to a private build cache and reject mismatched bytes."""
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / name
    if not target.exists():
        temporary = target.with_name(target.name + '.part')
        try:
            with urllib.request.urlopen(url, timeout=90) as response, temporary.open('wb') as output:
                shutil.copyfileobj(response, output)
            if sha256(temporary) != expected:
                raise ValueError('The official dependency digest does not match its pinned value.')
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    if sha256(target) != expected:
        raise ValueError('The cached dependency digest does not match its pinned value.')
    return target


def safe_zip_members(archive):
    """Accept only ordinary, relative ZIP files with no link/traversal names."""
    seen = set()
    devices = {'con', 'prn', 'aux', 'nul'} | {'com%d' % i for i in range(1, 10)} | {'lpt%d' % i for i in range(1, 10)}
    for member in archive.infolist():
        name = member.filename.replace('\\', '/')
        path = PurePosixPath(name)
        mode = member.external_attr >> 16
        parts = name.rstrip('/').split('/')
        identity = str(path).casefold()
        if (not name or path.is_absolute() or '..' in path.parts or ':' in name
                or '\x00' in name or stat.S_ISLNK(mode) or identity in seen
                or any(part in ('', '.', '..') or part.rstrip(' .') != part
                       or part.split('.')[0].casefold() in devices for part in parts)
                or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))):
            raise ValueError('Unsafe dependency archive member.')
        seen.add(identity)
        if not member.is_dir():
            yield member, str(path)


def extract_python(archive, destination):
    destination = Path(destination)
    destination.mkdir(parents=True)
    with zipfile.ZipFile(archive) as source:
        for member, name in safe_zip_members(source):
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read(member))
    # A fully isolated standard library and the adjacent application modules.
    pth = destination / 'python314._pth'
    if not pth.is_file() or not (destination / 'python.exe').is_file() or not (destination / 'pythonw.exe').is_file():
        raise ValueError('The verified Python archive is incomplete.')
    pth.write_text('python314.zip\n.\n..\n', encoding='utf-8')


def pe_machine(path):
    try:
        with Path(path).open('rb') as stream:
            if stream.read(2) != b'MZ':
                raise ValueError('Expected a Windows PE executable.')
            stream.seek(0x3C); offset = struct.unpack('<I', stream.read(4))[0]
            stream.seek(offset)
            if stream.read(4) != b'PE\0\0':
                raise ValueError('Invalid Windows PE signature.')
            return struct.unpack('<H', stream.read(2))[0]
    except struct.error as error:
        raise ValueError('Truncated Windows PE executable.') from error


def dotnet_environment(cache):
    cache = Path(cache).resolve()
    return dict(os.environ, DOTNET_CLI_HOME=str(cache / 'dotnet-home'),
                NUGET_PACKAGES=str(cache / 'nuget'), DOTNET_CLI_TELEMETRY_OPTOUT='1',
                DOTNET_GENERATE_ASPNET_CERTIFICATE='false', DOTNET_NOLOGO='1',
                DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE='true')


def publish(dotnet, project, rid, destination, scratch, env):
    project = ROOT / project
    if not project.is_file():
        raise ValueError('A native Windows source project is missing.')
    identity = project.parent.name.lower()
    intermediate = Path(scratch) / ('obj-' + identity)
    subprocess.run([str(dotnet), 'publish', str(project), '--configuration', 'Release',
        '--runtime', rid, '--self-contained', 'true', '--source', 'https://api.nuget.org/v3/index.json',
        '--output', str(destination), '-p:ContinuousIntegrationBuild=true',
        '-p:DebugType=none', '-p:DebugSymbols=false', '-p:IncludeSourceRevisionInInformationalVersion=false',
        '-p:PathMap=' + str(ROOT) + '=/_/src', '-p:BaseIntermediateOutputPath=' + str(intermediate) + os.sep,
        '-p:BaseOutputPath=' + str(Path(scratch) / ('bin-' + identity)) + os.sep],
        env=env, check=True, timeout=600)
    if identity == 'desktop':
        archive = Path(env['NUGET_PACKAGES']) / 'microsoft.web.webview2' / WEBVIEW_VERSION / ('microsoft.web.webview2.%s.nupkg' % WEBVIEW_VERSION)
        if base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode('ascii') != WEBVIEW_SHA512:
            raise ValueError('The restored official WebView2 package differs from its pinned checksum.')


def copy_published(source, destination):
    """No PDB/source maps/build caches are distribution files."""
    source, destination = Path(source), Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for path in sorted(source.rglob('*')):
        if path.is_symlink():
            raise ValueError('Unexpected symbolic link in native build output.')
        if not path.is_file() or path.suffix.lower() in ('.pdb', '.dbg', '.xml'):
            continue
        relative = path.relative_to(source)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def validate_windows_payload(root):
    """The proxy frontend is our source module, never an extra executable."""
    root = Path(root)
    if not (root / 'windows_proxy.py').is_file() or (root / 'windows_proxy.py').is_symlink():
        raise ValueError('The Windows proxy frontend module is missing.')
    allowed = {name.casefold() for name in WINDOWS_EXECUTABLES}
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('Unexpected Windows payload symlink.')
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if path.name.casefold().startswith('gost'):
            raise ValueError('An external proxy frontend is not part of the Windows package.')
        if path.suffix.casefold() == '.exe' and relative.casefold() not in allowed:
            raise ValueError('An unexpected executable is not part of the Windows package: ' + relative)


def verify_versions():
    values = {}
    for node in ast.parse((ROOT / 'manager.py').read_text()).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in ('VERSION', 'BUILD'):
                    values[target.id] = ast.literal_eval(node.value)
    if values != {'VERSION': VERSION, 'BUILD': BUILD}:
        raise ValueError('The controller and Windows packaging versions must agree before building.')


def make_zip(root, destination):
    root, destination = Path(root), Path(destination)
    temporary = destination.with_name(destination.name + '.tmp')
    with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as output:
        for path in sorted(root.rglob('*')):
            if path.is_symlink():
                raise ValueError('Unexpected package staging symlink.')
            if path.is_file():
                info = zipfile.ZipInfo('HopHarbor/' + path.relative_to(root).as_posix(), date_time=(2026, 1, 1, 0, 0, 0))
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                output.writestr(info, path.read_bytes())
    with zipfile.ZipFile(temporary) as checked:
        if checked.testzip() is not None:
            raise ValueError('The generated portable archive failed its integrity check.')
    os.replace(temporary, destination)


def build(arch, output_dir, dotnet, cache, helper_output=None, desktop_output=None, iscc=None):
    if arch not in ARCHITECTURES:
        raise ValueError('Choose arm64 or x64.')
    verify_versions()
    rid, vendor_arch, machine = ARCHITECTURES[arch]
    output_dir = Path(output_dir).resolve(); output_dir.mkdir(parents=True, exist_ok=True)
    cache = Path(cache).resolve(); cache.mkdir(parents=True, exist_ok=True)
    env = dotnet_environment(cache / 'tools')
    version = subprocess.check_output([str(dotnet), '--version'], text=True, env=env).strip()
    if version != SDK_VERSION:
        raise ValueError('Use the pinned .NET SDK %s for a reviewed build.' % SDK_VERSION)
    python_name = 'python-%s-embed-%s.zip' % (PYTHON_VERSION, vendor_arch)
    python_url = 'https://www.python.org/ftp/python/%s/%s' % (PYTHON_VERSION, python_name)
    py = checked_archive(python_url, PYTHON_SHA256[arch], cache / 'downloads', python_name)
    with tempfile.TemporaryDirectory(prefix='hopharbor-windows-build-', dir=cache) as temp:
        scratch = Path(temp); stage = scratch / 'HopHarbor'; stage.mkdir()
        for name in APP_FILES + WEB_FILES + VENDOR_FILES:
            path = ROOT / name
            if not path.is_file() or path.is_symlink():
                raise ValueError('Required reviewed Windows application file is missing: ' + name)
            target = stage / name; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(path, target)
        for name in ('LICENSE', 'THIRD-PARTY-NOTICES.md'):
            shutil.copyfile(ROOT / name, stage / name)
        assets = stage / 'assets'; assets.mkdir()
        shutil.copyfile(ROOT / 'packaging/windows/assets/HopHarbor.ico', assets / 'HopHarbor.ico')
        extract_python(py, stage / 'runtime')
        if helper_output is None:
            helper_output = scratch / 'helper'
            publish(dotnet, 'packaging/windows/NativeHelper/HopHarborHelper.csproj', rid, helper_output, scratch, env)
        if desktop_output is None:
            desktop_output = scratch / 'desktop'
            publish(dotnet, 'packaging/windows/Desktop/HopHarbor.csproj', rid, desktop_output, scratch, env)
        copy_published(helper_output, stage / 'bin'); copy_published(desktop_output, stage / 'ui')
        validate_windows_payload(stage)
        for binary in ('runtime/python.exe', 'runtime/pythonw.exe', 'bin/HopHarborHelper.exe', 'ui/HopHarbor.exe'):
            if pe_machine(stage / binary) != machine:
                raise ValueError('A package executable has the wrong architecture: ' + binary)
        provenance = {'architecture': arch, 'dependencies': [
            {'name': 'CPython embedded', 'version': PYTHON_VERSION, 'url': python_url, 'sha256': PYTHON_SHA256[arch]},
            {'name': '.NET SDK', 'version': SDK_VERSION, 'source': 'https://dotnet.microsoft.com/download/dotnet/10.0'},
            {'name': 'Microsoft.Web.WebView2 SDK', 'version': WEBVIEW_VERSION, 'source': 'https://www.nuget.org/packages/Microsoft.Web.WebView2/' + WEBVIEW_VERSION, 'sha512': WEBVIEW_SHA512, 'nuget_content_hash': WEBVIEW_CONTENT_HASH},
        ]}
        (stage / 'THIRD-PARTY-WINDOWS.json').write_text(json.dumps(provenance, indent=2) + '\n')
        (stage / 'hopharbor-package.json').write_text(json.dumps({'name': 'HopHarbor', 'version': VERSION, 'build': BUILD, 'architecture': arch}, indent=2) + '\n')
        # The portable archive also exposes a native, icon-bearing launcher.
        manifest = {p.relative_to(stage).as_posix(): sha256(p) for p in sorted(stage.rglob('*')) if p.is_file()}
        (stage / 'PACKAGE-SHA256.json').write_text(json.dumps(manifest, indent=2) + '\n')
        # Check both UTF-8 and Windows UTF-16 string pools for a leaked build path.
        private_needles = [str(Path.home()).encode(), str(ROOT).encode(), str(Path.home()).encode('utf-16le'), str(ROOT).encode('utf-16le')]
        for path in stage.rglob('*'):
            if path.is_file() and any(needle in path.read_bytes() for needle in private_needles):
                raise ValueError('A build file contains a private local path: ' + path.relative_to(stage).as_posix())
        archive = output_dir / ('HopHarbor-%s-windows-%s-portable.zip' % (VERSION, arch))
        make_zip(stage, archive)
        # ISCC consumes a separate, reviewed staging folder. Retain it only when
        # requested; it contains public payloads, never configuration/runtime.
        if iscc:
            subprocess.run([str(iscc), '/DPackageRoot=' + str(stage), '/DAppVersion=' + VERSION,
                '/DAppBuild=' + str(BUILD), '/DTargetArch=' + arch, '/DOutputDir=' + str(output_dir),
                str(ROOT / 'packaging/windows/HopHarbor.iss')], check=True, timeout=600)
    result = {'version': VERSION, 'build': BUILD, 'architecture': arch,
              'portable_zip': archive.name, 'sha256': sha256(archive), 'files': len(manifest) + 1}
    (output_dir / ('HopHarbor-%s-windows-%s-build.json' % (VERSION, arch))).write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=tuple(ARCHITECTURES), required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--cache-dir', type=Path, required=True, help='Private cache/build directory outside tracked source.')
    parser.add_argument('--dotnet', type=Path, required=True)
    parser.add_argument('--helper-output', type=Path, help='Previously published matching native helper directory.')
    parser.add_argument('--desktop-output', type=Path, help='Previously published matching desktop directory.')
    parser.add_argument('--iscc', type=Path, help='Optional official Inno Setup 7 ISCC.exe, run only on Windows.')
    args = parser.parse_args()
    if args.iscc and sys.platform != 'win32':
        parser.error('Compile the installer only on Windows; portable packages can be built on macOS.')
    print(json.dumps(build(args.arch, args.output_dir, args.dotnet, args.cache_dir,
                           args.helper_output, args.desktop_output, args.iscc)))


if __name__ == '__main__':
    main()
