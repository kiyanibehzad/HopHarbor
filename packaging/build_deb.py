#!/usr/bin/python3
"""Build a reviewed Ubuntu amd64/arm64 package without installing or starting it."""
import argparse
import ast
import gzip
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import install_linux


def version():
    for node in ast.parse((ROOT / 'manager.py').read_text()).body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'VERSION' for target in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError('No source version was found.')


def write_file(root, relative, content, mode=0o644):
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    target.chmod(mode)


def compressed_tar(root):
    """Stable owner, timestamp and relative paths; no build-machine metadata."""
    memory = io.BytesIO()
    with gzip.GzipFile(fileobj=memory, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(root.rglob('*')):
                if path.is_symlink():
                    raise ValueError('Unexpected symlink in package staging.')
                info = archive.gettarinfo(str(path), arcname='./' + str(path.relative_to(root)))
                info.uid = info.gid = 0
                info.uname = info.gname = 'root'
                info.mtime = 0
                info.pax_headers = {}
                # Directory traversal must not inherit the builder's private umask.
                if info.isdir():
                    info.mode = 0o755
                if info.isfile():
                    with path.open('rb') as handle:
                        archive.addfile(info, handle)
                else:
                    archive.addfile(info)
    return memory.getvalue()


def ar_member(name, data):
    if len(name) > 15:
        raise ValueError('Invalid ar member name.')
    header = ('%-16s%-12s%-6s%-6s%-8s%-10s`\n' % (name + '/', 0, 0, 0, '100644', len(data))).encode('ascii')
    return header + data + (b'\n' if len(data) % 2 else b'')


def build(arch, output, gost_archive=None):
    if arch not in install_linux.GOST_SHA256:
        raise ValueError('Choose amd64 or arm64.')
    release = version()
    with tempfile.TemporaryDirectory(prefix='hopharbor-deb-') as temporary:
        stage = Path(temporary)
        provenance = install_linux.fetch_gost(stage / 'gost', arch, gost_archive)
        data = stage / 'data'
        data.mkdir()
        app = data / 'usr/lib/hopharbor'
        install_linux.copy_app(app, stage / 'gost', provenance, public=True)
        command = '/usr/bin/python3 /usr/lib/hopharbor/install_linux.py --launch'
        write_file(data, 'usr/bin/hopharbor', '#!/bin/sh\nexec /usr/bin/python3 /usr/lib/hopharbor/install_linux.py --launch "$@"\n', 0o755)
        write_file(data, 'usr/share/applications/' + install_linux.DESKTOP_FILE, install_linux.desktop_text(command))
        write_file(data, 'etc/xdg/autostart/' + install_linux.DESKTOP_FILE, install_linux.desktop_text(command, background=True))
        write_file(data, 'usr/lib/systemd/user/' + install_linux.SERVICE, install_linux.service_text())
        for name, relative in [('HopHarbor.svg', 'scalable/apps/hopharbor.svg'),
                               ('hopharbor-symbolic.svg', 'symbolic/apps/hopharbor-symbolic.svg')]:
            source = app / 'assets' / name
            if source.is_file():
                write_file(data, 'usr/share/icons/hicolor/' + relative, source.read_text())
        notices = (ROOT / 'LICENSE').read_text() + '\n\n' + (ROOT / 'THIRD-PARTY-NOTICES.md').read_text()
        write_file(data, 'usr/share/doc/hopharbor/copyright', notices)
        write_file(data, 'usr/share/doc/hopharbor/README.md', (ROOT / 'docs/ubuntu.md').read_text())
        write_file(data, 'usr/share/doc/hopharbor/ubuntu-testing.md', (ROOT / 'docs/ubuntu-testing.md').read_text())
        control = stage / 'control'
        control.mkdir()
        installed_kib = sum(item.stat().st_size for item in data.rglob('*') if item.is_file()) // 1024 + 1
        write_file(control, 'control', '''Package: hopharbor
Version: %s
Section: net
Priority: optional
Architecture: %s
Maintainer: HopHarbor contributors <noreply@github.com>
Homepage: https://github.com/kiyanibehzad/HopHarbor
Depends: %s
Installed-Size: %d
Description: Local SSH SOCKS and HTTP proxy manager
 HopHarbor manages native OpenSSH forwarding, Session chains and pools,
 with a local desktop panel, Secret Service credential storage and bounded logs.
 The user background service is started when the desktop application opens.
''' % (release, arch, ', '.join(install_linux.DEPENDENCIES), installed_kib))
        # No maintainer scripts: package installation never starts/stops a user's tunnels.
        contents = b'!<arch>\n' + ar_member('debian-binary', b'2.0\n')
        contents += ar_member('control.tar.gz', compressed_tar(control))
        contents += ar_member('data.tar.gz', compressed_tar(data))
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary_output = output.with_name(output.name + '.tmp')
        temporary_output.write_bytes(contents)
        temporary_output.chmod(0o644)
        os.replace(temporary_output, output)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--gost-archive', type=Path,
                        help='Offline archive; its bytes must pass the pinned official digest.')
    args = parser.parse_args()
    print(build(args.arch, args.output, args.gost_archive))


if __name__ == '__main__':
    main()
