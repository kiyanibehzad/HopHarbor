#!/usr/bin/python3
"""Compile the narrowly scoped macOS Keychain helper without handling secrets."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile


def input_fingerprint(source):
    """Include every input that changes the signed helper, including build flags."""
    digest = hashlib.sha256()
    for name in ("keychain_helper.swift", "build_helper.py"):
        data = (source / name).read_bytes()
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(str(len(data)).encode("ascii") + b"\0")
        digest.update(data)
    return digest.hexdigest()


def binary_sha256(target):
    return hashlib.sha256(target.read_bytes()).hexdigest()


def provenance_path(target):
    return target.with_name(target.name + ".provenance.json")


def private_owned_file(path):
    try:
        info = path.lstat()
        return (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and not info.st_mode & 0o077)
    except OSError:
        return False


def signature_valid(target):
    return subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", str(target)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


def can_reuse(target, source):
    """Preserve an unchanged ad-hoc signature and its existing Keychain ACL."""
    marker = provenance_path(target)
    if not private_owned_file(target) or not private_owned_file(marker):
        return False
    try:
        if marker.stat().st_size > 4096:
            return False
        saved = json.loads(marker.read_text(encoding="utf-8"))
        return (saved.get("schema") == 1
                and saved.get("source_sha256") == input_fingerprint(source)
                and saved.get("binary_sha256") == binary_sha256(target)
                and signature_valid(target))
    except (OSError, ValueError, TypeError, AttributeError):
        return False


def write_provenance(target, source):
    """Record a verified private helper; callers must establish source provenance."""
    if not private_owned_file(target) or not signature_valid(target):
        raise RuntimeError("Refusing to record an unverified or non-private helper")
    record = {"schema": 1, "source_sha256": input_fingerprint(source),
              "binary_sha256": binary_sha256(target)}
    marker = provenance_path(target)
    descriptor, temporary = tempfile.mkstemp(prefix=".helper-provenance-", dir=str(target.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(record, stream, indent=2)
            stream.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, marker)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    target = args.output.resolve() if args.output else source.parent / "bin" / "keychain-helper"
    target.parent.mkdir(parents=True, exist_ok=True)
    if can_reuse(target, source):
        print("Reusing the unchanged, verified Keychain helper.")
    else:
        # Build separately so a failed compiler or signature leaves the old helper intact.
        with tempfile.TemporaryDirectory(prefix=".helper-build-", dir=str(target.parent)) as temporary:
            built = Path(temporary) / "keychain-helper"
            subprocess.run([
                "/usr/bin/xcrun", "swiftc", "-swift-version", "5", "-O",
                "-target", "arm64-apple-macosx13.0", "-framework", "Security", "-framework", "LocalAuthentication",
                str(source / "keychain_helper.swift"), "-o", str(built),
            ], check=True)
            built.chmod(0o700)
            subprocess.run([
                "/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime",
                "--identifier", "local.hopharbor.keychain", str(built),
            ], check=True)
            subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(built)], check=True)
            os.replace(built, target)
        write_provenance(target, source)
    askpass = target.parent / "ssh-askpass"
    shutil.copyfile(source / "ssh-askpass.sh", askpass)
    askpass.chmod(0o700)
    print(target)


if __name__ == "__main__":
    main()
