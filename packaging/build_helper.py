#!/usr/bin/python3
"""Compile the narrowly scoped macOS Keychain helper without handling secrets."""
from pathlib import Path
import argparse
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    target = args.output.resolve() if args.output else source.parent / "bin" / "keychain-helper"
    target.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        "/usr/bin/xcrun", "swiftc", "-swift-version", "5", "-O",
        "-target", "arm64-apple-macosx13.0", "-framework", "Security", "-framework", "LocalAuthentication",
        str(source / "keychain_helper.swift"), "-o", str(target),
    ], check=True)
    target.chmod(0o700)
    subprocess.run([
        "/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime",
        "--identifier", "local.hopharbor.keychain", str(target),
    ], check=True)
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(target)], check=True)
    askpass = target.parent / "ssh-askpass"
    shutil.copyfile(source / "ssh-askpass.sh", askpass)
    askpass.chmod(0o700)
    print(target)


if __name__ == "__main__":
    main()
