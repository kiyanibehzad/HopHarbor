#!/usr/bin/python3
"""Build the local panel launcher using Apple's installed command-line tools."""
from pathlib import Path
import argparse
import plistlib
import shutil
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser()
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--output", type=Path)
    target.add_argument("--archive-only", type=Path)
    parser.add_argument("--data-dir", type=Path)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    app = args.output.resolve() if args.output else source / "build" / "HopHarbor.app"
    with (source / "Info.plist").open("rb") as handle:
        info = plistlib.load(handle)
    if args.data_dir:
        info["HopHarborDataDirectory"] = str(args.data_dir.expanduser().resolve())
    # Stage outside File Provider so Finder cannot attach metadata mid-signing.
    with tempfile.TemporaryDirectory(prefix="proxy-manager-build-") as scratch:
        staged_app = Path(scratch) / "HopHarbor.app"
        contents = staged_app / "Contents"
        binary = contents / "MacOS" / "HopHarbor"
        binary.parent.mkdir(parents=True)
        (contents / "Resources").mkdir()
        icon = source / "assets" / "HopHarbor.icns"
        if not icon.is_file():
            raise RuntimeError("HopHarbor app icon is missing from packaging/assets")
        shutil.copyfile(icon, contents / "Resources" / "HopHarbor.icns")
        with (contents / "Info.plist").open("wb") as handle:
            plistlib.dump(info, handle)
        subprocess.run([
            "/usr/bin/xcrun", "swiftc", "-swift-version", "5", "-parse-as-library", "-O",
            "-target", "arm64-apple-macosx13.0", "-framework", "AppKit",
            "-framework", "WebKit", str(source / "PanelRecovery.swift"),
            str(source / "main.swift"), "-o", str(binary),
        ], check=True)
        subprocess.run([
            "/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime",
            "--identifier", info["CFBundleIdentifier"], str(staged_app),
        ], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(staged_app)], check=True)
        if args.archive_only:
            archive = args.archive_only.resolve()
            archive.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as package:
                package.write(staged_app, staged_app.name)
                for item in sorted(staged_app.rglob("*")):
                    package.write(item, str(item.relative_to(staged_app.parent)))
            with zipfile.ZipFile(archive) as package:
                if package.testzip() is not None:
                    raise RuntimeError("Built archive failed its integrity check")
            print(archive)
            return
        app.parent.mkdir(parents=True, exist_ok=True)
        if app.exists():
            with (app / "Contents" / "Info.plist").open("rb") as handle:
                existing = plistlib.load(handle)
            if existing.get("CFBundleIdentifier") != info["CFBundleIdentifier"]:
                raise RuntimeError("Refusing to replace an unrelated app bundle")
            shutil.rmtree(app)
        shutil.copytree(staged_app, app, copy_function=shutil.copyfile)
        (app / "Contents" / "MacOS" / "HopHarbor").chmod(0o755)
    # Metadata can be attached to the destination bundle as it is created.
    for attribute in ("com.apple.FinderInfo", "com.apple.ResourceFork"):
        subprocess.run(["/usr/bin/xattr", "-r", "-d", attribute, str(app)], capture_output=True)
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], check=True)
    print(app)


if __name__ == "__main__":
    main()
