# macOS source testing prerelease — 1.4.1 / build 14

This is the **macOS-only** user-testing prerelease `v1.4.1-preview.1`, for **Apple Silicon / arm64, macOS 13 or later**. It builds the normal HopHarbor app from reviewed public source. It is not Latest stable. Ubuntu and Windows downloads remain **1.3.2 / build 12**; their source metadata in this ref does not mean a 1.4.1 package has been released or tested there.

[Prerelease and source downloads](https://github.com/kiyanibehzad/HopHarbor/releases/tag/v1.4.1-preview.1) · [Changes and validation scope](release-1.4.1.md) · [Stable 1.3.2](https://github.com/kiyanibehzad/HopHarbor/releases/tag/v1.3.2)

## Before installing

Use your ordinary macOS account. Python 3.9 or later, Git, and Apple Xcode Command Line Tools with Swift are required. The installer uses `/usr/bin/python3` and `/usr/bin/xcrun`; if needed, complete `xcode-select --install` first. Intel Macs are not supported.

An upgrade replaces `~/Applications/HopHarbor.app` and the per-user background service. The installer stops existing connections; `--no-start` also stops the old service before replacing files. If your Internet access depends on HopHarbor, establish and verify an independent working connection first and preserve a private backup of the old app, runtime payload, LaunchAgent and data. The installer has no automatic rollback. Do not export or publish your credentials or private settings.

## Build from the exact prerelease ref

```sh
git clone --branch v1.4.1-preview.1 --depth 1 https://github.com/kiyanibehzad/HopHarbor.git HopHarbor-1.4.1-preview.1
cd HopHarbor-1.4.1-preview.1
/usr/bin/python3 install.py
open "$HOME/Applications/HopHarbor.app"
```

Review the source before running the installer. It downloads checksum-pinned GOST 3.3.1, builds the native panel and Keychain helper, and installs the per-user controller. Existing local settings and Keychain entries are retained. Fresh installs start with empty settings. The local app is ad-hoc signed; no notarized Mac binary is supplied.

## Or use the checked source archive

Download both files into one empty directory:

- [HopHarbor-1.4.1-preview.1-macos-source.zip](https://github.com/kiyanibehzad/HopHarbor/releases/download/v1.4.1-preview.1/HopHarbor-1.4.1-preview.1-macos-source.zip)
- [HopHarbor-1.4.1-preview.1-SHA256SUMS.txt](https://github.com/kiyanibehzad/HopHarbor/releases/download/v1.4.1-preview.1/HopHarbor-1.4.1-preview.1-SHA256SUMS.txt)

Then verify and extract:

```sh
shasum -a 256 -c HopHarbor-1.4.1-preview.1-SHA256SUMS.txt
ditto -x -k HopHarbor-1.4.1-preview.1-macos-source.zip .
cd HopHarbor-1.4.1-preview.1
/usr/bin/python3 install.py
open "$HOME/Applications/HopHarbor.app"
```

The archive contains only tracked, reviewed public source, tests and project resources. It contains no installed bundle, Preview harness, Sessions, credentials, keys or real-session screenshots. Native compilation needs the complete extracted tree, including `packaging/PanelRecovery.swift` and the three new shared runtime modules; copying only `manager.py` is insufficient.

## During the test cycle

Try the features relevant to your own use: standalone SSH Sessions, Firewall chains and forwarding, Connect All / Reconnect All, strict endpoint continuity, safe configuration Import/Export and Undo, appearance, and quiet update notices. Imported entries stay disconnected with autostart disabled; credentials, local key paths and host trust are not imported. Reconnect All preserves deliberately stopped entries. Release checking only notifies about newer stable releases; it never downloads or installs updates and does not promote this prerelease automatically.

When reporting a problem, include app version/build and a short description. Remove hosts, usernames, keys, tokens and other personal details from logs or screenshots. Keep a private rollback available during this test period. Stable downloads and previous release history are unchanged.
