# macOS source release — 1.4.2 / build 15

This is the **macOS-only** source release `v1.4.2`, for **Apple Silicon / arm64, macOS 13 or later**. Ubuntu and Windows downloads remain **1.3.2 / build 12** with their existing validation and support scope. Shared version metadata in this source does not imply a released or tested 1.4.2 package for those platforms.

[Release and source downloads](https://github.com/kiyanibehzad/HopHarbor/releases/tag/v1.4.2) · [Changes and validation scope](release-1.4.2.md)

## Before installing

Use your ordinary macOS account. Python 3.9 or later, Git, and Apple Xcode Command Line Tools with Swift are required. The installer uses `/usr/bin/python3` and `/usr/bin/xcrun`; if needed, complete `xcode-select --install` first. Intel Macs are not supported.

An upgrade replaces `~/Applications/HopHarbor.app` and the per-user background service. The installer stops existing connections; `--no-start` also stops the old service before replacing files. If your Internet access depends on HopHarbor, establish and verify an independent working connection first and preserve a private backup of the old app, runtime payload, LaunchAgent and data. The installer has no automatic rollback. Do not export or publish your credentials or private settings.

## Build from the exact release ref

```sh
git clone --branch v1.4.2 --depth 1 https://github.com/kiyanibehzad/HopHarbor.git HopHarbor-1.4.2
cd HopHarbor-1.4.2
/usr/bin/python3 install.py
open "$HOME/Applications/HopHarbor.app"
```

Review the source before running the installer. It downloads checksum-pinned GOST 3.3.1, builds the native panel and Keychain helper, and installs the per-user controller. Existing local settings and Keychain entries are retained. Fresh installs start with empty settings. The local app is ad-hoc signed; no notarized Mac binary is supplied.

## Or use the checked source archive

Download both files into one empty directory:

- [HopHarbor-1.4.2-macos-source.zip](https://github.com/kiyanibehzad/HopHarbor/releases/download/v1.4.2/HopHarbor-1.4.2-macos-source.zip)
- [HopHarbor-1.4.2-SHA256SUMS.txt](https://github.com/kiyanibehzad/HopHarbor/releases/download/v1.4.2/HopHarbor-1.4.2-SHA256SUMS.txt)

Then verify and extract:

```sh
shasum -a 256 -c HopHarbor-1.4.2-SHA256SUMS.txt
ditto -x -k HopHarbor-1.4.2-macos-source.zip .
cd HopHarbor-1.4.2
/usr/bin/python3 install.py
open "$HOME/Applications/HopHarbor.app"
```

The archive contains only tracked, reviewed public source, tests and project resources. It contains no installed bundle, Preview harness, Sessions, credentials, keys or real-session screenshots. Native compilation needs the complete extracted tree, including `packaging/PanelRecovery.swift` and the three new shared runtime modules; copying only `manager.py` is insufficient.

## Using this version

Search Sessions by name, address, user or Firewall. Filter Sessions by status and role, or Port Forwarding by type, Session and status. Options within a facet combine with OR; different facets and the search query combine with AND. Clearing filters keeps the search query. Bulk actions apply to the whole selected tab, including entries hidden by filters.

Disconnect All asks for confirmation. Port Forwarding stops all forwards; Sessions also stops standalone SSH connections. Deliberately stopped entries remain stopped during automatic retry and wake recovery. Reconnect All preserves deliberately stopped entries.

Click a Session's color strip to choose its color. Existing saved and manual colors are retained. Firewall in use opens dependency details; the connection icon continues to show actual connection status.

Tools provides configuration Import/Export and Undo. Imported entries stay disconnected with autostart disabled; credentials, local key paths and host trust are not imported. Release checking only notifies about newer stable releases; it never downloads or installs updates.

When reporting a problem, include app version/build and a short description. Remove hosts, usernames, keys, tokens and other personal details from logs or screenshots.
