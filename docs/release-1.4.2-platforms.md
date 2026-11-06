# HopHarbor 1.4.2 · build 15 — Ubuntu and Windows update

Ubuntu and Windows now provide the features from the Mac 1.4.2 cycle with their native file and process handling. All platforms use the app name **HopHarbor**, version **1.4.2**, build **15**. Windows remains **Preview**.

## Source and preserved Mac release

The original `v1.4.2` tag, Mac source ZIP and Mac checksum file are unchanged. GitHub's automatic Source code ZIP/tar archives still represent that original Mac snapshot; they do not contain the later native platform fixes.

For Ubuntu and Windows builds, use **HopHarbor-1.4.2-platforms-source.zip** and its checksum record from the [1.4.2 release](https://github.com/kiyanibehzad/HopHarbor/releases/tag/v1.4.2), or the frozen `platforms-source-1.4.2` branch. Verify HEAD against the exact **Platform Source** commit/tree listed on that release. The version-specific branch will not advance. The release's platform provenance record identifies artifact hashes and the reviewed source inputs.

The installed Mac app and its connections were not upgraded again during this phase. Earlier releases, tags and assets remain available.

## Features and native changes

- Standalone SSH Sessions and Firewall chains, including strict endpoint verification against the previously trusted host key and successful authentication.
- Connect All, Reconnect All and confirmed Disconnect All. Queued starts are cancelled, intentionally stopped connections stay stopped, and termination uses shared deadlines with ownership retained on failure.
- Tools Import/Export and Undo, using native Open/Save dialogs. Portable exports omit credentials, local key paths, host trust and control tokens. Imported connections stay disconnected and require any missing local credentials or trust to be configured separately.
- Session search, independent tab filters, persistent colors and the compact Session/Firewall interface from the Mac release. Filters do not silently narrow bulk-action scope.
- Advisory stable-release checks and narrowly allowed official release links. Checks do not download or install updates.

Ubuntu's GTK bridge accepts bounded portable exports from the current owned panel, writes selected files atomically with mode 0600 and returns only fixed outcome statuses. Child-frame and stale-document restrictions remain enforced.

Windows uses the current owned OpenSSH process's post-authentication local hook instead of unsupported Unix control sockets. A fresh private nonce is bound to each child generation; a process or banner alone cannot establish readiness. No remote command, shell permission or extra proxy listener is required. Native Windows Job ownership, private directory/file ACLs, cancellation and endpoint-proof cleanup are retained. Native Save As writes only to the selected destination; generic downloads remain blocked.

## Validation and limits

| Platform | New native execution | Other architecture |
| --- | --- | --- |
| Ubuntu 26.04.1 LTS | arm64 VM, Python 3.14, real GTK/WebKit under Xvfb | amd64 DEB built and structurally inspected; no native amd64 execution |
| Windows Preview | Windows 11 Pro 25H2 ARM64 VM, build 26200.9711, ordinary user token | x64 ZIP/Setup built and inspected; no fresh native x64 runtime qualification |

The integrated host and actual Ubuntu Python 3.14 suites completed **314 tests: 312 passed, 2 optional tests skipped** on each host. The optional cases differ by available platform tools: the Mac host lacks the local GOST integration fixture and compiled Windows policy tool; Ubuntu lacks the Mac Swift and compiled Windows policy fixtures. Windows separately ran its compiled recovery/file policy checks with 59 assertions.

Ubuntu passed 13 native feature, 20 authentication/lifecycle and 7 desktop checks against source and an installed arm64 candidate; 11 forwarding and 11 credential checks; real Session/endpoint checks with Ed25519 and RSA; and nine package/source upgrade checks from 1.3.2. The final shared runtime also passed the full Ubuntu suite, both real Session/endpoint suites, installed version/API/private-permission checks and all 14 source-byte matches. A final docs-only package rebuild changed the bundled test record and its generated Installed-Size, with all runtime, binary and service files unchanged. [Ubuntu evidence and limits](ubuntu-testing.md).

Windows passed 20 protocol, 10 native security, 13 actual WebView2 recovery, 11 production lifecycle, 25 real OpenSSH/forwarding and five fresh install/uninstall checks. A real 1.3.2-to-1.4.2 upgrade preserved the synthetic Session and Credential Manager secret; native Save As, private file ACL, import preview, merge/Undo and cleanup were exercised. Product ARM64 execution was checked using PE images and observed processes. The separate fixture Python and Inno compiler/installer used x64 emulation. [Windows evidence and limits](windows-arm64-validation-1.4.2.md).

Physical sleep, real OS network/logon transitions, a new long-duration soak and an elapsed 24-hour release interval were not established by these tests. Controlled clocks and explicit recovery calls do not substitute for those observations. Earlier Windows 10 x64 protocol failures remain recorded in the [historical recovery evidence](windows-panel-recovery.md). Native VM results do not establish Internet-speed measurements or blanket platform support.

## Downloads

- Ubuntu: [installation guide](ubuntu.md) and **HopHarbor-Ubuntu-1.4.2-SHA256SUMS.txt**.
- Windows: [Setup/portable guide](../packaging/windows/README.md) and **HopHarbor-Windows-1.4.2-SHA256SUMS.txt**.
- Mac: the original [1.4.2 source guide](macos-1.4.2.md) and **HopHarbor-1.4.2-SHA256SUMS.txt** remain unchanged.

Verify the matching checksum record before installing. No archive includes personal Sessions, credentials, keys, private diagnostics or real-session screenshots. An update can interrupt its own connections; schedule it appropriately and retain a private backup. No installer was run on the live Mac during this platform phase.
