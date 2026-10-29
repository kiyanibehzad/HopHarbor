# Windows preview: installation, usage and builds

This Windows implementation is under validation. The ARM64 preview requires
Windows 11; the x64 preview permits Windows 10 22H2 (build 19045) and Windows 11.
Every platform uses one shared HopHarbor version and build.

## Download and install

**HopHarbor 1.3.2 · build 12 — Windows preview** is available in the [shared release](https://github.com/kiyanibehzad/HopHarbor/releases/tag/v1.3.2). The exact published ARM64 ZIP and Setup have native Windows 11 Pro 24H2 ARM64 VM validation; Windows 10 x64 compatibility evidence is also recorded. See [ARM64 validation](../../docs/windows-arm64-validation-1.3.2.md) and [recovery and historical timing limits](../../docs/windows-panel-recovery.md).

| Computer | Installer |
| --- | --- |
| Intel / AMD x64 | [Download x64 Setup](https://github.com/kiyanibehzad/HopHarbor/releases/download/v1.3.2/HopHarbor-1.3.2-windows-x64-setup.exe) |
| Windows 11 ARM64 | [Download ARM64 Setup — Windows 11 ARM64 tested](https://github.com/kiyanibehzad/HopHarbor/releases/download/v1.3.2/HopHarbor-1.3.2-windows-arm64-setup.exe) |

[Portable ZIPs](https://github.com/kiyanibehzad/HopHarbor/releases/tag/v1.3.2) and [SHA-256 checksums](https://github.com/kiyanibehzad/HopHarbor/releases/download/v1.3.2/HopHarbor-1.3.2-SHA256SUMS.txt) are also available. Run Setup as your ordinary signed-in user, choose the optional sign-in/desktop shortcuts, and open **HopHarbor** from Start. The installers are unsigned. Both setup engines are x64; the ARM64 installer contains the native ARM64 app payload and targets Windows 11 ARM64.

Native Windows 11 Pro 24H2 ARM64 (build 26100.7840) checks passed for the exact
published 1.3.2/build 12 files: 20 protocol, 10 security, 13 recovery, 12 production
lifecycle, 19 forwarding and five actual install/uninstall checks. Desktop,
helper/controller, Python, OpenSSH and WebView2 were ARM64. Inno Setup/uninstall
engines and a separate synthetic SSH test server used x64 emulation. Native
Windows 11 x64, physical sleep, real OS network/logon/RDP transitions, SSH-agent
integration and signing/reputation remain unverified. Windows remains Preview;
these VM results do not establish blanket Windows support.

The prior Windows 10 x64 grouped 2 MiB/four-second failure remains historical and
failed; the ARM64 run passed the unchanged 20-case suite. Its additional synthetic
transfer took about 0.47 seconds with the same four-second bound, not a real
Internet-speed measurement. [Detailed ARM64 record](../../docs/windows-arm64-validation-1.3.2.md).

The desktop panel uses WinForms and Microsoft Edge WebView2. The independent
background controller uses the Windows OpenSSH **Client**, embedded CPython and
HopHarbor's own Windows proxy frontend. Credentials use Windows Credential Manager. No SSH Server, inbound firewall
rule, administrator service or WSL distribution is required.

## Installation layout

The first Windows version uses the fixed per-user application directory
`%LOCALAPPDATA%\Programs\HopHarbor`. Settings and bounded logs live separately in
`%LOCALAPPDATA%\HopHarbor`, protected with Windows ACLs. The installer runs without
administrator privileges. A portable ZIP must also be extracted so that
`ui\HopHarbor.exe` is inside that application directory; arbitrary portable paths
are not yet supported. Do not extract over a running installation.

Install OpenSSH Client using Windows Optional features if it is absent. Install
the [official Microsoft WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/)
if the panel reports it missing. HopHarbor never installs either system component
automatically.

Closing the window hides it in the system tray and releases the WebView. Reopening
authenticates again to the local service. **Quit Panel** exits only the panel;
connections keep running independently. The optional sign-in launcher starts the
panel in the system tray and supervises the background controller. Upgrades and
uninstallation stop only their matching application/data scope. Uninstalling
preserves settings and saved credentials.

Add a Session in the panel, then enter its password or private-key passphrase
there. These secrets are stored in the signed-in user's Windows Credential
Manager, separately for each Session. Key files remain in a user-selected
location. The app does not import another computer's sessions or credentials.
SSH agent authentication uses that user's existing agent and is not enabled or
reconfigured automatically. Firewall / SOCKS jump connections retain separate
Session credentials.

If the panel cannot connect, use **Reload Panel** in the tray, verify that
OpenSSH Client and WebView2 are available, and inspect the recent per-Session
logs in the panel. Restarting the panel does not restart working connections.
After sleep or a network change, the controller checks connectivity and retries
temporary failures automatically. Authentication failures require correcting
the Session credentials before reconnecting.

## Reproducible inputs

`packaging/build_windows.py` pins the .NET SDK, WebView2 NuGet package and embedded
Python archives. Downloaded Python archives are verified by SHA-256 before use;
the WebView2 SDK package has a pinned SHA-512 checksum.
Use official .NET SDK 10.0.403 and Inno Setup 7.1.0. Keep build caches, downloaded
archives and outputs outside tracked source. The builder copies an explicit
application allowlist, rejects links/traversal paths, strips PDBs and scans the
payload for private build paths. Each ZIP includes dependency provenance and a
file checksum manifest. It does not include configuration, credentials or
diagnostics.

Windows packages include `windows_proxy.py` from the reviewed application
allowlist and do not download, require or ship an external proxy frontend
executable. The controller starts it using the bundled native Python with `-B`
and `--config` pointing at a private descriptor. That descriptor contains only
the forwarding ID/type, the local listening port and one to four local SSH
backend ports; listeners and backend connections are fixed to `127.0.0.1`.
The child remains in the controller's owned Windows Job.

SOCKS5 CONNECT, HTTP proxy/HTTPS CONNECT and local TCP forwarding carry TCP
traffic. The Windows HTTP frontend handles one plain HTTP request per client
connection and replies with `Connection: close`; ordinary browser clients open
a new connection for the next request. HTTPS CONNECT and SOCKS/TCP connections
remain opaque streams. UDP, TLS interception and bonding several SSH sessions
into one faster TCP stream are not provided. macOS and Ubuntu retain their
existing frontend implementation.

Build each architecture using `python3 packaging/build_windows.py --arch arm64`
(or `x64`) with explicit `--output-dir`, `--cache-dir` and `--dotnet` paths. Run
`--help` for arguments. A Windows build host can also supply `--iscc ISCC.exe` to
compile the per-user installer from the same reviewed staging payload. macOS can
cross-publish the portable payload; the installer compiler runs on Windows.

For a separately compiled installer, extract the reviewed ZIP and invoke
`ISCC.exe` on `packaging/windows/HopHarbor.iss` with `PackageRoot`, `OutputDir`,
`TargetArch`, `AppVersion` and `AppBuild` preprocessor values. `PackageRoot` is the
extracted `HopHarbor` directory. Never point it at a live installed application.

## Isolated desktop smoke test

Run the installed native launcher with `--smoke-test --data-dir` followed by a
fresh absolute folder under the current user's temporary directory named
`HopHarbor-Smoke-*`. The test refuses a non-empty session/forward configuration.
It checks authentication, cleared bootstrap fragments, the Session editor,
System/Light/Dark appearance, tray/hide/reopen behavior and navigation boundaries,
then exits the panel. Synthetic results and a screenshot are stored in that
private test folder. The separate background controller remains running and
should be checked, then stopped using `install_windows.py --stop` with the exact
test `--app-dir` and `--data-dir` before removing fixtures.

Native ARM64 tests on Windows 11 ARM do not establish native x64 performance.
Installer, credentials, forwarding, multi-hop, sleep/reconnect and ownership/ACL
checks must pass on the actual target before release claims are made.

Windows 10 Pro 22H2 is an additional compatibility test target. It does not replace
Windows 11 validation. Microsoft's current [.NET 10 support matrix](https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.md)
lists specific Windows 10 Enterprise/LTSC releases, and does not list Pro 22H2.
Passing compatibility checks on that machine will be recorded separately from a
supported-platform release claim. WebView2 and Python 3.14 document Windows 10
compatibility. The panel content and tray retain System/Light/Dark appearance;
the native titlebar follows the Windows 10 default because its documented dark
titlebar attribute requires Windows 11.

## Historical 1.3.0/build 10 evidence

The following describes that earlier preview only; current 1.3.2 ARM64 results are
[recorded separately](../../docs/windows-arm64-validation-1.3.2.md).

Recorded evidence for the 1.3.0 build 10 preview: 250 host
unit tests pass. Native Windows 10 x64 checks pass for private ACLs, separate
credentials, process ownership, all 20 frontend protocol cases, 12 copied-payload
lifecycle cases including nine WebView2 assertions, and 19 end-to-end forwarding
cases. These include two-hop OpenSSH, SOCKS/HTTP/TCP, verified HTTPS with a signed
fixture CRL, pool failure/outage recovery, deterministic wake-handler recovery,
bounded logs and authenticated cleanup. Both Inno setup files compile and pass independent checksum/version/privacy
checks. The actual x64 per-user install, controller launch and uninstall pass
five native checks, including installed payload/ACL verification and owned
cleanup. See [the validation record](../../docs/windows-testing.md).
At that earlier validation point, this was compatibility evidence; native Windows
11/ARM64, physical sleep and signing/reputation were unverified. The later ARM64
testing above does not rewrite the earlier test outcomes.
