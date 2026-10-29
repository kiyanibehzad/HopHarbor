# HopHarbor 1.3.2 · build 12

One shared app version, source tree and release tag, **v1.3.2**, for macOS,
Ubuntu and the **Windows preview**. Previous releases and downloads are preserved.

## Changes

Native panels recover local sign-in after browser-cookie expiry or server-session
invalidation by rereading their protected control file and opening a fresh page.
Recovery does not restart the background controller or forwarding connections.
Automatic recovery is bounded; manual Retry remains available. HTTP 403 does not
trigger automatic sign-in, failed mutations are never replayed, and tokens are not
stored in page storage or recovery messages. Host/Origin/CSRF checks are unchanged.
Native frame protections prevent child documents from gaining recovery privileges
through a parent's bridge or the actual shared JavaScript helper.

## Downloads and installation

All application payloads use **1.3.2 / build 12**; platform/CPU names identify files.
The release contains two Ubuntu DEBs, Windows x64 and ARM64 Setup/portable pairs,
a reviewed source ZIP and `HopHarbor-1.3.2-SHA256SUMS.txt` covering all seven files.

- **Ubuntu 26.04 LTS:** download `hopharbor_1.3.2_amd64.deb` for Intel/AMD or
  `hopharbor_1.3.2_arm64.deb` for ARM. Run `sudo apt install ./<downloaded-file>`
  and open HopHarbor from Applications. Package installation preserves settings
  and does not restart a running controller; schedule any user-service restart
  when reconnecting existing clients is acceptable. The technical Ubuntu guide's
  older filename examples refer to previous packages; use these 1.3.2 filenames.
- **Windows preview:** run the matching `HopHarbor-1.3.2-windows-<arch>-setup.exe`
  as your ordinary user, then open HopHarbor from Start. OpenSSH Client and
  Microsoft Edge WebView2 Runtime must already be installed. Installers are
  unsigned; both Setup engines are x64 and the ARM64 Setup contains ARM64 app
  payloads. See [Windows installation](../packaging/windows/README.md).
- **macOS 13+ / Apple Silicon:** reviewed source only; see [source installation](../README.md#macos).
  No installed Mac app archive is published. This release process did not deploy
  the source update or restart the installed Mac app/backend.

## Validation and limits

The final integrated source suite ran **265 tests, all passed, none skipped** on
macOS, with the separate local GOST fixture and .NET 10 policy runner enabled.
It includes 28 compiled Swift policy assertions, 37 compiled Windows policy
assertions and 14 shared JavaScript transport/behavior cases.

- **macOS:** 13 actual AppDelegate/WKWebView checks and a normal arm64 launcher
  compile passed. Direct child, parent native bridge and actual parent helper
  cases were stopped before child page requests or script execution. This uses
  synthetic faults; it does not establish the original user incident's trigger.
- **Ubuntu 26.04.1 arm64 / WebKitGTK 2.52.6:** 19 actual native recovery checks
  passed from source and again from the installed final arm64 DEB; direct, parent
  bridge and actual helper attempts were tested through four frame-creation
  methods. Eleven forwarding, eleven credential/key/Secret Service and seven UI
  regressions, package/service/launcher lifecycle and source-byte audits passed.
  The amd64 DEB was built and inspected, not run natively. Full GNOME/Wayland tray
  visibility, physical suspend and graphical-login keyring behavior are unverified.
- **Windows preview / Windows 10 Pro 22H2 x64:** 13 native recovery cases, 10
  security boundary checks, 12 production lifecycle checks including 10 packaged
  panel assertions, 19 end-to-end forwarding checks and five actual x64
  installer/uninstaller checks passed. The private test assembly is separate from
  shipped binaries; the final production payload displayed build 12 and recovered
  a missing cookie without restarting its controller. Native Windows 11, ARM64
  execution/installation, SSH agent, physical sleep, real OS network/logon/RDP
  transitions, signing and reputation remain unverified.

**Windows protocol deadline limitation:** the unchanged grouped protocol suite
has **19 passes and one failed 2 MiB stream case**, reaching its original
four-second deadline in three candidate runs. The same suite and failure were
reproduced against the previous published 1.3.0 preview. Forwarding code and Python
runtime bytes are identical; the controller differs only in version/build metadata.
Separate diagnostics received the exact 2,097,165 bytes and EOF in 3.05 seconds
isolated and 3.66 seconds in a full-suite diagnostic using an explicit 30-second
read deadline. These diagnostics do **not** turn the original failures into passes.
This is accepted as a documented pre-existing preview timing/environment limitation;
no production timeout, forwarding implementation or authoritative test was changed.

Cookie expiry was shortened deterministically rather than waiting 12 hours.
Renderer coverage differs by platform: Ubuntu and Windows used actual isolated
renderer termination; macOS used a controlled native termination callback.
Physical sleep and uninterrupted proxy service during sleep are not claimed.

Reviewed assets contain no personal Sessions, credentials, keys, diagnostic reports
or real-session screenshots. Source archives contain only tracked reviewed files.
See the detailed [macOS](macos-panel-recovery.md), [Ubuntu](ubuntu-panel-recovery.md)
and [Windows](windows-panel-recovery.md) recovery records.
