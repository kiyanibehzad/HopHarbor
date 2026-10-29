# Windows validation records

Current 1.3.2/build 12 evidence includes [native Windows 11 ARM64 validation](windows-arm64-validation-1.3.2.md) of the exact published ZIP and Setup, alongside [Windows 10 x64 recovery validation and its historical protocol deadline failure](windows-panel-recovery.md). Windows remains Preview; the later ARM64 results do not replace the historical outcomes below.

## Historical 1.3.0/build 10 candidate validation

Windows preview: **1.3.0, build 10**. Evidence recorded 28–29 October 2026.
The local macOS installation and its active connections were kept separate.

## Evidence completed

- 250 host unit tests pass, including shared controller regressions, package
  scope, credentials/process boundaries, protocol framing and version agreement.
- Native x64 Windows 10 Pro 22H2 compatibility checks pass: 10 ACL/ownership/lock
  cases and five independent credential/process cases. They cover Unicode
  credentials, separate secrets, askpass limits, rejected prompts and owned
  descendant cleanup after controller exit.
- All 20 Windows frontend protocol tests pass under native CPython 3.14.9.
  They include CONNECT, SOCKS/TCP relay, framing, bounded admission, failover,
  idle opaque connections and cancellation before modern asyncio server closure.
- Twelve native x64 copied-payload lifecycle checks pass, including nine real
  WebView2 assertions: authentication, Session editor, appearance, tray,
  hide/reopen, navigation boundaries and recovery after a controller port change.
  Independent supervisor launch, duplicate adoption, scope rejection, optional
  sign-in registration, stop/restart and unregister also pass.
- All 19 native end-to-end forwarding checks pass with generated loopback
  fixtures. Two-hop OpenSSH uses independent password and encrypted-key
  credentials. Unknown/incorrect host keys and wrong secrets fail closed;
  corrected credentials clear old errors. SOCKS and ordinary HTTP requests,
  HTTPS through SOCKS and HTTP CONNECT, and fixed TCP forwarding pass.
- The Windows system curl client verifies the private TLS certificate and
  retrieves the fixture's signed CRL. Certificate and revocation checking remain
  enabled; system trust is unchanged. A failed SSH pool member reconnects while
  healthy members carry traffic, and every pool recovers after an upstream
  listener outage. The deterministic wake-handler exercise replaces SSH
  transports, preserves frontend processes and clears old errors. Recovery plus
  the follow-up HTTPS request took 5.31 seconds in this one loopback run; this
  was not physical sleep or a production speed benchmark.
- Native bounded-log and plaintext-secret exclusion checks pass. Authenticated
  shutdown releases owned jobs, listeners and locks; synthetic credentials and
  disposable fixture data were removed successfully.
- Both architecture ZIPs have reviewed manifests and official dependency
  provenance. Payloads contain no user sessions, keys, settings or diagnostics.
  Windows uses the project frontend; macOS and Ubuntu retain their existing one.

- Both Inno Setup installers compile successfully, with independently checked
  SHA-256, native setup-engine architecture and version resource 1.3.0.10.
  Both 336-file payload manifests and their compressed input checksums match.
  Reviewed payloads, setup files and redacted build logs pass private-path scans.
- Five actual native x64 installer checks pass: a fresh per-user installation,
  exact installed payload hashes and private ACLs (338 files including Inno's
  two uninstall files), Start Menu target and matching user registration, default
  controller health at 1.3.0 build 10, and the real uninstaller. Uninstallation
  removes the matching app/shortcut/registration and stops its jobs while
  preserving settings. The empty fixture settings were then removed only after
  service/lock and configuration checks. No saved credentials were deleted.

## Remaining gates at the historical 1.3.0 validation point

Native Windows 11 and ARM64, SSH agent authentication, physical sleep/network
changes, and login/logout or RDP-session transitions remain unverified. A loopback listener outage and an explicit call
to the wake handler do not establish actual operating-system event detection.
Cross-built ARM64 binaries are not evidence of native ARM64 behavior. No
signing/reputation or public Windows release claim is made by these results.

Tests use generated loopback-only SSH/HTTP/TLS fixtures and disposable user
scopes. Private reports and machine details stay outside the public checkout.
