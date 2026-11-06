# Windows ARM64 preview validation — 1.4.2, build 15

Recorded 6 November 2026. Windows remains **Preview**. This record covers the
1.4.2 ARM64 payload and installer below on Windows 11 Pro 25H2 ARM64,
build 26200.9711, in a VM. The final native runs used an ordinary user token
(`TokenElevation=0`, `TokenElevationType=3`), including installation and removal.
The live macOS installation and connections were not changed.

## Artifact identity and source

| Artifact | SHA-256 |
| --- | --- |
| ARM64 portable ZIP | `04cb169479f196f34d26ac9b2228e128499c9d503b005d02d850bce389f86471` |
| ARM64 Setup | `261df47b4396737b0f46e1e868bdff790707bfe2be67479ed4f78aaee5aabd4b` |
| x64 portable ZIP | `2fc5d2f76dd85caf27b36c50d1107efb3274d6f6052903bbddc1bccf1f813381` |
| x64 Setup | `50a5af45a8a201171c712d51df462a0d5295c74324479fe2bf28ba82f0db7885` |

Each portable archive has 340 files, with complete checksum manifests, matching
1.4.2/build 15 metadata and pinned dependency provenance. The actual ARM64
installation has 342 files including the two Inno uninstall files. Both Setup
files were compiled with the pinned official Inno Setup 7.1.0 compiler;
version resources are 1.4.2.15. Input manifests, executable architectures and
private-path scans passed before compilation and export.

Use the supplementary platform source archive or the frozen
`platforms-source-1.4.2` branch. Verify its exact commit and tree against
**Platform Source** in the [shared 1.4.2 release](https://github.com/kiyanibehzad/HopHarbor/releases/tag/v1.4.2).
The unchanged original `v1.4.2` tag and automatic GitHub Source code archives
contain the original Mac source, without these later platform fixes.
See the [Windows build guide](../packaging/windows/README.md#reproducible-inputs).

## Native evidence

- All 20 protocol checks passed, including the unchanged grouped 2 MiB stream
  deadline, opaque idle channels, framing, admission bounds and shutdown.
- Ten native security checks passed: private ACLs, lock exclusion, rejection of
  public files/hardlinks/junctions, separate Credential Manager secrets, Unicode
  askpass, invalid prompts and secrets, and owned Job descendant cleanup.
- Thirteen actual WebView2 recovery checks passed against the production
  Manager/Handler: authentication expiration, explicit Retry, recovery budget,
  stale/foreign/frame messages, hide/reopen races, renderer failure and no
  replay of failed mutations. Control identity remained unchanged.
- Eleven production lifecycle checks passed, including ten actual UI assertions,
  independent supervisor/controller launch, duplicate adoption, wrong-scope
  rejection, optional user sign-in registration, stop/restart and clean removal.
- Twenty-five real OpenSSH and forwarding checks passed. These cover Session-only
  password authentication; nested encrypted-key authentication; fresh proof
  after reconnect; endpoint continuity proof; rejection of a bad target after
  a successful jump; rejection of the wrong host key; owned transport cleanup;
  SOCKS, HTTP, HTTPS and TCP; pool survival; upstream outage; bounded logs and
  authenticated shutdown. TLS certificate and CRL validation remained enabled.
- The Session proof was tested with an application path containing spaces,
  Persian characters, an ampersand and a literal percent-delimited name. Private
  marker ownership is explicit, and a live process or banner is insufficient
  to mark a Session connected. Preliminary ownership and quoting failures were
  fixed and the full native workflow passed with the rebuilt payload.
- Five actual installer checks passed: fresh per-user installation, exact
  installed payload/ACLs, matching HKCU records and Start Menu target, controller
  health at 1.4.2/build 15, and real uninstall with settings preservation.
  Empty fixture settings were removed only after service/lock verification.

- Actual upgrade from the checksum-verified published ARM64 1.3.2/build 12
  installer to 1.4.2/build 15 retained the synthetic Session identity and its
  Credential Manager secret. Color export, nonmutating import preview, stopped
  merge and Undo passed; imported entries did not acquire credentials.
- The production native Save As dialog was opened, cancelled and then used to
  save a real configuration file. The file was valid, secret-free and had a
  private user ACL. The native import picker was cancelled and reopened; its
  selected synthetic JSON showed the expected one-Session preview and warnings
  about disconnected imports, credentials, host trust and omitted key paths.
  Cancelling that preview left the original Session unchanged.
- Final removal deleted the known synthetic credential and Session, stopped the
  owned processes, uninstalled the exact test installation and verified removal
  of its registry records, shortcut and empty private data. The private cleanup
  harness needed a JSON DELETE body and resumed-run initialization fixes;
  those fixture errors are retained in the evidence and did not change product
  files or invalidate the completed upgrade and file-dialog observations.

## Architecture and limits

Product Python 3.14.9, the controller/helper/desktop and system OpenSSH
9.5p2 (LibreSSL 3.8.2) used ARM64 binaries. The private synthetic SSH server
used a separate x64 Python/dependency set under emulation. Inno's compiler,
Setup and uninstall engines also used x64 emulation. PE image architecture was
recorded: the guest's `platform.machine()`/process-machine reports alone do not
reliably distinguish these emulated processes.

The x64 artifacts were built, inspected and compiled, but this update was not
run on a native Windows x64 machine. Historical x64 evidence is not fresh
1.4.2 qualification. Physical sleep, real OS network/logon/RDP transitions,
SSH-agent integration, long-duration sessions, clean prerequisite installation,
code signing and SmartScreen reputation remain unverified. The wake test calls
the production recovery handler; it is not a physical sleep test.

The earlier Windows 10 x64 grouped-stream deadline failure remains historical
and failed. See [Windows recovery history](windows-panel-recovery.md) and
[1.3.2 ARM64 evidence](windows-arm64-validation-1.3.2.md). Passing this ARM64 VM
run does not establish blanket Windows support or real-network performance.
