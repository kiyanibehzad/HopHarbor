# Native Windows 11 ARM64 validation — HopHarbor 1.3.2/build 12

On **29 October 2026**, the exact published ARM64 portable ZIP and Setup were
validated in a **Windows 11 Pro 24H2 ARM64 VM, build 26100.7840**. Windows remains
**Preview**. These results describe this environment and artifact set; they do
not establish blanket Windows support or change the historical Windows 10 results.

## Exact published artifacts

The app release remains [v1.3.2](https://github.com/kiyanibehzad/HopHarbor/releases/tag/v1.3.2),
source commit `413f268cbd4c471160657dd6c9e6fe003e0eab3f`.
No product source or published binaries were changed or rebuilt for these tests.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| [ARM64 portable ZIP](https://github.com/kiyanibehzad/HopHarbor/releases/download/v1.3.2/HopHarbor-1.3.2-windows-arm64-portable.zip) | 97336946 | `65704744f56d329f802520f788e80605b407d44151938f47079e0f3d371fccf3` |
| [ARM64 Setup](https://github.com/kiyanibehzad/HopHarbor/releases/download/v1.3.2/HopHarbor-1.3.2-windows-arm64-setup.exe) | 71774813 | `fbf8a3529ae449637db22887f3b1ae5def0528af4e24378335200a59a3624c0c` |

The 336-file payload manifest and installed payload matched; the actual installer
adds two Inno uninstall files. Use the existing [shared checksum file](https://github.com/kiyanibehzad/HopHarbor/releases/download/v1.3.2/HopHarbor-1.3.2-SHA256SUMS.txt).

## Native product and emulated test components

Desktop, native helper/controller, embedded Python 3.14.9, OpenSSH 9.5p2, curl 8.16.0
and WebView2 ran with ARM64 images. The self-contained .NET runtime was 10.0.14;
WebView2 Runtime was 156.0.4314.50 (SDK 1.0.4314.35). Image architecture, paths,
hashes and observed processes were checked; an API result of `process_machine=0`
alone was not used as proof of native execution.

The **Inno Setup/uninstaller engines are x64 and ran under emulation**. A separate
synthetic loopback SSH server used pinned x64 Python/AsyncSSH/cryptography under
emulation; the product's SSH client, controller and forwarding frontend were ARM64.
The recovery fault-injection fixture used a private ARM64 test DLL built from the
same release source. It is distinct from the shipped DLL; production lifecycle and
actual installer checks used the exact published product payload.

## Results

| Check group | Passed | Failed |
| --- | ---: | ---: |
| Original protocol suite, unchanged deadlines | 20 | 0 |
| Native file/ACL/credential/Job security boundaries | 10 | 0 |
| Actual WebView2 recovery, frame, renderer and lifecycle faults | 13 | 0 |
| Production lifecycle, including 10 packaged panel assertions | 12 | 0 |
| End-to-end forwarding | 19 | 0 |
| Actual Setup/install/uninstall | 5 | 0 |

Recovery covered actual cookie expiry, server-side invalidation, bounded automatic
attempts and manual Retry, no automatic 403 recovery, no failed-mutation replay,
child/parent bridge and actual helper attempts, stale source/view checks, hide and
rapid reopen, actual renderer failure, cleared fragments and no secret storage.

Forwarding used generated loopback SSH/TLS fixtures: independent password and
encrypted-key hops, strict host keys, rejected secrets, SOCKS/HTTP/fixed TCP,
private-CA TLS with a signed CRL, pools/outage recovery, bounded logs and owned
cleanup. Installation verified exact payload bytes, private ACLs, per-user
registration, controller health, panel/service independence and actual uninstall
with settings preservation. A rollback snapshot was retained; test installation,
data and processes were removed, the temporary host transfer was stopped and the
VM was left running. Personal credentials and the host's live service were untouched.

An additional synthetic **2 MiB + 13 bytes** transfer received all **2,097,165 bytes
and EOF in 0.4706 seconds**, with the original **four-second read bound** unchanged.
This is a loopback test measurement, not a real Internet-speed gain. The original
Windows 10 x64 grouped suite's 19-pass/one-failure result remains historical and
failed, including its reproduction on the previous published preview. The later
ARM64 result does not turn those earlier failures into passes; see [the historical
protocol deadline record](windows-panel-recovery.md#historical-windows-10-x64-transfer-timing-limitation).

## Remaining limits and documentation status

Native Windows 11 **x64** was not newly tested; Windows 10 Pro 22H2 x64 remains
compatibility evidence. Physical sleep/resume, real OS network/logon/logout/RDP
transitions, the 12-hour cookie wait, SSH-agent integration, signing/SmartScreen/
reputation and clean unprovisioned-machine prerequisites remain unverified.
A synthetic wake-handler test does not establish physical suspend behavior.

Only documentation and repository/release descriptions are updated after these
tests. The app version/build, release title/status, v1.3.2 tag/commit and all asset
bytes/identifiers/checksums remain unchanged. The release source ZIP and fixed tag
retain their publication-time documentation; the main branch records this later
validation. Private reports, machine paths and session captures are not published.
