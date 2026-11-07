# Experimental unsigned Windows CI validation

On **7 November 2026**, [manual run 42362741736](https://github.com/kiyanibehzad/HopHarbor/actions/runs/42362741736)
completed successfully for **ARM64 and x64** on GitHub-hosted `windows-2025`
x64 runners. ARM64 is cross-built. These are experimental unsigned build
outputs retaining 1.4.2/build 15 metadata; existing release downloads are
unchanged. No SignPath certificate, request, acceptance or signed release is
implied. The signing workflow remains locked by its literal false guard.

## Exact source and jobs

- Commit: [`c12afc5c1aaacde093ad57c118c04b7179c07fdc`](https://github.com/kiyanibehzad/HopHarbor/commit/c12afc5c1aaacde093ad57c118c04b7179c07fdc)
- Tree: `9b36bf386ab7728b759f5571bc0581e349338ba9`
- [ARM64 job 128374341878](https://github.com/kiyanibehzad/HopHarbor/actions/runs/42362741736/job/128374341878): success
- [x64 job 128374342063](https://github.com/kiyanibehzad/HopHarbor/actions/runs/42362741736/job/128374342063): success

Both jobs verified the pinned official SDK/Inno archives before use, used
reviewed NuGet runtime/host/WebView2 archives and retained tool verification
receipts. Checkout preserves Git blob bytes. Host and targeting packs restore
from NuGet through an empty SDK pack lookup root; .NET 10 pruning metadata
continues to use the verified SDK. Missing data and digest errors still fail.

## Downloaded artifact audit

Both actual GitHub artifact ZIPs were downloaded and independently compared
with their server digests. Each envelope contains eight allowlisted files:
portable ZIP, Setup, builder report, dependency receipt, SDK receipt, Inno
receipt, build provenance and final checksums. Each portable ZIP has **340 files**;
all **339 manifest entries** matched. All 22 packaged source/license/notice
inputs match the exact Git blobs. Project PE outputs and Setup are unsigned.
The four target dependency archives in each job match reviewed provenance.
The Windows owner independently verified all 305 upstream PE files in each
package byte-for-byte against the published 1.4.2 package. All three project
PE resources report ProductName `HopHarbor`, ProductVersion `1.4.2` and
FileVersion `1.4.2.15`; actual resource-directory parsing was used, including
the helper with its embedded runtime. Setup is an unsigned x64 engine with
version `1.4.2.15`.

| GitHub artifact | Envelope bytes | Envelope SHA-256 |
| --- | ---: | --- |
| [ARM64 · 13570660369](https://github.com/kiyanibehzad/HopHarbor/actions/runs/42362741736/artifacts/13570660369) | 167552828 | `6046231c8a5bbe11934fdc778a4088e446bd53569308233126519a85535c2b14` |
| [x64 · 13570119451](https://github.com/kiyanibehzad/HopHarbor/actions/runs/42362741736/artifacts/13570119451) | 177581710 | `331728ed87fe091ad0c81057d8ee5fcfec14b31fb1638ef9189e517b199a607e` |

Artifacts have **14-day retention**, expiring 21 November 2026, and GitHub may
require sign-in to download. The run and pinned workflow provide origin context;
a locally re-uploaded file or a hash alone is not a substitute for SignPath's
trusted-build integration.

| Experimental file | Bytes | SHA-256 |
| --- | ---: | --- |
| `HopHarbor-1.4.2-windows-arm64-portable.zip` | 97365384 | `451c496c03218afe6d1eadd7e9875ed251b0f5f46153a03589b772d91437e628` |
| `HopHarbor-1.4.2-windows-arm64-setup.exe` | 71796891 | `b52d43ea08f1db08fdeed9b7e7e5f34e1a9a6268b50448a4d6ac6700a08c7825` |
| `HopHarbor-1.4.2-windows-x64-portable.zip` | 101463227 | `0334f088e20b117e8f7a0eca666a174bb41c63ca080984257cdc94024ce2d348` |
| `HopHarbor-1.4.2-windows-x64-setup.exe` | 77653244 | `ea0d30d0dba52c109eb92d06244715e1a7f7fffbc9f75e7abd4895e0abec610d` |

## Scope and retained failed attempts

This verifies hosted compilation, package structure, source correspondence and
provenance. It does not establish native ARM64 application execution, new native
Windows x64 install/runtime qualification, bit-for-bit reproducibility, Windows
trust/reputation, signing or Foundation eligibility. No test certificate or
root was installed. No existing release, tag, asset or current Mac installation
was changed. Local focused provenance/boundary checks also passed.

Earlier attempts remain visible: initial push validation records
[42361966210](https://github.com/kiyanibehzad/HopHarbor/actions/runs/42361966210)
and [42361966968](https://github.com/kiyanibehzad/HopHarbor/actions/runs/42361966968)
ran zero jobs because of an invalid runner-context location. The signing job
never executed. [42362046383](https://github.com/kiyanibehzad/HopHarbor/actions/runs/42362046383)
found a same-architecture SDK-host/cache provenance gap and checkout line-ending
changes; its ARM artifact is diagnostic, not the accepted final source-byte
evidence. [42362553062](https://github.com/kiyanibehzad/HopHarbor/actions/runs/42362553062)
then exposed .NET 10 pruning metadata lookup. Those failures were corrected
without suppressing digest, source-byte or SDK data checks. Only the successful
final run above is accepted for this build trial.

[Code signing policy](code-signing-policy.md) · [Privacy policy](privacy-policy.md)
