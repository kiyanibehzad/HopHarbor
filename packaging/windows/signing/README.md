# Windows signing preparation

This is a **dormant candidate**, not an enabled signing service or a signed
release. Existing 1.4.2/build 15 downloads remain immutable. Do not run this
against historical downloads and present the result as a new trusted build.
Use a later approved release version, provider acceptance, public source,
reviewed workflow and approved public certificate fingerprint first.

## Ownership and licenses

| Component | Handling |
| --- | --- |
| `bin/HopHarborHelper.exe` | Project single-file application; contains the generated .NET host and bundled unmodified runtime. Sign the outer application only after Foundation accepts this classification. |
| `ui/HopHarbor.exe` | Generated application host for this project; requires the same provider classification review. |
| `ui/HopHarbor.dll` | Project-managed assembly, eligible signing target subject to acceptance. |
| `runtime/**`, other `ui/**` binaries | Upstream CPython, .NET, WindowsDesktop and WebView2 components; preserve every byte, including upstream signatures. Never select with `*.exe` or `*.dll` signing globs. |
| Inno generated uninstaller and final Setup | Project-specific installer outputs containing upstream engine code; ask Foundation to accept these outputs. Never sign the stock compiler, loader or runtime engine directly. |

HopHarbor is MIT. CPython's full combined license travels as `runtime/LICENSE.txt`;
its bundled dependencies retain their own notices. .NET/WindowsDesktop/apphost
packs are MIT with upstream notices. The pinned WebView2 **SDK** archive's
committed `vendor/windows/WEBVIEW2-LICENSE.txt` is Microsoft BSD-style
source/binary redistribution text, not an MIT license or the separate browser
Runtime EULA. Preserve all recorded notices. The externally installed browser
Runtime and Windows OpenSSH are prerequisites, not payloads built or signed here.
Provider review must confirm the SDK loader/control licensing and the external
Runtime treatment; this document does not decide Foundation eligibility.

Inno Setup 7.1.0's [upstream license](https://github.com/jrsoftware/issrc/blob/is-7_1_0/license.txt)
permits distribution subject to retaining its existing copyright/website notices
and identifying modifications. The compiler is a build tool; generated setup
and uninstall engines remain upstream-derived. Do not strip their notices.
[Dependency provenance](../../../vendor/windows/provenance.json) records the
seven runtime/SDK package archives and notice hashes across both architectures.

The reviewed 1.4.2 archives each contain 308 PE images: three unsigned project
outputs and 305 upstream images with embedded certificate tables. That structural
observation does **not** certify current chain validity or timestamp trust.

## Trust boundary and verification

[SignPath's artifact reference](https://docs.signpath.io/artifact-configuration/reference)
supports ZIP containers and PE Authenticode, but does not expose Inno as a deep
container. The three XML candidates therefore select only explicit project
paths, then the generated uninstaller and outer Setup in separate requests.
Each configuration requires `productVersion` and `fileVersion`, with product
name `HopHarbor` and SHA-256 signing. Project and outer Setup use file version
`<app-version>.<build>`; the uninstaller retains engine file version
**51.1055.0.0**, as pinned by Inno 7.1.0's
[Setup version resource](https://github.com/jrsoftware/issrc/blob/is-7_1_0/Projects/Res/Setup.version.rc).
Its product version is still the app version. Do not patch the engine file
version: Inno's second pass checks its content. XML syntax is locally parsed; service-side
schema validation and acceptance remain required.

Every returned file is compared with its unsigned input, allowing only the PE
checksum/security-directory fields, alignment padding and appended certificate
table to change. This includes the helper's bundle and Setup overlay. This check
is additional to Windows trust verification, not a replacement for it.
`verify-signature.ps1` requires valid Authenticode, a timestamp, exact product
metadata and the out-of-band approved **SHA-256 leaf certificate** fingerprint.
It then runs authenticated Microsoft SDK `signtool verify /pa /all /v /tw` and
rejects failures/warnings. It never imports roots, creates certificates, changes
execution policy or disables revocation/TLS/OS protections. Configure the
provider's trusted timestamp policy; certificate rotation requires a reviewed
fingerprint update. A matching subject name alone is insufficient.

Only the three project files change during payload merge. A fresh
`PACKAGE-SHA256.json` covers their **signed bytes**, and the portable archive is
created afterwards. The uninstaller is generated next, signed, reinserted using
Inno's cache, and finally the outer installer is signed. Final download checksums
must be calculated after every signing step. Do not refresh the manifest earlier
or insert the compiler cache or reports into the application payload.

## CI contract

[GitHub trusted-build integration](https://docs.signpath.io/trusted-build-systems/github)
requires workflow artifacts and provider-verified origin. For the OSS service,
all preceding workflow jobs must use GitHub-hosted runners. A locally built ZIP,
a source hash written into JSON or an artifact re-upload does not establish this
origin. Keep every stage in the reviewed workflow and retain original artifact
IDs, signing-request IDs, source commit, compiler inputs and final hashes.

Build fresh with the existing builder **without** `--helper-output`,
`--desktop-output` or `--iscc`. Verify the exact .NET SDK distribution and Inno
installer before executing either. Verify resolved architecture-specific NuGet
archives against committed provenance before submitting anything. The old
builder pins SDK/Python/WebView2 and normalizes ZIP timestamps, but pins only
WebView2's restored archive directly; a resolved-pack check is additionally
required for the .NET/WindowsDesktop archives. There is no committed NuGet lock
file or demonstrated byte-identical two-run build. Do not call this a reproducible
build proof. Authenticode timestamps intentionally change signed output bytes.

From repository root on the future Windows CI runner, with fresh paths outside
the checkout (`$job`, `$cache`, `$buildOut`, `$signedProject`, `$signedUninstaller`,
`$signedInstaller`) and verified tools (`$dotnet`, `$iscc`, `$signtool`):

```powershell
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
python packaging/build_windows.py --arch $arch --output-dir $buildOut --cache-dir $cache --dotnet $dotnet
# Run the workflow's resolved dependency verification before proceeding.
python packaging/windows/signing/pipeline.py prepare --unsigned-zip "$buildOut/HopHarbor-$version-windows-$arch-portable.zip" --arch $arch --work-dir $job --source-commit $sourceCommit
# Upload $job/project-request as a DIRECTORY. The artifact ZIP root is bin/ and ui/.
# SignPath: project-pe.xml; parameters productVersion=$version, fileVersion="$version.$build".
python packaging/windows/signing/pipeline.py apply --work-dir $job --signed-dir $signedProject --certificate-sha256 $certificateSha256 --signtool $signtool

$cacheUninstall = "$job/uninstaller-cache"
New-Item -ItemType Directory $cacheUninstall -ErrorAction Stop
$compileArgs = @('--no-ide-signtools', "/DPackageRoot=$job/signed-payload", "/DOutputDir=$job/unsigned-setup", "/DAppVersion=$version", "/DAppBuild=$build", "/DTargetArch=$arch", "/DSignedUninstallerCache=$cacheUninstall", 'packaging/windows/HopHarbor.iss')
# Capture native exit code even with PowerShell native-error promotion enabled.
$PSNativeCommandUseErrorActionPreference = $false
& $iscc @compileArgs 2>&1 | Tee-Object -FilePath "$job/first-compile.log"
$firstExit = $LASTEXITCODE
$PSNativeCommandUseErrorActionPreference = $true
python packaging/windows/signing/pipeline.py capture-uninstaller --work-dir $job --cache-dir $cacheUninstall --compiler-log "$job/first-compile.log" --compiler-exit-code $firstExit
# Upload $job/uninstaller-request; sign uninstaller.xml: productVersion=$version, fileVersion="51.1055.0.0".
python packaging/windows/signing/pipeline.py apply-uninstaller --work-dir $job --signed-dir $signedUninstaller --certificate-sha256 $certificateSha256 --signtool $signtool
& $iscc @compileArgs
if ($LASTEXITCODE -ne 0) { throw 'Second compile failed' }
python packaging/windows/signing/pipeline.py capture-installer --work-dir $job --installer "$job/unsigned-setup/HopHarbor-$version-windows-$arch-setup.exe"
# Upload $job/installer-request directory; sign installer.xml with the same metadata parameters.
python packaging/windows/signing/pipeline.py apply-installer --work-dir $job --signed-dir $signedInstaller --certificate-sha256 $certificateSha256 --signtool $signtool
```

Every Python command must stop the workflow on a nonzero exit. The workflow must
validate `ISCC --version` as 7.1.0 after checking the pinned official installer.
Use fresh uninstaller caches per matrix job; do not share caches across releases.
The first compile must fail with exit 2 at the documented signature-needed
boundary and produce exactly `uninst-7.1.0-<10hex>.e64`. Other failures are fatal.
The upload copy is named `uninstaller.exe`; its returned signed bytes replace
only the recorded original cache file. Inno verifies content compatibility on
the second compile. Both architectures use the x64 Inno engine.

[Inno's signed-uninstaller mechanism](https://jrsoftware.org/ishelp/topic_setup_signeduninstaller.htm)
also handles temporary self-copies. [Signing only the outer EXE](https://jrsoftware.org/ishelp/topic_setup_signtool.htm)
does not cover those copies. Never suppress Inno signature checks or use a
blanket signing flag on the payload. A later approved Windows test must verify
installed `unins000.exe`, its `.msg` companion, real install/upgrade/uninstall
and both architectures' signatures; historical unsigned installation file
counts are not an assertion about this candidate.

## Remaining gates

- Foundation acceptance of project, licenses and generated composite outputs;
  approved team roles/MFA/manual signing approval, project/configuration/policy IDs.
- Explicit privacy disclosure and any required consent/opt-out design: the
  application checks GitHub for releases, and external WebView2 uses Microsoft
  diagnostics/crash reporting/SmartScreen behavior. The panel currently sets
  only `--no-proxy-server`, not privacy opt-outs. Do not weaken SmartScreen or
  other security controls to meet a privacy requirement.
- Reviewed public source/workflow, pinned tools and actual GitHub trusted-build
  submission. No account, application, API request or workflow has been run here.
- Service XML acceptance, actual certificate/timestamp validation, two-pass Inno
  execution and narrowly scoped native signed-package qualification. Existing
  1.4.2 ARM64 evidence is reused for unchanged runtime behavior; it is not evidence
  of a completed signed build. Windows remains Preview, with no fresh x64 run.

Offline checks: `python -m unittest discover -s packaging/windows/signing -p 'test_*.py' -v`.
Synthetic certificate bytes exercise content boundaries only, never certificate trust.
