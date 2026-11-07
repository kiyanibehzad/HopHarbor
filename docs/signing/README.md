# Windows signing readiness and experimental builds

Status: **unsigned build trial authorized; SignPath not accepted or configured** (7 November 2026).
The published Windows 1.4.2/build 15 packages remain unsigned Preview artifacts.
No SignPath sponsorship, certificate issuance or signed release is claimed.
The manual [experimental unsigned workflow](../../.github/workflows/windows-unsigned-candidate.yml)
is enabled for review evidence. Its first run is tracked on the
[Actions page](https://github.com/kiyanibehzad/HopHarbor/actions/workflows/windows-unsigned-candidate.yml);
only a completed successful run supplies CI evidence. The signing workflow
retains its literal false guard and cannot run signing jobs.

## Proposed trust boundary

Use a reviewed source commit on the public main branch, a fresh GitHub-hosted
Windows runner, pinned action revisions and a new build directory for each
architecture. Never feed previously downloaded releases, local build outputs,
self-hosted runner artifacts or pull-request artifacts into the signing path.
The dispatch commit must equal the workflow's own GitHub SHA. The signing workflow retains a literal false job guard. The experimental
unsigned workflow is manual-only and cannot sign or publish a release.

The separate `windows-unsigned-candidate.yml` supplies the proposed prerequisite
CI trial without any SignPath account, certificate, secret or environment.
It builds both unsigned ZIP/Setup architectures and records source, manifest,
tool/dependency verification and output hashes. It is manual-only and enabled for the authorized trial. It does not prove
native ARM64 runtime qualification or signing acceptance.

The GitHub token is read-only. A future protected `signpath-release` environment
holds a submitter-only SignPath token; it cannot approve its own requests. Human
approval in SignPath remains required for each request, independently of GitHub
environment approval. GitHub MFA is enabled per maintainer self-report, not independently audited.
SignPath membership and protection settings remain unconfigured.

Only the explicit project PE allowlist is submitted. Vendor CPython, .NET and
WebView2 files retain their upstream bytes and signatures. Generated .NET hosts,
the bundled helper and Inno-generated installer/uninstaller require Foundation
confirmation before their inclusion is approved. No recursive `*.exe`/`*.dll`
signing rule is acceptable.

## Proposed build and signing sequence

1. Freshly build each portable payload using the reviewed builder and pinned SDK,
   Python, WebView2 and Inno inputs. Record the exact source commit and inputs.
2. Extract and validate the unsigned package. Submit only the three allowlisted
   project PEs as a GitHub workflow artifact, using that upload's artifact ID.
3. After manual approval, verify Windows trust, timestamp, exact approved leaf
   certificate SHA-256 and content binding. Preserve every vendor file; regenerate
   the package manifest and portable ZIP after signed bytes are installed.
4. Run Inno's opt-in signed-uninstaller first pass. Treat the expected unsigned
   cache handoff separately from other compiler failures. Sign the generated
   uninstaller through a second artifact-ID request and restore its cache name.
5. Repeat the same Inno command with the verified signed cache. Submit the outer
   installer through a third artifact-ID request. Verify it before final output.
6. Retain source/build/request IDs, certificate chain, timestamp evidence, file
   inventory, third-party byte comparison and final checksums for review. No
   release-upload step is included. Native install/upgrade/uninstall validation
   remains a subsequent authorized task.

This is origin-verifiable build preparation, **not proof of bit-for-bit
reproducibility**. Hosted runner images and SDK acquisition can change; NuGet
runtime inputs need a reviewed lock/inventory check. Signatures and timestamps
also change final bytes. Any mismatch must fail rather than relax validation.

## Before activating signing

- Obtain Foundation eligibility and generated-binary classification decisions.
- Establish sufficient reputation evidence; project age and two stars are not
  an endorsement or assurance of acceptance.
- Clarify the privacy/installer clause applicability described in [privacy policy](privacy-policy.md).
- Confirm real authors/reviewers/approvers and their MFA status. AI tools are not
  independent signing approvers.
- The published [Code signing policy](code-signing-policy.md) and
  [privacy policy](privacy-policy.md) describe unsigned/pending status. An active
  sponsorship acknowledgment belongs only after acceptance.
- Configure the GitHub/SignPath integration, repository scope, artifact XML,
  metadata parameters, manual signing policies, public certificate fingerprint
  and timestamp behavior. All identifiers in the workflow must be confirmed.
- Review the unsigned trial evidence, then test future signed candidates and
  assign a new shared version/build for any eventual app update. Preserve all
  existing tags/assets; never retrofit signatures into old downloads.

## References

- [Foundation conditions](https://signpath.org/terms.html)
- [Application](https://signpath.org/apply.html)
- [GitHub trusted builds](https://docs.signpath.io/trusted-build-systems/github)
- [Artifact configuration](https://docs.signpath.io/artifact-configuration/)
- [Inno signed uninstaller](https://jrsoftware.org/ishelp/topic_setup_signeduninstaller.htm)
- [GitHub workflow security](https://docs.github.com/en/actions/reference/security/secure-use)
