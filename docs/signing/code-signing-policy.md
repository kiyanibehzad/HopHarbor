# Code signing policy

**Windows releases are unsigned. SignPath onboarding and signing are pending.**
HopHarbor has not been accepted into the SignPath Foundation program. Current
Windows downloads remain unsigned Preview builds.

## Maintainer and proposed signing responsibilities

| Role | Proposed accountable person | Status |
| --- | --- | --- |
| Author / maintainer | Behzad Kiyani (`kiyanibehzad`) | Public repository owner/maintainer |
| Reviewer | Behzad Kiyani; future additional reviewer must be named | Current sole-maintainer model; no independent reviewer claimed |
| Signing approver | Behzad Kiyani | Proposed future role for final onboarding review; SignPath assignment absent |
| CI submitter | Future project-scoped SignPath CI identity | Not created; may submit only, cannot approve |

Outside contributions must be reviewed before merge. Changes to build scripts,
workflow, dependency pins, artifact configuration and this policy require review
before a signing request is approved. The approver checks the commit, build
origin, tests, dependency inventory and exact files requested, and records the
decision. Any future release signing request requires human approval; passing a job
does not grant approval. GitHub MFA for `kiyanibehzad` is enabled per maintainer self-report; it has not
been independently audited. Future SignPath members must also use MFA; no
SignPath account or signing integration is configured.

## Signing scope

Only HopHarbor-owned code built from the reviewed public repository is proposed
for signing, subject to Foundation approval of generated hosts and installers.
Upstream dependencies must not receive the project certificate. The configured
file allowlist and ProductName `HopHarbor`, product/file version restrictions
must be enforced. A public leaf-certificate fingerprint independently confirmed
by the maintainer binds verification; a matching publisher name alone is not
sufficient. Valid trust chains and timestamp verification are required.

Verified signed outputs receive fresh manifests/checksums. They are tested and
reviewed before any separately authorized publication. Already published tags,
asset bytes and checksums are immutable. A signature does not establish absence
of defects, eliminate all Windows reputation prompts or expand platform support.

## Privacy and provider identity

See [privacy policy](privacy-policy.md) for actual network behavior,
including automatic GitHub checks and external WebView2 services. Do not replace
that disclosure with a blanket no-network-transfer statement.

If accepted, the certificate publisher will be SignPath Foundation, not a
certificate issued in the maintainer's personal name. The Foundation acknowledgment will be added only after actual acceptance.
No active sponsorship, free-signing service or certificate is claimed.

[Foundation policy source](https://signpath.org/terms.html)
