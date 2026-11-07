# Integration settings — proposed, not configured

This is a checklist for a separately authorized setup after eligibility review.
Nothing here grants repository access, creates a token or installs a GitHub App.

| Setting | Proposed value / required decision |
| --- | --- |
| Repository | `https://github.com/kiyanibehzad/HopHarbor` only |
| Source | Reviewed `main` commit identical to workflow run SHA; no arbitrary input ref |
| Trusted build system | GitHub.com connector; every preceding job GitHub-hosted |
| Project slug | `hopharbor` — confirm availability/provider assignment |
| Signing policy | `release-signing` — human approval mandatory for every request |
| Artifact configurations | `hopharbor-project-pe-v1`, `hopharbor-uninstaller-v1`, `hopharbor-installer-v1` — XML under `packaging/windows/signing/` |
| XML parameters | `productVersion`: source app version; `fileVersion`: app version plus build for project/Setup; Inno 7.1.0 engine `51.1055.0.0` for uninstaller (product version stays the app version) |
| Certificate | Foundation-assigned certificate, subject/classification accepted by provider; obtain public leaf DER SHA-256 independently |
| Timestamp | Provider-managed file signing timestamp, verified by Windows/SignTool; no unsigned/timestamp-free fallback |
| Submitter | CI identity with submit permission only for this project/policy |
| Approver | Named human confirmed by maintainer; not CI or an AI assistant |
| MFA | GitHub owner MFA enabled per maintainer self-report; future SignPath members need MFA; no settings inspected |
| GitHub environment | `signpath-release`, restricted to reviewed main; required human review with sole-maintainer/self-review constraints explicitly considered |
| Environment secret | `SIGNPATH_API_TOKEN` — never paste into source, prompts, output or application draft |
| Public environment variables | `SIGNPATH_ORGANIZATION_ID`; `SIGNPATH_CERTIFICATE_SHA256` — confirmed values absent |
| GitHub permissions | Workflow `contents: read`, `actions: read`; no release write or OIDC privilege |
| GitHub App | Only if needed by approved connector/audit setup; separately review requested repository permissions |
| Runner/tooling | `windows-2025` GitHub-hosted x64; .NET SDK 10.0.403; Windows SDK SignTool 10.0.26100.0 preflight; pinned Inno 7.1.0 official installer; exact .NET SDK archive SHA-512 in `tool-pins.json` |
| Artifacts | Exact owned-file requests uploaded separately with immutable artifact IDs; seven-day inputs and fourteen-day verified review candidates |

The signing workflow retains a literal false job guard and `workflow_dispatch` only. The separate unsigned workflow is enabled only for
the authorized manual build trial.
Activation requires a separate reviewed change removing that guard after all
settings are approved. It does not have push/PR/release/workflow-run triggers,
does not fetch local release binaries and never publishes final assets.
Uploading an artifact in a public repository is itself a disclosure; future CI
must continue to use sanitized source/allowlisted outputs with no personal data.

The project/helper and generated Inno signing scopes require Foundation
confirmation. XML parsing and local tests do not mean SignPath has accepted the
artifact configuration. A first provider-validated request and Windows native
verification remain unexecuted. No untrusted certificate is imported for tests.

Provider references:
[GitHub integration](https://docs.signpath.io/trusted-build-systems/github),
[artifact configuration](https://docs.signpath.io/artifact-configuration/),
[file metadata restrictions](https://docs.signpath.io/artifact-configuration/reference#file-metadata-restrictions),
[timestamp behavior](https://docs.signpath.io/crypto-providers/).
