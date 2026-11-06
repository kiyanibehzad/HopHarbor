# HopHarbor 1.4.1 · build 14 — macOS source testing prerelease

`v1.4.1-preview.1` continues the macOS-only source test cycle for Apple Silicon macOS 13 or later. It is a prerelease, not Latest stable. Ubuntu and Windows packages remain **1.3.2 / build 12**; no package, rollout or support change is supplied for them. Source metadata shares 1.4.1 / build 14 in preparation for future coordinated releases. Previous tags and assets are preserved.

[Exact-ref Mac source installation](macos-preview-1.4.1.md) · [Previous 1.4.0 features and validation](release-1.4.0.md).

## Changes

- Tools groups Import, Export and conditional Undo across views, retaining native Mac file dialogs and focus/Escape/outside dismissal behavior.
- Each Session shows its Firewall route and an inline role indicator. The Firewall detail list includes unique direct and transitive dependents, separates saved disconnected entries and follows live status.
- Session colors can be chosen in New/Edit or from the card's color line. New entries get one initial palette choice; legacy entries have stable display defaults. Strict hexadecimal metadata persists in configuration and portable exports. Color-only changes remain available on active Sessions without regenerating SSH configuration or restarting transports.
- Compact card headers pair the 36-pixel live status icon with a centered 38-pixel name/endpoint block. Accessible status descriptions cover connecting, connected, degraded, error, stopped and Firewall-only use. The Forwarding status header remains visible on narrow panels.

The existing strict endpoint proofs, standalone SSH Sessions, dependency-ordered bulk actions, configuration safety, quiet release notices and appearance preference remain in place. The updater only checks official stable-release metadata and never downloads or installs an update.

## Validation and scope

The approved UI review records **295 unit checks: 293 passed and 2 optional checks skipped**, six color/metadata contracts and 36 native layout/status cases. Synthetic active color saves and import/export round trips preserve transport ownership, desired state, host trust and credentials. Native layout includes compact and narrow views. The independent release run is recorded separately before publication.

Validation applies to tested Mac and synthetic fixtures; it does not establish every remote policy, physical network/sleep transition or Ubuntu/Windows 1.4.1 runtime behavior. Installation builds an ad-hoc-signed Mac app locally; no notarized binary is supplied. Upgrades stop the background service, so preserve a private rollback and verify an independent connection when Internet access depends on HopHarbor. Screenshots, when included, use synthetic data only.
