# HopHarbor 1.4.2 · build 15 — macOS

This release provides reviewed source for **macOS 13+ on Apple Silicon**. [Installation and source checksum instructions](macos-1.4.2.md).

Ubuntu and Windows Preview downloads remain **1.3.2 · build 12**, with their existing validation and support limits. No Ubuntu or Windows 1.4.2 package is supplied. All platform shells share version/build metadata in source; this does not establish native validation or package availability on every platform. Historical releases and assets remain available.

## Changes

- Sessions now has search and a Filter panel for connection status and Firewall role. Port Forwarding filters by type, Session and status. Search and filters are independent between the tabs. Clearing filters keeps the search query; bulk actions still apply to the full tab scope.
- Disconnect All confirms before stopping connections. Port Forwarding stops forwards; Sessions also stops standalone SSH transports, including a Session that acquired forwarding after connecting. Pending starts are cancelled and deliberately stopped connections stay stopped during retry and wake handling.
- Bulk disconnection signals all selected owned children against one shared termination deadline. Failures retain ownership for retry and return individual results; a newer action cannot have its replacement runtime removed by an older bulk action.
- Session cards use an inset clickable color strip. New Sessions choose blue, purple or pink by default; existing saved, manual and legacy colors retain their behavior.
- The compact green Firewall in use badge retains live dependency details. Connection icons continue to distinguish actual status. The duplicate Sessions section heading has been removed.

This includes the preceding Mac test-cycle functionality: standalone Sessions, Firewall chains, strict endpoint continuity, Tools Import/Export and Undo, persistent Session colors, and stable-release notices. Update checks notify only; they do not download or install software.

## Validation scope

The versioned source passed **301 unit tests: 299 passed, 2 optional integration tests skipped**. The skips require separately supplied GOST and compiled Windows policy fixtures. Source tests do not establish Ubuntu or Windows native validation for this version.

An independent synthetic process test stopped 3 and 25 owned proxy process groups that ignored SIGTERM in approximately **0.51 and 0.52 seconds**. A concurrent state-lock probe waited approximately **0.40 and 0.41 seconds**. All synthetic children were reaped. These local timings demonstrate the shared deadline and are not a production timing guarantee or an Internet-speed benchmark.

Native WebKit UI review covered the final card, Firewall and Tools behavior in light/dark appearance with normal and long labels. Synthetic fixtures also exercised both Disconnect All scopes. Public screenshots use demo names and documentation-only addresses.

## Installation and release scope

The source archive contains tracked public source and project resources. It supplies no installed app bundle, notarized Mac binary, personal Sessions, keys, credentials, private test harness or real-session screenshots. Building requires Python, Git and Apple's command-line tools. The installer replaces the local service and interrupts its connections; establish an independent working connection before upgrading if access depends on HopHarbor. See the installation guide for the exact release ref and checksum procedure.
