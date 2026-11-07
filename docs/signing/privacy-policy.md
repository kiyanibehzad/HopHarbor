# Privacy policy

Applies to the examined HopHarbor 1.4.2/build 15 source and proposed Windows
signing preparation. Publishing this description does not establish Foundation
acceptance or compliance. Maintainer contact: [opensource@caracalx.io](mailto:opensource@caracalx.io).

## Local data and user-directed connections

HopHarbor stores SSH profiles, host trust, connection intent and bounded
diagnostic logs locally. On Windows, passwords and key passphrases are stored
in the signed-in user's Windows Credential Manager; private keys remain at
user-selected paths. The local panel uses authenticated loopback communication.
Configuration exports omit credentials, host trust and local key paths. Review
exports and logs before sharing: profile names, hosts and diagnostic addresses
can still be personal data.

The app connects to SSH servers and jump hosts configured by the operator.
Traffic forwarded through SOCKS/HTTP/TCP reaches destinations selected by client
applications. Those SSH providers and destination services can observe data
according to their protocols and policies. User-invoked HTTP/SOCKS tests request
`https://example.com/` through the chosen proxy; generic TCP tests only probe the
local listener. These are not arbitrary-port vulnerability scans.

## Automatic release checks

The controller automatically requests
`https://api.github.com/repos/kiyanibehzad/HopHarbor/releases/latest` at startup
when due and approximately once per 24 hours while running. A manual check can
also be requested, with a minimum retry interval. Requests use the fixed
`HopHarbor-release-notice` User-Agent. They do not include saved Sessions,
credentials, logs, an installation identifier or the current app version in the
request. GitHub and the intervening network can see normal connection metadata,
including the originating IP address and request time. Checks announce updates;
they do not download or install release assets. Opening a release link launches
the user's browser and is governed by GitHub/browser policies.

**Current behavior / applicability question:** there is no supported user-facing disable setting or installer
choice for these automatic checks. The internal test attribute
`allow_release_network` is not a documented end-user control. Do not claim that
an installer opt-out already exists. The Foundation clause concerns collection
and transfer of user data to systems not specified by the user; whether this
fixed version GET or separately installed runtime behavior triggers it needs
clarification. This is not a finding of ineligibility. Ask the provider whether
the proposed disclosure suffices or an installer-visible notice and supported
release-check control is needed before signing.

[GitHub privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement)

## Microsoft WebView2 and platform services

The Windows panel requires a separately installed Microsoft Edge WebView2
Runtime. HopHarbor does not bundle or silently install that browser runtime or
OpenSSH Client. The app's resource/navigation restrictions are not a guarantee
that WebView2 itself makes no network requests. Its defaults can involve
required/optional diagnostics, SmartScreen and crash reporting to Microsoft;
Windows diagnostic settings govern optional collection. Required services may
remain active. HopHarbor does not disable SmartScreen or system protections.
Microsoft's privacy terms and device policies apply to these separate services.

[Microsoft WebView2 data/privacy documentation](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/data-privacy)
and [Microsoft privacy statement](https://privacy.microsoft.com/privacystatement).

## Installation, removal and review

Setup changes the per-user application directory and shortcuts; sign-in startup
is a visible installer option. Upgrade/uninstall stop only the matching app
scope. Uninstall preserves private settings and saved credentials. Users can
remove those separately when desired. HopHarbor has no maintainer analytics or
crash-upload endpoint in the examined application source; this does not cover
independent operating-system or runtime services described above.

Before activating signing, review network behavior on the actual candidate
and clarify whether an installer-visible notice and supported controls are
required. This preparation changes neither live runtime settings nor
the existing installer behavior.
