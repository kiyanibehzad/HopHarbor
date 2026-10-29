# macOS panel recovery

Source update: **1.3.1, build 11**. Recorded **29 October 2026**.

This update changes the macOS panel and its web interface. The local deployment
keeps the existing background controller, SSH processes, proxy listeners and
saved connection settings running. A panel-only update can show a newer native
app version while the already-running controller still reports its earlier
version; it does not relabel or restart that controller.

## Confirmed failure mechanism

The panel exchanges its initial local access token for a session cookie and
removes that token from the page URL. In the earlier interface, a rejected API
request could lock the panel and stop status polling. The locked page's **Retry**
button only retried the API request; it did not repeat the native sign-in step.
Showing an existing macOS panel also reused its current page. Those code paths
could leave a healthy background service and working forwards behind a locked
panel.

The cookie has a finite lifetime, so an expired or missing cookie is one possible
trigger. The exact event that caused the reported user incident has not been
established. It must not be attributed to a controller crash, sleep, password
failure or lost server connections solely from the locked-panel message.

## Recovery behavior

The updated page can ask the native macOS panel to repeat local authentication
after a rejected session. Native recovery rereads the private local access file
and rebuilds the page. It does not send the control token through a page message
or save it in browser storage. Retry remains available when automatic recovery
cannot finish. Page-load and rendering failures have a separate recovery path.

The local origin, host and request protections remain in place. An HTTP 403
rejection does not automatically request a fresh authenticated page. Recovery
must be bounded so an unavailable service cannot cause a reload loop. No saved
form submission is automatically replayed after authentication is restored.

Use **Reload Panel** from the HopHarbor menu when a manual reload is needed.
This reloads the interface while leaving background connections running.

## Validation record

The following checks passed on Apple Silicon macOS using generated local data:

| Check | Result |
| --- | --- |
| Unit suite, shared controller regressions and source version agreement | 173 tests passed from the canonical checkout, including the existing local GOST boundary check |
| Actual panel JavaScript behavior | Seven cases within that suite: automatic and manual recovery, no 403/bootstrap retry loop, readiness, plain browser fallback and no failed mutation replay |
| Compiled Swift recovery policy | 28 assertions within that suite: trusted origin/frame/path checks, retry spacing, attempt limits and reset |
| Actual AppDelegate and WKWebView bootstrap | Passed; token fragment removed after authentication |
| Missing WebKit cookie and invalidated server session | Both recovered automatically through fresh authentication |
| Explicit Retry with corrected private access settings | Passed; rejected initial sign-in stayed bounded |
| Persistent HTTP 401 responses | Stopped after three automatic recovery attempts; Retry worked after correction |
| Real subframe, malformed messages and stale view callbacks | Rejected; successful readiness also canceled an already queued recovery |
| Controlled renderer termination callback | Rebuilt the panel successfully |
| Hide/reopen lifecycle | Discarded the page, canceled pending recovery and authenticated a fresh page on reopen |

The opt-in native runner is `tests/macos_panel_auth_smoke.py`; it compiles a
separate test bundle in native temporary storage, uses an ephemeral WebKit store
and a generated loopback service, and removes its own fixture afterward. It does
not read installed connection settings or start SSH. The installed panel's
persistent appearance preferences remain in its normal WebKit store.

The local interface-only deployment opened the authenticated Overview at
**1.3.1 / build 11**. Its existing controller, owned connection processes and
saved connection files were verified unchanged; proxy traffic still passed.
This is deployment evidence, not a forced failure of production authentication.

These checks deliberately deleted the synthetic browser cookie and invalidated
synthetic server sessions. They did not wait 12 hours, force a renderer crash,
put the computer to sleep or reproduce the exact original incident. Existing
Windows preview and Ubuntu package validation records retain their original
scope; their published files are not rebuilt for this macOS panel fix.
