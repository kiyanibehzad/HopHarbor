# Ubuntu panel authentication recovery

HopHarbor **1.3.2, build 12**. Validation recorded **29 October 2026**.

The native Ubuntu panel can recover from an expired browser cookie or an invalidated
server session without restarting the controller or its forwarding connections.
The existing token bootstrap removes its URL fragment before exchanging the token.
A rejected session previously left Retry repeating the rejected cookie; the native
shell now rereads its private control file and opens a fresh authenticated document.
The exact trigger of the originally reported macOS incident remains unproven.

## Trust boundary

Follow-up review found that the real shared `parent.postNativePanelMessage(...)`
helper could move a child's call into the parent's JavaScript context. The earlier
frame-message checks alone did not prevent that path. A real native baseline probe
confirmed the helper existed, ran in the child test and scheduled native recovery.
This follow-up closes that gap before publication.

The WebView now has a **native default Content-Security-Policy** with
`script-src 'none'; frame-src 'none'; child-src 'none'`. This additive engine policy
blocks content scripts, frame loads and inherited about:blank child scripts before
execution. Empty frame objects can still be created; they cannot execute the tested
child payloads or load a child document. The native navigation policy also rejects
all secondary document navigations.

The unchanged reviewed scripts from the installed `web/index.html` and fixed
`/app.js` are injected as separate user scripts, in their original order and only
in `TOP_FRAME`. This preserves each script's strict-mode boundary. WebKit's native
UserContentManager can execute these trusted scripts despite the content policy;
no arbitrary page URL or script is accepted. Unsupported script sources fail closed.
The shared web/controller files and their existing protections are unchanged.
The [WebKitGTK native policy documentation](https://webkitgtk.org/reference/webkit2gtk/stable/property.WebView.default-content-security-policy.html)
describes its additive application to all loaded content and the trusted
UserContentManager exception used here.

The public WebKitGTK message callback does not supply sender-frame metadata. The
native receiver is therefore registered only in a named isolated script world.
Its receiver script is injected only into the top frame and accepts browser-created
MessageEvents from that same window, the exact native-selected loopback origin and
port, and the exact `/` or `/index.html` path. Page JavaScript cannot access the
isolated native handler. The Python callback independently checks current WebView,
document generation, current origin/port/path and the exact fixed command shape.

The existing web transport name refers directly to the top WindowProxy's browser
`postMessage` method. There is deliberately no JavaScript wrapper or bound function:
those changed the sender identity when a same-origin iframe called its parent's
facade in actual WebKitGTK testing. Direct WindowProxy calls retain sender identity,
but calls through the parent's ordinary shared helper need the native content
policy above: apparent top-frame identity alone is insufficient. Constructed MessageEvents,
extra fields, arbitrary commands and navigation to other documents are rejected.
Each WebView owns one document; a native reload creates a different view and generation.

Only `ready` and `reauthenticate` with `authentication` or `retry` are accepted.
No page message contains a native token, destination or control-file settings.
The native shell constructs bootstrap URLs itself from the validated private file.
Tokens are not injected into scripts, returned in messages or saved in web storage.
Existing Host, Origin, CSRF and HTTP-only cookie protections are unchanged.

## Recovery and lifecycle

An API 401 requests automatic recovery once per document, except when the initial
session exchange itself fails. HTTP 403 and rejected bootstrap remain locked until
explicit Retry. Failed POST/PUT/DELETE operations are not replayed after sign-in.

Automatic recovery permits at most three attempts in a rolling 60-second window,
with at least two seconds between scheduled attempts and one pending recovery.
Explicit Retry can bypass exhausted automatic attempts while retaining spacing and
coalescing. A current trusted ready message cancels pending recovery and clears the
automatic budget. Hidden, stale and destroyed documents cannot affect this state.

Hiding cancels pending work. Reopening authenticates a fresh page, retaining the
persistent appearance preference. Native loading failures, a 20-second document
loading watchdog and renderer termination share bounded recovery. Native renderer
signals use owned-view/generation identity because a dead renderer can lose its URI;
script messages always require a valid live panel location. Concurrent failure
signals do not cancel an already pending recovery. None of these operations starts
or stops the background service or its SSH processes.

## Validation

The following passed in an independent Ubuntu **26.04.1 LTS arm64** VM with
GTK 3 and **WebKitGTK 2.52.6 / API 4.1**, using Xvfb, generated data and loopback
services. No host directory mounts, host SSH agent or production settings were used.

| Check | Result |
| --- | --- |
| Unit suite on macOS and Ubuntu | 263 tests on each; one platform-specific/fixture skip on each |
| Native panel recovery runner | 19 checks passed from reviewed source and from the installed arm64 package |
| Real HTTP-only WebKit cookie expiry with unchanged control file | Reauthenticated a fresh view |
| Server session invalidation with unchanged control file | Recovered automatically |
| Actual failed POST | One request only; no replay |
| HTTP 403 and rejected initial bootstrap | No automatic sign-in; Retry succeeded after correction |
| Persistent HTTP 401 | Three spaced attempts, then stopped; manual Retry succeeded |
| Real child / parent bridge / actual shared parent helper | All three prevented before child script execution, through dynamic append, document.write, srcdoc and HTTP frame loads |
| Foreign hostname/port/path, forged events and malformed commands | Rejected |
| Stale view/generation callbacks and wrong-path ready | Rejected; no budget reset |
| Pending recovery and current ready | Coalesced; valid ready canceled pending work |
| Hide/reopen and actual renderer termination | Fresh authenticated view |
| Controlled loading-timeout callback | Used the bounded native recovery path |
| Existing forwarding / credentials / desktop regressions | 11 / 11 / 7 checks passed |
| arm64 package lifecycle and launcher | Install, user-service verification/start/restart/stop, API 401/200, permissions, FD limit 8192 and independent panel exit passed |
| amd64 and arm64 package structure | Architecture, pinned GOST, source-byte agreement and private-path audit passed |

The macOS unit skip was the uninstalled local GOST fixture; Ubuntu ran that check
and skipped the compiled macOS Swift policy. The native test uses the actual shared `postNativePanelMessage` function, not a
replacement helper. Every attack payload marks its first instruction; all twelve
production attempts left that marker empty and issued no child HTTP requests.
The HTTP child fixture deliberately omits framing/CSP response headers, so its
rejection does not rely on test-server framing protections. The ordinary main-frame
helper, automatic authentication, Retry and ready continue to function.

The native runner deterministically
shortens the actual WebKit cookie lifetime rather than waiting 12 hours. Renderer
termination uses WebKit's actual `terminate_web_process()` API. The loading-timeout
case invokes the real native timeout callback; it does not claim a measured
20-second network stall. No physical suspend, full GNOME/Wayland tray visibility,
native amd64 execution or real graphical-login keyring behavior was established.
The packages in this validation are local review candidates; publication and final
cross-platform integration are separate steps.

## Reproduce

Inside a disposable Ubuntu environment, install the dependencies and test tools
listed in [the Ubuntu guide](ubuntu.md) and [existing verification record](ubuntu-testing.md),
plus Node.js for the shared JavaScript behavior tests. Supply the separately verified
Linux GOST fixture outside tracked source. As an ordinary user, run:

```sh
python3 -m unittest discover -s tests -v
dbus-run-session -- xvfb-run -a python3 tests/test_ubuntu_panel_auth_native.py
python3 tests/linux_credentials_smoke.py
dbus-run-session -- xvfb-run -a python3 tests/linux_desktop_smoke.py
python3 tests/linux_forwarding_smoke.py --gost /path/to/verified/gost
```

The native runner creates and removes its own empty controller, keyless configuration,
WebKit store and local listener. It does not use an installed user's service or Sessions.
