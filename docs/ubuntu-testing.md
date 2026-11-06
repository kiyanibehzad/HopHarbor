# Ubuntu 26.04 verification

HopHarbor Ubuntu **1.4.2, build 15** was tested on **6 November 2026** in a disposable **Ubuntu 26.04.1 LTS arm64** VM with Python 3.14 and WebKitGTK 2.52.6. Its home, D-Bus/keyring, SSH fixtures, application data and listeners were independent of the host installation. There were no host-directory mounts or SSH-agent forwarding. Tests used generated keys, synthetic credentials and loopback servers. The installed macOS application and its connections were not used by the tests.

The original `v1.4.2` tag and macOS source archive are preserved. Ubuntu's native additions are in the frozen `platforms-source-1.4.2` branch and supplementary platform source archive. The [release record](https://github.com/kiyanibehzad/HopHarbor/releases/tag/v1.4.2) identifies the exact supplementary commit/tree and artifact checksums. A matching version string alone does not establish matching source.

## Automated and native checks

- The final Ubuntu Python 3.14 unit run completed **314 tests: 312 passed and 2 skipped**. The skips require the macOS Swift policy and a compiled Windows policy executable. The initial macOS host checkpoint completed 305 tests with two optional fixture skips. This covers the shared controller, portability, release checking, endpoint proof, bulk ownership/deadlines, recovery, credentials, installation identity and Linux native validation.
- **13 real GTK/WebKit feature checks passed from source and the installed arm64 DEB.** They exercise authenticated version/build display; standalone SSH through a Firewall; search and independent filters; compact 780-pixel layout; the eight-color palette and color Save on a live Session without changing its SSH PID/trust; native Save/Open dialogs; portable export permissions and privacy; controlled Save failure, cancellation and hide/reopen cleanup; import preview/apply/reimport-no-op/Undo; malformed native-message rejection; throttled release checks; actual user-gesture release-link policy; and bulk Tunnels/Sessions confirmation, cancellation and ownership, including hidden active Sessions. Release responses and the external URI opener were controlled fixtures: no browser or update installer was launched.
- **20 real WebKit authentication/lifecycle checks passed from source and the installed arm64 DEB.** They cover cookie expiry, server-side session invalidation, failed POST without replay, 403/manual Retry, the rolling three-attempt recovery budget, rejected bootstrap, malformed messages, foreign origins/paths, stale views, one pending recovery, ready/hide cleanup and renderer termination. Sixteen child-frame attempts cover direct bridge, parent bridge, the actual shared parent helper and configuration Export via script insertion, document.write, srcdoc and HTTP frames. Native CSP prevents their first instruction and child HTTP request; no export dialog opens. Timing checks observe native dispatch and scheduled deadlines separately from variable HTTP arrival times.
- **Seven desktop regressions passed against the installed arm64 payload:** authenticated Overview, all Session authentication choices and Linux credential labels, System/Light/Dark updates, hidden WebView release/reopen, external-navigation rejection and interface exit without stopping the independent controller.
- **11 forwarding checks passed:** real two-hop SSH, pools of four/two/one, SOCKS, HTTP requests and CONNECT, verified loopback TLS, fixed TCP forwarding, child exit, simulated resume recovery and listener cleanup.
- **11 credential checks passed:** real Secret Service storage/deletion, password/passphrase separation, SSH askpass, encrypted keys, separate hop credentials, late agent availability and locked-keyring rejection.
- **Six Session/endpoint checks passed with Ed25519 and again with RSA host keys.** Real standalone SSH, Firewall/reconnect/wake/disconnect, endpoint identity proof, rejection without pinning on wrong host key or authentication, bounded cancellation and shutdown cleanup were exercised. The synthetic three-child wake case and state-lock wait were about 0.5 seconds.
- A real **25-process bulk reconnect** reaped all owned TERM-resistant children in about 0.66 seconds, with a roughly 0.51-second state-lock wait. Separate three/25-process disconnect probes completed in about 0.58/0.51 seconds; all owned children were reaped and deliberate stopped intent survived wake. These are local measurements, not remote-network timing guarantees.

## Installation and upgrade

Nine lifecycle checks exercised the exact previously published **1.3.2 arm64 DEB** and a 1.4.2 candidate, plus per-user source installs from the published 1.3.2 source:

- Package installation preserved the running old controller's PID/version. A deliberate restart inside the VM loaded 1.4.2/build 15 and the new modules.
- Both upgrade methods preserved synthetic Sessions/order, ports, pools, authentication settings, keepalive, stopped intent, private key, host trust and control-file bytes. Legacy colors did not trigger a configuration rewrite merely by viewing or upgrading.
- The installed package's API exported portable legacy colors and exercised import preview/apply/Undo. Its actual launcher opened separately and exiting the interface left the independent controller running.
- An invalid source-update GOST archive was rejected before stopping the old controller. The valid source update staged the new modules and removed staging directories afterward.
- A wrong-directory source uninstall was rejected. Matching source uninstall and Debian removal preserved the synthetic private settings and key material.

The package builder uses only its explicit public allowlist and pinned official GOST 3.3.1 archives. Both architecture artifacts must pass the Git & Release source-byte, control metadata, ELF architecture, provenance and privacy review before publication. Package creation on macOS never installs or starts the application.

The final Ubuntu runtime delta was qualified from reviewed commit `0d84ab7fb5db08dfeaa68f6e3a5bd4ee5207761a` (tree `d3b4caf3556364fe4cc1df5ca2c485271fe7c486`). Only `manager.py` and `session_tools.py` differed among the 14 packaged runtime/web files from the native feature checkpoint; their reviewed additions affect Windows branches. Linux native UI, configuration portability, release checking and installer bytes were unchanged, so Git & Release accepted reuse of the **40 native UI checks** above and **nine upgrade checks**. The full 314-test Ubuntu suite and both six-check real Ed25519/RSA Session/endpoint suites were rerun against the updated runtime. The rebuilt arm64 package additionally passed installed version/build, API 401/200, all 14 source-byte matches, private permissions and owned-process/listener cleanup checks. Both architecture DEBs passed independent Git & Release artifact review. Later Windows-only source/test changes leave those 14 Ubuntu runtime inputs unchanged; the release records the final source and package provenance.

## Limits

Native execution here covers **arm64 only**. The amd64 package is structurally inspected but has not been run on Intel/AMD Ubuntu hardware. Xvfb exercises real GTK dialogs, WebKit and the indicator API; it does not establish visible tray behavior in a complete GNOME/Wayland login. Physical suspend, post-login keyring unlock, a new 12-hour soak and an elapsed 24-hour release-check interval were not tested in this run. Release throttles were exercised with controlled time/state. The earlier recovery benchmark belongs to the [1.2.1 verification record](https://github.com/kiyanibehzad/HopHarbor/blob/v1.2.1/docs/ubuntu-testing.md); it is not a new 1.4.2 performance measurement.

## Reproduce in a disposable Ubuntu VM

Install application dependencies from [the Ubuntu guide](ubuntu.md), plus test-only packages:

```sh
sudo apt install openssh-server openssl xvfb dbus-x11 python3-gi-cairo xdotool
python3 -m unittest discover -s tests -v
python3 tests/linux_credentials_smoke.py
dbus-run-session -- xvfb-run -a python3 tests/linux_desktop_smoke.py
python3 tests/linux_forwarding_smoke.py --gost /usr/lib/hopharbor/bin/gost --report /tmp/hopharbor-forwarding.json
python3 tests/session_tools_smoke.py --host-key-type ed25519 --report /tmp/hopharbor-session-ed25519.json
python3 tests/session_tools_smoke.py --host-key-type rsa --report /tmp/hopharbor-session-rsa.json
python3 tests/bulk_actions_smoke.py --report /tmp/hopharbor-bulk.json
dbus-run-session -- xvfb-run -a python3 tests/test_ubuntu_142_native.py --report /tmp/hopharbor-features.json
dbus-run-session -- xvfb-run -a python3 tests/test_ubuntu_panel_auth_native.py --report /tmp/hopharbor-recovery.json
```

The two native feature/recovery runners accept `--app-dir /usr/lib/hopharbor` to test installed application bytes. Choose fresh report paths. Run as an ordinary user with a private home directory suitable for OpenSSH StrictModes. Forwarding requires a separately verified Linux GOST binary. Tests do not use the installed controller's data, production accounts or the host agent. Generated keys, downloaded binaries, VM images, reports and private test fixtures must remain outside tracked public source.
