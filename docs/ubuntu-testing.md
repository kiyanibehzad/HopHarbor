# Ubuntu 26.04 verification

HopHarbor Ubuntu 1.2.0, build 8 was verified on 27 October 2026 in a disposable **Ubuntu 26.04.1 LTS arm64** virtual machine. Its home directory, D-Bus/keyring, SSH fixtures, data directories and listeners were independent of the host installation. Tests used generated keys, synthetic credentials and loopback servers only.

- **134 unit tests passed** on Ubuntu and macOS, including native GOST probe coverage.
- **11 native forwarding checks passed:** two local SSH servers, two-hop forwarding, pools of 4/2/1 transports, SOCKS, HTTP absolute requests, HTTP CONNECT and SOCKS with verified local TLS, fixed TCP forwarding, recovery after a child exits, stale-error clearing, a simulated resume recovery and complete listener cleanup.
- **11 credential/authentication checks passed:** actual libsecret storage/deletion, password/passphrase separation, SSH askpass, rejected invalid/host-confirmation prompts, real encrypted-key authentication, separate per-hop credentials, late SSH-agent availability without a controller restart, and locked-keyring rejection. Account passwords were not changed by the tests.
- **7 GUI checks passed** with GTK/WebKitGTK under Xvfb: authenticated panel, the Session editor and all authentication choices, System/Light/Dark behavior, release/reopen of the hidden WebView, external-navigation rejection, and panel exit without stopping the independent controller. The screenshot in the README uses the empty test configuration.
- The arm64 Debian package was installed and launched in that VM. Its systemd user unit, authentication boundary, file permissions, start/restart/stop behavior, bounded logs and installation-scope guards were exercised.
- A source installation with a separate private data directory was installed, started, launched and removed inside the VM. A wrong-directory uninstall was rejected while the correct service stayed running; the matching uninstall preserved configuration.
- Both **amd64 and arm64** packages were built from an explicit public allowlist and accepted by `dpkg-deb`. GOST archives were verified against architecture-specific official SHA-256 digests before packaging.

## Limits of this verification

The amd64 package has not yet been run on native Intel/AMD hardware. Xvfb exercises the panel and indicator API, but does not verify the visible tray icon in a complete GNOME/Wayland desktop. Resume detection has clock-reader unit coverage and the recovery path was exercised with live local SSH transports; the physical computer/VM was not suspended during testing. Keyring unlock behavior after a real graphical login and forwarding speed depend on the target desktop and network.

## Reproduce inside a disposable Ubuntu VM

Install the application dependencies from [the Ubuntu guide](ubuntu.md), plus test-only packages:

```sh
sudo apt install openssh-server openssl xvfb dbus-x11 python3-gi-cairo
python3 -m unittest discover -s tests -v
python3 tests/linux_credentials_smoke.py
dbus-run-session -- xvfb-run -a python3 tests/linux_desktop_smoke.py
python3 tests/linux_forwarding_smoke.py --gost /usr/lib/hopharbor/bin/gost --report /tmp/hopharbor-forwarding-results.json
```

Run the scripts as an ordinary user. The forwarding test needs a separately verified Linux GOST executable; the unit suite uses `bin/gost` when supplied as a local, untracked fixture. Downloaded binaries and generated runtime data do not belong in Git. The integration scripts do not use the user's installed controller, stored Sessions, production server accounts, SSH agent or existing keys. The credential test creates its own agent and keyring.
