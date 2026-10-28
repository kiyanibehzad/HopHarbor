# Ubuntu 26.04 verification

HopHarbor Ubuntu **1.2.1, build 9** was verified on **28 October 2026** in a disposable **Ubuntu 26.04.1 LTS arm64** virtual machine. Its home directory, D-Bus/keyring, SSH fixtures, data directories and listeners were independent of the host installation. There were no host-directory mounts, host SSH-agent forwarding or production proxy listeners. Tests used generated keys, synthetic credentials and loopback servers only.

- **164 unit tests passed** on Ubuntu and macOS, including both platform identities for shared recovery deadlines, fast retry expiry, manually stopped forwards, authentication blocks and pool quarantine.
- **11 native forwarding checks passed:** two local SSH servers, two-hop forwarding, pools of 4/2/1 transports, SOCKS, HTTP absolute requests, HTTP CONNECT and SOCKS with verified local TLS, fixed TCP forwarding, recovery after a child exits, stale-error clearing, simulated resume recovery and complete listener cleanup. The resumed pools became ready in about 3.6 seconds in these loopback tests, with the same proxy frontend processes.
- **11 credential/authentication checks passed:** actual libsecret storage/deletion, password/passphrase separation, SSH askpass, rejected invalid/host-confirmation prompts, real encrypted-key authentication, separate per-hop credentials, late SSH-agent availability without a controller restart, and locked-keyring rejection. Account passwords were not changed by the tests.
- **7 GUI checks passed** with GTK/WebKitGTK under Xvfb: authenticated panel and current version, the Session editor and all authentication choices, System/Light/Dark behavior, release/reopen of the hidden WebView, external-navigation rejection, and panel exit without stopping the independent controller. Existing public screenshots use synthetic data.
- The **arm64 1.2.1 Debian package** was installed in that VM. Its systemd user unit passed verification and start/restart/stop checks. Unauthenticated API access returned 401 and authenticated access returned 200. The private directory was mode 0700, configuration/control/known-host files mode 0600, the open-file limit was 8192, and both bounded service log files remained empty in the idle test. The default Sessions and forwards were empty.


- A separate continuous-request benchmark compared 1.2.0 and 1.2.1 over two normal and two delayed-upstream cycles each, using two-hop SSH and pools of two for both SOCKS and HTTP. After an eight-second simulated upstream outage, full-pool readiness after the server returned improved from about **6.9 seconds to 1.4–1.5 seconds**; the first successful payload improved from about **4.2 seconds to 1.2–1.3 seconds**. Normal full-pool readiness improved from about 6.0 to 3.5 seconds, while normal first-payload timing stayed around 3.2–3.3 seconds. Proxy frontend processes stayed running, all SSH transports were replaced, and recovered status errors were empty. These are synthetic local measurements, not an Internet-speed or physical-resume guarantee.
- The packaged background launcher opened the panel and left its controller active after the interface exited.

The original 1.2.0 validation on 27 October 2026 additionally exercised a source installation in a separate private data directory, including launch/removal and wrong-directory uninstall protection. The installer and credential implementation are unchanged in 1.2.1; its unit and native credential regressions were rerun above. The 1.2.0 tag retains the earlier full test record.

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
