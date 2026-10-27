# HopHarbor on Ubuntu 26.04 LTS

The Ubuntu edition uses the same local English panel, Session definitions and forwarding engine as the macOS edition. It supports SOCKS, HTTP CONNECT, TCP forwarding, SSH Firewall chains, one to four SSH transports per forward, Session controls, keepalive, automatic recovery, System/Light/Dark appearance, and bounded same-day logs. It uses Ubuntu's OpenSSH, a per-user systemd service, Secret Service / GNOME Keyring, GTK/WebKitGTK, and the separately bundled, checksum-verified GOST dependency.

The Ubuntu installer and packages do not install a macOS app, run launchctl, migrate another machine's settings, or change server authentication. No personal Sessions, credentials, keys or live screenshots are included.

## Install the Ubuntu package

Choose **amd64** for Intel/AMD PCs, or **arm64** for an ARM Ubuntu installation:

```sh
sudo apt install ./hopharbor_1.2.0_amd64.deb
```

Open **HopHarbor** from Applications. The launcher starts only `local.hopharbor.manager.service` in your own user session. The empty default configuration opens no proxy ports. Add your Sessions, verify the server host keys, then create forwarding entries on unused local ports and test them before moving any client applications.

The package installs no system-wide SSH daemon or root background service. It does not start or stop tunnels during installation. A desktop-login entry keeps the indicator available after login. To start the background service at every user login even before the panel opens:

```sh
systemctl --user enable --now local.hopharbor.manager.service
```

An updated package does not restart a running controller. After reviewing an update, restart the service yourself at a suitable time; existing proxy connections will reconnect:

```sh
systemctl --user restart local.hopharbor.manager.service
```

Do not mix a source/per-user installation with a `.deb` installation. A unit in `~/.config/systemd/user` overrides the packaged user unit. Remove the old application/service using its original method first; configuration and keyring items are preserved. The installer and launcher check the selected user unit, canonical application/data paths and any running controller before changing a service. A stale launcher or uninstall command for another custom data directory is rejected instead of changing the current installation. The package launcher also rejects conflicting desktop/user-manager XDG data paths.

## Install from reviewed source instead

Run these commands inside a logged-in Ubuntu desktop session. The dependency installation uses sudo; the HopHarbor installer runs as your ordinary user:

```sh
sudo apt update
sudo apt install python3 python3-gi gir1.2-gtk-3.0 gir1.2-webkit2-4.1 gir1.2-ayatanaappindicator3-0.1 gir1.2-secret-1 gnome-keyring openssh-client curl dbus-user-session
git clone https://github.com/kiyanibehzad/HopHarbor.git
cd HopHarbor
python3 install_linux.py
```

The installer downloads the official GOST 3.3.1 binary for your architecture and checks its pinned SHA-256 before stopping any previous HopHarbor Linux service. It copies only application files, preserves the private configuration, and registers the user service, desktop launcher, app icon and login indicator. It rejects unsupported systems and root execution.

To prepare the installation without starting the service:

```sh
python3 install_linux.py --no-start --no-autostart
```

To use a previously downloaded official archive without downloading it again:

```sh
python3 install_linux.py --gost-archive /path/to/gost_3.3.1_linux_amd64.tar.gz
```

`--data-dir /absolute/private/path` selects a private data directory for a new per-user installation. There is one registered HopHarbor service per user. To change an existing installation's directory, remove its application/service with the original matching `--data-dir` first, then install with the new directory; settings are retained in the old directory. Opening the installed app starts its matching service, including after `--no-start`.

## Desktop behavior and credentials

Closing the window keeps the SSH service running. Use the top-panel indicator to open the panel again, keep the interface in the background, or quit the interface. Use **Disconnect** in the panel to stop a forward. Ubuntu's AppIndicator extension must be enabled for a visible tray icon; on other GNOME installations, install/enable the AppIndicator extension or open HopHarbor from Applications. The application keeps a usable window if indicator support is unavailable.

Passwords and encrypted-key passphrases are stored in your login keyring through Secret Service, never in JSON configuration. Unlock your login keyring before saving credentials. Unattended SSH credential lookup fails safely while the keyring is locked; it does not fall back to plaintext files. Automatic login, a keyring password different from your login password, and launching outside the desktop session may require unlocking the keyring first. A private key file must exist on the Ubuntu machine; paths and credentials from a Mac are not copied automatically. Agent mode requires the intended key to be available to that desktop session's SSH agent.

The panel follows the GTK desktop light/dark setting when **System** is selected. **Light** and **Dark** remain available as explicit choices. Sleep/resume recovery, keyring availability and indicator visibility depend on a working desktop session; test them on the target Ubuntu machine before relying on unattended forwarding.

## Files and diagnostics

| Item | Package install | Per-user source install |
| --- | --- | --- |
| Application | `/usr/lib/hopharbor` | `$XDG_DATA_HOME/hopharbor/app` |
| Private configuration/runtime/logs | `$XDG_DATA_HOME/hopharbor` | same |
| User unit | `/usr/lib/systemd/user/local.hopharbor.manager.service` | `$XDG_CONFIG_HOME/systemd/user/local.hopharbor.manager.service` |
| Desktop launcher | `/usr/share/applications/io.github.kiyanibehzad.HopHarbor.desktop` | `$XDG_DATA_HOME/applications/io.github.kiyanibehzad.HopHarbor.desktop` |

When unset, `XDG_DATA_HOME` defaults to `~/.local/share` and `XDG_CONFIG_HOME` to `~/.config`. The private directory is mode 0700 and configuration files mode 0600. For compatibility with the common controller, configuration and runtime state stay together inside this private data directory. Systemd/journald is not used to accumulate application traffic logs: controller stdout/stderr are discarded after the app installs its bounded streams.

Only the latest 200 current-day events remain in memory. Disk stdout/stderr files are capped at 256 KiB each and cleared on the next day; there are no accumulating rotated archives. Requests and traffic contents are not routinely logged. Diagnostic errors can still mention your own destinations: review them before sharing.

```sh
systemctl --user status local.hopharbor.manager.service
systemctl --user stop local.hopharbor.manager.service
systemctl --user start local.hopharbor.manager.service
```

All panel/proxy listeners bind to `127.0.0.1`. This app creates proxies; it does not transparently route all applications or replace a Proxifier-style routing engine. Configure your client applications to use a created SOCKS or HTTP port. For SOCKS remote DNS, select the client's proxy-DNS option (`socks5h://` in curl).

## Remove

For the package edition, stop your user service, remove the package, then refresh your user manager:

```sh
systemctl --user disable --now local.hopharbor.manager.service
sudo apt remove hopharbor
systemctl --user daemon-reload
```

For the source edition:

```sh
python3 install_linux.py --uninstall
```

Both methods preserve private settings and keyring credentials. Quit the menu-bar/panel interface separately if it is still open.

## Verification

See [the Ubuntu test record](ubuntu-testing.md) for the tested environment, results, reproduction commands and current limits.

## Build packages without installing

The package builder works on macOS or Linux. It copies a fixed public allowlist and does not inspect private runtime directories. It downloads and verifies the appropriate GOST release; no installer or service is executed:

```sh
python3 packaging/build_deb.py --arch amd64 --output /path/to/hopharbor_1.2.0_amd64.deb
python3 packaging/build_deb.py --arch arm64 --output /path/to/hopharbor_1.2.0_arm64.deb
```

Use `--gost-archive` for an offline build with the same pinned verification. A source/package build alone is not proof of a successful Ubuntu desktop test. Run the unit suite and the separate local integration tests on Ubuntu 26.04, including credential storage, two-hop forwarding, pool recovery, sleep/resume and desktop indicator behavior.

References: [Ubuntu WebKitGTK packages](https://packages.ubuntu.com/resolute/gir1.2-webkit2-4.1), [Ubuntu AppIndicator packages](https://packages.ubuntu.com/resolute/gir1.2-ayatanaappindicator3-0.1), [GNOME Secret Service library](https://gnome.pages.gitlab.gnome.org/libsecret/), [official GOST release and checksums](https://github.com/go-gost/gost/releases/tag/v3.3.1).
