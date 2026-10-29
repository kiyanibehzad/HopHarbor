# Third-party notices

## GOST

The macOS and Ubuntu editions use GOST from the official upstream release. Their installers and package builders verify its pinned digest before installation or redistribution. The public source checkout does not contain the GOST executable or release archive.

- Project and source: https://github.com/go-gost/gost
- Pinned release: 3.3.1
- macOS ARM64 download: https://github.com/go-gost/gost/releases/download/v3.3.1/gost_3.3.1_darwin_arm64.tar.gz
- SHA-256: `6b87b8c5fd728536d1b208382fc6b93a7bb04111d633a9f1e4651cd1ce62886d`
- Copyright (c) 2016 ginuerzh
- License: MIT; the complete upstream notice is retained in [upstream GOST notice](https://github.com/go-gost/gost/blob/v3.3.1/LICENSE).

[macOS provenance record](https://github.com/kiyanibehzad/HopHarbor/blob/main/vendor/provenance.json) records the macOS ARM64 provenance. Windows uses HopHarbor's own proxy frontend under the project's MIT license; its `THIRD-PARTY-WINDOWS.json` records redistributed CPython and Microsoft component provenance.

## Windows redistributed components

Windows packages include the following components. Their upstream notices are retained without modification and must accompany both the portable ZIP and the installed application.

- **.NET runtime and apphost 10.0.14**, used by the native panel and credential helper: MIT. See [license](vendor/windows/DOTNET-LICENSE.txt) and the complete [third-party notices](vendor/windows/DOTNET-THIRD-PARTY-NOTICES.txt).
- **WindowsDesktop runtime 10.0.14**, used by the native Windows Forms panel: MIT. See [license](vendor/windows/WINDOWSDESKTOP-LICENSE.txt). Its NuGet runtime packs contain this license and no separate third-party-notices file.
- **Microsoft.Web.WebView2 SDK 1.0.4314.35**, including its managed controls and native loader: Microsoft's BSD-style redistribution license. See [license](vendor/windows/WEBVIEW2-LICENSE.txt) and [third-party notice](vendor/windows/WEBVIEW2-NOTICE.txt). The browser WebView2 Runtime is an existing Microsoft system component or a separate installation; HopHarbor does not bundle it.
- **CPython embedded 3.14.9**: its complete upstream `LICENSE.txt` is included in the Windows package's `runtime/` directory. See the [Python license](https://www.python.org/psf/license/).

[vendor/windows/provenance.json](vendor/windows/provenance.json) records the exact upstream NuGet package URLs, versions, archive digests and notice digests for ARM64 and x64. The .NET SDK used to build the application is a build tool and is not redistributed.

## System components

HopHarbor invokes the operating system's OpenSSH client. The macOS edition uses the existing Python standard library and Apple's AppKit, WebKit, Security and LocalAuthentication frameworks. Ubuntu uses its system Python and GTK/WebKit dependencies. These system components are not bundled in the public source checkout and retain their respective upstream/system licenses. Windows redistribution is described above.

- OpenSSH: https://www.openssh.com/
- Python: https://www.python.org/psf/license/
- Apple system frameworks and development tools: https://developer.apple.com/

HopHarbor's original source is provided under the MIT License in [LICENSE](LICENSE).
