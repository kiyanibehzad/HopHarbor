# Third-party notices

## GOST

HopHarbor's installer downloads GOST from the official upstream release. The public source checkout does not contain the GOST executable or release archive.

- Project and source: https://github.com/go-gost/gost
- Pinned release: 3.3.1
- Download: https://github.com/go-gost/gost/releases/download/v3.3.1/gost_3.3.1_darwin_arm64.tar.gz
- SHA-256: `6b87b8c5fd728536d1b208382fc6b93a7bb04111d633a9f1e4651cd1ce62886d`
- Copyright (c) 2016 ginuerzh
- License: MIT; the complete upstream notice is retained in [vendor/GOST-LICENSE](vendor/GOST-LICENSE).

The installer verifies the pinned digest before installing GOST. [vendor/provenance.json](vendor/provenance.json) records the generic upstream release provenance.

## System components

HopHarbor invokes the OpenSSH client and Python standard library already installed on the Mac, and links to Apple's AppKit, WebKit, Security and LocalAuthentication frameworks. Their source or binaries are not redistributed by this source checkout. They retain their respective upstream/system licenses.

- OpenSSH: https://www.openssh.com/
- Python: https://www.python.org/psf/license/
- Apple system frameworks and development tools: https://developer.apple.com/

HopHarbor's original source is provided under the MIT License in [LICENSE](LICENSE).
