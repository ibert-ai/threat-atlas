# Development history

## 12 November 2026 — AtlasSOC Desktop Linux preview published

The separate `atlassoc-v0.7.0-linux` prerelease is build 13 from
`c8256318285e24cd8f794be01edff0a802276bc5` (PR44 integration). Windows and macOS
stable assets are unchanged. Linux has the shared SOC renderer, country focus
and wide layout, but no Radar, saved settings, update check or fullscreen toggle.
The release records Ubuntu 24.04 CI/Xvfb offline smoke, not physical Linux or live
feed acceptance. See [Linux preview details](ATLAS-SOC-LINUX.md).

## 11 November 2026 — stable screensaver and Desktop published

Screensaver `v0.4.8` build 16 and Desktop `atlassoc-v0.7.0` build 13 were
published from `7fba1cc1b3c0b7cdc295d67d4bff378d6d46fff4`. Screensaver promotes
the two-display Windows panorama; Classic remains unchanged. The version
advances because the Windows MSI payload changed. Optional Seeker code is not
selectable in release builds. Desktop retains RC1 features and includes the
macOS bundle-type packaging fix.

Published macOS packages are Developer ID signed, notarized and stapled;
Windows remains unsigned. Release notes report hosted build/installer checks
and macOS trust checks, while physical install/upgrade, scaling, ultrawide,
Intel hardware and idle/lock gaps remain explicit. See the
[0.4.8 release record](RELEASE-0.4.8.md) and [known limits](KNOWN-BUGS.md).
This documentation reconciliation did not rerun those historical checks.

## 29 October 2026 — historical country-map / Linux development record

- Added cached country borders and expiring classification shading, sharing feed
  colours and preserving polygon holes/islands. Conflict rule: highest active
  category; both reported endpoints included.
- Added a Linux windowed host, relocatable archive/AppDir packaging, optional
  operator-supplied AppImage tooling, and planned Linux CI smoke validation.
- Existing v0.4.0 release artifacts are untouched. No wishlist item is marked
  complete. Windows validation by the second agent and user visual approval are
  required before push/release; Linux native screensaver support is not claimed.
