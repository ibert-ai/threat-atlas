# Threat Atlas screensaver 0.4.8 — Stable · Windows + Linux + macOS

Product 0.4.8, build 16. Stable release by the maintainer's decision of 11 November 2026. It promotes the 0.4.7-rc.1 implementation: the owner-approved two-display Windows panorama with the seam over the Atlantic, and the standard single-display layout everywhere else. The Classic look is unchanged and is now pinned by an automated test. The numeric version advances to 0.4.8 because the installer payload changed. This release replaces 0.4.5 as the latest stable.

Stable is a release decision. It is not trusted Windows signing and not a claim that every hardware or manual check passed; the limits are listed below.

## Included platforms

- Windows 10/11 x64: all-users MSI and portable ZIP. Unsigned.
- Linux x86_64: windowed preview archive (extract and run `AppRun`).
- macOS 12+ (Apple silicon and Intel): `ThreatAtlas-macOS-signed.zip`, signed with Developer ID (Robert Ibert, team 7NXP86HMVH), notarized by Apple and stapled. It is built from the same commit on the maintainer's Mac and attached after the automated Windows/Linux publication, with its own SHA-256 file.

## Windows installation and updates

The MSI installs one x64 SCR into System32, documents into Program Files and three Start Menu items. Check the checksum and approve the administrator prompt. Uninstall an older per-user install first; the MSI refuses overlap. The MSI replaces an earlier all-users MSI install (0.4.5, 0.4.6-beta.1, 0.4.7-rc.1). Automatic updates are absent from the all-users MSI; use verified manual packages.

Windows binaries are unsigned. Windows SmartScreen may show a warning for the MSI and the SCR; verify the SHA-256 checksum before you choose to run them. Do not disable security protections.

## Changes since 0.4.7-rc.1

- Stable identity (no prerelease label on screen).
- The code for an optional Seeker theme is included but is not selectable in release builds. Nothing changes on screen.
- Internal: the on-screen clock can take a fixed offset in tests; no change in normal use.

## Known bugs and test limits

- Panorama is limited to two matching side-by-side displays. Mixed resolution, mixed DPI/scaling and hot-plug remain untested.
- Windows display scaling at 150% and 200% is not tested on a physical PC.
- Idle start, lock-on-resume and MSI upgrade were not re-tested on physical hardware for this build; the hosted MSI install/uninstall check passed.
- Intel Mac hardware is not tested (the Intel code runs under Rosetta in testing).
- Linux runs in a window: idle and lock integration, other distributions, DPI scaling, fullscreen and long-running stability are not verified.
- OS DNS resolution can delay feed-worker shutdown. No immediate-zero-background-traffic guarantee is made.

No simulated threats or TLS validation bypasses. Displayed records are real provider receipts, not verified unique attacks.
