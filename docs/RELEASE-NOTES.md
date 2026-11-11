> **Next version: 0.4.8 is being built by CL** (owner report, 11 November 2026).
> See [0.4.8 preparation and pending evidence](RELEASE-0.4.8.md).
> The 0.4.7 notes below are historical and do not describe 0.4.8 packages or test results.

# Threat Atlas screensaver 0.4.7-rc.1 — Windows + Linux release candidate

Product 0.4.7, build 15. First release candidate after 0.4.6-beta.1 (Windows panorama, build 14) and the Linux 0.4.6-beta.1 preview. Screensaver behaviour is unchanged from the beta: the owner-approved two-display panorama with the seam over the Atlantic, and the standard single-display layout everywhere else. The renderer is shared with AtlasSOC Desktop 0.7.0 RC1, whose wide-window offset is zero in screensaver mode. The numeric version advances to 0.4.7 because the installer payload changed. 0.4.5 stays the latest stable release.

## Included and excluded platforms

- Windows 10/11 x64: all-users MSI and portable ZIP. Unsigned.
- Linux x86_64: windowed preview archive (extract and run `AppRun`).
- macOS: excluded. Normal quarantined installation stays blocked by Gatekeeper until trusted signing/notarization is decided.

## Windows installation and updates

The MSI installs one x64 SCR into System32, documents into Program Files and three Start Menu items. Check the checksum and approve the administrator prompt. Uninstall an older per-user install first; the MSI refuses overlap. The MSI upgrades 0.4.5 and 0.4.6 installs. Automatic updates are absent from the all-users MSI; use verified manual packages.

## Known bugs and test limits

- Panorama is limited to two matching side-by-side displays. Mixed resolution, mixed DPI/scaling and hot-plug remain untested.
- Windows binaries are unsigned and may trigger a SmartScreen warning.
- Linux runs in a window: idle and lock integration, other distributions, DPI scaling, fullscreen and long-running stability are not verified.
- OS DNS resolution can delay feed-worker shutdown. No immediate-zero-background-traffic guarantee is made.

No simulated threats or TLS validation bypasses. Displayed records are real provider receipts, not verified unique attacks.
