# Threat Atlas screensaver 0.4.6-beta.1 — Windows panorama beta

Product 0.4.6, build 14. Robert approved the physical two-display result, visual layout and version/build identity on 7 November 2026. The candidate adds an undistorted panorama for two matching side-by-side displays, places the seam over the Atlantic and keeps each information panel on one display. Unsupported display layouts retain the standard renderer. The final edge-placement correction is included. Publication remains pending exact-package checks and successful CI on the reviewed integration commit.

## Included and excluded platforms

Windows 10/11 x64 only: all-users MSI and portable ZIP. No Linux package is included because this is a Windows-specific panorama beta. No macOS package is included because normal quarantined installation remains blocked by Gatekeeper and trusted signing/notarization is unresolved. The packages remain unsigned.

## Windows installation and updates

The MSI installs one x64 SCR into System32, documents into Program Files and three Start Menu items. Check the checksum and approve the administrator prompt. Manual System32 copying requires **Run as administrator**; routine screensaver execution does not. Uninstall the older per-user install first; the MSI refuses overlap. Automatic updates are absent from the all-users MSI pending a reviewed redesign; use verified manual packages. Windows binaries remain unsigned.

## Known bugs and test limits

- The owner approved physical two-display panorama behavior and the corrected visual layout. Exact-package reinstallation and upgrade checks remain pending.
- Panorama is limited to two matching side-by-side displays. Mixed resolution, mixed DPI/scaling, hot-plug and extended soak testing remain untested.
- Lock-on-resume and installation from a browser-downloaded MSI, including Zone.Identifier/SmartScreen behavior, remain untested.
- Native Settings listing, small/full preview, one-minute idle start, upgrade from 0.4.5 and post-uninstall Settings state require final candidate verification.
- Windows binaries remain unsigned and may trigger a trust warning.
- OS DNS resolution can delay feed-worker shutdown. No immediate-zero-background-traffic guarantee is made.

No simulated threats or TLS validation bypasses. Displayed records are real provider receipts, not verified unique attacks.
