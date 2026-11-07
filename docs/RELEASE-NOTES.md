# Threat Atlas screensaver 0.4.6-beta.1 — Windows panorama beta with Linux preview

Product 0.4.6, build 14. Robert approved the physical two-display result, visual layout and version/build identity on 7 November 2026. The candidate adds an undistorted panorama for two matching side-by-side displays, places the seam over the Atlantic and keeps each information panel on one display. Unsupported display layouts retain the standard renderer. The final edge-placement correction is included. Publication remains pending exact-package checks and successful CI on the reviewed integration commit.

## Included and excluded platforms

Windows 10/11 x64: all-users MSI and portable ZIP. Linux x86_64: windowed X11/XWayland preview archive (`ThreatAtlas-Linux-0.4.6-x86_64.tar.gz`), built from the same commit and smoke-tested under Xvfb. Linux is a preview application, not a lock-screen replacement, and has no panorama or Radar. No macOS package is included because normal quarantined installation remains blocked by Gatekeeper and trusted signing/notarisation.

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

## Linux preview limits

- Verified: workspace tests on Ubuntu 26.10; packaged binary `--smoke-test` under Xvfb; a visual window check on a GNOME Wayland desktop (source-build copy).
- Not verified: idle start, lock behaviour, other distributions and GPUs, rendering at other DPI or sizes, long-running stability.
- Panorama on mismatched displays: one run showed spanning FAIL (display 2 stayed black on a 1920x1080 at +1920,+52 setup with a 165 Hz and a 60 Hz display). Accepted only as a known exception for mismatched displays, pending maintainer decision. Matching two-display panorama remains the approved case.
