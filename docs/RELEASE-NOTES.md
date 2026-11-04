# Threat Atlas screensaver 0.4.5 — Stable for Windows and Linux

Product 0.4.5, build 13. Robert approved stable publication on 4 November 2026 after reviewing 0.4.4-rc.1. Application implementation is unchanged from approved RC source 47fdc290f03b64ceb441f495c6c4fa2a15138677; numeric version advances to preserve MSI upgrade identity, and the manifest prerelease is null. Final exact-source checks and package hashes accompany downloads. Older releases and RC1 remain available.

## Included and excluded platforms

Windows 10/11 x64: all-users MSI and portable ZIP. Linux x86_64: windowed X11/XWayland preview, without idle screensaver or lock-screen integration. No macOS package: normal quarantined installation remains blocked by Gatekeeper; trusted signing/notarization is unresolved. Stable does not imply trusted publisher signing or universal platform acceptance.

## Windows installation and updates

The MSI installs one x64 SCR into System32, documents into Program Files and three Start Menu items. Check the checksum and approve the administrator prompt. Manual System32 copying requires **Run as administrator**; routine screensaver execution does not. Uninstall the older per-user install first; the MSI refuses overlap. Automatic updates are absent from the all-users MSI pending a reviewed redesign; use verified manual packages. Windows binaries remain unsigned.

## Known bugs and test limits

- Lock-on-resume and installation from a browser-downloaded MSI, including Zone.Identifier/SmartScreen behavior, remain UNTESTED. The owner explicitly accepts release with these notes.
- Native Settings listing, small/full preview and one-minute idle start are owner-reported for the earlier MSI candidate. Layout, real per-user refusal and uninstall were checked by the testing agent. These are prior-candidate results, not fresh 0.4.5 native runs.
- Between-version installer upgrade and post-uninstall Settings state remain untested.
- Linux prior-source retests passed bounded Xvfb smoke, measured resize and held Escape. Owner manual GNOME XWayland resize/Escape passed. Very short Escape taps can be missed because key state is polled per frame. Earlier smoke timeout was not reproduced; its cause remains unconfirmed.
- Physical GPU, multimonitor, broad desktop/hardware and soak acceptance remain untested. Linux is a windowed viewer, not idle/lock integration.
- OS DNS resolution can delay feed-worker shutdown. No immediate-zero-background-traffic guarantee is made.

No simulated threats or TLS validation bypasses. Displayed records are real provider receipts, not verified unique attacks.
