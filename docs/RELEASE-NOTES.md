# Threat Atlas SOC 0.4.2-rc.1 — Beta

Beta prerelease, 31 October 2026; product/MSI version 0.4.2, Mac build 10.
Version 0.4.0 remains the latest stable release. Preserve earlier downloads.

## Changes since 0.4.1-rc.1

- Country borders and classification shading with independent expiry timestamps. High-volume traffic no longer removes an active country highlight when the 600-record recent buffer turns over.
- Linux x86_64 windowed preview with portable archive packaging and hosted Xvfb smoke checks. This is not an idle screensaver or lock-screen integration.
- Installed version, prerelease and build displayed in the shared renderer footer.
- Windows scaling/layout regression coverage and MSI ProductVersion 0.4.2 for a distinct upgrade identity.
- Retains live GreyNoise telemetry, certificate-validated TLS, clocks, native Mac lifecycle repairs and screenshot thumbnails.

## Signing and updates

Windows SCR/MSI are unsigned. Mac bundles contain Intel and Apple Silicon slices and are ad-hoc signed, not Developer ID signed or notarized. OS warnings or blocking may occur; do not disable protections. Automatic updates reject unsigned packages and ignore prereleases. Install manually. Linux is an unsigned application preview.

## Verification and limits

Publication requires quality/core tests, universal Mac build/native lifecycle/updater checks, Windows tests/build, Linux build/Xvfb smoke, MSI packaging and MSI lifecycle checks on the published source commit. Download checksums accompany all packages. Earlier-commit checks do not establish final-source acceptance.

Billy reports Windows and Linux candidate tests and 0.4.1-to-0.4.2 MSI upgrade/replacement/uninstall passed on source574e22e6. MAC independently passed13 core tests, formatting, Clippy, version tests, native Apple Silicon packaging/signatures, native saver lifecycle and offline updater safety on that source. Hosted final-source results must pass before publication.

Physical Intel Mac and Linux desktop acceptance, Windows interactive Settings, idle/lock transitions, multiple monitors/HiDPI, signed upgrade/rollback and extended soak remain incomplete. Visual approval does not imply those unrun tests passed. Linux Xvfb smoke is not physical desktop validation. See docs/QUALITY.md.

## Known bugs

- OS DNS resolution can delay feed-worker shutdown; immediate termination and zero background traffic after stopping are not guaranteed.
- A legacy Mac0.2 saver may remain selected after upgrade and show a blank preview. Select Threat Atlas SOC, back up duplicate legacy bundles and reopen System Settings.
- Signing and physical acceptance gaps above remain limitations. No trusted automatic-update support is claimed for this beta.

Use the per-user Windows MSI, universal Mac ZIP or Linux application archive. Keep known-working stable0.4.0 available. Source commit and Mac build are appended by the exact-commit publication job.
