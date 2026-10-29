# Threat Atlas SOC 0.4.0

Official unsigned release, 29 October 2026.

## Signing status

Windows SCR and MSI files are unsigned. macOS universal bundles are ad-hoc signed,
not Developer ID signed or notarized. Systems may warn or block installation.
Do not disable OS security protections. Automatic updates remain unavailable
until trusted publisher signing is configured.

## Changes since 0.3.0-rc.1

- UTC and system-local clocks with UTC offset and DST handling.
- macOS first-frame/lifecycle repairs and screenshot thumbnails.
- Optional publisher-verified updater implementation, rejecting unsigned updates.
- PowerShell 5.1/7 compatibility and installer/updater/rendering regression checks.
- Consistent version metadata across settings, bundles, installers and source.

## Validation and limitations

Publication requires automated quality, Windows, macOS, updater, MSI and MSI
install/uninstall checks to pass for the source commit below. SHA-256 checksums
accompany the assets. Real Mac Settings preview after restart, idle/lock transitions,
multiple monitors, Intel hardware, extended soak, interactive Windows setup and
upgrade/rollback acceptance remain incomplete. Signed upgrades have not been
validated. See docs/QUALITY.md for details and reviewed dependency exceptions.

Install the Windows MSI per user. On macOS, extract the ZIP and install
ThreatAtlasSOC.saver. Keep earlier known-working releases if needed.
