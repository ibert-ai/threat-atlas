# Threat Atlas SOC 0.4.1-rc.1 — Beta

Beta prerelease, 29 October 2026; product version 0.4.1, Mac build 9.
Version 0.4.0 remains the latest stable release.

## Changes since stable 0.4.0

- Advance patch development metadata consistently across Rust, MSI and macOS.
- Refresh release, quality, signing and automatic-update documentation.
- No runtime feature changes are introduced by this beta.
- Retains the dual clocks, macOS lifecycle repairs and screenshot thumbnails from 0.4.0.

## Signing and updates

Windows SCR/MSI files are unsigned. macOS universal bundles are ad-hoc signed,
not Developer ID signed or notarized. Systems may warn or block installation;
do not disable OS security protections. Automatic updates reject unsigned
builds and ignore prereleases. Install this beta manually if you choose to test it.

## Verification and limitations

Publication requires all six quality/platform/installer CI checks to pass for
the source commit below. SHA-256 checksums accompany all downloadable packages.
On-device Mac Settings preview, idle/lock transitions, multiple monitors, Intel
hardware, extended soak, interactive Windows setup and upgrade/rollback
acceptance remain incomplete. Signed upgrades have not been validated.
See docs/QUALITY.md for details and reviewed dependency exceptions.

Install the per-user Windows MSI, or extract the Mac ZIP and install
ThreatAtlasSOC.saver. Keep the stable 0.4.0 download available if you need it.

## Known bugs

- OS DNS lookup can delay feed-worker shutdown; immediate termination and zero background traffic after stopping are not guaranteed.
- After upgrading from legacy macOS 0.2, the old saver may remain selected and show a blank preview. Select **Threat Atlas SOC**, back up duplicate legacy bundles and reopen System Settings.
- See [known bugs and limitations](https://github.com/ibert-ai/threat-atlas/blob/main/docs/KNOWN-BUGS.md) for workarounds and reporting. Unsigned distribution, manual-only updates and incomplete platform acceptance are documented limitations, not newly confirmed runtime bugs.
