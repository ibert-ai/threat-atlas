# Known bugs and limitations

Reviewed against published release notes on 14 November 2026. Current releases are
[screensaver 0.4.8 / build 16](https://github.com/ibert-ai/threat-atlas/releases/tag/v0.4.8),
[AtlasSOC Desktop 0.7.0 / build 13](https://github.com/ibert-ai/threat-atlas/releases/tag/atlassoc-v0.7.0)
and the separate [Linux Desktop preview](https://github.com/ibert-ai/threat-atlas/releases/tag/atlassoc-v0.7.0-linux).
This review checks documentation and source, not execution of downloaded packages.
Historical version-specific observations below are retained; no unverified issue is closed.

## Current release limits

- Screensaver 0.4.8 and Desktop 0.7.0 macOS downloads are Developer ID signed, notarized and stapled according to the published release records. Their assets are listed on GitHub; this documentation pass did not repeat signature or Gatekeeper tests.
- Windows packages remain unsigned. The screensaver has an all-users MSI and ZIP; Desktop has a Just me / Everyone installer and portable ZIP. Automated installer checks are distinct from physical install/upgrade acceptance.
- Windows panorama supports two matching side-by-side displays. Mixed DPI/resolution, hot-plug, physical 150/200% scaling and physical ultrawide acceptance remain incomplete.
- Desktop's beta.2 F11 fullscreen report has not been re-verified on stable 0.7.0. Do not infer resolution from the existence of an F11 command.
- Intel Mac hardware remains untested; Rosetta results are not physical Intel acceptance.
- Linux Desktop is a separate preview, built from newer source than the stable Desktop tag. No Radar, saved settings, updater, fullscreen toggle or native Wayland. CI/Xvfb offline smoke does not establish physical Linux, live feed, manual pointer/hover, GPU, HiDPI or long-run acceptance.
- Immediate feed shutdown can still be delayed by DNS resolution. Full idle/lock, extended soak and signed update/rollback acceptance are not established for these exact packages.

## Historical distribution review — 31 October 2026

The distribution and Windows troubleshooting sections below describe 0.4.0,
0.4.1-rc.1 and 0.4.2-rc.1 unless stated otherwise. They do not describe current
macOS trust or withdraw the current 0.4.8 Windows MSI.

## Known behavior requiring improvement

| Item | Effect | Workaround / status |
|---|---|---|
| OS DNS lookup can delay feed-worker shutdown | Stopping a session does not guarantee immediate worker termination or zero background traffic. Other network operations have explicit timeouts. | No guaranteed immediate-stop workaround. See [quality review](QUALITY.md#still-requiring-acceptance-testing). |
| Old macOS saver can remain selected after upgrading | A legacy 0.2 bundle can show a blank preview while the new saver is installed. This does not establish a defect in the new bundle. | Back up duplicate legacy bundles, select **Threat Atlas SOC**, then reopen System Settings; see [installation guidance](../README.md#install). |

## Distribution limitations

- For the historical versions above, Windows binaries/MSI are unsigned; macOS bundles are ad-hoc signed and unnotarized. OS installation warnings or blocking are expected. Do not disable security protections.
- Automatic updates intentionally reject unsigned builds and prereleases. Use manual installation.
- Published 0.4.0 and 0.4.1-rc.1 have no Linux package. A planned Linux build is not an available download.

## Windows installation troubleshooting

The 0.4.2-rc.1 Windows MSI download was withdrawn 31 October 2026 pending installation-path/integration validation. The standalone Windows ZIP remains available for manual evaluation; no SCR executable defect is established. Existing published package bytes and source/tag remain unchanged.

The hosted MSI lifecycle check establishes file/shortcut installation, preference preservation and uninstall. It does not establish interactive Screen Saver Settings discovery after a browser download. Follow [Windows installation troubleshooting](WINDOWS-INSTALLATION.md) for missing Settings entries, deliberate file-specific Unblock handling, and the System32/SysWOW64 architecture distinction. The current 0.4.8 MSI instead installs one x64 SCR into System32, documents into Program Files and Start Menu items. Its published hosted lifecycle result does not close historical interactive-install reports or establish a fresh physical retest. Do not copy binaries into both system directories.

## Testing gaps, not confirmed bugs

On-device Settings preview, idle/lock transitions, multiple displays/HiDPI, Intel Mac hardware, extended soak and interactive upgrade/rollback acceptance remain incomplete for these published releases. See [QUALITY.md](QUALITY.md#still-requiring-acceptance-testing). Candidate-only test reports do not establish acceptance of a published version.

## Report and resolve

[Report a reproducible bug](https://github.com/ibert-ai/threat-atlas/issues/new) with the exact version/build, OS/architecture, steps, expected/actual behavior and redacted logs. Follow [SECURITY.md](../SECURITY.md) for security concerns.

For each confirmed issue, record affected versions, issue link, workaround, status and the first release containing a verified fix. Keep unverified reports and testing gaps labelled separately. Every release note must include its own **Known bugs** section describing that exact release; do not infer a fix from a later candidate.
