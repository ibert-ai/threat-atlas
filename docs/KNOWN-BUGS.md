# Known bugs and limitations

Reviewed 31 October 2026. Applies to published 0.4.0, 0.4.1-rc.1 and 0.4.2-rc.1 unless stated otherwise. This is not a claim that no other bugs exist.

## AtlasSOC Desktop 0.8.0-beta.1 — draft, not released

This section is for the proposed OSINT beta. No 0.8.0 package exists yet; the integration and the
optimisation/documentation gates are in progress. Do not treat these as shipped-version limitations.

| Area | Limitation / expected behavior | Status |
|---|---|---|
| Windows signing | Windows packages will be unsigned in the beta and may trigger SmartScreen or organisational policy. Do not disable protections. | Expected; code signing is a separate later version. |
| Windows testing | Install/upgrade, own-key entry, source dialog, restore of the previous screensaver and physical multi-monitor/DPI behavior still need Billy's test PCs. | NOT RUN for 0.8.0. |
| macOS/Linux | macOS and Linux packages are not part of the first beta; each follows the OS-by-OS rule and its own checks. The existing Linux preview remains windowed, without Radar/settings/updater and physically untested. | Out of the first-beta scope. |
| OSINT integration | Layer B (worker, settings, panels, dialogs) is being integrated by CL. A source is not available just because its parser module exists. | In progress. |
| Phishing.Database | The public list's last upstream commit was 2 October 2026; it may be stalled. The app marks it stale after 7 days and stops using it. The PhishStats fallback needs the user's own key and its API shape/limits are unverified. | Known feed risk. |
| Cert Spotter | The free tier allows 100 single-hostname and 10 full-domain queries per hour; the app uses at most 8 full-domain queries/hour and 10 watched domains. The provider may change the API. | Free-tier limits; unverified at runtime. |
| OTX | The field names/time format follow the provider SDK, not a live keyed answer; fixtures are synthetic. A first keyed run must confirm them. | Unverified live shape. |
| abuse.ch URLhaus | CSV column names are read from the header, but the live column set is unverified without an Auth-Key. A keyed user must confirm the first file. | Unverified live layout. |
| Keys and privacy | Every keyed source needs the user's own key. Click lookups send the clicked public IP to the provider; Cert Spotter sends watched domains. The app never fetches a URL/domain/IP from threat data. | Documented in PRIVACY.md. |
| Spamhaus naming | The DROP terms forbid using the Spamhaus name in marketing/promotional material. Product docs and the in-app source label may name it factually; social/website promotion must not. | Marketing restriction. |
| RIPE RIS, GeoLite2, signing | RIPE RIS/BGPStream is research only; GeoLite2 file reading needs a new dependency; Windows signing is separate. | Not in beta. |

## Known behavior requiring improvement

| Item | Effect | Workaround / status |
|---|---|---|
| OS DNS lookup can delay feed-worker shutdown | Stopping a session does not guarantee immediate worker termination or zero background traffic. Other network operations have explicit timeouts. | No guaranteed immediate-stop workaround. See [quality review](QUALITY.md#still-requiring-acceptance-testing). |
| Old macOS saver can remain selected after upgrading | A legacy 0.2 bundle can show a blank preview while the new saver is installed. This does not establish a defect in the new bundle. | Back up duplicate legacy bundles, select **Threat Atlas SOC**, then reopen System Settings; see [installation guidance](../README.md#install). |

## Distribution limitations

- Windows binaries/MSI are unsigned; macOS bundles are ad-hoc signed and unnotarized. OS installation warnings or blocking are expected. Do not disable security protections.
- Automatic updates intentionally reject unsigned builds and prereleases. Use manual installation.
- Published 0.4.0 and 0.4.1-rc.1 have no Linux package. A planned Linux build is not an available download.

## Windows installation troubleshooting

The 0.4.2-rc.1 Windows MSI download was withdrawn 31 October 2026 pending installation-path/integration validation. The standalone Windows ZIP remains available for manual evaluation; no SCR executable defect is established. Existing published package bytes and source/tag remain unchanged.

The hosted MSI lifecycle check establishes file/shortcut installation, preference preservation and uninstall. It does not establish interactive Screen Saver Settings discovery after a browser download. Follow [Windows installation troubleshooting](WINDOWS-INSTALLATION.md) for missing Settings entries, deliberate file-specific Unblock handling, and the System32/SysWOW64 architecture distinction. System-wide deployment and dual-directory copying require separate Windows validation; no installer fix is claimed here.

## Testing gaps, not confirmed bugs

On-device Settings preview, idle/lock transitions, multiple displays/HiDPI, Intel Mac hardware, extended soak and interactive upgrade/rollback acceptance remain incomplete for these published releases. See [QUALITY.md](QUALITY.md#still-requiring-acceptance-testing). Candidate-only test reports do not establish acceptance of a published version.

## Report and resolve

[Report a reproducible bug](https://github.com/ibert-ai/threat-atlas/issues/new) with the exact version/build, OS/architecture, steps, expected/actual behavior and redacted logs. Follow [SECURITY.md](../SECURITY.md) for security concerns.

For each confirmed issue, record affected versions, issue link, workaround, status and the first release containing a verified fix. Keep unverified reports and testing gaps labelled separately. Every release note must include its own **Known bugs** section describing that exact release; do not infer a fix from a later candidate.
