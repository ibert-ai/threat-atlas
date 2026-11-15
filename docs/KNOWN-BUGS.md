# Known bugs and limitations

Reviewed 31 October 2026. Applies to published 0.4.0, 0.4.1-rc.1 and 0.4.2-rc.1 unless stated otherwise. This is not a claim that no other bugs exist.

## AtlasSOC Desktop 0.8.0-rc.1 (build 15)

Release candidate. These are the known limits of this build, not a claim that no other bugs exist.

| Area | Limitation / expected behavior | Status |
|---|---|---|
| Windows signing | Windows packages are unsigned and may trigger SmartScreen or organisational policy. Do not disable protections. | Expected; code signing is a later version. |
| Small and scaled screens | The layout is the older fixed 1440x900 design that only grows in width. On small or scaled laptop screens (for example 1920x1080 at 125 %) the bottom of the window can be cropped. | Known. The 1920x1080 base scaling is designed in SOC-RESOLUTIONS.md and not built yet. Workaround: use fullscreen (F11) or a larger window. |
| Multiple screens | There is no option yet to span or mirror the SOC view over several screens. | Planned. |
| Windows testing | Install, upgrade and the menus were checked on two physical PCs; keyed sources on Windows (Credential Manager entry) have had little hardware testing. Long soak is limited. | See QUALITY.md. |
| macOS | Keyed sources were checked live on macOS with the maintainer's own keys. First use of a key asks once for Keychain access ("Always Allow"). | Checked. |
| ransomware.live | Depends on the provider. Its certificate was expired on 14 November 2026, which showed as "no data" on Windows until the provider fixed it. | Provider-side. |
| Phishing.Database | The public list may be stalled; the app marks it stale after 7 days and stops using it. | Known feed risk. |
| Cert Spotter | The free tier allows 100 single-hostname and 10 full-domain queries per hour; the app uses at most 8 full-domain queries/hour and 10 watched domains. The provider may change the API. | Free-tier limits. |
| Keys and privacy | Every keyed source needs the user's own key. Click lookups send the clicked public IP to the provider; certificate watch sends the watched domains. The app never fetches a URL/domain/IP from threat data. | Documented in PRIVACY.md. |
| AI help prompt | The prompt was tested with Claude models only (including one simulating a small model), never with a real Hugging Face, DeepSeek or local model, and not against live provider pages. Assistants can be wrong; the guide and your screen win. | Disclosed. |
| Spamhaus naming | The DROP terms forbid using the Spamhaus name in marketing/promotional material. Product docs and the in-app label may name it factually. | Marketing restriction. |
| Not included | Team Cymru ASN, MaxMind GeoLite2 file reading and RIPE RIS/BGPStream are not in this release. | Not in scope. |

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
