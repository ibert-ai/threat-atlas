# Known bugs and limitations

Reviewed 30 October 2026. Applies to published 0.4.0 and 0.4.1-rc.1 unless stated otherwise. This is not a claim that no other bugs exist.

## Known behavior requiring improvement

| Item | Effect | Workaround / status |
|---|---|---|
| OS DNS lookup can delay feed-worker shutdown | Stopping a session does not guarantee immediate worker termination or zero background traffic. Other network operations have explicit timeouts. | No guaranteed immediate-stop workaround. See [quality review](QUALITY.md#still-requiring-acceptance-testing). |
| Old macOS saver can remain selected after upgrading | A legacy 0.2 bundle can show a blank preview while the new saver is installed. This does not establish a defect in the new bundle. | Back up duplicate legacy bundles, select **Threat Atlas SOC**, then reopen System Settings; see [installation guidance](../README.md#install). |

## Distribution limitations

- Windows binaries/MSI are unsigned; macOS bundles are ad-hoc signed and unnotarized. OS installation warnings or blocking are expected. Do not disable security protections.
- Automatic updates intentionally reject unsigned builds and prereleases. Use manual installation.
- Published 0.4.0 and 0.4.1-rc.1 have no Linux package. A planned Linux build is not an available download.

## Testing gaps, not confirmed bugs

On-device Settings preview, idle/lock transitions, multiple displays/HiDPI, Intel Mac hardware, extended soak and interactive upgrade/rollback acceptance remain incomplete for these published releases. See [QUALITY.md](QUALITY.md#still-requiring-acceptance-testing). Candidate-only test reports do not establish acceptance of a published version.

## Report and resolve

[Report a reproducible bug](https://github.com/ibert-ai/threat-atlas/issues/new) with the exact version/build, OS/architecture, steps, expected/actual behavior and redacted logs. Follow [SECURITY.md](../SECURITY.md) for security concerns.

For each confirmed issue, record affected versions, issue link, workaround, status and the first release containing a verified fix. Keep unverified reports and testing gaps labelled separately. Every release note must include its own **Known bugs** section describing that exact release; do not infer a fix from a later candidate.
