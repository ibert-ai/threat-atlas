# Cloudflare Radar · macOS-only alpha

Request ATLAS-RADAR-MAC-20261102-01, Robert, 2 November 2026. Separate experiment branch `codex/macos-cloudflare-radar-alpha`; no production release and no Windows/Linux Radar integration authorized. The standalone Windows-first wall roadmap remains a separate workstream (PR16).

## Research and data semantics

Cloudflare exposes a free aggregated API, available on all plans, using a custom token with Account > Radar > Read. It is public-interest telemetry, not anonymous unauthenticated streaming and not individual attack events. Data is **CC BY-NC 4.0**, distinct from the MIT application code. Attribution is required. Commercial SOC deployment requires separate permission/appropriate licensing; accepting the dialog does not grant such permission.

Sources checked 2 November 2026:
- https://developers.cloudflare.com/radar/ — free API, datasets and CC BY-NC 4.0 notice.
- https://developers.cloudflare.com/radar/get-started/first-request/ — token permissions and metadata.
- https://developers.cloudflare.com/radar/investigate/outages/ — annotations, start/end and affected locations.
- https://developers.cloudflare.com/api/resources/radar/subresources/netflows/methods/timeseries/ — network traffic series and normalization.
- https://developers.cloudflare.com/radar/investigate/network-layer-attacks/ — network attack geolocation reflects data-centre attribution, not attribution to a human attacker.
- https://developers.cloudflare.com/fundamentals/api/reference/limits/ — general cumulative limit 1200 requests/5 min; respect endpoint policies and Retry-After.
- https://creativecommons.org/licenses/by-nc/4.0/legalcode.en — licence text.

Suitable later layers include L3/L7 attack trends, HTTP/bot breakdowns, DNS adoption and BGP anomalies. These are not all implemented. No inferred source/destination attack arcs are created from Radar aggregates.

## Implemented alpha

Native AppKit sidebar beside the existing map, for both the Mac app and saver. Optional global outage list (last 7 days, at most 5 returned annotations) and global normalized traffic trend (24 hours, hourly samples). Display source, fetch/dataset time, layer status and partial/stale/auth/rate-limit states. No geography, ASN filters, attack overlays or multiscreen wall support claimed in this alpha.

Radar is disabled by default. Open the app's Radar alpha settings menu (or saver options after consent), enable the integration and layers, and enter a Radar Read token into the secure field. Token is stored only in macOS Keychain; no token is committed, logged or stored in preferences. Empty field retains the token. Preferences use a shared named suite. No live calls without consent and a token. Requests use HTTPS, ephemeral sessions, normal TLS validation and timeouts. One singleton refreshes two endpoints every ten minutes per host process. Multi-process coordination, persistent response cache, cross-host quota coordination and token deletion UI remain future work. Separate screensaver host processes can have separate clients; this is not yet a production SOC wall collector.

Failed requests retain previous values with stale/error labels; unauthorized requests stop until settings retry, 429 respects a minimum ten-minute delay and numeric Retry-After. Synthetic parser fixtures are tests, never substituted for live data. No Cloudflare payload is included in Git.

## Mandatory consent and release requirements (all versions)

Robert requires first-start mandatory licence acceptance across app/screensaver products and reconfirmation for every new released version/build, including RCs. The alpha implements the Mac gate keyed by full release + build + notice/legal-code hashes. Decline exits the app. The saver does not start telemetry and displays a review-in-app notice rather than blocking the OS saver host with a modal dialog. Only the person reviewing the terms may accept; automated tests do not accept on their behalf.

`docs/CLOUDFLARE-LICENSE.json` records reviewed notice/legal-code fingerprints. Every CI quality run and direct Mac build fetches the current published terms with `scripts/check-cloudflare-license.py`. Changed or unreachable terms fail closed. Review the change, update the notice/UI, deliberately record review (`--record-review --header`), rerun tests and disclose the change before creating an RC/release. Do not automatically update the baseline in CI. Version/build changes regenerate `macos/RadarLicense.h`, invalidating old acceptance. Add this gate and native acceptance UX to every future platform version; Windows execution is assigned to Billy and is not implemented here. Linux remains out of scope. No retrospective modification of already published binaries.

## Validation

Compile native sources with Clang `-Werror`. Run `macos/TestRadar.m` (synthetic parser fixtures), core Rust regression tests and the normal Mac package build. Live API/schema accuracy, network error injection, Keychain consent prompts, multi-process behavior, full manual user acceptance and physical multiscreen validation require follow-up; no live API token was supplied. Native alpha binaries remain ad-hoc signed/unnotarized and are not a trusted production release.

Verified on MAC 2 November 2026: Rust 1.99.1; 13 core regression tests pass; 10 native parser/consent assertions pass; 3 release-gate tests pass (exact RC/build identity, changed terms rejection, unavailable terms rejection); Clang syntax with warnings as errors; version and source scans pass; native ARM64 saver/package built and strict signatures verified; native lifecycle smoke passes without accepting user terms. Intel/universal package not built in this run. Live Radar was not called. No end-user acceptance was performed. The package retains baseline 0.4.2-rc.1/build10 identifiers on this development branch; it is not a new official RC. Assign and review a new version/build and rerun the licence check before distribution.
