# OSINT sources — implementation handover

Last updated: 2026-11-14T08:40:21Z
Branch: `codex/osint-sources`
Latest commit at handover: `ab4b11f`
Wishlist: [docs/WISHLIST.md](WISHLIST.md)
Private coordination handover: `project-status-dashboard/handovers/mac.json`,
reference `MAC-ATLAS-OSINT-001-20261114-01`.

This document exists so another agent can continue without reconstructing the context. The
wishlist is the requirement; this file is the current state, contracts and next actions.

## Status

**Partial FAS 1.** The source registry, parsers, rate gates and first worker are implemented.
The remaining FAS 1 items and all of FAS 2/3 are still open. No release, no merge, no new
provider key and no commercial source is part of this work.

Implemented:

- `crates/core/src/osint.rs`
  - Source registry for all 17 wishlist sources: licence summary, attribution link, minimum
    interval, whether a user key is required, and whether the provider is non-commercial-only.
  - `RateGate` with persisted cooldown, exponential failure backoff and `Retry-After`.
  - CISA KEV JSON parser (skips malformed records), EPSS CSV parser (daily file, not the
    lookup-only API), KEV+EPSS join and cap, Tor bulk exit list parser.
  - Six unit tests: registry safety, rate gate/backoff, KEV parse, EPSS parse, join ordering
    and Tor dedupe. No live network in tests.
- `crates/windows/src/soc_osint.rs`
  - Background worker for CISA KEV, FIRST EPSS and Tor exit list.
  - Persisted gates and cache under `%LOCALAPPDATA%\ThreatAtlasSOC\osint-state.json` and
    `osint-cache.json`; a restart cannot bypass the provider floor.
  - KEV/EPSS at most once per 24 hours; Tor at most once per 30 minutes; `Retry-After` and
    backoff on failures. EPSS is fetched through the redirect-following public WinHTTP helper
    and gunzipped with `flate2`.
  - Started only after licence consent; never by the offline smoke test.
- `crates/windows/src/soc_host.rs`
  - Right-click items: **Known exploited (KEV + EPSS)**, **Tor exit nodes**,
    **Refresh OSINT**, **OSINT sources / licences**.
  - Dialogs show top KEV entries with EPSS/due date, Tor count and age, worker notes, and the
    full source registry with licence/attribution/minimum interval/key requirement.
- `crates/windows/src/soc_radar.rs`
  - Added `https_get_public`, which follows redirects for keyless public data while keeping
    cookies disabled. Token-bearing `https_get` still never follows redirects.
  - Exposed `retry_after_s` to the OSINT worker.

Not yet implemented:

- FAS 1: SANS ISC/DShield panel; MaxMind GeoLite2 + Team Cymru ASN enrichment; actual Tor
  map layer (the current UI shows count/age only); persistent UI toggles and a dedicated
  OSINT panel; conditional requests/ETag (the worker relies on the rate floor today).
- FAS 2: abuse.ch URLhaus/ThreatFox/SSLBL, AlienVault OTX, ransomware.live, Shodan InternetDB,
  AbuseIPDB. Keys/terms handling and per-source workers are not started.
- FAS 3: RIPE RIS/BGPStream, CertStream, Spamhaus DROP/EDROP, PhishTank.
- Feodo Tracker is intentionally absent; the provider currently reports empty datasets.

## Contracts

Every new source must use the `threat_atlas_core::osint` registry. Do not hard-code a licence
or interval in the host.

- **Non-commercial only.** If a provider's current terms require a commercial licence for this
  project's use, stop and raise it; do not ship the source.
- **Attribution** is shown in the OSINT sources dialog and in the source detail. The registry
  `attribution` URL is part of the test contract.
- **Rate limits** are a floor, not a target. Respect the higher of the provider rule and the
  registry value. Persist the gate and honour `Retry-After`.
- **No secrets in Git, logs or packages.** FAS 2 keys are user-supplied and stored through the
  existing OS credential-store pattern; the worker must work without a key and show an honest
  "key required" state.
- **No probing.** Never fetch a malware/phishing URL from the app. Display/link only.
- **No render-thread blocking.** One worker per source, bounded memory, one in-flight request.
- **Tests use fixtures.** Live provider checks are manual and documented, never unit tests.

## Verification

- `cargo test -p threat-atlas-core osint::` — 6 passed (2026-11-14).
- Windows CI run `43576353483` for `ab4b11f`: **PASS**. The workflow is
  `.github/workflows/windows-soc.yml`; it ran fmt, clippy with `-D warnings`, workspace tests,
  the Windows build, smoke test and installer checks. The earlier run at `180ee85` failed
  clippy for unused `View` fields and an elidable lifetime; both were fixed in `ab4b11f`.
- Do not mark the wishlist item done until the Windows CI run for the exact commit is green and
  the UI/dialog has been seen on Windows.

## How to take over

1. Read `docs/WISHLIST.md` and pick one item. Do not implement two sources in one change unless
   they share a parser.
2. Branch from `codex/osint-sources` (or from `main` after this branch merges) and keep the
   existing `osint` registry/rate-gate types.
3. For a new JSON/CSV source: add a parser and fixture tests in `crates/core/src/osint.rs`,
   add the source spec, then add the worker branch in `crates/windows/src/soc_osint.rs`.
4. For a new UI surface: follow the current dialog pattern for a quick slice, or add a panel in
   `crates/core/src/soc.rs` only after checking the classic/dashboard layout tests.
5. Run `cargo test -p threat-atlas-core osint::` and `cargo fmt --all -- --check`.
6. Push the branch and dispatch `.github/workflows/windows-soc.yml`; record the exact run id,
   commit and result in the private handover before asking another agent to continue.
7. Update the private `mac.json` handover and this file when the state changes.

## Known risks / open decisions

- **SANS ISC endpoint and terms** need confirmation before implementation; do not guess fields.
- **Tor as a map layer** needs a country/geo source. The bulk list is IP-only; MaxMind GeoLite2
  or a country-bearing Tor endpoint must be chosen and licensed first. The current count/age
  dialog is not the promised layer.
- **KEV panel** is currently a dialog, not a persistent panel. A panel needs a layout decision
  in the classic and dashboard themes.
- **EPSS** uses the daily CSV; do not switch to bulk API queries.
- **Conditional requests** are not implemented yet; adding ETag/If-Modified-Since must not
  weaken the persisted rate floor.
- The app remains an observation tool. KEV/EPSS, Tor exits and community feeds are context,
  not confirmed attacks on the user's assets.
