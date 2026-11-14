# Threat Atlas / AtlasSOC product wishlist

Requested by Robert, 14 November 2026. This is the product wishlist for the Threat Atlas
screensaver and AtlasSOC Desktop. It is not the status-page widget wishlist.

All items are **non-commercial only**. A source is in scope only when its terms allow this
project's non-commercial use; a free tier that requires a commercial licence for this use is
out of scope. Provider attribution, licence text and rate limits are acceptance criteria, not
implementation details.

## Cross-cutting requirements

Every OSINT source must satisfy these before it ships:

- **Licence and attribution.** Record the source, licence name, attribution text and link in a
  central registry and show it in the UI (source detail and an "OSINT sources" panel). Do not
  ship a source whose terms are unclear or commercial-only.
- **One worker per source.** Network work runs off the render thread, bounded in memory and
  scope, with a single in-flight request per source.
- **Rate limiting.** Each source has a declared minimum interval and cache TTL. The worker
  honours `Retry-After`, backs off exponentially on errors and never retries a 4xx in a loop.
  The minimum interval is enforced across restarts where the API provides a persisted cooldown
  (the Radar worker already does this).
- **Conditional requests.** Use `ETag`/`If-None-Match` or `If-Modified-Since` where the source
  provides it. A 304 is a success and extends the cache without parsing.
- **No bundled secrets.** Optional API keys are supplied by the user and stored in the OS
  credential store (Windows Credential Manager, macOS Keychain). Never write keys to settings,
  logs, packages or the repository.
- **No probing or fetching of malicious content.** URL/domain sources are displayed and linked;
  the app must not fetch a malware or phishing URL to "enrich" it.
- **Normalised event model.** `timestamp`, `source`, `category`, `ip`/`prefix`, `asn`, `country`,
  `confidence`, `title`, `url`, `first_seen`/`last_seen`. Unknown fields are ignored safely.
- **Source toggles and filters.** The user can enable/disable each layer or panel; the UI shows
  which source produced an item and never presents community reports as confirmed attacks.
- **Tests.** Parser fixtures, rate-limit/cooldown tests, licence-registry coverage and failure
  cases. Unit tests use fixtures and never the live network. Live smoke tests are manual and
  documented separately.
- **Documentation stays English.** Update `docs/ATLAS-SOC-BETA.md` and the source registry when a
  source ships. No release is implied by an implemented wishlist item.

## Work packages and handover

The items are deliberately **unassigned**. As of 14 November 2026, **CL owns distribution** of
the remaining work; CL assigns an item to an authorised agent and records the owner and exact
branch in the private handover (`project-status-dashboard/handovers/mac.json`) before work
starts. See [OSINT-HANDOVER.md](OSINT-HANDOVER.md) for the current implementation state,
contracts and takeover steps.

| ID | Phase | Current state | Suggested next step |
| --- | --- | --- | --- |
| ATLAS-OSINT-001 | FAS 1 | Partial: data, ETag, worker, dialog; panel open | Add a persistent panel and layout tests |
| ATLAS-OSINT-002 | FAS 1 | Partial: list/count/dialog; no map layer | Choose/confirm geo source; add layer and toggle |
| ATLAS-OSINT-003 | FAS 1 | Partial: parser, hourly worker, dialog; panel open | Add dedicated panel; keep CC BY-NC-SA attribution |
| ATLAS-OSINT-004 | FAS 1 | Open — CL distribution | Add GeoLite2/ASN enrichment and filter |
| ATLAS-OSINT-005 | FAS 2 | Open — CL distribution | Auth-Key flow, URLhaus/ThreatFox/SSLBL parsers |
| ATLAS-OSINT-006 | FAS 2 | Open — CL distribution | OTX key, pulse parser, 429 handling |
| ATLAS-OSINT-007 | FAS 2 | Open — CL distribution | Aggregate parser, 1 request/15 min |
| ATLAS-OSINT-008 | FAS 2 | Open — CL distribution | Click-only InternetDB cache |
| ATLAS-OSINT-009 | FAS 2 | Open — CL distribution | AbuseIPDB key and click cache |
| ATLAS-OSINT-010 | FAS 3 | Open — CL distribution | RIS/BGPStream feasibility and sampling cap |
| ATLAS-OSINT-011 | FAS 3 | Open — CL distribution | Watch-list and CT stream consumer |
| ATLAS-OSINT-012 | FAS 3 | Open — CL distribution | DROP/EDROP parser and daily gate |
| ATLAS-OSINT-013 | FAS 3 | Open — CL distribution | PhishTank key and conservative interval |

## FAS 1 — foundation, no new secrets

### ATLAS-OSINT-001 — CISA KEV + EPSS context panel

**Status:** planned.

Add a "Known exploited" panel to the SOC desktop. It lists CISA Known Exploited Vulnerabilities
joined with FIRST EPSS scores: CVE, vendor/product, date added, KEV due date, EPSS score and
percentile. Sort by KEV due date, then EPSS. This is context, not a map layer.

- Sources: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (JSON/CSV),
  [EPSS](https://www.first.org/epss/data.html) (daily CSV; the EPSS API is lookup-only and must
  not be used for bulk sync).
- Licence: CISA catalogue is public; EPSS is published free by FIRST/Empirical Security with
  attribution. Record the exact terms in the registry.
- Rate: KEV and EPSS at most **once per 24 hours**, conditional request, persisted last-success.
  Never bulk-query the EPSS API; use the daily CSV.
- Technical prerequisites: JSON/CSV parsers with fixture tests; join on CVE; cap the retained
  list (e.g. 2,000 newest/most relevant); tolerate missing EPSS scores; display source link;
  no network on the render thread.
- Acceptance: panel opens/closes from settings; shows KEV+EPSS or an honest "no data" state;
  a failed refresh keeps the last good cache with its timestamp; no key required.
- Tests: malformed KEV JSON, missing CVE in EPSS, duplicate CVEs, 304 path, cap enforcement.

### ATLAS-OSINT-002 — Tor exit-node layer

**Status:** planned.

Overlay Tor exit nodes on the map with a distinct informational colour and a source toggle.
Country is resolved from the existing geo data; do not claim that an exit node is malicious.

- Source: [Tor bulk exit list](https://check.torproject.org/torbulkexitlist).
- Licence: Tor Project public list; attribution in the source registry.
- Rate: at most **once per 30 minutes**; conditional request; cache last good list.
- Technical prerequisites: parse IPv4/IPv6, validate addresses, dedupe, cap displayed points,
  map to country via the existing country/geo data; no per-IP external lookups.
- Acceptance: toggle on/off; legend and attribution; no impact on GreyNoise severity colours;
  empty/failed list does not break the map.
- Tests: parser fixtures, invalid addresses, dedupe, refresh gate.

### ATLAS-OSINT-003 — SANS ISC / DShield attack statistics

**Status:** partial — parser, hourly worker and top-ports dialog implemented; dedicated panel pending.

Add a compact "Attack surface" panel with current SANS ISC/DShield aggregates: top target ports,
top source countries/ASNs (if provided), and observation time. Honeypot data is not unique
attacks; label it accordingly.

- Source: [SANS ISC API](https://isc.sans.edu/api/).
- Licence: CC BY-NC-SA 4.0; attribution, non-commercial and share-alike. Terms confirmed
  14 November 2026.
- Rate: **at most one request per hour** (daily aggregates are enough); conditional request
  where available; persisted last-success.
- Technical prerequisites: JSON parser with fixtures; tolerate changed fields; no per-request
  fan-out; cap rows.
- Acceptance: panel distinguishes "honeypot observations" from GreyNoise records; shows the
  observation window; failed refresh keeps the last good data.
- Tests: fixture parsing, missing fields, rate gate.

### ATLAS-OSINT-004 — Geo/ASN enrichment

**Status:** planned.

Improve map placement and add an ASN/network filter. Use MaxMind GeoLite2 for IP→country/ASN
and Team Cymru's DNS-based IP→ASN lookup for on-demand enrichment. This is enrichment, not a
new live feed.

- Sources: [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data),
  [Team Cymru IP-ASN mapping](https://www.team-cymru.com/ip-asn-mapping).
- Licence: GeoLite2 free with attribution under its published terms; Team Cymru terms for the
  free DNS service. Record both. No commercial GeoIP database is required.
- Rate: GeoLite2 at most **weekly** (manual/user-supplied update); Team Cymru DNS on demand,
  cached at least 24 hours, no bulk loops; do not exceed the resolver's normal query rate.
- Technical prerequisites: geo database version/date in the UI; local read-only database
  (no download without a user-supplied licence key); ASN cache; fall back to country-only if
  the database is absent.
- Acceptance: ASN shown in the country/detail panel; ASN filter works offline from cache; no
  startup failure when the database is missing.
- Tests: ASN formatting, cache hits, missing database path, no live DNS in unit tests.

## FAS 2 — optional user-supplied keys

### ATLAS-OSINT-005 — abuse.ch URLhaus / ThreatFox / SSLBL

**Status:** planned.

Add optional malware-URL and C2 layers: URLhaus recent/active malware URLs, ThreatFox IOCs and
SSLBL malicious certificates. Domains/URLs are resolved to IPs only through the app's normal
resolver and cached; the app never downloads a payload.

- Sources: [URLhaus API](https://urlhaus.abuse.ch/api/),
  [ThreatFox API](https://threatfox.abuse.ch/api/), [SSLBL](https://sslbl.abuse.ch/).
- Licence: abuse.ch community API under its fair-use principles; **commercial/for-profit use may
  require the paid abuse.ch commercial API**. This project's use must remain non-commercial.
  Record the exact terms and attribution.
- Rate: URLhaus database dumps are generated every 5 minutes — **never fetch more often than
  every 5 minutes**; use a longer interval (e.g. 15 minutes) in the app. ThreatFox/SSLBL follow
  their published API limits; one request per source per interval, conditional where possible.
- Keys: optional abuse.ch Auth-Key supplied by the user, stored in the OS credential store. The
  app works without it and shows an honest "key required" state.
- Technical prerequisites: Auth-Key handling; gzip/CSV/JSON fixtures; domain→IP cache; source
  category labels (malware URL, C2, certificate); false-positive disclaimer.
- Acceptance: layers can be enabled independently; attribution and key state visible; no key in
  logs; cached data survives restarts; failed refresh keeps last good data.
- Tests: fixtures, key-missing path, rate gate (5-minute floor), invalid URLs/IPs.

**Feodo Tracker is not included:** its datasets are currently empty according to the provider.
Re-evaluate only after the provider restores them.

### ATLAS-OSINT-006 — AlienVault OTX pulses

**Status:** planned.

Optional OTX pulse layer: recent pulses with IPv4/domain indicators and a short description.
Community pulses are not confirmed attacks; label them as community intelligence.

- Source: [OTX API](https://otx.alienvault.com/api).
- Licence: free OTX account/API key; pulse data licences vary. Record the terms and do not
  redistribute restricted pulses. Non-commercial use only.
- Rate: OTX documents a limit around **5 requests/second**; the app must stay far below it:
  at most a few requests per **15 minutes**, honour `429`/`Retry-After`, single worker.
- Technical prerequisites: user-supplied key; pulse parser; indicator validation; cap pulses;
  cache and backoff; source link.
- Acceptance: optional layer; key-missing state; no token in logs; rate limiter verified.
- Tests: fixtures, 429 handling, key-missing path, cap.

### ATLAS-OSINT-007 — ransomware.live aggregate

**Status:** planned.

Add an aggregate ransomware panel: victim counts by country/sector and recent group activity.
Show aggregates, not victim identities, unless a later privacy review approves more.

- Source: [ransomware.live API](https://www.ransomware.live/api) (v2, no authentication;
  PRO optional).
- Licence: free API terms; non-commercial use; attribution. No IPv6 support noted by the
  provider.
- Rate: free v2 is limited to **1 request/minute per endpoint**; use one request per
  **15 minutes**, cache, and honour errors.
- Technical prerequisites: aggregate-only parser; country/sector normalisation; no personal
  data; cache; no automatic retries beyond backoff.
- Acceptance: panel shows the observation window and source; no victim names by default.
- Tests: fixtures, rate gate, empty state.

### ATLAS-OSINT-008 — Shodan InternetDB click enrichment

**Status:** planned.

On an IP detail click, show Shodan InternetDB data: open ports, hostnames, CPEs, tags and known
CVEs. This is enrichment, never a live map layer.

- Source: [Shodan InternetDB](https://internetdb.shodan.io/).
- Licence: **free for non-commercial use only**; commercial use requires an enterprise licence.
  This project must remain non-commercial; record the terms.
- Rate: no key; data is updated weekly. One lookup per user action, cached at least 24 hours;
  no bulk lookups or prefetching.
- Technical prerequisites: IP validation; JSON parser; cache; click-only.
- Acceptance: detail panel shows source and update age; missing data is honest; no automatic
  lookups from map hover.
- Tests: fixtures, cache, invalid IP, no network in tests.

### ATLAS-OSINT-009 — AbuseIPDB click enrichment

**Status:** planned.

Optional AbuseIPDB reputation for an IP detail click: abuse confidence, report count, last
reported, categories. Community reports are not confirmed incidents.

- Source: [AbuseIPDB API](https://www.abuseipdb.com/api).
- Licence: free API tier; confirm the non-commercial terms for this use. Record them.
- Rate: free tier is **1,000 checks/day**; one check per user action, cached at least 24 hours,
  respect rate-limit headers, no bulk checks.
- Technical prerequisites: user-supplied key; IP validation; cache; key-missing state; no key
  in logs.
- Acceptance: optional detail section; source/attribution; failed/limit state honest.
- Tests: fixtures, rate headers, cache, key-missing path.

## FAS 3 — network and high-volume sources

### ATLAS-OSINT-010 — RIPE RIS / BGPStream BGP layer

**Status:** planned.

Add a BGP anomaly layer: hijacks, route leaks and unexpected origin ASNs from RIPE RIS /
BGPStream. BGP data is prefix/ASN-based; render regions or arcs, not fake points.

- Sources: [BGPStream](https://bgpstream.com/), [RIPE RIS](https://ris.ripe.net/).
- Licence: free BGP data with attribution; record the exact terms.
- Rate: one stream/subscription; bounded sampling; no unbounded MRT downloads in the desktop
  process; reconnect with backoff. Prefer a small pre-aggregated feed if the live stream is too
  heavy for a desktop app.
- Technical prerequisites: ASN/prefix validation; optional MaxMind ASN mapping; event schema;
  feature flag; memory cap.
- Acceptance: layer can be disabled; no impact on the GreyNoise feed; clear source/age labels.
- Tests: fixture events, prefix parsing, cap/backoff; no live stream in unit tests.

### ATLAS-OSINT-011 — CertStream filtered certificate-transparency layer

**Status:** planned.

Use Certificate Transparency for newly issued certificates that match configured watch terms
(own brands/domains, lookalike patterns). Do not plot every certificate.

- Source: Certificate Transparency logs / [CertStream](https://github.com/CaliDog/certstream-server).
- Licence: CT logs are public; the hosted CertStream endpoint's terms must be checked; prefer a
  self-hosted or trusted consumer for production. Record the terms.
- Rate: one WebSocket connection; client-side filtering; reconnect/backoff; cap events/second;
  no full-log storage.
- Technical prerequisites: watch-list config; domain normalisation; dedupe; no external
  resolution unless the user enables it.
- Acceptance: watch-list matches only; high-volume protection; clear source/age.
- Tests: fixture certificates, watch-list matching, flood cap, reconnect state.

### ATLAS-OSINT-012 — Spamhaus DROP/EDROP netblock layer

**Status:** planned.

Show Spamhaus DROP/EDROP netblocks as a shaded informational layer. These are netblocks, not
individual attacks.

- Source: [Spamhaus DROP](https://www.spamhaus.org/drop/).
- Licence: free for **non-commercial use with attribution**; commercial use requires a
  Spamhaus licence. Record the exact terms.
- Rate: at most **once per day**; conditional request; cache.
- Technical prerequisites: CIDR parser; reject private/special ranges; map to country/region;
  cap rendered blocks.
- Acceptance: layer toggle; attribution; no confusion with severity colours.
- Tests: CIDR fixtures, invalid ranges, daily gate.

### ATLAS-OSINT-013 — PhishTank phishing layer

**Status:** planned.

Optional phishing URLs, resolved to hosting IPs and shown as a separate layer. The app never
opens a phishing URL automatically.

- Source: [PhishTank](https://phishtank.org/developer_info.php).
- Licence: free API terms; confirm non-commercial use and attribution.
- Rate: follow the published API limit; use a conservative interval (e.g. one request per
  hour), cache, honour errors.
- Technical prerequisites: user-supplied key if required; URL validation; domain→IP cache;
  category label; no auto-fetch.
- Acceptance: layer toggle; attribution; failed refresh keeps cache.
- Tests: fixtures, URL validation, rate gate, no auto-fetch.

## Explicitly out of scope

- **Feodo Tracker** — datasets empty at the time of writing; revisit when restored.
- **VirusTotal public API, Shodan full API, Censys, SecurityTrails, commercial threat feeds** —
  commercial or non-commercial-only terms that do not fit this project's distribution; do not
  bundle them. A future owner decision could add a user-supplied integration after legal review.
- **OpenPhish commercial feed** — the academic/non-commercial programme is not the same as the
  commercial feed; do not ship until the terms are confirmed.
- Any source that requires scraping a web page rather than a documented API/feed.

## Delivery order

1. **FAS 1:** OSINT-001, 002, 003, 004. No new secrets; foundation (registry, rate limiter,
   cache, normalised events, UI toggles/panels).
2. **FAS 2:** OSINT-005, 006, 007, 008, 009. Optional keys; click enrichment; aggregate panels.
3. **FAS 3:** OSINT-010, 011, 012, 013. Network/high-volume sources; stricter caps.

Each item is independently releasable and must not make the app depend on a source being
available. The app remains an observation tool; none of these sources turns it into prevention
software or a confirmed-attack feed.
