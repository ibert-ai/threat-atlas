# OSINT source changes: CT watch-list and phishing feed (research, 14 Nov 2026)

Status: research only. No code. Decisions needed from Robert (owner) and MAC before any module is written.
Follows `OSINT-CT-RESEARCH.md` (CertStream dead) and `OSINT-PHISHTANK-RESEARCH.md` (PhishTank unusable).

## A. Replace CertStream (011) with a CT watch-list

Need: tell the user when a certificate is logged for a domain they care about (their own domains, look-alikes).
A watch-list of the user's own domains fits this better than a firehose, and it keeps traffic small.

| | Cert Spotter (SSLMate) v1 API | crt.sh |
|---|---|---|
| Documentation | Yes, public API docs | None (a public web front end for a PostgreSQL database) |
| Terms | Published; unauthenticated use is for personal/evaluation queries | None published |
| Limits seen | `x-ratelimit-limit: 100` per hour unauthenticated; free tier 100 single-hostname and 10 full-domain queries per hour with the user's own key | Not stated; known to time out under load |
| Stability promise | May change without notice (stated) | None |
| Fit | Good for a small per-user watch-list, polled slowly | Not suitable as a dependency |

Recommendation: **Cert Spotter v1, user's own API key (free tier), polled at most hourly per watched domain, user-entered domains only.**
Never ship or share a key. Without a key the module stays off (consistent with the own-key rule). crt.sh is not used as a dependency.
Open points for the owner: (1) accept a source that "may change without notice"; (2) watch-list length cap (suggest 10 domains, matching the free full-domain quota); (3) wording for the privacy text: watched domain names are sent to SSLMate.

## B. Replace PhishTank (013)

| Source | Licence / terms | Fit |
|---|---|---|
| OpenPhish | Personal use only. Commercial use (including security operations, threat intelligence, detection, product development, automation) prohibited. No redistribution or display to third parties without written consent. | **Ruled out** for a distributed tool unless OpenPhish gives written consent. |
| PhishStats | Free tier with account (anonymous/registered/paid tiers). ToS section 5 forbids sharing, reselling or redistributing raw feeds without written permission and bulk download beyond tier quotas. Data updated about every 90 minutes. `api.phishstats.info` was **not reachable** from this machine during the probe (connection failed), so the API format and limits are unverified. | Possible only as click-only per-address lookups with the user's own account key. Cannot be bundled or mirrored. |
| Phishing.Database (community project) | MIT licence (repository `LICENSE`, 2018–2025 copyright lines). Plain text lists on GitHub raw. | Best licence fit. Risks below. |

Phishing.Database facts checked on 14 Nov 2026:
- Files: `phishing-domains-ACTIVE.txt` about 11 MB, `phishing-links-ACTIVE.txt` about 66 MB, `phishing-IPs-ACTIVE.txt` about 100 KB.
- Repository not archived; about 1.6k stars.
- **Latest commit seen is 2 Oct 2026** ("Update Feeds [skip ci]", earlier ones every few hours). That is about six weeks old, so the feed may have stalled or moved. This must be re-checked before any decision.
- The MIT licence covers the project; the lists aggregate third-party reports, so we should not claim more than "MIT, as published" and should credit the project.

Recommendation: **Phishing.Database `phishing-domains-ACTIVE.txt` as the v1 source, conditional on the feed being fresh again** (rule: treat data older than 7 days as stale and stop using it, same pattern as GeoLite staleness in `osint_geo.rs`).
- Download at most once per 24 h with `If-None-Match` (ETag), cap the body (say 16 MB), parse line by line, keep a hash set of domains only.
- Do not fetch the 66 MB links list; do not fetch any listed URL; defang when displaying.
- If the feed stays stale, fall back to PhishStats click-only lookups with the user's own key, after the API is verified.
- OpenPhish only if written consent is obtained (owner could ask).

Open points for the owner: (1) approve Phishing.Database as v1 given the stale-feed risk; (2) 16 MB cap and 24 h cadence OK; (3) whether to ask OpenPhish for consent; (4) whether PhishStats lookups are wanted as a second source.

## Next steps (after decisions)
1. Terms note `docs/OSINT-TERMS-<NAME>.md` per chosen source (terms before code).
2. Layer A module with fixtures, no network in tests, bounded parser.
3. Registry entries replacing 011 and 013, then Layer B host integration one source per commit with green Windows CI.
4. Add to `docs/VERSION-FEATURES.md` and settings privacy text.
