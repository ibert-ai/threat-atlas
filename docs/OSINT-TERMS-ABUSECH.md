# ATLAS-OSINT-005 — abuse.ch (ThreatFox, URLhaus, SSLBL): terms and handling note

Read by CL on 14 November 2026 for `ATLAS-CL-OSINT-REASSIGN-20261114-01`. **(unverified)** marks anything that
could not be checked. No account or key was created. ThreatFox fixtures are the provider's documented example,
the SSLBL fixture is a real excerpt of a public file, the URLhaus fixture is synthetic.

## Terms

Source: abuse.ch *Terms of Use — abuse.ch Platforms*, https://abuse.ch/terms-of-use/ (effective 4 Nov 2025, last
updated 21 Oct 2026, read 14 Nov 2026), plus the API pages https://urlhaus.abuse.ch/api/,
https://threatfox.abuse.ch/api/, https://sslbl.abuse.ch/blacklist/.

| Question | URLhaus, ThreatFox | SSLBL |
|---|---|---|
| Key | **Required.** Free Auth-Key from https://auth.abuse.ch/ (sign in with X, Google or LinkedIn). ThreatFox: HTTP header `Auth-Key`. URLhaus: the key is part of the export URL. | **None.** The files are public. |
| Licence | Free "under the fair use principles". Access is for authenticated users. | "Free to use without limitations according to Creative Commons principles (CC0) for both commercial and non-commercial purposes" (Terms 3.4, also Feodo Tracker and YARAify). |
| Commercial use | "Companies, networks, or individuals with commercial or for-profit needs may require a paid subscription" (managed by Spamhaus). | Allowed (CC0). |
| Volume | "Query Volume Limits and File Export Volume Limits ... reasonably expected for non-commercial or non-profit purposes"; exceeding them may restrict access, and the login page says accounts with unusually high volume may be limited for up to 72 hours. | Dumps are generated every 5 minutes; "do not fetch it more often than every 5 minutes". |
| Other limits | No high-volume automatic harvesting; no copying or modifying the platforms; data may not be used to train AI models. | — |
| Attribution | None required in anything read; we show source name and link. | None (CC0). |

### What this means for AtlasSOC

- **URLhaus and ThreatFox: only each user's own Auth-Key**, entered in the settings, stored in the OS credential
  store, never shipped, never shared. A shared project key would be harvesting under one identity. A company
  user needs the commercial subscription; the key dialog should say so.
- **Registry corrections** in `osint.rs`: `Source::Sslbl` should be `requires_key: false`,
  `non_commercial_only: false`, licence "CC0 (abuse.ch Terms of Use 3.4)". `Urlhaus` and `ThreatFox` stay as they
  are (key required, non-commercial, 15 minutes, which is above the provider's 5-minute floor).
- **No private use of the data beyond display.** No export, no republishing, no AI training.
- **SSLBL's botnet C2 IP list is deprecated** (the file header says "deprecated on 2025-01-03"; it was empty on
  14 Nov 2026). Only the SSL certificate blacklist (SHA1 fingerprints with a reason, about 850 KB) is useful,
  and it has **no geography**: it suits a recent-listings panel and counts, not a map layer.
- **ThreatFox indicators** are domains, `ip:port`, URLs and hashes. Only `ip:port` can become a map point (via the
  geo/ASN work in ATLAS-OSINT-004). IOCs older than six months are expired by the provider.

## Handling rules (pure functions in `osint_abusech.rs`)

1. **Key hygiene.** `looks_like_auth_key` accepts 16–128 letters and digits only, because the URLhaus key sits in
   the request path (`/v2/files/exports/<key>/recent.csv`); anything else is rejected, never escaped.
   `redact_key` removes the key from any text before it is logged or shown. Never log the URL or path.
2. **Floors.** 15 minutes between successful fetches of one feed (provider: 5). One request in flight per feed.
   Stop on 401/403 and on 429 and wait; never retry in a loop.
3. **Never fetch what the data points to.** URLs, domains and IPs in the feeds are shown with `defang` and linked
   only to the provider's own entry page (`https://urlhaus.abuse.ch/` is enforced for URLhaus entries; ThreatFox
   references must be `https://`).
4. **Bounded parsers:** body limits (8 MB, 16 MB, 4 MB), row caps (5,000, 20,000, 5,000), over-long and
   control-character strings dropped, tags capped, unknown JSON fields ignored.
5. **Header-driven URLhaus CSV.** Columns are found by name in the `# id,dateadded,url,...` header comment; an
   unknown layout is an error, not a guess. **(unverified)** The column names could not be checked against a live
   file because an Auth-Key is required. The first live check by a user with a key must confirm them.
6. **ThreatFox status words:** `ok` is data, `no_result` is an empty list, anything else is an error that carries
   only the cleaned status word.

## Privacy

Each fetch sends the user's Auth-Key to abuse.ch and reveals that the user runs AtlasSOC (use a contact-bearing
`User-Agent`, as the other workers do). Say so in the OSINT sources dialog and `PRIVACY.md` before shipping
(documentation owner: MAC).

## Integration notes for the host worker (hot-file turn, not part of this branch)

- ThreatFox: `POST https://threatfox-api.abuse.ch/api/v1/` with header `Auth-Key`, body from
  `threatfox_recent_body(1)`. URLhaus: `GET https://urlhaus-api.abuse.ch/` + `urlhaus_recent_path(key)`.
  SSLBL: `GET https://sslbl.abuse.ch/blacklist/sslblacklist.csv`, conditional request (ETag) allowed.
- Without a key, URLhaus and ThreatFox show an honest "key required" state and make no request; SSLBL works
  without one.
