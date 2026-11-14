# ATLAS-OSINT-007 — ransomware.live (free API v2): terms and handling note

Read by CL on 14 November 2026 for `ATLAS-CL-OSINT-REASSIGN-20261114-02` (taken over from Seek, who had not
started). **(unverified)** marks anything that could not be checked. The fixtures are **synthetic**: the shape
follows the live answer, but all names and values are invented, so no real victim is stored in the repository.

## What it is

`GET https://api.ransomware.live/v2/recentvictims` returns a JSON array of the latest disclosed incidents (100
records, about 100 KB on 14 Nov 2026) with the fields `activity` (sector), `attackdate`, `claim_url`, `country`
(ISO two-letter or empty), `data_size`, `description`, `discovered`, `domain` (masked), `group`, `press`, `ransom`,
`screenshot`, `url` and `victim` **(measured)**. Other documented paths (https://www.ransomware.live/apidocs):
`/groups`, `/group/<name>`, `/countryvictims/<code>`, `/sectorvictims/<sector>`, `/victims/<year>/<month>`,
`/certs/<country>` and more. **Careful:** `/v2/stats`, `/v2/countrystats`, `/openapi.json` and `/docs` answered with
status 200 and an **HTML page**, not JSON, so the parser rejects HTML explicitly **(measured)**.

## Terms

Source: https://www.ransomware.live/api (API comparison, read 14 Nov 2026) and https://www.ransomware.live/about.

| Question | Finding |
|---|---|
| API v2 (free) | "Free", "No authentication", "Rate limited: 1 req/min per endpoint", "No advanced features", "No new features", "No IPv6 support", "Victims delayed vs PRO". |
| Who may use it | "**Personal use only.** For anyone who wants to remain anonymous, this API is available for free but with limitations. **It is not intended for corporate or business use.**" |
| API PRO | A free API key (500,000 calls a month, "no rate limit, but fair use applies"); "For corporate and business use, read the Terms & Conditions before using the API." The Terms & Conditions page was not found (`/terms` is a 404) **(unverified)**. |
| Licence / attribution | None stated; the site credits many sources on its About page. We show the source name and link. |
| What the data is | Publicly disclosed claims from ransomware groups' leak sites, aggregated. The site "does not host or distribute any leaked data". The claims are the criminals' own; the project's own group descriptions say some groups' claims "cannot be verified". |

### What this means for AtlasSOC

- **Fits as a personal, non-commercial tool.** Each user runs the free v2 API from their own computer for their
  own use; the project does not run a shared server. A company using AtlasSOC commercially is outside "personal
  use": the settings text should say so and point to API PRO and its terms.
- **Aggregate only, by design.** The application shows how many incidents, in which countries and sectors, by
  which groups, in the last days. It **never keeps or shows victim names, domains, links, screenshots or
  descriptions.** The parser reads only country, group, sector and two times; all other fields are skipped
  without being stored (a test checks the debug output of the result for victim strings).
- **Say what it is:** "claims published by criminal groups; not verified; delayed compared with the provider's
  paid tier".
- The registry entry (`Source::RansomwareLive`: no key, non-commercial only, 15 minutes, attribution
  `https://www.ransomware.live/api`) is correct and needs no change.

## Handling rules (pure functions in `osint_ransomware.rs`)

1. One request per 15 minutes at most (the provider allows one per minute per endpoint), counting failed attempts
   (`fetch_due`). Stop on 429 (`classify_status`); no retry loop. Only `/v2/recentvictims` is used.
2. Body at most 1 MB; at most 500 records; an HTML page or any non-array body is an error (`parse_recent`).
3. Group names at most 64 characters, sectors at most 60, control characters rejected, country must be two
   upper-case letters, "Not Found" is no sector; times more than a day in the future are dropped.
4. `summarize` counts a window (for example 7 days), ranks the top countries, groups and sectors, and ignores
   incidents without a time.

## Privacy

Each request tells ransomware.live that this computer runs AtlasSOC (use a contact-bearing `User-Agent`). No
address or account of the user is sent. Say so in the OSINT sources dialog and `PRIVACY.md`.

## Integration notes for the host worker (hot-file turn, not part of this branch)

- Show counts per country (a country-level shading or a list), per group and per sector; a map point per incident
  is not possible (the data has a country, not a location) and not wanted.
- A country with an empty code is counted in the total but not in the country list.
