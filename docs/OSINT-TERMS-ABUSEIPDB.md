# ATLAS-OSINT-009 — AbuseIPDB: terms and handling note

Read by CL on 14 November 2026 for `ATLAS-CL-OSINT-REASSIGN-20261114-01`. **(unverified)** marks anything that
needs a second look. No account or key was created for this note; the fixtures use the shapes in the provider's
published documentation, not live answers.

## What it is

`GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=<n>` with request headers
`Key: <user's own API key>` and `Accept: application/json` returns one JSON object `{"data": {...}}` with, among
others: `ipAddress`, `isPublic`, `ipVersion`, `isWhitelisted`, `abuseConfidenceScore` (0 to 100), `countryCode`,
`usageType`, `isp`, `domain`, `hostnames`, `isTor`, `totalReports`, `numDistinctUsers`, `lastReportedAt`.
Source: https://docs.abuseipdb.com/ (read 14 Nov 2026).

Errors come as `{"errors":[{"detail":"…","status":N}]}`. Rate-limit response headers: `X-RateLimit-Limit`,
`X-RateLimit-Remaining`, `X-RateLimit-Reset` (epoch seconds), and `Retry-After` (seconds) on 429.

## Terms

Source: AbuseIPDB Services Terms of Use, https://www.abuseipdb.com/legal ("Last Updated: 3/15/2023", read 14 Nov 2026).

| Question | Finding |
|---|---|
| Free plan | Free/Individual plans are "for users who want to evaluate AbuseIPDB, contribute IP abuse reports, or use the platform for non-commercial personal projects". |
| Commercial use | "You may not use Free plans for commercial purposes." Commercial use, or use by multiple accounts related to one user or organisation, needs a paid plan. |
| Accounts | "A single user or organization may not register multiple Free user accounts." |
| Resale | "You agree not to reproduce, duplicate, copy, sell, resell or exploit any portion of the Website (including the API and associated data)" without permission. |
| Automated access | Allowed for "authorized use of the AbuseIPDB API". |
| Attribution | None required in anything read. |
| Free-plan limits | 1,000 checks per day, 100 block checks per day (https://www.abuseipdb.com/pricing and the rate-limit table in the API docs). |

### What this means for AtlasSOC

- **Only the user's own key.** The application must never contain or share a key. A key shared by the project
  or by several people would break the one-free-account-per-user rule and could be read as resale.
- **Non-commercial.** Each user's own free key used for their own lookups fits "non-commercial personal
  projects". A company user needs a paid plan; the key entry dialog should say so.
- **No bulk or republication.** Show a result to the person who clicked; do not export, aggregate or publish
  AbuseIPDB data. The local 24 h cache is for that user's own screen only.
- The registry entry (`Source::AbuseIpdb`: key required, non-commercial only, 24 h interval, attribution
  `https://www.abuseipdb.com/api`) is correct. Its licence text, "confirm non-commercial terms before shipping",
  can now read: "Free Individual plan: non-commercial personal use, one account per person, own key only."

## Handling rules (pure functions in `osint_abuseipdb.rs`)

1. **Click only**, one address per click, public addresses only (`is_lookup_allowed`, `check_path`).
2. **Key hygiene:** user-supplied, OS credential store, only in the `Key` header to `api.abuseipdb.com`, never in
   Git, logs, URLs or error text. `looks_like_key` is a shape check only (20–128 letters and digits).
3. **Stop on 401/403** (`CheckError::Auth`) and on **429** (`CheckError::RateLimited`); honour `Retry-After` and
   `X-RateLimit-Remaining: 0` (`RateInfo::must_pause`). Never retry in a loop.
4. **Local budget** of 800 checks per UTC day (`DailyBudget`), below the 1,000 plan limit, because the same key
   may be used by the user's other tools (Fail2Ban is the provider's own example).
5. **24-hour cache** of answers (`cache_fresh`).
6. **Bounded parser:** a score outside 0–100 or a missing or invalid address rejects the whole answer (a wrong
   score must not be shown); over-long, control-character or malformed fields are dropped; lists are capped.

## Privacy

Each lookup sends the clicked IP address and the user's key to AbuseIPDB. Say so in the OSINT sources dialog and
`PRIVACY.md` before shipping (documentation owner: MAC).

## Integration notes for the host worker (hot-file turn, not part of this branch)

- Needs a key-entry step in the settings using the existing credential-store pattern (as for the Cloudflare token).
- Without a key the source shows an honest "key required" state and makes no request.
