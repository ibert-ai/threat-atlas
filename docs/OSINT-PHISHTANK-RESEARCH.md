# ATLAS-OSINT-013 — PhishTank: research and stop report

Research only; no code. Written by CL on 14 November 2026 for `ATLAS-CL-OSINT-REASSIGN-20261114-02` (taken over
from Seek, who had not started). The distribution handover said: check whether PhishTank still issues new keys and
what the terms are; if not, report and stop instead of writing a parser. **(measured)** = observed on 14 November
2026. **(unverified)** = needs a check.

## Result: stop. A key cannot be obtained, and the terms could not be read.

| Check | Result |
|---|---|
| Registration page `https://phishtank.org/register.php` | "**New user registration temporarily disabled.**" **(measured)** |
| Terms of Use `https://phishtank.org/terms_of_use.php` | The page returned the site's start page, not terms text; **the terms were not readable** **(measured)** |
| Developer page | "If you do intend to fetch these files automatically, please register for an application key ... Without this key, you will be limited to a few downloads per day." |
| Operator | Cisco Talos Intelligence Group |
| Data files | Hourly ("updated every hour on the hour"): `https://data.phishtank.com/data/online-valid.csv` (also `.xml`, `.json`, `.php`, and `.gz`/`.bz2`). A request without a key redirected to a signed CDN address and answered; the CSV was about 8.7 MB with the header `phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target` **(measured, one header request and a 600-byte range request)** |
| API | `https://checkurl.phishtank.com/checkurl/` (POST); a descriptive `User-Agent` is required; over-limit gives HTTP 509; "users going grossly over the limit ... may ... be blocked at the firewall level". |

So the keyless download works today, but only "a few" per day, the exact limit is not stated, and a person who wants
a key cannot get one while registration is closed. The registry entry says `requires_key: true`; for a public
application most users could never satisfy that.

## Options

| Option | What it is | Verdict |
|---|---|---|
| A. PhishTank keyless daily file | One download per day of `online-valid.csv.gz`, no key | Technically possible. **Blocked on terms**: they could not be read, and the data licence and any non-commercial or redistribution rule are unknown. |
| B. PhishTank with the user's own key | For people who already have a key | Works for old members only; closed to new users. |
| C. OpenPhish Community feed | Free text list of phishing URLs, updated every 12 hours (`https://openphish.com/feed.txt`; measured: about 15 KB, one URL per line) | A candidate. Its page marks commercial use as "limited" and links a Terms of Use that was **not read**. URLs only (no brand or time metadata in the free feed). **(unverified)** |
| D. abuse.ch URLhaus | Malware distribution URLs, already item 005 | Not phishing, but covers the "bad URL" layer for users with a key |
| E. Do not build a phishing layer | — | Honest if no source fits |

## Recommendation

1. **Do not write `osint_phishtank.rs` now.** Keep ATLAS-OSINT-013 open but marked blocked: "registration closed, terms
   unreadable".
2. **Ask PhishTank** (via their contact page or developers mailing list) for the written terms and whether a keyless
   daily download of `online-valid.csv.gz` by a free open source desktop app is acceptable. Until there is an answer,
   build nothing.
3. **Read OpenPhish's Terms of Use** and decide whether the Community feed replaces PhishTank as ATLAS-OSINT-013. That is
   a source change and needs a decision (owner or OSINT coordinator).
4. **Whatever source is chosen:** never fetch or open a listed URL; show it defanged and link only to the provider's own
   entry page; downloads at most daily (hourly files, "no need to check every minute"); bounded parser; a clear
   "no data / not available" state.

## Sources

- https://phishtank.org/developer_info.php , https://phishtank.org/api_info.php , https://phishtank.org/register.php
- https://data.phishtank.com/data/online-valid.csv (header and first rows, measured)
- https://openphish.com/phishing_feeds.html , https://openphish.com/feed.txt (measured)
