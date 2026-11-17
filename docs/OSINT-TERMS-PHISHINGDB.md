# ATLAS-OSINT-013 — Phishing.Database domains list: terms and handling note

Written by CL on 14 November 2026 after the owner approved the source change (ATLAS-OWNER-OSINT-SOURCE-DECISION-20261114-01).
Replaces PhishTank (see `OSINT-PHISHTANK-RESEARCH.md`, `OSINT-SOURCE-CHANGES-RESEARCH.md`). **(unverified)** marks anything that needs
a second look.

## What it is

Plain text, one domain per line: `https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt`
(about 11 MB on 14 Nov 2026; the project also publishes a 66 MB URL list and a 100 KB IP list, which we do **not** use).
Project: https://github.com/Phishing-Database/Phishing.Database (about 1.6k stars, not archived).

## Terms

| Question | Finding |
|---|---|
| Licence | MIT (repository `LICENSE`, copyright lines 2018–2025: Mitchell Krog, Nissar Chababy, Phishing.Database Contributors). |
| Third-party data | The lists aggregate reports from others. We claim only "MIT, as published" and credit the project. |
| Attribution | "Phishing.Database (MIT licence)" with the project link. Keep the MIT notice in the third-party notices file. |
| Freshness | Last commit seen 2 Oct 2026 ("Update Feeds"), about six weeks old. **The feed may be stalled.** |

### What this means for AtlasSOC

- **Download once per 24 h**, conditional on the ETag where the host allows; cap the body at 16 MiB; stream-parse line by line.
- **Keep only 64-bit hashes of domains** in memory (about 9 MB), not the strings.
- **Stale rule:** if the list has not changed for 7 days, stop using it and tell the user (`FeedState::is_stale`). This protects users from a dead feed.
- **Never fetch a listed domain.** Show listed names defanged (`evil[.]example`).
- A hit means "this name is on the community phishing list", not proof of compromise. Shared hosting parents are matched exactly only.
- Fallback if the feed stays stale: PhishStats click-only lookups with the user's own key. Its terms forbid redistributing the raw feed; its API was unreachable in the probe, so format and limits are unverified.

## Privacy

The download sends no user data (the list is fetched whole and matched locally). GitHub sees the user's IP address as for any download.
