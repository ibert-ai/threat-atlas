# ATLAS-OSINT-012 — Spamhaus DROP (DROP, DROPv6, ASN-DROP): terms and handling note

Read by CL on 14 November 2026 for `ATLAS-CL-OSINT-REASSIGN-20261114-02` (taken over from Seek, who had not
started). **(unverified)** marks anything that could not be checked. The fixtures are real excerpts of the public
files, fetched the same day.

## What it is

Three public, keyless JSON-lines files at `https://www.spamhaus.org/drop/`:

| File | Content | Size on 14 Nov 2026 |
|---|---|---|
| `drop_v4.json` | IPv4 netblocks: `{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}` | about 107 KB, 1,759 records |
| `drop_v6.json` | IPv6 netblocks, same shape | about 6 KB, 90 records |
| `asndrop.json` | AS numbers: `{"asn":245,"rir":"arin","domain":"…","cc":"US","asname":"PRC-AS"}` | about 40 KB, 455 records |

Each file ends with a metadata line: `{"type":"metadata","timestamp":<epoch>,"size":…,"records":…,"copyright":"(c)
2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}`. The old text files
(`drop.txt`) still exist but Spamhaus recommends the JSON files. **eDROP was merged into DROP on 10 April 2024**,
so the registry name "Spamhaus DROP/EDROP" should become "Spamhaus DROP".

## Terms

Sources: https://www.spamhaus.org/drop/ (FAQ) and https://www.spamhaus.org/drop/terms/ ("Spamhaus Don't Route Or Peer
Lists Terms of Use"), read 14 Nov 2026.

| Question | Finding |
|---|---|
| Cost | "The DROP Lists are provided to you free of charge subject to these Terms." No key. |
| Commercial use | **No non-commercial-only restriction in the Terms of Use.** (Spamhaus sells separate commercial datasets and feeds through Spamhaus Technology; those are other products.) The registry's `non_commercial_only: true` and "commercial licence required" are therefore not supported by the terms and should be corrected. |
| Fetch rate | "Please DO NOT auto-fetch the DROP list more than once per hour!" ... "Automated downloads must be at least one hour apart." Once per day "is more than enough in most cases". "Excessive downloads may result in your IP being firewalled from the Spamhaus website." |
| Naming | **"You may under no circumstances use ... the 'Spamhaus' name ... or any reference to the 'Spamhaus data' in your marketing, promotional or any other commercial materials."** (Terms 3.2) |
| Intellectual property | The content is protected by copyright and database right; no licence is granted beyond use under the Terms (3.1). |
| Currency | "Almost all allocations change over time. Please check regularly ... They should not be imported into your networks filters without subsequent reviews." (4.2) |
| Liability | None (free of charge). The lists are "advisory 'drop all traffic' lists". |
| Attribution | No attribution rule found; the terms forbid promotional use of the name instead. |

### What this means for AtlasSOC

- **Use is allowed and free**, no key, no account.
- **Naming rule (important for marketing):** the application may show the source in its own OSINT sources dialog
  and documentation to say where data comes from. **The name "Spamhaus" must not appear in promotional material:**
  the website feature list, release announcements, social posts and store texts say "malicious netblock lists" or
  "DROP-style lists" at most, and must not name Spamhaus. Seek (marketing) and MAC (website, documentation) need to
  know this. Whether in-app and documentation mentions count as "other commercial materials" is a question for
  Spamhaus; the project is not commercial, and the mentions are factual source labels **(unverified: ask Spamhaus
  if the project ever sells anything)**.
- **Advisory data, not a verdict.** A hit means "this range is on the DROP list", with its SBL record. Never show it as
  proof that a machine or a person is malicious.

## Handling rules (pure functions in `osint_spamhaus.rs`)

1. **Fetch once a day, never closer than an hour, failures count** (`fetch_due`): an attempt that failed cannot be
   repeated sooner than one hour, and a success is repeated after 24 hours.
2. **Bounded parsers:** body at most 2 MB; at most 20,000 records per list; a record must have a valid prefix (host
   bits zero), an SBL id (`SBL` plus digits) and a registry; records of the wrong address family, in private or
   reserved space, or with control characters are skipped and counted; a file with neither records nor metadata is
   an error.
3. **Age:** the list's own generation time is shown; after 7 days the data carries a warning and is not used for
   decisions (`is_stale`).
4. **Lookup** against the listed netblocks, most specific first (`lookup`), and an AS check (`asn_listed`).

## Privacy

Each download tells Spamhaus that this computer runs AtlasSOC (use a contact-bearing `User-Agent`, as the other
workers do). The lists are checked locally; no address from the user's screen is sent to Spamhaus.

## Integration notes for the host worker (hot-file turn, not part of this branch)

- Three requests to `www.spamhaus.org`, one worker, conditional requests (ETag/Last-Modified) allowed, persisted
  last-attempt and last-success times so a restart cannot shorten the gap.
- Registry corrections to make in `osint.rs`: name "Spamhaus DROP", `non_commercial_only: false`, licence text
  "Free of charge under the DROP Terms of Use; do not use the Spamhaus name in promotional material", interval 24 h.
- A CIDR layer on the map needs a rendering decision (a netblock is not a point): list or count first.
