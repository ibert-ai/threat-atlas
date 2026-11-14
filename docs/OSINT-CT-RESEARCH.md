# ATLAS-OSINT-011 — Certificate Transparency (CertStream): research and stop report

Research only; no code. Written by CL on 14 November 2026 for `ATLAS-CL-OSINT-DISTRIBUTION-20261114-01`.
**(measured)** = observed on 14 November 2026. **(unverified)** = needs a check before it is relied on.

## Result: stop. The public CertStream stream is not operating.

The distribution handover said to check first whether the public CertStream service still works and to stop and
report if it does not. It does not deliver data, so no `osint_certstream.rs` code is written.

| Check | Result |
|---|---|
| `https://certstream.calidog.io/` | HTTP 200 (Cloudflare in front) **(measured)** |
| WebSocket `wss://certstream.calidog.io/` and `/full-stream` | The upgrade succeeds (HTTP 101), then **no data at all**: 0 bytes in 16 s, 40 s and 20 s on three connections **(measured)** |
| `/latest.json` (the 25 most recent certificates the server holds) | All 25 are from one log (Google "Argon2026h1") and were seen about **379 days ago**; none is recent **(measured)** |
| crt.sh entries for `certstream.calidog.io` itself | The last certificate expired on 4 March 2024 **(measured)** |
| Reports from users | The hosted service went down in December 2023 and again from February 2024; one comment blames a lapsed paid subscription **(unverified, user comments in a GitHub issue)** |

The server software is alive: `CaliDog/certstream-server` (Elixir, MIT licence, last push 17 Feb 2026), and the
community Go reimplementation `d-Rickyy-b/certstream-server-go` is described as a drop-in replacement. Both are
code to run yourself, not a hosted service with any promise of availability.

## Options

| Option | What it is | For a desktop app |
|---|---|---|
| A. Hosted CertStream | The public instance above | **Not usable** (no data) |
| B. Self-hosted certstream server | The user runs the MIT Elixir or Go server and points AtlasSOC at it | Only for power users; an optional "custom endpoint" setting at most. The wire format is documented (see below). |
| C. Read the CT logs directly | Poll the public logs (Google's log list, version 97, 13 Nov 2026, shows 17 usable classic logs and 22 usable tiled logs) | Not realistic: the CertStream README says it ships "millions of certificates a day" from these logs. Even at about 1 to 2 KB per entry that is gigabytes per day, to filter locally. **(estimate)** |
| D. Watch-list queries on crt.sh | Ask Sectigo's crt.sh for certificates for the user's own domains, once per domain per hour or less | Realistic and tiny. Measured: one query for a small domain took 2.2 s and returned 15 entries (4.7 KB) as JSON with `id`, `issuer_name`, `common_name`, `name_value`, `not_before`, `not_after`, `serial_number`. |
| E. Do not build it | — | Honest if no source fits |

crt.sh facts: the home page states "© Sectigo Limited 2015-2026"; **no terms of use, rate limit or API
documentation were found on it**, and it is not an official API **(unverified)**. Outages and throttling are
commonly reported by users **(unverified)**. Facebook's and Cloudflare's CT monitors need an account and are not
considered.

## Recommendation

1. **Change the item.** Re-scope ATLAS-OSINT-011 from "live CT stream layer" to **"CT watch-list"**: the user
   enters their own domains; AtlasSOC asks crt.sh for each, at most once per hour (staggered, 24 h cache of the
   last seen `id`s) and shows **new** certificates (domain names, issuer, validity, link to the crt.sh entry).
   That is the use case that matters to one person (a certificate for my domain I did not request).
2. **Opt-in, best effort, honest about failures:** show "crt.sh did not answer" instead of an empty list; no retry
   loop; back off on errors.
3. **Privacy:** the watched domains are sent to crt.sh (Sectigo), which reveals what the user monitors. Say so in
   the OSINT sources dialog and `PRIVACY.md`.
4. **Terms first:** ask Sectigo (crt.sh) whether automated, low-volume watch-list queries from a free open source
   desktop app are acceptable, and record the answer. No terms were found to rely on. **Until that answer, build
   nothing.**
5. **Optional later:** a custom certstream-compatible endpoint for power users who run their own server.

This needs a decision because the source changes: owner (Robert) or the OSINT coordinator (MAC).

## If a stream is ever used: the documented message (for fixtures)

`{"message_type":"certificate_update","data":{"update_type":"X509LogEntry","leaf_cert":{"subject":{...},
"extensions":{...},"not_before":<epoch>,"not_after":<epoch>,"all_domains":[...],"as_der":"..."},"chain":[...],
"cert_index":<n>,"seen":<epoch>,"source":{"url":"...","name":"..."}}}`; `/` omits the DER, `/full-stream`
includes it; heartbeat messages also occur. `/latest.json` returned `{"messages":[...]}` with the same objects
**(measured)**.

## Sources

- https://certstream.calidog.io/ , https://certstream.calidog.io/latest.json (measured 14 Nov 2026)
- https://github.com/CaliDog/certstream-server (README, licence MIT) and https://github.com/d-Rickyy-b/certstream-server-go
- Google CT log list: https://www.gstatic.com/ct/log_list/v3/log_list.json
- https://crt.sh/ (query `?q=<domain>&output=json`)
