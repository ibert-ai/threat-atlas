# ATLAS-OSINT-010 — BGP routing data (RIPE RIS Live, BGPStream): research

Research only; no code. Written by CL on 14 November 2026 for `MAC-ATLAS-OSINT-CL-20261114-01`.
Everything marked **(measured)** was observed on 14 November 2026; everything marked **(unverified)**
needs a check before it is relied on.

## Recommendation

1. **Use RIPE RIS Live directly** (WebSocket + JSON, no key, no library dependency). Do not embed BGPStream.
2. **Never subscribe to the full stream.** Measured: about 5,500 messages/s and 20 Mbit/s (9 GB per hour). Even one
   collector is about 480 messages/s and 1.7 Mbit/s (0.75 GB per hour). A desktop feed must be **opt-in, narrowly
   filtered on the server, and reduced to small per-second counters on the client**.
3. **Show attribution** for RIPE NCC RIS in the OSINT sources dialog and ask RIPE whether the logo and boilerplate
   rule applies to a free open source app (see "Licence").
4. Treat BGP as a *context layer* (activity gauge, watch-list alerts), not a live map of every update.

## RIPE RIS Live

| Item | Finding | Source |
|---|---|---|
| Endpoint | `wss://ris-live.ripe.net/v1/ws/?client=<name>` | RIPE Labs articles (below); connection worked on 14 Nov 2026 |
| Auth | None. No key, token or account. | measured |
| Client id | A `client` query parameter appears in all RIPE examples. Use `threat-atlas-<version>`. Whether it is mandatory is not stated. | RIPE examples |
| Subscribe | `{"type":"ris_subscribe","data":{...}}` | RIS Live home page |
| Filters | `host` (one RRC), `type` (BGP/RIS message type), `require` (key must be present), `peer`, `path` (ASN or pattern on AS_PATH), `prefix`, `moreSpecific` (default true), `lessSpecific` (default false) | published JSON schema `ris_subscribe.schema.json` |
| Socket options | `includeRaw` (Base64-encoded raw BGP message, default false), `acknowledge` (`ris_subscribe_ok`, default false) | same schema |
| Sampling | None offered. The only reduction is server-side filtering; sampling must be done on the client. | schema |
| Full stream | A non-interactive "firehose" exists "for researchers". Not for an application. | RIS Live home page, RIPE Labs |
| Rate limit | **None published** in anything readable. The manual URL linked from RIPE's pages currently shows RIPE's "not found" page. Ask `rislive@ripe.net`. | — |

### Message schema (published)

Envelope: `{"type":"ris_message","data":{...}}`. Every `data` object has `timestamp` (number, seconds, receipt
time at the collector), `peer` (IP), `peer_asn` (string), `id` (unique, sortable per session), `host` (RRC name),
`type`, and `raw` only when requested. `type` values in the schema: `UPDATE`, `KEEPALIVE`, `OPEN`,
`NOTIFICATION`, `RIS_PEER_STATE`. **(measured)** the stream actually sent `STATE` for peer state changes, so a
parser must ignore unknown types and never fail on them.

`UPDATE` adds: `path` (array of ASNs, first upstream first, may end in an AS_SET), `community` (array of pairs),
`origin`, `med`, `aggregator`, `announcements` (array of `{next_hop, prefixes[]}`) and `withdrawals` (array of
prefix strings). One message can carry many prefixes (measured: 2.0 announced prefixes per UPDATE on average).

### Measured volume (3 connections of 15 s, 14 Nov 2026, from one connection in Europe, `client=threat-atlas-research`)

| Subscription | Messages/s | Bandwidth | UPDATEs | Announced prefixes | Withdrawals |
|---|---|---|---|---|---|
| `{}` (everything) | 5,544 | 19.7 Mbit/s (36.9 MB / 15 s) | 82,530 | 165,031 | 6,895 |
| `{"host":"rrc00"}` | 482 | 1.7 Mbit/s (3.1 MB / 15 s) | 7,180 | 12,908 | 1,171 |
| `{"host":"rrc00","type":"UPDATE","require":"announcements"}` | 479 | 1.7 Mbit/s (3.2 MB / 15 s) | 7,189 | 15,192 | 47 |

The server did not throttle or close any connection. 45 seconds in total: this is one sample, not a rate
guarantee, and BGP volume varies by time of day and during incidents.

## What a desktop feed can realistically be

Server-side filters are the only tool, so the design has to be a narrow subscription plus local reduction:

- **Watch list (default use):** `prefix` and/or `path` for the user's own prefixes or ASNs, with `moreSpecific`
  and `lessSpecific` as needed. Near-zero traffic in normal times, and it is exactly the case where BGP data is
  useful to one person (new origin, new more-specific, withdrawal of own prefix).
- **Activity gauge (optional, heavier):** one collector (`host`), `type=UPDATE`. Reduce on the client to counters
  per second (announcements, withdrawals, distinct origin ASNs, distinct peers) and a short ring buffer.
  Bandwidth 1.7 Mbit/s is too much for a background default; make it an explicit opt-in with a visible warning.
- **Hard bounds:** one WebSocket, one subscription at a time, drop messages when the worker falls behind (never
  block the render thread), cap memory per source, reconnect with exponential backoff and jitter, no reconnect
  loop on `ris_error`, `acknowledge` on so a bad filter is visible. Never fetch MRT dumps.

### Proposed derived events (design only)

| Event | Rule | Needs |
|---|---|---|
| Origin change | A watched prefix is announced with an origin ASN different from the last seen one | local state per watched prefix |
| New more-specific | A prefix inside a watched prefix appears | `moreSpecific=true` |
| Withdrawal wave | Withdrawals of watched prefixes from several peers within a window | window counter |
| Activity spike | Announcements/s over a rolling baseline (gauge only) | baseline per hour |

Hijack or leak *classification* is out of scope: a single UPDATE does not prove one. If the project wants
curated hijack/leak events, check whether Cloudflare Radar's BGP endpoints (already a project source, user token)
provide them **(unverified)**.

## Licence and attribution

- RIPE NCC's *RIS Commercial Use Terms and Conditions* (https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/commercial-use/)
  grant a revocable permission by default to organisations that (a) accept the RIPE NCC Terms of Service and
  (b) acknowledge RIPE NCC and RIS by including the **RIPE NCC logo**, a link to https://www.ripe.net/ris and a
  fixed boilerplate paragraph. The page applies those conditions to "paid services, products, reports, or any
  other derivative" and to commercial packaging.
- The commercial-use page does not establish the applicable permission for our free desktop app.
  Eligibility under the project's source policy remains **unverified** until the applicable terms and
  attribution requirements are confirmed; this research note does not authorize enabling the feed.
- **Open question:** whether a free open source desktop app counts as a "product" under that page. The raw-data
  terms page that might settle it could not be read (not found or rate-limited on 14 Nov 2026).
- **Recommended:** show the attribution link and the boilerplate in the OSINT sources dialog regardless. The
  logo is a separate decision for the owner (third-party trademark; project logo rule). Ask `rislive@ripe.net`.
- Suggested registry entry: licence "RIPE NCC by-default permission; ToS and attribution", attribution URL
  `https://www.ripe.net/ris`, key required **no**, non-commercial-only **no**, minimum interval: not applicable
  (stream; bounds above).

## BGPStream (CAIDA)

- Open source framework for live and historical BGP data: C library `libbgpstream` and Python `pybgpstream`,
  both BSD-2-Clause. Dependency `libwandio` is LGPL v3. No Rust binding found. Needs C dependencies at build and
  run time, which is heavy for the current Windows build and adds licence review.
- Data: default broker `https://broker.bgpstream.caida.org/v2` (`/meta`, `/data`), archive files from
  `http://bgp-archive.caida.org/`, live from the RouteViews BMP stream and RIS Live. In other words RIS Live is
  already what it would use for live RIPE data.
- No terms of use, rate limits or citation rule found on the pages read. Underlying data have their own terms
  (RIPE above; Route Views not checked).
- **Verdict:** no benefit over RIS Live for a desktop app; do not embed. RouteViews as a second source can be
  revisited later by its own item.

## Open points for the implementer

1. Does the Windows host's HTTP layer (WinHTTP, `soc_radar.rs`) support WebSockets as needed, or is a small
   WebSocket client needed? **(unverified)**
2. Ask RIPE (`rislive@ripe.net`): rate/connection limits, whether `client` is required, whether the
   attribution rule applies to a free open source application.
3. Decide default: watch-list only (recommended) or also the optional activity gauge.
4. Fixtures: save a handful of real `UPDATE`, `KEEPALIVE` and `STATE` messages (public data) for parser tests;
   no live network in unit tests.

## Sources

- RIS Live: https://ris-live.ripe.net/ , schemas https://ris-live.ripe.net/schemas/v1/ris_subscribe.schema.json ,
  https://ris-live.ripe.net/schemas/v1/ris_message.schema.json , https://ris-live.ripe.net/schemas/v1/ris_message-UPDATE.schema.json
- RIPE Labs: https://labs.ripe.net/Members/chris_amin/ris-live-bgp-message-stream ,
  https://labs.ripe.net/author/ioannis-sermetziadis/usage-patterns-of-ris-live-at-code-bgp/
- RIS commercial use terms: https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/commercial-use/
- BGPStream: https://bgpstream.caida.org/ , https://bgpstream.caida.org/docs/api/broker , https://github.com/CAIDA/libbgpstream
