# ATLAS-OSINT-008 — Shodan InternetDB: terms and handling note

Read by CL on 14 November 2026 for `ATLAS-CL-OSINT-REASSIGN-20261114-01`. Facts come with their source;
**(unverified)** marks anything that needs a second look before it is relied on.

## What it is

`GET https://internetdb.shodan.io/<ip>` returns what Shodan knows about one IP address: open ports, hostnames,
CPE software identifiers, tags and CVE ids. No key, no account. Published description: "Fast IP lookups to get
information about open ports" (OpenAPI document at https://internetdb.shodan.io/openapi.json, one operation
`GET /{ip}`, schema `Host` with `cpes`, `hostnames`, `ip`, `ports`, `tags`, `vulns`).

Measured on 14 November 2026 with one request for `1.1.1.1` (a public DNS address): HTTP 200, JSON, about 220
bytes, served from Cloudflare's cache with `cache-control: public, max-age=432000` (5 days). An address with no
data returns HTTP 404 with `{"detail":"No information available"}`. The sample is saved as a test fixture.

## Terms

| Question | Finding | Source |
|---|---|---|
| Key needed? | No. | Shodan, "Introducing the InternetDB API" https://blog.shodan.io/introducing-the-internetdb-api/ |
| Commercial use? | Free for non-commercial use. A company may use it, but not to build commercial products it charges money for. Commercial products need a Shodan licence. | same post; search summary of Shodan's own pages |
| Attribution? | None required in anything read. We still show the source name and link. | — |
| Rate limit | Not clear. Shodan's developer documentation (https://book.shodan.io/developer-apis/internetdb/) is reported to allow bursts of up to 10,000 requests per second **(unverified)**; Shodan's account pages state 1 request per second for API plans. | search summary 14 Nov 2026 |

Fits the project rule "non-commercial sources only": AtlasSOC is free and open source. The existing registry
entry (`Source::ShodanInternetDb`: non-commercial only, no key, 24 h interval, attribution
`https://internetdb.shodan.io/`) is correct and needs no change.

## Handling rules (implemented as pure functions in `osint_internetdb.rs`)

1. **Click only.** A lookup happens only when the user clicks an address. Never in bulk, never on a timer, never
   for every address on the map.
2. **Public addresses only.** Private, loopback, link-local, carrier-grade NAT, benchmarking, documentation,
   multicast, reserved and IPv4-mapped IPv6 addresses are never sent (`is_lookup_allowed`).
3. **Conservative rate.** At most one request in flight and at least one second between requests, whatever the
   undocumented provider limit really is (`gap_elapsed`).
4. **24-hour cache** of every answer, including "no information" (`cache_fresh`); the provider's own cache is
   longer (5 days), so a fresher answer is not expected.
5. **No retry on 404.** It means "no data", not an error.
6. **Bounded and cleaned answer:** body at most 64 KB, lists capped, control characters and over-long strings
   dropped, only well-formed CVE ids kept, ports 1–65535, unknown fields ignored.

## Privacy

Each lookup sends the clicked IP address to Shodan (a third party) and reveals that the user's computer
asked about it. The OSINT sources dialog and `PRIVACY.md` must say so before the feature ships. This is not yet
written (documentation owner: MAC).

## Integration notes for the host worker (hot-file turn, not part of this branch)

- Host `internetdb.shodan.io`, path from `lookup_path`, HTTPS with certificate validation, no cookies, a
  contact-bearing `User-Agent` consistent with the other OSINT workers.
- Persist the cache in the existing OSINT state directory; never log the clicked address.
- Show: ports, hostnames, tags, CVE ids (link a CVE to the KEV panel entry when it is in KEV).
