# ATLAS-OSINT-004 — IP-to-ASN and country (Team Cymru, optional GeoLite2): terms and handling note

Read by CL on 14 November 2026 for `ATLAS-CL-OSINT-DISTRIBUTION-20261114-01`. **(unverified)** marks anything that
could not be checked. Owner decision 14 Nov 2026 (`ATLAS-OWNER-OSINT-DECISIONS-20261114-01`): Team Cymru ASN is the
default, a GeoLite2 file is optional, supplied by the user, never bundled.

## Team Cymru IP-to-ASN mapping (default)

Source: https://www.team-cymru.com/ip-asn-mapping (read 14 Nov 2026).

- **Cost and terms:** "Free, forever. Underwritten by Team Cymru as a community service." Interfaces: WHOIS (TCP
  43), DNS and HTTPS; data from 50+ BGP peers, refreshed every 4 hours; bulk speed "10k IPs / min".
  No separate usage terms or per-client limit were found on the page **(unverified: the site's "Intelligence
  Terms" link was not opened)**. No attribution rule found; we show the source name and link.
- **Real answers (queried 14 Nov 2026, saved as fixtures):**
  - `1.1.1.1.origin.asn.cymru.com TXT` → `"13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"`
  - `8.8.8.8.origin.asn.cymru.com TXT` → `"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"`
  - IPv6 uses the 32 reversed nibbles and `origin6.asn.cymru.com`:
    `…origin6.asn.cymru.com TXT` for `2606:4700:4700::1111` → `"13335 | 2606:4700:4700::/48 | US | arin | 2011-11-01"`
  - `AS13335.asn.cymru.com TXT` → `"13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"`
- **The country is not a location.** It is the registry country of the announced prefix. Show it as "registered in",
  never as where a machine is. A prefix with more than one origin returns several AS numbers in one answer
  (handled; the fixture for that case is synthetic).

### Handling rules (pure functions in `osint_geo.rs`)

1. Public addresses only (`is_lookup_allowed`, `origin_query`).
2. **Cache by prefix:** one answer covers every address in the announced prefix, so the longest matching prefix is
   reused for 24 hours (`PrefixCache`, at most 4,096 prefixes).
3. **Query budget:** a burst of 30, then one DNS query per second (`QueryBudget`). Far below the stated bulk speed.
4. Bounded parsers: at most 8 origin AS numbers, names at most 200 characters, control characters, bad prefixes
   (host bits set, length too long), bad dates and bad AS numbers are rejected; an invalid country code is dropped.
5. **ASN filter** typed by the user (`AS13335, 15169`): at most 100 entries, bad entries are an error.

### Privacy

The address being looked up is sent as a DNS name, so it passes through the user's DNS resolver (often the
internet provider) and reaches Team Cymru. Say so in the OSINT sources dialog and `PRIVACY.md`; the lookup should
happen only for addresses the feature needs to place (for example Tor exit nodes the user asked to see).

## MaxMind GeoLite2 (optional, user-supplied)

Sources: GeoLite End User License Agreement, https://www.maxmind.com/en/geolite2/eula (updated 12 Feb 2026);
https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/ ; https://www.maxmind.com/en/geolite-free-ip-geolocation-data
(all read 14 Nov 2026).

| Question | Finding |
|---|---|
| Access | Needs a MaxMind account and a licence key; downloading or using the database means accepting the EULA. 30 database downloads per day. |
| Currency | "You must delete GeoLite databases within 30 days of a new release." |
| Attribution | Required ("Attribution required" in the plan table; the EULA incorporates Creative Commons Attribution-ShareAlike 4.0). |
| Use | "No use of the GeoLite Data for identifying specific households or individuals." Accuracy is not guaranteed; GeoLite City is "not recommended for commercial use cases". City answers are an area (latitude, longitude and an accuracy radius up to 1,000 km), not a point. |
| Redistribution | MaxMind lists redistribution options separately; **we avoid the question: the database is never bundled or downloaded by AtlasSOC.** |

### Design (owner decision applied)

- The user downloads GeoLite2 (ASN and optionally Country or City) from their own MaxMind account and points
  AtlasSOC at the `.mmdb` file in the settings (`looks_like_geolite_file`). The application never downloads it and
  never holds a licence key.
- The update obligation is the user's. The application reads the file's build time and warns when it is older than
  30 days (`geolite_is_stale`); a stale file is not used for new lookups.
- Show `GEOLITE_ATTRIBUTION` in the OSINT sources dialog whenever the file is in use.
- City results are drawn as an area with the accuracy radius, never as an exact point, and never described as a
  person or household.
- **Not in this module:** reading `.mmdb` files needs a new dependency (the `maxminddb` crate). CL must approve it,
  check its licence and run `cargo audit` and `cargo deny` first (part of the optimisation round). Until then the
  default path (Team Cymru) is complete without it.

## Integration notes for the host worker (hot-file turn, not part of this branch)

- The host needs a DNS TXT query (Windows: the DNS API in `windows-sys`; macOS: the system resolver through the Swift
  side or a small C call). The core only builds the name and parses the text.
- For the Tor layer (ATLAS-OSINT-002) the registry country can place a point at the country's centre, labelled
  "registered in"; a GeoLite2 file, when present, refines it.
