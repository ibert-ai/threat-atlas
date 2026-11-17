# ATLAS-OSINT-006 — AlienVault OTX (LevelBlue Open Threat Exchange): terms and handling note

Read by CL on 14 November 2026 for `ATLAS-CL-OSINT-REASSIGN-20261114-01`. **(unverified)** marks anything that
could not be checked. No account or key was created. All fixtures are **synthetic**: the JSON shape follows the
provider's SDK and published descriptions, because every real answer needs an API key.

## What it is

`GET https://otx.alienvault.com/api/v1/pulses/subscribed?limit=<n>&modified_since=<ISO time>` with the header
`X-OTX-API-KEY: <user's own key>` returns `{"count", "next", "previous", "results": [pulse, ...]}`. `next` is an
absolute link to the following page. Source: the provider's own Python SDK,
https://github.com/AlienVault-OTX/OTX-Python-SDK (`OTXv2.py`, read 14 Nov 2026: endpoint, header, `limit`,
`modified_since`, `results`, `next`). A pulse carries `id`, `name`, `description`, `author_name`, `created`,
`modified`, `tlp`, `public`, `tags`, `malware_families`, `targeted_countries`, `attack_ids`, `industries`,
`references` and `indicators` (each with `indicator`, `type`, ...). **(unverified)** The exact field list and the
time format (`2026-11-14T08:12:45.123000`, UTC without zone) are taken from SDK use and third-party descriptions,
not from a live answer.

## Terms

Source: *OTX End User Agreement*, https://levelblue.com/terms/otx-eula (read 14 Nov 2026; OTX now belongs to
LevelBlue).

| Question | Finding |
|---|---|
| Cost / commercial use | "OTX is free to end users for non-commercial use." |
| Access | "Limited, terminable, non-exclusive, non-transferable" access to the OTX platform. |
| Use limitations | The user must not copy, mirror, republish, download, display, transmit or distribute OTX or its software, must not "license, sell, rent, lease, transfer, assign, distribute, display, disclose, or otherwise commercially exploit" it or make it available to a third party (for example as a service bureau), and must not "share private, non-public indicators". A breach allows immediate termination. |
| Keys | One OTX API key per account **(unverified, third-party source)**. |
| Rate limit | No figure published in anything readable. A third-party write-up says "no hard cap" and asks for reasonable use **(unverified)**. The SDK retries a 429 up to five times with growing delays; that is the SDK's behaviour, not a provider limit. |
| Attribution | None required in anything read. |

### What this means for AtlasSOC

- **Only each user's own OTX account and key.** The agreement is between OTX and the person who signed up, and it
  is non-transferable. The application must never ship or share a key.
- **Non-commercial.** A company using AtlasSOC commercially is outside the free terms. The key dialog should say
  so.
- **Show, do not redistribute.** Pulses are shown to the user whose key fetched them. No export, no republishing,
  no sharing between users. The local cache stays on that computer.
- **Private pulses are never kept.** The subscribed feed can include private (non-public) pulses from the user's
  groups. `parse_pulses` keeps only `public` pulses with TLP white or green; private, amber and red pulses are
  counted as skipped and dropped.
- The registry entry (`Source::Otx`: key required, non-commercial only, 15 minutes, attribution
  `https://otx.alienvault.com/api`) is correct and needs no change.

## Handling rules (pure functions in `osint_otx.rs`)

1. **Key hygiene.** User-supplied, OS credential store, sent only in the `X-OTX-API-KEY` header to
   `otx.alienvault.com`, never in Git, logs, URLs or error text. `looks_like_key` is a shape check only
   (32–128 letters and digits).
2. **The paging link cannot leak the key.** `next` comes from the server and the key goes with every request,
   so `next_path` accepts only `https://otx.alienvault.com/api/v1/pulses/subscribed?...`: same host, no
   credentials in the URL, no port, no fragment, no other endpoint. Anything else ends the poll.
3. **One attempt per poll, no retry loop.** 401/403 stops until the user fixes the key; 429 stops until
   `Retry-After` (bounded to a week) and at least the next regular interval.
4. **Bounded polling:** at least 15 minutes between polls, at most 5 pages of 50 pulses per poll, the look-back
   starts at the last success minus 5 minutes (first poll: 24 hours).
5. **Bounded parser:** body at most 8 MB, at most 100 pulses per page, names, descriptions, tags and lists
   capped, control characters dropped, only `https://` references (never fetched), indicators reduced to counts
   per type plus at most 20 public IP addresses for the map. Documentation, private, loopback and reserved
   ranges are never mapped.

## Privacy

Each poll sends the user's key to OTX and tells OTX the user's IP address. Say so in the OSINT sources dialog and
`PRIVACY.md` before shipping (documentation owner: MAC).

## Integration notes for the host worker (hot-file turn, not part of this branch)

- Without a key the source shows an honest "key required" state and makes no request.
- Map points need the geo work in ATLAS-OSINT-004; until then show counts, names, tags, malware families and
  target countries.
- A first live check by a user with a key must confirm the field names listed above.
