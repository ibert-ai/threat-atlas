# ATLAS-OSINT-011 — Cert Spotter CT watch-list: terms and handling note

Written by CL on 14 November 2026 after the owner approved the source change (ATLAS-OWNER-OSINT-SOURCE-DECISION-20261114-01).
Replaces the dead CertStream stream (see `OSINT-CT-RESEARCH.md`, `OSINT-SOURCE-CHANGES-RESEARCH.md`).
**(unverified)** marks anything that needs a second look. No account or key was created; the fixtures use the shapes in the
provider's published documentation, with the public `example.com` answer for the happy path.

## What it is

`GET https://api.certspotter.com/v1/issuances?domain=<d>&include_subdomains=true&expand=dns_names&expand=issuer[&after=<id>]`
with header `Authorization: Bearer <user's own key>` returns a JSON array of issuance objects in discovery order. Fields used:
`id` (opaque, used as the `after` cursor), `dns_names`, `issuer.friendly_name`, `not_before`, `not_after`, `revoked`
(nullable). `domain` must be a registered domain or below; a bare TLD is an error.
Source: https://sslmate.com/help/reference/ct_search_api_v1 (read 14 Nov 2026).

Observed response headers on an unauthenticated query: `x-ratelimit-limit: 100`, `x-ratelimit-remaining`, `cache-control: max-age=14400`.

## Terms and limits

| Question | Finding |
|---|---|
| Unauthenticated use | Allowed for personal and evaluation queries, about 100 per hour. |
| Free tier with a key | 100 single-hostname and 10 full-domain queries per hour (provider pricing/terms, read 14 Nov 2026). |
| Production use | Use your own key. |
| Stability | The provider says the API may change without notice. |
| Attribution | None found. We credit "SSLMate Cert Spotter" in the sources dialog anyway. |

### What this means for AtlasSOC

- **Own key only.** Never ship or share a key. Without a key the source is off.
- **User-entered domains only**, at most 10 (the full-domain quota). No watching of third-party domains from a built-in list.
- **Local budget** of 8 queries per hour, below the 10 full-domain limit; poll each domain at most once per hour.
- **Stop** on 401/403 and on 429; honour `Retry-After`. Never retry in a loop.
- Treat the answer as data: cap the body (1 MiB), names per issuance and issuances per page; drop malformed entries.

## Privacy

Each poll sends the watched domain name and the user's key to SSLMate (a third party). Say so in the OSINT sources dialog and
`PRIVACY.md` before shipping (documentation owner: MAC).
