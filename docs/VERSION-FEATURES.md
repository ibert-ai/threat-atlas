# Features by version

What each published version contains, and what is planned for the next one. Written 14 November 2026 from the
published release notes and the source; kept up to date by the documentation owner. A feature is not "included"
until it is in a published release and its documentation is complete (see the checklist at the end).

## Published

### Threat Atlas screensaver 0.4.8 (build 16, stable, 11 November 2026)

Windows 10/11 x64 (all-users MSI and portable ZIP, unsigned), macOS 12+ (Developer ID signed and notarized),
Linux x86_64 (windowed preview).

- World map with animated routes, received-record counters and a recent-observations log from the GreyNoise
  public threat-map feed. Records are received records, not verified unique attacks.
- UTC and local time in the header, from the operating system's time zone rules.
- Country borders and observation shading; the installed version is shown in the footer.
- Two-display Windows panorama for two matching side-by-side displays.
- The Classic look is pinned by an automated test. Code for an optional Seeker theme is in the source but is not
  selectable in release builds.

### AtlasSOC Desktop 0.7.0 (build 13, stable, 11 November 2026)

Windows x64 (installer with "Just me" or "Everyone", and portable ZIP, unsigned) and macOS 14+ universal
(Developer ID signed and notarized).

- Live SOC view of GreyNoise public threat-map records; Realtime, Calm and Still motion; severity filters; country
  focus and hover details; freeze.
- Classic layout (default) and an optional Dashboard layout; wide layouts up to 2.4:1 with a Top countries column.
- Optional Cloudflare Radar country aggregates with the user's own read-only token (Cloudflare data is CC BY-NC 4.0,
  non-commercial); licence consent at first start of each version.
- SOC fullscreen; compact macOS window; a built-in guide for creating the Radar token; update check on Windows.

### AtlasSOC Desktop 0.7.0 Linux x86_64 preview (build 13, pre-release, 12 November 2026)

Windowed X11/XWayland application with the shared SOC view, keyboard controls, country focus and the wide layout.
No Cloudflare Radar, update check, saved settings or fullscreen toggle. Tested by CI under a virtual display only.

## Next version (not yet assigned a number, not released)

The numeric version must advance when the Windows installer payload changes (see `RELEASING.md`). Nothing here
may be published before the release gates below are met.

### OSINT sources (ATLAS-OSINT-001 to 013)

All non-commercial sources, each with its own licence, attribution and minimum interval in one registry. Status
on 14 November 2026: "module" means the tested, pure parsing code is merged into the OSINT branch; "integration"
means the host (worker, dialog, panel, settings) still has to use it.

| Item | Source | Needs a key | State |
|---|---|---|---|
| 001 | CISA KEV + FIRST EPSS | no | data, worker and dialog done; panel open |
| 002 | Tor exit nodes | no | count and dialog done; map layer open |
| 003 | SANS ISC / DShield top ports | no | parser, worker and dialog done; panel open |
| 004 | Team Cymru ASN (default), optional GeoLite2 file | no (GeoLite2: the user's own MaxMind account) | module in review; reading the file needs a new dependency |
| 005 | abuse.ch ThreatFox, URLhaus, SSLBL | ThreatFox and URLhaus: the user's own key; SSLBL: none (CC0) | module merged; integration open |
| 006 | AlienVault OTX | the user's own key | module merged; integration open |
| 007 | ransomware.live | no | open |
| 008 | Shodan InternetDB | no | module merged; integration open |
| 009 | AbuseIPDB | the user's own key | module merged; integration open |
| 010 | RIPE RIS Live (BGP) | no | research done; opt-in, narrowly filtered design |
| 011 | Certificate Transparency | no | the public CertStream service is not operating; re-scope to a crt.sh watch-list proposed |
| 012 | Spamhaus DROP/EDROP | no | open |
| 013 | PhishTank | the user's own key | open; check that new keys are still issued |

Rules that apply to every source: a user's own key only (never shipped or shared), click-only lookups for
per-address services, third-party recipients named in the privacy text, provider rate limits as a floor, no
fetching of anything the data points to.

### Other planned changes

- Trusted Windows code signing (Certum Open Source certificate ordered 14 November 2026, owner verification
  pending). Signed packages are a new version, not a replacement of 0.4.8.
- The optimisation and hardening round (see the release gates).
- More languages in the applications (ATLAS-I18N-001), Radar in the screensaver settings (ATLAS-SAVER-RADAR-001),
  Zero Wire security briefings (ATLAS-SOC-SOURCE-002): wishlist items, not scheduled.

## Release gates for a public release

Owner decisions of 14 November 2026. A release is not published until both gates are met for the code in it.

1. **Optimisation and hardening round, then new tests.** Baseline numbers, evidence-based optimisation, safety and
   best-practice checks, new tests after the optimisation (fuzz and property tests for every parser, soak), CI
   green on the exact commit and independent review. Evidence in `docs/QUALITY.md` or the release record.
2. **Documentation complete for every new feature:**
   - the feature is described for users (what it shows, where the data comes from, what it needs);
   - the OSINT sources dialog lists the source with licence, attribution, minimum interval and key requirement;
   - `PRIVACY.md` names every third party that receives data (clicked addresses, keys, watched domains) and what
     they learn;
   - `THIRD-PARTY-NOTICES.txt` and attribution lines are updated (for example GeoLite2, RIPE, abuse.ch terms);
   - known limits and unverified points are written down, not implied away;
   - the version map above, `CHANGELOG.md`, the release notes and the README feature list name the feature and the
     version it ships in;
   - wishlist and bug statuses are updated with their evidence.
