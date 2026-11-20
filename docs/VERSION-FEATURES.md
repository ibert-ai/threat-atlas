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

### AtlasSOC Desktop 0.8.0-rc.1 (build 15, release candidate, pre-release, 16 November 2026)

Windows x64 (installer and portable ZIP, unsigned) and macOS 14+ (see the release page for signing). Not the latest
stable; 0.7.0 stays stable.

- 13 optional OSINT sources with a switch each (off = no request): CISA KEV + FIRST EPSS, Tor exits, SANS ISC /
  DShield top ports, ransomware.live, Spamhaus DROP, abuse.ch SSLBL, Phishing.Database, Shodan InternetDB
  (click-only); AlienVault OTX, abuse.ch URLhaus, abuse.ch ThreatFox, AbuseIPDB (click-only), SSLMate certificate
  watch (own key, up to ten own domains).
- Keys in the macOS Keychain or Windows Credential Manager; memory-only in the data worker; sent only to their own
  provider. Settings window with licences, intervals, key guide and a "Last problem" line per source.
- Most-attacked-ports block under the top countries; rotating cards for the other sources.
- Optional AI help prompt for getting the free keys, with a plain list of what it does and does not do.
- Voluntary Ko-fi support link and a page on where the money goes (`SUPPORT.md`).
- Hardening round with evidence (QUALITY.md); parser robustness tests; `rc.1` stamp in the app and in the ZIP name.

| Item | Source | Needs a key | State in 0.8.0-rc.1 |
|---|---|---|---|
| 001 | CISA KEV + FIRST EPSS | no | included (card, dialog, Settings) |
| 002 | Tor exit nodes | no | included (count and dialog; map layer open) |
| 003 | SANS ISC / DShield top ports | no | included (standing block and card) |
| 004 | Team Cymru ASN, optional GeoLite2 file | no | not included |
| 005 | abuse.ch SSLBL, URLhaus, ThreatFox | SSLBL none; URLhaus and ThreatFox own key | included |
| 006 | AlienVault OTX | own key | included |
| 007 | ransomware.live | no | included |
| 008 | Shodan InternetDB | no | included (click-only) |
| 009 | AbuseIPDB | own key | included (click-only) |
| 010 | RIPE RIS Live (BGP) | no | not included (research) |
| 011 | Certificate watch (SSLMate CT Search) | own key | included (re-scoped from CertStream) |
| 012 | Spamhaus DROP | no | included |
| 013 | Phishing.Database (replaces PhishTank) | no | included |

## Next version (not yet assigned a number, not released)

The numeric version must advance when the Windows installer payload changes (see `RELEASING.md`). Planned, not built:
the 1920x1080 base scaling (SOC-RESOLUTIONS.md), a multi-screen option, a ransomware-by-country map layer, Tor map
layer, trusted Windows code signing (Certum order of 14 November 2026), and the wishlist items below.

### Threat Atlas screensaver 0.5.0 (planned, Beta channel first, not built into a release)

Owner decisions D1-D4 of 16 November 2026 (see `SCREENSAVER-PARITY-PLAN.md`). The shared core, the Windows host (SP4) and
the settings reader are merged into `codex/osint-sources`; the macOS host (SP5) is in progress; nothing is published.

- The screensaver shows the AtlasSOC view: rotating OSINT cards for the sources the user has switched on in AtlasSOC
  Settings, and the most-attacked-ports block. A focus rotation visits the five busiest countries, starting from the
  world overview.
- The screensaver only reads AtlasSOC's settings and keys. With no AtlasSOC settings file, no OSINT request is made.
- Not in this version: Cloudflare Radar in the screensaver (D2, waits for Cloudflare's licence answer), a configuration
  window in the screensaver (D4), Linux saver, panorama with the new view (panorama keeps the classic view).
- Limits: not yet run on a real Windows PC or a Mac (SP8); the Windows saver uses the core's own HTTPS client, not the
  system proxy; unsigned on Windows until the Certum certificate exists.

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
