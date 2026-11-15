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

## Next version — AtlasSOC Desktop 0.8.0 beta / RC1 candidate (not released)

Status on 15 November 2026. The working beta identity is **0.8.0-beta.1, build 14**; the owner ordered an RC1
candidate for **0.8.0-rc.1, build 15** on 16 November. No package, tag or public release exists yet. Nothing here
may be announced as shipped before the release gates below are met and Robert gives the go.

### New features

- One **Settings** surface: every source has its own on/off switch; **off means no background request** (no fetch,
  no retry, no stored key sent). New sources start off. Each source keeps its own last problem and a **View data**
  page.
- The OSINT worker is shared by Windows and macOS (`crates/core`), so a source behaves the same on both.
- Live intelligence appears as **rotating cards under the Radar rows** in both layouts; the wide layout also has a
  standing **most-attacked-ports** block. OSINT is context next to the map, not a separate dashboard.
- Keys are stored only in the **macOS Keychain** or **Windows Credential Manager**, held in memory by the worker,
  and sent only to their own provider. They are not written to settings, logs, notes, the status page or Git.
- **AI key guide (candidate, branch #82):** a copy-and-paste prompt for any chat assistant, large or small, that
  walks a customer through creating the free accounts and entering keys without the assistant ever seeing a key.
  It is not a setup service and cannot validate a key. Pending merge/build confirmation.
- Voluntary **Ko-fi** support link (candidate, branch #82): free, no perks, nothing compulsory; all money goes back
  into project costs. No provider endorsement.
- AtlasSOC Desktop identity/BETA stamp; Windows remains unsigned in this beta.

### OSINT sources (ATLAS-OSINT-001 to 013)

All sources are non-commercial and optional. Status on 15 November 2026: "wired" means the host worker, Settings
and data view use the source; "live" means it was checked against the real provider. Windows keyed sources are
**not yet tested with keys on Windows hardware** — mark that as a known limit.

| Item | Source | Needs a key | State on 15 November 2026 |
|---|---|---|---|
| 001 | CISA KEV + FIRST EPSS | no | wired on macOS and Windows; KEV/EPSS cards and data view |
| 002 | Tor exit nodes | no | wired; count and data view; map layer not in this beta |
| 003 | SANS ISC / DShield top ports | no | wired; top-ports card and standing ports block in the wide layout |
| 004 | Team Cymru ASN (optional GeoLite2 file) | no (GeoLite2 needs the user's MaxMind file) | **not in the 0.8.0 beta**; DNS path still pending; GeoLite2 needs a new dependency |
| 005 | abuse.ch SSLBL | no (CC0) | wired; malicious-certificate list |
| 005 | abuse.ch ThreatFox | own abuse.ch Auth-Key | wired; POST API; live on macOS; Windows keys untested |
| 005 | abuse.ch URLhaus | own abuse.ch Auth-Key | wired; GET API; live on macOS; Windows keys untested |
| 006 | AlienVault OTX | own OTX key | wired; public TLP white/green pulses; live on macOS; Windows keys untested |
| 007 | ransomware.live | no | wired; aggregates only (no victim data); live on Windows 15 Nov after the provider fixed its expired certificate |
| 008 | Shodan InternetDB | no | wired; click-only public-IP lookup after confirmation; no bulk/hover |
| 009 | AbuseIPDB | own AbuseIPDB key | wired; click-only; live on macOS; Windows keys untested |
| 010 | RIPE RIS Live (BGP) | no | research only; not in the beta |
| 011 | Certificate Transparency watch (SSLMate CT Search) | own SSLMate key | wired; up to 10 domains; live on macOS; Windows keys untested; replaces the dead CertStream stream |
| 012 | Spamhaus DROP | no | wired; advisory netblocks, checked locally; do not use the name in promotional copy |
| 013 | Phishing.Database | no | wired; MIT list, matched locally; stale after 7 days; replaces PhishTank |

Rules that apply to every source: a user's own key only (never shipped or shared), click-only lookups for
per-address services, third-party recipients named in `PRIVACY.md`, provider rate limits as a floor, and no
fetching of anything the data points to. The source dialog lists licence, attribution, minimum interval and key
requirement.

### Not in this beta

- Team Cymru ASN (DNS path pending) and RIPE RIS (research only).
- GeoLite2 file reading (new dependency).
- Windows code signing (Certum activation pending) and a signed/notarised macOS build until CL's published marker.
- 1920x1080 scaling and the multi-screen option (design in `docs/SOC-RESOLUTIONS.md`; the current frame is fixed
  1440x900 and the bottom can be cropped on small screens).
- Ransomware-by-country map layer.

### Release gates

The owner decisions of 14 November 2026 still apply to a public release. The 15 November RC1 order **compresses**
the independent-review and soak gates: they are disclosed as compressed/CL self-review where they could not run,
not silently skipped. A release is not published until both gates are met for the exact code:

1. **Optimisation and hardening round, then new tests.** Baseline numbers, evidence-based optimisation, safety and
   best-practice checks, new tests after the optimisation (fuzz and property tests for every parser, soak), CI
   green on the exact commit and independent review. Evidence in `docs/QUALITY.md` or the release record.
2. **Documentation complete for every new feature:**
   - the feature is described for users (what it shows, where the data comes from, what it needs);
   - the OSINT sources dialog lists the source with licence, attribution, minimum interval and key requirement;
   - `PRIVACY.md` names every third party that receives data (clicked addresses, keys, watched domains) and what
     they learn;
   - `THIRD-PARTY-NOTICES.txt` and attribution lines are updated;
   - known limits and unverified points are written down, not implied away;
   - the version map, `CHANGELOG.md`, release notes and README feature list name the feature and the version;
   - wishlist and bug statuses are updated with their evidence.

Known unverified points for the beta: Windows key entry with real keys on hardware, Windows soak, macOS soak,
hardware matrix, code signing/notarisation, and 1920x1080 scaling. Do not present these as done.
