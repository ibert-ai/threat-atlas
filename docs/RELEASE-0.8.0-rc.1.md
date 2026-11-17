# AtlasSOC Desktop 0.8.0-rc.1 — release candidate 1 (build 15)

**Status: pre-release, not the latest stable.** AtlasSOC Desktop 0.7.0 stays the stable version. This is a release
candidate: it is feature-complete for 0.8.0 and is published so that more people can test it before a stable
0.8.0. Report problems at <https://github.com/ibert-ai/threat-atlas/issues> (never attach a key or token).

AtlasSOC is free. It is not a commercial product and the data it shows comes from sources that are licensed for
non-commercial use only (see [Data licences](#data-licences)).

## What is new since 0.7.0

- **13 optional OSINT sources** shown next to the live GreyNoise map, each with its own on/off switch. Off means no
  request at all.
  - No account or key needed (8): CISA Known Exploited Vulnerabilities with FIRST EPSS scores, Tor exit nodes,
    SANS ISC / DShield most attacked ports, ransomware.live (incidents by country, group and sector), Spamhaus
    DROP, abuse.ch SSLBL, Phishing.Database, and Shodan InternetDB (click-only).
  - Your own free key (5): AlienVault OTX, abuse.ch URLhaus, abuse.ch ThreatFox, AbuseIPDB (click-only), and
    SSLMate certificate watch for up to ten domains you own.
- **Most attacked ports** (SANS ISC / DShield) as a standing block under the top countries, and rotating cards for
  the other sources.
- **One Settings window** (macOS: Settings; Windows: right-click > Settings) with the data sources, their licences
  and minimum intervals, the key guide, and a plain "Last problem" line per source.
- **Keys stay on your computer.** They are saved in the macOS Keychain or Windows Credential Manager, held in
  memory by the data worker, never written to a settings file, log or crash report, and sent only to their own
  provider.
- **An optional AI help prompt** you can paste into any AI assistant to be guided, one step at a time, through
  getting your own free keys. You do every step yourself; the assistant cannot see your screen or your keys.
  See [OSINT-API-KEYS.md](OSINT-API-KEYS.md#ai-guide) and the list of what it does and does not do.
- **A voluntary support link** (Ko-fi). Tips are optional, give no extra features, support or rights, and all
  money goes back into the project: [SUPPORT.md](SUPPORT.md).
- The portable ZIP, its manifest and the on-screen stamp now say `rc.1`.

## Privacy and security properties

These are facts about how the program is built, not a guarantee that it is free of faults.

- Connections use verified TLS. The base view needs no account, no cookies, no login and no API key.
- A source that is off, or a keyed source without its key, makes **no request**.
- Click-only lookups (Shodan InternetDB, AbuseIPDB) send only the public address you click, after you confirm.
  Private, loopback and link-local addresses are never sent. Certificate watch sends only the domains you enter.
- The app never fetches a URL, domain or address taken from threat data. Links in data are defanged.
- Provider rate limits are a floor, and a refused key is not retried in a loop.
- Licence consent is stored for this exact version and build, and shown again after an upgrade.
- Hardening evidence for this build is in [QUALITY.md](QUALITY.md#hardening-round-for-080-rc1).
- Privacy text, including every third party that receives data: [PRIVACY.md](../PRIVACY.md).

## Platforms

| Platform | File | Signing |
|---|---|---|
| Windows 10/11 x64 | `AtlasSOC-Setup-0.8.0-build15.exe` (Just me or Everyone) and `AtlasSOC-Windows-x64-v0.8.0-rc.1-build15.zip` (portable) | **Unsigned.** Windows SmartScreen or organisational policy may warn or block; do not turn protections off. |
| macOS 14+ (Apple silicon and Intel) | `AtlasSOC-macOS-universal-v0.8.0-rc.1-build15` ZIP | See the release page: Developer ID signed and notarised only when stated there. |

Linux is not part of this release candidate. The existing 0.7.0 Linux preview is unchanged.

## Install, upgrade and roll back

- Windows: run the installer and choose **Just me** (no administrator rights) or **Everyone**. It upgrades an
  earlier AtlasSOC in the same scope. The update check in the app follows the pre-release channel only when the
  installed build is itself a pre-release.
- macOS: unzip and move `AtlasSOC.app` where you want it; quit the old one first. Allow the Keychain request once
  ("Always Allow") when you add a key.
- Keep a copy of 0.7.0 if you want to go back; settings and keys are kept unless you remove them.

## Data licences

Cloudflare Radar data is CC BY-NC 4.0 (attribution, non-commercial). The other sources have their own terms,
listed with attribution in the app (Settings > Sources, licences and attribution) and in
[OSINT-SOURCES.md](OSINT-SOURCES.md). Nothing in AtlasSOC is a verdict: a listing, a score or a report is context,
not proof that an address is malicious or that you are affected.

## Known limits

The full list is in [KNOWN-BUGS.md](KNOWN-BUGS.md). The main ones:

- Windows is unsigned.
- Screen size handling follows the older fixed layout. On small or scaled laptop screens (for example 125 %) the
  bottom of the window can be cropped; the 1920x1080 base scaling in [SOC-RESOLUTIONS.md](SOC-RESOLUTIONS.md) is
  designed but not built yet. A multi-screen option is also planned, not built.
- Keyed sources were checked live on macOS with the maintainer's own keys. On Windows, OTX and abuse.ch key entry
  (saved in Credential Manager, kept after a restart, removable) was checked on one physical PC; AbuseIPDB and
  SSLMate key entry on Windows was not.
- ransomware.live depends on the provider; on 14 November 2026 its certificate was expired for a day.
- Team Cymru ASN, MaxMind GeoLite2 and RIPE RIS are not in this release.
- Soak: one hour of continuous running on one Windows PC with stable memory and CPU; there was no multi-hour soak. See QUALITY.md.

## Support

Free software, voluntary tips only: <https://ko-fi.com/threatatlas>. Where the money goes: [SUPPORT.md](SUPPORT.md).
