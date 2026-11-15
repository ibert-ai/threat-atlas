# AtlasSOC Desktop 0.8.0-beta.1 — draft release notes

**Status: draft, not released, not published.** This file prepares the beta; it is not a download, tag,
installer or claim that the beta exists. The version number is proposed and may change when the version manifest
is prepared.

## What the beta is for

AtlasSOC Desktop 0.8.0 beta adds optional, non-commercial OSINT sources to the existing SOC view so the new
functions can be tested on real screens. The base GreyNoise view is unchanged; every source can be turned off.

## Platforms

- **Windows x64 first.** The package will be unsigned and disclosed as such. SmartScreen or organisational
  policy may warn or block; do not disable protections.
- **macOS and Linux** are not part of the first beta. Each is added only after its own checks, per the OS-by-OS
  rule in [RELEASING.md](RELEASING.md).

## Sources in the beta scope

- CISA KEV + FIRST EPSS (known-exploited vulnerabilities)
- Tor exit count (map layer after the geo work)
- SANS ISC/DShield top target ports
- Team Cymru ASN context
- abuse.ch SSLBL (CC0, no key)
- abuse.ch ThreatFox and URLhaus (user's own Auth-Key)
- AlienVault OTX (user's own key; public TLP white/green pulses)
- ransomware.live aggregates (personal, non-commercial free API)
- Shodan InternetDB (click-only, public IP)
- AbuseIPDB (click-only, user's own key)
- SSLMate Cert Spotter (user's own key; up to 10 watched domains)
- Spamhaus DROP (advisory netblocks)
- Phishing.Database (MIT list, local matching)

**Not in this beta:** RIPE RIS/BGPStream (research only), GeoLite2 file reading, Windows code signing.

## What a user needs

No account is needed for the base view. Keyed sources use the user's own provider key, stored in Windows
Credential Manager or the macOS Keychain. Click lookups send only the public address the user clicks. Cert
Spotter sends only the domains the user chooses to watch. See [PRIVACY.md](../PRIVACY.md) and the
[OSINT source guide](OSINT-SOURCES.md).

## Known limitations

See [KNOWN-BUGS.md](KNOWN-BUGS.md) for the beta section. Highlights:

- Windows packages are unsigned.
- The Windows install/upgrade, own-key entry, source dialog and restore path still need physical test-PC
  acceptance.
- The OSINT integration is in progress; a parser being merged does not mean the source is wired into the app.
- Phishing.Database may be stalled; the app stops using it after 7 days without a change.
- Cert Spotter free-tier limits apply; the API may change.
- OTX and URLhaus live field/column shapes are unverified without a user key.
- Spamhaus's terms forbid using its name in marketing/promotional material; product docs may name it only as
  the factual source.
- No source is a verdict: KEV/EPSS, Tor exits, honeypot ports, netblocks, community pulses and phishing lists
  are context, not proof that an address is malicious or that a user is affected.

## Release gates

A beta is not published until the gates in [VERSION-FEATURES.md](VERSION-FEATURES.md) are met for the exact
commit:

1. optimisation/hardening round, then new tests (fuzz/property, soak where applicable), CI green and
   independent review;
2. documentation complete for every new source: user guide, privacy, third-party notices, known limits,
   version map, changelog, release notes and README.

Robert's separate go is required for any publication. Preparing this draft or merging its code does not
authorize a release.

## Installation, upgrade and rollback (when a beta exists)

- Use the exact named beta package from the release page; do not reuse it as a stable update.
- Keep a copy of the working previous version. The beta replaces the app folder/bundle; do not overwrite
  release assets under an old tag.
- Preserve the app's local settings/credential-store entries unless you intentionally remove them; removing the
  app does not necessarily remove its data folder.
- The Windows beta is unsigned; no automatic updater is implied. Verify the source commit and checksums when a
  package is published.
- Report the exact version/build, OS, steps, expected/actual behavior and sanitised logs. Never attach keys or
  raw private telemetry.

## Verification still required

- Windows: install/upgrade, source dialog, own-key entry by the owner, click lookups, restore previous
  screensaver, multi-monitor and DPI behavior.
- macOS/Linux: not in the first beta; separate checks.
- No live provider smoke test is claimed for keyed sources without the owner's own key.
