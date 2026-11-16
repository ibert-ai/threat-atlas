# Screensaver on-screen attribution (saver-parity draft)

Reference `ATLAS-SAVER-PARITY-001`, SP7. Draft for the saver-parity Beta, not a shipped release.
The stable 0.4.8 screensaver has no OSINT cards. These are the short lines intended for the screensaver cards and its
footer; the full notices remain in [OSINT-ATTRIBUTION.md](OSINT-ATTRIBUTION.md). Do not use a provider name in
marketing or promotional material.

| Card / source | On-screen line |
|---|---|
| GreyNoise base view | GreyNoise public threat map |
| CISA KEV + FIRST EPSS | CISA KEV · FIRST EPSS |
| Tor exits | Tor Project exit list |
| SANS ISC / DShield | SANS ISC / DShield · CC BY-NC-SA 4.0 |
| abuse.ch SSLBL | abuse.ch SSLBL · CC0 |
| abuse.ch ThreatFox / URLhaus | abuse.ch ThreatFox / URLhaus · own key |
| AlienVault OTX | AlienVault OTX · own key |
| ransomware.live | ransomware.live |
| Spamhaus DROP | Spamhaus DROP |
| Phishing.Database | Phishing.Database · MIT |
| SSLMate Cert Spotter | SSLMate Cert Spotter · own key |

## Rules

- Show the source line on every card that displays data from that source; do not rely on a single footer line.
- Keep the licence marker where the source requires attribution (SANS ISC CC BY-NC-SA 4.0; Phishing.Database MIT).
- `Spamhaus` is used only as the factual data-source label. Do not use it in marketing or promotional material.
- SSLMate and the keyed sources are shown only when the user has enabled them and supplied their own key.
- Click-only lookups (Shodan InternetDB and AbuseIPDB) are not part of the saver and have no saver card.
- No new logo is required. If a logo is used, only the approved Threat Atlas pack is allowed.
- This list must be reviewed with the privacy section before any saver release.
