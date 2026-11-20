# Screensaver parity matrix (SP0)

Reference `ATLAS-SAVER-PARITY-001`, package SP0, decisions D1-D4 of 16 November 2026 applied. **Port** = same data and drawing, no input; **Rotate** = replaces a click with a timed rotation; **SOC only** = stays in AtlasSOC.

| AtlasSOC feature | Saver today | Class | First saver beta (D1) | Work |
|---|---|---|---|---|
| GreyNoise records, buffers, LIVE/STALE/OFFLINE | yes (`Session`) | Port | yes (exists) | keep |
| UTC and local clocks, country colours | yes | Port | yes (exists) | keep |
| Most-attacked-ports block | no | Port | **yes** | SP1 |
| Rotating OSINT cards: KEV + EPSS, Tor exits, SANS ISC, ransomware.live, Spamhaus DROP, SSLBL, Phishing.Database, OTX, URLhaus + ThreatFox, certificate watch | no | Port | **yes** | SP1 + SP3 (worker start via `ta_saver_*`) |
| Source switches, intervals, key entry, licences, key guide | no | SOC only (D4) | saver **reads** the AtlasSOC settings | SP2 |
| Cloudflare Radar aggregate | no (`RadarSession` exists, unused) | Port | **no, held (D2)** | after Cloudflare's answer |
| Country focus, severity filter, hover inspect | no | Rotate | timed rotation of the focus country | SP1 |
| Realtime / Calm / Still, freeze | saver has its own motion | SOC only | keep saver behaviour | none |
| Click-only lookups (Shodan InternetDB, AbuseIPDB) | no | SOC only | no | none |
| Record list, rate chart, dashboard layout, themes | no | Rotate (rate chart, record list as a card) | rate chart as a card | SP1 |
| Consent identity, Cloudflare notice | n/a | SOC only | n/a without Radar | SP7 |
| Updates view and channels | saver updaters exist | Port later | notice only, Beta channel | UPDATE-CHANNELS WP3-WP5 |
| TA logo | planned (ATLAS-BRAND-001) | Port | yes | with SP1 |
| Mirroring, multi-monitor, hotplug | saver per-display | already in the saver | keep, test in SP8 | SP8 |

Budget rule (SP1): the first beta must not exceed the 0.4.8 saver's CPU, memory and frame time by more than 25 percent on the same machine; the number is measured by Billy (Windows) and MAC (macOS) from the 0.4.8 baseline and recorded before SP1 code lands. If it does, cards are cut, not the budget raised.
