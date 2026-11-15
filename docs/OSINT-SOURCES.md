# OSINT sources in AtlasSOC Desktop

Draft for **AtlasSOC Desktop 0.8.0-beta.1**. The integration is in progress; this document describes the
sources and the rules the app follows once they are enabled. Do not publish it as a description of a shipped
release before the 0.8.0 beta release gates are met.

AtlasSOC's base view is GreyNoise's public threat-map feed. The sources below are optional additions. None is
required to start the app, and every one can be turned off. All are non-commercial; a source that requires a key
uses **your own** key, stored in Windows Credential Manager or the macOS Keychain, never in the app, a log or Git.

A source shows **context**, not a verdict. "Listed", "reported" or "observed" does not prove that an address is
malicious or that your organisation is affected.

## Sources at a glance

| Source | What it adds | Key | Refresh | Licence / attribution |
|---|---|---|---|---|
| CISA KEV + FIRST EPSS | Known exploited vulnerabilities with an exploit-probability score | no | daily | CISA public catalogue; EPSS free, attribution |
| Tor exit nodes | Count of public Tor exit addresses (map layer after the geo work) | no | 30 min | Tor Project public list |
| SANS ISC / DShield | Top attacked target ports and their record/target/source counts | no | hourly | CC BY-NC-SA 4.0 |
| Team Cymru ASN | IP-to-ASN lookup for network context | no | cached | Team Cymru free DNS service |
| abuse.ch SSLBL | Recently listed malicious TLS certificates | no | 15 min | CC0 |
| abuse.ch ThreatFox | Recent malware/C2 indicators | own Auth-Key | 15 min | abuse.ch fair use |
| abuse.ch URLhaus | Recent malware-distribution URLs | own Auth-Key | 15 min | abuse.ch fair use |
| AlienVault OTX | Public subscribed pulses, TLP white/green only | own key | 15 min | OTX end-user terms, non-commercial |
| ransomware.live | Aggregate ransomware claims by country, group and sector | no | 15 min | Free API v2, personal non-commercial |
| Shodan InternetDB | Ports/hostnames/CVEs for one clicked public IP | no | click-only, 24 h cache | Free non-commercial use |
| AbuseIPDB | Community report count for one clicked IP | own key | click-only, 24 h cache | Free Individual plan, non-commercial personal |
| SSLMate Cert Spotter | New certificates for up to 10 domains you enter | own key | hourly | SSLMate CT search API |
| Spamhaus DROP | Advisory malicious netblock list | no | daily | DROP Terms of Use; see naming note |
| Phishing.Database | Community phishing-domain list, matched locally | no | daily | MIT |

Not in the beta: RIPE RIS/BGPStream (research only), GeoLite2 file reading, Windows code signing.

## What each source does and does not mean

### CISA KEV + FIRST EPSS

CISA's Known Exploited Vulnerabilities catalogue lists CVEs that CISA has evidence are exploited. FIRST EPSS
estimates the probability that a CVE will be exploited in the next 30 days. The app joins them by CVE and shows
the top entries with the KEV due date and EPSS score.

- **Does not mean** that your software is affected. Check the product/version against the CVE.
- Both sources are fetched at most once a day; the EPSS API is not used for bulk sync.

### Tor exit nodes

The Tor Project publishes the public exit list. The app shows a count and, after the geo work, a country-level
layer.

- **Does not mean** that an exit node is malicious. It is public Tor infrastructure.
- The list is fetched at most every 30 minutes.

### SANS ISC / DShield

SANS ISC aggregates honeypot reports. The app shows the top target ports with record, target and source counts
and the report date.

- **Does not mean** unique attacks or attacks on you. These are honeypot observations, and the counts are
  unfiltered reports.
- The data is CC BY-NC-SA 4.0; attribution is shown. One request per hour at most.

### Team Cymru ASN

Team Cymru's DNS service maps a public IP to its autonomous system. The app uses it to label network context
and to support an ASN filter.

- **Does not mean** that the network is malicious.
- Lookups are cached; no bulk loop is used.

### abuse.ch: SSLBL, ThreatFox, URLhaus

SSLBL lists malicious TLS certificates (SHA-1 fingerprints and a reason). ThreatFox lists recent IOCs;
URLhaus lists recent malware-distribution URLs. The app shows the SSLBL certificate list and the recent
ThreatFox/URLhaus entries with defanged links; it never opens a URL from the data.

- **Does not mean** that a listed domain or IP is currently serving malware.
- SSLBL is CC0 and needs no key. ThreatFox and URLhaus use **your own abuse.ch Auth-Key**; a shared project key
  would be harvesting under one identity. The app fetches at most every 15 minutes (the provider's floor is
  5 minutes). Commercial use may require abuse.ch's paid API; AtlasSOC's use is non-commercial.

### AlienVault OTX

OTX "subscribed pulses" are community threat reports. The app keeps only **public** pulses with **TLP white or
green**; private, amber and red pulses are dropped. A pulse is reduced to its name, description, tags, malware
families, targeted countries, ATT&CK ids and a few public IP addresses.

- **Does not mean** that a pulse is correct or current. It is community intelligence.
- Uses **your own OTX key**; one attempt per 15-minute poll, no retry loop.

### ransomware.live

The free API v2 publishes recent ransomware claims. The app shows **aggregates only**: counts by country,
group and sector, and a time window. It never stores or displays victim names, domains, links, screenshots or
descriptions.

- **Does not mean** that a claim is true; the claims are the criminals' own and some are unverifiable.
- Free API v2 is for **personal, non-commercial use**. A company using AtlasSOC commercially needs the
  provider's PRO tier and its terms. The app fetches at most every 15 minutes.

### Shodan InternetDB

InternetDB returns open ports, hostnames, CPEs, tags and known CVE ids for a public IP. The app reads one
address from the clipboard only when you choose **Look up IP from clipboard (Shodan InternetDB)…**, refuses
non-public addresses, and shows a confirmation that names Shodan as the recipient before it sends anything. It
never looks up on hover and never in bulk.

- **Does not mean** that the host is vulnerable; the data is updated weekly and is a snapshot.
- Free for non-commercial use. One request per second at most, one in flight, no retry. A 404 means "no
  information", not an error. Answers are cached for 24 hours (at most 200 entries) on your computer.
- Shodan receives the pasted public IP and your public IP address. Private, loopback, link-local, multicast,
  documentation and other non-public addresses are never sent.

### AbuseIPDB

AbuseIPDB returns community reports for one public IP: confidence score, report count, categories and last
report time. Click-only, like InternetDB.

- **Does not mean** that the IP attacked you. Reports are community-submitted and may be wrong.
- Uses **your own** AbuseIPDB key under the free Individual plan (non-commercial personal use, one account per
  person). The app keeps a local budget of 800 checks per UTC day, below the free 1,000, so your other tools
  keep room; 24-hour cache; stop on 401/429.

### SSLMate Cert Spotter

Cert Spotter reports certificate-transparency issuances for domains you enter. The app watches at most 10
domains, fetches at most 8 times per hour, and shows the newest certificates and issuer names.

- **Does not mean** that a certificate is malicious. It is a new issuance for a domain you chose to watch.
- Uses **your own SSLMate key**. Without a key the source is off. The provider may change the API.

### Spamhaus DROP

DROP is an advisory list of netblocks that Spamhaus recommends dropping. The app shows a count/list and, when
the map layer is implemented, a shaded netblock layer.

- **Does not mean** that every host in the range is malicious; it is an advisory list and changes over time.
- Free under the DROP Terms of Use. The terms do **not** allow using the Spamhaus name in marketing or
  promotional material; product documentation and the in-app source label name it only as the data source.
  Fetched at most once a day, never closer than an hour; stale after 7 days.

### Phishing.Database

A community list of active phishing domains, matched **locally** against domains in the app. The app does not
fetch a listed domain.

- **Does not mean** that a domain is currently compromised; it is a community list, and this feed may be stale.
- MIT licence. The list is fetched at most once a day (16 MB cap). If it has not changed for 7 days the app
  stops using it and says so. `PhishStats` click-only lookups are a fallback only if the feed stays stale; they
  require the user's own key and their terms are unverified.

## Keys, storage and privacy

Key setup and first-run approval steps are in [OSINT-API-KEYS.md](OSINT-API-KEYS.md).

- Keys are entered in the app and stored in Windows Credential Manager / macOS Keychain under the existing
  credential-store pattern. They are sent only to the provider they belong to, never to another source, never
  in a URL that is logged, and never in Git.
- Click lookups send the clicked **public** IP to Shodan or AbuseIPDB. Click only.
- Cert Spotter sends the **domain you entered** to SSLMate. Watch only domains you are authorised to watch.
- Keyless downloads reveal your IP address to the provider, like any HTTPS request. No account or user data is
  sent.
- Cached data stays on your computer; the app does not upload it. Remove the app's local data folder to clear it.
- The app never fetches a URL, domain or IP taken from threat data. Links are shown defanged and only the
  provider's own page is linked.

See [PRIVACY.md](../PRIVACY.md) for the full list of recipients and what they receive.
