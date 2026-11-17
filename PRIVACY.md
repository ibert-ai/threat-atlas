# Privacy policy

Threat Atlas SOC displays public GreyNoise internet threat-map telemetry.
When the screensaver or preview runs, it automatically connects to
`wss://threat-map-api.greynoise.io/ws`. GreyNoise receives your public IP address
and normal connection metadata, such as connection time. DNS requests are handled
by your configured DNS resolver. GreyNoise controls the upstream service; see
https://www.greynoise.io/privacy-policy for its privacy practices.

The base view does not require an account, cookies or API keys. Optional OSINT sources may use your own
provider key (stored by the operating system, never by AtlasSOC). The app adds no analytics, advertising or
tracking. Received telemetry is kept in bounded memory
for display and is discarded when the process ends. It does not visit, probe or
connect to observed IP addresses. OS crash reports are subject to your OS settings.

The optional developer audit tool writes received country/coordinate records,
receipt times, counters, payload fingerprints and rendered frames to a local
folder you choose. It does not upload those audit files.

GitHub handles repository downloads, issues and discussions under GitHub's own
privacy policy. Signing providers process release artifacts and maintainer account
information under their own policies. This policy does not claim that third-party
services collect no data. Changes to network behavior should update this policy.

If you enable automatic updates, a separate per-user background task checks the
public GitHub releases API at login/daily (macOS) or daily while signed in
(Windows). It downloads stable updates from GitHub and its release-asset CDN over
HTTPS, verifies publisher code signatures locally, and installs them. GitHub/CDN
operators receive your IP address and normal request metadata. No account/token
is sent. A local status file records the latest result; it is not uploaded.
Disable updates from the preview app menu (macOS) or Start Menu (Windows).

## AtlasSOC standalone beta

The standalone beta first requires version/build/terms consent before constructing its GreyNoise worker. On Windows and macOS, a user-supplied Radar Read token, kept in Windows Credential Manager or macOS Keychain, lets the app retrieve past-day aggregates from api.cloudflare.com after consent, at most every 15 minutes, until paused or the token is removed. It retains aggregate cache/receipt time and persisted cooldown under Application Support/ThreatAtlasPrivateRadar with one worker lock and a15-minute request floor. Data is aggregated, not individual live events. No added analytics or host probing. Profile/Keychain data is not deleted automatically on bundle/folder removal. The standalone installs no updater/startup task; screensaver updater statements above apply only to that separate product. See docs/ATLAS-SOC-BETA.md for all paths, scope and limitations.

After consent, the Windows Desktop app sends one anonymous request to `api.github.com` at each start to see whether a newer version exists. It sends no token, account or cookie. GitHub sees the IP address and app name. A download happens only after the user chooses to update.

## OSINT sources (AtlasSOC Desktop 0.8.0 beta, draft)

This section applies only when an OSINT source is enabled. The sources are optional and all are non-commercial.
The full user guide is [docs/OSINT-SOURCES.md](docs/OSINT-SOURCES.md); key setup and tester approval steps are in
[docs/OSINT-API-KEYS.md](docs/OSINT-API-KEYS.md).

- **Keyless feed providers:** CISA (`cisa.gov`), FIRST EPSS (`epss.empiricalsecurity.com`), the Tor Project
  (`check.torproject.org`), SANS ISC (`isc.sans.edu`), Team Cymru, abuse.ch (`urlhaus-api.abuse.ch`,
  `threatfox-api.abuse.ch`, `sslbl.abuse.ch`), Spamhaus (`spamhaus.org`), ransomware.live (`ransomware.live`) and
  GitHub raw for the Phishing.Database list. Each sees the tester's public IP and normal HTTPS request metadata
  when the app fetches the feed. No account, token, screen content or address from the user's own network is sent
  with those fetches.
- **Click-only lookups:** Shodan InternetDB receives the clicked **public** IP and the tester's public IP after an
  explicit clipboard confirmation naming Shodan; AbuseIPDB receives the clicked public IP and the tester's own
  key. Neither is called unless the user explicitly asks for it. Private, loopback, link-local, multicast,
  documentation and other non-public addresses are never sent. Results are cached locally for 24 hours (at most
  200 InternetDB entries) and are not uploaded.
- **Keyed sources:** abuse.ch ThreatFox/URLhaus, AlienVault OTX, AbuseIPDB and SSLMate Cert Spotter use the user's
  own key, stored in Windows Credential Manager or macOS Keychain. The key is sent only to that provider, together
  with the normal request metadata (and, for Cert Spotter, the domains the user chose to watch; for AbuseIPDB,
  the clicked IP). It is never shipped, logged, or sent to another source.
- **Cert Spotter:** sends the watched domain names and the user's key to SSLMate. Watch only domains you are
  authorised to watch.
- **ransomware.live:** the app sends no address or account; the provider sees the request IP. The app keeps only
  aggregate country/group/sector counts, never victim names or links.
- **Spamhaus DROP:** the app downloads the public list; Spamhaus sees the request IP. The list is checked locally;
  no addresses from the user's screen are sent.
- **Phishing.Database:** the app downloads the public list from GitHub and matches it locally. GitHub sees the
  request IP; no domain from the user's screen is sent. If the feed is stale, the app says so and stops using it.
- **No probing:** AtlasSOC never fetches, resolves or connects to a URL, domain or address taken from threat data.
  Links are shown defanged and only the provider's own page is linked.
- **Local data:** source caches, source state, settings and consent stay under the app's local data folder
  (`%LOCALAPPDATA%\ThreatAtlasSOC` on Windows, Application Support on macOS). They are not uploaded. Removing the
  folder clears them; removing the app does not necessarily remove the folder.
- **Provider terms:** each source's licence, attribution and rate limit is shown in the app's OSINT sources
  dialog and in [docs/OSINT-SOURCES.md](docs/OSINT-SOURCES.md). A provider's privacy policy also applies to the
  requests that reach it.
