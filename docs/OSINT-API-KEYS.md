# OSINT API keys and first-run approvals

Draft for **AtlasSOC Desktop 0.8.0-beta.1**. This page is for testers. Keys are optional; the base GreyNoise
view needs none. Each key belongs to the tester, is stored by the operating system, and is sent only to the
provider it belongs to.

## Keyed sources at a glance

| Provider | Key needed | Where to get it | Free-tier note |
|---|---|---|---|
| abuse.ch ThreatFox + URLhaus | abuse.ch Auth-Key | https://auth.abuse.ch/ | fair use; commercial use may need abuse.ch's paid API |
| AlienVault OTX | OTX API key | https://otx.alienvault.com/ (account settings) | free; non-commercial |
| AbuseIPDB | API key | https://www.abuseipdb.com/register | free Individual plan, 1,000 checks/day; non-commercial personal |
| SSLMate Cert Spotter | API key | https://sslmate.com/certspotter/ | free: 100 single-host / 10 full-domain queries per hour |
| Cloudflare Radar (optional, existing) | Radar Read token | [Cloudflare token guide](CLOUDFLARE-RADAR-TOKEN-GUIDE.md) | CC BY-NC 4.0, non-commercial |

No key is used by CISA KEV, FIRST EPSS, Tor Project, SANS ISC, Team Cymru, abuse.ch SSLBL, ransomware.live,
Shodan InternetDB, Spamhaus DROP or Phishing.Database.

## abuse.ch Auth-Key

<a id="abusech-auth-key"></a>

1. Create a free account at https://auth.abuse.ch/ and copy the **Auth-Key**. Do not reuse another person's key.
2. In AtlasSOC, open **Settings → OSINT sources → abuse.ch** and paste the key. Enable ThreatFox and/or URLhaus
   separately. SSLBL needs no key.
3. The key is stored in Windows Credential Manager or the macOS Keychain and sent only to
   `threatfox-api.abuse.ch` / `urlhaus-api.abuse.ch`. URLhaus places it in the request path, so the app never
   logs or displays that path.
4. ThreatFox/URLhaus refresh at most every 15 minutes (the provider's floor is 5 minutes). Disable a source to
   stop its requests immediately.
5. abuse.ch's community API is free under its fair-use principles; commercial use may require the paid abuse.ch
   API. AtlasSOC's use is non-commercial.

## AlienVault OTX

<a id="alienvault-otx"></a>

1. Sign in at https://otx.alienvault.com/, open the account/API settings and copy the API key.
2. In **Settings → OSINT sources → AlienVault OTX**, paste the key and enable the source.
3. The key is sent only in the `X-OTX-API-KEY` header to `otx.alienvault.com`, one attempt per 15-minute poll.
   The app keeps public TLP white/green pulses only; private, amber and red pulses are dropped.
4. Free OTX use is non-commercial; pulse licences can still restrict redistribution. Do not publish pulse
   content beyond what AtlasSOC displays.

## AbuseIPDB

<a id="abuseipdb"></a>

1. Create an AbuseIPDB account and API key at https://www.abuseipdb.com/register. Use the free **Individual**
   plan (1,000 checks/day, one account per person, non-commercial).
2. In **Settings → OSINT sources → AbuseIPDB**, paste the key and enable the click lookup.
3. The app looks up an address **only after a click**, at most 800 checks per UTC day (below the plan so the
   tester's other tools keep room), caches 24 hours, and stops on 401/429. Private, loopback, link-local and
   other non-public addresses are never sent.
4. The clicked public IP and the key go to `api.abuseipdb.com`; AbuseIPDB also sees the tester's public IP.

## SSLMate Cert Spotter

<a id="sslmated-cert-spotter"></a>

1. Create an SSLMate account and API key; see https://sslmate.com/help/reference/ct_search_api_v1 and the
   Cert Spotter product page.
2. In **Settings → OSINT sources → Cert Spotter**, paste the key and enter **only domains you are authorised to
   watch** (up to 10). The app polls each domain at most hourly, at most 8 full-domain queries per hour.
3. The watched domain and key go to `api.certspotter.com`; no other data is sent. The provider may change the API
   without notice. The free tier is 100 single-host / 10 full-domain queries per hour.

## Cloudflare Radar (existing optional source)

<a id="cloudflare-radar"></a>

Follow [CLOUDFLARE-RADAR-TOKEN-GUIDE.md](CLOUDFLARE-RADAR-TOKEN-GUIDE.md). The token is read-only Account /
Radar / Read, stored in the OS credential store, sent only to `api.cloudflare.com`, and used at most every 15
minutes. Radar data is CC BY-NC 4.0 and non-commercial.

## No-key sources

<a id="no-key-sources"></a>

CISA KEV + FIRST EPSS, Tor Project exit list, SANS ISC/DShield, Team Cymru ASN, abuse.ch SSLBL,
ransomware.live, Shodan InternetDB, Spamhaus DROP and Phishing.Database need no account or key. Each provider
sees the tester's public IP and normal HTTPS request metadata when the app fetches its feed. Shodan InternetDB
also receives the **clicked** public IP after an explicit confirmation; AbuseIPDB and Cert Spotter are
click-keyed as above.

## Key storage and "off means no requests"

<a id="key-storage"></a>

- Keys are stored by Windows Credential Manager or the macOS Keychain, never in the app's settings file, logs,
  crash reports or Git.
- The Settings screen has one on/off switch per source. **Off means no background request for that source**:
  the worker does not fetch it, does not queue a retry and does not send a stored key.
- Removing a key disables the keyed source. An invalid/revoked key stops after 401/403; the app does not retry in
  a loop.
- The app never fetches a URL, domain or address taken from threat data. Links are defanged and only the
  provider's own page is linked.

## Windows: UAC, SmartScreen and Defender (unsigned beta)

<a id="windows-approval"></a>

The Windows beta is **unsigned**. These prompts are expected; do not disable Windows security features.

1. Run the exact beta installer/portable package from the release page; verify the source commit and checksum
   when they are published.
2. **UAC** may ask for administrator approval. Choose the install scope the beta documents (per-user is normally
   enough). Decline if the prompt is not for the expected package.
3. **SmartScreen** may show "Windows protected your PC". Only if the package is the exact verified beta, use
   **More info → Run anyway**; otherwise stop. Do not turn SmartScreen off globally.
4. **Defender** may scan or quarantine the new unsigned executable. Do not add a broad exclusion or disable
   Defender. If it quarantines the verified package, report the detection to the maintainer with the exact file
   hash and package name; use the previous working version meanwhile.
5. After install, open **Settings → OSINT sources**, verify that a disabled source makes no requests, and enter
   only the tester's own keys. Uninstall/restore the previous saver or app when the test is done.

## macOS first open (when a macOS beta exists)

<a id="macos-first-open"></a>

The macOS beta follows its own signing/notarisation check before it is offered. If a test build is unsigned or
not notarised, Gatekeeper may block it:

1. Open the app from the exact test package. If macOS says it cannot verify the developer, open **System
   Settings → Privacy & Security** and use **Open Anyway** for that exact app; or Control-click the app and
   choose **Open**.
2. Do not disable Gatekeeper or remove quarantine as a general workaround. If the build is not signed/notarised,
   report that as the expected beta limitation and use the previous version.
3. Keys are stored in the macOS Keychain, not in the app bundle. Remove them from the app's settings when the
   test is done.

## Reporting

Report the exact version/build, OS, package hash, the source and setting, the prompt (UAC/SmartScreen/Defender/
Gatekeeper), and the redacted result. Never attach a key, token or raw private telemetry. See
[SECURITY.md](../SECURITY.md) and [PRIVACY.md](../PRIVACY.md).
