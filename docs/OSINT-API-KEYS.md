# OSINT API keys and first-run approvals

Draft for **AtlasSOC Desktop 0.8.0-beta.1**. This page is for testers and customers. Keys are optional; the base GreyNoise
view needs none. Each key belongs to the tester, is stored by the operating system, and is sent only to the
provider it belongs to.

## Keyed sources at a glance

| Provider | Key needed | Where to get it | Free-tier note |
|---|---|---|---|
| abuse.ch ThreatFox + URLhaus | abuse.ch Auth-Key | https://auth.abuse.ch/ | fair use; commercial use may need abuse.ch's paid API |
| AlienVault OTX | OTX API key | https://otx.alienvault.com/ (account settings) | free; non-commercial |
| AbuseIPDB | API key | https://www.abuseipdb.com/register | free Individual plan, 1,000 checks/day; non-commercial personal |
| SSLMate Cert Spotter (CT Search API) | API key | https://sslmate.com/signup?for=ct_search_api | free tier of the CT Search API (the paid Cert Spotter monitoring plans are not needed); limits on https://sslmate.com/pricing |
| Cloudflare Radar (optional, existing) | Radar Read token | [Cloudflare token guide](CLOUDFLARE-RADAR-TOKEN-GUIDE.md) | CC BY-NC 4.0, non-commercial |

No key is used by CISA KEV, FIRST EPSS, Tor Project, SANS ISC, Team Cymru, abuse.ch SSLBL, ransomware.live,
Shodan InternetDB, Spamhaus DROP or Phishing.Database.

## How to add a key in AtlasSOC (all providers)

<a id="add-a-key"></a>

Keys are optional. A keyed source stays quiet (no requests at all) until you add its key **and** switch it on.

**macOS**
1. Open **Settings** (menu AtlasSOC → Settings, or Command-comma).
2. Under **Data sources**, find the source. Under its description the row says **API key: not set**.
3. Press **Add key…**, paste the key and press **Save**. The key goes into your Keychain (service
   `ThreatAtlas.OSINT`) and is never written to a file, shown again or logged. macOS may ask once whether
   AtlasSOC may use the Keychain item: choose **Always Allow**.
4. Switch the source on. The row shows its status ("No data yet" until the first poll, which follows within a
   minute). **Replace key…** and **Remove key** appear once a key is saved. A source that is switched off makes
   no requests even if a key is saved.

**Windows**
1. Right-click the AtlasSOC window and open **Settings → API keys (your own, stored in Credential Manager)**.
2. Choose the provider, for example **AlienVault OTX key: add...**. Windows opens its own credential box: paste
   the key in the **Password** field and press OK. (The User name box is filled in for you; leave it.) The key
   goes into Windows Credential Manager (entries named `AtlasSOC/OSINT/...`) and is never written to a file.
3. Open **Settings → Data sources** and tick the source. The source is marked "(needs your key)". Choose
   **Settings → View data** to see what arrived; the first poll follows within a minute.
4. **Remove ... key** in the same menu deletes the entry. A source that is off makes no requests.

**Certificate watch** (SSLMate) also needs your own domains: **Settings → API keys → Certificate watch: set
domains...**. Windows shows its credential box; type up to 10 domains separated by commas in the **User name**
box and leave the password empty. On macOS the domains go into the text field on the Certificate watch row in
Settings, then **Save domains**. Only watch domains you are authorised to watch.

**AbuseIPDB** is click-only: copy one public IP address, then **View data → Check IP from clipboard (AbuseIPDB)...**
on Windows or **Check copied IP...** on macOS, and confirm. Nothing is sent before you confirm.

**If a key is refused**, the row says so ("the API key was refused"). Check that you pasted the whole key without
spaces, that the account is verified (see the provider steps below), and add the key again. The app does not retry
a refused key in a loop.

## What each provider's sign-up looks like

Provider sites change; if a button has moved, look for the words in bold. Use a Google sign-in where the provider
offers one. Create the account with an address you can open, because most providers send a confirmation link.

| Provider | Steps (about 5 minutes) |
|---|---|
| **abuse.ch** | 1. Open https://auth.abuse.ch/ and sign in (Google, GitHub, X, LinkedIn or an e-mail link). 2. On **Profile Settings** choose a user name and display name and press **Create Profile** (a Cloudflare check may need a click). 3. Under **Auth Key** press **Generate Key**. The key is shown **once**: copy it before you close the box. |
| **AlienVault OTX** | 1. Open https://otx.alienvault.com/ and choose **Sign Up** (the Google button is quickest). 2. Pick a user name and country and accept the processing consent. 3. Open **Settings** (https://otx.alienvault.com/settings). Your key is the **OTX Key** line at the top. |
| **AbuseIPDB** | 1. Open https://www.abuseipdb.com/register, choose the free **Individual** plan, fill in the form, tick the captcha and press **Register**. 2. Open the confirmation e-mail and follow its link (the key page stays closed until the address is confirmed). 3. **My API → Keys**, type a name, press **Create**, then **Show** and copy the key. |
| **SSLMate (Cert Spotter / CT Search)** | 1. Open https://sslmate.com/signup?for=ct_search_api and create the account (user name, e-mail, password). 2. **API Keys → Create an API key**, give it a name and choose the usage **Certificate Transparency Search** (the smallest permission that works). 3. Copy the key from the page that opens. |

Keep every key private: treat it like a password, never paste it in chat, e-mail or an issue, and delete a key
at the provider if you think it leaked. Each key only unlocks the free tier of its own account.

## Let an AI assistant guide you (optional)

<a id="ai-guide"></a>

You can paste the prompt below into any AI assistant (ChatGPT, Claude, Gemini, a local model, and so on). It
walks you through the sign-up and the AtlasSOC settings one small step at a time. You still do every step
yourself: the assistant cannot see your screen or your keys and does not set anything up for you.

**Important:** never paste an API key, password or verification code into the chat. Copy the key from the
provider's website straight into AtlasSOC's key box. An assistant may make mistakes or be out of date, so if its
instructions do not match what you see, trust what is on the screen and the steps in this guide.

### What the prompt does and does not do

<a id="ai-guide-limits"></a>

**What it does**
- It is written to work with any AI assistant that can chat: the large cloud assistants, smaller models, and
  local or open models (for example through Hugging Face, DeepSeek, Ollama or LM Studio). It needs no web access,
  plugins, settings or system prompt. It is short and plain on purpose, so smaller models can follow it. Smaller
  models make more mistakes; if one does, trust this guide and your screen.
- You copy it and paste it into any AI assistant. The assistant first asks which computer you use (macOS or
  Windows) and which source you want.
- It gives one small step at a time and waits for your answer. It uses only the official addresses (abuse.ch,
  AlienVault OTX, AbuseIPDB, SSLMate) and the steps from this guide, so it works even if the assistant cannot
  browse the web.
- It shows how the key is added in AtlasSOC on macOS and Windows, and what to do if a key is refused.
- It reminds you that the account must be your own and free, that use is non-commercial, and that you may only
  watch domains you are allowed to watch.

**What it does not do**
- It does not set anything up for you. You make every click and every entry yourself.
- It does not see your screen, your keys or your accounts, and nobody at Threat Atlas receives your chat or your
  keys.
- It never asks for a key, password or verification code in the chat, and it will not check or enter a key for
  you. If you paste a key by mistake, delete it at the provider and create a new one.
- The key goes only from the provider's website directly into AtlasSOC's own key box, where it is stored in the
  macOS Keychain or Windows Credential Manager.
- It does not say that it works until you confirm that the source row in AtlasSOC shows data.
- It is not a guarantee. An assistant can be wrong or out of date. If it disagrees with this guide or with what
  you see on screen, this guide and your screen are right. We do not control any assistant and do not run or
  see your conversation.

Copy everything in the box:

```text
TASK: Help me add my own free API keys to AtlasSOC (Threat Atlas SOC, a desktop app). Guide me one small step at a time.

MOST IMPORTANT RULES
1. Every reply has exactly one step line, then one question line ending in "?". Nothing else. Then wait for me.
2. Never accept a key, password or code in this chat, and never sign in for me. If I ask you to check, enter, save or test a key, reply only: "I cannot check or enter keys. Copy the key from the provider straight into AtlasSOC's key box yourself." If I paste a key or password anyway, say "It is now exposed. Do not use it." Give one step: delete it at the provider. Ask only: "Have you deleted it?" Do not guess button names.
3. Certificate watch only for domains I own or have written permission to watch. If I name a company, client, competitor or a domain I do not own, reply only: "I can only help with a domain you own, for your own non-commercial use. Do you own it?" Give no steps.

OTHER RULES
4. Answer in the language I write in (for example Swedish if I write Swedish). Keep addresses and button names exactly as written here, in English. Use plain short sentences.
5. Use only the addresses below. Never make up addresses, buttons or settings. If you are not sure, say "I am not sure, please follow the text on your screen and the official guide" and stop guessing.
6. Only my own account, free plan, non-commercial use.
7. You cannot see my screen. Never say it works. If I say "it works" without quoting words, ask only: "What exact words does the source row in AtlasSOC show?" Say it works only after I quote words that show data.

FIRST REPLY: if I have not yet told you my computer and the source, send only this text with no greeting before it: "Which computer do you use (macOS or Windows), and which source do you want: abuse.ch, AlienVault OTX, AbuseIPDB or SSLMate certificate watch?" If I already told you both, skip it and give step 1 for that source.

SOURCES (keys are optional and free)
- abuse.ch (ThreatFox + URLhaus, one key for both): https://auth.abuse.ch/ . Sign in (Google works), create the profile, then Auth Key > Generate Key. The key is shown only once.
- AlienVault OTX: https://otx.alienvault.com/ . Sign Up, open Settings, the key is the "OTX Key" line.
- AbuseIPDB: https://www.abuseipdb.com/register . Free Individual plan, confirm the e-mail, then My API > Keys > Create > Show.
- SSLMate certificate watch: https://sslmate.com/signup?for=ct_search_api . Create the account, then API Keys > Create an API key with usage "Certificate Transparency Search".

IN ATLASSOC
- macOS: AtlasSOC > Settings (Command-comma) > the source > Add key... > paste > Save > switch the source on. If macOS asks about the Keychain, choose Always Allow. If a key is already saved, press Replace key... instead.
- Windows: right-click the window > Settings > API keys > the provider > paste the key in the Password field (leave the User name) > OK > Settings > Data sources > tick the source. Windows has no "Replace key...": to replace a key, use Settings > API keys > Remove ... key, then add the key again.
- Certificate watch domains (up to 10): macOS: text field on the Certificate watch row, then Save domains. Windows: Settings > API keys > Certificate watch: set domains..., domains separated by commas in the User name box, password empty.
- If AtlasSOC says the key was refused: the whole key must be pasted without spaces and the account e-mail must be confirmed; then replace the key as above.

FINISH: ask "Which source is it, and what exact words does its row in AtlasSOC show?"
```

If the assistant and this guide disagree, the guide is correct. Report guide mistakes at
https://github.com/Ibert-Iam/threat-atlas/issues (never include a key).

## abuse.ch Auth-Key

<a id="abusech-auth-key"></a>

1. Create a free account at https://auth.abuse.ch/ and copy the **Auth-Key**. Do not reuse another person's key.
2. In AtlasSOC add the key as described in [How to add a key](#add-a-key), then enable ThreatFox and/or URLhaus
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
2. Add the key as described in [How to add a key](#add-a-key) and enable **AlienVault OTX**.
3. The key is sent only in the `X-OTX-API-KEY` header to `otx.alienvault.com`, one attempt per 15-minute poll.
   The app keeps public TLP white/green pulses only; private, amber and red pulses are dropped.
4. Free OTX use is non-commercial; pulse licences can still restrict redistribution. Do not publish pulse
   content beyond what AtlasSOC displays.

## AbuseIPDB

<a id="abuseipdb"></a>

1. Create an AbuseIPDB account and API key at https://www.abuseipdb.com/register. Use the free **Individual**
   plan (1,000 checks/day, one account per person, non-commercial).
2. Add the key as described in [How to add a key](#add-a-key) and enable the click lookup.
3. The app looks up an address **only after a click**, at most 800 checks per UTC day (below the plan so the
   tester's other tools keep room), caches 24 hours, and stops on 401/429. Private, loopback, link-local and
   other non-public addresses are never sent.
4. The clicked public IP and the key go to `api.abuseipdb.com`; AbuseIPDB also sees the tester's public IP.

## SSLMate Cert Spotter

<a id="sslmated-cert-spotter"></a>

1. Create a free SSLMate account for the CT Search API at https://sslmate.com/signup?for=ct_search_api and an API
   key with the usage **Certificate Transparency Search** (steps in the provider table above). API reference:
   https://sslmate.com/help/reference/ct_search_api_v1 .
2. Add the key as described in [How to add a key](#add-a-key), then enter **only domains you are authorised to
   watch** (up to 10). The app polls each domain at most hourly, at most 8 full-domain queries per hour.
3. The watched domain and key go to `api.certspotter.com`; no other data is sent. The provider may change the API
   without notice. Free-tier limits are shown on https://sslmate.com/pricing and in your SSLMate account.

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
