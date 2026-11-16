# AtlasSOC Desktop 0.8.0-beta.1 — communication draft

Status: **draft for Robert and CL review. Not released, not published, not a download.** The integration branch is
`codex/osint-sources`; PR #79 (keyed sources, Settings key entry and the AI key guide) was still open when this
draft was written. Sources marked **†** are part of PR #79 and must not be described as shipped until that PR is
merged and tested. Windows signing, 1920x1080 scaling, Team Cymru ASN (004) and RIPE RIS (010) are **out of this
beta**.

## What we are announcing

The next AtlasSOC Desktop beta keeps the calm GreyNoise view and adds **optional, non-commercial OSINT context**
around it: known-exploited vulnerabilities, attack ports, malicious certificates and URLs, community threat
reports, ransomware aggregates, click-only host checks, certificate watch-lists, advisory netblocks and a
phishing-domain list.

The three things to make clear:

1. **It is still free.** No paid tier, no locked feature, no account required for the base view. The new sources
   are optional and can be switched off.
2. **Your keys stay yours.** Keyed sources use your own free provider key, stored in the OS credential store and
   sent only to that provider. A source that is off makes no request.
3. **Help is built in.** A copy-and-paste **AI key guide** prompt walks a customer through creating the free
   accounts and adding the keys, one step at a time — without the assistant ever seeing a key.

Supporting message: if the project is useful, a voluntary Ko-fi tip helps cover code-signing certificates and
licences. Nothing is required; all money goes back into the project. Robert has paid for it personally so far.

## Headline options

1. **More context, same calm view — AtlasSOC Desktop 0.8.0 beta**
2. **One AI prompt to help you add the free API keys your OSINT sources need**
3. **Thirteen OSINT feeds. One Settings screen. Your keys stay yours.**
4. **Free, non-commercial context for your SOC view — with help setting it up**

Recommendation: lead with option 1 for the release, use option 2 as the feature headline inside the notes, and
option 3 for a technical/SOC audience. Avoid claiming the number "thirteen" until the source table is frozen;
"the new OSINT sources" is safer in a short post.

## What is new in the beta

### One Settings screen

- Every data source has its own **on/off** switch. New sources start **off**.
- **Off means no background request** for that source — no fetch, no retry, no stored key sent.
- **View data** shows what arrived for a source; each source keeps its own **last problem** instead of one
  global message overwriting the rest.
- The screen links to the key guide, the AI help prompt and the latest release/update item.
- Windows opens Settings from the right-click menu; macOS uses the normal Settings window (`Cmd-,`).

### A shared OSINT worker

- Windows and macOS now use the same Rust worker in `crates/core`, so a source behaves the same on both.
- The live intelligence is shown as **rotating cards under the Radar rows** in both layouts. The wide layout
  also has the standing **most-attacked-ports** block.
- The view keeps the existing map, records and severity controls; OSINT is additional context, not a new
  dashboard.

### Keyed sources, with OS credential storage

- macOS: keys go into the **Keychain** (service `ThreatAtlas.OSINT`), entered through a masked field; the app
  shows only "key saved", never the key.
- Windows: keys go into **Windows Credential Manager** (`AtlasSOC/OSINT/...`), entered through the Windows
  credential prompt. Windows key entry is part of the same beta work; do not announce it as already shipped
  until it is in the build being tested.
- The worker receives the key **in memory only**. It is not written to settings, logs, crash reports, notes or
  the status page.
- Refused keys stop the source; there is no retry loop. Removing the key disables the keyed source.

### The AI key guide (part of the same beta work; confirm it is in the build)

- A short prompt, copied from the app/guide into **any chat AI assistant**: large cloud models, smaller models,
  local/open models. No plugin, web access or system prompt is needed.
- The assistant asks which computer and which source, then gives **one small step and one question per reply**.
- It uses only the official provider addresses and the steps from the guide. It never asks for or accepts a
  key, password or verification code, never signs in, and never says the key works until the customer quotes
  what the AtlasSOC source row shows.
- **We do not set anything up for the customer.** The assistant cannot see the screen, keys or accounts, and
  nobody at Threat Atlas receives the chat or keys.
- Smaller models make more mistakes. The guide and the screen win over the assistant. So far the prompt has
  been tested with one assistant family and simulated weak-model cases, not with every model; say "works with
  any chat assistant, large or small" and add the honest caveat, not "tested on all models".

### Free, with voluntary support

- Free to use; no paid edition, no feature gated behind a tip.
- A **Ko-fi** link is available for anyone who wants to support the project. Tips are voluntary, give no extra
  features, support or rights, and are not payment for data.
- All money goes back into project costs: code-signing certificates, data/API licences, test computers/accounts
  and build services, domains and hosting. So far Robert has paid these personally (sole proprietorship,
  Sweden).
- No data provider endorses Threat Atlas or the tips.

## Sources in this beta

`†` = in the PR #79 work, confirm after merge. `—` = no key. All are optional; all are non-commercial.
The app shows licence, attribution and minimum interval for every source in its own source dialog.

| Source | What it adds | Key | Refresh / floor | Notes |
|---|---|---|---|---|
| CISA KEV + FIRST EPSS | Known-exploited CVEs with EPSS and due dates | — | daily | Context, not proof your software is affected |
| Tor exit nodes | Count of public Tor exits | — | 30 min | Exit node ≠ malicious |
| SANS ISC / DShield | Top attacked target ports and counts | — | hourly | Honeypot observations; CC BY-NC-SA 4.0 |
| abuse.ch SSLBL | Malicious TLS certificates | — | 15 min | CC0; certificate fingerprint list |
| abuse.ch ThreatFox † | Recent malware/C2 indicators | own abuse.ch Auth-Key | 15 min | POST API; fair use |
| abuse.ch URLhaus † | Recent malware-distribution URLs | own abuse.ch Auth-Key | 15 min | GET API; links shown defanged |
| AlienVault OTX † | Public community pulses, counts and families | own OTX key | 15 min | TLP white/green only; no indicators shown/fetched |
| ransomware.live | Ransomware claims by country/group/sector | — | 15 min | Aggregates only; never victim names/links |
| Shodan InternetDB | Ports/hostnames/CPEs/CVEs for one clicked public IP | — | click-only; 1/s; 24 h cache | Confirmation names Shodan; no bulk/hover |
| AbuseIPDB † | Community report count for one clicked public IP | own AbuseIPDB key | click-only; 800/day; 24 h cache | Free Individual plan; non-commercial personal |
| SSLMate CT Search † | New certificates for up to 10 domains you enter | own SSLMate key | hourly; max 8 full-domain/h | Only domains you own or may watch |
| Spamhaus DROP | Advisory malicious netblocks | — | daily | DROP terms; do **not** use the Spamhaus name in marketing copy |
| Phishing.Database | Community phishing-domain list | — | daily | MIT; matched locally; stale after 7 days |

Not in this beta: Team Cymru ASN (004), RIPE RIS/BGPStream (010), GeoLite2 file reading, Windows code signing,
1920x1080 scaling and the multi-screen option.

## Manual API keys — what to say

Keys are **optional**. The base GreyNoise view needs none. A keyed source is silent until its key is added **and**
the source is switched on.

**macOS**
1. AtlasSOC → Settings (`Cmd-,`) → the source row.
2. **Add key…**, paste the key, **Save**. It goes to Keychain; choose **Always Allow** if macOS asks.
3. Switch the source on; **View data** shows the first result. **Replace key…** / **Remove key** are on the row.

**Windows** (part of the same beta work)
1. Right-click the window → **Settings → API keys** → the provider.
2. Paste the key in the **Password** field; leave the prefilled user name; OK.
3. **Settings → Data sources** → tick the source. Windows has no "Replace key…": remove and add again.
4. Certificate watch: **Settings → API keys → Certificate watch: set domains…**, up to 10 domains separated by
   commas (User name box, password empty).

**Provider sign-up in one line each** (full steps in `docs/OSINT-API-KEYS.md`):
- abuse.ch: https://auth.abuse.ch/ → profile → **Auth Key → Generate Key**; shown once.
- AlienVault OTX: https://otx.alienvault.com/ → sign up → **Settings** → **OTX Key**.
- AbuseIPDB: https://www.abuseipdb.com/register → free **Individual** → confirm e-mail → **My API → Keys →
  Create → Show**.
- SSLMate CT Search: https://sslmate.com/signup?for=ct_search_api → **API Keys → Create**, usage
  **Certificate Transparency Search**.

**Safety lines to repeat**
- Never paste a key, password or verification code into a chat, e-mail or issue. The AI guide never needs it.
- Copy the key from the provider's page straight into AtlasSOC's key box.
- If a key was exposed, delete it at the provider and create a new one.
- Own account, free plan, non-commercial use. Watch only domains you own or have written permission to watch.
- Off means no requests; click lookups send only the public IP you confirm.

## The copy-and-paste AI prompt

This is the CL draft prompt (generic, small-model friendly). It belongs in `docs/OSINT-API-KEYS.md` under
**“Let an AI assistant guide you (optional)”**, with the plain “what it does / does not do” list next to it.
Put it behind a copy button in the docs, and link the docs from Settings (macOS **API keys** section, Windows
right-click **Settings**).

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

**What the prompt does not do:** it does not set anything up, cannot see the screen, never receives a key or
password, and cannot validate a key. If a customer pastes a key into a chat, treat it as exposed. The assistant
can be wrong or out of date; the guide and the screen win. We do not control any assistant and do not see the
conversation.

## Licensing and support — wording

Short version:

> Threat Atlas is free and runs without profit. If you want to help cover code-signing certificates and
> licences, you can leave a voluntary tip on Ko-fi. Tips give no extra features, support or rights, and are not
> required. All money goes back into the project.

Longer version for the README/SUPPORT page:

> Threat Atlas is free and open source (MIT); the data sources keep their own non-commercial terms. Nothing is
> compulsory and no feature depends on a tip. Voluntary tips through Ko-fi cover the costs of keeping the
> project running: code-signing certificates, data/API licences, test computers and accounts, build services,
> domains and hosting. Until now these costs have been paid personally by the maintainer, Robert Ibert (sole
> proprietorship, Sweden). Tips go to him for the project and are not used for anything outside that list. No
> data provider endorses Threat Atlas or the tips.

Do **not** say: "donation", if that implies tax relief/charity — use "voluntary tip/support"; "all profits" (there
are none); "paid support"; "unlock"; "membership"; "guaranteed"; "Cloudflare/Spamhaus/… supports us".

## Ready-to-use copy

### Release intro (about 130 words)

> **AtlasSOC Desktop 0.8.0 beta — more context, same calm view.**
>
> Threat Atlas is free, and the next AtlasSOC Desktop beta adds optional OSINT context to the live GreyNoise
> view: known-exploited vulnerabilities, attack ports, malicious certificates and URLs, community threat reports,
> ransomware aggregates, click-only host checks, certificate watch-lists, advisory netblocks and a
> phishing-domain list. Every source is optional, non-commercial and switchable; off means no requests.
>
> Keyed sources use your own free provider key, stored in the macOS Keychain or Windows Credential Manager and
> sent only to that provider. A built-in copy-and-paste AI prompt walks you through the sign-up and the key box,
> one small step at a time — the assistant never sees your key.
>
> Windows beta is unsigned; SmartScreen/UAC prompts are expected. Not a stable release. If you want to support
> the project, a voluntary Ko-fi tip helps cover signing certificates and licences; all of it goes back into the
> project.

### Short social post (under 280 characters)

> AtlasSOC Desktop 0.8.0 beta: optional non-commercial OSINT context for the GreyNoise view — KEV/EPSS, attack
> ports, malicious certs/URLs, OTX, ransomware aggregates, click-only host checks, certificate watch, netblocks
> and phishing domains. Free, your own keys, off = no requests. A copy-paste AI prompt helps you set up keys
> safely. Windows unsigned beta. Support via Ko-fi. [link]

Do not name Spamhaus in the social copy (its terms prohibit promotional use of the name); say "advisory
netblocks" instead. In the docs/source dialog, the factual source label is fine.

### Tone and emoji by channel

Threat Atlas is free, open source and non-profit, so the tone can be warm and human. Emojis are fine in social
media, but they are not a substitute for the facts and must never imply a severity verdict.

| Channel | Emoji policy | Tone |
|---|---|---|
| **ibert.se** | **No emojis.** | Calm, factual, documentation-like. |
| **LinkedIn** | **Restrained: 0–1**, preferably at the end, never in the headline. | Professional, specific, no hype. |
| **Facebook** | 2–4 relevant emojis; friendly and plain. | Helpful, community-minded, no alarmism. |
| **Instagram** | 2–5 relevant emojis; visual and short. | Warm, curious, behind-the-scenes. |
| **README, docs, in-app text** | No emojis (keep the existing plain style). | Precise and scannable. |

Use emojis that describe the project, not the threat: 🌍 map/world, 🔎 context/lookup, 🛡️ defensive posture,
💚 free/open project, 🤝 community/voluntary support. Do **not** use 🔴/🟠/🟢 or police/alert emojis as severity
labels; the sources are context, not a verdict. Avoid a wall of emojis; one idea per line is better than five
symbols in a row.

**LinkedIn variant (one emoji, at the end):**

> AtlasSOC Desktop 0.8.0 beta adds optional, non-commercial OSINT context to the live GreyNoise view: known
> exploited vulnerabilities, attack ports, malicious certificates and URLs, community reports, ransomware
> aggregates, click-only host checks, certificate watch-lists, advisory netblocks and phishing domains. Every
> source is optional and switchable; off means no requests. Your own provider keys stay in the OS credential
> store, and a copy-paste AI prompt helps you add them safely. Free and open source, with voluntary support
> through Ko-fi. Windows beta is unsigned. 🔎

**Facebook variant (friendly, 3 emojis):**

> More context, same calm view. 🌍
>
> The next AtlasSOC Desktop beta adds optional OSINT context to the GreyNoise map: what is being exploited, which
> ports are being hit, malicious certificates and URLs, community reports, ransomware trends, a click-only host
> check, certificate watch and a phishing-domain list. Everything is optional; switch a source off and it makes no
> requests. Your own free API keys stay in your operating system's credential store, and a copy-paste AI prompt
> can walk you through setting them up safely. Free, open source, and built to stay that way. 💚
>
> Windows beta is unsigned, so SmartScreen may ask first. If you want to support the project, a voluntary Ko-fi
> tip helps cover signing certificates and licences. 🤝

**Instagram caption (short, 4 emojis):**

> A calmer way to add OSINT context to your SOC view 🔭
>
> Known exploited vulnerabilities, attack ports, malicious certificates and URLs, community reports, ransomware
> trends, click-only host checks, certificate watch and phishing domains — optional, non-commercial, and yours to
> switch off. Your keys stay in your OS credential store. A copy-paste AI prompt helps you set them up safely 💚
>
> Free and open source. Voluntary support via Ko-fi, never required 🤝
>
> #ThreatAtlas #AtlasSOC #OSINT #OpenSource #CyberSecurity

Keep the website copy emoji-free even when the same text is reused from social. On LinkedIn, if the post already
has a visual or a link preview, zero emojis is better than one.

### README paragraph

> **Your own API keys (optional).** Keyed OSINT sources use your own free provider key. Keys are stored in the
> macOS Keychain or Windows Credential Manager, held in memory by the worker and sent only to that provider. The
> Settings screen has a per-source switch; off means no requests. If you want help creating the accounts and
> adding the keys, copy the **AI key guide** prompt into any chat assistant — it walks you through one step at a
> time and never asks for the key. See [docs/OSINT-API-KEYS.md](docs/OSINT-API-KEYS.md).

## GitHub follow and transparent source — carry to the next release

**Not published now.** Keep this for the next release notes/README/social copy.

Use the GitHub link **sparingly**, not in every post. It is a follow/source link, not a sales CTA.

- Public repository: https://github.com/ibert-ai/threat-atlas
- To get release notifications: open the repository, choose **Watch → Custom → Releases**. A logged-in user can
  also open https://github.com/ibert-ai/threat-atlas/subscription directly.
- The full project source is open on GitHub. Read it **before** you decide to use the app or get involved.
- In-app updates are **being worked on**, not available yet. Until they ship, get new versions from the GitHub
  Releases page and verify the published checksums. Do not promise a release date.

### Ready-to-use follow/source copy (use at most once per release)

> Want to follow the work? Watch the repository on GitHub and choose **Releases** to be notified when a new
> version is out: https://github.com/ibert-ai/threat-atlas. The project is open source — you can read the whole
> thing before you decide to use it.
>
> We are working on updating versions from inside the app. Until that is ready, releases are published on GitHub
> with checksums. Nothing is hidden: read the source, the release notes and the known limits first.

Short version for a release note footer:

> Follow releases on GitHub: https://github.com/ibert-ai/threat-atlas (Watch → Custom → Releases). In-app
> updates are in development; the full source is open for inspection before you use it.

## Do not say (guardrails)

- "Released", "available now", "stable" or a download link until Robert gives the go and the exact build exists.
- "Signed Windows" or "no warnings": the Windows beta is unsigned. SmartScreen/UAC/Defender prompts are expected;
  never tell users to disable protection.
- "All sources work" before PR #79 is merged and the Windows build is manually tested. Mark keyed sources as
  beta/being tested.
- "Secure/private" as an absolute: say what is sent, to whom, and that keys stay in the OS store. Source data can
  be wrong; context is not a verdict.
- "Spamhaus" in promotional/social copy; use "advisory netblocks" there. Factual docs/in-app labels are fine.
- "Tested on all AI models" or "works with every assistant": say "works with any chat assistant, large or small;
  smaller models make more mistakes" and note the limited testing.
- "Charity", "tax-deductible", "nonprofit", "all profits": use "voluntary tips", "without profit", "goes back
  into the project". Robert pays personally; tips go to him for the project.
- "Cloudflare/OTX/abuse.ch/… endorses us": no provider endorsement is implied.
- A release date or a promise that 1920x1080 scaling/multi-screen is in this beta. It is not.
- Emojis on ibert.se, or more than one on LinkedIn, or emojis as severity labels (🔴/🟠/🟢). Keep docs, README
  and in-app text emoji-free.

## Open decisions for Robert and CL

1. Freeze the source list and stage: which of the **†** sources are in the first Windows beta, and which wait.
2. Confirm the version/build string and the exact Windows package name for the announcement.
3. Confirm PR #79 merge and the Windows key-entry UX before saying "Windows Credential Manager" in public copy.
4. Confirm the AI guide is in the build; if not, present it as "coming in the beta" or hold the paragraph.
5. Choose language(s): English docs plus Swedish social variant? The prompt answers in the customer's language.
6. Confirm the Ko-fi URL and the final support wording; link it from README, Settings/Help and `FUNDING.yml`.
7. Decide whether the ransomware.live provider certificate outage belongs in "known issues" (it was a provider
   problem, not an app bug) and how to phrase it without blaming the provider.
8. Keep the scaling/bottom-crop limitation in Known bugs; do not let the announcement imply it is fixed.

## Internal status notes

- Confirmed in the app before PR #79: KEV/EPSS, Tor, SANS, ransomware.live, Shodan InternetDB, Spamhaus DROP,
  Phishing.Database, SSLBL.
- PR #79 work adds OTX, ThreatFox, URLhaus, AbuseIPDB, Cert Spotter and macOS/Windows key entry; the AI guide is
  in the same working branch. Confirm the final PR/build contents before announcing either.
- Out: Team Cymru (004), RIPE RIS (010), GeoLite2, Windows signing, 1920x1080 scaling, multi-screen.
- The public status page is CL-owned; do not edit `public-status.json` by hand.
- The GitHub follow/source link is used sparingly, at most once per release — not as a recurring CTA. Do not
  promise that in-app updates are available now or give a date; say they are being worked on.
- Do not imply the GitHub watch/subscription page is a download page. The public download source is the Releases
  page; the subscription page is only for notification settings and requires login.
