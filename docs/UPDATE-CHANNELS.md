# Update channels, automatic upgrades and the update feed (plan for the next version)

Status: **specification only. Nothing in this document is built yet.** It was requested by the owner on 16 November 2026 after AtlasSOC 0.8.0-rc.1, for the next version of every Threat Atlas project (screensaver and AtlasSOC Desktop). The five owner decisions in section 10 were taken on 16 November 2026 (all recommendations accepted).

## 1. What the owner asked for

1. A new **Settings → Updates** section in every app.
2. **Automatic upgrade**, even when the operating system still needs the user's approval (installer prompt, UAC, Gatekeeper).
3. A choice of **update channel**: **Stable** (default), **Release Candidates** and **Betas**.
4. **Fallback** between channels: Beta falls back to the newest RC; RC falls back to Stable. If we must pull a version, the fallback must still work.
5. A **PowerShell script and a terminal script** that fetch the newest version of each channel directly.
6. The **feed in Git must be maintained** (not left to go stale).

## 2. Today (verified in the code, 16 Nov 2026)

- `crates/core/src/update.rs`: parses GitHub release JSON; `newer(body, current, include_prerelease)` picks the newest non-draft release; `is_prerelease(identity)` makes a pre-release build follow the beta channel. Only two modes exist (stable, "includes pre-releases").
- `scripts/update-atlassoc.ps1`: Windows script with channels `stable` and `beta`; verifies the installer SHA-256 against the digest GitHub reports and starts the normal interactive installer.
- `crates/windows/src/soc_update.rs`, `macos/Updater.swift`, `updater/Update-ThreatAtlas.ps1`: per-user updaters for the screensaver. They read only `releases/latest` (stable) and reject pre-releases. `docs/UPDATES.md` describes this and its trust rules.
- macOS AtlasSOC Settings → Updates (`private-beta/cloudflare-macos/OsintSettingsView.swift`) only shows the installed version and a button that opens the GitHub releases page. **It also still says "This beta is not Developer ID signed yet", which is wrong since RC1 is signed and notarised. Fix this text in the next version (see section 9).**
- AtlasSOC releases must stay pre-release with `latest=false` while a screensaver stable is `releases/latest`, because the screensaver updaters read `releases/latest`. That coupling is exactly why a feed is needed.

## 3. Channels and fallback

| Selected channel | Offers | Resolution |
|---|---|---|
| **Stable** (default) | newest stable | stable only |
| **Release Candidates** | newest of RC and stable | highest version wins; if no RC is newer than stable, the user gets stable |
| **Betas** | newest of beta, RC and stable | highest version wins; falls back to RC, then stable |

Rules:

- Versions use SemVer precedence: `0.8.0-beta.2 < 0.8.0-rc.1 < 0.8.0`. A newer stable always beats an older RC or beta, so a user on Beta moves to the stable release when it ships.
- **Pulling a version:** the feed lists `withdrawn` tags. The client never offers a withdrawn version and skips it when resolving the channel, which gives the fallback automatically (a withdrawn beta resolves to the newest good RC, and so on).
- If the **installed** version is withdrawn, the app shows a warning and offers the channel's resolved version as a **user-approved** move. It never downgrades silently. Downgrades need an explicit `rollback_to` entry in the feed and the user's approval.
- **Switching to Stable from a pre-release channel reinstalls the whole app with the latest stable version** (decision Q4, section 11). It happens only after a confirmation dialog ("This replaces 0.9.0-beta.2 with 0.7.0") with a Cancel button, never automatically. Settings are backed up first and keys stay in the Keychain / Credential Manager. Switching from Beta to RC works the same way if the RC is older than the installed version.
- A channel pointer that is empty or unreachable falls through to the next channel; if the feed itself is unreachable or invalid, the app keeps the current version and shows the last successful check time.

## 4. The update feed

**Why a feed instead of calling the GitHub API directly:** one source for the apps and both scripts, no API rate limits for many users, explicit control over what each channel offers, and a way to withdraw a version without deleting a release.

**Location (decided):** a dedicated branch `update-feed` in the public repository, containing only `feed.json` and `history/`. Apps read `https://raw.githubusercontent.com/Ibert-Iam/threat-atlas/update-feed/feed.json`. A separate branch means a release does not need a merge to `main`. A copy of the feed is also uploaded as a release asset for offline mirrors.

**Shape (draft, `schema_version` 1):**

```json
{
  "schema_version": 1,
  "generated_at": "2026-11-16T12:00:00Z",
  "products": {
    "atlassoc": {
      "channels": {
        "stable": { "version": "0.7.0", "tag": "atlassoc-v0.7.0" },
        "rc":     { "version": "0.8.0-rc.1", "tag": "atlassoc-v0.8.0-rc.1" },
        "beta":   null
      },
      "releases": [
        {
          "version": "0.8.0-rc.1", "build": 15, "tag": "atlassoc-v0.8.0-rc.1",
          "channel": "rc", "published_at": "2026-11-15T19:54:43Z",
          "min_supported_from": "0.6.0",
          "assets": [
            { "platform": "windows-x64", "kind": "installer", "name": "AtlasSOC-Setup-0.8.0-build15.exe",
              "url": "https://github.com/Ibert-Iam/threat-atlas/releases/download/atlassoc-v0.8.0-rc.1/AtlasSOC-Setup-0.8.0-build15.exe",
              "sha256": "e86ecccc3f348de59d04af80637bae2e4d76829df27f8a4178e0bd39b31acc13", "size": 4099642,
              "signature": "unsigned" }
          ],
          "notes_url": "https://github.com/Ibert-Iam/threat-atlas/releases/tag/atlassoc-v0.8.0-rc.1"
        }
      ],
      "withdrawn": []
    },
    "screensaver": { "channels": { "stable": { "version": "0.4.8", "tag": "v0.4.8" }, "rc": null, "beta": null }, "releases": [], "withdrawn": [] }
  }
}
```

**Trust rules (unchanged in spirit from `docs/UPDATES.md`):**

- The feed is only a **pointer**. It never authorises installation by itself. The client verifies the SHA-256 from the feed, then the OS signature where the artifact is signed (Authenticode, Developer ID plus Gatekeeper), and fails closed on a mismatch or on an unexpected publisher.
- Downloads come only from `https://github.com/Ibert-Iam/threat-atlas/releases/download/…`; any other host in the feed is rejected.
- **Owner name:** the GitHub account was renamed from `ibert-ai` to `Ibert-Iam` on 16 November 2026. Only `Ibert-Iam` is accepted. The old name is an empty reserved organisation (so nobody else can claim it) and every validator rejects it explicitly; old URLs still redirect, but an updater must never trust a redirect target it did not pin. Shipped 0.4.x screensaver updaters pin the old path and therefore reject the new URLs (known limit of already released versions).
- **Decided:** sign `feed.json` with a detached Ed25519 signature (public keys built into the apps) so a compromised branch cannot redirect users. See section 10, decision 2, for who holds the keys and the rotation rule. Without it, anyone with push rights to the branch controls what users are offered.

## 5. Keeping the feed maintained

- A script `scripts/update-feed.py` generates and validates the feed from the GitHub release metadata and the published `SHA256SUMS` file. It refuses entries whose asset is missing, whose hash differs from the one downloaded back, or whose tag does not exist.
- The release checklist (`docs/RELEASING.md`) gains a mandatory step: *update and verify the feed* before a release is announced. A release is not "published" in the project's own records until the feed points to it.
- CI check on pull requests and on a **daily schedule**: every URL in the feed returns HTTP 200, every hash matches the downloaded file, every channel pointer resolves, every `withdrawn` tag is excluded from all pointers.
- Publisher (CL) owns the feed. MAC reviews feed changes in the same way as release evidence. Changes are normal commits, so the history is the audit trail.

## 6. Settings → Updates (every app)

- Installed version, build and **its own channel** (for example "0.8.0 RC 1, build 15, release candidate").
- **Channel selector:** Stable (default), Release Candidates, Betas. Selecting RC or Beta shows a plain warning: *"Pre-release versions can contain bugs. If a pre-release is pulled, you are offered the next safer version."*
- **Automatic updates:** Off, Notify me (default) or **Download and install**. Download and install downloads and verifies in the background and **applies the update the next time the user starts the app**, never by closing or restarting a running app. If no instance is running when the check happens, it installs at once. Without that mode the app shows a banner about a new version in the user's own channel. Operating-system approval prompts remain. Never silent elevation, never a disabled security check.
- **Check now**, last check time and result, the version that would be installed, and a link to the release notes.
- Never forces a process to close. A running app, screensaver host or System Settings simply defers the installation to its next start. A long-running SOC wall therefore keeps its version until someone starts it again; the banner says "Update downloaded, installs next time the app starts".
- Offline or feed errors: keep the current version, show the reason.

## 7. Scripts (direct download of the newest version per channel)

- `scripts/get-latest.ps1` (Windows PowerShell 5.1+) and `scripts/get-latest.sh` (macOS and Linux terminal). Parameters: `-Product atlassoc|screensaver`, `-Channel stable|rc|beta`, `-DownloadOnly`, `-Force`, `-Silent` (no prompts from the script; Windows and macOS approvals still appear).
- They read the feed, apply the same fallback rules, verify the SHA-256 and print the resolved version, channel and file path. They start the normal installer only when asked.
- The existing `scripts/update-atlassoc.ps1` is extended from `stable|beta` to `stable|rc|beta` and moved onto the feed. A one-line command for each channel goes into `README.md` and `docs/UPDATES.md`.

## 8. Scope and order of work (superseded by the work packages in section 12)

1. Feed schema, `scripts/update-feed.py`, CI checks, initial feed (stable, RC1, empty beta), decisions in section 10.
2. Core resolver in `crates/core/src/update.rs` (channel resolution, withdrawn handling, unit tests including every fallback case) and Swift/PowerShell equivalents.
3. Settings → Updates UI in the Windows host and the macOS app; automatic mode.
4. `get-latest` scripts.
5. Screensaver updaters (`soc_update.rs`, `Updater.swift`, `Update-ThreatAtlas.ps1`) moved to the feed with channel selection. They keep the signed-artifact requirement from `docs/UPDATES.md`; an unsigned Windows build can therefore be *downloaded and offered*, but cannot be silently updated until Windows signing exists.
6. Docs: `docs/UPDATES.md`, `docs/RELEASING.md`, `README.md`.

## 9. Acceptance and tests

- Unit tests: stable/RC/beta resolution with every combination of present and missing channels; withdrawn pointer falls back; a newer stable beats an older RC and beta; no silent downgrade; invalid, oversized or non-GitHub-host feeds rejected.
- Feed tests: schema validation, hash and URL checks, daily CI check passes.
- Real tests per platform: N → N+1 on Stable; Beta → RC fallback by withdrawing a test beta; offline retry; interrupted download; rejected wrong-hash artifact; approval prompts appear and nothing is installed without them.
- **Bug to fix in the same version:** the macOS Settings text that says the beta is not Developer ID signed. The text must follow the build's real signing state.
- A real signed N → N+1 test on Windows needs a signing certificate (Certum order pending). Until then Windows automatic update is "download, verify, ask".

## 10. Owner decisions (taken 16 November 2026: all recommendations accepted)

1. **Feed location:** a dedicated branch `update-feed` in the public repository (not a file on `main`).
2. **Feed signature (revised the same day at the owner's request):** `feed.json` is signed with a detached Ed25519 signature, and the **publisher agent (CL) holds the daily signing key**, so feed updates and withdrawals never wait for the owner (for example during the night). Safeguards that go with this:
   - The signing key is generated on the publisher's machine for this one purpose, stored in the macOS Keychain, and never written to the repository, Git handovers, Telegram, logs or command arguments. It signs only `feed.json` for Threat Atlas and AtlasSOC, and is never used for anything else.
   - Apps embed **two** public keys: the signing key and an offline **recovery key held only by the owner**. A feed update that rotates the signing key must be signed by the recovery key. If the signing key is ever lost or suspected compromised, the owner rotates it without shipping a new app version.
   - The signing script refuses to sign a feed that fails `scripts/update-feed.py` validation (hashes, URLs, channel pointers, withdrawn tags), and logs each signing (feed hash, time, release tag) in the private handover.
   - Apps reject an unsigned or wrongly signed feed and keep the installed version.
3. **Default automatic mode on a fresh install:** *Notify me*. "Download and ask" and "Off" stay selectable. Nothing is downloaded in the background by default.
4. **One implementation:** the screensaver and AtlasSOC share one Settings → Updates design and one feed.
5. **Beta channel display:** shown only when the feed lists a beta for that product.

## 11. Decisions from the design interview (16 November 2026)

All 13 questions were answered by the owner. Q-numbers match the interview.

| # | Decision |
|---|---|
| Q1 | Install **directly**, but never by closing a running app (Q1c): the update waits and installs the next time the user starts the app. |
| Q1b | Direct install only for users who chose the mode *Download and install*. Everyone else gets a banner about a new version in their own channel (Beta, RC or Stable). Default stays *Notify me*. |
| Q2 | Automatic updates only for Windows installed **per user**. A machine-wide Windows installation gets a notice and a button that opens the installer, where the user approves UAC. |
| Q3 | One check per day at start or the first opportunity, with a random delay, plus a **Check now** button. Same interval for all channels. |
| Q4 | Switching to Stable **reinstalls the whole app** with Stable (see section 3 and Q4b). |
| Q4b | A dialog with Cancel before the reinstall; settings are backed up first (Windows `settings.json` has `schema_version`; on macOS the preferences are exported because `UserDefaults` has no version); keys stay in the Keychain / Credential Manager; if the older version cannot read the settings it starts with defaults and the backup is kept. |
| Q5 | A withdrawn installed version gets a visible banner offering the next safe version. The scenario is untested; we only make room for it. |
| Q6 | The app stores and sends nothing beyond what cannot be avoided (the request itself reveals the IP address to the host). No version header, no installation ID, a generic user agent, nothing reused for other purposes. Stated in the privacy text. |
| Q7 / Q7b | A custom feed is a good feature and is offered **as a mirror only**: the user copies our signed feed and files to their own https server. We run nothing, see no traffic and keep no logs. Our signing keys stay required (no custom keys in this version). A banner says "custom feed in use". The mirror owner is responsible for their own server and logs. |
| Q8 / Q8b | Automatic installation of **unsigned Windows builds** is allowed only after the user actively ticks a consent box (not pre-ticked) saying the build is not signed by a trusted publisher, that Windows therefore cannot confirm who created it, that the software is open source under the MIT licence and provided as is, and that the user wants automatic installation. The feed signature and the SHA-256 check stay mandatory. The consent is stored locally (date, version; nothing is sent) and is asked again when the signing state changes and for every new major version. Without consent nothing is installed automatically. **The wording is reviewed by a qualified person before release**, because the owner is legally responsible for what is published. |
| Q9 | The screensaver shows a banner, but the user must go into Settings and click Update; no automatic installation on Windows until a signed certificate exists. |
| Q10 | Banners appear at the top of the apps and in Settings → Updates; for the screensaver only in its settings dialog, never while it runs. |
| Q11 | A banner can be dismissed per version and returns only for a newer version in the same channel; Settings always shows that an update exists. |
| Q12 | The screensaver's Update button downloads and verifies the file, then opens the normal installer where the user approves UAC or the macOS prompt. |
| Q13 | The macOS screensaver's existing automatic updater stays as an optional switch, off by default; with the switch off the banner and button apply. |

Still open (not decided): the exact wording of the consent text (work package WP7, owner review), the test plan for N → N+1 before a signed Windows build exists (WP9), and which version is the first to include the Updates view (owner decision at release planning).

## 12. Work packages

| WP | Work | Owner | Needs |
|---|---|---|---|
| WP1 | Publish the feed on the `update-feed` branch, signing script (key held by the publisher in the macOS Keychain), daily link and hash CI job | CL | owner's offline recovery public key (R1) |
| WP2 | Core resolver, staging area and apply-on-start logic in `crates/core/src/update.rs`, with tests for every channel and fallback case | CL | PR 94 merged |
| WP3 | Windows host: Settings → Updates (channel selector, banner, modes, per-user rule, machine-wide notice, consent box, reinstall to Stable, mirror setting) | CL | WP2, WP7 text |
| WP4 | macOS app: the same view; fix the stale text "This beta is not Developer ID signed yet" | CL | WP2 |
| WP5 | Screensaver: banner and Update button in the settings dialogs, macOS optional auto switch | CL | WP2 |
| WP6 | `get-latest` scripts (PR 95) finished and reviewed | CL, review MAC | PR 94, 95 |
| WP7 | Consent text, privacy text (Q6), `docs/UPDATES.md`, `PRIVACY.md`, README | MAC drafts; owner has the consent text reviewed (R2) | decisions above |
| WP8 | Guide for mirroring the feed (Q7b), no data on our side | MAC | WP1 |
| WP9 | Test plan and execution: Windows per-user and machine-wide, withdrawn-version fallback, Beta to RC to Stable, switch to Stable reinstall, offline, interrupted download, wrong hash, no silent installation; macOS equivalents | Billy (Windows), CL (macOS) | WP2 to WP5 builds |
| WP10 | Announcement and website text after release | Seek | release published |
| R1 | Create and hold the offline recovery key; give CL the public part | Robert | none |
| R2 | Have the consent text reviewed by a qualified person | Robert | WP7 draft |
| R3 | Choose the first version that includes the Updates view | Robert | WP2 to WP5 progress |
