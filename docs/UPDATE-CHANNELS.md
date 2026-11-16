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
- Switching to a more stable channel never downgrades automatically. It only stops offering newer prereleases. The user may install the stable version manually from Settings.
- A channel pointer that is empty or unreachable falls through to the next channel; if the feed itself is unreachable or invalid, the app keeps the current version and shows the last successful check time.

## 4. The update feed

**Why a feed instead of calling the GitHub API directly:** one source for the apps and both scripts, no API rate limits for many users, explicit control over what each channel offers, and a way to withdraw a version without deleting a release.

**Location (decided):** a dedicated branch `update-feed` in the public repository, containing only `feed.json` and `history/`. Apps read `https://raw.githubusercontent.com/ibert-ai/threat-atlas/update-feed/feed.json`. A separate branch means a release does not need a merge to `main`. A copy of the feed is also uploaded as a release asset for offline mirrors.

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
              "url": "https://github.com/ibert-ai/threat-atlas/releases/download/atlassoc-v0.8.0-rc.1/AtlasSOC-Setup-0.8.0-build15.exe",
              "sha256": "e86ecccc3f348de59d04af80637bae2e4d76829df27f8a4178e0bd39b31acc13", "size": 4099642,
              "signature": "unsigned" }
          ],
          "notes_url": "https://github.com/ibert-ai/threat-atlas/releases/tag/atlassoc-v0.8.0-rc.1"
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
- Downloads come only from `https://github.com/ibert-ai/threat-atlas/releases/download/…`; any other host in the feed is rejected.
- **Decided:** sign `feed.json` with a detached Ed25519 signature (public key built into the apps) so a compromised branch cannot redirect users. The signing key must be held by the owner, not stored in the repository. Without it, anyone with push rights to the branch controls what users are offered.

## 5. Keeping the feed maintained

- A script `scripts/update-feed.py` generates and validates the feed from the GitHub release metadata and the published `SHA256SUMS` file. It refuses entries whose asset is missing, whose hash differs from the one downloaded back, or whose tag does not exist.
- The release checklist (`docs/RELEASING.md`) gains a mandatory step: *update and verify the feed* before a release is announced. A release is not "published" in the project's own records until the feed points to it.
- CI check on pull requests and on a **daily schedule**: every URL in the feed returns HTTP 200, every hash matches the downloaded file, every channel pointer resolves, every `withdrawn` tag is excluded from all pointers.
- Publisher (CL) owns the feed. MAC reviews feed changes in the same way as release evidence. Changes are normal commits, so the history is the audit trail.

## 6. Settings → Updates (every app)

- Installed version, build and **its own channel** (for example "0.8.0 RC 1, build 15, release candidate").
- **Channel selector:** Stable (default), Release Candidates, Betas. Selecting RC or Beta shows a plain warning: *"Pre-release versions can contain bugs. If a pre-release is pulled, you are offered the next safer version."*
- **Automatic updates:** Off, Notify me, or Download and ask. "Download and ask" downloads and verifies in the background, then starts the installer when the user approves. Operating-system approval prompts remain. Never silent elevation, never a disabled security check.
- **Check now**, last check time and result, the version that would be installed, and a link to the release notes.
- Defers while the app, the screensaver host or System Settings is running; never forces a process to close.
- Offline or feed errors: keep the current version, show the reason.

## 7. Scripts (direct download of the newest version per channel)

- `scripts/get-latest.ps1` (Windows PowerShell 5.1+) and `scripts/get-latest.sh` (macOS and Linux terminal). Parameters: `-Product atlassoc|screensaver`, `-Channel stable|rc|beta`, `-DownloadOnly`, `-Force`, `-Silent` (no prompts from the script; Windows and macOS approvals still appear).
- They read the feed, apply the same fallback rules, verify the SHA-256 and print the resolved version, channel and file path. They start the normal installer only when asked.
- The existing `scripts/update-atlassoc.ps1` is extended from `stable|beta` to `stable|rc|beta` and moved onto the feed. A one-line command for each channel goes into `README.md` and `docs/UPDATES.md`.

## 8. Scope and order of work

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
2. **Feed signature:** `feed.json` is signed with a detached Ed25519 signature. The private key is held only by the owner and is never stored in the repository, in Git handovers or by an agent. Apps embed the public key and reject an unsigned or wrongly signed feed (they keep the installed version). Open detail for the implementation: how the owner signs each feed update without giving the key to an agent (for example, an agent prepares the unsigned feed and the owner signs it locally with a small script).
3. **Default automatic mode on a fresh install:** *Notify me*. "Download and ask" and "Off" stay selectable. Nothing is downloaded in the background by default.
4. **One implementation:** the screensaver and AtlasSOC share one Settings → Updates design and one feed.
5. **Beta channel display:** shown only when the feed lists a beta for that product.
