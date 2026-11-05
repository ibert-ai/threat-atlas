# Windows standalone SOC development beta

The PR19 Windows host is a standalone app, separate from `ThreatAtlas.scr`. It uses the same SOC renderer as the macOS app, with a single GreyNoise feed shared by every display window. The development package is AtlasSOC0.7.0/build9 by Ibert Consulting, using the exact Sentinel resources from PR20. This is not a new screensaver release or public-release acceptance.

## Build and run

On Windows 10/11 x64 with Rust MSVC, Python 3 and Visual Studio C++ build tools:

```powershell
./scripts/build-windows-soc.ps1
./scripts/test-windows-soc.ps1
./dist/windows-soc/AtlasSOC.exe
```

The build checks the reviewed Cloudflare licence against current published terms and fails if they change or cannot be retrieved. It never records new legal approval automatically. Run the repository security review/audit gates as well before accepting a release candidate.

Extract the ZIP into a user-owned folder and launch `AtlasSOC.exe`. No administrator rights, screensaver selection, startup task, sleep inhibition or lock preference change is required. The EXE is unsigned; ordinary Windows reputation/trust checks apply. Do not disable those protections. Close the app before replacing its portable folder. Uninstall by removing that extracted folder; settings remain in `%LOCALAPPDATA%/ThreatAtlasSOC` for subsequent versions. There is no standalone MSI or auto-updater in this increment. Existing screensaver installers are not standalone SOC installers. The full required installer scope/shortcut behavior is specified separately in [ATLAS-SOC-INSTALLER.md](ATLAS-SOC-INSTALLER.md).

## Consent and network behavior

The first normal launch shows the Cloudflare Radar data notice, CC BY-NC 4.0 attribution/noncommercial restriction, legal/source URLs and reviewed fingerprints. **No** is the default; declining quits without a feed. Only the person reviewing the terms may choose Yes. Acceptance does not grant commercial-use permission. Acceptance is bound to full app version/build plus notice/legal hashes; any change requires reconfirmation. Settings reset does not accept or erase consent.

After consent, one background worker connects with verified TLS to `wss://threat-map-api.greynoise.io/ws`. Counts are received records, not unique attacks; timestamps describe receipt and do not establish upstream event age or attacker identity. No raw telemetry, credentials or API tokens are saved in settings. Windows has no Cloudflare request worker or token store in this increment; Radar aggregates are not fabricated or inferred from GreyNoise records.

`--smoke-test REPORT.json` is an offline rendering/lifecycle test. It constructs no feed, does not read or change real consent and displays no synthetic attack records. It does not prove live telemetry or accept licence terms.

## Controls and persistence

Right-click for native controls; F1 shows help. F11 toggles fullscreen; Escape leaves fullscreen/mirroring before closing. Ordinary mouse movement does not exit. R/C/S select Realtime/Calm/Still; Space freezes the displayed frame while the feed continues; 1/2/3 toggle provider severity classes; M mirrors all detected displays; T toggles always-on-top. Frame caps are 5/10/20 fps. Left-click focuses a country; hovering shows inspection details in the title.

Settings are bounded, versioned JSON under `%LOCALAPPDATA%/ThreatAtlasSOC/settings.json`, separate from `consent.json`. Invalid or oversized settings fall back to defaults and report the problem. Changes use atomic replacements. Mirror windows recover from monitor geometry/list changes; the feed and renderer remain shared. There is a 16-window cap and a 34-megapixel limit per display.

## Acceptance limits

Mirrored fullscreen windows are implemented. Per-display log/metrics roles, selected-display layouts, spanning canvases, login startup, standalone MSI/upgrade integration and an eight-hour physical wall soak remain pending. Automated native smoke covers window creation, drawing and exit without networking; it does not prove physical mixed-DPI/hotplug behavior, live feed delivery, idle/lock acceptance, signature trust or installation on another machine. MAC owns final cross-platform integration, product identity, documentation and publication. Preserve stable screensaver releases and keep the combined beta blocked until required gates pass.

## Update to the latest version

Run this in PowerShell. It asks for stable or beta, verifies the installer's SHA256 against GitHub, and starts the normal installer. Windows may show a UAC prompt or an unsigned-file warning.

```powershell
irm https://raw.githubusercontent.com/ibert-ai/threat-atlas/main/scripts/update-atlassoc.ps1 -OutFile "$env:TEMP\update-atlassoc.ps1"; powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\update-atlassoc.ps1"
```

Add `-Channel beta` or `-Channel stable` to skip the question, `-Force` to reinstall the same version, or `-DownloadOnly` to stop after verification. `stable` finds nothing until a full AtlasSOC release exists.
