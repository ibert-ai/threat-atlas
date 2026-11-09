# AtlasSOC 0.7.0 RC1 (release candidate 1) — build 12

Standalone beta for Windows x64 and macOS 14+ (Apple silicon and Intel). Separate from the existing Threat Atlas screensaver. Product: AtlasSOC by Ibert Consulting; Sentinel is the current working icon, with final design selection still open.

## What it does

Observe GreyNoise public threat-map records with provider classifications, received-record counters, country focus/inspection, severity filters and Realtime/Calm/Still display modes. Records are not unique attacks or guaranteed-current incidents. Animation is bounded and may sample received records. This is an observation tool, not prevention software or a production incident-response guarantee.

macOS and Windows additionally support optional Cloudflare Radar past-day aggregate country values. They are not individual realtime attacks or inferred source/target events. Linux standalone is not included. Windows supports persistent native controls and mirrored windows; full SOC-wall roles/spanning are future work.

## Installation

**Windows:** run `AtlasSOC-Setup-0.7.0-build12.exe` and choose **Just me** (no administrator rights) or **Everyone**, plus optional desktop and Start menu shortcuts; or extract the portable `AtlasSOC-Windows-x64-v0.7.0-build12.zip` into a user-owned folder and run `AtlasSOC.exe`. Windows 10/11 x64. Both are unsigned: follow OS trust policy and do not disable security protections. At start AtlasSOC asks `api.github.com` whether a newer AtlasSOC exists and offers it in the right-click menu; nothing installs without your confirmation. Settings/consent stay in `%LOCALAPPDATA%\ThreatAtlasSOC`. Existing screensaver installers are separate products.

**macOS:** unzip `AtlasSOC-macOS-universal-v0.7.0-build12.zip`, then copy `AtlasSOC.app` to your chosen Applications location. Requires macOS14+. The app is ad-hoc signed, not Developer ID signed or notarised; Gatekeeper or organisational policy may refuse to open it. Do not disable Gatekeeper or strip quarantine as a workaround. It installs no startup agent or automatic updater; check the releases page for new versions. Quit before replacement/removal. The existing development bundle identifier `dev.threatatlas.private.radar` and Radar support/Keychain locations are retained for continuity; this bundle is separate from the stable screensaver.

The final Windows installer is planned to offer `%ProgramFiles%\AtlasSOC` for all users or `%LocalAppData%\Programs\AtlasSOC` for one user, and independent desktop/Start menu shortcut choices. Those requirements are NOT implemented by this portable beta. See ATLAS-SOC-INSTALLER.md.

## Consent, credentials and privacy

Before the normal app constructs a feed/worker, the user must accept the displayed Cloudflare Radar notice/CC BY-NC4.0 terms for this exact version/build/notice/legal identity. Decline exits. A changed build or reviewed terms requires acceptance again; no agent or silent install accepts for another person. This beta is for noncommercial Radar use with attribution; commercial permission is separate. Source code licensing does not override provider data terms.

After consent, GreyNoise uses `wss://threat-map-api.greynoise.io/ws` with TLS validation. No probing of observed hosts or added analytics. macOS Radar is opt-in: the tester supplies their own Account/Radar/Read token (step-by-step: [CLOUDFLARE-RADAR-TOKEN-GUIDE.md](CLOUDFLARE-RADAR-TOKEN-GUIDE.md)), stored in macOS Keychain service `ThreatAtlas.PrivateRadarBeta`, account `RadarRead`. Requests go to `api.cloudflare.com`; minimum15 minutes, persisted cooldown, retry/backoff and single-worker lock. Saved aggregate cache/worker lock is under Application Support/ThreatAtlasPrivateRadar. The token is not exported in packages. On Windows the token is stored in Windows Credential Manager (`AtlasSOC/CloudflareRadar`) and the cache/state under `%LOCALAPPDATA%\ThreatAtlasSOC`; same request floor, backoff and single-worker rules. Running saver and standalone may create separate GreyNoise connections. Third-party servers receive normal connection metadata/public IP.

## Known limits

Unsigned Windows and ad-hoc/unnotarised Mac distribution; no trusted automatic update. No standalone installer/upgrade acceptance, physical mixed-DPI/multimonitor/hotplug/Intel-hardware certification, eight-hour soak or full sleep/wake validation. Mirroring is not per-display SOC wall roles or spanning. Dense Radar labels can overlap. Immediate feed-worker shutdown can be delayed during DNS/connect. See SECURITY.md and the versioned verification record; passing offline smoke does not prove live networking or physical hardware coverage.

Unfiltered audit reports three inherited warnings: proc-macro-error1.0.4/RUSTSEC-2024-0370 and glib0.18.5/RUSTSEC-2024-0429 in the Linux-only GTK branch, and ttf-parser0.25.1/RUSTSEC-2026-0192 in the bundled immutable-font path. Existing reviewed exceptions remain unchanged; this is not a clean unfiltered audit. No Linux binary or user/network-font loading is introduced. Maintenance work remains tracked. No claim of vulnerability-free software.

## Updates, feedback and rollback

Download the next explicitly named AtlasSOC standalone package, quit the app and replace only its folder/bundle. Keep a copy of a working prior beta. Do not use the screensaver's signed updater to install this unsigned beta. Preserve profile settings/Keychain data unless you intentionally remove them. Report platform/OS, exact version/build, steps and sanitised logs at https://github.com/ibert-ai/threat-atlas/issues ; never attach tokens or raw private telemetry.
