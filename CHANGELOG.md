## 0.4.6-beta.1 — release candidate, 7 November 2026, build 14

- Add an owner-approved Windows panorama layout for two matching side-by-side displays.
- Keep the map undistorted, place the seam over the Atlantic and keep information panels on one display.
- Correct the panorama window position after physical testing found an eight-pixel left-edge gap.
- Preserve the standard single-display rendering and fall back to it for unsupported display layouts.
- Prepare Windows-only beta packaging; macOS and Linux packages are excluded from this candidate.

## 0.4.5 — 4 November 2026

- Promote the owner-approved 0.4.4 RC implementation to stable for Windows x64 and Linux x86_64 preview.
- Advance installer/version identity and document unsigned distribution, no MSI automatic updater and remaining manual test gaps.
- Exclude macOS pending Gatekeeper trust; preserve previous releases.

# AtlasSOC standalone 0.7.0-beta.1 / build10

- Separate Windows x64 and macOS14+ universal standalone SOC on the shared real-data renderer.
- Provider-classified received records, country focus/inspection, severity filters and Realtime/Calm/Still.
- Windows persistent controls/mirroring and offline native smoke; macOS optional Radar aggregates, version/build/terms consent before network startup.
- Sentinel working identity, pinned Node24 CI actions and platform-specific installation/privacy/known limits.
- Portable Windows beta; final installer/upgrade, physical wall/soak/trusted signing remain incomplete. No Windows Radar or Linux standalone. Existing screensaver release metadata/assets unchanged.

# Changelog

## 0.4.2-rc.1 — beta preparation, 31 October 2026, build 10

- Add country borders and expiring classification shading; preserve country activity independently of the bounded recent-record buffer.
- Add a native Linux windowed preview and archive packaging/hosted smoke check.
- Display the embedded installed product/prerelease/build version in the renderer.
- Integrate Windows scaling/layout coverage and advance MSI ProductVersion to 0.4.2.
- Keep TLS validation, unsigned-update rejection and earlier releases unchanged.

Physical platform, signing, idle/lock and multi-monitor limits remain disclosed in release notes.

## 0.4.1-rc.1 — beta, 29 October 2026, build 9

- Start the next patch development version without changing published 0.4.0 assets.
- Clarify published versus development versions, signing status, update restrictions
  and outstanding platform acceptance in the documentation.

This version/documentation update introduces no runtime feature changes.

## 0.4.0 — 29 October 2026, build 8

- Display UTC and the system local clock with its current UTC offset and DST rules.
- Add optional per-user, publisher-verified automatic updates for Windows/macOS;
  trusted signed releases are required. Unsigned previews cannot enable updates.
- Fix PowerShell 5.1 security-module loading when launched from PowerShell 7.
- Repair macOS first-frame and host lifecycle handling; add screenshot thumbnails.
- Add updater, native rendering and installer regression checks.
- Centralize release metadata and correct outdated documentation/settings text.

On-device Mac Settings acceptance and signed upgrade validation remain pending.
Official unsigned release: Windows files unsigned; macOS ad-hoc signed and
unnotarized. Automatic updates remain unavailable without trusted signing.

## 0.3.0-rc.1 — published 28 October 2026

- Public Rust screensaver preview for Windows x64 and Intel/Apple Silicon Mac.
- Per-user Windows MSI and macOS ZIP distributions.
- GreyNoise live telemetry, bounded rendering/feed processing and quality checks.
- Windows artifacts unsigned; macOS bundles ad-hoc signed.

This published preview predates the clock/updater/macOS repairs listed above.
