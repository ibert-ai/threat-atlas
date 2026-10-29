# Changelog

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
