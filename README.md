# Threat Atlas SOC

Native Rust SOC screensaver for macOS 12+ and Windows 10/11 x64. It draws a world
map, animated routes, receipt counters and a recent-observations log from the
GreyNoise public threat-map feed. The header shows both UTC and the computer's local time, including its current UTC offset, using the operating system's timezone and daylight-saving rules. No embedded website, cookies, login or API key.

## Release status

The official **0.4.0**, build **8**, release ships without trusted code signing.
Windows SCR/MSI files are unsigned; macOS bundles are ad-hoc signed and unnotarized.
Systems may warn or block installation. Do not disable OS security protections.
It includes dual clocks, optional signed-update support, macOS preview fixes and
screenshot thumbnails. Automatic updates remain unavailable without trusted signing.
[Downloads](https://github.com/ibert-ai/threat-atlas/releases/tag/v0.4.0).
Manual platform acceptance remains incomplete; see docs/QUALITY.md.
See [release/version handling](docs/RELEASING.md) and [change history](CHANGELOG.md).

## Install

**Windows:** use the MSI matching the release you downloaded. The per-user installer copies the
screensaver to `%LOCALAPPDATA%\ThreatAtlas` and adds a **Threat Atlas SOC** Start
Menu folder. Open **Set up Threat Atlas**, choose the saver, set the wait time,
and Apply. **Preview Threat Atlas** opens a normal window. No manual copying or
administrator account is required. Before uninstalling via Settings → Apps,
select another screen saver. The installer preserves idle, lock and password
settings. See [Windows setup](installer/INSTALL.txt).

**macOS:** extract the macOS ZIP, double-click `ThreatAtlasSOC.saver`, and install
for your user account. Quit and reopen System Settings, then open Wallpaper →
Screen Saver → Custom → Other → Show All and select **Threat Atlas SOC**. The ZIP
also contains **Threat Atlas SOC.app**, a windowed preview. The universal bundle
supports Intel and Apple Silicon. Keep bundles zipped when syncing through cloud
storage: Finder metadata on unpacked bundles can invalidate ad-hoc signatures.
If an upgrade shows a blank **Threat Atlas** preview, check that you selected
**Threat Atlas SOC**, rather than the old 0.2 bundle. Older copies named
`ThreatAtlas.saver` may remain in both `~/Library/Screen Savers` and
`/Library/Screen Savers`; back them up before removing duplicates. The new bundle
uses a distinct class/identifier and includes screenshot thumbnails. Reopen
System Settings after installing. Automatic updating requires a trusted signed
release; it is unavailable in the current unsigned/ad-hoc previews.

This release is unsigned on Windows and ad-hoc signed on macOS. Future trusted
signing is described in [signing instructions](docs/SIGNING.md). Do not disable
OS security protections to run an untrusted download.

## Automatic updates (next signed release)

After a one-time install of a trusted signed build, enable automatic updates:

- **Windows:** Start Menu → Threat Atlas SOC → **Enable automatic updates**.
  A per-user task checks daily while signed in; **Check for updates** runs it now.
- **macOS:** open the preview app and choose **Enable automatic updates** from
  its application menu. This installs the preview in `~/Applications` and a
  per-user LaunchAgent, which checks at login and every 24 hours.

Updates download and install in place without repeating the installation steps.
Checks use stable releases only and defer while the screen saver is running.
They preserve screen saver selection, idle time and password settings.
Unsigned/ad-hoc preview builds cannot enable updates. See [update design and
release requirements](docs/UPDATES.md), including signing-key rotation and removal.

## Data and privacy

The telemetry runtime connects to GreyNoise's public threat-map WebSocket,
`wss://threat-map-api.greynoise.io/ws`, using certificate-validated TLS. GreyNoise
receives your IP address and normal connection metadata. No analytics or observed
IP-address scanning is added. See [GreyNoise's privacy policy](https://www.greynoise.io/privacy-policy).
This independent project is not endorsed by GreyNoise.

The feed supplies no event IDs or event timestamps. Times are local UTC receipt
times; counters are received records, not unique attacks. Routes are a bounded
visual sample and expire after six seconds. LIVE means a valid record arrived
within ten seconds. Stale/offline feeds are labelled and reconnect with backoff.
This viewer cannot verify provider event age or authenticity. Availability and
schema may change. Review the provider's terms before redistributing or using
its feed commercially; the MIT license covers this project's code, not telemetry.

## Build and check

Install Python 3.9+ and current stable Rust. macOS requires Xcode Command Line Tools; Windows
requires MSVC C++ Build Tools and the Windows SDK.

```sh
python3 scripts/version.py --check
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo install cargo-audit --version 0.22.2 --locked
cargo audit --deny warnings
bash scripts/build-macos.sh --universal
```

Windows:

```powershell
rustup target add x86_64-pc-windows-msvc
powershell -File scripts/build-windows.ps1
```

MSI after building `dist/ThreatAtlas.scr`: install `msitools`/`wixl` on Linux or
macOS, then `bash scripts/build-msi.sh`. The MSI contains an embedded cabinet.
`./scripts/test-msi.ps1` tests installation/uninstallation on a disposable Windows
account. Do not run that test on an account with an existing Threat Atlas install.

GitHub Actions builds both platforms, produces an MSI, runs quality checks and
runs an MSI lifecycle test on a Windows runner. Workflows use read-only repository
permissions and pinned action commits. Release signing is deliberately separate
from untrusted pull-request builds. Enable GitHub private vulnerability reporting
and branch protection after creating the repository.

`cargo run --release --locked -p threat-atlas-core --example verify_live -- audit-run`
checks the external feed for increasing records and changed payloads, producing
frames and JSON. It needs network access and is not an offline CI test.

[Quality review and limitations](docs/QUALITY.md) · [Security policy](SECURITY.md)

## License

Source: MIT. Bundled JetBrains Mono: SIL OFL; see `assets/FONT-LICENSE.txt`.
Natural Earth land outlines are public domain. See `assets/ATTRIBUTION.md`.
Third-party Rust crates retain their own licenses. Provider content is not MIT.
