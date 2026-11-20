# Linux AtlasSOC: gap list (LX0)

Reference `ATLAS-SAVER-PARITY-001`, package LX0. Measured on `codex/osint-sources` on 16 November 2026. Windows reference: `crates/windows/src/soc_*.rs`; Linux today: `crates/linux/src/bin/atlassoc.rs` (259 lines, `minifb` with X11 only).

## What the Linux host already has
Feed and renderer from the core, `R/C/S` motion, `L` layout, `1/2/3` severities, freeze, country click-to-focus, hover label in the title, 2.4:1 wide layout, `--help`, an offline smoke test in CI.

## Gaps, and where each is closed

| Gap | Windows has it as | Closed in | Needs |
|---|---|---|---|
| HTTPS for the OSINT sources | WinHTTP hook (`soc_osint.rs`) | **already in core**: `osint_net::https_get` / `https_post` (rustls, bundled web roots) | wire the worker to those two functions; no new HTTP client |
| OSINT worker, text pages, 13 sources | `soc_osint.rs` re-exports `osint_worker` | core (shared) | Linux host starts the worker, reads the settings, draws the cards |
| Settings file, terms acceptance | `soc_config.rs` (`Settings`, `Terms`, atomic write) | **core** (move, keep behaviour) | LX3: lift `soc_config.rs` logic that is not Windows-specific into the core, then use it from both hosts; the saver (SP2) reads the same file |
| Credentials (OSINT keys, Radar token) | Credential Manager (`soc_radar::osint_keys`) | **new, Linux host**: Secret Service over D-Bus, no plain-text fallback | LX2; new dependency, so run the dependency audit and `THIRD-PARTY-NOTICES.txt` |
| Menu, Settings window, dialogs | Win32 popup menu (`soc_host.rs`) | **new, Linux host** | `minifb` has no menus or dialogs, see decision below |
| Fullscreen toggle, saved window size | `tao` fullscreen, settings | Linux host | follows from the window decision |
| Cloudflare Radar | `soc_radar.rs` (675 lines) | held | LX4 waits for Cloudflare (D2) |
| Update notice | `soc_update.rs` (102 lines) | Linux host | LX6, after UPDATE-CHANNELS WP3 |
| Packaging | installer | `scripts/build-linux-soc.sh` (tar.gz) | LX5: AppImage first |
| Wayland | `tao` supports it | window decision | LX7 |
| Real-machine evidence | physical Windows and Mac tests | Billy | LX1 |

## Decision for LX3 (made by CL, recorded; revisit only on evidence)
Move the Linux host from `minifb` to `tao` + `softbuffer`, the stack the Windows host already uses. Reasons: native Wayland and X11 from one code path, window state and fullscreen come for free, and it keeps one host pattern across platforms. The menu and Settings are drawn **inside the window by the core renderer** (overlay panels using the existing text and card drawing), so no GTK is added. That avoids the GTK/glib advisories listed in `docs/ATLAS-SOC-BETA.md` and keeps Linux, a later Linux screensaver and the Windows host on the same panels.
Fallback if the overlay proves too limited in the LX3 spike: a separate small Settings window on the same stack. A spike result decides, with screenshots.

## Order
LX1 (Billy, now) and LX0 (this) first. Then LX3's window move, LX2 credentials, the settings lift into the core, then Settings and cards. LX4 stays out until Cloudflare answers.
