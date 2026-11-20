# Plan: lift the screensaver to AtlasSOC's feature level without a rewrite

Status: **plan approved by the owner on 16 November 2026 (D1-D4 and the Linux to-do); implementation not started.** Requested by the owner on 16 November 2026. Reference `ATLAS-SAVER-PARITY-001`.

## 1. Why this is mostly composition, not new code

The two products already share one Rust core (`crates/core`). Measured on `codex/osint-sources`:

| Layer | Screensaver | AtlasSOC Desktop |
|---|---|---|
| Data (feed, bounded buffers, countries, clocks) | `core` (shared) | `core` (shared) |
| Rendering | `core::Session` / `render` (panorama frame) | `core::SocSession` / `render::soc::SocView` (cards, panels) |
| Radar aggregates | `core::RadarSession` exists, no saver host uses it | `radar`, `radar_poll`, host `soc_radar.rs` |
| 13 OSINT sources, worker, text, FFI | in `core` (`osint_worker`, `osint_text`, `osint_ffi`), **no saver host calls them** | host `soc_osint.rs` |
| Host code | Windows `windows.rs` 319 lines, macOS `ThreatAtlasView.m` 72 lines (calls `ta_*` C functions), Linux 310 lines | Windows `soc_host.rs` 1277 lines |

The saver hosts are thin: they open a window, ask the core for a frame, blit it. So parity means: add a saver view in the core that reuses the SOC cards, add a small `ta_saver_*` C interface, and let each host start the same data worker. No renderer, parser or source is rewritten.

## 2. What can and cannot move into a screensaver

A screensaver has no mouse and no keyboard (any input ends it). Sorted by that rule:

- **Port as is (non-interactive):** GreyNoise feed, clocks, country colours, Radar aggregate view, most-attacked-ports block, rotating OSINT cards (KEV/EPSS, Tor, SANS ISC, ransomware.live, Spamhaus, SSLBL, Phishing.Database, OTX, URLhaus/ThreatFox, certificate watch), "Last problem" is **not** needed.
- **Port as auto-rotation instead of clicks:** country focus and severity filter become a timed rotation (same cards, no input).
- **Stays in AtlasSOC / configuration only:** click-only lookups (Shodan InternetDB, AbuseIPDB), hover and inspect, key entry, filters, update dialogs, consent prompts.

## 3. Hard constraints (carried over, not negotiable)

1. The stable screensaver 0.4.8 stays untouched; parity ships as a **new version on the Beta channel first** (`docs/UPDATE-CHANNELS.md`), never replacing Stable until gates pass.
2. Radar in the saver needs the Cloudflare consent text **and** an answer to the licence question (mail sent 16 Nov 2026). Until Cloudflare answers, Radar stays out of the saver. Other sources carry their own licence and attribution lines (`docs/OSINT-ATTRIBUTION.md`).
3. Keys stay in Keychain / Credential Manager; the saver only **reads** them, never prints, never stores copies.
4. Idle/lock behaviour is unchanged: no System32 changes beyond today, no change to password or lock settings, no network call from a keypress.
5. Performance budget: CPU, memory and frame time must not exceed the 0.4.8 baseline by more than the owner-agreed margin (set in SP1). Optimisation and hardening round and new tests before any public release (`optimisation gate`).
6. "Off means no request" for every source, same as AtlasSOC.

## 4. Work packages

| ID | Package | Owner | Depends on | Done when |
|---|---|---|---|---|
| SP0 | Parity matrix: every AtlasSOC feature classed port / port non-interactive / SOC-only, with the owner decisions in §5 | CL | none | matrix merged; Robert signs off D1-D4 |
| SP1 | `SaverView` in the core: composes existing `SocView` cards without input, timed rotation, performance budget measured on 0.4.8 baseline | CL | SP0 | golden-frame tests green on Windows, macOS, Linux CI; budget numbers recorded |
| SP2 | Shared settings reader in the core: which sources are on, intervals, read-only credential lookup; single config file shared with AtlasSOC | CL | SP0 | tests incl. missing/corrupt file = sources off |
| SP3 | `ta_saver_*` C interface next to the `ta_*` functions (new, frame, start/stop worker, drop) | CL | SP1, SP2 | header and Rust tests; old `ta_*` calls unchanged |
| SP4 | Windows saver host: start the data worker, draw `SaverView`, `/c` configuration opens AtlasSOC Settings or a small dialog | CL (code), Billy (test) | SP3 | SCR runs on a real Windows PC, 30 min soak OK, no dialog on idle |
| SP5 | macOS saver host: `ThreatAtlasView.m` calls `ta_saver_*`; configuration sheet | MAC (build, sign, notarise, test on Mac), CL (FFI support) | SP3 | saver runs in System Settings preview and real idle, 30 min soak OK |
| SP6 | Linux saver host (later phase) | MAC | SP4, SP5 | decide after SP4/SP5; not in the first beta |
| SP7 | Consent, privacy and attribution: on-screen attribution lines, saver section in `PRIVACY.md`, consent wording (R2 review by a qualified person), Radar decision | Seek (texts), CL (check), Robert (decision) | SP0 | texts merged, nothing implies a claim we cannot back |
| SP8 | Tests: multi-monitor, idle and lock, battery/CPU against 0.4.8, mixed DPI; ✅/⚠️/🚨 per case | Billy (Windows), MAC (macOS) | SP4, SP5 | result line per case in the handover files |
| SP9 | Docs, website and release: wishlist row, release notes, website text, Beta-channel feed entry | Seek (texts), CL (release), MAC (review) | SP8 | optimisation gate passed, Beta pre-release published |

## 5. Owner decisions (D1-D4) — ANSWERED 16 November 2026

Robert answered "yes, as you recommend" for all four, and approved the Linux to-do (section 7) as written:

- **D1 Scope: GreyNoise, rotating OSINT cards and the ports block in the first beta; Radar later.**
- **D2 Radar in the saver: waits for Cloudflare's answer.**
- **D3 Version: the saver stays on its own line, next version 0.5.0 (Beta channel first).**
- **D4 Configuration: saver settings live in AtlasSOC Settings (one place); the saver only reads them.**

Original options, for the record:

- **D1 Scope:** which of the SOC features in §2 "port non-interactive" you want in the first beta (proposal: GreyNoise + rotating OSINT cards + ports block; Radar later).
- **D2 Radar in the saver:** wait for Cloudflare's answer (recommended) or ship without Radar.
- **D3 Version number:** continue the 0.4.x line (0.5.0) or align with AtlasSOC 0.8.x.
- **D4 Configuration:** saver settings live in AtlasSOC Settings (one place, recommended) or the saver gets its own small configuration dialog on each OS.

## 6. Order of work and risk

1. SP0 and D1-D4 first (a day). 2. SP1-SP3 in the core in one go; they are the only real new code and are testable in CI without any PC. 3. SP4 and SP5 in parallel once SP3 lands. 4. SP7 runs alongside from the start. 5. SP8, then SP9.

Main risks: Radar licence answer (mitigated by D2), a saver that spends more CPU than 0.4.8 (mitigated by the SP1 budget), configuration split across two apps (mitigated by D4), two OS hosts drifting apart (mitigated by keeping all logic in the core and hosts thin).

## 7. To-do: a proper Linux build of AtlasSOC (the SOC part)

Requested by the owner on 16 November 2026, same reference `ATLAS-SAVER-PARITY-001`. The Linux SOC today is the 0.7.0 **preview** (`crates/linux`, 310 lines, `atlassoc` binary, CI-only): feed and renderer only. It has never run on a physical Linux desktop and lacks most of what Windows and macOS have. The core is shared, so the work is a host, not a rewrite.

Missing today (from `docs/ATLAS-SOC-LINUX.md`): the 13 OSINT sources, Cloudflare Radar, saved settings and the Settings window, update check, a fullscreen toggle, menus and table view, packaging beyond a tar.gz, native Wayland, and any test on real hardware or a second distribution.

| ID | Package | Owner | Depends on | Done when |
|---|---|---|---|---|
| LX0 | Gap list against Windows `soc_host.rs` and the macOS app: what the Linux host must call from the core (worker, settings reader, credential store, radar poll) | CL | none | list merged, each gap tagged host-only or core |
| LX1 | Real-machine baseline: install the 0.7.0 preview on a physical Linux PC (Ubuntu 24.04 X11 first), record start, live feed, resize, multi-monitor, what breaks | Billy | none (can start now) | ✅/⚠️/🚨 per case with screenshots |
| LX2 | Credential storage: Secret Service (libsecret) behind the same read/write interface as Keychain and Credential Manager; no plain-text fallback | CL | LX0 | tests; keys never in logs or config files |
| LX3 | Host features: saved settings, fullscreen toggle, menu, table view, Settings window with the 13 sources, intervals and key guide | CL | LX0, LX2 | parity checklist for Linux in `docs/SOC-DESKTOP-PARITY.md` |
| LX4 | Radar on Linux: consent identity and 15 minute floor as on Windows | CL | LX3, Cloudflare answer (D2) | only after the licence answer; otherwise stays out |
| LX5 | Packaging: AppImage first, `.deb` later; desktop file and icon with the TA logo; checksums | MAC (review), CL (script) | LX3 | package starts on a clean Ubuntu 24.04 and Fedora |
| LX6 | Update path: Linux uses the manual update flow of `docs/UPDATE-CHANNELS.md` (check and notice, no silent install) | CL | UPDATE-CHANNELS WP3 | notice works on the Beta channel |
| LX7 | Wayland: test native Wayland vs XWayland, decide whether to add native support | CL, Billy (test) | LX3 | decision recorded with evidence |
| LX8 | Tests and soak: 30 min soak, multi-monitor, two distributions; results as ✅/⚠️/🚨 | Billy | LX3, LX5 | one line per case in billy.json |
| LX9 | Docs and release: Linux page, privacy section, release notes; Beta channel entry | Seek (texts), CL (release) | LX8 | optimisation gate passed |

Linux stays a **separate pre-release** until LX1-LX8 are green; it never becomes `latest`. The Linux saver host (SP6 above) is a different task and follows later.
