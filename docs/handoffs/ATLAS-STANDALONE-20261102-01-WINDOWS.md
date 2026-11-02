# Windows SOC implementation handoff

Request: ATLAS-STANDALONE-20261102-01 / ATLAS-REVIEW19-20261102-03/04. Host: BILLY-BADASS. Work branch: `codex/windows-standalone-soc`. Base: PR19 `7b1b92d72e531d319e82ba36b576839896ee1480`, from main `68d136004228b09d9fd6fa3208b10c1ff88ef639`. Development Windows identity: 0.7.0/build9, matching the current Mac candidate; not a new public screensaver release.

## Delivered source

- Separate `threat-atlas-soc` binary packaged as `AtlasSOC.exe`; native SCR source and entry point unchanged. Exact Sentinel assets/specs adopted from PR20 `01d68891c79f9837df5f9752a76b254ed2f02481`; Windows icon/version resources compile with the installed Microsoft SDK. Product/publisher: AtlasSOC by Ibert Consulting.
- Shared PR19 SOC renderer, Realtime default, Calm/Still and severity controls, country hover/focus, freeze-display, fullscreen/windowed, always-on-top and frame caps.
- Mirrored display windows, one shared GreyNoise feed and one renderer, monitor-change recovery, bounded window/backbuffer resources. No Windows Cloudflare worker/token storage or inferred aggregate routes.
- Versioned bounded settings, corrupt-file fallback and atomic writes; settings separate from consent.
- Native first-start licence dialog, default decline, exact release/build/notice/legal identity. Feed construction occurs only after acceptance in normal mode. Offline smoke never constructs a feed or changes real consent.
- Portable package script, native offline smoke script and dedicated Windows SOC CI workflow. The build fails on changed/unreachable published terms. Existing screensaver workflow/artifacts are not relabelled as standalone SOC.

## Validation completed so far

Windows native Rust 1.99.1 MSVC: all32 core tests,2 existing Windows layout tests and5 SOC config/consent/layout/inspection tests passed. Native Clippy with warnings denied passed. Sentinel resource changes require a new exact-source build and package check; those results follow in the durable local checkpoint.

Debug native smoke created a window, presented three frames and exited; it recorded no feed construction and no consent write. Real consent store was unchanged by smoke. A subsequent normal launch was observed with zero TCP sockets before acceptance. A matching consent record then appeared through the native dialog and the app established a TLS connection on port443. No agent action accepted terms. Visual inspection confirmed changing GreyNoise received-record counts, map/arcs, native menu, Calm/Realtime switch, fullscreen entry, Escape back to windowed, and persisted settings. The test process was closed after verification. These debug observations are not automatically final-package evidence.

Fresh unfiltered RustSec audit (no ignore list), database `263a4d951a0867d4bddc29dddd6d59427c78f9a7`, 1,402 advisories, 326 locked dependencies: zero vulnerability entries; warnings remain for `proc-macro-error1.0.4` (RUSTSEC-2024-0370), `glib0.18.5` (RUSTSEC-2024-0429, unsound iterator, patched in0.20) and `ttf-parser0.25.1` (RUSTSEC-2026-0192). These are inherited, not fixed or newly suppressed by this branch. Linux-only reachability does not erase the full-lockfile findings. Existing historical ignores must not be cited as a fully clear security review.

Published Cloudflare notice/legal fingerprints matched the reviewed record. Source-pattern scan and existing screensaver manifest consistency passed. No reviewed terms baseline was rewritten.

## Remaining acceptance / ownership

This is a review increment, **not publication GO**. The full PR16 SOC-wall roadmap remains larger than this host increment: per-display roles, selected-display layouts, spanning, standalone MSI/upgrade, physical1/2/3+ display and mixed-DPI/hotplug acceptance, eight-hour soak and trust/signature acceptance remain pending. No Windows Radar port or Linux expansion is included.

MAC owns independent verification, security findings/currency integration with PR18, final product/version identity, Windows+Mac integration, documentation/notes/privacy/licensing and final publication. Claude owns the Mac implementation and promised cross-platform interface/consent specification and standalone Mac CI. Billy supplies Windows source, package hashes and exact native evidence. Do not infer Windows SOC acceptance from older screensaver CI or claim a Mac-only release is authorized.

Use `scripts/build-windows-soc.ps1`, `scripts/test-windows-soc.ps1` and `docs/WINDOWS-SOC.md`. Record the exact artifact source commit and hashes from `dist/windows-soc/manifest.json` and the final local evidence before integrating. Preserve stable releases and updater trust controls. Request MAC review of this branch; Billy must not merge, tag or publish a release.
