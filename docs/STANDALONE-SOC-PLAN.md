# Windows-first standalone and SOC wall roadmap

Owner request: ATLAS-STANDALONE-20261102-01. Source: Robert's explicit chat instruction, 2 November 2026. MAC (Roberts-Air) to BILLY-BADASS.

## Deliverables and order

1. Windows 10/11 x64 `ThreatAtlas.exe`, a real standalone application with persistent settings, windowed/fullscreen modes and SOC multiscreen wall controls. Keep `ThreatAtlas.scr` as the native screensaver with its `/s`, `/p HWND` and `/c` contracts. The current `--windowed` preview and ZIP are not the requested complete standalone product.
2. Finish and document Windows acceptance before porting these standalone/SOC features to macOS. macOS needs a native `.app` host, shared rendering/data/settings semantics, per-display windows, AppKit settings, universal Intel/Apple Silicon packaging, signing/notarization plan and native acceptance. Existing `.saver` remains separate. Do not add Linux features or remove historical Linux support in this task.
3. Separate request ATLAS-RADAR-MAC-20261102-01 authorizes a macOS-only Cloudflare Radar research/alpha branch now. It does not authorize Radar on Windows/Linux or waive the Windows-first gate for the standalone wall port.

## Options grounded in the current code

Current `crates/windows/src/windows.rs` owns one Tao window, a 50 ms loop, one shared-feed Session and letterboxed 1440x900 renderer. `/c` only displays information; `scripts/build-windows.ps1` only packages SCR. Add real controls incrementally rather than claiming wall support from borderless fullscreen.

Shared saver/app settings: data-layer visibility (routes, country shading, counters, observations), provider-specific freshness/attribution, UTC/local clock visibility, font/contrast presets, frame-rate/CPU cap, animation density, route lifetime with bounded memory, reconnect status, diagnostics without raw telemetry or secrets. Persist a versioned schema with safe defaults, input bounds and corrupt-config recovery. Provider filtering must not mislabel received-record totals as unique attacks.

Standalone-only: start windowed or fullscreen; explicit selected displays; mirrored wall, per-display roles (map / log / metrics), optional spanning canvas with accurate monitor geometry; portrait and mixed DPI; saved layouts and restore-on-start; always-on-top opt-in; pause/resume and operator exit; optional launch-at-login and sleep inhibition with clear opt-in. Do not exit on ordinary mouse motion in app mode. Hotplug/reorder/reconnect must recover without orphan windows.

Screensaver: native configuration sheet/dialog for permitted shared options, display selection where compatible with OS saver hosting, lower-rate preview, and preserve OS-controlled idle time, password and lock behavior. Never add app-only sleep inhibition or bypass lock security to screensaver mode.

SOC wall: share one feed/snapshot across windows (not one network connection per monitor), synchronized timestamps, per-layer stale/offline indicators, bounded resources, no blocking UI-thread networking, source provenance and no fabricated attack source/destination pairs. Real wall layouts are pending implementation and tests.

## Billy implementation and Git handover

BILLY-BADASS owns Windows implementation. Start from latest `main`, create `codex/windows-standalone-soc`, and acknowledge this request in Git with exact base SHA, scope and first milestones. Keep unrelated changes isolated. First deliver EXE packaging, independent app lifecycle and persistent options; then multiple windows/display roles and recovery; then installer integration and soak. Existing withdrawn MSI investigation remains tracked, not declared fixed by the new EXE.

Return a PR plus `docs/handoffs/ATLAS-STANDALONE-20261102-01-WINDOWS.md` containing request ID, host, branch/base/head SHA, build/version, changed options, artifact links and SHA256, exact commands and pass/fail/not-run results, known limits, screenshots, and next action. Request MAC review in Git before any macOS wall port. No production release/version approval is implied.

Acceptance: workspace tests/Clippy/version gates; EXE starts and closes without saver semantics; `/s`, `/p`, `/c` regression; option persistence/reset/corrupt-config; Windows native interactive install/uninstall/upgrade with trust behavior; 1/2/3+ displays including portrait, negative coordinates, primary switch, mixed 100/150/200% DPI, hotplug and restart; independent windows and mirrored/spanned correctness; offline/reconnect/stale reporting; resource-bound and 8-hour soak with measured CPU/RAM and data volume. Headless CI does not replace physical monitor/idle-lock acceptance. Record unrun cases honestly. macOS port begins only after Windows results reviewed against these gates.

Routine progress: Billy owns `status/billy.json` on `codex/release-status`, MAC owns `status/mac.json`; never merge that branch into code. Respect its change-driven writes, caching/backoff and polling protocol. Telegram is for brief handoffs/owner decisions. Robert monitors the existing LAN-only dashboard at http://roberts-macbook-air.local:8765/. A reachable server does not prove agent health or completed delivery.

## Mandatory first-start licence gate — owner clarification 2 November 2026

All application and screensaver versions must require explicit acceptance of the Cloudflare Radar terms at first start and again for each new released version/build, including RCs. Record acceptance against full version/build and reviewed licence identity, never a permanent boolean. Display attribution, CC BY-NC 4.0 noncommercial restriction, legal/source links, and clarify that acceptance does not authorize commercial use. Decline must prevent application startup/telemetry; saver hosts show review-in-app instructions without obstructing OS lock/security UI. Never accept on Robert's behalf or collect a token in chat. Each RC must re-fetch and compare the Cloudflare notice and linked legal code against a reviewed baseline; changed or unreachable terms block release until reviewed, notice updated and tests pass. Add Windows-specific launch and consent/reconfirmation regression tests. The macOS Radar alpha implements the first gate; Billy must implement equivalent Windows UX as part of the Windows standalone work, without adding Radar data integration to Windows before Robert approval. No Linux work.

## Superseding priority — security and public screensaver bugs first

Robert clarified on 2 November 2026: security is the absolute priority, then fix and verify public screensaver bugs before standalone implementation. Standalone/SOC wall remains a wishlist item, blocked behind screensaver acceptance. Review PR18 (security-sanity and dependency-currency gate, evidence and Known Vulnerabilities). Current advisory scan found no known RustSec findings; four package currency reviews block builds. Billy must first reproduce/triage Windows screensaver installation/discovery and right-click Install behavior, preserve idle/lock preferences, then return a Git handover with exact commits, artifacts and test gaps. Do not infer acknowledgement or completion from this request. Never suppress vulnerabilities, maintenance findings or failed/unavailable checks to ship a build. No new Linux feature work.
