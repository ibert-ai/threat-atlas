# OSINT panels — design and layout contract (pre-integration)

Status: design and layout tests only. No hot file (`crates/core/src/soc.rs`, `crates/core/src/render.rs`,
`crates/windows/src/soc_host.rs`) is touched on this branch. The hot-file turn is owned and announced by CL;
see `MAC-ATLAS-OSINT-PANEL-TURN-REQUEST-20261114-01` in the private handover.

## Goal

Show the FAS 1 OSINT data that already exists in the worker without turning the observation view into a
dashboard of its own:

- **KEV + EPSS:** the top known-exploited vulnerabilities with EPSS and due date.
- **SANS ISC:** the top target ports with records/targets/sources and the report date.
- **Sources:** the licence, attribution and minimum interval for the enabled sources.
- **Tor:** a count/age line until the geo decision (ATLAS-OSINT-004) provides positions.

The panel is informational, visually secondary, closed by default, and never a wizard or a recurring prompt.

## Placement

### Classic theme (1440 × 900)

A floating panel over the right half of the map, opened only by the user:

```
x = 600, y = 250, w = 380, h = 360
```

- The map is `(45, 230, 940, 470)`; the panel sits inside it and leaves the left half of the map visible.
- The right-hand panels start at `x = 1005`, so the panel never covers the latest-records or Radar panels.
- The header ends at `y = 230` and the bottom panel starts higher than `y = 735`; `y + h = 610`, so neither is
  covered.
- On a wider classic frame the panel keeps its size and stays at `x = 600`; the map grows to the right, so the
  panel remains inside it.

### Dashboard theme

Use the existing Radar tile (`08`, `(1025, 545, 390, 310)`) as a **tabbed panel**: `RADAR`, `KEV`, `SANS`.
No new geometry and no reflow; the Radar rows remain available on their tab. On a wide frame the tile moves right
with `dx`, so the OSINT rectangle is `(1025 + dx, 545, 390, 310)`.

### Small windows

The renderer frame is always 1440 × 900 (letterboxed), so the panel never depends on the physical window size.
The only size dependency is the wide-frame `dx`, handled above.

## Panel anatomy

```
┌ OSINT ─────────────────────────────── KEV │ SANS │ SOURCES ┐
│ CVE-2026-0001   EPSS 0.91   due 2026-01-22                  │
│   Acme — Widget: ...                                        │
│ ... up to 5 rows ...                                        │
│                                                             │
│ Source: CISA KEV + FIRST EPSS · updated 12 min ago          │
└─────────────────────────────────────────────────────────────┘
```

- Header: `OSINT` label left; three tabs right; active tab uses the informational accent, not a severity colour.
- Up to 5 data rows; each row two lines (identifier + detail), 22 px line height.
- Footer: source names, licence/attribution hint and the age of the data.
- Empty state: `No data yet — first refresh is scheduled.` Never a blank panel.
- KEV/SANS data is **informational**; do not use red/yellow/green severity colours for it.
- No pointer interaction required. Keyboard: `F2` toggles, `←`/`→` change tab, `Esc` closes. A right-click menu item
  mirrors the toggle for discoverability.
- The panel never fetches. It renders the worker's cached `OsintView`.

## Data contract for integration

The Windows worker already exposes `View { kev, kev_updated_ms, epss_updated_ms, tor_count, tor_updated_ms,
sans, sans_updated_ms, note }` (`crates/windows/src/soc_osint.rs`). The hot-file integration should move the
render-facing subset into a small core type so `soc.rs` does not depend on the Windows module:

```rust
pub struct OsintPanel {
    pub kev: Vec<(String, Option<f64>, String)>, // cve, epss, due
    pub sans: Vec<(u32, u64, u64, u64)>,          // port, records, targets, sources
    pub sans_date: String,
    pub tor_count: usize,
    pub updated_ms: u64,
    pub note: String,
}
```

- Cap the vectors at 5 for rendering; the worker may keep more.
- Format EPSS with two decimals; missing score is `n/a`, never `0`.
- Truncate every string by **characters**, not bytes; the renderer's font is ASCII-oriented but data may contain
  non-ASCII.
- Age is computed at draw time from `updated_ms`; no clock in the data type.

## Layout tests (this branch)

`crates/core/tests/osint_panel_design.rs` is the pre-integration contract. It asserts:

- the classic rectangle stays inside the frame, map and the free area between header/right panels/bottom panel;
- the dashboard rectangle tracks `dx`, stays inside the frame and does not cross the right edge;
- the panel is tall enough for header + five two-line rows + footer;
- tab selection wraps and never goes out of range;
- character truncation is Unicode-safe and bounded.

When CL grants the hot-file turn, move the rectangle/tab/truncation functions into `soc.rs`, keep these tests, and
add a render snapshot test for the classic and dashboard themes. Run the Windows CI on the integration commit; this
branch alone is docs + an integration test and does not need a Windows build.

## Acceptance (hot-file turn)

- `F2` opens/closes; menu item matches; `Esc` closes before it exits the app.
- Classic: panel does not cover the latest-records/Radar panels; dashboard: Radar/KEV/SANS tabs all reachable.
- Empty, partial (KEV only) and stale states render honestly with the age and no invented data.
- No new network request, no token, no key and no source fetch from the render thread.
- Existing map, hover, focus, severity and mirroring behaviour unchanged.
- `cargo fmt --check`, clippy `-D warnings`, core tests and the Windows CI are green on the integration commit.
