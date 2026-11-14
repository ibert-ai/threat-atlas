//! Pre-integration layout contract for the OSINT panels.
//!
//! This file deliberately does not touch the production renderer. It keeps the geometry and text rules
//! testable before CL grants the hot-file turn; the functions move into `soc.rs` at integration.

const FRAME_W: f32 = 1440.;
const FRAME_H: f32 = 900.;
const MAP: Rect = Rect {
    x: 45.,
    y: 230.,
    w: 940.,
    h: 470.,
};
const RIGHT_PANELS_X: f32 = 1005.;
const HEADER_BOTTOM: f32 = 230.;
const ROWS: usize = 5;
const ROW_H: f32 = 22.;
const HEADER_H: f32 = 32.;
const FOOTER_H: f32 = 28.;
const TABS: [&str; 3] = ["KEV", "SANS", "SOURCES"];

#[derive(Clone, Copy, Debug, PartialEq)]
struct Rect {
    x: f32,
    y: f32,
    w: f32,
    h: f32,
}

impl Rect {
    fn right(self) -> f32 {
        self.x + self.w
    }

    fn bottom(self) -> f32 {
        self.y + self.h
    }

    fn inside(self, frame_w: f32, frame_h: f32) -> bool {
        self.x >= 0. && self.y >= 0. && self.right() <= frame_w && self.bottom() <= frame_h
    }

    fn overlaps(self, other: Rect) -> bool {
        self.x < other.right()
            && self.right() > other.x
            && self.y < other.bottom()
            && self.bottom() > other.y
    }
}

/// Classic theme: floating panel over the right half of the map, closed by default.
fn classic_panel() -> Rect {
    Rect {
        x: 600.,
        y: 250.,
        w: 380.,
        h: 360.,
    }
}

/// Dashboard theme: reuse the Radar tile as a three-tab panel; `dx` is the wide-frame extra width.
fn dashboard_panel(dx: f32) -> Rect {
    Rect {
        x: 1025. + dx.max(0.),
        y: 545.,
        w: 390.,
        h: 310.,
    }
}

fn tab_next(index: usize, delta: isize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    (index as isize + delta).rem_euclid(len as isize) as usize
}

/// Character-safe truncation with an ellipsis. Never splits a UTF-8 sequence.
fn truncate_chars(value: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut out: String = value.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Enough vertical room for the header, five two-line rows and the footer.
fn panel_fits_rows(rect: Rect) -> bool {
    rect.h >= HEADER_H + ROWS as f32 * ROW_H * 2. + FOOTER_H
}

#[test]
fn classic_panel_is_inside_the_map_and_clear_of_fixed_panels() {
    let panel = classic_panel();
    assert!(panel.inside(FRAME_W, FRAME_H));
    assert!(panel.y >= HEADER_BOTTOM);
    assert!(
        panel.right() <= RIGHT_PANELS_X,
        "must not cover the right panels"
    );
    assert!(
        panel.right() <= MAP.right(),
        "must stay inside the map width"
    );
    assert!(panel.bottom() <= MAP.bottom());
    assert!(panel.x >= MAP.x && panel.y >= MAP.y);
    assert!(panel_fits_rows(panel));
}

#[test]
fn dashboard_panel_tracks_wide_frames_without_crossing_the_edge() {
    for dx in [0., 60., 150., 400., 800.] {
        let frame_w = FRAME_W + dx;
        let panel = dashboard_panel(dx);
        assert!(panel.inside(frame_w, FRAME_H), "dx={dx}");
        assert_eq!(panel.x, 1025. + dx);
        assert!(panel_fits_rows(panel));
    }
}

#[test]
fn tabs_wrap_and_stay_in_range() {
    assert_eq!(tab_next(0, -1, TABS.len()), 2);
    assert_eq!(tab_next(0, 1, TABS.len()), 1);
    assert_eq!(tab_next(2, 1, TABS.len()), 0);
    assert_eq!(tab_next(1, 0, TABS.len()), 1);
    assert_eq!(tab_next(0, 1, 0), 0);
    assert_eq!(TABS, ["KEV", "SANS", "SOURCES"]);
}

#[test]
fn truncation_is_character_safe_and_bounded() {
    assert_eq!(truncate_chars("CVE-2026-0001", 32), "CVE-2026-0001");
    assert_eq!(truncate_chars("ÅÄÖåäö", 4), "ÅÄÖ…");
    assert_eq!(truncate_chars("ÅÄÖåäö", 5), "ÅÄÖå…");
    assert_eq!(truncate_chars("anything", 0), "");
    assert_eq!(truncate_chars("", 5), "");
    assert!(
        truncate_chars("a".repeat(1000).as_str(), 10)
            .chars()
            .count()
            <= 10
    );
}

#[test]
fn empty_data_has_an_honest_state() {
    // The panel must never look like "no threats" when the worker simply has no data yet.
    fn empty_state(updated_ms: u64) -> &'static str {
        if updated_ms == 0 {
            "No data yet — first refresh is scheduled."
        } else {
            "No rows in the current report."
        }
    }
    assert!(empty_state(0).contains("first refresh"));
    assert!(!empty_state(0).to_lowercase().contains("no threats"));
    assert!(empty_state(1).contains("No rows"));
}

#[test]
fn panel_does_not_overlap_fixed_right_panels() {
    let panel = classic_panel();
    let latest = Rect {
        x: 1005.,
        y: 205.,
        w: 400.,
        h: 510.,
    };
    let radar = Rect {
        x: 1005.,
        y: 735.,
        w: 400.,
        h: 120.,
    };
    assert!(!panel.overlaps(latest));
    assert!(!panel.overlaps(radar));
}
