//! Calm, interactive SOC view on the shared map: GreyNoise live records plus Cloudflare Radar
//! aggregates. Built for long viewing: no travelling dots, flashing or pulsing; a few slow,
//! fading arcs; country tints that change over minutes, not seconds.
//! Severity is red/yellow/green only; information uses subtle slate blue and grey.
use super::{xy, Renderer, MUTED};
use crate::feed::Snapshot;
use crate::radar::{self, Aggregate, Freshness};
use std::collections::VecDeque;
use tiny_skia::*;

pub const RED: [u8; 3] = [235, 87, 87];
pub const YELLOW: [u8; 3] = [242, 201, 76];
pub const GREEN: [u8; 3] = [72, 199, 142];
/// Informational layers (Radar aggregates, status) must never read as severity.
pub const INFO: [u8; 3] = [116, 151, 189];
const TEXT: [u8; 3] = [203, 222, 235];
const FOCUS: [u8; 3] = [168, 214, 230];
pub fn severity(class: usize) -> [u8; 3] {
    match class {
        0 => RED,
        1 => YELLOW,
        2 => GREEN,
        _ => MUTED,
    }
}
const CLASS_NAMES: [&str; 3] = ["MALICIOUS", "SUSPICIOUS", "BENIGN"];

pub const ARC_LIFE_MS: u64 = 8000;
const ARC_FADE_IN_MS: u64 = 1000;
/// New arcs admitted per second, most severe first; the provider sends far more records.
pub const ARCS_PER_SECOND: f64 = 2.;
pub const MAX_ARCS: usize = 20;
const LIST_REFRESH_MS: u64 = 2000;
/// Realtime mode: bounded so it cannot run away with CPU or memory however fast records arrive.
pub const REALTIME_ARCS_PER_SECOND: f64 = 40.;
pub const REALTIME_MAX_ARCS: usize = 160;
pub const REALTIME_ARC_LIFE_MS: u64 = 3000;
const REALTIME_FADE_IN_MS: u64 = 250;
const REALTIME_LIST_REFRESH_MS: u64 = 500;
/// Country tints and outlines are redrawn at most once a second (or when options change).
const OVERLAY_REFRESH_MS: u64 = 1000;
type OverlayKey = (
    [bool; 3],
    Option<usize>,
    u64,
    bool,
    Freshness,
    bool,
    Vec<String>,
);
const MAP: (f32, f32, f32, f32) = (45., 230., 940., 470.);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Motion {
    Calm,
    Still,
    /// Default, screensaver-like: many short arcs sampled uniformly from what arrives.
    Realtime,
}
/// Panel layout and styling around the shared map. The map itself, arcs, tints and data are the
/// same in every theme; only the frame around them changes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Theme {
    /// The established layout; stays the default.
    #[default]
    Classic,
    /// Robert, 9 November 2026 (ATLAS-SOC-LAYOUT-001): optional dense dashboard. Black background,
    /// one cyan accent, numbered tiles, a callout on the focused country and a status line.
    Dashboard,
}
#[derive(Clone, Debug)]
pub struct Options {
    pub severities: [bool; 3],
    pub motion: Motion,
    pub focus: Option<usize>,
    /// Cloudflare Radar icon layer on/off, and origin codes (upper case) the viewer has hidden.
    pub radar_layer: bool,
    pub radar_hidden: Vec<String>,
    pub theme: Theme,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            severities: [true; 3],
            // Robert, 2 November 2026: Realtime is the default; Calm and Still stay available.
            motion: Motion::Realtime,
            focus: None,
            radar_layer: true,
            radar_hidden: Vec::new(),
            theme: Theme::Classic,
        }
    }
}
/// Dashboard theme palette. The accent is informational and never a severity colour.
const DASH_BG: [u8; 3] = [3, 6, 10];
const DASH_PANEL: [u8; 3] = [5, 11, 17];
const ACCENT: [u8; 3] = [64, 214, 230];
const ACCENT_DIM: [u8; 3] = [28, 86, 100];
const DASH_GRID: [u8; 3] = [13, 32, 42];
/// Dashboard tiles: (x, y, w, h, number and label). Map tile matches the shared map rectangle.
const DASH_TILES: [(f32, f32, f32, f32, &str); 11] = [
    (35., 96., 265., 96., "01 MALICIOUS / 5 MIN"),
    (315., 96., 265., 96., "02 SUSPICIOUS / 5 MIN"),
    (595., 96., 265., 96., "03 BENIGN / 5 MIN"),
    (875., 96., 265., 96., "04 RECORDS / S (10 S AVG)"),
    (1155., 96., 260., 96., "05 FOCUS | MOTION"),
    (25., 205., 980., 510., "06 LIVE MAP / GREYNOISE RECEIPTS"),
    (1025., 205., 390., 330., "07 LATEST SELECTED RECORDS"),
    (1025., 545., 390., 310., "08 CLOUDFLARE RADAR / TOP ROWS"),
    (25., 740., 560., 115., "09 RECEIVED RECORDS / S (LAST 90 S)"),
    (595., 740., 200., 115., "10 SEVERITY MIX / 5 MIN"),
    (805., 740., 200., 115., "11 LEGEND"),
];
/// Wide frames: with at least this much extra width a "top countries" column fills the space
/// between the map and the right-hand panels; less is added to the map and legend panels.
const WIDE_COLUMN_MIN: f32 = 150.;
/// Panel colour of the classic layout.
const CLASSIC_PANEL: [u8; 3] = [10, 23, 36];
/// The five header tiles across the frame width: (x, w). Identical to the 1440 layout at dx = 0.
fn header_tiles(dx: f32) -> [(f32, f32); 5] {
    if dx <= 0. {
        return [
            (35., 265.),
            (315., 265.),
            (595., 265.),
            (875., 265.),
            (1155., 260.),
        ];
    }
    let w = (1380. + dx - 4. * 15.) / 5.;
    std::array::from_fn(|i| (35. + i as f32 * (w + 15.), w))
}
/// Extra width that widens the map and legend panels (narrow wide frames) and the extra column
/// rectangle (wider frames), both in frame coordinates.
fn wide_split(dx: f32) -> (f32, Option<(f32, f32, f32, f32)>) {
    if dx >= WIDE_COLUMN_MIN {
        (0., Some((1025., 205., dx - 20., 650.)))
    } else {
        (dx.max(0.), None)
    }
}
/// Dashboard tiles in frame coordinates for a frame `dx` pixels wider than 1440.
fn dash_tiles(dx: f32) -> Vec<(f32, f32, f32, f32, &'static str)> {
    let (grow, column) = wide_split(dx);
    let head = header_tiles(dx);
    let mut tiles: Vec<_> = DASH_TILES
        .iter()
        .enumerate()
        .map(|(i, &(x, y, w, h, label))| match i {
            0..=4 => (head[i].0, y, head[i].1, h, label),
            5 | 10 => (x, y, w + grow, h, label),
            6 | 7 => (x + dx.max(0.), y, w, h, label),
            _ => (x, y, w, h, label),
        })
        .collect();
    if let Some((x, y, w, h)) = column {
        let label = if w < 220. {
            "12 TOP COUNTRIES"
        } else {
            "12 TOP COUNTRIES / 5 MIN"
        };
        tiles.push((x, y, w, h, label));
    }
    tiles
}
/// A static Cloudflare Radar map icon: an origin badge sized by its largest share, or a target
/// diamond (only for targets the provider supplied). Never connected by lines.
struct Icon {
    target: bool,
    at: (f32, f32),
    size: f32,
    label: String,
    /// Pie slices (fractions of the pie) for an origin's ranked rows; empty or one = full disc.
    slices: Vec<f32>,
}
struct Arc {
    a: (f32, f32),
    b: (f32, f32),
    born: u64,
    class: usize,
    life: u64,
    fade_in: u64,
    /// Realtime arcs carry a head dot that travels source to destination once (no looping).
    travelling: bool,
}
struct Line {
    route: String,
    class: usize,
    received_ms: u64,
}
pub struct SocView {
    renderer: Renderer,
    pub options: Options,
    arcs: VecDeque<Arc>,
    last_sequence: u64,
    tokens: f64,
    /// xorshift state for realtime sampling (display only, not security-relevant).
    rng: u64,
    last_ms: u64,
    list: Vec<Line>,
    list_ms: u64,
    overlay_ms: u64,
    overlay_key: Option<OverlayKey>,
    /// Map + tints + outlines + rings, rebuilt with the overlay; each frame starts from a copy.
    composed: Pixmap,
    icons: Vec<Icon>,
    counts: (Vec<(usize, [u64; 3])>, [u64; 3]),
    /// Theme the renderer's static base was painted for; repainted when `options.theme` changes.
    base_theme: Theme,
}
impl Default for SocView {
    fn default() -> Self {
        Self::new()
    }
}
/// Frame coordinates (1440x900) to lon/lat, inside the map rectangle only.
pub fn lon_lat(x: f32, y: f32) -> Option<(f64, f64)> {
    let (mx, my, mw, mh) = MAP;
    if x < mx || y < my || x > mx + mw || y > my + mh {
        return None;
    }
    Some((
        ((x - mx) / mw) as f64 * 360. - 180.,
        90. - ((y - my) / mh) as f64 * 180.,
    ))
}
impl Renderer {
    pub fn new_soc() -> Self {
        let mut r = Self::blank();
        r.paint_soc_base(Theme::Classic);
        r
    }
    /// Repaint the static frame (background, panels, map, fixed labels) for a theme.
    fn paint_soc_base(&mut self, theme: Theme) {
        match theme {
            Theme::Classic => {
                self.base_map();
                let (grow, column) = wide_split(self.wide_dx);
                self.wide_raw = true;
                if grow > 0. {
                    self.rect(1005., 205., grow, 510., CLASSIC_PANEL, 255);
                    self.rect(1005., 735., grow, 120., CLASSIC_PANEL, 255);
                }
                if let Some((x, y, w, h)) = column {
                    self.rect(x, y, w, h, CLASSIC_PANEL, 255);
                    let title = if w < 220. {
                        "TOP COUNTRIES"
                    } else {
                        "TOP COUNTRIES / 5 MIN"
                    };
                    self.text(x as i32 + 19, 225, 15, title, INFO);
                }
                self.wide_raw = false;
                self.text(35, 28, 30, "THREAT ATLAS", [223, 241, 249]);
                self.text(
                    36,
                    70,
                    14,
                    "SECURITY OPERATIONS / GREYNOISE LIVE + CLOUDFLARE RADAR",
                    MUTED,
                );
                self.text(1044, 225, 15, "LATEST SELECTED RECORDS", INFO);
                self.text(45, 750, 14, "RECEIVED RECORDS / SECOND (LAST 90 S)", MUTED);
            }
            Theme::Dashboard => self.dashboard_base(),
        }
        self.text(
            35,
            875,
            12,
            "GREYNOISE: RECEIVED RECORDS, NOT UNIQUE ATTACKS | RADAR: AGGREGATE SHARES | TIMES UTC",
            MUTED,
        );
        self.version_label();
        self.base = self.pix.clone();
    }
    fn dashboard_base(&mut self) {
        let (w, h) = (self.pix.width(), self.pix.height());
        let tiles = dash_tiles(self.wide_dx);
        self.wide_raw = true;
        self.pix
            .fill(Color::from_rgba8(DASH_BG[0], DASH_BG[1], DASH_BG[2], 255));
        // Fine frame grid behind everything.
        for x in (0..=w).step_by(40) {
            self.line(x as f32, 0., x as f32, h as f32, DASH_GRID, 1., 70);
        }
        for y in (0..=h).step_by(40) {
            self.line(0., y as f32, w as f32, y as f32, DASH_GRID, 1., 70);
        }
        for &(x, y, tw, th, _) in &tiles {
            self.rect(x, y, tw, th, DASH_PANEL, 255);
        }
        // Graticule every 15 degrees, then the shared land polygons.
        for lon in (-180..=180).step_by(15) {
            let (a, b) = xy(lon as f64, 90.);
            let (c, d) = xy(lon as f64, -90.);
            self.line(a, b, c, d, DASH_GRID, 1., 200);
        }
        for lat in (-90..=90).step_by(15) {
            let (a, b) = xy(-180., lat as f64);
            let (c, d) = xy(180., lat as f64);
            self.line(a, b, c, d, DASH_GRID, 1., 200);
        }
        Self::draw_land(&mut self.pix, Transform::identity(), 0.7);
        for &(x, y, tw, th, label) in &tiles {
            self.tile_frame(x, y, tw, th);
            self.text(x as i32 + 10, y as i32 + 8, 11, label, ACCENT);
        }
        self.text(35, 22, 26, "THREAT ATLAS", [223, 241, 249]);
        self.text(
            37,
            60,
            12,
            "SOC / DASHBOARD LAYOUT / GREYNOISE LIVE + CLOUDFLARE RADAR",
            ACCENT_DIM,
        );
        self.wide_raw = false;
    }
    /// Thin tile outline with brighter corner ticks.
    fn tile_frame(&mut self, x: f32, y: f32, w: f32, h: f32) {
        let (r, b) = (x + w, y + h);
        for (a, c, d, e) in [(x, y, r, y), (r, y, r, b), (x, b, r, b), (x, y, x, b)] {
            self.line(a, c, d, e, ACCENT_DIM, 1., 200);
        }
        let t = 9.;
        for (cx, cy, dx, dy) in [
            (x, y, 1., 1.),
            (r, y, -1., 1.),
            (x, b, 1., -1.),
            (r, b, -1., -1.),
        ] {
            self.line(cx, cy, cx + t * dx, cy, ACCENT, 1.5, 230);
            self.line(cx, cy, cx, cy + t * dy, ACCENT, 1.5, 230);
        }
    }
}
impl SocView {
    pub fn new() -> Self {
        Self {
            renderer: Renderer::new_soc(),
            options: Options::default(),
            arcs: VecDeque::new(),
            last_sequence: 0,
            tokens: 1.,
            rng: 0x9e37_79b9_7f4a_7c15,
            last_ms: 0,
            list: Vec::new(),
            list_ms: 0,
            overlay_ms: 0,
            overlay_key: None,
            composed: Pixmap::new(crate::WIDTH, crate::HEIGHT).unwrap(),
            icons: Vec::new(),
            counts: (Vec::new(), [0; 3]),
            base_theme: Theme::Classic,
        }
    }
    /// Frame width in pixels (height is always 900).
    pub fn width(&self) -> u32 {
        self.renderer.size().0
    }
    /// Lay the frame out `width` pixels wide (at least 1440, at most 3x): the map keeps its size,
    /// the right-hand panels move to the right edge and the space between holds a top-countries
    /// column. Returns the width in use.
    pub fn set_width(&mut self, width: u32) -> u32 {
        let width = width.clamp(crate::WIDTH, crate::WIDTH * 3);
        if width != self.width() {
            self.renderer.resize_wide(width);
            self.renderer.paint_soc_base(self.base_theme);
            self.composed = Pixmap::new(width, crate::HEIGHT).unwrap();
            self.overlay_key = None;
        }
        width
    }
    pub fn arc_count(&self) -> usize {
        self.arcs.len()
    }
    pub fn country_at(&self, x: f32, y: f32) -> Option<usize> {
        let (lon, lat) = lon_lat(x, y)?;
        self.renderer.countries.at(lon, lat)
    }
    fn selected(&self, class: usize, source: &str, destination: &str) -> bool {
        class < 3
            && self.options.severities[class]
            && self.options.focus.is_none_or(|focus| {
                [source, destination]
                    .iter()
                    .any(|c| self.renderer.countries.index(c) == Some(focus))
            })
    }
    fn next_random(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }
    /// Admit new arcs within the mode's budget and expire old ones. Calm: a few, most severe
    /// first. Realtime: many, sampled uniformly so the colour mix matches what actually arrived.
    fn update_arcs(&mut self, s: &Snapshot) {
        let now = s.now_ms;
        let elapsed = now.saturating_sub(self.last_ms).min(5000) as f64;
        self.last_ms = now;
        let (rate, cap, life, fade_in) = match self.options.motion {
            Motion::Realtime => (
                REALTIME_ARCS_PER_SECOND,
                REALTIME_MAX_ARCS,
                REALTIME_ARC_LIFE_MS,
                REALTIME_FADE_IN_MS,
            ),
            _ => (ARCS_PER_SECOND, MAX_ARCS, ARC_LIFE_MS, ARC_FADE_IN_MS),
        };
        self.tokens = (self.tokens + elapsed / 1000. * rate).min(rate * 1.5);
        let mut fresh: Vec<_> = s
            .recent
            .iter()
            .filter(|r| r.sequence > self.last_sequence)
            .filter(|r| {
                self.selected(
                    r.record.class(),
                    &r.record.source.country,
                    &r.record.destination.country,
                )
            })
            .collect();
        self.last_sequence = self.last_sequence.max(s.records);
        if self.options.motion == Motion::Still {
            self.arcs.clear();
            return;
        }
        if self.options.motion == Motion::Realtime {
            let take = self.tokens.floor() as usize;
            if take > 0 && fresh.len() > take {
                // Reservoir sampling: every arrival has the same chance, whatever the batch pattern.
                let mut picked: Vec<_> = fresh[..take].to_vec();
                for (i, record) in fresh.iter().enumerate().skip(take) {
                    let j = (self.next_random() % (i as u64 + 1)) as usize;
                    if j < take {
                        picked[j] = record;
                    }
                }
                fresh = picked;
            }
        } else {
            fresh.sort_by_key(|r| r.record.class()); // stable: newest first within a class
        }
        for r in fresh {
            if self.tokens < 1. {
                break;
            }
            self.tokens -= 1.;
            self.arcs.push_back(Arc {
                a: xy(r.record.source.longitude, r.record.source.latitude),
                b: xy(
                    r.record.destination.longitude,
                    r.record.destination.latitude,
                ),
                born: now,
                class: r.record.class(),
                life,
                fade_in,
                travelling: self.options.motion == Motion::Realtime,
            });
        }
        self.arcs
            .retain(|a| now.saturating_sub(a.born) < a.life && a.class < 3);
        while self.arcs.len() > cap {
            self.arcs.pop_front();
        }
    }
    /// Draw one frame. `counts` are per-country and overall malicious/suspicious/benign counts
    /// for the last few minutes; `radar` is the latest validated Cloudflare snapshot, if any.
    pub fn draw(
        &mut self,
        s: &Snapshot,
        counts: (Vec<(usize, [u64; 3])>, [u64; 3]),
        radar_data: Option<&Aggregate>,
        radar_received_ms: u64,
    ) -> &[u8] {
        self.counts = counts;
        if self.options.theme != self.base_theme {
            self.base_theme = self.options.theme;
            self.renderer.paint_soc_base(self.base_theme);
            self.overlay_key = None; // recompose tints and icons on the new base
        }
        self.update_arcs(s);
        let now = s.now_ms;
        let selected = self.options.severities;
        let r = &mut self.renderer;

        // Radar aggregates: informational icon layer (slate), never severity fills or routes.
        let radar_state = radar::freshness(radar_data, radar_received_ms, now);
        let radar_dim = if radar_state == Freshness::Stale {
            0.5
        } else {
            1.
        };
        let key = (
            self.options.severities,
            self.options.focus,
            radar_received_ms,
            radar_data.is_some(),
            radar_state,
            self.options.radar_layer,
            self.options.radar_hidden.clone(),
        );
        if now.saturating_sub(self.overlay_ms) >= OVERLAY_REFRESH_MS
            || self.overlay_key.as_ref() != Some(&key)
        {
            self.overlay_ms = now;
            self.overlay_key = Some(key);
            // Country tints: most frequent selected severity in the window, intensity by log volume.
            let selected = self.options.severities;
            let totals: Vec<(usize, u64, usize)> = self
                .counts
                .0
                .iter()
                .filter_map(|(index, c)| {
                    let total: u64 = (0..3).filter(|&k| selected[k]).map(|k| c[k]).sum();
                    let dominant = (0..3)
                        .filter(|&k| selected[k])
                        .max_by_key(|&k| (c[k], 3 - k))?;
                    (total > 0).then_some((*index, total, dominant))
                })
                .collect();
            let peak = totals.iter().map(|t| t.1).max().unwrap_or(1).max(1) as f64;
            let fills: Vec<_> = totals
                .iter()
                .map(|&(index, total, dominant)| {
                    let level = (1. + total as f64).ln() / (1. + peak).ln();
                    let dim = if self.options.focus.is_some_and(|f| f != index) {
                        0.35
                    } else {
                        1.
                    };
                    (index, severity(dominant), ((22. + 78. * level) * dim) as u8)
                })
                .collect();
            r.countries.fill(&mut r.country_overlay, &fills);

            self.icons = match radar_data {
                Some(data) if self.options.radar_layer => {
                    radar_icons(data, &r.countries, &self.options.radar_hidden)
                }
                _ => Vec::new(),
            };
            if let Some(focus) = self.options.focus {
                r.countries
                    .outline(&mut r.country_overlay, &[(focus, 2.2, 230)], FOCUS);
            }
            let mut composed = r.base.clone();
            composed.draw_pixmap(
                0,
                0,
                r.country_overlay.as_ref(),
                &PixmapPaint::default(),
                Transform::identity(),
                None,
            );
            let alpha = 230. * radar_dim;
            // Larger markers first so smaller neighbours (e.g. HK next to CN) stay on top.
            let mut order: Vec<&Icon> = self.icons.iter().collect();
            order.sort_by(|a, b| b.size.total_cmp(&a.size));
            for icon in order {
                draw_icon(&mut composed, icon, alpha);
            }
            self.composed = composed;
        }
        r.pix.data_mut().copy_from_slice(self.composed.data());
        for icon in self.icons.iter().filter(|i| !i.label.is_empty()) {
            let (x, y) = icon.at;
            let colour = if icon.target { TARGET } else { INFO };
            r.text(
                (x + icon.size + 4.) as i32,
                (y - 7.) as i32,
                11,
                &icon.label,
                colour,
            );
        }

        // Arcs: one stroked curve each, fading in and then out over the arc's life. Only
        // realtime arcs carry a head dot, which travels once and never loops.
        for arc in &self.arcs {
            let age = now.saturating_sub(arc.born);
            let alpha = if age < arc.fade_in {
                150. * age as f32 / arc.fade_in as f32
            } else {
                150. * (1. - (age - arc.fade_in) as f32 / (arc.life - arc.fade_in) as f32)
            }
            .clamp(0., 150.);
            let (a, b, c) = (arc.a, arc.b, severity(arc.class));
            let cy = (a.1.min(b.1) - ((b.0 - a.0).abs() * 0.18).min(100.)).max(212.);
            let point = |t: f32| {
                let q = 1. - t;
                (
                    q * q * a.0 + 2. * q * t * (a.0 + b.0) / 2. + t * t * b.0,
                    q * q * a.1 + 2. * q * t * cy + t * t * b.1,
                )
            };
            let mut curve = PathBuilder::new();
            curve.move_to(a.0, a.1);
            for i in 1..25 {
                let p = point(i as f32 / 24.);
                curve.line_to(p.0, p.1);
            }
            if let Some(path) = curve.finish() {
                let mut paint = Paint::default();
                paint.set_color_rgba8(c[0], c[1], c[2], alpha as u8);
                paint.anti_alias = true;
                let width = if arc.travelling { 1.1 } else { 1.3 };
                r.pix.stroke_path(
                    &path,
                    &paint,
                    &Stroke {
                        width,
                        ..Default::default()
                    },
                    Transform::identity(),
                    None,
                );
            }
            r.dot(b.0, b.1, 2.2, c, alpha as u8);
            if arc.travelling {
                let head = point((age as f32 / (arc.life as f32 * 0.6)).min(1.));
                r.dot(head.0, head.1, 2.6, c, (alpha * 1.5).min(230.) as u8);
            }
        }

        let radar_label = match radar_state {
            Freshness::NoData => "NO DATA",
            Freshness::Empty => "EMPTY",
            Freshness::Current => "CURRENT",
            Freshness::Stale => "STALE",
        };

        // Latest selected records, refreshed every 2 s (Realtime 0.5 s) so the list does not scroll.
        let list_refresh = if self.options.motion == Motion::Realtime {
            REALTIME_LIST_REFRESH_MS
        } else {
            LIST_REFRESH_MS
        };
        if now.saturating_sub(self.list_ms) >= list_refresh || self.list.is_empty() {
            self.list_ms = now;
            let focus = self.options.focus;
            let severities = self.options.severities;
            let countries = &r.countries;
            self.list = s
                .recent
                .iter()
                .filter(|x| {
                    let class = x.record.class();
                    class < 3
                        && severities[class]
                        && focus.is_none_or(|f| {
                            countries.index(&x.record.source.country) == Some(f)
                                || countries.index(&x.record.destination.country) == Some(f)
                        })
                })
                .take(7)
                .map(|x| Line {
                    route: format!(
                        "{} > {}",
                        x.record.source.country.chars().take(17).collect::<String>(),
                        x.record
                            .destination
                            .country
                            .chars()
                            .take(17)
                            .collect::<String>()
                    ),
                    class: x.record.class(),
                    received_ms: x.received_ms,
                })
                .collect();
        }
        if self.options.theme == Theme::Dashboard {
            let panel = Dashboard {
                s,
                options: &self.options,
                list: &self.list,
                counts: &self.counts,
                radar_data,
                radar_label,
            };
            panel.draw(r);
            return r.pix.data();
        }

        // Header: clocks, sources, five summary boxes.
        let (utc, local) = crate::clock::labels(now);
        r.text(1044, 24, 18, &utc, [218, 236, 242]);
        r.text(1044, 50, 18, &local, [218, 236, 242]);
        r.text(
            1044,
            80,
            13,
            &format!("GREYNOISE {} | RADAR {}", s.status, radar_label),
            INFO,
        );
        let total = self.counts.1;
        let rate: u64 = s.rate.iter().rev().take(10).sum::<u64>() / 10;
        let focus = self
            .options
            .focus
            .and_then(|f| r.countries.label(f))
            .map_or("ALL".into(), |(code, _)| code.to_string());
        let motion = match self.options.motion {
            Motion::Calm => "CALM",
            Motion::Still => "STILL",
            Motion::Realtime => "REALTIME",
        };
        let head = header_tiles(r.wide_dx);
        r.wide_raw = true;
        for (i, &(tx, tw)) in head.iter().enumerate() {
            let x = tx as i32;
            // The 1440 layout keeps its original five equal 265 px boxes.
            let tw = if r.wide_dx > 0. { tw } else { 265. };
            r.rect(tx, 112., tw, 70., [12, 28, 42], 255);
            let (label, value, colour) = match i {
                0..=2 if selected[i] => (
                    format!("{} / 5 MIN", CLASS_NAMES[i]),
                    total[i].to_string(),
                    severity(i),
                ),
                0..=2 => (
                    format!("{} / HIDDEN", CLASS_NAMES[i]),
                    total[i].to_string(),
                    MUTED,
                ),
                3 => ("RECORDS / S (10 S AVG)".into(), rate.to_string(), INFO),
                _ => ("FOCUS | MOTION".into(), format!("{focus} | {motion}"), INFO),
            };
            r.text(x + 12, 119, 12, &label, MUTED);
            r.text(
                x + 12,
                142,
                25,
                &value.chars().take(16).collect::<String>(),
                colour,
            );
        }
        if let (_, Some(column)) = wide_split(r.wide_dx) {
            top_countries(r, &self.counts.0, selected, column, 252, TEXT);
        }
        r.wide_raw = false;

        // Right panel: latest selected records.
        for (i, line) in self.list.iter().enumerate() {
            let y = 256 + i as i32 * 42;
            r.text(1044, y, 13, &line.route, TEXT);
            let when = crate::clock::labels(line.received_ms).0;
            r.text(
                1044,
                y + 18,
                11,
                &format!("{} | {}", CLASS_NAMES[line.class], when),
                severity(line.class),
            );
        }
        if self.list.is_empty() {
            r.text(1044, 258, 13, "NO SELECTED RECORDS YET", MUTED);
        }

        // Right panel, lower half: Cloudflare Radar rows as supplied (informational).
        let layer = if self.options.radar_layer {
            ""
        } else {
            " (LAYER OFF)"
        };
        r.text(
            1044,
            560,
            15,
            &format!("CLOUDFLARE RADAR / TOP ROWS{layer}"),
            INFO,
        );
        match radar_data {
            Some(data) => {
                for (i, row) in data.rows.iter().take(8).enumerate() {
                    let y = 590 + i as i32 * 26;
                    let origin: String = row.origin_country_alpha2.trim().chars().take(8).collect();
                    let target: String = row
                        .target_country_alpha2
                        .as_deref()
                        .map_or("?".into(), |t| t.trim().chars().take(8).collect());
                    let hidden = !self.options.radar_layer
                        || self
                            .options
                            .radar_hidden
                            .iter()
                            .any(|h| h.eq_ignore_ascii_case(&origin));
                    let note = if hidden { " (HIDDEN)" } else { "" };
                    r.text(
                        1044,
                        y,
                        12,
                        &format!("{:>2}. {origin} -> {target}{note}", i + 1),
                        if hidden { MUTED } else { TEXT },
                    );
                    let label: String = data.value_label(i).chars().take(16).collect();
                    r.text(1290, y, 12, &label, if hidden { MUTED } else { INFO });
                }
                r.text(
                    1044,
                    805,
                    11,
                    &format!(
                        "AGGREGATE, NOT LIVE | {radar_label} | {}",
                        data.normalization
                    ),
                    MUTED,
                );
            }
            None => r.text(
                1044,
                590,
                12,
                "NO RADAR DATA (PRESS START IN THE APP)",
                MUTED,
            ),
        }

        // Bottom panel: quiet volume bars and a legend.
        let peak = s.rate.iter().copied().max().unwrap_or(1).max(1) as f32;
        for (i, &value) in s.rate.iter().enumerate() {
            let h = 70. * value as f32 / peak;
            r.rect(45. + i as f32 * 6.4, 845. - h, 4.5, h, INFO, 110);
        }
        let legend = [
            ("MALICIOUS", RED),
            ("SUSPICIOUS", YELLOW),
            ("BENIGN", GREEN),
        ];
        for (i, (label, colour)) in legend.iter().enumerate() {
            let y = 762 + i as i32 * 18;
            r.rect(640., y as f32 + 3., 12., 10., *colour, 200);
            r.text(660, y, 12, label, TEXT);
        }
        for (i, (target, label)) in [(false, "RADAR ORIGIN"), (true, "RADAR TARGET")]
            .into_iter()
            .enumerate()
        {
            let y = 816 + i as i32 * 18;
            let icon = Icon {
                target,
                at: (646., y as f32 + 8.),
                size: 6.,
                label: String::new(),
                slices: if target { Vec::new() } else { vec![0.65, 0.35] },
            };
            draw_icon(&mut r.pix, &icon, 230.);
            r.text(660, y, 11, label, TEXT);
        }
        let arcs_note = if self.options.motion == Motion::Realtime {
            "ARCS: UP TO 40/S, 3 S"
        } else {
            "ARCS: MAX 2/S, FADE 8 S"
        };
        for (i, note) in [
            "TINT: TOP CLASS, 5 MIN",
            arcs_note,
            "PIE AREA = RADAR SHARE",
            "TARGETS ONLY IF SUPPLIED",
            "CLICK COUNTRY TO FOCUS",
        ]
        .iter()
        .enumerate()
        {
            r.text(820, 762 + i as i32 * 18, 11, note, MUTED);
        }
        if s.status != "LIVE" && !s.error.is_empty() {
            r.text(
                270,
                690,
                13,
                &format!("GREYNOISE {}: {}", s.status, s.error),
                MUTED,
            );
        }
        r.pix.data()
    }
    /// Details for the country under a frame point, as JSON for the host's hover panel.
    pub fn inspect(&self, x: f32, y: f32, radar_data: Option<&Aggregate>) -> Option<String> {
        let index = self.country_at(x, y)?;
        let (code, name) = self.renderer.countries.label(index)?;
        let counts = self
            .counts
            .0
            .iter()
            .find(|(i, _)| *i == index)
            .map_or([0; 3], |(_, c)| *c);
        let radar_rows: Vec<_> = radar_data
            .map(|data| {
                data.rows
                    .iter()
                    .enumerate()
                    .filter(|(_, row)| row.origin_country_alpha2.trim().eq_ignore_ascii_case(code))
                    .map(|(i, row)| {
                        serde_json::json!({
                            "rank": i + 1,
                            "target": row.target_country_alpha2,
                            "value": data.value_label(i),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(
            serde_json::json!({
                "index": index,
                "code": code,
                "name": name,
                "window_minutes": crate::countries::COUNT_MINUTES,
                "malicious": counts[0],
                "suspicious": counts[1],
                "benign": counts[2],
                "radar_rows": radar_rows,
            })
            .to_string(),
        )
    }
}

/// Per-frame data for the dashboard theme's dynamic panels. Same sources as the classic theme.
struct Dashboard<'a> {
    s: &'a Snapshot,
    options: &'a Options,
    list: &'a [Line],
    counts: &'a (Vec<(usize, [u64; 3])>, [u64; 3]),
    radar_data: Option<&'a Aggregate>,
    radar_label: &'a str,
}
impl Dashboard<'_> {
    fn draw(&self, r: &mut Renderer) {
        let (s, o, now) = (self.s, self.options, self.s.now_ms);
        let selected = o.severities;
        let total = self.counts.1;

        // Header clocks, right-aligned in the title band.
        let (utc, local) = crate::clock::labels(now);
        r.text(1044, 20, 15, &utc, [218, 236, 242]);
        r.text(1044, 44, 15, &local, [218, 236, 242]);
        r.text(1044, 68, 11, "THEME: DASHBOARD", ACCENT_DIM);

        // 01-05: big-number tiles.
        let rate: u64 = s.rate.iter().rev().take(10).sum::<u64>() / 10;
        let focus = o
            .focus
            .and_then(|f| r.countries.label(f))
            .map_or("ALL".into(), |(code, _)| code.to_string());
        let motion = match o.motion {
            Motion::Calm => "CALM",
            Motion::Still => "STILL",
            Motion::Realtime => "REALTIME",
        };
        let tiles = dash_tiles(r.wide_dx);
        r.wide_raw = true;
        if let Some(&(x, y, w, h, _)) = tiles.get(11) {
            top_countries(r, &self.counts.0, selected, (x, y, w, h), 232, TEXT);
        }
        for (i, &(x, y, _, _, _)) in tiles.iter().take(5).enumerate() {
            let (value, colour, note) = match i {
                0..=2 if selected[i] => (total[i].to_string(), severity(i), ""),
                0..=2 => (total[i].to_string(), MUTED, "HIDDEN"),
                3 => (rate.to_string(), ACCENT, ""),
                _ => (format!("{focus} | {motion}"), ACCENT, ""),
            };
            let size = if i == 4 { 24 } else { 36 };
            r.text(
                x as i32 + 12,
                y as i32 + 36,
                size,
                &value.chars().take(16).collect::<String>(),
                colour,
            );
            if !note.is_empty() {
                r.text(x as i32 + 190, y as i32 + 8, 11, note, MUTED);
            }
        }
        r.wide_raw = false;

        // 06: map tile hints, focused-country callout, status line under the map.
        let arcs_note = if o.motion == Motion::Realtime {
            "ARCS UP TO 40/S, 3 S"
        } else {
            "ARCS MAX 2/S, FADE 8 S"
        };
        r.text(
            560,
            213,
            10,
            &format!("CLICK COUNTRY TO FOCUS | TINT: TOP CLASS 5 MIN | {arcs_note}"),
            MUTED,
        );
        if let Some(index) = o.focus {
            self.callout(r, index);
        }
        let error = if s.status != "LIVE" && !s.error.is_empty() {
            format!(" | {}", s.error.chars().take(60).collect::<String>())
        } else {
            String::new()
        };
        let feed_colour = if s.status == "LIVE" { ACCENT } else { MUTED };
        r.dot(37., 727., 3.5, feed_colour, 230);
        r.text(
            46,
            720,
            11,
            &format!(
                "GREYNOISE {}{error} | RADAR {} | {utc} | {local} | {}",
                s.status,
                self.radar_label,
                Renderer::version_text()
            ),
            TEXT,
        );

        // 07: latest selected records.
        for (i, line) in self.list.iter().enumerate() {
            let y = 236 + i as i32 * 41;
            r.rect(1037., y as f32 + 2., 3., 28., severity(line.class), 220);
            r.text(1048, y, 13, &line.route, TEXT);
            let when = crate::clock::labels(line.received_ms).0;
            r.text(
                1048,
                y + 17,
                11,
                &format!("{} | {}", CLASS_NAMES[line.class], when),
                severity(line.class),
            );
        }
        if self.list.is_empty() {
            r.text(1048, 238, 13, "NO SELECTED RECORDS YET", MUTED);
        }

        // 08: Cloudflare Radar rows as supplied (informational).
        if !o.radar_layer {
            r.text(1300, 553, 11, "LAYER OFF", MUTED);
        }
        match self.radar_data {
            Some(data) => {
                for (i, row) in data.rows.iter().take(8).enumerate() {
                    let y = 576 + i as i32 * 26;
                    let origin: String = row.origin_country_alpha2.trim().chars().take(8).collect();
                    let target: String = row
                        .target_country_alpha2
                        .as_deref()
                        .map_or("?".into(), |t| t.trim().chars().take(8).collect());
                    let hidden = !o.radar_layer
                        || o.radar_hidden
                            .iter()
                            .any(|h| h.eq_ignore_ascii_case(&origin));
                    let note = if hidden { " (HIDDEN)" } else { "" };
                    r.text(
                        1037,
                        y,
                        12,
                        &format!("{:>2}. {origin} -> {target}{note}", i + 1),
                        if hidden { MUTED } else { TEXT },
                    );
                    let label: String = data.value_label(i).chars().take(14).collect();
                    r.text(1300, y, 12, &label, if hidden { MUTED } else { INFO });
                }
                r.text(
                    1037,
                    826,
                    11,
                    &format!(
                        "AGGREGATE, NOT LIVE | {} | {}",
                        self.radar_label, data.normalization
                    ),
                    MUTED,
                );
            }
            None => r.text(
                1037,
                578,
                12,
                "NO RADAR DATA (PRESS START IN THE APP)",
                MUTED,
            ),
        }

        // 09: receipt-rate bars across the tile.
        let peak = s.rate.iter().copied().max().unwrap_or(1).max(1) as f32;
        let step = 536. / s.rate.len().max(1) as f32;
        for (i, &value) in s.rate.iter().enumerate() {
            let h = 68. * value as f32 / peak;
            r.rect(
                37. + i as f32 * step,
                845. - h,
                (step * 0.7).max(1.),
                h,
                ACCENT,
                150,
            );
        }
        r.text(470, 748, 11, &format!("PEAK {}", peak as u64), MUTED);

        // 10: severity mix of the selected classes over the count window.
        let sum: u64 = (0..3).filter(|&k| selected[k]).map(|k| total[k]).sum();
        for k in 0..3 {
            let y = 770. + k as f32 * 26.;
            let share = if selected[k] && sum > 0 {
                total[k] as f32 / sum as f32
            } else {
                0.
            };
            let colour = if selected[k] { severity(k) } else { MUTED };
            r.rect(607., y + 13., 176., 6., DASH_GRID, 255);
            r.rect(607., y + 13., 176. * share, 6., colour, 220);
            let pct = if selected[k] {
                format!("{:>3}%", (share * 100.).round() as u32)
            } else {
                " OFF".into()
            };
            r.text(
                607,
                y as i32 - 2,
                11,
                &format!("{:<10} {pct}", &CLASS_NAMES[k][..3]),
                TEXT,
            );
        }

        // 11: legend.
        for (i, (label, colour)) in [
            ("MALICIOUS", RED),
            ("SUSPICIOUS", YELLOW),
            ("BENIGN", GREEN),
        ]
        .iter()
        .enumerate()
        {
            let y = 766 + i as i32 * 16;
            r.rect(817., y as f32 + 3., 10., 8., *colour, 200);
            r.text(833, y, 11, label, TEXT);
        }
        for (i, (target, label)) in [(false, "RADAR ORIGIN"), (true, "RADAR TARGET")]
            .into_iter()
            .enumerate()
        {
            let y = 814 + i as i32 * 16;
            let icon = Icon {
                target,
                at: (822., y as f32 + 7.),
                size: 5.,
                label: String::new(),
                slices: if target { Vec::new() } else { vec![0.65, 0.35] },
            };
            draw_icon(&mut r.pix, &icon, 230.);
            r.text(833, y, 11, label, TEXT);
        }
    }
    /// Leader line from the focused country to a label box with its window counts.
    fn callout(&self, r: &mut Renderer, index: usize) {
        let Some((lon, lat)) = r.countries.anchor(index) else {
            return;
        };
        let Some((code, name)) = r.countries.label(index) else {
            return;
        };
        let (code, name) = (code.to_string(), name.to_uppercase());
        let counts = self
            .counts
            .0
            .iter()
            .find(|(i, _)| *i == index)
            .map_or([0; 3], |(_, c)| *c);
        let (ax, ay) = xy(lon, lat);
        let (bw, bh) = (236., 50.);
        // Keep the box inside the map tile, preferring above-right of the anchor.
        let bx = if ax + 40. + bw < 1000. {
            ax + 40.
        } else {
            ax - 40. - bw
        };
        let by = (ay - 70.).clamp(232., 700. - bh);
        let join = (if bx > ax { bx } else { bx + bw }, by + bh / 2.);
        r.line(ax, ay, join.0, join.1, ACCENT, 1., 220);
        r.dot(ax, ay, 3., ACCENT, 240);
        r.rect(bx, by, bw, bh, DASH_BG, 235);
        r.tile_frame(bx, by, bw, bh);
        let title: String = format!("{code} / {name}").chars().take(28).collect();
        r.text(bx as i32 + 9, by as i32 + 7, 12, &title, ACCENT);
        r.text(
            bx as i32 + 9,
            by as i32 + 27,
            11,
            &format!(
                "MAL {} SUS {} BEN {} / {} MIN",
                counts[0],
                counts[1],
                counts[2],
                crate::countries::COUNT_MINUTES
            ),
            TEXT,
        );
    }
}

/// Common short form of a formal country name for narrow lists ("Kingdom of Spain" -> "SPAIN").
fn short_name(name: &str) -> String {
    const PREFIXES: [&str; 12] = [
        "FEDERAL REPUBLIC OF ",
        "PEOPLE'S REPUBLIC OF ",
        "ISLAMIC REPUBLIC OF ",
        "UNITED REPUBLIC OF ",
        "DEMOCRATIC REPUBLIC OF THE ",
        "REPUBLIC OF THE ",
        "REPUBLIC OF ",
        "KINGDOM OF THE ",
        "KINGDOM OF ",
        "COMMONWEALTH OF THE ",
        "COMMONWEALTH OF ",
        "STATE OF ",
    ];
    let upper = name.to_uppercase();
    PREFIXES
        .iter()
        .find_map(|p| upper.strip_prefix(p))
        .filter(|rest| !rest.is_empty())
        .map_or(upper.clone(), str::to_string)
}
/// Wide frames only: countries ranked by received records of the selected classes in the count
/// window, with a severity bar. Drawn in frame coordinates (`wide_raw`), inside `area`.
fn top_countries(
    r: &mut Renderer,
    counts: &[(usize, [u64; 3])],
    selected: [bool; 3],
    area: (f32, f32, f32, f32),
    top: i32,
    text: [u8; 3],
) {
    let (x, _, w, h) = area;
    let total = |c: &[u64; 3]| (0..3).filter(|&k| selected[k]).map(|k| c[k]).sum::<u64>();
    let mut ranked: Vec<_> = counts.iter().filter(|(_, c)| total(c) > 0).collect();
    ranked.sort_by_key(|(index, c)| (std::cmp::Reverse(total(c)), *index));
    let rows = ((h - (top as f32 - area.1) - 16.) / 28.).max(0.) as usize;
    let peak = ranked.first().map_or(1, |(_, c)| total(c)).max(1) as f32;
    let left = x as i32 + 19;
    let chars = ((w - 38.) / 7.5).max(4.) as usize;
    if ranked.is_empty() {
        r.text(left, top, 12, "NO SELECTED RECORDS YET", MUTED);
    }
    for (i, (index, c)) in ranked.into_iter().take(rows).enumerate() {
        let y = top + i as i32 * 28;
        let sum = total(c);
        let count = sum.to_string();
        let room = chars.saturating_sub(count.len() + 1);
        // Narrow column: the code alone rather than a name cut mid-word.
        let name = r
            .countries
            .label(*index)
            .map_or(String::from("?"), |(code, name)| {
                if chars >= 20 {
                    format!("{code} {}", short_name(name))
                } else {
                    code.to_string()
                }
            });
        r.text(
            left,
            y,
            12,
            &name.chars().take(room).collect::<String>(),
            text,
        );
        r.text(
            left + (chars.saturating_sub(count.len()) as f32 * 7.5) as i32,
            y,
            12,
            &count,
            INFO,
        );
        // Severity mix bar, length relative to the busiest country.
        let full = (w - 38.) * sum as f32 / peak;
        let mut bx = left as f32;
        for k in (0..3).filter(|&k| selected[k]) {
            let part = full * c[k] as f32 / sum as f32;
            r.rect(bx, y as f32 + 17., part, 4., severity(k), 200);
            bx += part;
        }
    }
}

/// Lighter slate for target diamonds, still informational rather than severity.
const TARGET: [u8; 3] = [170, 192, 216];
/// Pie marker blues: brighter than the slate text so markers stand out, but never a severity colour.
const PIE: [u8; 3] = [110, 168, 232];
const PIE_ALT: [u8; 3] = [64, 118, 190];
/// Marker fill opacity (50%) so the map and tints stay visible underneath.
const MARKER_FILL: f32 = 128.;
/// Each of an origin's ranked rows as a fraction of that pie (provider order). These are the
/// rows' relative sizes within one marker, not a new total shown anywhere.
fn origin_slices(data: &Aggregate, code: &str) -> Vec<f32> {
    let values: Vec<f64> = data
        .rows
        .iter()
        .zip(&data.values)
        .filter(|(row, _)| row.origin_country_alpha2.trim().eq_ignore_ascii_case(code))
        .map(|(_, &value)| value)
        .collect();
    let whole: f64 = values.iter().sum();
    if values.len() < 2 || whole <= 0. {
        return Vec::new();
    }
    values.iter().map(|v| (v / whole) as f32).collect()
}
/// Closed wedge from angle `a0` to `a1` (radians, clockwise from 12 o'clock).
fn wedge(x: f32, y: f32, r: f32, a0: f32, a1: f32) -> Option<Path> {
    let mut b = PathBuilder::new();
    b.move_to(x, y);
    let steps = (((a1 - a0) / 0.08).ceil() as usize).max(2);
    for i in 0..=steps {
        let a = a0 + (a1 - a0) * i as f32 / steps as f32;
        b.line_to(x + r * a.sin(), y - r * a.cos());
    }
    b.close();
    b.finish()
}
/// Origin badges (size by each origin's largest share; rows are never summed) and target
/// diamonds for provider-supplied targets of visible rows. Hidden origins hide their targets too.
fn radar_icons(
    data: &Aggregate,
    countries: &crate::countries::CountryMap,
    hidden: &[String],
) -> Vec<Icon> {
    let place = |code: &str| {
        countries
            .index(code)
            .and_then(|i| countries.anchor(i))
            .or_else(|| radar::small_place(code))
            .map(|(lon, lat)| xy(lon, lat))
    };
    let visible = |code: &str| !hidden.iter().any(|h| h.eq_ignore_ascii_case(code.trim()));
    let largest = data.largest();
    let share = |value: f64| {
        if largest > 0. {
            (value / largest).sqrt() as f32
        } else {
            0.
        }
    };
    let mut icons = Vec::new();
    for (n, origin) in data
        .origins()
        .into_iter()
        .filter(|o| visible(&o.code))
        .enumerate()
    {
        let Some(at) = place(&origin.code) else {
            continue;
        };
        let best = data
            .rows
            .iter()
            .zip(&data.values)
            .position(|(row, &value)| {
                row.origin_country_alpha2
                    .trim()
                    .eq_ignore_ascii_case(&origin.code)
                    && value == origin.largest
            });
        let value = best.map(|i| data.value_label(i)).unwrap_or_default();
        icons.push(Icon {
            target: false,
            at,
            // Pie area is proportional to the listed value: radius scales with its square root.
            size: 9. + 21. * share(origin.largest),
            slices: origin_slices(data, &origin.code),
            // Label the eight largest origins only, to keep the map quiet.
            label: if n < 8 {
                format!(
                    "{} {value}",
                    origin.code.chars().take(8).collect::<String>()
                )
            } else {
                String::new()
            },
        });
    }
    let mut targets: Vec<(String, f64)> = Vec::new();
    for (row, &value) in data.rows.iter().zip(&data.values) {
        let Some(target) = row
            .target_country_alpha2
            .as_deref()
            .map(|t| t.trim().to_uppercase())
        else {
            continue;
        };
        if target.is_empty() || !visible(&row.origin_country_alpha2) {
            continue;
        }
        match targets.iter_mut().find(|t| t.0 == target) {
            Some(t) => t.1 = t.1.max(value),
            None => targets.push((target, value)),
        }
    }
    for (code, value) in targets {
        let Some(mut at) = place(&code) else { continue };
        // A country that is also an origin keeps both icons: the target sits just below.
        if let Some(origin) = icons.iter().find(|i| !i.target && i.at == at) {
            at.1 += origin.size + 12.;
        }
        icons.push(Icon {
            target: true,
            at,
            size: 6. + 9. * share(value),
            label: format!("T {}", code.chars().take(8).collect::<String>()),
            slices: Vec::new(),
        });
    }
    icons
}
fn draw_icon(pixmap: &mut Pixmap, icon: &Icon, alpha: f32) {
    let (x, y) = icon.at;
    let stroke = |pixmap: &mut Pixmap, path: &Path, rgb: [u8; 3], a: f32, width: f32| {
        let mut p = Paint::default();
        p.set_color_rgba8(rgb[0], rgb[1], rgb[2], a.clamp(0., 255.) as u8);
        p.anti_alias = true;
        pixmap.stroke_path(
            path,
            &p,
            &Stroke {
                width,
                ..Default::default()
            },
            Transform::identity(),
            None,
        );
    };
    let fill = |pixmap: &mut Pixmap, path: &Path, rgb: [u8; 3], a: f32| {
        let mut p = Paint::default();
        p.set_color_rgba8(rgb[0], rgb[1], rgb[2], a.clamp(0., 255.) as u8);
        p.anti_alias = true;
        pixmap.fill_path(path, &p, FillRule::Winding, Transform::identity(), None);
    };
    if icon.target {
        let s = icon.size;
        let mut b = PathBuilder::new();
        b.move_to(x, y - s);
        b.line_to(x + s, y);
        b.line_to(x, y + s);
        b.line_to(x - s, y);
        b.close();
        if let Some(path) = b.finish() {
            fill(pixmap, &path, TARGET, MARKER_FILL * alpha / 230.);
            stroke(pixmap, &path, TARGET, alpha, 1.5);
        }
        return;
    }
    // Pie: one slice per ranked row of this origin (a full disc for a single row), 50% opacity.
    let r = icon.size;
    if icon.slices.len() < 2 {
        if let Some(disc) = PathBuilder::from_circle(x, y, r) {
            fill(pixmap, &disc, PIE, MARKER_FILL * alpha / 230.);
        }
    } else {
        let mut start = 0f32;
        for (i, fraction) in icon.slices.iter().enumerate() {
            let end = start + fraction * std::f32::consts::TAU;
            if let Some(path) = wedge(x, y, r, start, end) {
                let colour = if i % 2 == 0 { PIE } else { PIE_ALT };
                fill(pixmap, &path, colour, MARKER_FILL * alpha / 230.);
                stroke(pixmap, &path, [10, 23, 36], alpha * 0.6, 1.);
            }
            start = end;
        }
    }
    if let Some(ring) = PathBuilder::from_circle(x, y, r) {
        stroke(pixmap, &ring, PIE, alpha, 1.4);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::State;
    fn row(source: &str, destination: &str, intention: &str) -> String {
        serde_json::json!({
            "source": {"latitude": 52, "longitude": 5, "country": source},
            "destination": {"latitude": 40, "longitude": -100, "country": destination},
            "intention": intention
        })
        .to_string()
    }
    fn counts(state: &State, now: u64) -> (Vec<(usize, [u64; 3])>, [u64; 3]) {
        state.counts(now)
    }
    #[test]
    fn arcs_are_rate_limited_capped_and_fade_out() {
        let mut view = SocView::new();
        view.options.motion = Motion::Calm;
        let mut state = State::default();
        let mut most = 0;
        for second in 0..40u64 {
            let now = 1_000_000 + second * 1000;
            for _ in 0..200 {
                state.ingest(&row("NL", "US", "malicious"), now);
            }
            for frame in 0..8 {
                let t = now + frame * 125;
                let snapshot = state.snapshot(t);
                view.draw(&snapshot, counts(&state, t), None, 0);
                most = most.max(view.arc_count());
            }
        }
        // 8000 records arrived; at most 2/s are drawn and never more than MAX_ARCS at once.
        assert!((10..=MAX_ARCS).contains(&most), "peak arcs {most}");
        let quiet = 1_000_000 + 60_000;
        view.draw(&state.snapshot(quiet), counts(&state, quiet), None, 0);
        assert_eq!(
            view.arc_count(),
            0,
            "arcs expire after {ARC_LIFE_MS} ms without new records"
        );
    }
    #[test]
    fn still_mode_and_severity_filters_suppress_arcs() {
        let mut view = SocView::new();
        let mut state = State::default();
        view.options.motion = Motion::Still;
        for i in 0..10u64 {
            state.ingest(&row("NL", "US", "malicious"), 1000 + i * 500);
            view.draw(
                &state.snapshot(1000 + i * 500),
                counts(&state, 1000 + i * 500),
                None,
                0,
            );
        }
        assert_eq!(view.arc_count(), 0);
        view.options = Options {
            severities: [false, true, true],
            ..Options::default()
        };
        for i in 10..20u64 {
            state.ingest(&row("NL", "US", "malicious"), 1000 + i * 500);
            view.draw(
                &state.snapshot(1000 + i * 500),
                counts(&state, 1000 + i * 500),
                None,
                0,
            );
        }
        assert_eq!(view.arc_count(), 0, "hidden severity draws no arcs");
    }
    #[test]
    fn focus_limits_arcs_and_inspect_reports_window_counts() {
        let mut view = SocView::new();
        let mut state = State::default();
        let nl = view.renderer.countries.index("NL").unwrap();
        view.options.focus = Some(nl);
        for i in 0..20u64 {
            state.ingest(&row("BR", "US", "malicious"), 1000 + i * 500);
            view.draw(
                &state.snapshot(1000 + i * 500),
                counts(&state, 1000 + i * 500),
                None,
                0,
            );
        }
        assert_eq!(
            view.arc_count(),
            0,
            "records not touching the focused country stay hidden"
        );
        state.ingest(&row("NL", "US", "suspicious"), 12_000);
        state.ingest(&row("Netherlands", "DE", "benign"), 12_000);
        view.draw(&state.snapshot(12_100), counts(&state, 12_100), None, 0);
        assert!(view.arc_count() >= 1);
        let (x, y) = xy(5.3, 52.1);
        let info: serde_json::Value =
            serde_json::from_str(&view.inspect(x, y, None).unwrap()).unwrap();
        assert_eq!(info["code"], "NL");
        assert_eq!(
            (
                info["malicious"].as_u64(),
                info["suspicious"].as_u64(),
                info["benign"].as_u64()
            ),
            (Some(0), Some(1), Some(1))
        );
        let (ox, oy) = xy(-30., 0.);
        assert!(
            view.inspect(ox, oy, None).is_none(),
            "open ocean has no country"
        );
        assert!(view.inspect(5., 5., None).is_none(), "outside the map");
    }
    #[test]
    fn country_tint_uses_severity_colours_and_radar_stays_informational() {
        let mut view = SocView::new();
        let mut state = State::default();
        for _ in 0..50 {
            state.ingest(&row("BR", "BR", "malicious"), 5000);
        }
        let body = r#"{"success":true,"result":{"meta":{"lastUpdated":"x","normalization":"PERCENTAGE","dateRange":[{"startTime":"a","endTime":"b"}]},"top_0":[{"originCountryAlpha2":"AU","originCountryName":"Australia","value":"3"}]}}"#;
        let radar_data = radar::parse(body.as_bytes()).unwrap();
        let frame = view
            .draw(
                &state.snapshot(6000),
                counts(&state, 6000),
                Some(&radar_data),
                6000,
            )
            .to_vec();
        let pixel = |lon: f64, lat: f64| {
            let (x, y) = xy(lon, lat);
            let i = (y as usize * crate::WIDTH as usize + x as usize) * 4;
            [frame[i], frame[i + 1], frame[i + 2]]
        };
        let brazil = pixel(-51.9, -10.);
        assert!(
            brazil[0] > brazil[1] + 15 && brazil[0] > brazil[2] + 15,
            "Brazil tinted red: {brazil:?}"
        );
        let australia = pixel(134., -25.);
        assert!(
            australia[2] >= australia[0],
            "Radar does not fill countries with a severity colour: {australia:?}"
        );
    }
    #[test]
    fn counts_window_and_country_dedupe() {
        let mut state = State::default();
        state.ingest(&row("NL", "Netherlands", "malicious"), 60_000);
        state.ingest(&row("NL", "US", "benign"), 120_000);
        let nl = crate::countries::CountryMap::new().index("NL").unwrap();
        let (countries, total) = state.counts(120_000);
        assert_eq!(total, [1, 0, 1]);
        assert_eq!(
            countries.iter().find(|c| c.0 == nl).unwrap().1,
            [1, 0, 1],
            "same-country record counted once"
        );
        let (countries, total) = state.counts(60_000 * 7);
        assert_eq!(total, [0, 0, 0]);
        assert!(countries.is_empty(), "counts expire after the window");
    }

    const ICON_BODY: &str = r#"{"success":true,"result":{"meta":{"lastUpdated":"x","normalization":"PERCENTAGE","dateRange":[{"startTime":"a","endTime":"b"}]},"top_0":[{"originCountryAlpha2":"BR","originCountryName":"Brazil","targetCountryAlpha2":"US","targetCountryName":"United States","value":"7.4"},{"originCountryAlpha2":"CN","originCountryName":"China","value":"4.0"},{"originCountryAlpha2":"HK","originCountryName":"Hong Kong","value":"2.1"}]}}"#;
    #[test]
    fn icon_layer_marks_origins_and_supplied_targets_only() {
        let view = SocView::new();
        let data = radar::parse(ICON_BODY.as_bytes()).unwrap();
        let icons = radar_icons(&data, &view.renderer.countries, &[]);
        let origins: Vec<_> = icons
            .iter()
            .filter(|i| !i.target)
            .map(|i| i.label.clone())
            .collect();
        assert_eq!(origins, vec!["BR 7.40%", "CN 4.00%", "HK 2.10%"]);
        let targets: Vec<_> = icons
            .iter()
            .filter(|i| i.target)
            .map(|i| i.label.clone())
            .collect();
        assert_eq!(
            targets,
            vec!["T US"],
            "only the provider-supplied target is marked"
        );
        let br = icons.iter().find(|i| i.label.starts_with("BR")).unwrap();
        assert!(
            br.size
                > icons
                    .iter()
                    .find(|i| i.label.starts_with("CN"))
                    .unwrap()
                    .size,
            "size follows share"
        );
        let hidden = radar_icons(&data, &view.renderer.countries, &["br".into()]);
        assert!(
            hidden.iter().all(|i| !i.label.starts_with("BR")),
            "hidden origin removed"
        );
        assert!(
            hidden.iter().all(|i| !i.target),
            "hidden origin hides its targets"
        );
    }
    #[test]
    fn layer_toggle_and_no_lines_between_origin_and_target() {
        let state = State::default();
        let data = radar::parse(ICON_BODY.as_bytes()).unwrap();
        let mut view = SocView::new();
        let on = view
            .draw(
                &state.snapshot(1000),
                counts(&state, 1000),
                Some(&data),
                1000,
            )
            .to_vec();
        view.options.radar_layer = false;
        let off = view
            .draw(
                &state.snapshot(1000),
                counts(&state, 1000),
                Some(&data),
                1000,
            )
            .to_vec();
        let pixel = |frame: &[u8], (x, y): (f32, f32)| {
            let i = (y as usize * crate::WIDTH as usize + x as usize) * 4;
            [frame[i], frame[i + 1], frame[i + 2]]
        };
        let countries = &view.renderer.countries;
        let at = |code: &str| {
            let (lon, lat) = countries.anchor(countries.index(code).unwrap()).unwrap();
            xy(lon, lat)
        };
        let (br, us) = (at("BR"), at("US"));
        assert_ne!(
            pixel(&on, br),
            pixel(&off, br),
            "origin icon drawn when the layer is on"
        );
        // Midpoint between Brazil and the US (Caribbean Sea): no route or line is drawn.
        let mid = ((br.0 + us.0) / 2., (br.1 + us.1) / 2.);
        assert_eq!(pixel(&on, mid), pixel(&off, mid));
    }
    #[test]
    fn icon_anchors_fall_inside_their_countries() {
        let map = crate::countries::CountryMap::new();
        for code in ["US", "BR", "FR", "RU", "CN", "IN", "AU", "CL", "NO", "ID"] {
            let index = map.index(code).unwrap();
            let (lon, lat) = map.anchor(index).unwrap();
            assert_eq!(map.at(lon, lat), Some(index), "{code} anchor {lon},{lat}");
        }
    }
    #[test]
    fn origins_are_half_opaque_pies_sized_by_value() {
        let body = ICON_BODY.replace(
            r#"{"originCountryAlpha2":"CN""#,
            r#"{"originCountryAlpha2":"BR","originCountryName":"Brazil","value":"2.5"},{"originCountryAlpha2":"CN""#,
        );
        let data = radar::parse(body.as_bytes()).unwrap();
        let view = SocView::new();
        let icons = radar_icons(&data, &view.renderer.countries, &[]);
        let icon = |code: &str| {
            icons
                .iter()
                .find(|i| !i.target && i.label.starts_with(code))
                .unwrap()
        };
        // Brazil has two ranked rows (7.4 and 2.5): two slices in provider order.
        let br = &icon("BR").slices;
        assert_eq!(br.len(), 2);
        assert!((br[0] - 7.4 / 9.9).abs() < 1e-4 && (br[1] - 2.5 / 9.9).abs() < 1e-4);
        assert!(icon("CN").slices.is_empty(), "single row draws a full disc");
        // Area follows the listed value: (r - 9)^2 is proportional to value / largest.
        let (rb, rc) = (icon("BR").size - 9., icon("CN").size - 9.);
        assert!(((rc * rc) / (rb * rb) - 4.0 / 7.4).abs() < 0.01);
        // 50% fill: the centre of China's disc lies between the bare map and the marker colour.
        let state = State::default();
        let mut on = SocView::new();
        let frame = on
            .draw(
                &state.snapshot(1000),
                counts(&state, 1000),
                Some(&data),
                1000,
            )
            .to_vec();
        let mut off = SocView::new();
        off.options.radar_layer = false;
        let bare = off
            .draw(
                &state.snapshot(1000),
                counts(&state, 1000),
                Some(&data),
                1000,
            )
            .to_vec();
        let (x, y) = icon("CN").at;
        let i = ((y - 4.) as usize * crate::WIDTH as usize + (x + 4.) as usize) * 4;
        for k in 0..3 {
            let (map, marker, seen) = (bare[i + k] as f32, PIE[k] as f32, frame[i + k] as f32);
            let expected = map + (marker - map) * 0.5;
            assert!(
                (seen - expected).abs() <= 6.,
                "channel {k}: map {map}, marker {marker}, seen {seen}"
            );
        }
    }
    #[test]
    fn realtime_is_the_default() {
        assert_eq!(Options::default().motion, Motion::Realtime);
        assert_eq!(SocView::new().options.motion, Motion::Realtime);
    }
    #[test]
    fn realtime_is_busier_but_bounded_and_keeps_the_class_mix() {
        let mut view = SocView::new();
        view.options.motion = Motion::Realtime;
        let mut state = State::default();
        let mut peak = 0;
        let mut classes = [0usize; 3];
        for second in 0..12u64 {
            let now = 2_000_000 + second * 1000;
            for i in 0..600 {
                // Arrivals are 1/6 malicious, 2/6 suspicious, 3/6 benign.
                let intention = [
                    "malicious",
                    "suspicious",
                    "suspicious",
                    "benign",
                    "benign",
                    "benign",
                ][i % 6];
                state.ingest(&row("NL", "US", intention), now);
            }
            for frame in 0..15 {
                let t = now + frame * 66;
                view.draw(&state.snapshot(t), counts(&state, t), None, 0);
                peak = peak.max(view.arc_count());
                for arc in &view.arcs {
                    if arc.born == t {
                        classes[arc.class] += 1;
                    }
                }
            }
        }
        assert!(
            (60..=REALTIME_MAX_ARCS).contains(&peak),
            "realtime peak {peak}"
        );
        let total: usize = classes.iter().sum();
        assert!(
            total as f64 <= REALTIME_ARCS_PER_SECOND * 12. * 1.1 + 60.,
            "budget respected: {total}"
        );
        // Even sampling keeps roughly the arrival mix instead of only the most severe class.
        let share = |k: usize| classes[k] as f64 / total as f64;
        assert!(
            share(0) > 0.08 && share(1) > 0.2 && share(2) > 0.35,
            "mix {classes:?}"
        );
        let later = 2_000_000 + 12_000 + REALTIME_ARC_LIFE_MS + 100;
        view.draw(&state.snapshot(later), counts(&state, later), None, 0);
        assert_eq!(
            view.arc_count(),
            0,
            "realtime arcs expire after {REALTIME_ARC_LIFE_MS} ms"
        );
        // Back to calm: the cap drops to MAX_ARCS on the next frame.
        view.options.motion = Motion::Calm;
        for i in 0..200 {
            state.ingest(&row("NL", "US", "benign"), later + 10 + i);
        }
        view.options.motion = Motion::Realtime;
        view.draw(
            &state.snapshot(later + 500),
            counts(&state, later + 500),
            None,
            0,
        );
        view.options.motion = Motion::Calm;
        view.draw(
            &state.snapshot(later + 600),
            counts(&state, later + 600),
            None,
            0,
        );
        assert!(view.arc_count() <= MAX_ARCS);
    }
    fn still_frame(view: &mut SocView, state: &State, now: u64) -> Vec<u8> {
        view.draw(&state.snapshot(now), counts(state, now), None, 0)
            .to_vec()
    }
    fn busy_state() -> State {
        let mut state = State::default();
        for (i, (src, dst)) in [("NL", "US"), ("CN", "DE"), ("BR", "US"), ("NL", "FR")]
            .iter()
            .cycle()
            .take(40)
            .enumerate()
        {
            state.ingest(
                &row(src, dst, ["malicious", "suspicious", "benign"][i % 3]),
                1000 + i as u64,
            );
        }
        state
    }
    #[test]
    fn wide_frames_keep_the_map_and_move_the_right_panels() {
        let state = busy_state();
        let now = 5_000;
        for theme in [Theme::Classic, Theme::Dashboard] {
            let mut standard = SocView::new();
            standard.options.motion = Motion::Still;
            standard.options.theme = theme;
            let base = still_frame(&mut standard, &state, now);
            for width in [1500u32, 1900, 2560] {
                let mut view = SocView::new();
                view.options.motion = Motion::Still;
                view.options.theme = theme;
                assert_eq!(view.set_width(width), width);
                let frame = still_frame(&mut view, &state, now);
                assert_eq!(frame.len(), width as usize * crate::HEIGHT as usize * 4);
                // The map (with tints) is pixel-identical: same size, same place, same clicks.
                for y in (240..700).step_by(7) {
                    for x in (60..980).step_by(7) {
                        let a = (y * crate::WIDTH as usize + x) * 4;
                        let b = (y * width as usize + x) * 4;
                        assert_eq!(
                            base[a..a + 3],
                            frame[b..b + 3],
                            "{theme:?} {width} map at {x},{y}"
                        );
                    }
                }
                // The right-hand panels moved to the right edge, unchanged.
                let dx = (width - crate::WIDTH) as usize;
                for y in (210..850).step_by(9) {
                    for x in (1030..1410).step_by(9) {
                        let a = (y * crate::WIDTH as usize + x) * 4;
                        let b = (y * width as usize + x + dx) * 4;
                        // Dashboard background grid stays on its 40 px raster between tiles.
                        let dark = |p: &[u8]| p[..3].iter().all(|&c| c < 20);
                        if theme == Theme::Dashboard && dark(&base[a..]) && dark(&frame[b..]) {
                            continue;
                        }
                        assert_eq!(
                            base[a..a + 3],
                            frame[b..b + 3],
                            "{theme:?} {width} panel at {x},{y}"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn short_country_names_for_the_top_list() {
        assert_eq!(short_name("Kingdom of Spain"), "SPAIN");
        assert_eq!(short_name("Kingdom of the Netherlands"), "NETHERLANDS");
        assert_eq!(short_name("Democratic Republic of the Congo"), "CONGO");
        assert_eq!(short_name("Canada"), "CANADA");
        assert_eq!(short_name("Republic of "), "REPUBLIC OF ");
    }
    #[test]
    fn wide_frames_fill_the_extra_space_and_restore_exactly() {
        let state = busy_state();
        let now = 5_000;
        let mut reference = SocView::new();
        reference.options.motion = Motion::Still;
        let classic = still_frame(&mut reference, &state, now);
        let mut view = SocView::new();
        view.options.motion = Motion::Still;
        let px = |frame: &[u8], width: u32, x: usize, y: usize| {
            let i = (y * width as usize + x) * 4;
            [frame[i], frame[i + 1], frame[i + 2]]
        };
        // Small extra width: the map panel grows; no column.
        view.set_width(1540);
        let frame = still_frame(&mut view, &state, now);
        assert_eq!(px(&frame, 1540, 1060, 400), CLASSIC_PANEL);
        // Enough for a column: a top-countries panel with text between map and right panels.
        view.set_width(1900);
        let frame = still_frame(&mut view, &state, now);
        let column: Vec<_> = (1030..1460)
            .flat_map(|x| (240..300).map(move |y| (x, y)))
            .map(|(x, y)| px(&frame, 1900, x, y))
            .collect();
        assert!(column.contains(&CLASSIC_PANEL), "column panel painted");
        assert!(
            column.iter().any(|p| p.iter().all(|&c| c > 150)),
            "country rows written"
        );
        // Back to 1440: exactly the standard frame again; out-of-range widths are clamped.
        assert_eq!(view.set_width(100), crate::WIDTH);
        assert_eq!(still_frame(&mut view, &state, now), classic);
        assert_eq!(view.set_width(u32::MAX), crate::WIDTH * 3);
        view.options.theme = Theme::Dashboard;
        let frame = still_frame(&mut view, &state, now);
        assert_eq!(
            frame.len(),
            (crate::WIDTH * 3) as usize * crate::HEIGHT as usize * 4
        );
    }
    #[test]
    fn classic_is_the_default_theme_and_switching_back_restores_it_exactly() {
        assert_eq!(Options::default().theme, Theme::Classic);
        let mut state = State::default();
        for i in 0..20u64 {
            state.ingest(
                &row(
                    "NL",
                    "US",
                    ["malicious", "suspicious", "benign"][i as usize % 3],
                ),
                1000 + i,
            );
        }
        let now = 5_000;
        let mut reference = SocView::new();
        reference.options.motion = Motion::Still;
        let classic = still_frame(&mut reference, &state, now);

        let mut view = SocView::new();
        view.options.motion = Motion::Still;
        view.options.theme = Theme::Dashboard;
        let dashboard = still_frame(&mut view, &state, now);
        assert_ne!(classic, dashboard, "dashboard repaints the frame");
        view.options.theme = Theme::Classic;
        assert_eq!(
            still_frame(&mut view, &state, now),
            classic,
            "classic frame is unchanged"
        );
    }
    #[test]
    fn dashboard_uses_black_background_and_accent_tiles() {
        let mut view = SocView::new();
        view.options.motion = Motion::Still;
        view.options.theme = Theme::Dashboard;
        let frame = still_frame(&mut view, &State::default(), 5_000);
        let px = |x: usize, y: usize| {
            let i = (y * crate::WIDTH as usize + x) * 4;
            [frame[i], frame[i + 1], frame[i + 2]]
        };
        // Gap between tiles is near-black (classic is navy 5,12,21 there).
        let gap = px(1015, 400);
        assert!(gap.iter().all(|&c| c < 16), "gap {gap:?}");
        // Top-left corner tick of tile 01 uses the cyan accent.
        let tick = px(37, 96);
        assert!(
            tick[1] > 150 && tick[2] > 150 && tick[0] < 120,
            "tick {tick:?}"
        );
    }
    #[test]
    fn dashboard_callout_marks_the_focused_country_and_classic_has_none() {
        let mut state = State::default();
        state.ingest(&row("NL", "US", "malicious"), 1000);
        let mut view = SocView::new();
        view.options.motion = Motion::Still;
        let index = view
            .renderer
            .countries
            .index("US")
            .expect("US in country map");
        let (lon, lat) = view.renderer.countries.anchor(index).expect("anchor");
        let (x, y) = xy(lon, lat);
        let at = |frame: &[u8]| {
            let i = (y.round() as usize * crate::WIDTH as usize + x.round() as usize) * 4;
            [frame[i], frame[i + 1], frame[i + 2]]
        };
        let is_accent = |c: [u8; 3]| c[1] > 150 && c[2] > 150 && c[0] < 140;
        view.options.focus = Some(index);
        let classic = still_frame(&mut view, &state, 5_000);
        assert!(!is_accent(at(&classic)), "classic has no callout dot");
        view.options.theme = Theme::Dashboard;
        let dashboard = still_frame(&mut view, &state, 5_000);
        assert!(
            is_accent(at(&dashboard)),
            "callout dot at anchor: {:?}",
            at(&dashboard)
        );
    }
    #[test]
    fn dashboard_keeps_the_same_bounded_arcs() {
        let mut view = SocView::new();
        view.options.theme = Theme::Dashboard;
        let mut state = State::default();
        let mut most = 0;
        for second in 0..10u64 {
            let now = 1_000_000 + second * 1000;
            for _ in 0..500 {
                state.ingest(&row("NL", "US", "malicious"), now);
            }
            for frame in 0..10 {
                let t = now + frame * 100;
                view.draw(&state.snapshot(t), counts(&state, t), None, 0);
                most = most.max(view.arc_count());
            }
        }
        assert!(most > MAX_ARCS && most <= REALTIME_MAX_ARCS, "peak {most}");
    }
}
