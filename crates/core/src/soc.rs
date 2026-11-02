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
/// Country tints and outlines are redrawn at most once a second (or when options change).
const OVERLAY_REFRESH_MS: u64 = 1000;
type OverlayKey = ([bool; 3], Option<usize>, u64, bool, Freshness);
const MAP: (f32, f32, f32, f32) = (45., 230., 940., 470.);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Motion {
    Calm,
    Still,
}
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub severities: [bool; 3],
    pub motion: Motion,
    pub focus: Option<usize>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            severities: [true; 3],
            motion: Motion::Calm,
            focus: None,
        }
    }
}
struct Arc {
    a: (f32, f32),
    b: (f32, f32),
    born: u64,
    class: usize,
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
    last_ms: u64,
    list: Vec<Line>,
    list_ms: u64,
    overlay_ms: u64,
    overlay_key: Option<OverlayKey>,
    /// Map + tints + outlines + rings, rebuilt with the overlay; each frame starts from a copy.
    composed: Pixmap,
    counts: (Vec<(usize, [u64; 3])>, [u64; 3]),
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
        r.base_map();
        r.text(35, 28, 30, "THREAT ATLAS", [223, 241, 249]);
        r.text(
            36,
            70,
            14,
            "SECURITY OPERATIONS / GREYNOISE LIVE + CLOUDFLARE RADAR",
            MUTED,
        );
        r.text(1044, 225, 15, "LATEST SELECTED RECORDS", INFO);
        r.text(45, 750, 14, "RECEIVED RECORDS / SECOND (LAST 90 S)", MUTED);
        r.text(
            35,
            875,
            12,
            "GREYNOISE: RECEIVED RECORDS, NOT UNIQUE ATTACKS | RADAR: AGGREGATE SHARES | TIMES UTC",
            MUTED,
        );
        r.version_label();
        r.base = r.pix.clone();
        r
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
            last_ms: 0,
            list: Vec::new(),
            list_ms: 0,
            overlay_ms: 0,
            overlay_key: None,
            composed: Pixmap::new(crate::WIDTH, crate::HEIGHT).unwrap(),
            counts: (Vec::new(), [0; 3]),
        }
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
    /// Admit a few new arcs from the newest records (most severe first) and expire old ones.
    fn update_arcs(&mut self, s: &Snapshot) {
        let now = s.now_ms;
        let elapsed = now.saturating_sub(self.last_ms).min(5000) as f64;
        self.last_ms = now;
        self.tokens = (self.tokens + elapsed / 1000. * ARCS_PER_SECOND).min(ARCS_PER_SECOND * 1.5);
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
        fresh.sort_by_key(|r| r.record.class()); // stable: newest first within a class
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
            });
        }
        self.arcs
            .retain(|a| now.saturating_sub(a.born) < ARC_LIFE_MS && a.class < 3);
        while self.arcs.len() > MAX_ARCS {
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
        self.update_arcs(s);
        let now = s.now_ms;
        let selected = self.options.severities;
        let r = &mut self.renderer;

        // Radar aggregates: subtle informational outlines, never severity fills.
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
        );
        if now.saturating_sub(self.overlay_ms) >= OVERLAY_REFRESH_MS
            || self.overlay_key != Some(key)
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

            let mut rings = Vec::new();
            if let Some(data) = radar_data {
                let largest = data.largest();
                let mut outlines = Vec::new();
                for origin in data.origins() {
                    let share = if largest > 0. {
                        (origin.largest / largest).sqrt()
                    } else {
                        0.
                    } as f32;
                    match (
                        r.countries.index(&origin.code),
                        radar::small_place(&origin.code),
                    ) {
                        (Some(index), _) => {
                            outlines.push((index, 1.0 + 1.8 * share, (200. * radar_dim) as u8))
                        }
                        (None, Some((lon, lat))) => rings.push((xy(lon, lat), share)),
                        _ => {}
                    }
                }
                r.countries.outline(&mut r.country_overlay, &outlines, INFO);
            }
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
            for ((x, y), share) in rings {
                if let Some(path) = PathBuilder::from_circle(x, y, 3. + 7. * share) {
                    let mut p = Paint::default();
                    p.set_color_rgba8(INFO[0], INFO[1], INFO[2], (210. * radar_dim) as u8);
                    composed.stroke_path(
                        &path,
                        &p,
                        &Stroke {
                            width: 1.4,
                            ..Default::default()
                        },
                        Transform::identity(),
                        None,
                    );
                }
            }
            self.composed = composed;
        }
        r.pix.data_mut().copy_from_slice(self.composed.data());

        // Arcs: static curves that fade in over 1 s and out over the rest of their life.
        for arc in &self.arcs {
            let age = now.saturating_sub(arc.born);
            let alpha = if age < ARC_FADE_IN_MS {
                150. * age as f32 / ARC_FADE_IN_MS as f32
            } else {
                150. * (1. - (age - ARC_FADE_IN_MS) as f32 / (ARC_LIFE_MS - ARC_FADE_IN_MS) as f32)
            }
            .clamp(0., 150.) as u8;
            let (a, b, c) = (arc.a, arc.b, severity(arc.class));
            let cy = (a.1.min(b.1) - ((b.0 - a.0).abs() * 0.18).min(100.)).max(212.);
            let point = |t: f32| {
                let q = 1. - t;
                (
                    q * q * a.0 + 2. * q * t * (a.0 + b.0) / 2. + t * t * b.0,
                    q * q * a.1 + 2. * q * t * cy + t * t * b.1,
                )
            };
            let mut prev = a;
            for i in 1..25 {
                let p = point(i as f32 / 24.);
                r.line(prev.0, prev.1, p.0, p.1, c, 1.3, alpha);
                prev = p;
            }
            r.dot(b.0, b.1, 2.2, c, alpha);
        }

        // Header: clocks, sources, five summary boxes.
        let (utc, local) = crate::clock::labels(now);
        r.text(1044, 24, 18, &utc, [218, 236, 242]);
        r.text(1044, 50, 18, &local, [218, 236, 242]);
        let radar_label = match radar_state {
            Freshness::NoData => "NO DATA",
            Freshness::Empty => "EMPTY",
            Freshness::Current => "CURRENT",
            Freshness::Stale => "STALE",
        };
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
        let motion = if self.options.motion == Motion::Calm {
            "CALM"
        } else {
            "STILL"
        };
        for i in 0..5 {
            let x = 35 + i as i32 * 280;
            r.rect(x as f32, 112., 265., 70., [12, 28, 42], 255);
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

        // Right panel: latest selected records, refreshed every 2 s so the list does not scroll.
        if now.saturating_sub(self.list_ms) >= LIST_REFRESH_MS || self.list.is_empty() {
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
        r.text(1044, 560, 15, "CLOUDFLARE RADAR / TOP ROWS", INFO);
        match radar_data {
            Some(data) => {
                for (i, row) in data.rows.iter().take(8).enumerate() {
                    let y = 590 + i as i32 * 26;
                    let origin: String = row.origin_country_alpha2.trim().chars().take(8).collect();
                    let target: String = row
                        .target_country_alpha2
                        .as_deref()
                        .map_or("?".into(), |t| t.trim().chars().take(8).collect());
                    r.text(
                        1044,
                        y,
                        12,
                        &format!("{:>2}. {origin} -> {target}", i + 1),
                        TEXT,
                    );
                    let label: String = data.value_label(i).chars().take(16).collect();
                    r.text(1290, y, 12, &label, INFO);
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
            ("RADAR OUTLINE", INFO),
        ];
        for (i, (label, colour)) in legend.iter().enumerate() {
            let y = 772 + i as i32 * 19;
            r.rect(640., y as f32 + 3., 12., 10., *colour, 200);
            r.text(660, y, 12, label, TEXT);
        }
        r.text(820, 772, 11, "TINT: MOST FREQUENT", MUTED);
        r.text(820, 791, 11, "SELECTED CLASS, 5 MIN", MUTED);
        r.text(820, 810, 11, "ARCS: MAX 2/S, FADE 8 S", MUTED);
        r.text(820, 829, 11, "CLICK COUNTRY TO FOCUS", MUTED);
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
}
