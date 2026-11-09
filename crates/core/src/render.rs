use crate::{feed::Snapshot, HEIGHT, WIDTH};
use std::collections::{HashMap, VecDeque};
use tiny_skia::*;
/// Wide two-display layout; a child module so it shares the renderer's drawing helpers.
#[path = "panorama.rs"]
pub mod panorama;
/// Calm interactive SOC view; a child module so it shares the renderer's map and helpers.
#[path = "soc.rs"]
pub mod soc;
const CYAN: [u8; 3] = [68, 220, 225];
const MUTED: [u8; 3] = [100, 139, 159];
pub(crate) fn color(i: usize) -> [u8; 3] {
    match i {
        0 => [255, 93, 115],
        1 => [255, 190, 82],
        2 => [76, 215, 163],
        _ => [116, 151, 189],
    }
}
pub(crate) fn xy(lon: f64, lat: f64) -> (f32, f32) {
    (
        45. + ((lon + 180.) / 360.) as f32 * 940.,
        230. + ((90. - lat) / 180.) as f32 * 470.,
    )
}
struct Route {
    a: (f32, f32),
    b: (f32, f32),
    time: u64,
    class: usize,
}
pub struct Renderer {
    pix: Pixmap,
    base: Pixmap,
    font: fontdue::Font,
    glyphs: HashMap<(char, u16), (fontdue::Metrics, Vec<u8>)>,
    routes: VecDeque<Route>,
    last: u64,
    countries: crate::countries::CountryMap,
    country_classes: Vec<Option<usize>>,
    country_overlay: Pixmap,
    panorama: Option<panorama::View>,
    /// Wide SOC frame (macOS window wider than 16:10): extra pixels inserted at `WIDE_SPLIT`.
    /// Everything drawn at x >= WIDE_SPLIT moves right by this amount unless `wide_raw` is set.
    /// Zero for the screensaver and the standard 1440x900 SOC frame, which stay unchanged.
    pub(crate) wide_dx: f32,
    pub(crate) wide_raw: bool,
}
/// Column boundary between the map and the right-hand panels in the 1440x900 layout.
pub(crate) const WIDE_SPLIT: f32 = 1015.;
impl Default for Renderer {
    fn default() -> Self {
        Self::new()
    }
}
pub(crate) fn release_label(release: &str) -> String {
    let release: serde_json::Value = serde_json::from_str(release).unwrap_or_default();
    let version = release["version"]
        .as_str()
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    let suffix = release["prerelease"]
        .as_str()
        .map(|value| format!("-{value}"))
        .unwrap_or_default();
    let build = release["build"]
        .as_u64()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".into());
    format!("v{version}{suffix} | b{build}")
}
impl Renderer {
    pub fn new() -> Self {
        let mut r = Self::blank();
        r.base_map();
        r.text(35, 28, 30, "THREAT ATLAS", [223, 241, 249]);
        r.text(36, 70, 14, "SECURITY OPERATIONS / GLOBAL TELEMETRY", MUTED);
        r.text(1044, 225, 17, "RECENT OBSERVATIONS", CYAN);
        r.text(45, 750, 14, "RECEIVED RECORDS / SECOND", MUTED);
        r.text(35,875,12,"GREYNOISE PUBLIC THREAT MAP | RECEIPT TIMES UTC | COUNTS ARE RECEIVED RECORDS, NOT UNIQUE ATTACKS",MUTED);
        r.version_label();
        r.base = r.pix.clone();
        r
    }
    /// Standalone SOC view: the same map, panels and font, labelled for Cloudflare Radar aggregates.
    pub fn new_radar() -> Self {
        let mut r = Self::blank();
        r.base_map();
        r.text(35, 28, 30, "THREAT ATLAS", [223, 241, 249]);
        r.text(
            36,
            70,
            14,
            "SECURITY OPERATIONS / CLOUDFLARE RADAR AGGREGATES",
            MUTED,
        );
        r.text(1044, 225, 17, "TOP ROWS / ORIGIN -> TARGET", CYAN);
        r.text(45, 750, 14, "PROVIDER WINDOW / FRESHNESS", MUTED);
        r.text(35,875,12,"CLOUDFLARE RADAR | LAYER 3 TOP ATTACKS | AGGREGATE SHARES, NOT INDIVIDUAL ATTACKS | NO ROUTES DRAWN",MUTED);
        r.desktop_version_label();
        r.base = r.pix.clone();
        r
    }
    fn blank() -> Self {
        Self::blank_sized(WIDTH, HEIGHT)
    }
    fn blank_sized(width: u32, height: u32) -> Self {
        let pix = Pixmap::new(width, height).unwrap();
        let base = pix.clone();
        let font = fontdue::Font::from_bytes(
            include_bytes!("../../../assets/mono.ttf") as &[u8],
            fontdue::FontSettings::default(),
        )
        .unwrap();
        Self {
            pix,
            base,
            font,
            glyphs: HashMap::new(),
            routes: VecDeque::new(),
            last: 0,
            countries: crate::countries::CountryMap::new(),
            country_classes: Vec::new(),
            country_overlay: Pixmap::new(width, height).unwrap(),
            panorama: None,
            wide_dx: 0.,
            wide_raw: false,
        }
    }
    /// Frame x for a layout x: right-hand column shifted in a wide SOC frame.
    pub(crate) fn wx(&self, x: f32) -> f32 {
        if !self.wide_raw && self.wide_dx > 0. && x >= WIDE_SPLIT {
            x + self.wide_dx
        } else {
            x
        }
    }
    /// Resize the frame for the wide SOC layout (height stays 900); callers repaint the base.
    pub(crate) fn resize_wide(&mut self, width: u32) {
        let width = width.max(WIDTH);
        self.pix = Pixmap::new(width, HEIGHT).unwrap();
        self.base = self.pix.clone();
        self.country_overlay = Pixmap::new(width, HEIGHT).unwrap();
        self.wide_dx = (width - WIDTH) as f32;
    }
    /// Frame size in pixels; `WIDTH` x `HEIGHT` except in the panorama layout.
    pub fn size(&self) -> (u32, u32) {
        (self.pix.width(), self.pix.height())
    }
    fn version_label(&mut self) {
        self.draw_release_label(include_str!("../../../version.json"));
    }
    /// The Desktop app has its own identity, independent of the screensaver's version.json.
    fn desktop_version_label(&mut self) {
        self.draw_release_label(include_str!("../../../atlassoc-beta-version.json"));
    }
    fn draw_release_label(&mut self, release: &str) {
        self.text(1120, 875, 12, &release_label(release), MUTED);
    }
    /// Background, panels, graticule and land shared by the screensaver and the standalone SOC view.
    fn base_map(&mut self) {
        self.pix.fill(Color::from_rgba8(5, 12, 21, 255));
        for (x, y, w, h) in [
            (25., 205., 980., 510.),
            (1025., 205., 390., 650.),
            (25., 735., 980., 120.),
        ] {
            self.rect(x, y, w, h, [10, 23, 36], 255);
        }
        for lon in (-180..=180).step_by(30) {
            let (a, b) = xy(lon as f64, 90.);
            let (c, d) = xy(lon as f64, -90.);
            self.line(a, b, c, d, [22, 43, 57], 1., 180);
        }
        for lat in (-90..=90).step_by(30) {
            let (a, b) = xy(-180., lat as f64);
            let (c, d) = xy(180., lat as f64);
            self.line(a, b, c, d, [22, 43, 57], 1., 180);
        }
        Self::draw_land(&mut self.pix, Transform::identity(), 0.7);
    }
    /// Bundled land polygons, transformed from `xy` coordinates into `target`.
    fn draw_land(target: &mut Pixmap, transform: Transform, outline: f32) {
        let land: serde_json::Value =
            serde_json::from_str(include_str!("../../../assets/land.json")).unwrap();
        for feature in land["features"].as_array().unwrap() {
            let g = &feature["geometry"];
            let polys = if g["type"] == "Polygon" {
                vec![g["coordinates"].clone()]
            } else {
                g["coordinates"].as_array().unwrap().clone()
            };
            for poly in polys {
                for ring in poly.as_array().unwrap() {
                    let mut pb = PathBuilder::new();
                    let mut first = true;
                    for point in ring.as_array().unwrap() {
                        let (x, y) = xy(point[0].as_f64().unwrap(), point[1].as_f64().unwrap());
                        if first {
                            pb.move_to(x, y);
                            first = false
                        } else {
                            pb.line_to(x, y)
                        }
                    }
                    pb.close();
                    if let Some(path) = pb.finish() {
                        let mut paint = Paint::default();
                        paint.set_color_rgba8(22, 49, 63, 255);
                        target.fill_path(&path, &paint, FillRule::EvenOdd, transform, None);
                        paint.set_color_rgba8(48, 90, 106, 220);
                        target.stroke_path(
                            &path,
                            &paint,
                            &Stroke {
                                width: outline,
                                ..Default::default()
                            },
                            transform,
                            None,
                        );
                    }
                }
            }
        }
    }
    /// Standalone SOC frame for Cloudflare Radar aggregates: whole countries shaded by each
    /// origin's largest provider row, small places as rings, ranked rows listed as supplied.
    /// No routes, events or summed totals; stale snapshots are dimmed and labelled.
    pub fn draw_radar(
        &mut self,
        data: Option<&crate::radar::Aggregate>,
        received_ms: u64,
        now_ms: u64,
    ) -> &[u8] {
        use crate::radar::{freshness, small_place, Freshness};
        const AMBER: [u8; 3] = [255, 190, 82];
        self.pix.data_mut().copy_from_slice(self.base.data());
        let state = freshness(data, received_ms, now_ms);
        let dim = if state == Freshness::Stale { 0.5 } else { 1. };
        let largest = data.map_or(0., |d| d.largest());
        let share = |value: f64| {
            if largest > 0. {
                (value / largest).sqrt()
            } else {
                0.
            }
        };
        let origins = data.map(|d| d.origins()).unwrap_or_default();
        let mut shades = Vec::new();
        let mut rings = Vec::new();
        let mut unplaced = Vec::new();
        for origin in &origins {
            let alpha = ((40. + 130. * share(origin.largest)) * dim) as u8;
            match (
                self.countries.index(&origin.code),
                small_place(&origin.code),
            ) {
                (Some(index), _) => shades.push((index, alpha)),
                (None, Some((lon, lat))) => {
                    rings.push((xy(lon, lat), share(origin.largest), alpha))
                }
                (None, None) => unplaced.push(origin.code.chars().take(8).collect::<String>()),
            }
        }
        self.countries
            .shade(&mut self.country_overlay, &shades, AMBER);
        self.pix.draw_pixmap(
            0,
            0,
            self.country_overlay.as_ref(),
            &PixmapPaint::default(),
            Transform::identity(),
            None,
        );
        for ((x, y), share, alpha) in rings {
            let r = 3. + 9. * share as f32;
            self.dot(x, y, r, AMBER, alpha);
            if let Some(path) = PathBuilder::from_circle(x, y, r) {
                let mut p = Paint::default();
                p.set_color_rgba8(AMBER[0], AMBER[1], AMBER[2], (230. * dim) as u8);
                self.pix.stroke_path(
                    &path,
                    &p,
                    &Stroke {
                        width: 1.2,
                        ..Default::default()
                    },
                    Transform::identity(),
                    None,
                );
            }
        }
        let (utc, local) = crate::clock::labels(now_ms);
        self.text(1044, 24, 18, &utc, [218, 236, 242]);
        self.text(1044, 50, 18, &local, [218, 236, 242]);
        let (status, status_color) = match state {
            Freshness::NoData => ("NO DATA", MUTED),
            Freshness::Empty => ("EMPTY RESPONSE", MUTED),
            Freshness::Current => ("CURRENT SNAPSHOT", color(2)),
            Freshness::Stale => ("STALE SNAPSHOT", AMBER),
        };
        self.text(
            1044,
            80,
            14,
            &format!("CLOUDFLARE / {status}"),
            status_color,
        );
        let received = i64::try_from(received_ms)
            .ok()
            .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
            .filter(|_| data.is_some())
            .map_or("-".into(), |t| t.format("%H:%M UTC").to_string());
        let boxes = [
            (
                "ROWS",
                data.map_or("-".into(), |d| d.rows.len().to_string()),
            ),
            (
                "ORIGINS",
                data.map_or("-".into(), |_| origins.len().to_string()),
            ),
            (
                "NORMALIZATION",
                data.map_or("-".into(), |d| d.normalization.clone()),
            ),
            (
                "PROVIDER UPDATED",
                data.map_or("-".into(), |d| d.last_updated.clone()),
            ),
            ("RECEIVED", received),
        ];
        for (i, (label, value)) in boxes.iter().enumerate() {
            let x = 35 + i as i32 * 280;
            self.rect(x as f32, 112., 265., 70., [12, 28, 42], 255);
            self.text(x + 12, 119, 12, label, MUTED);
            let value: String = value.chars().take(22).collect();
            self.text(
                x + 12,
                145,
                17,
                &value,
                if i < 2 { CYAN } else { [203, 222, 235] },
            );
        }
        if let Some(data) = data {
            for (i, (row, &value)) in data.rows.iter().zip(&data.values).take(20).enumerate() {
                let y = 258 + i as i32 * 29;
                let origin: String = row.origin_country_alpha2.trim().chars().take(8).collect();
                let target: String = row
                    .target_country_alpha2
                    .as_deref()
                    .map_or("target not supplied".into(), |t| {
                        t.trim().chars().take(8).collect()
                    });
                self.text(
                    1044,
                    y,
                    13,
                    &format!("{:>2}. {origin} -> {target}", i + 1),
                    [203, 222, 235],
                );
                let label: String = data.value_label(i).chars().take(16).collect();
                self.text(1300, y, 13, &label, AMBER);
                let width = if largest > 0. {
                    (340. * value / largest) as f32
                } else {
                    0.
                };
                self.rect(1044., (y + 18) as f32, width, 3., AMBER, (180. * dim) as u8);
            }
            if let Some(window) = data.windows.first() {
                let line = format!("WINDOW {} - {}", window.start_time, window.end_time);
                self.text(45, 778, 13, &line, [203, 222, 235]);
            }
            let line = format!(
                "EACH VALUE IS ONE ROW'S SHARE OF ALL LAYER 3 ATTACKS | ROWS NOT SUMMED | {status}"
            );
            self.text(45, 802, 13, &line, status_color);
            if !unplaced.is_empty() {
                self.text(
                    45,
                    826,
                    13,
                    &format!("NOT ON MAP: {}", unplaced.join(", ")),
                    MUTED,
                );
            }
        } else {
            self.text(
                270,
                450,
                16,
                "NO CLOUDFLARE DATA RECEIVED | NO SAMPLE TELEMETRY SHOWN",
                MUTED,
            );
        }
        if state == Freshness::Empty {
            self.text(330, 450, 16, "PROVIDER RETURNED NO COUNTRY ROWS", MUTED);
        }
        self.pix.data()
    }
    fn rect(&mut self, x: f32, y: f32, w: f32, h: f32, c: [u8; 3], a: u8) {
        let x = self.wx(x);
        let mut p = Paint::default();
        p.set_color_rgba8(c[0], c[1], c[2], a);
        if let Some(rect) = Rect::from_xywh(x, y, w, h) {
            self.pix.fill_rect(rect, &p, Transform::identity(), None);
        }
    }
    #[allow(clippy::too_many_arguments)] // Explicit coordinates keep drawing call sites readable.
    fn line(&mut self, x: f32, y: f32, xx: f32, yy: f32, c: [u8; 3], w: f32, a: u8) {
        let (x, xx) = (self.wx(x), self.wx(xx));
        let mut b = PathBuilder::new();
        b.move_to(x, y);
        b.line_to(xx, yy);
        if let Some(path) = b.finish() {
            let mut p = Paint::default();
            p.set_color_rgba8(c[0], c[1], c[2], a);
            self.pix.stroke_path(
                &path,
                &p,
                &Stroke {
                    width: w,
                    ..Default::default()
                },
                Transform::identity(),
                None,
            );
        }
    }
    fn dot(&mut self, x: f32, y: f32, r: f32, c: [u8; 3], a: u8) {
        let x = self.wx(x);
        if let Some(path) = PathBuilder::from_circle(x, y, r) {
            let mut p = Paint::default();
            p.set_color_rgba8(c[0], c[1], c[2], a);
            self.pix
                .fill_path(&path, &p, FillRule::Winding, Transform::identity(), None);
        }
    }
    fn text(&mut self, x: i32, y: i32, size: u16, text: &str, c: [u8; 3]) {
        let mut pen = self.wx(x as f32) as i32;
        let (width, height) = self.size();
        // A network peer must not grow the glyph cache with arbitrary Unicode.
        // Limit work to visible text; unsupported/control characters render as '?'.
        for ch in text.chars().take(160) {
            let ch = if ch.is_ascii_graphic() || ch == ' ' {
                ch
            } else {
                '?'
            };
            let (m, b) = self
                .glyphs
                .entry((ch, size))
                .or_insert_with(|| self.font.rasterize(ch, size as f32));
            for yy in 0..m.height {
                for xx in 0..m.width {
                    let px = pen + m.xmin + xx as i32;
                    let py = y + size as i32 - m.ymin - m.height as i32 + yy as i32;
                    if px >= 0 && py >= 0 && px < width as i32 && py < height as i32 {
                        let a = b[yy * m.width + xx] as u32;
                        let i = (py as usize * width as usize + px as usize) * 4;
                        let data = self.pix.data_mut();
                        for k in 0..3 {
                            data[i + k] =
                                ((c[k] as u32 * a + data[i + k] as u32 * (255 - a)) / 255) as u8;
                        }
                    }
                }
            }
            pen += m.advance_width.round() as i32;
        }
    }
    /// Take a bounded sample of new records as routes and expire routes older than six seconds.
    fn update_routes(&mut self, s: &Snapshot, project: impl Fn(f64, f64) -> (f32, f32)) {
        let fresh: Vec<_> = s
            .recent
            .iter()
            .filter(|r| r.sequence > self.last && s.now_ms.saturating_sub(r.received_ms) < 6000)
            .collect();
        for r in fresh.iter().step_by((fresh.len() / 8).max(1)).take(10) {
            self.routes.push_back(Route {
                a: project(r.record.source.longitude, r.record.source.latitude),
                b: project(
                    r.record.destination.longitude,
                    r.record.destination.latitude,
                ),
                time: r.received_ms,
                class: r.record.class(),
            });
        }
        self.last = s.records;
        self.routes
            .retain(|r| s.now_ms.saturating_sub(r.time) < 6000);
        while self.routes.len() > 240 {
            self.routes.pop_front();
        }
    }
    /// Animated arcs, kept below `top` and raised by at most `lift` pixels.
    fn draw_routes(&mut self, now_ms: u64, top: f32, lift: f32) {
        let routes: Vec<_> = self
            .routes
            .iter()
            .map(|r| (r.a, r.b, r.time, r.class))
            .collect();
        for (a, b, t, class) in routes {
            let age = now_ms.saturating_sub(t) as f32 / 6000.;
            let c = color(class);
            let alpha = ((1. - age) * 160.) as u8;
            let cy = (a.1.min(b.1) - ((b.0 - a.0).abs() * 0.18).min(lift)).max(top);
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
                self.line(prev.0, prev.1, p.0, p.1, c, 1., alpha);
                prev = p;
            }
            let p = point((age * 3.).fract());
            self.dot(p.0, p.1, 3., c, 240);
            self.dot(b.0, b.1, 2., c, alpha);
        }
    }
    pub fn draw(&mut self, s: &Snapshot) -> &[u8] {
        if self.panorama.is_some() {
            return self.draw_panorama(s);
        }
        self.pix.data_mut().copy_from_slice(self.base.data());
        let classes = self.countries.classes(s);
        if classes != self.country_classes {
            self.countries
                .highlights(&mut self.country_overlay, &classes);
            self.country_classes = classes;
        }
        self.pix.draw_pixmap(
            0,
            0,
            self.country_overlay.as_ref(),
            &PixmapPaint::default(),
            Transform::identity(),
            None,
        );
        self.update_routes(s, xy);
        self.draw_routes(s.now_ms, 212., 100.);
        let (utc, local) = crate::clock::labels(s.now_ms);
        self.text(1044, 24, 18, &utc, [218, 236, 242]);
        self.text(1044, 50, 18, &local, [218, 236, 242]);
        self.text(
            1044,
            80,
            14,
            &format!("FEED / {}", s.status),
            if s.status == "LIVE" {
                color(2)
            } else {
                color(1)
            },
        );
        for (i, (label, value)) in [
            ("RECORDS", s.records),
            ("MALICIOUS", s.counts[0]),
            ("SUSPICIOUS", s.counts[1]),
            ("BENIGN", s.counts[2]),
            ("BATCHES", s.batches),
        ]
        .iter()
        .enumerate()
        {
            let x = 35 + i as i32 * 280;
            self.rect(x as f32, 112., 265., 70., [12, 28, 42], 255);
            self.text(x + 12, 119, 12, label, MUTED);
            self.text(
                x + 12,
                142,
                25,
                &value.to_string(),
                if i > 0 && i < 4 { color(i - 1) } else { CYAN },
            );
        }
        for (i, r) in s.recent.iter().take(9).enumerate() {
            let y = 265 + i as i32 * 56;
            let src: String = r.record.source.country.chars().take(19).collect();
            let dst: String = r.record.destination.country.chars().take(19).collect();
            self.text(1044, y, 13, &format!("{} > {}", src, dst), [203, 222, 235]);
            self.text(
                1044,
                y + 19,
                11,
                &format!(
                    "{} / {} / spoofable:{}",
                    r.sequence, r.record.intention, r.record.spoofable
                ),
                color(r.record.class()),
            );
        }
        self.text(
            1044,
            787,
            12,
            &format!("CHANGED PAYLOADS {}", s.changed_batches),
            CYAN,
        );
        self.text(
            1044,
            812,
            11,
            &format!(
                "SHA256 {}",
                s.last_digest.chars().take(25).collect::<String>()
            ),
            MUTED,
        );
        let max = *s.rate.iter().max().unwrap_or(&1);
        for (i, v) in s.rate.iter().enumerate() {
            let h = *v as f32 / max.max(1) as f32 * 55.;
            self.rect(45. + i as f32 * 10.4, 835. - h, 7., h.max(1.), CYAN, 180);
        }
        if s.status != "LIVE" {
            self.rect(210., 430., 600., 70., [5, 12, 21], 235);
            self.text(
                230,
                450,
                18,
                &format!("{} / waiting for fresh telemetry", s.status),
                color(1),
            );
        }
        self.pix.data()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::State;
    #[test]
    fn untrusted_text_has_bounded_glyph_cache() {
        let mut renderer = Renderer::new();
        let initial = renderer.glyphs.len();
        let text: String = (0x1000..0x2000).filter_map(char::from_u32).collect();
        renderer.text(0, 0, 13, &text, CYAN);
        assert!(renderer.glyphs.len() <= initial + 1);
    }
    #[test]
    fn empty_and_expiring_routes() {
        let mut r = Renderer::new();
        let mut state = State::default();
        let a = r.draw(&state.snapshot(1000)).to_vec();
        state.ingest(r#"[{"source":{"latitude":50,"longitude":4,"country":"NL"},"destination":{"latitude":30,"longitude":80,"country":"IN"},"intention":"malicious"}]"#,1000);
        let b = r.draw(&state.snapshot(2000)).to_vec();
        assert_ne!(a, b);
        assert_eq!(r.routes.len(), 1);
        r.draw(&state.snapshot(8000));
        assert!(r.routes.is_empty());
    }
}
