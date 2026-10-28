use crate::{feed::Snapshot, HEIGHT, WIDTH};
use std::collections::{HashMap, VecDeque};
use tiny_skia::*;
const CYAN: [u8; 3] = [68, 220, 225];
const MUTED: [u8; 3] = [100, 139, 159];
fn color(i: usize) -> [u8; 3] {
    match i {
        0 => [255, 93, 115],
        1 => [255, 190, 82],
        2 => [76, 215, 163],
        _ => [116, 151, 189],
    }
}
fn xy(lon: f64, lat: f64) -> (f32, f32) {
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
}
impl Default for Renderer {
    fn default() -> Self {
        Self::new()
    }
}
impl Renderer {
    pub fn new() -> Self {
        let pix = Pixmap::new(WIDTH, HEIGHT).unwrap();
        let base = pix.clone();
        let font = fontdue::Font::from_bytes(
            include_bytes!("../../../assets/mono.ttf") as &[u8],
            fontdue::FontSettings::default(),
        )
        .unwrap();
        let mut r = Self {
            pix,
            base,
            font,
            glyphs: HashMap::new(),
            routes: VecDeque::new(),
            last: 0,
        };
        r.pix.fill(Color::from_rgba8(5, 12, 21, 255));
        for (x, y, w, h) in [
            (25., 205., 980., 510.),
            (1025., 205., 390., 650.),
            (25., 735., 980., 120.),
        ] {
            r.rect(x, y, w, h, [10, 23, 36], 255);
        }
        for lon in (-180..=180).step_by(30) {
            let (a, b) = xy(lon as f64, 90.);
            let (c, d) = xy(lon as f64, -90.);
            r.line(a, b, c, d, [22, 43, 57], 1., 180);
        }
        for lat in (-90..=90).step_by(30) {
            let (a, b) = xy(-180., lat as f64);
            let (c, d) = xy(180., lat as f64);
            r.line(a, b, c, d, [22, 43, 57], 1., 180);
        }
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
                        r.pix.fill_path(
                            &path,
                            &paint,
                            FillRule::EvenOdd,
                            Transform::identity(),
                            None,
                        );
                        paint.set_color_rgba8(48, 90, 106, 220);
                        r.pix.stroke_path(
                            &path,
                            &paint,
                            &Stroke {
                                width: 0.7,
                                ..Default::default()
                            },
                            Transform::identity(),
                            None,
                        );
                    }
                }
            }
        }
        r.text(35, 28, 30, "THREAT ATLAS", [223, 241, 249]);
        r.text(36, 70, 14, "SECURITY OPERATIONS / GLOBAL TELEMETRY", MUTED);
        r.text(1044, 225, 17, "RECENT OBSERVATIONS", CYAN);
        r.text(45, 750, 14, "RECEIVED RECORDS / SECOND", MUTED);
        r.text(35,875,12,"GREYNOISE PUBLIC THREAT MAP | RECEIPT TIMES UTC | COUNTS ARE RECEIVED RECORDS, NOT UNIQUE ATTACKS",MUTED);
        r.base = r.pix.clone();
        r
    }
    fn rect(&mut self, x: f32, y: f32, w: f32, h: f32, c: [u8; 3], a: u8) {
        let mut p = Paint::default();
        p.set_color_rgba8(c[0], c[1], c[2], a);
        if let Some(rect) = Rect::from_xywh(x, y, w, h) {
            self.pix.fill_rect(rect, &p, Transform::identity(), None);
        }
    }
    #[allow(clippy::too_many_arguments)] // Explicit coordinates keep drawing call sites readable.
    fn line(&mut self, x: f32, y: f32, xx: f32, yy: f32, c: [u8; 3], w: f32, a: u8) {
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
        if let Some(path) = PathBuilder::from_circle(x, y, r) {
            let mut p = Paint::default();
            p.set_color_rgba8(c[0], c[1], c[2], a);
            self.pix
                .fill_path(&path, &p, FillRule::Winding, Transform::identity(), None);
        }
    }
    fn text(&mut self, x: i32, y: i32, size: u16, text: &str, c: [u8; 3]) {
        let mut pen = x;
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
                    if px >= 0 && py >= 0 && px < WIDTH as i32 && py < HEIGHT as i32 {
                        let a = b[yy * m.width + xx] as u32;
                        let i = (py as usize * WIDTH as usize + px as usize) * 4;
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
    pub fn draw(&mut self, s: &Snapshot) -> &[u8] {
        self.pix.data_mut().copy_from_slice(self.base.data());
        let fresh: Vec<_> = s
            .recent
            .iter()
            .filter(|r| r.sequence > self.last && s.now_ms.saturating_sub(r.received_ms) < 6000)
            .collect();
        for r in fresh.iter().step_by((fresh.len() / 8).max(1)).take(10) {
            self.routes.push_back(Route {
                a: xy(r.record.source.longitude, r.record.source.latitude),
                b: xy(
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
        let routes: Vec<_> = self
            .routes
            .iter()
            .map(|r| (r.a, r.b, r.time, r.class))
            .collect();
        for (a, b, t, class) in routes {
            let age = s.now_ms.saturating_sub(t) as f32 / 6000.;
            let c = color(class);
            let alpha = ((1. - age) * 160.) as u8;
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
                self.line(prev.0, prev.1, p.0, p.1, c, 1., alpha);
                prev = p;
            }
            let p = point((age * 3.).fract());
            self.dot(p.0, p.1, 3., c, 240);
            self.dot(b.0, b.1, 2., c, alpha);
        }
        let sec = s.now_ms / 1000;
        self.text(
            1050,
            36,
            22,
            &format!(
                "{:02}:{:02}:{:02} UTC",
                sec / 3600 % 24,
                sec / 60 % 60,
                sec % 60
            ),
            [218, 236, 242],
        );
        self.text(
            1050,
            75,
            16,
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
