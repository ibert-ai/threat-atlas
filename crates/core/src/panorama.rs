//! Wide layout for two side-by-side displays. The map keeps its proportions and runs across both
//! displays, with the seam on 30W: open Atlantic, crossing only northern Greenland. Panels stay
//! entirely on one display, so no text or panel is ever split.
use super::*;

/// Logical frame height, the same as the standard layout.
const FRAME_HEIGHT: u32 = 900;
const MARGIN: f32 = 25.;
const GAP: f32 = 20.;
/// Width of the observations column, matching the standard layout's panel.
const COLUMN: f32 = 390.;
const TOP: f32 = 25.;
const BOTTOM: f32 = 855.;
/// Longitude placed on the seam between the displays.
const SEAM_LON: f32 = -30.;
/// Latitudes kept on the map. The rest is empty polar area in this telemetry.
const NORTH: f32 = 84.;
const SOUTH: f32 = -60.;
/// Pixels per degree of the shared `xy` map coordinates.
const BASE_SCALE: f32 = 940. / 360.;
/// Displays narrower than 3:2 leave too little room beside the map.
const MIN_DISPLAY_ASPECT: f32 = 1.5;

/// Whether two matching side-by-side displays of this combined size suit the layout.
pub fn fits(width: u32, height: u32) -> bool {
    height > 0 && width as f32 / height as f32 / 2. >= MIN_DISPLAY_ASPECT
}

/// Placement of the map and panels for one frame size.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct View {
    pub width: u32,
    pub seam: f32,
    /// Map pixels per degree, equal on both axes so the map is never stretched.
    pub scale: f32,
    pub map_top: f32,
    /// Inner edge of the left column.
    pub left_end: f32,
    /// Start of the observations column.
    pub right_start: f32,
}

impl View {
    /// `width` and `height` are the physical window size; the frame matches its shape exactly.
    pub fn new(width: u32, height: u32) -> Self {
        let aspect = width as f32 / height.max(1) as f32;
        // An even width puts the seam on a pixel boundary between the displays.
        let width = ((FRAME_HEIGHT as f32 * aspect / 2.).round() as u32).max(1) * 2;
        let seam = width as f32 / 2.;
        let right_room = width as f32 - MARGIN - COLUMN - GAP - 15. - seam;
        let east = 180. - SEAM_LON;
        let scale = (right_room / east).min((BOTTOM - TOP - 30.) / (NORTH - SOUTH));
        let map_height = (NORTH - SOUTH) * scale;
        Self {
            width,
            seam,
            scale,
            map_top: (TOP + BOTTOM - map_height) / 2.,
            left_end: seam + (-180. - SEAM_LON) * scale - GAP - 15.,
            right_start: width as f32 - MARGIN - COLUMN,
        }
    }
    /// Longitude and latitude to frame pixels. Latitudes beyond the map stay on its edge.
    pub fn xy(&self, lon: f64, lat: f64) -> (f32, f32) {
        (
            self.seam + (lon as f32 - SEAM_LON) * self.scale,
            self.map_top + (NORTH - (lat as f32).clamp(SOUTH, NORTH)) * self.scale,
        )
    }
    fn map_origin(&self) -> (i32, i32) {
        let (x, y) = self.xy(-180., NORTH as f64);
        (x.floor() as i32, y.floor() as i32)
    }
    fn map_size(&self) -> (u32, u32) {
        (
            (360. * self.scale).ceil() as u32 + 1,
            ((NORTH - SOUTH) * self.scale).ceil() as u32 + 1,
        )
    }
    /// From shared `xy` coordinates to an image that starts at `map_origin`.
    fn map_transform(&self) -> Transform {
        let k = self.scale / BASE_SCALE;
        let (x, y) = super::xy(-180., NORTH as f64);
        let (tx, ty) = self.xy(-180., NORTH as f64);
        let (ox, oy) = self.map_origin();
        Transform::from_row(k, 0., 0., k, tx - ox as f32 - x * k, ty - oy as f32 - y * k)
    }
    /// Thickness in shared `xy` coordinates that draws as `width` pixels.
    fn thin(&self, width: f32) -> f32 {
        width * BASE_SCALE / self.scale
    }
}

impl Renderer {
    /// Renderer for two matching side-by-side displays with this combined physical size.
    pub fn new_panorama(width: u32, height: u32) -> Self {
        let view = View::new(width, height);
        let (map_width, map_height) = view.map_size();
        let mut r = Self::blank_sized(view.width, FRAME_HEIGHT);
        r.country_overlay = Pixmap::new(map_width, map_height).unwrap();
        r.panorama_base(&view);
        r.panorama = Some(view);
        r
    }
    fn panorama_base(&mut self, view: &View) {
        let right = view.right_start;
        self.pix.fill(Color::from_rgba8(5, 12, 21, 255));
        let map_left = view.left_end + GAP;
        for (x, y, w, h) in [
            (map_left, TOP, right - GAP - map_left, BOTTOM - TOP),
            (right, 205., COLUMN, 650.),
            (MARGIN, 475., view.left_end - MARGIN, 380.),
        ] {
            self.rect(x, y, w, h, [10, 23, 36], 255);
        }
        for lon in (-180..=180).step_by(30) {
            let (a, b) = view.xy(lon as f64, NORTH as f64);
            let (c, d) = view.xy(lon as f64, SOUTH as f64);
            self.line(a, b, c, d, [22, 43, 57], 1., 180);
        }
        for lat in (-60..=60).step_by(30) {
            let (a, b) = view.xy(-180., lat as f64);
            let (c, d) = view.xy(180., lat as f64);
            self.line(a, b, c, d, [22, 43, 57], 1., 180);
        }
        let (map_width, map_height) = view.map_size();
        let mut land = Pixmap::new(map_width, map_height).unwrap();
        Self::draw_land(&mut land, view.map_transform(), view.thin(0.7));
        let (x, y) = view.map_origin();
        self.pix.draw_pixmap(
            x,
            y,
            land.as_ref(),
            &PixmapPaint::default(),
            Transform::identity(),
            None,
        );
        self.text(35, 28, 30, "THREAT ATLAS", [223, 241, 249]);
        self.text(36, 70, 14, "SECURITY OPERATIONS / GLOBAL TELEMETRY", MUTED);
        let x = right as i32 + 19;
        self.text(x, 225, 17, "RECENT OBSERVATIONS", CYAN);
        self.text(45, 492, 14, "RECEIVED RECORDS / SECOND", MUTED);
        self.text(35, 875, 12, "GREYNOISE PUBLIC THREAT MAP | RECEIPT TIMES UTC | COUNTS ARE RECEIVED RECORDS, NOT UNIQUE ATTACKS", MUTED);
        let label = Self::version_text();
        self.text(x + 76, 875, 12, &label, MUTED);
        self.base = self.pix.clone();
    }
    pub(super) fn draw_panorama(&mut self, s: &Snapshot) -> &[u8] {
        let Some(view) = self.panorama else {
            return self.pix.data();
        };
        self.pix.data_mut().copy_from_slice(self.base.data());
        let classes = self.countries.classes(s);
        if classes != self.country_classes {
            self.countries.highlights_with(
                &mut self.country_overlay,
                &classes,
                view.map_transform(),
                view.thin(0.65),
            );
            self.country_classes = classes;
        }
        let (x, y) = view.map_origin();
        self.pix.draw_pixmap(
            x,
            y,
            self.country_overlay.as_ref(),
            &PixmapPaint::default(),
            Transform::identity(),
            None,
        );
        self.update_routes(s, |lon, lat| view.xy(lon, lat));
        self.draw_routes(s.now_ms, TOP + 7., 100. * view.scale / BASE_SCALE);

        let column = view.right_start as i32 + 19;
        let (utc, local) = crate::clock::labels(s.now_ms);
        self.text(column, 24, 18, &utc, [218, 236, 242]);
        self.text(column, 50, 18, &local, [218, 236, 242]);
        self.text(
            column,
            80,
            14,
            &format!("FEED / {}", s.status),
            if s.status == "LIVE" {
                color(2)
            } else {
                color(1)
            },
        );
        let cards = [
            ("RECORDS", s.records, CYAN),
            ("MALICIOUS", s.counts[0], color(0)),
            ("SUSPICIOUS", s.counts[1], color(1)),
            ("BENIGN", s.counts[2], color(2)),
            ("BATCHES", s.batches, CYAN),
            ("CHANGED PAYLOADS", s.changed_batches, CYAN),
        ];
        let width = (view.left_end - MARGIN - 15.) / 2.;
        for (i, (label, value, tint)) in cards.iter().enumerate() {
            let x = MARGIN + (i % 2) as f32 * (width + 15.);
            let y = 112. + (i / 2) as f32 * 118.;
            self.rect(x, y, width, 103., [12, 28, 42], 255);
            self.text(x as i32 + 12, y as i32 + 12, 12, label, MUTED);
            self.text(x as i32 + 12, y as i32 + 42, 32, &value.to_string(), *tint);
        }
        for (i, r) in s.recent.iter().take(9).enumerate() {
            let y = 265 + i as i32 * 56;
            let src: String = r.record.source.country.chars().take(19).collect();
            let dst: String = r.record.destination.country.chars().take(19).collect();
            self.text(column, y, 13, &format!("{src} > {dst}"), [203, 222, 235]);
            self.text(
                column,
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
            column,
            812,
            11,
            &format!(
                "SHA256 {}",
                s.last_digest.chars().take(25).collect::<String>()
            ),
            MUTED,
        );
        let max = *s.rate.iter().max().unwrap_or(&1);
        let step = (view.left_end - MARGIN - 40.) / s.rate.len().max(1) as f32;
        for (i, v) in s.rate.iter().enumerate() {
            let h = *v as f32 / max.max(1) as f32 * 300.;
            self.rect(
                45. + i as f32 * step,
                835. - h,
                (step * 0.67).max(1.),
                h.max(1.),
                CYAN,
                180,
            );
        }
        if s.status != "LIVE" {
            // Beside the seam, on the display with the larger part of the map.
            let x = view.seam + 120.;
            self.rect(x, 430., 600., 70., [5, 12, 21], 235);
            self.text(
                x as i32 + 20,
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

    const PAIRS: [(u32, u32); 4] = [(3840, 1080), (5120, 1440), (3840, 1200), (6880, 1440)];

    #[test]
    fn map_keeps_equal_axes_and_seam_stays_in_the_atlantic() {
        for (width, height) in PAIRS {
            let view = View::new(width, height);
            let (x, _) = view.xy(SEAM_LON as f64, 0.);
            assert_eq!(x, view.width as f32 / 2.);
            assert_eq!(view.width % 2, 0);
            let (a, b) = (view.xy(0., 0.), view.xy(30., 30.));
            assert!((((b.0 - a.0) - (b.1 - a.1).abs()) / (b.0 - a.0)).abs() < 1e-3);
            assert!(view.xy(-34.8, 0.).0 < view.seam, "Brazil stays on the left");
            assert!(
                view.xy(-17.5, 14.).0 > view.seam,
                "Africa stays on the right"
            );
        }
    }

    #[test]
    fn panels_never_cross_the_seam_and_map_fits_between_them() {
        for (width, height) in PAIRS {
            let view = View::new(width, height);
            assert!(view.left_end < view.seam && view.right_start > view.seam);
            assert!(view.left_end > 500., "left column too narrow: {view:?}");
            assert!(view.xy(-180., 0.).0 > view.left_end);
            assert!(view.xy(180., 0.).0 < view.right_start);
            assert!(view.xy(0., NORTH as f64).1 >= TOP);
            assert!(view.xy(0., SOUTH as f64).1 <= BOTTOM);
        }
    }

    #[test]
    fn fills_the_window_shape_without_stretching() {
        for (width, height) in PAIRS {
            let view = View::new(width, height);
            let frame = view.width as f32 / FRAME_HEIGHT as f32;
            let window = width as f32 / height as f32;
            assert!((frame - window).abs() / window < 0.002);
        }
    }

    #[test]
    fn narrow_display_pairs_do_not_fit() {
        assert!(fits(3840, 1080));
        assert!(!fits(2160, 1920));
        assert!(!fits(2048, 768));
    }

    #[test]
    fn expiring_routes_and_out_of_range_latitudes_stay_on_the_map() {
        use crate::feed::State;
        let mut r = Renderer::new_panorama(3840, 1080);
        assert_eq!(r.size(), (3200, 900));
        let mut state = State::default();
        let empty = r.draw(&state.snapshot(1000)).to_vec();
        state.ingest(r#"[{"source":{"latitude":-89,"longitude":4,"country":"AQ"},"destination":{"latitude":30,"longitude":-80,"country":"US"},"intention":"malicious"}]"#,1000);
        assert_ne!(empty, r.draw(&state.snapshot(2000)));
        let view = View::new(3840, 1080);
        assert!(r.routes[0].a.1 <= view.xy(0., SOUTH as f64).1);
        r.draw(&state.snapshot(8000));
        assert!(r.routes.is_empty());
    }
}
