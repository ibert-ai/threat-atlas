//! Cached country polygons and telemetry-driven country highlights.
use crate::feed::{Record, Snapshot};
use serde::Deserialize;
use std::collections::{HashMap, VecDeque};
use std::sync::OnceLock;
use tiny_skia::{FillRule, Paint, Path, PathBuilder, Pixmap, Stroke, Transform};

pub const HIGHLIGHT_MS: u64 = 6000;
#[derive(Deserialize)]
struct Geometry {
    aliases: Vec<String>,
    polygons: Vec<Vec<Vec<[f64; 2]>>>,
}
pub struct CountryMap {
    paths: Vec<Vec<Path>>,
    aliases: HashMap<String, usize>,
    /// Raw lon/lat polygons (outer ring first) for hit testing, plus display code and name.
    rings: Vec<Vec<Vec<Vec<[f64; 2]>>>>,
    labels: Vec<(String, String)>,
    /// Label point per country: area centroid of its largest landmass (lon, lat).
    anchors: Vec<Option<(f64, f64)>>,
}
fn key(name: &str) -> String {
    name.trim().to_lowercase()
}
fn country_aliases() -> &'static HashMap<String, usize> {
    static ALIASES: OnceLock<HashMap<String, usize>> = OnceLock::new();
    ALIASES.get_or_init(|| CountryMap::new().aliases)
}
/// At most three receipt timestamps per bundled country, independent of traffic volume.
#[derive(Default)]
pub struct Activity {
    last_seen: HashMap<usize, [Option<u64>; 3]>,
}
impl Activity {
    pub fn record(&mut self, record: &Record, received_ms: u64) {
        let class = record.class();
        if class > 2 {
            return;
        }
        for location in [&record.source, &record.destination] {
            if let Some(&country) = country_aliases().get(&key(&location.country)) {
                let times = self.last_seen.entry(country).or_insert([None; 3]);
                times[class] = Some(times[class].map_or(received_ms, |last| last.max(received_ms)));
            }
        }
    }
    pub fn snapshot(&self) -> Vec<(usize, [Option<u64>; 3])> {
        let mut entries: Vec<_> = self
            .last_seen
            .iter()
            .map(|(&id, &times)| (id, times))
            .collect();
        entries.sort_by_key(|entry| entry.0);
        entries
    }
}
/// Minutes of per-country severity counts kept for the SOC view's calm summaries.
pub const COUNT_MINUTES: u64 = 5;
const TOTAL: usize = usize::MAX;
/// Per-minute malicious/suspicious/benign receipt counts for each bundled country (as source or
/// destination, once per record) and overall. Bounded: at most COUNT_MINUTES buckets per country.
#[derive(Default)]
pub struct Counts {
    minutes: HashMap<usize, VecDeque<(u64, [u64; 3])>>,
}
impl Counts {
    pub fn record(&mut self, record: &Record, received_ms: u64) {
        let class = record.class();
        if class > 2 {
            return;
        }
        let minute = received_ms / 60_000;
        let mut keys = vec![TOTAL];
        for location in [&record.source, &record.destination] {
            if let Some(&country) = country_aliases().get(&key(&location.country)) {
                if !keys.contains(&country) {
                    keys.push(country);
                }
            }
        }
        for k in keys {
            let buckets = self.minutes.entry(k).or_default();
            match buckets.back_mut() {
                Some(last) if last.0 == minute => last.1[class] += 1,
                _ => {
                    let mut counts = [0; 3];
                    counts[class] = 1;
                    buckets.push_back((minute, counts));
                }
            }
            while buckets
                .front()
                .is_some_and(|b| b.0 + COUNT_MINUTES <= minute)
            {
                buckets.pop_front();
            }
        }
    }
    /// Counts inside the last COUNT_MINUTES minutes: per country (sorted by index) and overall.
    pub fn summary(&self, now_ms: u64) -> (Vec<(usize, [u64; 3])>, [u64; 3]) {
        let now = now_ms / 60_000;
        let sum = |buckets: &VecDeque<(u64, [u64; 3])>| {
            let mut total = [0; 3];
            for (minute, counts) in buckets {
                if *minute <= now && minute + COUNT_MINUTES > now {
                    for class in 0..3 {
                        total[class] += counts[class];
                    }
                }
            }
            total
        };
        let mut countries: Vec<_> = self
            .minutes
            .iter()
            .filter(|(&k, _)| k != TOTAL)
            .map(|(&k, buckets)| (k, sum(buckets)))
            .filter(|(_, c)| c.iter().any(|&n| n > 0))
            .collect();
        countries.sort_by_key(|entry| entry.0);
        let total = self.minutes.get(&TOTAL).map_or([0; 3], sum);
        (countries, total)
    }
}
/// Area-weighted centroid of the outer ring of the largest polygon (shoelace formula).
fn anchor(polygons: &[Vec<Vec<[f64; 2]>>]) -> Option<(f64, f64)> {
    let area_centroid = |ring: &[[f64; 2]]| {
        let (mut area, mut cx, mut cy) = (0., 0., 0.);
        for i in 0..ring.len() {
            let ([x0, y0], [x1, y1]) = (ring[i], ring[(i + 1) % ring.len()]);
            let cross = x0 * y1 - x1 * y0;
            area += cross;
            cx += (x0 + x1) * cross;
            cy += (y0 + y1) * cross;
        }
        (area.abs() / 2., cx / (3. * area), cy / (3. * area))
    };
    let (_, ring, (x, y)) = polygons
        .iter()
        .filter_map(|polygon| polygon.first())
        .filter(|ring| ring.len() >= 3)
        .map(|ring| (area_centroid(ring), ring))
        .filter(|((area, x, y), _)| *area > 0. && x.is_finite() && y.is_finite())
        .map(|((area, x, y), ring)| (area, ring, (x, y)))
        .max_by(|a, b| a.0.total_cmp(&b.0))?;
    if contains(ring, x, y) {
        return Some((x, y));
    }
    // Concave shapes (e.g. Norway): use the middle of the widest inside span at that latitude.
    let mut crossings: Vec<f64> = (0..ring.len())
        .filter_map(|i| {
            let ([x0, y0], [x1, y1]) = (ring[i], ring[(i + 1) % ring.len()]);
            ((y0 > y) != (y1 > y)).then(|| x0 + (y - y0) * (x1 - x0) / (y1 - y0))
        })
        .collect();
    crossings.sort_by(f64::total_cmp);
    crossings
        .as_chunks::<2>()
        .0
        .iter()
        .max_by(|a, b| (a[1] - a[0]).total_cmp(&(b[1] - b[0])))
        .map(|span| ((span[0] + span[1]) / 2., y))
        .or(Some((x, y)))
}
/// Ray-casting point-in-ring test in lon/lat degrees.
fn contains(ring: &[[f64; 2]], lon: f64, lat: f64) -> bool {
    let mut inside = false;
    let mut j = ring.len().wrapping_sub(1);
    for i in 0..ring.len() {
        let ([xi, yi], [xj, yj]) = (ring[i], ring[j]);
        if (yi > lat) != (yj > lat) && lon < (xj - xi) * (lat - yi) / (yj - yi) + xi {
            inside = !inside;
        }
        j = i;
    }
    inside
}
impl Default for CountryMap {
    fn default() -> Self {
        Self::new()
    }
}
impl CountryMap {
    pub fn new() -> Self {
        let geometry: Vec<Geometry> =
            serde_json::from_str(include_str!("../../../assets/countries.json"))
                .expect("bundled country geometry");
        let mut paths = Vec::new();
        let mut aliases = HashMap::new();
        let mut rings = Vec::new();
        let mut labels = Vec::new();
        let mut anchors = Vec::new();
        for (index, country) in geometry.into_iter().enumerate() {
            let code = country
                .aliases
                .iter()
                .find(|a| a.len() == 2)
                .cloned()
                .unwrap_or_default();
            let name = country
                .aliases
                .iter()
                .find(|a| a.len() > 3)
                .cloned()
                .unwrap_or_else(|| code.clone());
            labels.push((code, name));
            for alias in country.aliases {
                aliases.entry(key(&alias)).or_insert(index);
            }
            anchors.push(anchor(&country.polygons));
            rings.push(country.polygons.clone());
            let mut polygons = Vec::new();
            for polygon in country.polygons {
                let mut builder = PathBuilder::new();
                for ring in polygon {
                    for (i, [lon, lat]) in ring.into_iter().enumerate() {
                        let (x, y) = super::render::xy(lon, lat);
                        if i == 0 {
                            builder.move_to(x, y);
                        } else {
                            builder.line_to(x, y);
                        }
                    }
                    builder.close();
                }
                if let Some(path) = builder.finish() {
                    polygons.push(path);
                }
            }
            paths.push(polygons);
        }
        for (alias, canonical) in [
            ("UK", "GB"),
            ("United States", "US"),
            ("USA", "US"),
            ("South Korea", "KR"),
            ("North Korea", "KP"),
            ("Ivory Coast", "CI"),
        ] {
            if let Some(index) = aliases.get(&key(canonical)).copied() {
                aliases.insert(key(alias), index);
            }
        }
        Self {
            paths,
            aliases,
            rings,
            labels,
            anchors,
        }
    }
    /// Label point (lon, lat) for icons: centroid of the country's largest landmass.
    pub fn anchor(&self, index: usize) -> Option<(f64, f64)> {
        self.anchors.get(index).copied().flatten()
    }
    /// ISO alpha-2 code and display name of a bundled country.
    pub fn label(&self, index: usize) -> Option<(&str, &str)> {
        self.labels
            .get(index)
            .map(|(code, name)| (code.as_str(), name.as_str()))
    }
    /// Country containing a lon/lat point (even-odd across all rings, so holes stay outside).
    pub fn at(&self, lon: f64, lat: f64) -> Option<usize> {
        self.rings.iter().position(|polygons| {
            polygons.iter().any(|polygon| {
                polygon
                    .iter()
                    .filter(|ring| contains(ring, lon, lat))
                    .count()
                    % 2
                    == 1
            })
        })
    }
    /// Fill whole countries with per-country colour and opacity; borders stay on top.
    pub fn fill(&self, pixmap: &mut Pixmap, fills: &[(usize, [u8; 3], u8)]) {
        pixmap.fill(tiny_skia::Color::TRANSPARENT);
        for &(index, rgb, alpha) in fills {
            if let Some(paths) = self.paths.get(index) {
                let mut paint = Paint::default();
                paint.set_color_rgba8(rgb[0], rgb[1], rgb[2], alpha);
                for path in paths {
                    pixmap.fill_path(path, &paint, FillRule::EvenOdd, Transform::identity(), None);
                }
            }
        }
        self.borders(pixmap);
    }
    /// Emphasise country borders (used for informational layers that must not look like severity).
    pub fn outline(&self, pixmap: &mut Pixmap, outlines: &[(usize, f32, u8)], rgb: [u8; 3]) {
        for &(index, width, alpha) in outlines {
            if let Some(paths) = self.paths.get(index) {
                let mut paint = Paint::default();
                paint.set_color_rgba8(rgb[0], rgb[1], rgb[2], alpha);
                for path in paths {
                    pixmap.stroke_path(
                        path,
                        &paint,
                        &Stroke {
                            width,
                            ..Default::default()
                        },
                        Transform::identity(),
                        None,
                    );
                }
            }
        }
    }
    /// Highlight both reported endpoints. Unknown categories/countries stay neutral.
    /// Most severe observation still inside the receipt-time window wins.
    pub fn classes(&self, snapshot: &Snapshot) -> Vec<Option<usize>> {
        let mut classes = vec![None; self.paths.len()];
        for (index, times) in &snapshot.country_activity {
            if let Some(result) = classes.get_mut(*index) {
                *result = times.iter().position(|time| {
                    time.is_some_and(|received| {
                        received <= snapshot.now_ms && snapshot.now_ms - received < HIGHLIGHT_MS
                    })
                });
            }
        }
        classes
    }
    /// Bundled country index for an ISO alpha-2 code or a known alias.
    pub fn index(&self, code: &str) -> Option<usize> {
        self.aliases.get(&key(code)).copied()
    }
    /// Shade whole countries in one colour at per-country opacity; borders stay on top.
    pub fn shade(&self, pixmap: &mut Pixmap, shades: &[(usize, u8)], rgb: [u8; 3]) {
        pixmap.fill(tiny_skia::Color::TRANSPARENT);
        for &(index, alpha) in shades {
            if let Some(paths) = self.paths.get(index) {
                let mut paint = Paint::default();
                paint.set_color_rgba8(rgb[0], rgb[1], rgb[2], alpha);
                for path in paths {
                    pixmap.fill_path(path, &paint, FillRule::EvenOdd, Transform::identity(), None);
                }
            }
        }
        self.borders(pixmap);
    }
    pub fn borders(&self, pixmap: &mut Pixmap) {
        let mut paint = Paint::default();
        paint.set_color_rgba8(70, 108, 124, 190);
        for paths in &self.paths {
            for path in paths {
                pixmap.stroke_path(
                    path,
                    &paint,
                    &Stroke {
                        width: 0.65,
                        ..Default::default()
                    },
                    Transform::identity(),
                    None,
                );
            }
        }
    }
    pub fn highlights(&self, pixmap: &mut Pixmap, classes: &[Option<usize>]) {
        pixmap.fill(tiny_skia::Color::TRANSPARENT);
        for (paths, class) in self.paths.iter().zip(classes) {
            if let Some(class) = class {
                let rgb = super::render::color(*class);
                let mut paint = Paint::default();
                paint.set_color_rgba8(rgb[0], rgb[1], rgb[2], 85);
                for path in paths {
                    pixmap.fill_path(path, &paint, FillRule::EvenOdd, Transform::identity(), None);
                }
            }
        }
        // Borders remain visible above shaded country polygons.
        self.borders(pixmap);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::State;
    #[test]
    fn classification_conflicts_expiry_and_unknowns() {
        let map = CountryMap::new();
        let mut state = State::default();
        for (intention, time) in [("malicious", 1000), ("benign", 2000), ("suspicious", 2500)] {
            let row = serde_json::json!({"source":{"latitude":52,"longitude":5,"country":"NL"},"destination":{"latitude":40,"longitude":-100,"country":"United States"},"intention":intention});
            state.ingest(&row.to_string(), time);
        }
        let nl = map.aliases["nl"];
        let us = map.aliases["us"];
        let classes = map.classes(&state.snapshot(3000));
        assert_eq!(classes[nl], Some(0));
        assert_eq!(classes[us], Some(0));
        assert_eq!(map.classes(&state.snapshot(7000))[nl], Some(1));
        assert!(map
            .classes(&state.snapshot(8500))
            .iter()
            .all(Option::is_none));
        assert!(map
            .classes(&state.snapshot(999))
            .iter()
            .all(Option::is_none));
        state.ingest(r#"{"source":{"latitude":0,"longitude":0,"country":"??"},"destination":{"latitude":52,"longitude":5,"country":"NL"},"intention":"unknown"}"#,9000);
        assert!(map
            .classes(&state.snapshot(9000))
            .iter()
            .all(Option::is_none));
    }
    #[test]
    fn traffic_volume_does_not_expire_country_highlights() {
        let map = CountryMap::new();
        let mut state = State::default();
        let row = |source: &str, destination: &str, intention: &str| {
            serde_json::json!({
                "source":{"latitude":0,"longitude":0,"country":source},
                "destination":{"latitude":0,"longitude":0,"country":destination},
                "intention":intention
            })
            .to_string()
        };
        state.ingest(&row("NL", "DE", "malicious"), 1000);
        for _ in 0..1000 {
            state.ingest(&row("US", "SE", "benign"), 1001);
        }
        let snapshot = state.snapshot(2000);
        assert_eq!(snapshot.recent.len(), 600);
        assert_eq!(map.classes(&snapshot)[map.aliases["nl"]], Some(0));
        assert_eq!(map.classes(&snapshot)[map.aliases["de"]], Some(0));
        state.ingest(&row("NL", "Germany", "suspicious"), 3000);
        assert_eq!(
            map.classes(&state.snapshot(6999))[map.aliases["nl"]],
            Some(0)
        );
        assert_eq!(
            map.classes(&state.snapshot(7000))[map.aliases["nl"]],
            Some(1)
        );
        assert_eq!(map.classes(&state.snapshot(9000))[map.aliases["nl"]], None);
        let before = state.snapshot(9000).country_activity.len();
        for index in 0..1000 {
            state.ingest(&row(&format!("unknown-{index}"), "??", "malicious"), 9000);
        }
        assert_eq!(state.snapshot(9000).country_activity.len(), before);
    }
    #[test]
    fn polygon_holes_and_separate_parts_are_preserved() {
        let map = CountryMap::new();
        assert!(map.paths.len() > 170);
        assert!(map.paths[map.aliases["fj"]].len() > 1);
        // South Africa includes the Lesotho hole; never build each ring as a solid fill.
        assert_eq!(map.aliases["south africa"], map.aliases["za"]);
        let mut pixels = Pixmap::new(crate::WIDTH, crate::HEIGHT).unwrap();
        let mut classes = vec![None; map.paths.len()];
        classes[map.aliases["za"]] = Some(0);
        map.highlights(&mut pixels, &classes);
        let (x, y) = super::super::render::xy(28.5, -29.5);
        let i = (y as usize * crate::WIDTH as usize + x as usize) * 4;
        assert_eq!(
            pixels.data()[i + 3],
            0,
            "Lesotho interior must remain unfilled"
        );
    }
}
