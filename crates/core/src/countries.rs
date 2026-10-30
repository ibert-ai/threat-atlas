//! Cached country polygons and telemetry-driven country highlights.
use crate::feed::Snapshot;
use serde::Deserialize;
use std::collections::HashMap;
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
}
fn key(name: &str) -> String {
    name.trim().to_lowercase()
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
        for (index, country) in geometry.into_iter().enumerate() {
            for alias in country.aliases {
                aliases.entry(key(&alias)).or_insert(index);
            }
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
        Self { paths, aliases }
    }
    /// Highlight both reported endpoints. Unknown categories/countries stay neutral.
    /// Most severe observation still inside the receipt-time window wins.
    pub fn classes(&self, snapshot: &Snapshot) -> Vec<Option<usize>> {
        let mut classes = vec![None; self.paths.len()];
        for event in &snapshot.recent {
            if event.received_ms > snapshot.now_ms
                || snapshot.now_ms.saturating_sub(event.received_ms) >= HIGHLIGHT_MS
            {
                continue;
            }
            let class = event.record.class();
            if class > 2 {
                continue;
            }
            for location in [&event.record.source, &event.record.destination] {
                if let Some(&index) = self.aliases.get(&key(&location.country)) {
                    classes[index] =
                        Some(classes[index].map_or(class, |previous: usize| previous.min(class)));
                }
            }
        }
        classes
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
    fn highlight_includes_records_beyond_visible_feed_sample() {
        let map = CountryMap::new();
        let mut state = State::default();
        state.ingest(r#"{"source":{"latitude":52,"longitude":5,"country":"NL"},"destination":{"latitude":52,"longitude":5,"country":"NL"},"intention":"malicious"}"#, 1000);
        for _ in 0..200 {
            state.ingest(r#"{"source":{"latitude":40,"longitude":-100,"country":"US"},"destination":{"latitude":40,"longitude":-100,"country":"US"},"intention":"benign"}"#, 2000);
        }
        let snapshot = state.snapshot(3000);
        assert_eq!(snapshot.recent.len(), 201);
        assert_eq!(map.classes(&snapshot)[map.aliases["nl"]], Some(0));
        assert_eq!(map.classes(&state.snapshot(7000))[map.aliases["nl"]], None);
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
