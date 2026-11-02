//! Offline visual QA only: deterministic synthetic records and Radar rows, never production telemetry.
use std::{fs, path::Path};
use threat_atlas_core::{feed::State, radar, render::soc::SocView, HEIGHT, WIDTH};
const RADAR: &str = r#"{"success":true,"result":{"meta":{"lastUpdated":"2026-01-01T00:00:00Z","normalization":"PERCENTAGE","dateRange":[{"startTime":"2025-12-31T00:00:00Z","endTime":"2026-01-01T00:00:00Z"}]},"top_0":[{"originCountryAlpha2":"BR","originCountryName":"Brazil","value":"7.4"},{"originCountryAlpha2":"US","originCountryName":"United States","value":"4.5"},{"originCountryAlpha2":"HK","originCountryName":"Hong Kong","value":"2.1"}]}}"#;
fn main() {
    let output = std::env::args().nth(1).expect("output directory");
    fs::create_dir_all(&output).unwrap();
    let places = [
        ("US", 39., -98.),
        ("CN", 35., 104.),
        ("BR", -14., -52.),
        ("DE", 51., 10.),
        ("NL", 52., 5.),
        ("RU", 61., 100.),
        ("IN", 21., 79.),
        ("FR", 46., 2.),
        ("GB", 54., -2.),
        ("JP", 36., 138.),
    ];
    let mut state = State::default();
    let mut view = SocView::new();
    let radar_data = radar::parse(RADAR.as_bytes()).unwrap();
    let start = 1_767_225_600_000u64; // 2026-01-01T00:00:00Z
    for frame in 0..80u64 {
        let now = start + frame * 125;
        for i in 0..40usize {
            let (s, d) = (places[(i + frame as usize) % 10], places[(i * 7 + 3) % 10]);
            let intention =
                ["malicious", "suspicious", "benign", "benign"][(i + frame as usize) % 4];
            let row = format!(
                r#"{{"source":{{"latitude":{},"longitude":{},"country":"{}"}},"destination":{{"latitude":{},"longitude":{},"country":"{}"}},"intention":"{intention}"}}"#,
                s.1, s.2, s.0, d.1, d.2, d.0
            );
            state.ingest(&row, now);
        }
        let pixels = view
            .draw(
                &state.snapshot(now),
                state.counts(now),
                Some(&radar_data),
                start,
            )
            .to_vec();
        if frame == 79 {
            let pix = tiny_skia::Pixmap::from_vec(
                pixels,
                tiny_skia::IntSize::from_wh(WIDTH, HEIGHT).unwrap(),
            )
            .unwrap();
            pix.save_png(Path::new(&output).join("soc-calm-test-fixture.png"))
                .unwrap();
        }
    }
}
