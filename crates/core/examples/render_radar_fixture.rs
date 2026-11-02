//! Offline visual QA only: deterministic synthetic Radar aggregates, never production telemetry.
use std::{fs, path::Path};
use threat_atlas_core::{RadarSession, HEIGHT, WIDTH};
const BODY: &str = r#"{"success":true,"result":{"meta":{"lastUpdated":"2026-01-01T00:00:00Z","normalization":"PERCENTAGE","dateRange":[{"startTime":"2025-12-31T00:00:00Z","endTime":"2026-01-01T00:00:00Z"}]},"top_0":[{"originCountryAlpha2":"BR","originCountryName":"Brazil","targetCountryAlpha2":"US","targetCountryName":"United States","value":"7.4"},{"originCountryAlpha2":"US","originCountryName":"United States","value":"4.5"},{"originCountryAlpha2":"BR","originCountryName":"Brazil","value":"4.4"},{"originCountryAlpha2":"HK","originCountryName":"Hong Kong","value":"2.1"},{"originCountryAlpha2":"CL","originCountryName":"Chile","value":"2.0"},{"originCountryAlpha2":"XX","originCountryName":"Unknown","value":"1.0"}]}}"#;
fn main() {
    let output = std::env::args().nth(1).expect("output directory");
    fs::create_dir_all(&output).unwrap();
    let received = 1_767_225_600_000; // 2026-01-01T00:00:00Z, fixed for reproducible frames
    let mut session = RadarSession::new();
    let save = |name: &str, session: &mut RadarSession, now: u64| {
        let pixels = session.frame_at(now).to_vec();
        let pix = tiny_skia::Pixmap::from_vec(
            pixels,
            tiny_skia::IntSize::from_wh(WIDTH, HEIGHT).unwrap(),
        )
        .unwrap();
        pix.save_png(Path::new(&output).join(format!("{name}.png")))
            .unwrap();
    };
    save("radar-no-data", &mut session, received);
    assert!(session.set(BODY.as_bytes(), received));
    save(
        "radar-current-test-fixture",
        &mut session,
        received + 60_000,
    );
    save(
        "radar-stale-test-fixture",
        &mut session,
        received + 3_600_000,
    );
}
