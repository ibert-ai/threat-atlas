//! Offline visual QA only: deterministic synthetic records, never production telemetry.
use std::{fs, path::Path};
use threat_atlas_core::{
    feed::State,
    render::{Renderer, SaverTheme},
    HEIGHT, WIDTH,
};

fn main() {
    let output = std::env::args().nth(1).expect("output directory");
    fs::create_dir_all(&output).unwrap();
    let places = [
        ("US", 39., -98.),
        ("GB", 54., -2.),
        ("DE", 51., 10.),
        ("FR", 46., 2.),
        ("RU", 61., 100.),
        ("CN", 35., 104.),
        ("JP", 36., 138.),
        ("IN", 21., 79.),
        ("BR", -14., -52.),
        ("ZA", -26., 28.),
        ("AU", -25., 135.),
        ("SG", 1.35, 103.8),
    ];
    let start = 1_767_225_600_000u64; // 2026-01-01T00:00:00Z, fixed for reproducible frames
    let mut state = State::default();
    let mut n = 0usize;
    for t in 0..30u64 {
        for _ in 0..4 {
            let (s, d) = (places[n % places.len()], places[(n * 5 + 3) % places.len()]);
            let intention = ["malicious", "suspicious", "benign", "benign"][n % 4];
            let row = format!(
                r#"{{"source":{{"latitude":{},"longitude":{},"country":"{}"}},"destination":{{"latitude":{},"longitude":{},"country":"{}"}},"intention":"{intention}"}}"#,
                s.1, s.2, s.0, d.1, d.2, d.0
            );
            state.ingest(&row, start + t * 1_000);
            n += 1;
        }
    }
    let mut snapshot = state.snapshot(start + 31_000);
    snapshot.status = "LIVE".into();
    let mut renderer = Renderer::new_with_theme(SaverTheme::Seeker);
    let pixels = renderer.draw(&snapshot).to_vec();
    let pix = tiny_skia::Pixmap::from_vec(
        pixels,
        tiny_skia::IntSize::from_wh(WIDTH, HEIGHT).unwrap(),
    )
    .unwrap();
    pix.save_png(Path::new(&output).join("seeker-test-fixture.png"))
        .unwrap();
    println!("seeker-test-fixture.png");
}
