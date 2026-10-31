//! Offline visual QA only: deterministic synthetic records, never production telemetry.
use std::{fs, path::Path};
use threat_atlas_core::{feed::State, render::Renderer, HEIGHT, WIDTH};
fn main() {
    let output = std::env::args().nth(1).expect("output directory");
    fs::create_dir_all(&output).unwrap();
    let mut state = State::default();
    let mut renderer = Renderer::new();
    for (name, category) in [("neutral", None), ("categories-test-fixture", Some(()))] {
        if category.is_some() {
            state.ingest(r#"[{"source":{"latitude":40,"longitude":-100,"country":"US"},"destination":{"latitude":50,"longitude":10,"country":"DE"},"intention":"malicious"},{"source":{"latitude":-10,"longitude":-50,"country":"BR"},"destination":{"latitude":20,"longitude":78,"country":"IN"},"intention":"suspicious"},{"source":{"latitude":-25,"longitude":135,"country":"AU"},"destination":{"latitude":60,"longitude":15,"country":"SE"},"intention":"benign"}]"#,1000);
        }
        let mut snapshot = state.snapshot(2000);
        snapshot.status = "OFFLINE TEST FIXTURE".into();
        let pixels = renderer.draw(&snapshot).to_vec();
        let pix = tiny_skia::Pixmap::from_vec(
            pixels,
            tiny_skia::IntSize::from_wh(WIDTH, HEIGHT).unwrap(),
        )
        .unwrap();
        pix.save_png(Path::new(&output).join(format!("{name}.png")))
            .unwrap();
    }
}
