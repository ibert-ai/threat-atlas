//! Visual QA: renders the panorama layout from the real public feed, never from invented records.
use std::{thread::sleep, time::Duration};
use threat_atlas_core::Session;
fn main() {
    let output = std::env::args().nth(1).expect("output PNG");
    let width: u32 = std::env::args().nth(2).map_or(3840, |v| v.parse().unwrap());
    let height: u32 = std::env::args().nth(3).map_or(1080, |v| v.parse().unwrap());
    let mut session = Session::panorama(width, height);
    for _ in 0..240 {
        session.frame();
        sleep(Duration::from_millis(50));
    }
    let snapshot = session.snapshot();
    eprintln!("status {} records {}", snapshot.status, snapshot.records);
    let (w, h) = session.renderer.size();
    let started = std::time::Instant::now();
    for _ in 0..10 {
        session.frame();
    }
    eprintln!("frame {:?}", started.elapsed() / 10);
    let pixels = session.frame().to_vec();
    tiny_skia::Pixmap::from_vec(pixels, tiny_skia::IntSize::from_wh(w, h).unwrap())
        .unwrap()
        .save_png(output)
        .unwrap();
}
