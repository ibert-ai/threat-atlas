use std::{
    fs, thread,
    time::{Duration, Instant},
};
use threat_atlas_core::{Session, HEIGHT, WIDTH};
fn main() {
    let dir = std::env::args().nth(1).unwrap_or("verification".into());
    fs::create_dir_all(&dir).unwrap();
    let mut s = Session::new();
    let start = Instant::now();
    let mut rows = Vec::new();
    for n in 0..60 {
        let snap = s.snapshot();
        let pixels = s.renderer.draw(&snap);
        let mut ppm = format!("P6\n{} {}\n255\n", WIDTH, HEIGHT).into_bytes();
        for p in pixels.as_chunks::<4>().0 {
            ppm.extend_from_slice(&p[..3]);
        }
        fs::write(format!("{dir}/frame-{n:03}.ppm"), ppm).unwrap();
        if n % 10 == 0 || n == 59 {
            println!(
                "{:.2}s {} records / {} changed / {}",
                start.elapsed().as_secs_f64(),
                snap.records,
                snap.changed_batches,
                snap.status
            );
            rows.push(serde_json::json!({"elapsed_seconds":start.elapsed().as_secs_f64(),"snapshot":snap}));
        }
        thread::sleep(Duration::from_millis(500));
    }
    fs::write(
        format!("{dir}/audit.json"),
        serde_json::to_vec_pretty(&rows).unwrap(),
    )
    .unwrap();
    let first = rows[1]["snapshot"]["records"].as_u64().unwrap();
    let last = rows.last().unwrap();
    assert!(last["snapshot"]["records"].as_u64().unwrap() > first);
    assert!(last["snapshot"]["changed_batches"].as_u64().unwrap() > 2);
    assert_eq!(last["snapshot"]["status"], "LIVE");
}
