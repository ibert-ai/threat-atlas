//! Manual smoke test of the shared OSINT worker against the real providers (uses the network).
//! `cargo run --release -p threat-atlas-core --example osint_worker_smoke`
use threat_atlas_core::{
    osint, osint_ffi::LIVE_SOURCES, osint_net, osint_text, osint_worker::Osint,
};

fn main() {
    let dir = std::env::temp_dir().join(format!("atlassoc-osint-smoke-{}", std::process::id()));
    let enabled: Vec<String> = LIVE_SOURCES
        .iter()
        .map(|s| osint::source_spec(*s).id.to_owned())
        .collect();
    let worker = Osint::start(dir.clone(), enabled, osint_net::https_get);
    worker.lookup("1.1.1.1".parse().unwrap());
    std::thread::sleep(std::time::Duration::from_secs(60));
    let view = worker.view();
    let now = threat_atlas_core::feed::now_ms();
    for source in LIVE_SOURCES {
        let page = osint_text::page(source, &view, "8.8.8.8", now);
        println!(
            "=== {:?}\n{}\n",
            source,
            page.lines().take(6).collect::<Vec<_>>().join("\n")
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}
