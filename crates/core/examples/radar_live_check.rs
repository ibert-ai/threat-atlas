//! One live request through `radar_fetch::https_get` with the CL Cloudflare Radar TEST token
//! (macOS Keychain service IbertConsulting.CL.CloudflareRadarTest, account radar-read-test), read
//! inside this process. Prints status, size and validation only, never the token.
//! Run: cargo run -p threat-atlas-core --example radar_live_check
fn main() {
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("security")
            .args([
                "find-generic-password",
                "-s",
                "IbertConsulting.CL.CloudflareRadarTest",
                "-a",
                "radar-read-test",
                "-w",
            ])
            .output()
            .expect("security");
        let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if token.is_empty() {
            println!("SKIP: test token not in this Keychain");
            return;
        }
        match threat_atlas_core::radar_fetch::https_get(&token, std::time::Duration::from_secs(20))
        {
            Ok(r) => {
                let parsed = threat_atlas_core::radar::parse(&r.body);
                println!(
                    "status={} bytes={} ratelimit={:?} valid={} last_updated={}",
                    r.status,
                    r.body.len(),
                    r.ratelimit,
                    parsed.is_ok(),
                    parsed.map(|a| a.last_updated).unwrap_or_default()
                );
            }
            Err(e) => println!("ERROR {e}"),
        }
    }
}
