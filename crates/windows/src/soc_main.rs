#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
mod soc_config;
#[cfg(windows)]
mod soc_host;
#[cfg(windows)]
mod soc_radar;

fn main() {
    #[cfg(windows)]
    if let Err(error) = soc_host::run() {
        soc_host::show_error(&error.to_string());
        std::process::exit(1);
    }
    #[cfg(not(windows))]
    eprintln!("ThreatAtlas.exe is a Windows application; use the native macOS SOC host on Mac.");
}
