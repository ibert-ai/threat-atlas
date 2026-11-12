#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
mod soc_config;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
fn main() {
    if let Err(e) = windows::run() {
        windows::show_error(&e.to_string());
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Use scripts/build-macos.sh to build the native macOS screensaver.");
}
