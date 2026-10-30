#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use minifb::{Key, Window, WindowOptions};
    use threat_atlas_core::{Session, HEIGHT, WIDTH};
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Threat Atlas Linux preview\nUsage: threat-atlas-linux [--smoke-test]\nEsc or close exits. Requires X11 or XWayland. This is an application preview, not a secure screensaver/lock screen.");
        return Ok(());
    }
    if args.iter().any(|a| a != "--smoke-test") {
        return Err("Unknown argument; use --help".into());
    }
    let smoke = args.iter().any(|a| a == "--smoke-test");
    let mut window = Window::new(
        "Threat Atlas SOC — Linux preview",
        WIDTH as usize,
        HEIGHT as usize,
        WindowOptions {
            resize: true,
            ..WindowOptions::default()
        },
    )?;
    window.set_target_fps(30);
    let mut session = Session::new();
    let mut buffer = vec![0u32; (WIDTH * HEIGHT) as usize];
    let mut frames = 0;
    while window.is_open() && !window.is_key_down(Key::Escape) {
        for (out, rgba) in buffer.iter_mut().zip(session.frame().as_chunks::<4>().0) {
            *out = ((rgba[0] as u32) << 16) | ((rgba[1] as u32) << 8) | rgba[2] as u32;
        }
        window.update_with_buffer(&buffer, WIDTH as usize, HEIGHT as usize)?;
        frames += 1;
        if smoke && frames == 3 {
            break;
        }
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = run() {
        eprintln!("Threat Atlas Linux preview: {error}");
        std::process::exit(1);
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "Build this application on Linux. Use the native Windows/macOS hosts on those platforms."
    );
}
