//! AtlasSOC Desktop for Linux (preview): the shared SOC view in a resizable X11/XWayland window.
//! Same feed, renderer and TLS validation as the Windows and macOS hosts. No Cloudflare Radar,
//! no update check and no saved settings in this preview; it is not a screensaver or lock screen.

/// Desktop identity shared with the other hosts, so the title and the footer agree.
#[cfg(any(target_os = "linux", test))]
const IDENTITY: &str = include_str!("../../../../atlassoc-beta-version.json");

#[cfg(target_os = "linux")]
const HELP: &str = "AtlasSOC Desktop - Linux preview
Usage: atlassoc [--smoke-test]

Keys (window must have focus):
  R / C / S   Realtime / Calm / Still animation
  L           Classic / Dashboard layout
  1 / 2 / 3   show or hide malicious / suspicious / benign
  Space       freeze or resume the display (the feed continues)
  F1 or H     print this help in the terminal
  Esc         quit
Mouse: left-click a country to focus it (click again to clear); hover shows its counts in the title.

Requires X11 or XWayland. Resize the window: wider shapes add a Top countries column.
Not included in this preview: Cloudflare Radar, update check, saved settings, fullscreen toggle.
Records are GreyNoise public threat-map receipts, not verified unique attacks.";

/// "0.7.0 (build 13)" from the identity file; a readable fallback if it cannot be parsed.
#[cfg(any(target_os = "linux", test))]
fn identity_label(identity: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(identity).unwrap_or_default();
    match (value["version"].as_str(), value["build"].as_u64()) {
        (Some(version), Some(build)) => format!("{version} (build {build})"),
        _ => "unknown version".into(),
    }
}

/// Frame width for a window shape: 900 high, 1440 to 2160 wide (2.4:1), in steps of 8.
#[cfg(any(target_os = "linux", test))]
fn frame_width(width: usize, height: usize) -> u32 {
    if width == 0 || height == 0 {
        return 1440;
    }
    let wanted = (width as u128 * 900 / height as u128 / 8 * 8).min(2160) as u32;
    wanted.clamp(1440, 2160)
}

/// Window point to frame point for a frame drawn centred with its aspect ratio kept.
#[cfg(any(target_os = "linux", test))]
fn frame_point(window: (usize, usize), frame: (u32, u32), at: (f32, f32)) -> Option<(f32, f32)> {
    let (w, h) = (window.0 as f32, window.1 as f32);
    let (fw, fh) = (frame.0 as f32, frame.1 as f32);
    if w <= 0. || h <= 0. || fw <= 0. || fh <= 0. {
        return None;
    }
    let scale = (w / fw).min(h / fh);
    let (x, y) = (
        (at.0 - (w - fw * scale) / 2.) / scale,
        (at.1 - (h - fh * scale) / 2.) / scale,
    );
    ((0. ..fw).contains(&x) && (0. ..fh).contains(&y)).then_some((x, y))
}

/// One line for the title from the view's inspection JSON.
#[cfg(any(target_os = "linux", test))]
fn inspection_label(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    Some(format!(
        "{} ({}) - {} malicious / {} suspicious / {} benign in {} minutes",
        value.get("name")?.as_str()?,
        value.get("code")?.as_str()?,
        value.get("malicious")?.as_u64()?,
        value.get("suspicious")?.as_u64()?,
        value.get("benign")?.as_u64()?,
        value.get("window_minutes")?.as_u64()?
    ))
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use minifb::{Key, KeyRepeat, MouseButton, MouseMode, ScaleMode, Window, WindowOptions};
    use threat_atlas_core::{
        feed::{self, Feed, State},
        render::soc::{Motion, SocView, Theme},
        HEIGHT, WIDTH,
    };
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{HELP}");
        return Ok(());
    }
    if args.iter().any(|a| a != "--smoke-test") {
        return Err("Unknown argument; use --help".into());
    }
    let smoke = !args.is_empty();
    let base_title = format!("AtlasSOC {} - Linux preview", identity_label(IDENTITY));
    let mut window = Window::new(
        &base_title,
        WIDTH as usize,
        HEIGHT as usize,
        WindowOptions {
            resize: true,
            scale_mode: ScaleMode::AspectRatioStretch,
            ..WindowOptions::default()
        },
    )?;
    window.set_target_fps(30);
    // The smoke test never opens a network connection: it draws an empty offline state.
    let feed = (!smoke).then(Feed::shared);
    let offline = State::default();
    let mut view = SocView::new();
    // No Cloudflare Radar in this preview: no token is read and nothing is requested.
    view.options.radar_layer = false;
    view.options.radar_note = Some("RADAR NOT INCLUDED IN THE LINUX PREVIEW".into());
    if !smoke {
        println!("{HELP}");
    }
    let mut buffer: Vec<u32> = Vec::new();
    let mut frozen = false;
    let mut was_down = false;
    let mut title = base_title.clone();
    let mut frames = 0u32;
    while window.is_open() && !window.is_key_down(Key::Escape) {
        for key in window.get_keys_pressed(KeyRepeat::No) {
            match key {
                Key::R => view.options.motion = Motion::Realtime,
                Key::C => view.options.motion = Motion::Calm,
                Key::S => view.options.motion = Motion::Still,
                Key::L => {
                    view.options.theme = match view.options.theme {
                        Theme::Classic => Theme::Dashboard,
                        Theme::Dashboard => Theme::Classic,
                    }
                }
                Key::Key1 => view.options.severities[0] ^= true,
                Key::Key2 => view.options.severities[1] ^= true,
                Key::Key3 => view.options.severities[2] ^= true,
                Key::Space => frozen = !frozen,
                Key::F1 | Key::H => println!("{HELP}"),
                _ => {}
            }
        }
        let size = window.get_size();
        // The smoke test also exercises the wide layout on its second frame.
        let width = if smoke && frames == 1 {
            view.set_width(2160)
        } else {
            view.set_width(frame_width(size.0, size.1))
        };
        let point = window
            .get_mouse_pos(MouseMode::Discard)
            .and_then(|at| frame_point(size, (width, HEIGHT), at));
        let down = window.get_mouse_down(MouseButton::Left);
        if down && !was_down {
            if let Some((x, y)) = point {
                let hit = view.country_at(x, y);
                view.options.focus = if view.options.focus == hit { None } else { hit };
            }
        }
        was_down = down;
        let wanted = point
            .and_then(|(x, y)| view.inspect(x, y, None))
            .and_then(|body| inspection_label(&body))
            .map_or_else(
                || base_title.clone(),
                |label| format!("{base_title} | {label}"),
            );
        if wanted != title {
            window.set_title(&wanted);
            title = wanted;
        }
        if !frozen || buffer.len() != (width * HEIGHT) as usize {
            let (snapshot, counts) = match &feed {
                Some(feed) => (feed.snapshot(), feed.counts()),
                None => {
                    let now = feed::now_ms();
                    (offline.snapshot(now), offline.counts(now))
                }
            };
            let rgba = view.draw(&snapshot, counts, None, 0);
            buffer.clear();
            buffer.extend(
                rgba.as_chunks::<4>()
                    .0
                    .iter()
                    .map(|p| ((p[0] as u32) << 16) | ((p[1] as u32) << 8) | p[2] as u32),
            );
        }
        window.update_with_buffer(&buffer, width as usize, HEIGHT as usize)?;
        frames += 1;
        if smoke && frames == 3 {
            println!("AtlasSOC Linux smoke test: 3 frames presented, offline, no feed constructed");
            break;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = run() {
        eprintln!("AtlasSOC Linux preview: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Build AtlasSOC for Linux on Linux. Use the native Windows/macOS apps elsewhere.");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn title_uses_the_desktop_identity() {
        let label = identity_label(IDENTITY);
        assert!(label.contains(" (build "), "{label}");
        assert_eq!(identity_label("not json"), "unknown version");
    }
    #[test]
    fn frame_width_follows_the_window_shape_within_limits() {
        assert_eq!(frame_width(1440, 900), 1440);
        assert_eq!(frame_width(800, 900), 1440);
        assert_eq!(frame_width(1920, 1080), 1600);
        assert_eq!(frame_width(3440, 1440), 2144);
        assert_eq!(frame_width(5120, 1440), 2160);
        assert_eq!(frame_width(0, 0), 1440);
        assert_eq!(frame_width(usize::MAX, 1), 2160);
    }
    #[test]
    fn window_points_map_to_frame_points_and_letterbox_is_outside() {
        // Same shape, half size: plain scaling.
        assert_eq!(
            frame_point((720, 450), (1440, 900), (360., 225.)),
            Some((720., 450.))
        );
        // Taller window: bars above and below.
        assert_eq!(frame_point((1440, 1100), (1440, 900), (10., 50.)), None);
        assert_eq!(
            frame_point((1440, 1100), (1440, 900), (10., 100.)),
            Some((10., 0.))
        );
        // Wider window than the 2.4:1 cap: bars left and right.
        assert_eq!(frame_point((2400, 900), (2160, 900), (60., 10.)), None);
        assert_eq!(
            frame_point((2400, 900), (2160, 900), (120., 10.)),
            Some((0., 10.))
        );
        assert_eq!(frame_point((0, 0), (1440, 900), (0., 0.)), None);
    }
    #[test]
    fn hover_label_needs_every_field() {
        let body = r#"{"name":"Sweden","code":"SE","malicious":3,"suspicious":2,"benign":1,"window_minutes":15}"#;
        assert_eq!(
            inspection_label(body).as_deref(),
            Some("Sweden (SE) - 3 malicious / 2 suspicious / 1 benign in 15 minutes")
        );
        assert_eq!(inspection_label(r#"{"name":"Sweden"}"#), None);
    }
}
