use std::{
    error::Error,
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};
use std::{num::NonZeroU32, rc::Rc};
use tao::{
    dpi::{PhysicalPosition, PhysicalSize},
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    platform::windows::WindowBuilderExtWindows,
    window::{Fullscreen, WindowBuilder},
};
use threat_atlas_core::{render::panorama, Session, HEIGHT, WIDTH};
use windows_sys::Win32::{
    Foundation::{HWND, POINT, RECT},
    UI::{
        Input::KeyboardAndMouse::GetAsyncKeyState,
        WindowsAndMessaging::{
            GetClientRect, GetCursorPos, IsWindow, MessageBoxW, IDNO, IDYES, MB_ICONERROR, MB_OK,
            MB_YESNOCANCEL,
        },
    },
};

pub fn show_error(message: &str) {
    let msg: Vec<u16> = format!("Threat Atlas: {message}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let title: Vec<u16> = "Threat Atlas".encode_utf16().chain(Some(0)).collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            msg.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

fn scaled_frame_layout(width: u32, height: u32) -> (u32, u32, u32, u32) {
    let scale = (width as f32 / WIDTH as f32).min(height as f32 / HEIGHT as f32);
    let draw_width = (WIDTH as f32 * scale) as u32;
    let draw_height = (HEIGHT as f32 * scale) as u32;
    let offset_x = (width - draw_width) / 2;
    let offset_y = (height - draw_height) / 2;
    (draw_width, draw_height, offset_x, offset_y)
}

fn panorama_setting() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|root| {
        PathBuf::from(root)
            .join("Threat Atlas")
            .join("screensaver-display-mode")
    })
}

pub fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args
        .first()
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "/c".into());
    if command.starts_with("/c") || command.starts_with("-c") {
        let path = panorama_setting().ok_or("Cannot find the local settings folder")?;
        let enabled = fs::read_to_string(&path).is_ok_and(|mode| mode.trim() == "panorama");
        let mode = if enabled { "Panorama" } else { "Standard" };
        let message: Vec<u16> = format!(
            "Current display mode: {mode}\n\nYes: Panorama across two matching side-by-side displays\nNo: Standard display mode\nCancel: Keep the current mode\n\nLive GreyNoise public threat-map telemetry. No cookies, browser, account or API key required.\nGreen LIVE means records arrived within 10 seconds. Routes expire after 6 seconds. Offline feeds reconnect automatically.\nThe header shows UTC and system local time. Observation times are receipt times in UTC.\nUse Windows Screen Saver Settings for idle time and lock behavior."
        )
        .encode_utf16()
        .chain(Some(0))
        .collect();
        let title: Vec<u16> = "Threat Atlas Screen Saver"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let choice = unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_YESNOCANCEL,
            )
        };
        if let Some(mode) = match choice {
            IDYES => Some("panorama"),
            IDNO => Some("standard"),
            _ => None,
        } {
            fs::create_dir_all(path.parent().ok_or("Invalid settings path")?)?;
            fs::write(path, mode)?;
        }
        return Ok(());
    }
    let preview = command == "/p" || command == "-p" || command.starts_with("/p:");
    let parent: Option<HWND> = if preview {
        let raw = command
            .split_once(':')
            .map(|(_, v)| v.to_string())
            .or_else(|| args.get(1).cloned())
            .ok_or("Preview requires a parent HWND")?;
        let hwnd = raw.parse::<usize>()? as HWND;
        if unsafe { IsWindow(hwnd) } == 0 {
            return Err("Invalid preview window".into());
        }
        Some(hwnd)
    } else {
        None
    };
    if !preview && !["/s", "-s", "--windowed"].contains(&command.as_str()) {
        return Err("Use /s, /p HWND, /c, or --windowed".into());
    }
    let windowed = command == "--windowed";
    let event_loop = EventLoop::new();
    let mut panorama_size = None;
    let mut builder = WindowBuilder::new()
        .with_title("Threat Atlas")
        .with_decorations(windowed)
        .with_skip_taskbar(!windowed)
        .with_inner_size(PhysicalSize::new(1280, 800));
    if let Some(hwnd) = parent {
        let mut rect: RECT = unsafe { std::mem::zeroed() };
        if unsafe { GetClientRect(hwnd, &mut rect) } == 0 {
            return Err("Cannot read preview bounds".into());
        }
        builder = builder
            .with_parent_window(hwnd as _)
            .with_position(PhysicalPosition::new(0, 0))
            .with_inner_size(PhysicalSize::new(
                rect.right.max(1) as u32,
                rect.bottom.max(1) as u32,
            ))
            .with_focused(false);
    } else if !windowed {
        let panorama = panorama_setting()
            .and_then(|path| fs::read_to_string(path).ok())
            .is_some_and(|mode| mode.trim() == "panorama");
        let mut monitors: Vec<_> = event_loop.available_monitors().take(3).collect();
        monitors.sort_by_key(|monitor| monitor.position().x);
        builder = match monitors.as_slice() {
            [left, right]
                if panorama
                    && left.size() == right.size()
                    && left.scale_factor() == right.scale_factor()
                    && left.position().y == right.position().y
                    && i64::from(left.position().x) + i64::from(left.size().width)
                        == i64::from(right.position().x)
                    && panorama::fits(left.size().width * 2, left.size().height) =>
            {
                let size = PhysicalSize::new(left.size().width * 2, left.size().height);
                panorama_size = Some(size);
                builder
                    .with_position(left.position())
                    .with_inner_size(size)
                    .with_always_on_top(true)
            }
            _ => builder.with_fullscreen(Some(Fullscreen::Borderless(None))),
        };
    }
    let window = Rc::new(builder.build(&event_loop)?);
    if !windowed && !preview {
        window.set_cursor_visible(false);
    }
    let context = softbuffer::Context::new(window.clone())?;
    let mut surface = softbuffer::Surface::new(&context, window.clone())?;
    let mut session = match panorama_size {
        Some(size) => Session::panorama(size.width, size.height),
        None => Session::new(),
    };
    let (frame_width, frame_height) = session.renderer.size();
    let started = Instant::now();
    let mut origin: POINT = unsafe { std::mem::zeroed() };
    unsafe {
        GetCursorPos(&mut origin);
    }
    let mut previous_keys = [false; 256];
    for (key, previous) in previous_keys.iter_mut().enumerate().skip(1) {
        *previous = unsafe { GetAsyncKeyState(key as i32) } < 0;
    }
    event_loop.run(move |event, _, flow| {
        *flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(50));
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            *flow = ControlFlow::Exit;
        }
        if let Event::MainEventsCleared = event {
            if let Some(hwnd) = parent {
                if unsafe { IsWindow(hwnd) } == 0 {
                    *flow = ControlFlow::Exit;
                    return;
                }
                let mut rect: RECT = unsafe { std::mem::zeroed() };
                if unsafe { GetClientRect(hwnd, &mut rect) } != 0 {
                    let size =
                        PhysicalSize::new(rect.right.max(1) as u32, rect.bottom.max(1) as u32);
                    if window.inner_size() != size {
                        window.set_inner_size(size);
                    }
                }
            } else if !windowed && started.elapsed() > Duration::from_secs(2) {
                let mut point: POINT = unsafe { std::mem::zeroed() };
                unsafe {
                    GetCursorPos(&mut point);
                }
                let mut pressed = false;
                for (key, previous) in previous_keys.iter_mut().enumerate().skip(1) {
                    let down = unsafe { GetAsyncKeyState(key as i32) } < 0;
                    pressed |= down && !*previous;
                    *previous = down;
                }
                if (point.x - origin.x).abs() > 5 || (point.y - origin.y).abs() > 5 || pressed {
                    *flow = ControlFlow::Exit;
                    return;
                }
            } else {
                unsafe {
                    GetCursorPos(&mut origin);
                }
                for (key, previous) in previous_keys.iter_mut().enumerate().skip(1) {
                    *previous = unsafe { GetAsyncKeyState(key as i32) } < 0;
                }
            }
            let size = window.inner_size();
            if let (Some(width), Some(height)) =
                (NonZeroU32::new(size.width), NonZeroU32::new(size.height))
            {
                if surface.resize(width, height).is_err() {
                    *flow = ControlFlow::Exit;
                    return;
                }
                let rgba = session.frame();
                if let Ok(mut buffer) = surface.buffer_mut() {
                    // The panorama frame already has the window's shape and fills it.
                    let (dw, dh, ox, oy) = if panorama_size.is_some() {
                        (size.width, size.height, 0, 0)
                    } else {
                        scaled_frame_layout(size.width, size.height)
                    };
                    let scale_x = dw as f32 / frame_width as f32;
                    let scale_y = if panorama_size.is_some() {
                        dh as f32 / frame_height as f32
                    } else {
                        scale_x
                    };
                    buffer.fill(0x00060c14);
                    for y in 0..dh {
                        let sy = ((y as f32 / scale_y) as u32).min(frame_height - 1);
                        for x in 0..dw {
                            let sx = ((x as f32 / scale_x) as u32).min(frame_width - 1);
                            let i = ((sy * frame_width + sx) * 4) as usize;
                            buffer[((y + oy) * size.width + x + ox) as usize] = ((rgba[i] as u32)
                                << 16)
                                | ((rgba[i + 1] as u32) << 8)
                                | rgba[i + 2] as u32;
                        }
                    }
                    if buffer.present().is_err() {
                        *flow = ControlFlow::Exit;
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::scaled_frame_layout;
    use threat_atlas_core::{HEIGHT, WIDTH};

    #[test]
    fn centers_and_fits_common_display_resolutions() {
        for (width, height) in [
            (1024, 768),
            (1280, 720),
            (1280, 800),
            (1920, 1080),
            (2560, 1440),
            (3440, 1440),
            (3840, 2160),
            (1080, 1920),
        ] {
            let (draw_width, draw_height, offset_x, offset_y) = scaled_frame_layout(width, height);
            assert!(draw_width <= width && draw_height <= height);
            assert!(width - draw_width - offset_x <= offset_x + 1);
            assert!(height - draw_height - offset_y <= offset_y + 1);
            let source_aspect = WIDTH as f64 / HEIGHT as f64;
            let drawn_aspect = draw_width as f64 / draw_height as f64;
            assert!((source_aspect - drawn_aspect).abs() < 0.003);
        }
    }

    #[test]
    fn uses_expected_letterboxing_for_representative_displays() {
        assert_eq!(scaled_frame_layout(1280, 720), (1152, 720, 64, 0));
        assert_eq!(scaled_frame_layout(1280, 800), (1280, 800, 0, 0));
        assert_eq!(scaled_frame_layout(1024, 768), (1024, 640, 0, 64));
        assert_eq!(scaled_frame_layout(3440, 1440), (2304, 1440, 568, 0));
        assert_eq!(scaled_frame_layout(3840, 2160), (3456, 2160, 192, 0));
    }
}
