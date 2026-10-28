use std::{
    error::Error,
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
use threat_atlas_core::{Session, HEIGHT, WIDTH};
use windows_sys::Win32::{
    Foundation::{HWND, POINT, RECT},
    UI::{
        Input::KeyboardAndMouse::GetAsyncKeyState,
        WindowsAndMessaging::{
            GetClientRect, GetCursorPos, IsWindow, MessageBoxW, MB_ICONERROR, MB_OK,
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

pub fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args
        .first()
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "/c".into());
    if command.starts_with("/c") || command.starts_with("-c") {
        let message: Vec<u16> = "Threat Atlas 0.2 — Native SOC display\n\nLive GreyNoise public threat-map telemetry.\nNo cookies, browser, account or API key required.\n\nGreen LIVE means records arrived within 10 seconds.\nRoutes expire after 6 seconds. Offline feeds reconnect automatically.\nTimes are local receipt times displayed in UTC.\n\nUse Windows Screen Saver Settings for idle time and lock behavior.".encode_utf16().chain(Some(0)).collect();
        let title: Vec<u16> = "Threat Atlas".encode_utf16().chain(Some(0)).collect();
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OK,
            );
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
        builder = builder.with_fullscreen(Some(Fullscreen::Borderless(None)));
    }
    let window = Rc::new(builder.build(&event_loop)?);
    if !windowed && !preview {
        window.set_cursor_visible(false);
    }
    let context = softbuffer::Context::new(window.clone())?;
    let mut surface = softbuffer::Surface::new(&context, window.clone())?;
    let mut session = Session::new();
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
                    let scale =
                        (size.width as f32 / WIDTH as f32).min(size.height as f32 / HEIGHT as f32);
                    let dw = (WIDTH as f32 * scale) as u32;
                    let dh = (HEIGHT as f32 * scale) as u32;
                    let ox = (size.width - dw) / 2;
                    let oy = (size.height - dh) / 2;
                    buffer.fill(0x00060c14);
                    for y in 0..dh {
                        let sy = ((y as f32 / scale) as u32).min(HEIGHT - 1);
                        for x in 0..dw {
                            let sx = ((x as f32 / scale) as u32).min(WIDTH - 1);
                            let i = ((sy * WIDTH + sx) * 4) as usize;
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
