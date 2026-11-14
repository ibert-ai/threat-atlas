use crate::soc_config::{self, Motion, Settings, Terms, Theme, BUILD, VERSION};
use crate::soc_osint::{Osint, View as OsintView};
use crate::soc_radar::Radar;
use crate::soc_update::{self, Status as UpdateStatus, Updater};
use std::{
    error::Error,
    num::NonZeroU32,
    path::PathBuf,
    rc::Rc,
    time::{Duration, Instant},
};
use tao::{
    dpi::{PhysicalPosition, PhysicalSize},
    event::{ElementState, Event, MouseButton, WindowEvent},
    event_loop::{ControlFlow, EventLoop, EventLoopWindowTarget},
    keyboard::KeyCode,
    platform::windows::WindowExtWindows,
    window::{Fullscreen, Window, WindowBuilder},
};
use threat_atlas_core::{
    feed::{self, Feed, State},
    render::soc::{Motion as CoreMotion, SocView, Theme as CoreTheme},
    HEIGHT,
};
use windows_sys::Win32::{
    Foundation::{HWND, POINT},
    System::LibraryLoader::GetModuleHandleW,
    UI::{Shell::ShellExecuteW, WindowsAndMessaging::*},
};

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

pub fn show_error(text: &str) {
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide(text).as_ptr(),
            wide("Threat Atlas SOC").as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

fn consent(path: &std::path::Path) -> Result<bool, Box<dyn Error>> {
    let terms = Terms::reviewed();
    let key = terms.key(VERSION, BUILD);
    if soc_config::accepted(path, &key) {
        return Ok(true);
    }
    let text = format!(
        "Threat Atlas SOC {VERSION} (build {BUILD})\n\nCloudflare Radar data licence: CC BY-NC 4.0 (Attribution-NonCommercial).\n{}\n\n{}\n{}\n\n{}\nAcceptance does not grant commercial-use permission.\n\nGreyNoise public threat-map records are received records, not unique attacks; no endorsement implied. Windows connects to GreyNoise. If you save your own Cloudflare token, it also reads Radar aggregates from api.cloudflare.com, at most every 15 minutes. When it starts, it asks api.github.com whether a newer version exists.\n\nNo feed or worker starts until acceptance. Acceptance is required again for each new version/build or reviewed terms change.\n\nNotice fingerprint: {}\nLegal fingerprint: {}\n\nYES: I have read the linked notice/legal code and accept these terms for this version/build.\nNO: Decline and quit. The default is NO.",
        terms.notice, terms.notice_url, terms.license_url, terms.scope, terms.notice_sha256, terms.legal_sha256
    );
    let result = unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide(&text).as_ptr(),
            wide("Threat Atlas SOC - licence consent").as_ptr(),
            MB_YESNO | MB_DEFBUTTON2 | MB_ICONINFORMATION,
        )
    };
    if result != IDYES {
        return Ok(false);
    }
    soc_config::record_acceptance(path, &key)?;
    Ok(true)
}

struct Display {
    window: Rc<Window>,
    surface: softbuffer::Surface<Rc<Window>, Rc<Window>>,
    icon_loaded: bool,
}

fn displays(
    target: &EventLoopWindowTarget<()>,
    settings: &Settings,
) -> Result<Vec<Display>, Box<dyn Error>> {
    let monitors: Vec<_> = if settings.mirror_all_displays {
        target.available_monitors().take(16).map(Some).collect()
    } else {
        vec![None]
    };
    let mut result = Vec::new();
    for monitor in if monitors.is_empty() {
        vec![None]
    } else {
        monitors
    } {
        let mut builder = WindowBuilder::new()
            .with_title("AtlasSOC by Ibert Consulting - right-click or F1 for controls")
            .with_inner_size(PhysicalSize::new(settings.width, settings.height))
            .with_min_inner_size(PhysicalSize::new(640, 400))
            .with_always_on_top(settings.always_on_top);
        if monitor.is_some() || settings.fullscreen {
            builder = builder.with_fullscreen(Some(Fullscreen::Borderless(monitor)));
        }
        let window = Rc::new(builder.build(target)?);
        let icon_loaded = unsafe {
            // Win32 MAKEINTRESOURCE(1) is a resource identifier, never dereferenced as a pointer.
            let icon = LoadIconW(
                GetModuleHandleW(std::ptr::null()),
                std::ptr::without_provenance(1),
            );
            if !icon.is_null() {
                SendMessageW(
                    window.hwnd() as HWND,
                    WM_SETICON,
                    ICON_BIG as usize,
                    icon as isize,
                );
                SendMessageW(
                    window.hwnd() as HWND,
                    WM_SETICON,
                    ICON_SMALL as usize,
                    icon as isize,
                );
            }
            !icon.is_null()
        };
        let context = softbuffer::Context::new(window.clone())?;
        let surface = softbuffer::Surface::new(&context, window.clone())?;
        result.push(Display {
            window,
            surface,
            icon_loaded,
        });
    }
    Ok(result)
}

fn help(window: &Window) {
    let text = "Right-click anywhere for settings.\n\nF11: fullscreen/windowed\nSpace: freeze/resume display (the shared feed continues)\nR / C / S: Realtime / Calm / Still animation\nL: Classic / Dashboard layout\n1 / 2 / 3: malicious / suspicious / benign visibility\nM: mirror all detected displays (one shared feed)\nT: always on top\nF1: this help\nEscape: leave fullscreen/mirroring, otherwise close\n\nLeft-click a country to focus; hover shows country details in the title.\nSettings save under LocalAppData/ThreatAtlasSOC. Reset settings never resets licence acceptance.\n\nOSINT: right-click > Known exploited (KEV + EPSS), Tor exit nodes, Refresh OSINT or OSINT sources / licences.

Cloudflare Radar (optional): right-click > Set Cloudflare Radar token (collection starts when it is saved); Collect Cloudflare Radar data pauses or resumes it. Past-day aggregate shares, at most one request every 15 minutes; the token stays in Windows Credential Manager. Right-click > How to get a Cloudflare token opens the step-by-step guide.\n\nGreyNoise live receipts, not unique attacks.\nMirroring is implemented; independent display roles/spanning and physical multimonitor acceptance remain pending. No sleep or lock settings are changed.";
    unsafe {
        MessageBoxW(
            window.hwnd() as HWND,
            wide(text).as_ptr(),
            wide("Threat Atlas SOC controls").as_ptr(),
            MB_OK,
        );
    }
}

fn age(ms: u64) -> String {
    if ms == 0 {
        return "never".into();
    }
    let secs = feed::now_ms().saturating_sub(ms) / 1000;
    if secs < 120 {
        format!("{secs}s ago")
    } else if secs < 7200 {
        format!("{} min ago", secs / 60)
    } else {
        format!("{} h ago", secs / 3600)
    }
}

fn show_kev(window: &Window, view: Option<&OsintView>) {
    let Some(view) = view else {
        unsafe {
            MessageBoxW(
                window.hwnd() as HWND,
                wide("OSINT worker is not running in this mode.").as_ptr(),
                wide("Threat Atlas SOC").as_ptr(),
                MB_OK | MB_ICONINFORMATION,
            )
        };
        return;
    };
    let mut text = format!(
        "CISA Known Exploited Vulnerabilities + FIRST EPSS\nUpdated: {}\n\n",
        age(view.kev_updated_ms)
    );
    if view.kev.is_empty() {
        text.push_str("No data yet. The first refresh is scheduled within 24 hours.\n");
    }
    for item in view.kev.iter().take(12) {
        let epss = item
            .epss
            .as_ref()
            .map_or_else(|| "n/a".to_string(), |s| format!("{:.2}", s.epss));
        text.push_str(&format!(
            "{}  EPSS {}  due {}\n  {} — {}: {}\n",
            item.kev.cve, epss, item.kev.due_date, item.kev.vendor, item.kev.product, item.kev.name
        ));
    }
    text.push_str("\nSource: CISA KEV + FIRST EPSS. Context only; not confirmation that your assets are affected. Non-commercial use with attribution.");
    unsafe {
        MessageBoxW(
            window.hwnd() as HWND,
            wide(&text).as_ptr(),
            wide("Threat Atlas SOC - known exploited").as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        )
    };
}

fn show_tor(window: &Window, view: Option<&OsintView>) {
    let Some(view) = view else {
        unsafe {
            MessageBoxW(
                window.hwnd() as HWND,
                wide("OSINT worker is not running in this mode.").as_ptr(),
                wide("Threat Atlas SOC").as_ptr(),
                MB_OK | MB_ICONINFORMATION,
            )
        };
        return;
    };
    let text = format!(
        "Tor exit nodes: {}\nUpdated: {}\n\nSource: Tor Project bulk exit list. Exit nodes are public Tor infrastructure, not malicious hosts. Non-commercial use with attribution.",
        view.tor_count,
        age(view.tor_updated_ms)
    );
    unsafe {
        MessageBoxW(
            window.hwnd() as HWND,
            wide(&text).as_ptr(),
            wide("Threat Atlas SOC - Tor exits").as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        )
    };
}

fn show_osint_sources(window: &Window) {
    let mut text = String::from("Threat Atlas SOC - OSINT sources\nNon-commercial use only. Provider terms, attribution and minimum intervals are part of the contract.\n\n");
    for source in threat_atlas_core::osint::SOURCES {
        let spec = threat_atlas_core::osint::source_spec(*source);
        text.push_str(&format!(
            "{}\n  Licence: {}\n  Attribution: {}\n  Minimum interval: {} min\n  Key required: {}\n\n",
            spec.name,
            spec.licence,
            spec.attribution,
            spec.min_interval_ms / 60_000,
            if spec.requires_key { "yes" } else { "no" }
        ));
    }
    unsafe {
        MessageBoxW(
            window.hwnd() as HWND,
            wide(&text).as_ptr(),
            wide("Threat Atlas SOC - OSINT sources").as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        )
    };
}

fn menu(
    window: &Window,
    settings: &Settings,
    paused: bool,
    radar: Option<&Radar>,
    update: Option<&UpdateStatus>,
    _osint: Option<&OsintView>,
) -> u32 {
    unsafe {
        let menu = CreatePopupMenu();
        if menu.is_null() {
            return 0;
        }
        let options = [
            (1, "Fullscreen / windowed (F11)", settings.fullscreen),
            (2, "Mirror all displays (M)", settings.mirror_all_displays),
            (3, "Always on top (T)", settings.always_on_top),
            (4, "Freeze display (Space; feed continues)", paused),
            (5, "Realtime (R)", settings.motion == Motion::Realtime),
            (6, "Calm (C)", settings.motion == Motion::Calm),
            (7, "Still (S)", settings.motion == Motion::Still),
            (8, "Malicious (1)", settings.severities[0]),
            (9, "Suspicious (2)", settings.severities[1]),
            (10, "Benign (3)", settings.severities[2]),
            (11, "5 frames/second", settings.fps == 5),
            (12, "10 frames/second", settings.fps == 10),
            (13, "20 frames/second", settings.fps == 20),
            (
                17,
                "Collect Cloudflare Radar data",
                radar.is_some_and(Radar::collecting),
            ),
            (18, "Set Cloudflare Radar token...", false),
            (19, "Remove Cloudflare Radar token", false),
            (20, "Show Cloudflare Radar on the map", settings.radar_layer),
            (25, "Classic layout (L)", settings.theme == Theme::Classic),
            (
                26,
                "Dashboard layout (L)",
                settings.theme == Theme::Dashboard,
            ),
            (27, "How to get a Cloudflare token...", false),
            (14, "Reset display settings", false),
            (15, "Controls and limitations (F1)", false),
            (35, "Known exploited (KEV + EPSS)", false),
            (36, "Tor exit nodes", false),
            (37, "Refresh OSINT", false),
            (38, "OSINT sources / licences", false),
        ];
        for (id, text, checked) in options {
            AppendMenuW(
                menu,
                MF_STRING | if checked { MF_CHECKED } else { 0 },
                id,
                wide(text).as_ptr(),
            );
        }
        if let Some(update) = update {
            let enabled = matches!(update, UpdateStatus::Available(_));
            AppendMenuW(
                menu,
                MF_STRING | if enabled { 0 } else { MF_GRAYED },
                21,
                wide(&update.label()).as_ptr(),
            );
        }
        AppendMenuW(menu, MF_STRING, 16, wide("Exit").as_ptr());
        let mut point: POINT = std::mem::zeroed();
        GetCursorPos(&mut point);
        let chosen = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_RIGHTBUTTON,
            point.x,
            point.y,
            0,
            window.hwnd() as HWND,
            std::ptr::null(),
        ) as u32;
        DestroyMenu(menu);
        chosen
    }
}

/// Asks first, then hands over to the update script. Returns true when the app should close.
fn start_update(window: &Window, update: &UpdateStatus) -> bool {
    let text = format!(
        "{}\n\nAtlasSOC will close, download the installer from GitHub, check it and replace this version. Windows may ask for approval. The app then opens again and asks you to review the licence for the new version.\n\nContinue?",
        update.label().trim_end_matches("...")
    );
    let answer = unsafe {
        MessageBoxW(
            window.hwnd() as HWND,
            wide(&text).as_ptr(),
            wide("Update AtlasSOC").as_ptr(),
            MB_YESNO | MB_ICONQUESTION,
        )
    };
    if answer != IDYES {
        return false;
    }
    match soc_update::launch() {
        Ok(()) => true,
        Err(error) => {
            show_error(&format!("Cannot start the update: {error}"));
            false
        }
    }
}

/// Opens the token guide shipped next to AtlasSOC.exe (read-only HTML), or the public docs.
fn open_token_guide(window: &Window) {
    let local = std::env::current_exe()
        .ok()
        .and_then(|exe| {
            exe.parent()
                .map(|dir| dir.join("Cloudflare-Radar-Token-Guide.html"))
        })
        .filter(|path| path.is_file());
    let target = local.map_or_else(
        || "https://github.com/ibert-ai/threat-atlas/blob/main/docs/CLOUDFLARE-RADAR-TOKEN-GUIDE.md".to_string(),
        |path| path.display().to_string(),
    );
    unsafe {
        ShellExecuteW(
            window.hwnd() as HWND,
            wide("open").as_ptr(),
            wide(&target).as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
    }
}

fn paint(display: &mut Display, rgba: &[u8], frame_w: u32) -> Result<(), Box<dyn Error>> {
    let size = display.window.inner_size();
    let (Some(width), Some(height)) = (NonZeroU32::new(size.width), NonZeroU32::new(size.height))
    else {
        return Ok(());
    };
    // Bound the software backbuffer on pathological/very large desktops; never allocate a spanning canvas.
    if u64::from(size.width) * u64::from(size.height) > 34_000_000 {
        return Err("Display exceeds the 34-megapixel rendering limit".into());
    }
    display.surface.resize(width, height)?;
    let (dw, dh, ox, oy) = soc_config::layout_frame(size.width, size.height, frame_w, HEIGHT);
    if rgba.len() < frame_w as usize * HEIGHT as usize * 4 {
        return Ok(());
    }
    let mut buffer = display.surface.buffer_mut()?;
    buffer.fill(0x00060c14);
    for y in 0..dh {
        let sy = u64::from(y) * u64::from(HEIGHT) / u64::from(dh);
        for x in 0..dw {
            let sx = u64::from(x) * u64::from(frame_w) / u64::from(dw);
            let i = ((sy * u64::from(frame_w) + sx) * 4) as usize;
            buffer[((y + oy) * size.width + x + ox) as usize] =
                (u32::from(rgba[i]) << 16) | (u32::from(rgba[i + 1]) << 8) | u32::from(rgba[i + 2]);
        }
    }
    buffer.present()?;
    Ok(())
}

fn frame_point(window: &Window, point: PhysicalPosition<f64>, frame_w: u32) -> Option<(f32, f32)> {
    let size = window.inner_size();
    let (dw, dh, ox, oy) = soc_config::layout_frame(size.width, size.height, frame_w, HEIGHT);
    if dw == 0
        || dh == 0
        || point.x < f64::from(ox)
        || point.y < f64::from(oy)
        || point.x >= f64::from(ox + dw)
        || point.y >= f64::from(oy + dh)
    {
        return None;
    }
    Some((
        ((point.x - f64::from(ox)) * f64::from(frame_w) / f64::from(dw)) as f32,
        ((point.y - f64::from(oy)) * f64::from(HEIGHT) / f64::from(dh)) as f32,
    ))
}

pub fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let smoke = args.first().is_some_and(|s| s == "--smoke-test");
    if !args.is_empty() && !smoke {
        return Err("No screensaver switches in ThreatAtlas.exe. Launch without arguments; --smoke-test REPORT.json is an offline rendering test only.".into());
    }
    let report = if smoke {
        Some(PathBuf::from(
            args.get(1)
                .ok_or("--smoke-test requires an output JSON path")?,
        ))
    } else {
        None
    };
    if smoke && args.len() != 2 {
        return Err("Use --smoke-test REPORT.json".into());
    }
    let state_dir =
        PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LocalAppData is unavailable")?)
            .join("ThreatAtlasSOC");
    // Critical ordering: only the human-approved normal launch can construct Feed::shared.
    // The offline native smoke path never reads/writes real consent and never constructs a feed.
    let feed = if smoke {
        None
    } else {
        if !consent(&state_dir.join("consent.json"))? {
            return Ok(());
        }
        Some(Feed::shared())
    };
    let radar = (!smoke).then(|| Radar::start(state_dir.clone()));
    let osint = (!smoke).then(|| Osint::start(state_dir.clone()));
    let updater = (!smoke).then(Updater::start);
    let path = state_dir.join("settings.json");
    let (mut settings, warning) = if smoke {
        (Settings::default(), None)
    } else {
        Settings::load(&path)
    };
    if let Some(warning) = warning {
        show_error(&warning);
    }
    let event_loop = EventLoop::new();
    let mut windows = displays(&event_loop, &settings)?;
    let mut view = SocView::new();
    let offline = State::default();
    let mut paused = false;
    let mut rgba = Vec::new();
    let mut cursor = PhysicalPosition::new(0., 0.);
    let mut rebuild = false;
    let mut dirty = false;
    let started = Instant::now();
    let mut last_frame = Instant::now() - Duration::from_secs(1);
    let mut last_monitors = String::new();
    let mut monitor_check = Instant::now() - Duration::from_secs(3);
    let mut frames = 0u64;
    event_loop.run(move |event, target, flow| {
        *flow = ControlFlow::WaitUntil(last_frame + Duration::from_millis(1000 / u64::from(settings.fps)));
        match event {
            Event::WindowEvent { window_id, event, .. } => {
                let Some(display) = windows.iter().find(|w| w.window.id() == window_id) else { return; };
                let mut action = 0;
                match event {
                    WindowEvent::CloseRequested => *flow = ControlFlow::Exit,
                    WindowEvent::CursorMoved { position, .. } => {
                        cursor = position;
                        let hover_radar = radar.as_ref().map_or((None, 0), Radar::data).0;
                        let detail = frame_point(&display.window, position, view.width()).and_then(|(x, y)| view.inspect(x, y, hover_radar.as_deref())).and_then(|json| soc_config::inspection_label(&json));
                        display.window.set_title(&format!("AtlasSOC {VERSION}/{BUILD} by Ibert Consulting · {} · {}", if smoke { "OFFLINE TEST - NO NETWORK" } else if paused { "DISPLAY FROZEN - FEED CONTINUES" } else { "right-click or F1: controls" }, detail.unwrap_or_default()));
                    }
                    WindowEvent::MouseInput { state: ElementState::Released, button: MouseButton::Right, .. } => {
                        let osint_view = osint.as_ref().map(Osint::view);
                        action = menu(&display.window, &settings, paused, radar.as_ref(), updater.as_ref().map(Updater::status).as_ref(), osint_view.as_ref());
                    }
                    WindowEvent::MouseInput { state: ElementState::Released, button: MouseButton::Left, .. } => {
                        if let Some((x, y)) = frame_point(&display.window, cursor, view.width()) {
                            let hit = view.country_at(x, y);
                            view.options.focus = if view.options.focus == hit { None } else { hit };
                        }
                    }
                    WindowEvent::KeyboardInput { event, .. } if event.state == ElementState::Pressed && !event.repeat => {
                        action = match event.physical_key {
                            KeyCode::F11 => 1, KeyCode::KeyM => 2, KeyCode::KeyT => 3, KeyCode::Space => 4,
                            KeyCode::KeyR => 5, KeyCode::KeyC => 6, KeyCode::KeyS => 7,
                            KeyCode::Digit1 => 8, KeyCode::Digit2 => 9, KeyCode::Digit3 => 10, KeyCode::F1 => 15,
                            KeyCode::KeyL => if settings.theme == Theme::Dashboard { 25 } else { 26 },
                            KeyCode::Escape if settings.fullscreen || settings.mirror_all_displays => { settings.fullscreen = false; settings.mirror_all_displays = false; rebuild = true; dirty = true; 0 }
                            KeyCode::Escape => 16, _ => 0,
                        };
                    }
                    WindowEvent::Resized(size) if !settings.fullscreen && !settings.mirror_all_displays
                        && (640..=3840).contains(&size.width) && (400..=2160).contains(&size.height)
                        && (settings.width != size.width || settings.height != size.height) => {
                        settings.width = size.width; settings.height = size.height; dirty = true;
                    }
                    _ => {}
                }
                match action {
                    1 => { settings.fullscreen = !settings.fullscreen; settings.mirror_all_displays = false; rebuild = true; }
                    2 => { settings.mirror_all_displays = !settings.mirror_all_displays; rebuild = true; }
                    3 => { settings.always_on_top = !settings.always_on_top; for w in &windows { w.window.set_always_on_top(settings.always_on_top); } }
                    4 => paused = !paused,
                    5 => settings.motion = Motion::Realtime, 6 => settings.motion = Motion::Calm, 7 => settings.motion = Motion::Still,
                    8..=10 => settings.severities[(action - 8) as usize] = !settings.severities[(action - 8) as usize],
                    11 => settings.fps = 5, 12 => settings.fps = 10, 13 => settings.fps = 20,
                    25 => settings.theme = Theme::Classic, 26 => settings.theme = Theme::Dashboard,
                    27 => open_token_guide(&display.window),
                    35 => { let view = osint.as_ref().map(Osint::view); show_kev(&display.window, view.as_ref()); }
                    36 => { let view = osint.as_ref().map(Osint::view); show_tor(&display.window, view.as_ref()); }
                    37 => { if let Some(osint) = &osint { osint.refresh(); } }
                    38 => show_osint_sources(&display.window),
                    14 => { settings = Settings::default(); rebuild = true; }
                    15 => help(&display.window),
                    17 => { if let Some(radar) = &radar { radar.toggle_collecting(); } }
                    18 => { if let Some(radar) = &radar { radar.set_token(display.window.hwnd() as HWND); } }
                    19 => { if let Some(radar) = &radar { radar.remove_token(); } }
                    20 => settings.radar_layer = !settings.radar_layer,
                    16 => *flow = ControlFlow::Exit,
                    21 => {
                        if let Some(update) = updater.as_ref().map(Updater::status) {
                            if start_update(&display.window, &update) {
                                *flow = ControlFlow::Exit;
                            }
                        }
                    }
                    _ => {}
                }
                if action != 0 && action != 15 && action != 16 && action != 21 && action != 27 { dirty = true; }
            }
            Event::MainEventsCleared => {
                if monitor_check.elapsed() >= Duration::from_secs(2) {
                    let signature = target.available_monitors().map(|m| format!("{:?}{:?}{:?}{}", m.name(), m.position(), m.size(), m.scale_factor())).collect::<Vec<_>>().join(";");
                    if settings.mirror_all_displays && !last_monitors.is_empty() && signature != last_monitors { rebuild = true; }
                    last_monitors = signature;
                    monitor_check = Instant::now();
                }
                if rebuild {
                    match displays(target, &settings) {
                        Ok(new) => windows = new,
                        Err(error) => { show_error(&error.to_string()); *flow = ControlFlow::Exit; }
                    }
                    rebuild = false;
                }
                if dirty && !smoke {
                    if let Err(error) = settings.save(&path) { show_error(&format!("Cannot save settings: {error}")); }
                    dirty = false;
                }
                if last_frame.elapsed() >= Duration::from_millis(1000 / u64::from(settings.fps)) {
                    if !paused || rgba.is_empty() {
                        view.options.motion = match settings.motion { Motion::Calm => CoreMotion::Calm, Motion::Still => CoreMotion::Still, Motion::Realtime => CoreMotion::Realtime };
                        view.options.severities = settings.severities;
                        view.options.theme = match settings.theme { Theme::Classic => CoreTheme::Classic, Theme::Dashboard => CoreTheme::Dashboard };
                        let snapshot = feed.as_ref().map_or_else(|| offline.snapshot(feed::now_ms()), |f| f.snapshot());
                        let counts = feed.as_ref().map_or_else(|| offline.counts(feed::now_ms()), |f| f.counts());
                        // Frame shape follows the first window (mirrors of another shape letterbox).
                        if let Some(first) = windows.first() {
                            let size = first.window.inner_size();
                            view.set_width(soc_config::frame_width(size.width, size.height));
                        }
                        view.options.radar_layer = settings.radar_layer;
                        let (radar_data, radar_received) = radar.as_ref().map_or((None, 0), Radar::data);
                        view.options.radar_note = radar.as_ref().map(Radar::note);
                        rgba = view.draw(&snapshot, counts, radar_data.as_deref(), radar_received).to_vec();
                    }
                    for window in &mut windows {
                        if let Err(error) = paint(window, &rgba, (rgba.len() / 4 / HEIGHT as usize) as u32) { show_error(&error.to_string()); *flow = ControlFlow::Exit; break; }
                    }
                    frames += 1;
                    last_frame = Instant::now();
                }
                if smoke && started.elapsed() >= Duration::from_secs(3) {
                    let result = serde_json::json!({"product":"AtlasSOC", "version":VERSION, "build":BUILD, "offline_test":true, "feed_constructed":feed.is_some(), "frames_presented":frames, "windows":windows.len(), "width":view.width(), "height":HEIGHT, "consent_written":false, "sentinel_icon_loaded":windows.iter().all(|w| w.icon_loaded)});
                    if let Err(error) = soc_config::write_atomic(report.as_ref().unwrap(), &serde_json::to_vec_pretty(&result).unwrap()) { show_error(&error.to_string()); }
                    *flow = ControlFlow::Exit;
                }
            }
            Event::LoopDestroyed if !smoke && dirty => { if let Err(error) = settings.save(&path) { show_error(&format!("Cannot save settings: {error}")); } }
            _ => {}
        }
    });
}
