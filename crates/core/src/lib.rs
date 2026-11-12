pub mod clock;
mod countries;
pub mod feed;
pub mod i18n;
pub mod radar;
pub mod radar_poll;
pub mod render;
pub mod update;
use feed::{Feed, Snapshot};
use std::sync::Arc;
pub const WIDTH: u32 = 1440;
pub const HEIGHT: u32 = 900;
pub struct Session {
    pub feed: Arc<Feed>,
    pub renderer: render::Renderer,
}
impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}
impl Session {
    pub fn new() -> Self {
        // Preview-only selectors. Debug builds only: a release saver must never change look or
        // position because of environment variables (ATLAS-CL-SEEK-HEARTBEAT-AND-THEME-REVIEW).
        #[cfg(debug_assertions)]
        let theme = match std::env::var("THREAT_ATLAS_THEME").ok().as_deref() {
            Some("seeker") => render::SaverTheme::Seeker,
            _ => render::SaverTheme::Classic,
        };
        #[cfg(not(debug_assertions))]
        let theme = render::SaverTheme::Classic;

        let mut renderer = render::Renderer::new_with_theme(theme);

        #[cfg(debug_assertions)]
        {
            let lat = std::env::var("THREAT_ATLAS_LAT")
                .ok()
                .and_then(|v| v.parse::<f64>().ok());
            let lon = std::env::var("THREAT_ATLAS_LON")
                .ok()
                .and_then(|v| v.parse::<f64>().ok());
            if let (Some(lat), Some(lon)) = (lat, lon) {
                renderer.set_local_location(lat, lon);
            }
        }
        Self {
            feed: Feed::shared(),
            renderer,
        }
    }
    /// Session with the wide two-display layout for a window of this physical size.
    pub fn panorama(width: u32, height: u32) -> Self {
        Self {
            feed: Feed::shared(),
            renderer: render::Renderer::new_panorama(width, height),
        }
    }
    pub fn frame(&mut self) -> &[u8] {
        let snap = self.feed.snapshot();
        self.renderer.draw(&snap)
    }
    pub fn snapshot(&self) -> Snapshot {
        self.feed.snapshot()
    }
}
/// Set the position the Seeker rings are centred on.
///
/// # Safety
/// `session` must be null or a pointer returned by `ta_new` that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn ta_set_location(session: *mut Session, lat: f64, lon: f64) {
    // Reject anything that is not a real coordinate: NaN, infinities and out-of-range values
    // would place the rings nowhere or on an undefined projection (CL review requirement).
    if !lat.is_finite()
        || !lon.is_finite()
        || !(-90.0..=90.0).contains(&lat)
        || !(-180.0..=180.0).contains(&lon)
    {
        return;
    }
    if let Some(session) = session.as_mut() {
        session.renderer.set_local_location(lat, lon);
    }
}

#[no_mangle]
pub extern "C" fn ta_new() -> *mut Session {
    std::panic::catch_unwind(|| Box::into_raw(Box::new(Session::new())))
        .unwrap_or(std::ptr::null_mut())
}
/// # Safety
/// `session` must be a live pointer from ta_new, used only on its owning UI thread.
/// The returned RGBA buffer remains valid until the next frame or ta_drop.
#[no_mangle]
pub unsafe extern "C" fn ta_frame(session: *mut Session) -> *const u8 {
    if session.is_null() {
        return std::ptr::null();
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        (&mut *session).frame().as_ptr()
    }))
    .unwrap_or(std::ptr::null())
}
/// # Safety
/// `session` must be null or a pointer returned by ta_new, dropped exactly once.
#[no_mangle]
pub unsafe extern "C" fn ta_drop(session: *mut Session) {
    if !session.is_null() {
        drop(Box::from_raw(session));
    }
}
#[no_mangle]
pub extern "C" fn ta_width() -> u32 {
    WIDTH
}
#[no_mangle]
pub extern "C" fn ta_height() -> u32 {
    HEIGHT
}

/// Standalone SOC session for Cloudflare Radar aggregates. Unlike `Session` it opens no feed:
/// the host app owns the Cloudflare request worker and Keychain token and passes response bodies in.
pub struct RadarSession {
    renderer: render::Renderer,
    data: Option<radar::Aggregate>,
    received_ms: u64,
}
impl Default for RadarSession {
    fn default() -> Self {
        Self::new()
    }
}
impl RadarSession {
    pub fn new() -> Self {
        Self {
            renderer: render::Renderer::new_radar(),
            data: None,
            received_ms: 0,
        }
    }
    /// Replaces the snapshot only when the body validates; a rejected body keeps prior data.
    pub fn set(&mut self, body: &[u8], received_ms: u64) -> bool {
        match radar::parse(body) {
            Ok(data) => {
                self.data = Some(data);
                self.received_ms = received_ms;
                true
            }
            Err(_) => false,
        }
    }
    pub fn frame_at(&mut self, now_ms: u64) -> &[u8] {
        self.renderer
            .draw_radar(self.data.as_ref(), self.received_ms, now_ms)
    }
}
#[no_mangle]
pub extern "C" fn ta_radar_new() -> *mut RadarSession {
    std::panic::catch_unwind(|| Box::into_raw(Box::new(RadarSession::new())))
        .unwrap_or(std::ptr::null_mut())
}
/// Returns 0 when the Cloudflare response body was accepted, -1 when rejected (prior data kept).
/// # Safety
/// `session` must be a live pointer from ta_radar_new; `body` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn ta_radar_set(
    session: *mut RadarSession,
    body: *const u8,
    len: usize,
    received_ms: u64,
) -> i32 {
    if session.is_null() || body.is_null() || len > radar::MAX_BYTES {
        return -1;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let body = std::slice::from_raw_parts(body, len);
        if (&mut *session).set(body, received_ms) {
            0
        } else {
            -1
        }
    }))
    .unwrap_or(-1)
}
/// # Safety
/// `session` must be a live pointer from ta_radar_new, used only on its owning UI thread.
/// The returned RGBA buffer (ta_soc_width x ta_height) remains valid until the next frame or ta_radar_drop.
#[no_mangle]
pub unsafe extern "C" fn ta_radar_frame(session: *mut RadarSession) -> *const u8 {
    if session.is_null() {
        return std::ptr::null();
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        (&mut *session).frame_at(feed::now_ms()).as_ptr()
    }))
    .unwrap_or(std::ptr::null())
}
/// # Safety
/// `session` must be null or a pointer returned by ta_radar_new, dropped exactly once.
#[no_mangle]
pub unsafe extern "C" fn ta_radar_drop(session: *mut RadarSession) {
    if !session.is_null() {
        drop(Box::from_raw(session));
    }
}

/// Live SOC session: GreyNoise public threat-map records (the screensaver's shared feed) plus
/// the latest Cloudflare Radar snapshot handed in by the host app, drawn calmly on one map.
pub struct SocSession {
    feed: Arc<Feed>,
    view: render::soc::SocView,
    radar: Option<radar::Aggregate>,
    radar_received_ms: u64,
}
impl Default for SocSession {
    fn default() -> Self {
        Self::new()
    }
}
impl SocSession {
    pub fn new() -> Self {
        Self {
            feed: Feed::shared(),
            view: render::soc::SocView::new(),
            radar: None,
            radar_received_ms: 0,
        }
    }
    pub fn set_radar(&mut self, body: &[u8], received_ms: u64) -> bool {
        match radar::parse(body) {
            Ok(data) => {
                self.radar = Some(data);
                self.radar_received_ms = received_ms;
                true
            }
            Err(_) => false,
        }
    }
    pub fn frame(&mut self) -> &[u8] {
        let snapshot = self.feed.snapshot();
        let counts = self.feed.counts();
        self.view.draw(
            &snapshot,
            counts,
            self.radar.as_ref(),
            self.radar_received_ms,
        )
    }
}
#[no_mangle]
pub extern "C" fn ta_soc_new() -> *mut SocSession {
    std::panic::catch_unwind(|| Box::into_raw(Box::new(SocSession::new())))
        .unwrap_or(std::ptr::null_mut())
}
/// Returns 0 when the Cloudflare response body was accepted, -1 when rejected (prior data kept).
/// # Safety
/// `session` must be a live pointer from ta_soc_new; `body` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn ta_soc_set_radar(
    session: *mut SocSession,
    body: *const u8,
    len: usize,
    received_ms: u64,
) -> i32 {
    if session.is_null() || body.is_null() || len > radar::MAX_BYTES {
        return -1;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let body = std::slice::from_raw_parts(body, len);
        if (&mut *session).set_radar(body, received_ms) {
            0
        } else {
            -1
        }
    }))
    .unwrap_or(-1)
}
/// `severities`: bit 0 malicious, bit 1 suspicious, bit 2 benign.
/// `motion`: 0 calm (default), 1 still, 2 realtime; anything else is calm.
/// # Safety
/// `session` must be null or a live pointer from ta_soc_new.
#[no_mangle]
pub unsafe extern "C" fn ta_soc_set_options(
    session: *mut SocSession,
    severities: u32,
    motion: u32,
) {
    if let Some(session) = session.as_mut() {
        let options = &mut session.view.options;
        options.severities = [
            severities & 1 != 0,
            severities & 2 != 0,
            severities & 4 != 0,
        ];
        options.motion = match motion {
            1 => render::soc::Motion::Still,
            2 => render::soc::Motion::Realtime,
            _ => render::soc::Motion::Calm,
        };
    }
}
/// Cloudflare Radar icon layer: `enabled` 0/1, plus origin codes to hide as comma-separated ASCII
/// (e.g. "BR,HK"; empty or null hides none). Invalid or oversized input leaves the hidden list empty.
/// # Safety
/// `session` must be null or a live pointer from ta_soc_new; `hidden` must point to `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ta_soc_set_radar_layer(
    session: *mut SocSession,
    enabled: u32,
    hidden: *const u8,
    len: usize,
) {
    let Some(session) = session.as_mut() else {
        return;
    };
    let codes = if hidden.is_null() || len == 0 || len > 4096 {
        Vec::new()
    } else {
        std::str::from_utf8(std::slice::from_raw_parts(hidden, len))
            .map(radar_codes)
            .unwrap_or_default()
    };
    let options = &mut session.view.options;
    options.radar_layer = enabled != 0;
    options.radar_hidden = codes;
}
/// Layout theme: 0 classic (default), 1 dashboard; anything else is classic.
/// # Safety
/// `session` must be null or a live pointer from ta_soc_new.
#[no_mangle]
pub unsafe extern "C" fn ta_soc_set_theme(session: *mut SocSession, theme: u32) {
    if let Some(session) = session.as_mut() {
        session.view.options.theme = match theme {
            1 => render::soc::Theme::Dashboard,
            _ => render::soc::Theme::Classic,
        };
    }
}
/// Frame width for the macOS window's shape: at least 1440 (the standard 16:10 layout, unchanged),
/// at most 4320; height stays 900. Wider frames keep the map size, move the right-hand panels to
/// the right edge and add a top-countries column. Returns the width in use (0 for null).
/// # Safety
/// `session` must be null or a live pointer from ta_soc_new, used only on its owning UI thread.
#[no_mangle]
pub unsafe extern "C" fn ta_soc_set_width(session: *mut SocSession, width: u32) -> u32 {
    session
        .as_mut()
        .map_or(0, |session| session.view.set_width(width))
}
/// Current frame width of a SOC session (0 for null); the height is always ta_height().
/// # Safety
/// `session` must be null or a live pointer from ta_soc_new.
#[no_mangle]
pub unsafe extern "C" fn ta_soc_width(session: *const SocSession) -> u32 {
    session.as_ref().map_or(0, |session| session.view.width())
}
/// Up to 100 trimmed upper-case codes of at most 8 ASCII alphanumerics each.
fn radar_codes(list: &str) -> Vec<String> {
    list.split(',')
        .map(|code| code.trim().to_uppercase())
        .filter(|code| {
            !code.is_empty() && code.len() <= 8 && code.chars().all(|c| c.is_ascii_alphanumeric())
        })
        .take(100)
        .collect()
}
/// Focus the country under a frame point (1440x900 coordinates); the same country or open
/// water clears focus. Returns the focused country index or -1.
/// # Safety
/// `session` must be null or a live pointer from ta_soc_new.
#[no_mangle]
pub unsafe extern "C" fn ta_soc_focus_at(session: *mut SocSession, x: f32, y: f32) -> i32 {
    let Some(session) = session.as_mut() else {
        return -1;
    };
    let hit = session.view.country_at(x, y);
    let options = &mut session.view.options;
    options.focus = if hit == options.focus { None } else { hit };
    options.focus.map_or(-1, |index| index as i32)
}
/// Writes JSON details for the country under a frame point into `out` (UTF-8, no terminator).
/// Returns the byte length, or 0 when there is no country or `capacity` is too small.
/// # Safety
/// `session` must be null or a live pointer from ta_soc_new; `out` must hold `capacity` bytes.
#[no_mangle]
pub unsafe extern "C" fn ta_soc_inspect(
    session: *mut SocSession,
    x: f32,
    y: f32,
    out: *mut u8,
    capacity: usize,
) -> usize {
    let Some(session) = session.as_ref() else {
        return 0;
    };
    if out.is_null() {
        return 0;
    }
    match session.view.inspect(x, y, session.radar.as_ref()) {
        Some(json) if json.len() <= capacity => {
            std::ptr::copy_nonoverlapping(json.as_ptr(), out, json.len());
            json.len()
        }
        _ => 0,
    }
}
/// # Safety
/// `session` must be a live pointer from ta_soc_new, used only on its owning UI thread.
/// The returned RGBA buffer (ta_soc_width x ta_height) remains valid until the next frame or ta_soc_drop.
#[no_mangle]
pub unsafe extern "C" fn ta_soc_frame(session: *mut SocSession) -> *const u8 {
    if session.is_null() {
        return std::ptr::null();
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        (&mut *session).frame().as_ptr()
    }))
    .unwrap_or(std::ptr::null())
}
/// # Safety
/// `session` must be null or a pointer returned by ta_soc_new, dropped exactly once.
#[no_mangle]
pub unsafe extern "C" fn ta_soc_drop(session: *mut SocSession) {
    if !session.is_null() {
        drop(Box::from_raw(session));
    }
}

#[cfg(test)]
mod radar_session_tests {
    use super::*;
    // Synthetic fixture only: never presented as telemetry.
    const BODY: &str = r#"{"success":true,"result":{"meta":{"lastUpdated":"2026-01-01T00:00:00Z","normalization":"PERCENTAGE","dateRange":[{"startTime":"2025-12-31T00:00:00Z","endTime":"2026-01-01T00:00:00Z"}]},"top_0":[{"originCountryAlpha2":"BR","originCountryName":"Brazil","value":"7.5"},{"originCountryAlpha2":"HK","originCountryName":"Hong Kong","value":"2.1"},{"originCountryAlpha2":"XX","originCountryName":"Unknown","value":"1.0"}]}}"#;
    fn pixel(frame: &[u8], lon: f64, lat: f64) -> [u8; 4] {
        let (x, y) = render::xy(lon, lat);
        let i = (y as usize * WIDTH as usize + x as usize) * 4;
        [frame[i], frame[i + 1], frame[i + 2], frame[i + 3]]
    }
    #[test]
    fn shades_reported_origins_only() {
        let mut session = RadarSession::new();
        let empty = session.frame_at(1000).to_vec();
        assert!(session.set(BODY.as_bytes(), 1000));
        let frame = session.frame_at(2000).to_vec();
        // Brazil interior gains amber; an unreported country (Australia) is unchanged.
        let (before, after) = (pixel(&empty, -51.9, -10.), pixel(&frame, -51.9, -10.));
        assert!(
            after[0] > before[0] + 40 && after[1] > before[1] + 20,
            "{before:?} -> {after:?}"
        );
        assert_eq!(pixel(&empty, 134., -25.), pixel(&frame, 134., -25.));
        // Hong Kong is not in the 1:110m polygons and gets a ring marker instead.
        assert!(pixel(&frame, 114.2, 22.3)[0] > pixel(&empty, 114.2, 22.3)[0] + 40);
    }
    #[test]
    fn stale_snapshot_is_dimmed_and_bad_bodies_keep_prior_data() {
        let mut session = RadarSession::new();
        assert!(session.set(BODY.as_bytes(), 1000));
        let fresh = pixel(session.frame_at(2000), -51.9, -10.);
        let stale = pixel(session.frame_at(1001 + radar::STALE_AFTER_MS), -51.9, -10.);
        assert!(
            stale[0] < fresh[0],
            "stale {stale:?} should be dimmer than {fresh:?}"
        );
        assert!(!session.set(b"{\"success\":false}", 5000));
        assert_eq!(session.received_ms, 1000);
        assert_eq!(session.data.as_ref().map(|d| d.rows.len()), Some(3));
    }
    #[test]
    fn ffi_rejects_null_oversize_and_invalid_input() {
        unsafe {
            assert_eq!(
                ta_radar_set(std::ptr::null_mut(), BODY.as_ptr(), BODY.len(), 0),
                -1
            );
            assert!(ta_radar_frame(std::ptr::null_mut()).is_null());
            ta_radar_drop(std::ptr::null_mut());
            let session = ta_radar_new();
            assert!(!session.is_null());
            assert_eq!(ta_radar_set(session, std::ptr::null(), 0, 0), -1);
            assert_eq!(
                ta_radar_set(session, BODY.as_ptr(), radar::MAX_BYTES + 1, 0),
                -1
            );
            assert_eq!(ta_radar_set(session, b"nope".as_ptr(), 4, 0), -1);
            assert_eq!(ta_radar_set(session, BODY.as_ptr(), BODY.len(), 1000), 0);
            assert!(!ta_radar_frame(session).is_null());
            ta_radar_drop(session);
        }
    }
    #[test]
    fn radar_layer_codes_are_bounded_and_normalised() {
        assert_eq!(
            radar_codes(" br, HK ,,x y,toolongcode,US"),
            vec!["BR", "HK", "US"]
        );
        let mut session = RadarSession::new();
        assert!(session.set(BODY.as_bytes(), 1));
        unsafe {
            ta_soc_set_radar_layer(std::ptr::null_mut(), 1, b"BR".as_ptr(), 2);
        }
    }
}
