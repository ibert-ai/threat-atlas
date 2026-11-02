pub mod clock;
mod countries;
pub mod feed;
pub mod radar;
pub mod render;
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
        Self {
            feed: Feed::shared(),
            renderer: render::Renderer::new(),
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
/// The returned RGBA buffer (ta_width x ta_height) remains valid until the next frame or ta_radar_drop.
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
}
