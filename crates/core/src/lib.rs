pub mod clock;
pub mod feed;
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
