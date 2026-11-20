//! Non-interactive AtlasSOC view for screensaver hosts (ATLAS-SAVER-PARITY-001, package SP1).
//!
//! It reuses the SOC renderer (`render::soc::SocView`): the same map, arcs, countries, rotating OSINT
//! cards and ports block. A screensaver has no mouse or keyboard, so what a click does in AtlasSOC
//! (focus a country) becomes a timed rotation here. Decisions of 16 November 2026: no Cloudflare Radar in
//! the saver (D2), settings are read from the shared settings (D4), the existing `Session` stays as it is.

use crate::{
    feed::{self, Feed, Snapshot},
    osint_ffi::OsintHandle,
    osint_text,
    render::soc::{IntelCard, Motion, SocView, Theme},
};
use std::sync::Arc;

/// How long one country (or the overview) stays in focus before the next one.
pub const FOCUS_HOLD_MS: u64 = 20_000;
/// How many of the busiest countries take part in the rotation.
pub const FOCUS_COUNTRIES: usize = 5;

/// The busiest countries by total count, most active first; ties go to the lower index so the order is
/// the same on every run.
pub fn ranked_countries(counts: &[(usize, [u64; 3])]) -> Vec<usize> {
    let mut all: Vec<(usize, u64)> = counts
        .iter()
        .map(|(country, c)| (*country, c.iter().sum::<u64>()))
        .filter(|(_, total)| *total > 0)
        .collect();
    all.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    all.into_iter()
        .take(FOCUS_COUNTRIES)
        .map(|(country, _)| country)
        .collect()
}

/// Focus for the moment `now_ms`: the first slot is the whole-world overview, then each ranked country in
/// turn. With no ranked country the answer is always the overview.
pub fn focus_for(now_ms: u64, ranked: &[usize]) -> Option<usize> {
    if ranked.is_empty() {
        return None;
    }
    let slot = (now_ms / FOCUS_HOLD_MS) as usize % (ranked.len() + 1);
    if slot == 0 {
        None
    } else {
        Some(ranked[slot - 1])
    }
}

/// Fixed options for a screensaver: realtime motion, every severity, the classic layout, no Radar.
fn apply_saver_options(view: &mut SocView) {
    view.options.severities = [true; 3];
    view.options.motion = Motion::Realtime;
    view.options.theme = Theme::Classic;
    view.options.radar_layer = false;
    view.options.focus = None;
    view.options.saver_identity = true;
}

/// Frame width for a window's shape (the frame is always 900 high): at least the standard 1440, at most 2160
/// (2.4:1, covers 21:9 ultrawide), in steps of 8 px. This is the same rule AtlasSOC on Windows uses.
pub fn frame_width_for_window(width: u32, height: u32) -> u32 {
    if width == 0 || height == 0 {
        return 1440;
    }
    // Clamp in u64 before narrowing, so an extreme window shape cannot wrap.
    let wanted = u64::from(width) * 900 / u64::from(height) / 8 * 8;
    wanted.clamp(1440, 2160) as u32
}

pub struct SaverSession {
    feed: Arc<Feed>,
    view: SocView,
    /// Monotonic start of the session; the focus rotation counts from here so it always opens on the overview
    /// and a system clock change cannot move it.
    started: std::time::Instant,
    /// The rotation slot the held focus was chosen for, and that focus. The ranking is read only when a new
    /// slot starts, so the focus never changes in the middle of a slot.
    slot: Option<u64>,
    held_focus: Option<usize>,
}
impl Default for SaverSession {
    fn default() -> Self {
        Self::new()
    }
}
impl SaverSession {
    pub fn new() -> Self {
        let mut view = SocView::new();
        apply_saver_options(&mut view);
        Self {
            feed: Feed::shared(),
            view,
            started: std::time::Instant::now(),
            slot: None,
            held_focus: None,
        }
    }
    /// Replace the OSINT cards (an empty list keeps the plain layout).
    pub fn set_cards(&mut self, cards: Vec<IntelCard>) {
        self.view.intel = cards;
    }
    /// Pulls the current cards from a running OSINT worker. Call about once a second.
    pub fn set_intel(&mut self, osint: &crate::osint_worker::Osint) {
        self.set_cards(osint_text::cards(
            &osint.view(),
            &osint.enabled(),
            feed::now_ms(),
        ));
    }
    /// Draw one frame, `elapsed_ms` after the session started (monotonic). Hosts call `frame`; this exists so the
    /// drawing and the rotation can be tested without a live feed or a real clock.
    pub fn draw_at(
        &mut self,
        elapsed_ms: u64,
        snapshot: &Snapshot,
        counts: (Vec<(usize, [u64; 3])>, [u64; 3]),
    ) -> &[u8] {
        let slot = elapsed_ms / FOCUS_HOLD_MS;
        if self.slot != Some(slot) {
            let ranked = ranked_countries(&counts.0);
            self.held_focus = focus_for(slot * FOCUS_HOLD_MS, &ranked);
            self.slot = Some(slot);
        }
        self.view.options.focus = self.held_focus;
        self.view.draw(snapshot, counts, None, 0)
    }
    pub fn frame(&mut self) -> &[u8] {
        let snapshot = self.feed.snapshot();
        let counts = self.feed.counts();
        let elapsed = self.started.elapsed().as_millis() as u64;
        self.draw_at(elapsed, &snapshot, counts)
    }
    /// Frame width in pixels (height is always 900).
    pub fn width(&self) -> u32 {
        self.view.width()
    }
    /// Lay the frame out for a window of this physical size (width and height in pixels). Returns the frame width.
    pub fn fit_window(&mut self, width: u32, height: u32) -> u32 {
        self.view.set_width(frame_width_for_window(width, height))
    }
    /// Set the frame width directly (1440 to 4320). Hosts that know the window shape use `fit_window`.
    pub fn fit(&mut self, width: u32) -> u32 {
        self.view.set_width(width)
    }
    #[cfg(test)]
    fn options(&self) -> &crate::render::soc::Options {
        &self.view.options
    }
}

#[no_mangle]
pub extern "C" fn ta_saver_new() -> *mut SaverSession {
    std::panic::catch_unwind(|| Box::into_raw(Box::new(SaverSession::new())))
        .unwrap_or(std::ptr::null_mut())
}
/// Pulls the current OSINT cards from the worker into the view. Call about once a second.
/// # Safety
/// `session` and `osint` must be live pointers (or null, then nothing happens). Same thread as every other
/// `ta_saver_*` call on this session, never concurrently.
#[no_mangle]
pub unsafe extern "C" fn ta_saver_set_intel(session: *mut SaverSession, osint: *mut OsintHandle) {
    if let (Some(s), Some(o)) = (session.as_mut(), osint.as_ref()) {
        s.set_intel(o.osint());
    }
}
/// Lays the frame out for a window of `width` x `height` physical pixels; returns the frame width (height is always
/// 900). Prefer this to `ta_saver_fit`.
/// # Safety
/// `session` must be null or a live pointer from `ta_saver_new`. Same thread as every other `ta_saver_*` call on
/// this session, never concurrently.
#[no_mangle]
pub unsafe extern "C" fn ta_saver_fit_window(
    session: *mut SaverSession,
    width: u32,
    height: u32,
) -> u32 {
    match session.as_mut() {
        Some(s) => s.fit_window(width, height),
        None => 0,
    }
}
/// Sets the frame width directly (clamped to 1440..4320); returns it. The height is always 900.
/// # Safety
/// `session` must be null or a live pointer from `ta_saver_new`. Same thread as every other `ta_saver_*` call on
/// this session, never concurrently.
#[no_mangle]
pub unsafe extern "C" fn ta_saver_fit(session: *mut SaverSession, window_width: u32) -> u32 {
    match session.as_mut() {
        Some(s) => s.fit(window_width),
        None => 0,
    }
}
/// # Safety
/// `session` must be a live pointer from `ta_saver_new`. All `ta_saver_*` calls on one session (`set_intel`, `fit`,
/// `frame`, `drop`) must come from a single thread, never concurrently.
/// The returned RGBA buffer stays valid only until the next `ta_saver_frame`, `ta_saver_fit_window` or
/// `ta_saver_fit` (a resize can
/// reallocate the buffer and invalidate the pointer) or `ta_saver_drop`. Copy it out before calling any of them.
#[no_mangle]
pub unsafe extern "C" fn ta_saver_frame(session: *mut SaverSession) -> *const u8 {
    if session.is_null() {
        return std::ptr::null();
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        (&mut *session).frame().as_ptr()
    }))
    .unwrap_or(std::ptr::null())
}
/// # Safety
/// `session` must be null or a pointer from `ta_saver_new`, dropped exactly once, on the same thread as every other
/// `ta_saver_*` call on this session and not concurrently with one.
#[no_mangle]
pub unsafe extern "C" fn ta_saver_drop(session: *mut SaverSession) {
    if !session.is_null() {
        drop(Box::from_raw(session));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranking_orders_by_total_then_index_and_drops_empty_countries() {
        let counts = vec![
            (7, [1, 0, 0]),
            (3, [2, 2, 0]),
            (9, [0, 0, 0]),
            (5, [4, 0, 0]),
            (1, [4, 0, 0]),
        ];
        assert_eq!(ranked_countries(&counts), vec![1, 3, 5, 7]);
    }

    #[test]
    fn ranking_keeps_only_the_busiest_few() {
        let counts: Vec<(usize, [u64; 3])> = (0..20).map(|i| (i, [20 - i as u64, 0, 0])).collect();
        let ranked = ranked_countries(&counts);
        assert_eq!(ranked.len(), FOCUS_COUNTRIES);
        assert_eq!(ranked, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn rotation_starts_with_the_overview_then_walks_the_ranking_and_wraps() {
        let ranked = [4, 8];
        assert_eq!(focus_for(0, &ranked), None);
        assert_eq!(focus_for(FOCUS_HOLD_MS - 1, &ranked), None);
        assert_eq!(focus_for(FOCUS_HOLD_MS, &ranked), Some(4));
        assert_eq!(focus_for(2 * FOCUS_HOLD_MS, &ranked), Some(8));
        assert_eq!(focus_for(3 * FOCUS_HOLD_MS, &ranked), None);
        assert_eq!(focus_for(4 * FOCUS_HOLD_MS, &ranked), Some(4));
    }

    #[test]
    fn rotation_without_countries_is_always_the_overview() {
        for t in [0, 1, FOCUS_HOLD_MS, 10 * FOCUS_HOLD_MS, u64::MAX] {
            assert_eq!(focus_for(t, &[]), None);
        }
    }

    #[test]
    fn saver_options_are_fixed_and_exclude_radar() {
        let mut view = SocView::new();
        view.options.severities = [false; 3];
        view.options.motion = Motion::Still;
        view.options.radar_layer = true;
        view.options.focus = Some(3);
        apply_saver_options(&mut view);
        assert_eq!(view.options.severities, [true; 3]);
        assert_eq!(view.options.motion, Motion::Realtime);
        assert_eq!(view.options.theme, Theme::Classic);
        assert!(!view.options.radar_layer);
        assert!(view.options.saver_identity);
        assert_eq!(view.options.focus, None);
    }

    #[test]
    fn a_frame_is_drawn_and_the_focus_is_held_for_the_whole_slot() {
        let mut session = SaverSession::new();
        let a_first = (vec![(2, [5, 0, 0]), (6, [3, 0, 0])], [8, 0, 0]);
        let b_first = (vec![(2, [3, 0, 0]), (6, [5, 0, 0])], [8, 0, 0]);
        let snap = feed::State::default().snapshot(0);
        let len = session.draw_at(0, &snap, a_first.clone()).len();
        assert_eq!(len, session.width() as usize * 900 * 4);
        assert_eq!(
            session.options().focus,
            None,
            "starts on the world overview"
        );
        session.draw_at(FOCUS_HOLD_MS, &snap, a_first.clone());
        assert_eq!(session.options().focus, Some(2));
        // The ranking flips mid-slot: the focus stays until the slot ends.
        session.draw_at(FOCUS_HOLD_MS + FOCUS_HOLD_MS - 1, &snap, b_first.clone());
        assert_eq!(session.options().focus, Some(2));
        // Next slot: re-ranked with the new order, so the next ranked country (A > B flipped) is chosen.
        session.draw_at(2 * FOCUS_HOLD_MS, &snap, b_first);
        assert_eq!(session.options().focus, Some(2));
        session.draw_at(3 * FOCUS_HOLD_MS, &snap, a_first);
        assert_eq!(session.options().focus, None);
    }

    #[test]
    fn frame_width_follows_the_window_shape() {
        assert_eq!(frame_width_for_window(0, 0), 1440);
        assert_eq!(frame_width_for_window(1280, 800), 1440);
        assert_eq!(frame_width_for_window(1920, 1080), 1600);
        assert_eq!(frame_width_for_window(3440, 1440), 2144);
        assert_eq!(frame_width_for_window(7680, 1080), 2160);
    }

    #[test]
    fn extreme_window_shapes_do_not_wrap() {
        assert_eq!(frame_width_for_window(u32::MAX, 1), 2160);
        assert_eq!(frame_width_for_window(1, u32::MAX), 1440);
        assert_eq!(frame_width_for_window(u32::MAX, u32::MAX), 1440);
    }

    #[test]
    fn cards_can_be_set_and_cleared() {
        let mut session = SaverSession::new();
        session.set_cards(vec![IntelCard {
            title: "KEV".into(),
            ..IntelCard::default()
        }]);
        assert_eq!(session.view.intel.len(), 1);
        session.set_cards(Vec::new());
        assert!(session.view.intel.is_empty());
    }

    /// SP1 budget measurement: `cargo test -p threat-atlas-core --release saver_frame_time -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn saver_frame_time_against_the_classic_saver() {
        let counts = (
            vec![(2, [50, 9, 1]), (6, [30, 4, 2]), (11, [20, 1, 0])],
            [100, 14, 3],
        );
        let snap = |now| feed::State::default().snapshot(now);
        let mut classic =
            crate::render::Renderer::new_with_theme(crate::render::SaverTheme::Classic);
        let mut saver = SaverSession::new();
        let time = |f: &mut dyn FnMut(u64)| {
            f(1); // warm-up
            let t = std::time::Instant::now();
            for i in 0..120u64 {
                f(1_000 + i * 33);
            }
            t.elapsed().as_secs_f64() * 1000.0 / 120.0
        };
        let a = time(&mut |now| {
            classic.draw(&snap(now));
        });
        let b = time(&mut |now| {
            saver.draw_at(now, &snap(now), counts.clone());
        });
        println!(
            "classic saver: {a:.2} ms/frame, saver view: {b:.2} ms/frame, ratio {:.2}",
            b / a
        );
    }

    /// Memory measurement: `cargo test -p threat-atlas-core --release saver_memory -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn saver_memory_against_the_classic_saver() {
        fn rss_mb() -> f64 {
            let out = std::process::Command::new("ps")
                .args(["-o", "rss=", "-p", &std::process::id().to_string()])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<f64>()
                .unwrap_or(0.0)
                / 1024.0
        }
        let counts = (vec![(2, [50, 9, 1]), (6, [30, 4, 2])], [100, 14, 3]);
        let snap = feed::State::default().snapshot(1000);
        let base = rss_mb();
        let mut classic =
            crate::render::Renderer::new_with_theme(crate::render::SaverTheme::Classic);
        for i in 0..20 {
            classic.draw(&feed::State::default().snapshot(1000 + i * 100));
        }
        let after_classic = rss_mb();
        let mut saver = SaverSession::new();
        saver.fit_window(1920, 1080);
        for i in 0..20 {
            saver.draw_at(i * 100, &snap, counts.clone());
        }
        let after_saver = rss_mb();
        println!(
            "rss MB: start {base:.1}, classic renderer +{:.1}, saver view +{:.1}",
            after_classic - base,
            after_saver - after_classic
        );
    }
}
