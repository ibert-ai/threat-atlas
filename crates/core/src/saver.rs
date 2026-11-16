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
}

pub struct SaverSession {
    feed: Arc<Feed>,
    view: SocView,
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
        }
    }
    /// Replace the OSINT cards (an empty list keeps the plain layout).
    pub fn set_cards(&mut self, cards: Vec<IntelCard>) {
        self.view.intel = cards;
    }
    /// Draw one frame from a snapshot and the country counts. Hosts call `frame`; this exists so the
    /// drawing can be tested without a live feed.
    pub fn draw(
        &mut self,
        snapshot: &Snapshot,
        counts: (Vec<(usize, [u64; 3])>, [u64; 3]),
    ) -> &[u8] {
        let ranked = ranked_countries(&counts.0);
        self.view.options.focus = focus_for(snapshot.now_ms, &ranked);
        self.view.draw(snapshot, counts, None, 0)
    }
    pub fn frame(&mut self) -> &[u8] {
        let snapshot = self.feed.snapshot();
        let counts = self.feed.counts();
        self.draw(&snapshot, counts)
    }
    /// Frame width in pixels (height is always 900).
    pub fn width(&self) -> u32 {
        self.view.width()
    }
    /// Lay the frame out for a window of this physical size, like the SOC view.
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
/// `session` and `osint` must be live pointers (or null, then nothing happens).
#[no_mangle]
pub unsafe extern "C" fn ta_saver_set_intel(session: *mut SaverSession, osint: *mut OsintHandle) {
    if let (Some(s), Some(o)) = (session.as_mut(), osint.as_ref()) {
        s.set_cards(osint_text::cards(
            &o.osint().view(),
            &o.osint().enabled(),
            feed::now_ms(),
        ));
    }
}
/// Frame width in pixels for a window of `window_width` pixels; height is always 900.
/// # Safety
/// `session` must be null or a live pointer from `ta_saver_new`.
#[no_mangle]
pub unsafe extern "C" fn ta_saver_fit(session: *mut SaverSession, window_width: u32) -> u32 {
    match session.as_mut() {
        Some(s) => s.fit(window_width),
        None => 0,
    }
}
/// # Safety
/// `session` must be a live pointer from `ta_saver_new`, used only on its owning UI thread.
/// The returned RGBA buffer stays valid until the next frame or `ta_saver_drop`.
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
/// `session` must be null or a pointer from `ta_saver_new`, dropped exactly once.
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
        assert_eq!(view.options.focus, None);
    }

    #[test]
    fn a_frame_is_drawn_from_a_snapshot_and_the_focus_follows_the_clock() {
        let mut session = SaverSession::new();
        let counts = (vec![(2, [5, 0, 0]), (6, [3, 0, 0])], [8, 0, 0]);
        let at = |now| {
            let state = feed::State::default();
            state.snapshot(now)
        };
        let snap = at(FOCUS_HOLD_MS);
        let len = session.draw(&snap, counts.clone()).len();
        assert_eq!(len, session.width() as usize * 900 * 4);
        assert_eq!(session.options().focus, Some(2));
        let snap = at(2 * FOCUS_HOLD_MS);
        session.draw(&snap, counts);
        assert_eq!(session.options().focus, Some(6));
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
            saver.draw(&snap(now), counts.clone());
        });
        println!(
            "classic saver: {a:.2} ms/frame, saver view: {b:.2} ms/frame, ratio {:.2}",
            b / a
        );
    }
}
