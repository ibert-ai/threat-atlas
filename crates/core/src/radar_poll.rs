//! Request rules for a Cloudflare Radar worker. No network or OS code, so every rule tests offline.
use serde::{Deserialize, Serialize};

pub const MIN_INTERVAL_MS: u64 = 15 * 60 * 1000;
const MAX_BACKOFF_MS: u64 = 6 * 60 * 60 * 1000;
/// A saved time further ahead than this is damaged or a clock change, never a real cooldown.
const MAX_WAIT_MS: u64 = 24 * 60 * 60 * 1000;
pub const HOST: &str = "api.cloudflare.com";
pub const PATH: &str =
    "/client/v4/radar/attacks/layer3/top/attacks?dateRange=1d&limit=20&format=JSON";

/// Saved between runs, so a relaunch can never add a request. Holds no token and no data.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PollState {
    pub next_ms: u64,
    pub paused: bool,
    pub denied: bool,
    /// A permanent client error stops polling until the user acts.
    pub stopped: bool,
    pub received_ms: u64,
    pub failures: u32,
}

pub enum Response {
    /// A valid aggregate arrived. `quota_reset_s` is set when no quota remains.
    Data { quota_reset_s: Option<u64> },
    Status {
        code: u16,
        retry_after_s: Option<u64>,
    },
    /// Network failure, or a body that failed validation.
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    NeedsToken,
    Refused,
    Paused,
    Stopped,
    Waiting(u64),
    Current,
    Stale,
    Unavailable,
}

fn delay_ms(failures: u32, retry_after_s: Option<u64>) -> u64 {
    let backoff = (60_000u64 << failures.min(9)).min(MAX_BACKOFF_MS);
    let asked = retry_after_s
        .unwrap_or(0)
        .saturating_mul(1000)
        .min(MAX_WAIT_MS);
    backoff.max(MIN_INTERVAL_MS).max(asked)
}

impl PollState {
    pub fn sanitize(&mut self, now_ms: u64) {
        if self.next_ms > now_ms.saturating_add(MAX_WAIT_MS) {
            self.next_ms = now_ms + MIN_INTERVAL_MS;
        }
        if self.received_ms > now_ms {
            self.received_ms = 0;
        }
    }
    pub fn may_request(&self, has_token: bool, now_ms: u64) -> bool {
        has_token && !self.paused && !self.denied && !self.stopped && now_ms >= self.next_ms
    }
    /// Call and save before any I/O: a crash or relaunch mid-request still counts as a request.
    pub fn begin(&mut self, now_ms: u64) {
        self.next_ms = now_ms + MIN_INTERVAL_MS;
    }
    pub fn finish(&mut self, response: Response, now_ms: u64) {
        match response {
            Response::Data { quota_reset_s } => {
                self.failures = 0;
                self.received_ms = now_ms;
                if let Some(reset) = quota_reset_s {
                    let wait = delay_ms(0, Some(reset.saturating_add(5)));
                    self.next_ms = self.next_ms.max(now_ms + wait);
                }
            }
            Response::Status {
                code: 401 | 403, ..
            } => self.denied = true,
            Response::Status {
                code,
                retry_after_s,
            } => {
                self.failures = self.failures.saturating_add(1);
                self.next_ms = now_ms + delay_ms(self.failures, retry_after_s);
                self.stopped = (300..500).contains(&code) && code != 429;
            }
            Response::Failed => {
                self.failures = self.failures.saturating_add(1);
                self.next_ms = now_ms + delay_ms(self.failures, None);
            }
        }
    }
    /// A new token or an explicit restart clears refusal and stop; the wait stays.
    pub fn resume(&mut self) {
        self.paused = false;
        self.denied = false;
        self.stopped = false;
    }
    pub fn status(&self, has_token: bool, has_data: bool, now_ms: u64) -> Status {
        if !has_token {
            Status::NeedsToken
        } else if self.denied {
            Status::Refused
        } else if self.paused {
            Status::Paused
        } else if self.stopped {
            Status::Stopped
        } else if has_data {
            let age = now_ms.saturating_sub(self.received_ms);
            if age > crate::radar::STALE_AFTER_MS {
                Status::Stale
            } else {
                Status::Current
            }
        } else if self.failures > 0 {
            Status::Unavailable
        } else {
            Status::Waiting(self.next_ms.max(now_ms))
        }
    }
}

/// Reads the seconds until reset from a Ratelimit header, only when no quota remains.
pub fn quota_reset_s(header: &str) -> Option<u64> {
    let mut parts = header.split(';').map(str::trim);
    if !parts.clone().any(|part| part == "r=0") {
        return None;
    }
    parts.find_map(|part| part.strip_prefix("t=")?.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 1_800_000_000_000;

    #[test]
    fn a_new_install_with_a_token_requests_once_then_waits() {
        let mut s = PollState::default();
        assert!(s.may_request(true, NOW));
        s.begin(NOW);
        assert!(!s.may_request(true, NOW + MIN_INTERVAL_MS - 1));
        s.finish(
            Response::Data {
                quota_reset_s: None,
            },
            NOW,
        );
        assert!(s.may_request(true, NOW + MIN_INTERVAL_MS));
        assert_eq!(s.status(true, true, NOW), Status::Current);
    }
    #[test]
    fn no_token_or_pause_never_requests() {
        let mut s = PollState::default();
        assert!(!s.may_request(false, NOW));
        assert_eq!(s.status(false, false, NOW), Status::NeedsToken);
        s.paused = true;
        assert!(!s.may_request(true, NOW));
        assert_eq!(s.status(true, false, NOW), Status::Paused);
    }
    #[test]
    fn a_saved_interval_survives_a_restart() {
        let mut s = PollState::default();
        s.begin(NOW);
        let text = serde_json::to_string(&s).unwrap();
        assert!(!text.contains("token"));
        let saved: PollState = serde_json::from_str(&text).unwrap();
        assert!(!saved.may_request(true, NOW + 1000));
        assert_eq!(
            saved.status(true, false, NOW),
            Status::Waiting(NOW + MIN_INTERVAL_MS)
        );
    }
    #[test]
    fn refused_tokens_stop_until_a_new_one_is_saved() {
        for code in [401, 403] {
            let mut s = PollState::default();
            s.finish(
                Response::Status {
                    code,
                    retry_after_s: None,
                },
                NOW,
            );
            assert!(!s.may_request(true, NOW + 10 * MIN_INTERVAL_MS));
            assert_eq!(s.status(true, false, NOW), Status::Refused);
            s.resume();
            assert!(s.may_request(true, NOW + 10 * MIN_INTERVAL_MS));
        }
    }
    #[test]
    fn permanent_errors_stop_but_rate_limits_only_wait() {
        let mut s = PollState::default();
        s.finish(
            Response::Status {
                code: 404,
                retry_after_s: None,
            },
            NOW,
        );
        assert_eq!(s.status(true, false, NOW), Status::Stopped);
        let mut s = PollState::default();
        s.finish(
            Response::Status {
                code: 429,
                retry_after_s: Some(3600),
            },
            NOW,
        );
        assert!(!s.stopped);
        assert_eq!(s.next_ms, NOW + 3_600_000);
    }
    #[test]
    fn failures_back_off_and_recovery_resets() {
        let mut s = PollState::default();
        s.finish(Response::Failed, NOW);
        assert_eq!(s.next_ms, NOW + MIN_INTERVAL_MS);
        assert_eq!(s.status(true, false, NOW), Status::Unavailable);
        for _ in 0..20 {
            s.finish(
                Response::Status {
                    code: 500,
                    retry_after_s: None,
                },
                NOW,
            );
        }
        assert_eq!(s.next_ms, NOW + MAX_BACKOFF_MS);
        s.finish(
            Response::Data {
                quota_reset_s: None,
            },
            NOW,
        );
        assert_eq!(s.failures, 0);
    }
    #[test]
    fn stale_data_is_named() {
        let s = PollState {
            received_ms: NOW,
            ..Default::default()
        };
        assert_eq!(
            s.status(true, true, NOW + crate::radar::STALE_AFTER_MS + 1),
            Status::Stale
        );
    }
    #[test]
    fn quota_and_damaged_state_are_bounded() {
        assert_eq!(quota_reset_s("\"default\";r=0;t=2000"), Some(2000));
        assert_eq!(quota_reset_s("\"default\";r=5;t=2000"), None);
        let mut s = PollState::default();
        s.finish(
            Response::Data {
                quota_reset_s: Some(2000),
            },
            NOW,
        );
        assert_eq!(s.next_ms, NOW + 2_005_000);
        s.next_ms = u64::MAX;
        s.received_ms = u64::MAX;
        s.sanitize(NOW);
        assert_eq!((s.next_ms, s.received_ms), (NOW + MIN_INTERVAL_MS, 0));
        s.finish(
            Response::Status {
                code: 429,
                retry_after_s: Some(u64::MAX),
            },
            NOW,
        );
        assert_eq!(s.next_ms, NOW + MAX_WAIT_MS);
    }
}
