//! ATLAS-OSINT-009 - AbuseIPDB click enrichment.
//!
//! Pure functions for one-IP reputation lookups with the user's own AbuseIPDB key: which addresses may
//! be sent, the request path, a bounded parser for the CHECK answer, error classification, the
//! provider's rate-limit headers, a local daily budget and the 24 hour cache rule. No network, clock or
//! file system here; the host worker does the request. See `docs/OSINT-TERMS-ABUSEIPDB.md`.
//!
//! Proposed registry values (the entry already exists in `osint.rs`): free Individual plan for
//! non-commercial personal use, one user key per person, attribution link
//! <https://www.abuseipdb.com/api>, click only, 24 hour cache.
//!
//! Rules for the host: the key is the user's own, stored in the OS credential store, sent only in the
//! `Key` request header to `api.abuseipdb.com`, never logged, never in Git, never shared between users;
//! look up only when the user clicks an address; stop on 401 and on 429.

use serde::Deserialize;
use std::net::IpAddr;

/// Host for every request.
pub const HOST: &str = "api.abuseipdb.com";
/// Days of reports the CHECK answer covers (the provider default is 30, the maximum 365).
pub const MAX_AGE_IN_DAYS: u32 = 90;
/// How long a stored answer stays fresh: 24 hours.
pub const CACHE_TTL_MS: u64 = 24 * 60 * 60 * 1000;
/// The free Individual plan allows 1,000 checks per day (provider documentation, 14 Nov 2026).
pub const FREE_DAILY_CHECKS: u32 = 1_000;
/// Local budget per UTC day. Lower than the plan so the user's other tools sharing the key keep room.
pub const LOCAL_DAILY_BUDGET: u32 = 800;
/// Largest response body accepted. A real answer is under 1 KB.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

const MAX_HOSTNAMES: usize = 20;
const MAX_TEXT: usize = 200;
const MAX_USAGE_TYPE: usize = 100;

/// Why a lookup did not produce a result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckError {
    /// 401/403: the key is missing, wrong or revoked. Stop and ask the user; never retry.
    Auth,
    /// 429: daily or short-term limit reached. Stop until `Retry-After` / the daily reset.
    RateLimited,
    /// Any other API error, with the provider's detail text cleaned and shortened.
    Api(String),
    /// The body is not the expected JSON.
    Malformed(String),
}

/// What AbuseIPDB reports for one IP address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckResult {
    pub ip: String,
    pub is_public: bool,
    /// 0 to 100.
    pub confidence_score: u8,
    pub country_code: Option<String>,
    pub usage_type: Option<String>,
    pub isp: Option<String>,
    pub domain: Option<String>,
    pub hostnames: Vec<String>,
    pub is_tor: bool,
    pub total_reports: Option<u32>,
    pub distinct_users: Option<u32>,
    pub last_reported_at: Option<String>,
}

/// The provider's rate-limit response headers, already parsed. All fields optional.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateInfo {
    pub limit: Option<u32>,
    pub remaining: Option<u32>,
    pub retry_after_s: Option<u64>,
    pub reset_epoch_s: Option<u64>,
}

impl RateInfo {
    /// True when the next request must wait: no checks left, or the provider said to retry later.
    pub fn must_pause(&self) -> bool {
        self.remaining == Some(0) || self.retry_after_s.is_some()
    }
}

/// Counts requests per UTC day against a local budget.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DailyBudget {
    pub day: u64,
    pub used: u32,
}

impl DailyBudget {
    /// Take one request from today's budget. False when the budget is used up. The count resets when the
    /// UTC day changes; a clock that moves backwards does not reset it.
    pub fn take(&mut self, now_ms: u64, limit: u32) -> bool {
        let day = now_ms / 86_400_000;
        if day > self.day {
            self.day = day;
            self.used = 0;
        }
        if self.used >= limit {
            return false;
        }
        self.used += 1;
        true
    }
}

#[derive(Deserialize)]
struct Envelope {
    data: Option<Raw>,
    #[serde(default)]
    errors: Vec<ApiError>,
}

#[derive(Deserialize)]
struct ApiError {
    #[serde(default)]
    detail: String,
}

#[derive(Deserialize)]
struct Raw {
    #[serde(rename = "ipAddress", default)]
    ip: String,
    #[serde(rename = "isPublic", default)]
    is_public: bool,
    #[serde(rename = "abuseConfidenceScore", default)]
    score: i64,
    #[serde(rename = "countryCode", default)]
    country: Option<String>,
    #[serde(rename = "usageType", default)]
    usage_type: Option<String>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(rename = "isTor", default)]
    is_tor: bool,
    #[serde(rename = "totalReports", default)]
    total_reports: Option<i64>,
    #[serde(rename = "numDistinctUsers", default)]
    distinct_users: Option<i64>,
    #[serde(rename = "lastReportedAt", default)]
    last_reported_at: Option<String>,
}

/// True for addresses the public internet can route to. A private address must never be sent to a third
/// party. (Same rule as `osint_internetdb::is_lookup_allowed`; the integrator may merge the two copies.)
pub fn is_lookup_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || v4.is_unspecified()
                || o[0] == 0
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (18..=19).contains(&o[1]))
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || v6.to_ipv4_mapped().is_some())
        }
    }
}

/// Request path and query for one address. `None` when the address must not be sent. The address is
/// written by `IpAddr`'s own formatter, so nothing user-typed reaches the URL.
pub fn check_path(ip: IpAddr) -> Option<String> {
    is_lookup_allowed(ip)
        .then(|| format!("/api/v2/check?ipAddress={ip}&maxAgeInDays={MAX_AGE_IN_DAYS}"))
}

/// Cheap shape check for a key the user pasted: 20 to 128 ASCII letters or digits. It does not prove the
/// key is valid; only the provider can. Never log the key, even when this returns false.
pub fn looks_like_key(key: &str) -> bool {
    (20..=128).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// True while a stored answer fetched at `fetched_ms` may still be shown. The future counts as stale.
pub fn cache_fresh(fetched_ms: u64, now_ms: u64) -> bool {
    now_ms >= fetched_ms && now_ms - fetched_ms < CACHE_TTL_MS
}

/// Parse the rate-limit header values (each `None` when the header is absent or not a number).
pub fn parse_rate_headers(
    limit: Option<&str>,
    remaining: Option<&str>,
    retry_after: Option<&str>,
    reset: Option<&str>,
) -> RateInfo {
    fn num<T: std::str::FromStr>(v: Option<&str>) -> Option<T> {
        v.and_then(|s| s.trim().parse().ok())
    }
    RateInfo {
        limit: num(limit),
        remaining: num(remaining),
        retry_after_s: num::<u64>(retry_after).map(|s| s.min(7 * 24 * 3600)),
        reset_epoch_s: num(reset),
    }
}

fn clean(s: &str, max: usize) -> Option<String> {
    let t = s.trim();
    (!t.is_empty() && t.len() <= max && !t.chars().any(char::is_control)).then(|| t.to_string())
}

fn clean_opt(s: Option<String>, max: usize) -> Option<String> {
    s.and_then(|s| clean(&s, max))
}

fn count(v: Option<i64>) -> Option<u32> {
    v.and_then(|n| u32::try_from(n).ok())
}

/// Classify a non-200 answer from its HTTP status and body.
pub fn classify_error(status: u16, body: &[u8]) -> CheckError {
    match status {
        401 | 403 => CheckError::Auth,
        429 => CheckError::RateLimited,
        _ => {
            let detail = serde_json::from_slice::<Envelope>(body)
                .ok()
                .and_then(|e| e.errors.into_iter().next())
                .and_then(|e| clean(&e.detail, 300))
                .unwrap_or_else(|| format!("HTTP {status}"));
            CheckError::Api(detail)
        }
    }
}

/// Parse a CHECK answer (HTTP 200). A score outside 0 to 100 or a missing or invalid address makes the
/// whole answer an error (a wrong score must not be shown); other bad fields are dropped.
pub fn parse_check(bytes: &[u8]) -> Result<CheckResult, CheckError> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err(CheckError::Malformed("response too large".into()));
    }
    let env: Envelope = serde_json::from_slice(bytes)
        .map_err(|e| CheckError::Malformed(format!("AbuseIPDB JSON: {e}")))?;
    if let Some(first) = env.errors.into_iter().next() {
        return Err(CheckError::Api(
            clean(&first.detail, 300).unwrap_or_else(|| "API error".into()),
        ));
    }
    let raw = env
        .data
        .ok_or_else(|| CheckError::Malformed("no data object".into()))?;
    let ip: IpAddr = raw
        .ip
        .parse()
        .map_err(|_| CheckError::Malformed("missing or invalid ipAddress".into()))?;
    let score = u8::try_from(raw.score)
        .ok()
        .filter(|s| *s <= 100)
        .ok_or_else(|| CheckError::Malformed("abuseConfidenceScore out of range".into()))?;
    let country_code = raw
        .country
        .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()));
    let last_reported_at = raw
        .last_reported_at
        .filter(|s| s.len() <= 40 && chrono::DateTime::parse_from_rfc3339(s).is_ok());
    Ok(CheckResult {
        ip: ip.to_string(),
        is_public: raw.is_public,
        confidence_score: score,
        country_code,
        usage_type: clean_opt(raw.usage_type, MAX_USAGE_TYPE),
        isp: clean_opt(raw.isp, MAX_TEXT),
        domain: clean_opt(raw.domain, MAX_TEXT),
        hostnames: raw
            .hostnames
            .iter()
            .filter_map(|h| clean(h, 253))
            .take(MAX_HOSTNAMES)
            .collect(),
        is_tor: raw.is_tor,
        total_reports: count(raw.total_reports),
        distinct_users: count(raw.distinct_users),
        last_reported_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = include_str!("../tests/fixtures/osint/abuseipdb/check-ok.json");
    const MINIMAL: &str = include_str!("../tests/fixtures/osint/abuseipdb/check-minimal.json");
    const MESSY: &str = include_str!("../tests/fixtures/osint/abuseipdb/check-messy.json");
    const DAILY: &str = include_str!("../tests/fixtures/osint/abuseipdb/error-daily-limit.json");
    const AUTH: &str = include_str!("../tests/fixtures/osint/abuseipdb/error-auth.json");
    const MALFORMED: &str = include_str!("../tests/fixtures/osint/abuseipdb/malformed.json");

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn documented_example_parses() {
        let r = parse_check(OK.as_bytes()).unwrap();
        assert_eq!(r.ip, "118.25.6.39");
        assert!(r.is_public && !r.is_tor);
        assert_eq!(r.confidence_score, 100);
        assert_eq!(r.country_code.as_deref(), Some("CN"));
        assert_eq!(
            r.usage_type.as_deref(),
            Some("Data Center/Web Hosting/Transit")
        );
        assert_eq!(r.total_reports, Some(1));
        assert_eq!(r.distinct_users, Some(1));
        assert_eq!(
            r.last_reported_at.as_deref(),
            Some("2018-12-20T20:55:14+00:00")
        );
        assert!(r.hostnames.is_empty());
    }

    #[test]
    fn minimal_answer_keeps_missing_fields_empty() {
        let r = parse_check(MINIMAL.as_bytes()).unwrap();
        assert_eq!(r.ip, "8.8.8.8");
        assert_eq!(r.confidence_score, 0);
        assert_eq!(r.country_code, None);
        assert_eq!(r.isp, None);
        assert_eq!(r.last_reported_at, None);
    }

    #[test]
    fn messy_fields_are_dropped_not_shown() {
        let r = parse_check(MESSY.as_bytes()).unwrap();
        assert_eq!(r.confidence_score, 87);
        assert_eq!(r.country_code, None, "not a two-letter code");
        assert_eq!(r.usage_type, None, "over-long text");
        assert_eq!(r.total_reports, None, "negative count");
        assert_eq!(r.last_reported_at, None, "not an RFC 3339 time");
        assert_eq!(
            r.hostnames.len(),
            MAX_HOSTNAMES,
            "capped, control-character name dropped"
        );
        assert!(r.hostnames.iter().all(|h| !h.contains('\0')));
        assert!(r.is_tor);
    }

    #[test]
    fn a_wrong_score_or_address_rejects_the_whole_answer() {
        for body in [
            r#"{"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":101}}"#,
            r#"{"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":-1}}"#,
            r#"{"data":{"ipAddress":"nope","abuseConfidenceScore":5}}"#,
            r#"{"data":{"abuseConfidenceScore":5}}"#,
            r#"{}"#,
        ] {
            assert!(
                matches!(parse_check(body.as_bytes()), Err(CheckError::Malformed(_))),
                "{body}"
            );
        }
        assert!(matches!(
            parse_check(MALFORMED.as_bytes()),
            Err(CheckError::Malformed(_))
        ));
        assert!(matches!(
            parse_check(&vec![b' '; MAX_BODY_BYTES + 1]),
            Err(CheckError::Malformed(_))
        ));
    }

    #[test]
    fn errors_are_classified_without_leaking_the_key() {
        assert_eq!(classify_error(401, AUTH.as_bytes()), CheckError::Auth);
        assert_eq!(classify_error(403, b""), CheckError::Auth);
        assert_eq!(
            classify_error(429, DAILY.as_bytes()),
            CheckError::RateLimited
        );
        assert_eq!(
            classify_error(422, br#"{"errors":[{"detail":"The ip address must be a valid IP address.","status":422}]}"#),
            CheckError::Api("The ip address must be a valid IP address.".into())
        );
        assert_eq!(
            classify_error(500, b"<html>"),
            CheckError::Api("HTTP 500".into())
        );
        assert!(matches!(
            parse_check(DAILY.as_bytes()),
            Err(CheckError::Api(d)) if d.contains("Daily rate limit")
        ));
    }

    #[test]
    fn rate_headers_decide_when_to_stop() {
        let r = parse_rate_headers(Some("1000"), Some("0"), Some("29241"), Some("1545973200"));
        assert_eq!(r.limit, Some(1000));
        assert_eq!(r.remaining, Some(0));
        assert_eq!(r.retry_after_s, Some(29241));
        assert!(r.must_pause());
        let ok = parse_rate_headers(Some("1000"), Some("812"), None, None);
        assert!(!ok.must_pause());
        let junk = parse_rate_headers(Some("x"), Some(""), Some("-5"), None);
        assert_eq!(junk, RateInfo::default());
        let huge = parse_rate_headers(None, None, Some("99999999999"), None);
        assert_eq!(
            huge.retry_after_s,
            Some(7 * 24 * 3600),
            "retry-after is bounded"
        );
    }

    #[test]
    fn local_daily_budget_resets_on_a_new_utc_day_only() {
        let mut b = DailyBudget::default();
        let day = 86_400_000u64;
        let t0 = 100 * day + 5;
        for _ in 0..3 {
            assert!(b.take(t0, 3));
        }
        assert!(!b.take(t0 + 1_000, 3), "budget used up");
        assert!(
            !b.take(t0 - 50 * day, 3),
            "a clock moving backwards does not reset it"
        );
        assert!(b.take(101 * day, 3), "new UTC day");
        assert_eq!(b.used, 1);
        assert!(LOCAL_DAILY_BUDGET < FREE_DAILY_CHECKS);
    }

    #[test]
    fn only_public_addresses_are_sent_and_the_path_is_fixed() {
        for blocked in [
            "10.0.0.1",
            "192.168.0.5",
            "127.0.0.1",
            "169.254.0.1",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fc00::2",
            "::ffff:1.2.3.4",
        ] {
            assert_eq!(check_path(ip(blocked)), None, "{blocked}");
        }
        assert_eq!(
            check_path(ip("8.8.8.8")).as_deref(),
            Some("/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90")
        );
        assert!(check_path(ip("2606:4700:4700::1111"))
            .unwrap()
            .contains("ipAddress=2606:4700:4700::1111"));
    }

    #[test]
    fn key_shape_and_cache_rules() {
        assert!(looks_like_key(&"a1".repeat(40)));
        assert!(!looks_like_key("short"));
        assert!(!looks_like_key(&format!("{} ", "a".repeat(30))), "space");
        assert!(!looks_like_key(&"é".repeat(30)), "non-ASCII");
        assert!(!looks_like_key(&"a".repeat(129)));
        assert!(cache_fresh(10, 10 + CACHE_TTL_MS - 1));
        assert!(!cache_fresh(10, 10 + CACHE_TTL_MS));
        assert!(!cache_fresh(10, 9));
    }
}
