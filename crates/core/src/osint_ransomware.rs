//! ATLAS-OSINT-007 - ransomware.live recent-victims aggregates.
//!
//! Pure functions: a bounded parser that keeps **only** country, group, sector and times of each disclosed
//! incident, and aggregation into counts. No victim name, domain, link, description or screenshot is ever kept
//! in memory, cached or shown: the application shows how much and where, not who. No network, clock or file
//! system here; the host does the request. See `docs/OSINT-TERMS-RANSOMWARE.md`.
//!
//! Proposed registry values (the entry exists in `osint.rs`): free API v2, no key, personal use only (not for
//! corporate or business use), attribution link <https://www.ransomware.live/api>, one request per 15 minutes
//! (the provider's limit is one per minute per endpoint), `non_commercial_only: true`. Keep as it is.
//!
//! Rules for the host: `GET https://api.ransomware.live/v2/recentvictims` with `Accept: application/json` and a
//! contact-bearing `User-Agent`; never request `/v2/stats` or other paths the free API does not serve as JSON
//! (some paths answer with an HTML page and status 200); stop on 429.

use serde::Deserialize;

pub const HOST: &str = "api.ransomware.live";
pub const RECENT_PATH: &str = "/v2/recentvictims";
/// The provider's limit is one request per minute per endpoint; ours is one per 15 minutes.
pub const MIN_INTERVAL_MS: u64 = 15 * 60 * 1000;
/// Largest body accepted. The real answer is about 100 KB (100 records).
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Most records read from one answer.
pub const MAX_RECORDS: usize = 500;

const MAX_NAME: usize = 64;
const MAX_SECTOR: usize = 60;
/// A record dated more than this far in the future is a data error and is ignored.
const FUTURE_SLACK_MS: u64 = 24 * 60 * 60 * 1000;

// Our floor must not be below the provider's one-minute limit.
const _: () = assert!(MIN_INTERVAL_MS >= 60 * 1000);

/// One disclosed incident, reduced to what the application may keep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incident {
    /// Two-letter country code, when the provider gave a valid one.
    pub country: Option<String>,
    /// The ransomware group's name.
    pub group: String,
    /// Industry sector; `None` when the provider says "Not Found" or gives nothing usable.
    pub sector: Option<String>,
    /// When the attack was dated by the provider, milliseconds since the Unix epoch.
    pub attack_ms: Option<u64>,
    /// When the provider first listed it.
    pub discovered_ms: Option<u64>,
}

impl Incident {
    /// The time used for windows: the attack date, else the listing date.
    pub fn when_ms(&self) -> Option<u64> {
        self.attack_ms.or(self.discovered_ms)
    }
}

/// Counts over a time window.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub total: u32,
    pub window_days: u32,
    /// Most recent incident time inside the window.
    pub newest_ms: Option<u64>,
    pub by_country: Vec<(String, u32)>,
    pub by_group: Vec<(String, u32)>,
    pub by_sector: Vec<(String, u32)>,
}

/// Why a request did not produce incidents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RansomError {
    /// 429: stop until the next regular interval (and `Retry-After` when given).
    RateLimited,
    /// Any other non-200 status.
    Http(u16),
    /// The body is not the expected JSON array (including an HTML page).
    Malformed(String),
}

// Only the fields we keep are named; serde skips every other field (victim, domain, URLs, description,
// screenshot, ...) without storing it.
#[derive(Deserialize)]
struct Raw {
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    activity: Option<String>,
    #[serde(default)]
    attackdate: Option<String>,
    #[serde(default)]
    discovered: Option<String>,
}

fn clean(s: &str, max: usize) -> Option<String> {
    let t = s.trim();
    (!t.is_empty() && t.len() <= max && !t.chars().any(char::is_control)).then(|| t.to_string())
}

fn time_ms(s: Option<&str>) -> Option<u64> {
    let t = chrono::DateTime::parse_from_rfc3339(s?.trim()).ok()?;
    u64::try_from(t.timestamp_millis()).ok()
}

/// Classify a non-200 answer from its HTTP status.
pub fn classify_status(status: u16) -> RansomError {
    if status == 429 {
        RansomError::RateLimited
    } else {
        RansomError::Http(status)
    }
}

/// Parse a `/v2/recentvictims` answer. Records without a usable group are skipped; times in the far future are
/// dropped; an HTML page or any non-array body is an error, never a panic.
pub fn parse_recent(bytes: &[u8], now_ms: u64) -> Result<Vec<Incident>, RansomError> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err(RansomError::Malformed("response too large".into()));
    }
    if bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) == Some(b'<') {
        return Err(RansomError::Malformed(
            "an HTML page instead of JSON".into(),
        ));
    }
    let rows: Vec<serde_json::Value> = serde_json::from_slice(bytes)
        .map_err(|e| RansomError::Malformed(format!("ransomware.live JSON: {e}")))?;
    let limit = now_ms.saturating_add(FUTURE_SLACK_MS);
    Ok(rows
        .into_iter()
        .take(MAX_RECORDS)
        .filter_map(|v| serde_json::from_value::<Raw>(v).ok())
        .filter_map(|r| {
            let ok_time = |t: Option<u64>| t.filter(|t| *t <= limit);
            Some(Incident {
                group: clean(r.group.as_deref()?, MAX_NAME)?,
                country: r
                    .country
                    .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase())),
                sector: r
                    .activity
                    .as_deref()
                    .and_then(|a| clean(a, MAX_SECTOR))
                    .filter(|a| a != "Not Found"),
                attack_ms: ok_time(time_ms(r.attackdate.as_deref())),
                discovered_ms: ok_time(time_ms(r.discovered.as_deref())),
            })
        })
        .collect())
}

fn top(counts: std::collections::BTreeMap<&str, u32>, n: usize) -> Vec<(String, u32)> {
    let mut v: Vec<(String, u32)> = counts
        .into_iter()
        .map(|(k, c)| (k.to_string(), c))
        .collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

/// Count incidents from the last `window_days` days (by `when_ms`). Incidents with no usable time are not
/// counted. The three lists hold the `top_n` most frequent values, most frequent first (ties by name).
pub fn summarize(incidents: &[Incident], now_ms: u64, window_days: u32, top_n: usize) -> Summary {
    let from = now_ms.saturating_sub(u64::from(window_days) * 24 * 3600 * 1000);
    let mut s = Summary {
        window_days,
        ..Summary::default()
    };
    let (mut countries, mut groups, mut sectors) = (
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::new(),
    );
    for i in incidents {
        let Some(t) = i.when_ms().filter(|t| *t >= from) else {
            continue;
        };
        s.total = s.total.saturating_add(1);
        s.newest_ms = Some(s.newest_ms.map_or(t, |n| n.max(t)));
        if let Some(c) = &i.country {
            *countries.entry(c.as_str()).or_insert(0u32) += 1;
        }
        *groups.entry(i.group.as_str()).or_insert(0u32) += 1;
        if let Some(sec) = &i.sector {
            *sectors.entry(sec.as_str()).or_insert(0u32) += 1;
        }
    }
    s.by_country = top(countries, top_n);
    s.by_group = top(groups, top_n);
    s.by_sector = top(sectors, top_n);
    s
}

/// True when a request may be sent: at least 15 minutes since the last attempt (success or failure).
pub fn fetch_due(last_attempt_ms: Option<u64>, now_ms: u64) -> bool {
    last_attempt_ms.is_none_or(|t| now_ms < t || now_ms - t >= MIN_INTERVAL_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = include_str!("../tests/fixtures/osint/ransomware/recentvictims-ok.json");
    const MESSY: &str = include_str!("../tests/fixtures/osint/ransomware/recentvictims-messy.json");
    const HTML: &str = include_str!("../tests/fixtures/osint/ransomware/html-instead-of-json.txt");
    const MALFORMED: &str = include_str!("../tests/fixtures/osint/ransomware/malformed.json");
    const OBJECT: &str = include_str!("../tests/fixtures/osint/ransomware/object-not-array.json");

    // 2026-11-14T12:00:00Z
    const NOW: u64 = 1_794_657_600_000;

    #[test]
    fn a_normal_answer_parses_to_incidents() {
        let v = parse_recent(OK.as_bytes(), NOW).unwrap();
        assert_eq!(v.len(), 8);
        assert_eq!(v[0].group, "akira");
        assert_eq!(v[0].country.as_deref(), Some("US"));
        assert_eq!(v[0].sector.as_deref(), Some("Manufacturing"));
        assert_eq!(v[3].sector, None, "Not Found is no sector");
        assert_eq!(v[4].country, None, "an empty country is none");
        assert!(v[0].attack_ms.unwrap() > v[0].attack_ms.unwrap() - 1);
        assert_eq!(v[0].when_ms(), v[0].attack_ms);
    }

    #[test]
    fn no_victim_data_survives_parsing() {
        let v = parse_recent(OK.as_bytes(), NOW).unwrap();
        let dump = format!("{v:?}");
        for secret in [
            "Example Victim Corporation",
            "exampleonionaddress",
            "example.invalid",
            "SYNTHETIC victim description",
            "e***********",
        ] {
            assert!(!dump.contains(secret), "{secret} must not be kept");
        }
    }

    #[test]
    fn messy_records_are_skipped_or_cleaned() {
        let v = parse_recent(MESSY.as_bytes(), NOW).unwrap();
        let groups: Vec<&str> = v.iter().map(|i| i.group.as_str()).collect();
        assert_eq!(
            groups,
            vec!["akira", "akira", "play", "qilin", "nogroupdate", "akira"],
            "control-character group, 200-char group and the non-object are dropped; a record with a group but no time is kept"
        );
        let undated = &v[4];
        assert_eq!(undated.when_ms(), None);
        assert_eq!(
            summarize(&v, NOW, 30, 10).total,
            4,
            "the undated record and the far-future one are not counted in any window"
        );
        assert_eq!(v[1].country, None, "'United States' is not a country code");
        let bad_time = &v[2];
        assert_eq!(bad_time.attack_ms, None, "'yesterday' is not a time");
        assert!(
            bad_time.discovered_ms.is_some(),
            "the listing time is used instead"
        );
        assert_eq!(bad_time.sector, None, "an over-long sector is dropped");
        let future = &v[3];
        assert_eq!(
            (future.attack_ms, future.discovered_ms),
            (None, None),
            "far-future times are dropped"
        );
    }

    #[test]
    fn html_and_broken_bodies_are_errors() {
        assert_eq!(
            parse_recent(HTML.as_bytes(), NOW),
            Err(RansomError::Malformed(
                "an HTML page instead of JSON".into()
            ))
        );
        assert!(matches!(
            parse_recent(MALFORMED.as_bytes(), NOW),
            Err(RansomError::Malformed(_))
        ));
        assert!(matches!(
            parse_recent(OBJECT.as_bytes(), NOW),
            Err(RansomError::Malformed(_))
        ));
        assert!(matches!(
            parse_recent(b"", NOW),
            Err(RansomError::Malformed(_))
        ));
        assert!(matches!(
            parse_recent(&vec![b' '; MAX_BODY_BYTES + 1], NOW),
            Err(RansomError::Malformed(_))
        ));
        assert_eq!(parse_recent(b"  []  ", NOW), Ok(Vec::new()));
        assert_eq!(classify_status(429), RansomError::RateLimited);
        assert_eq!(classify_status(503), RansomError::Http(503));
    }

    #[test]
    fn summaries_count_a_window_and_rank_the_top() {
        let v = parse_recent(OK.as_bytes(), NOW).unwrap();
        let s = summarize(&v, NOW, 3, 3);
        assert_eq!(
            s.total, 6,
            "the Nov 10 and Nov 9 incidents are outside a 3-day window"
        );
        assert_eq!(s.by_group[0], ("akira".to_string(), 2));
        assert_eq!(s.by_group.len(), 3);
        assert_eq!(s.by_country[0], ("US".to_string(), 3));
        assert_eq!(s.by_sector[0], ("Manufacturing".to_string(), 3));
        assert!(s.by_country.iter().all(|(c, _)| c.len() == 2));
        assert!(s.newest_ms.unwrap() > NOW - 3 * 24 * 3600 * 1000);
        let all = summarize(&v, NOW, 30, 50);
        assert_eq!(all.total, 8);
        assert_eq!(
            all.by_sector.iter().map(|(_, c)| *c).sum::<u32>(),
            7,
            "one incident has no sector"
        );
        let none = summarize(&v, NOW, 0, 3);
        assert_eq!(none.total, 0);
        assert!(summarize(&[], NOW, 7, 3).by_group.is_empty());
    }

    #[test]
    fn requests_keep_a_fifteen_minute_gap() {
        let m = 60_000u64;
        assert!(fetch_due(None, 0));
        assert!(!fetch_due(Some(1_000 * m), 1_000 * m + 14 * m));
        assert!(fetch_due(Some(1_000 * m), 1_000 * m + 15 * m));
        assert!(
            fetch_due(Some(5_000), 100),
            "clock went backwards: allow, do not stall"
        );
    }
}
