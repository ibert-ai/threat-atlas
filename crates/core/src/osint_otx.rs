//! ATLAS-OSINT-006 - AlienVault OTX (LevelBlue Open Threat Exchange) subscribed pulses.
//!
//! Pure functions: request builders, a bounded parser for one page of the "subscribed pulses" answer,
//! the rules for which pulses may be shown, error classification and a safe check of the paging link.
//! No network, clock or file system here; the host worker does the requests. See
//! `docs/OSINT-TERMS-OTX.md` for the terms read on 14 November 2026.
//!
//! Proposed registry values (the entry already exists in `osint.rs`): free for non-commercial use
//! under the user's own OTX account and key, attribution link <https://otx.alienvault.com/api>,
//! minimum interval 15 minutes, 429 stops polling. Keep the entry as it is.
//!
//! Rules for the host: the key is the user's own, stored in the OS credential store, sent only in the
//! `X-OTX-API-KEY` header to `otx.alienvault.com`, never logged, never in Git; one attempt per poll (the
//! provider's own SDK retries 429 five times, which this application must not do); stop on 401 and 429;
//! follow a paging link only through `next_path`, never directly.

use serde::Deserialize;
use serde_json::Value;
use std::net::IpAddr;

/// The only host that receives the key.
pub const HOST: &str = "otx.alienvault.com";
const PULSES_PATH: &str = "/api/v1/pulses/subscribed";
/// Pulses requested per page (the provider's SDK default).
pub const PAGE_SIZE: u32 = 50;
/// Pages followed in one poll.
pub const MAX_PAGES: u32 = 5;
/// Our floor between two polls: 15 minutes.
pub const MIN_INTERVAL_MS: u64 = 15 * 60 * 1000;
/// First poll looks back this far; later polls start at the last success minus the overlap.
pub const FIRST_LOOKBACK_MS: u64 = 24 * 60 * 60 * 1000;
pub const OVERLAP_MS: u64 = 5 * 60 * 1000;
// Polling bounds the registry and the terms note rely on.
const _: () = assert!(MIN_INTERVAL_MS >= 15 * 60 * 1000 && MAX_PAGES <= 10);
/// Largest response body accepted for one page.
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

const MAX_PULSES_PER_PAGE: usize = 100;
const MAX_NAME: usize = 200;
const MAX_DESCRIPTION: usize = 1_000;
const MAX_AUTHOR: usize = 64;
const MAX_LIST: usize = 20;
const MAX_ITEM: usize = 60;
const MAX_REFERENCES: usize = 5;
const MAX_SAMPLE_IPS: usize = 20;
const MAX_TYPE_KINDS: usize = 16;

/// Why a poll did not produce pulses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OtxError {
    /// 401/403: the key is wrong or revoked. Stop and ask the user; never retry.
    Auth,
    /// 429: throttled. Stop until `Retry-After`, and at least until the next regular interval.
    Throttled,
    /// Any other API error, with the provider's detail text cleaned and shortened.
    Api(String),
    /// The body is not the expected JSON.
    Malformed(String),
}

/// One pulse that may be shown: public, and TLP white or green.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pulse {
    pub id: String,
    pub name: String,
    pub description: String,
    pub author: String,
    pub created_ms: Option<u64>,
    pub modified_ms: Option<u64>,
    pub tags: Vec<String>,
    pub malware_families: Vec<String>,
    pub targeted_countries: Vec<String>,
    /// MITRE ATT&CK technique ids such as `T1059`.
    pub attack_ids: Vec<String>,
    /// Only `https://` links. Never fetched by the application.
    pub references: Vec<String>,
    /// Total indicators in the pulse, as reported.
    pub indicator_count: u32,
    /// Indicator kinds with their counts, most frequent first (for example `IPv4`, `domain`).
    pub indicator_types: Vec<(String, u32)>,
    /// A few public IP addresses from the indicators, for the map. Never more than 20.
    pub sample_ips: Vec<IpAddr>,
}

/// One page of the answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PulsePage {
    /// Path and query of the next page, already checked by `next_path`.
    pub next: Option<String>,
    pub pulses: Vec<Pulse>,
    /// Pulses on this page that were left out (private, restricted, malformed).
    pub skipped: u32,
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    next: Option<String>,
    #[serde(default)]
    results: Vec<Value>,
}

/// Cheap shape check for a pasted key: 32 to 128 ASCII letters or digits. Only the provider can tell
/// whether it is valid. Never log the key, even when this returns false.
pub fn looks_like_key(key: &str) -> bool {
    (32..=128).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Start of the look-back window for a poll: the last success minus a small overlap, or 24 hours before
/// `now_ms` on the first poll. A last success in the future (bad clock) counts as a first poll.
pub fn since_ms(last_success_ms: Option<u64>, now_ms: u64) -> u64 {
    match last_success_ms {
        Some(t) if t <= now_ms => t.saturating_sub(OVERLAP_MS),
        _ => now_ms.saturating_sub(FIRST_LOOKBACK_MS),
    }
}

fn iso_utc(ms: u64) -> String {
    let secs = i64::try_from(ms / 1000).unwrap_or(0);
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%S").to_string())
        .unwrap_or_else(|| "1970-01-01T00:00:00".into())
}

/// Request path and query for the first page of a poll.
pub fn first_page_path(since_ms: u64) -> String {
    format!(
        "{PULSES_PATH}?limit={PAGE_SIZE}&modified_since={}",
        iso_utc(since_ms)
    )
}

/// Turn the `next` link from an answer into a path that is safe to request, or `None`. The link comes from
/// the server, and the key travels with every request, so it must stay on the same host and the same
/// endpoint: `https://otx.alienvault.com/api/v1/pulses/subscribed?...` only, no credentials in the URL, no
/// other port, no fragment.
pub fn next_path(link: &str) -> Option<String> {
    let rest = link.strip_prefix("https://")?;
    let (authority, path_and_query) = rest.split_once('/')?;
    if authority != HOST {
        return None;
    }
    let path_and_query = format!("/{path_and_query}");
    let (path, query) = path_and_query.split_once('?')?;
    (path == PULSES_PATH
        && !query.is_empty()
        && query.len() <= 512
        && !path_and_query.contains('#')
        && query.bytes().all(|b| b.is_ascii_graphic()))
    .then_some(path_and_query)
}

/// Parse a `Retry-After` header value in seconds; a missing or bad value gives `None`, a huge one is
/// bounded to a week.
pub fn retry_after_s(header: Option<&str>) -> Option<u64> {
    header
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|s| s.min(7 * 24 * 3600))
}

fn clean(s: &str, max: usize) -> Option<String> {
    let t = s.trim();
    (!t.is_empty() && t.len() <= max && !t.chars().any(char::is_control)).then(|| t.to_string())
}

fn strings(v: &Value, max_items: usize, max_len: usize) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .filter_map(|s| clean(s, max_len))
                .take(max_items)
                .collect()
        })
        .unwrap_or_default()
}

/// OTX times look like `2026-11-14T08:12:45.123000` (UTC, no zone); a trailing `Z` is accepted.
fn time_ms(v: &Value) -> Option<u64> {
    let s = v.as_str()?.trim().trim_end_matches('Z');
    let t = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f").ok()?;
    u64::try_from(t.and_utc().timestamp_millis()).ok()
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_i64() == Some(1),
        _ => false,
    }
}

/// Addresses that the public internet can route to (the same rule as the click-lookup sources).
fn is_public(ip: IpAddr) -> bool {
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

/// Decide whether a pulse may be shown and, if so, reduce it to a bounded `Pulse`.
/// Shown: public pulses with TLP white or green. Private pulses, amber and red pulses are never kept:
/// the user agreement forbids sharing private, non-public indicators.
fn reduce(v: &Value) -> Option<Pulse> {
    let o = v.as_object()?;
    if !truthy(o.get("public")?) {
        return None;
    }
    let tlp = o
        .get("tlp")
        .or_else(|| o.get("TLP"))
        .and_then(Value::as_str)
        .unwrap_or("white")
        .to_ascii_lowercase();
    if tlp != "white" && tlp != "green" {
        return None;
    }
    let id = clean(o.get("id")?.as_str()?, 64)
        .filter(|i| i.bytes().all(|b| b.is_ascii_alphanumeric()))?;
    let name = clean(o.get("name")?.as_str()?, MAX_NAME)?;
    let indicators = o.get("indicators").and_then(Value::as_array);
    let mut kinds: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    let mut sample_ips: Vec<IpAddr> = Vec::new();
    for ind in indicators.into_iter().flatten() {
        let Some(kind) = ind
            .get("type")
            .and_then(Value::as_str)
            .and_then(|k| clean(k, 32))
        else {
            continue;
        };
        if kinds.len() < MAX_TYPE_KINDS || kinds.contains_key(&kind) {
            *kinds.entry(kind.clone()).or_insert(0) += 1;
        }
        if (kind == "IPv4" || kind == "IPv6") && sample_ips.len() < MAX_SAMPLE_IPS {
            if let Some(ip) = ind
                .get("indicator")
                .and_then(Value::as_str)
                .and_then(|s| s.trim().parse::<IpAddr>().ok())
                .filter(|ip| is_public(*ip))
            {
                if !sample_ips.contains(&ip) {
                    sample_ips.push(ip);
                }
            }
        }
    }
    let mut indicator_types: Vec<(String, u32)> = kinds.into_iter().collect();
    indicator_types.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let attack_ids = o
        .get("attack_ids")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.get("id").and_then(Value::as_str).or_else(|| x.as_str()))
                .filter_map(|s| clean(s, 16))
                .take(MAX_LIST)
                .collect()
        })
        .unwrap_or_default();
    let references = o
        .get("references")
        .map(|r| strings(r, MAX_REFERENCES, 512))
        .unwrap_or_default()
        .into_iter()
        .filter(|u| u.starts_with("https://"))
        .collect();
    let list = |key: &str| {
        o.get(key)
            .map(|v| strings(v, MAX_LIST, MAX_ITEM))
            .unwrap_or_default()
    };
    Some(Pulse {
        id,
        name,
        description: o
            .get("description")
            .and_then(Value::as_str)
            .and_then(|d| clean(d, MAX_DESCRIPTION))
            .unwrap_or_default(),
        author: o
            .get("author_name")
            .and_then(Value::as_str)
            .and_then(|a| clean(a, MAX_AUTHOR))
            .unwrap_or_default(),
        created_ms: o.get("created").and_then(time_ms),
        modified_ms: o.get("modified").and_then(time_ms),
        tags: list("tags"),
        malware_families: list("malware_families"),
        targeted_countries: list("targeted_countries"),
        attack_ids,
        references,
        indicator_count: u32::try_from(indicators.map_or(0, Vec::len)).unwrap_or(u32::MAX),
        indicator_types,
        sample_ips,
    })
}

/// Parse one page of the answer. Pulses that may not be shown or are malformed are counted in `skipped`;
/// a malformed body is an error, never a panic. The paging link is kept only if `next_path` accepts it.
pub fn parse_pulses(bytes: &[u8]) -> Result<PulsePage, OtxError> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err(OtxError::Malformed("response too large".into()));
    }
    let env: Envelope =
        serde_json::from_slice(bytes).map_err(|e| OtxError::Malformed(format!("OTX JSON: {e}")))?;
    let mut page = PulsePage {
        next: env.next.as_deref().and_then(next_path),
        ..PulsePage::default()
    };
    for v in env.results.iter().take(MAX_PULSES_PER_PAGE) {
        match reduce(v) {
            Some(p) => page.pulses.push(p),
            None => page.skipped += 1,
        }
    }
    page.skipped +=
        u32::try_from(env.results.len().saturating_sub(MAX_PULSES_PER_PAGE)).unwrap_or(u32::MAX);
    Ok(page)
}

/// Classify a non-200 answer from its HTTP status and body.
pub fn classify_error(status: u16, body: &[u8]) -> OtxError {
    match status {
        401 | 403 => OtxError::Auth,
        429 => OtxError::Throttled,
        _ => {
            let detail = serde_json::from_slice::<Value>(body)
                .ok()
                .and_then(|v| {
                    v.get("detail")
                        .and_then(Value::as_str)
                        .and_then(|d| clean(d, 300))
                })
                .unwrap_or_else(|| format!("HTTP {status}"));
            OtxError::Api(detail)
        }
    }
}

/// The `n` most mentioned malware families over a set of pulses, most frequent first (ties by name).
pub fn top_malware_families(pulses: &[Pulse], n: usize) -> Vec<(String, u32)> {
    let mut counts: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
    for p in pulses {
        for m in &p.malware_families {
            *counts.entry(m.as_str()).or_insert(0) += 1;
        }
    }
    let mut v: Vec<(String, u32)> = counts
        .into_iter()
        .map(|(k, c)| (k.to_string(), c))
        .collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = include_str!("../tests/fixtures/osint/otx/pulses-ok.json");
    const EMPTY: &str = include_str!("../tests/fixtures/osint/otx/pulses-empty.json");
    const MESSY: &str = include_str!("../tests/fixtures/osint/otx/pulses-messy.json");
    const DETAIL: &str = include_str!("../tests/fixtures/osint/otx/error-detail.json");
    const THROTTLED: &str = include_str!("../tests/fixtures/osint/otx/error-throttled.json");
    const MALFORMED: &str = include_str!("../tests/fixtures/osint/otx/malformed.json");

    #[test]
    fn a_normal_page_parses() {
        let page = parse_pulses(OK.as_bytes()).unwrap();
        assert_eq!(page.pulses.len(), 2);
        assert_eq!(page.skipped, 0);
        let p = &page.pulses[0];
        assert_eq!(p.name, "Mozi botnet activity");
        assert_eq!(p.author, "example_author");
        assert_eq!(p.malware_families, vec!["Mozi"]);
        assert_eq!(p.targeted_countries, vec!["Sweden", "United States"]);
        assert_eq!(p.attack_ids, vec!["T1059"]);
        assert_eq!(p.references, vec!["https://example.invalid/report"]);
        assert_eq!(p.indicator_count, 5);
        assert_eq!(p.modified_ms, Some(1_794_643_965_123));
        assert!(p.created_ms.unwrap() < p.modified_ms.unwrap());
        assert!(
            p.sample_ips.is_empty(),
            "203.0.113.0/24 and 2001:db8::/32 are documentation ranges, never mapped"
        );
        assert_eq!(
            p.indicator_types
                .iter()
                .map(|(k, _)| k.as_str())
                .collect::<Vec<_>>(),
            vec!["CVE", "IPv4", "IPv6", "URL", "domain"],
            "equal counts sorted by name"
        );
        assert_eq!(
            page.next.as_deref(),
            Some(
                "/api/v1/pulses/subscribed?limit=50&modified_since=2026-11-14T00%3A00%3A00&page=2"
            )
        );
        assert_eq!(
            top_malware_families(&page.pulses, 3),
            vec![("Mozi".to_string(), 1)]
        );
    }

    #[test]
    fn empty_and_failed_pages() {
        let page = parse_pulses(EMPTY.as_bytes()).unwrap();
        assert!(page.pulses.is_empty() && page.next.is_none() && page.skipped == 0);
        assert!(matches!(
            parse_pulses(MALFORMED.as_bytes()),
            Err(OtxError::Malformed(_))
        ));
        assert!(matches!(parse_pulses(b""), Err(OtxError::Malformed(_))));
        assert!(matches!(
            parse_pulses(&vec![b' '; MAX_BODY_BYTES + 1]),
            Err(OtxError::Malformed(_))
        ));
    }

    #[test]
    fn private_and_restricted_pulses_are_never_kept() {
        let page = parse_pulses(MESSY.as_bytes()).unwrap();
        let names: Vec<&str> = page.pulses.iter().map(|p| p.name.as_str()).collect();
        assert!(!names.contains(&"Private pulse"));
        assert!(!names.contains(&"Red pulse"));
        assert!(!names.contains(&"Amber pulse"));
        assert!(
            names.contains(&"Bad times"),
            "white pulse with bad times is kept, times dropped"
        );
        assert!(names.contains(&"Good one after the bad ones"));
        assert!(
            !names.iter().any(|n| n.starts_with("Many indicators")),
            "a name with a control character is dropped"
        );
        assert!(
            !names.iter().any(|n| n.len() > MAX_NAME),
            "over-long name dropped"
        );
        assert!(
            page.skipped >= 8,
            "private, red, amber, long name, control char, no id, not an object: {}",
            page.skipped
        );
        let bad = page.pulses.iter().find(|p| p.name == "Bad times").unwrap();
        assert_eq!((bad.created_ms, bad.modified_ms), (None, None));
    }

    #[test]
    fn the_paging_link_must_stay_on_otx() {
        assert!(
            parse_pulses(MESSY.as_bytes()).unwrap().next.is_none(),
            "evil.example link dropped"
        );
        let good = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&page=3";
        assert_eq!(
            next_path(good).as_deref(),
            Some("/api/v1/pulses/subscribed?limit=50&page=3")
        );
        for bad in [
            "http://otx.alienvault.com/api/v1/pulses/subscribed?page=2",
            "https://otx.alienvault.com.evil.example/api/v1/pulses/subscribed?page=2",
            "https://user:pw@otx.alienvault.com/api/v1/pulses/subscribed?page=2",
            "https://otx.alienvault.com:8443/api/v1/pulses/subscribed?page=2",
            "https://otx.alienvault.com/api/v1/pulses/my?page=2",
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            "https://otx.alienvault.com/api/v1/pulses/subscribed?",
            "https://otx.alienvault.com/api/v1/pulses/subscribed?page=2#frag",
            "https://otx.alienvault.com/api/v1/pulses/subscribed?page=2 x",
            "//otx.alienvault.com/api/v1/pulses/subscribed?page=2",
            "/api/v1/pulses/subscribed?page=2",
            "",
        ] {
            assert_eq!(next_path(bad), None, "{bad}");
        }
    }

    #[test]
    fn lists_and_indicators_are_bounded() {
        let page = parse_pulses(MESSY.as_bytes()).unwrap();
        // The pulse with 600 indicators has a control character in its name, so build the check from the
        // raw JSON of a clean one instead.
        let mut v: Value = serde_json::from_str(MESSY).unwrap();
        let many = v["results"][5].take();
        let mut m = many.as_object().unwrap().clone();
        m.insert("name".into(), Value::String("Many indicators".into()));
        let p = reduce(&Value::Object(m)).unwrap();
        assert_eq!(p.indicator_count, 600);
        assert_eq!(p.sample_ips.len(), MAX_SAMPLE_IPS);
        assert!(p.sample_ips.iter().all(|ip| is_public(*ip)));
        assert_eq!(p.tags.len(), MAX_LIST);
        assert_eq!(p.malware_families.len(), MAX_LIST);
        assert_eq!(
            p.references,
            vec!["https://example.invalid/ok"],
            "only https links"
        );
        assert_eq!(p.indicator_types.iter().map(|(_, c)| *c).sum::<u32>(), 600);
        assert!(page.pulses.len() <= MAX_PULSES_PER_PAGE);
    }

    #[test]
    fn errors_are_classified() {
        assert_eq!(classify_error(401, DETAIL.as_bytes()), OtxError::Auth);
        assert_eq!(classify_error(403, b""), OtxError::Auth);
        assert_eq!(
            classify_error(429, THROTTLED.as_bytes()),
            OtxError::Throttled
        );
        assert_eq!(
            classify_error(500, b"<html>"),
            OtxError::Api("HTTP 500".into())
        );
        assert_eq!(
            classify_error(400, br#"{"detail":"Bad modified_since."}"#),
            OtxError::Api("Bad modified_since.".into())
        );
        assert_eq!(retry_after_s(Some(" 3512 ")), Some(3512));
        assert_eq!(retry_after_s(Some("-1")), None);
        assert_eq!(retry_after_s(Some("999999999999")), Some(7 * 24 * 3600));
        assert_eq!(retry_after_s(None), None);
    }

    #[test]
    fn request_window_and_path() {
        let now = 1_794_650_000_000u64;
        assert_eq!(since_ms(None, now), now - FIRST_LOOKBACK_MS);
        assert_eq!(
            since_ms(Some(now - 1_000_000), now),
            now - 1_000_000 - OVERLAP_MS
        );
        assert_eq!(
            since_ms(Some(now + 5), now),
            now - FIRST_LOOKBACK_MS,
            "future success = first poll"
        );
        assert_eq!(since_ms(Some(10), now), 0, "no underflow");
        assert_eq!(
            first_page_path(1_794_643_200_000),
            "/api/v1/pulses/subscribed?limit=50&modified_since=2026-11-14T08:00:00"
        );
        assert!(next_path(&format!("https://{HOST}{}", first_page_path(0))).is_some());
    }

    #[test]
    fn key_shape_and_floors() {
        assert!(looks_like_key(&"ab12".repeat(16)));
        assert!(!looks_like_key("short"));
        assert!(!looks_like_key(&format!("{}-", "a".repeat(40))));
        assert!(!looks_like_key(&"a".repeat(129)));
    }
}
