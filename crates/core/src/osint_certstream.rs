//! ATLAS-OSINT-011 - certificate-transparency watch-list (Cert Spotter v1).
//!
//! Replaces the CertStream stream, which is dead (see `docs/OSINT-CT-RESEARCH.md`). The owner approved
//! this change on 14 November 2026. The user lists their own domains; the host polls Cert Spotter at most
//! once an hour per domain and shows new certificates. Pure functions only: domain checks, the request
//! path, a bounded parser, error classification, a local hourly budget and the poll rule. No network,
//! clock or file system here. See `docs/OSINT-TERMS-CERTSPOTTER.md`.
//!
//! Proposed registry values: name "Cert Spotter (CT watch-list)", user's own free API key required,
//! non-commercial personal use per the provider's free tier, minimum interval 1 hour per domain,
//! attribution "SSLMate Cert Spotter" with link <https://sslmate.com/certspotter/>.
//!
//! Rules for the host: the key is the user's own, kept in the OS credential store, sent only as
//! `Authorization: Bearer` to `api.certspotter.com`, never logged, never in Git, never shared.
//! Only domains the user typed are sent. Stop on 401/403 and on 429.

use serde_json::Value;
use std::net::IpAddr;

/// Host for every request.
pub const HOST: &str = "api.certspotter.com";
/// At most this many watched domains (the free tier allows 10 full-domain queries per hour).
pub const MAX_WATCHED: usize = 10;
/// Poll each domain at most once per hour.
pub const POLL_INTERVAL_MS: u64 = 60 * 60 * 1000;
/// Free tier: full-domain queries per hour (provider documentation, 14 Nov 2026).
pub const FREE_FULL_DOMAIN_QUERIES_PER_HOUR: u32 = 10;
/// Local budget per UTC hour, below the plan limit so the user's other tools sharing the key keep room.
pub const LOCAL_HOURLY_BUDGET: u32 = 8;
/// Largest response body accepted.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Most issuances kept from one page.
pub const MAX_ISSUANCES: usize = 200;

// The local budget must stay below the plan limit.
const _: () = assert!(LOCAL_HOURLY_BUDGET < FREE_FULL_DOMAIN_QUERIES_PER_HOUR);
const _: () = assert!(MAX_WATCHED <= FREE_FULL_DOMAIN_QUERIES_PER_HOUR as usize);

const MAX_NAMES: usize = 50;
const MAX_TEXT: usize = 120;
const MAX_ID: usize = 40;

/// Why a poll did not produce a result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CtError {
    /// 401/403: key missing, wrong or revoked. Stop and ask the user; never retry.
    Auth,
    /// 429 or `rate_limited`: stop until `Retry-After`.
    RateLimited,
    /// Any other API error, with the provider's text cleaned and shortened.
    Api(String),
    /// The body is not the expected JSON.
    Malformed(String),
}

/// One certificate issuance seen in the CT logs for a watched domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issuance {
    /// Opaque provider id; also the `after` cursor.
    pub id: String,
    pub dns_names: Vec<String>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub revoked: Option<bool>,
}

fn valid_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Normalise a domain the user typed: lower case, one trailing dot removed, ASCII letters, digits and
/// hyphens only (write internationalised names in Punycode), at least two labels, not an IP address,
/// no wildcard. `None` when it cannot be sent.
pub fn normalize_domain(input: &str) -> Option<String> {
    let s = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 || s.parse::<IpAddr>().is_ok() {
        return None;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 || !labels.iter().all(|l| valid_label(l)) {
        return None;
    }
    if labels.last()?.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(s)
}

fn valid_dns_name(s: &str) -> bool {
    s == s.trim() && normalize_domain(s.strip_prefix("*.").unwrap_or(s)).is_some()
}

fn valid_cursor(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_ID && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Request path and query for one watched domain, optionally continuing after a cursor. `None` when the
/// domain or cursor is not acceptable, so nothing user-typed reaches the URL unchecked.
pub fn watch_path(domain: &str, after: Option<&str>) -> Option<String> {
    let d = normalize_domain(domain)?;
    let mut p =
        format!("/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names&expand=issuer");
    if let Some(a) = after {
        if !valid_cursor(a) {
            return None;
        }
        p.push_str("&after=");
        p.push_str(a);
    }
    Some(p)
}

fn clean_text(s: &str) -> Option<String> {
    let t: String = s.chars().filter(|c| !c.is_control()).collect();
    let t: String = t.trim().chars().take(MAX_TEXT).collect();
    (!t.is_empty()).then_some(t)
}

fn valid_time(v: Option<&Value>) -> Option<String> {
    let s = v?.as_str()?;
    chrono::DateTime::parse_from_rfc3339(s).ok()?;
    Some(s.to_string())
}

fn parse_one(v: &Value) -> Option<Issuance> {
    let o = v.as_object()?;
    let id = o.get("id")?.as_str()?;
    if !valid_cursor(id) {
        return None;
    }
    let mut dns_names: Vec<String> = Vec::new();
    for n in o.get("dns_names")?.as_array()? {
        if let Some(s) = n.as_str().filter(|s| valid_dns_name(s)) {
            let s = s.to_ascii_lowercase();
            if !dns_names.contains(&s) && dns_names.len() < MAX_NAMES {
                dns_names.push(s);
            }
        }
    }
    if dns_names.is_empty() {
        return None;
    }
    Some(Issuance {
        id: id.to_string(),
        dns_names,
        issuer: o
            .get("issuer")
            .and_then(|i| i.get("friendly_name"))
            .and_then(Value::as_str)
            .and_then(clean_text),
        not_before: valid_time(o.get("not_before")),
        not_after: valid_time(o.get("not_after")),
        revoked: o.get("revoked").and_then(Value::as_bool),
    })
}

/// Parse one page of the issuances answer. Entries without a valid id or any valid name are dropped;
/// names, text and the list are bounded. An error object becomes a `CtError`.
pub fn parse_issuances(body: &[u8]) -> Result<Vec<Issuance>, CtError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(CtError::Malformed("answer too large".into()));
    }
    let v: Value =
        serde_json::from_slice(body).map_err(|e| CtError::Malformed(format!("not JSON: {e}")))?;
    match v {
        Value::Array(items) => Ok(items
            .iter()
            .take(MAX_ISSUANCES)
            .filter_map(parse_one)
            .collect()),
        Value::Object(o) => {
            let code = o.get("code").and_then(Value::as_str).unwrap_or("");
            if code == "rate_limited" {
                return Err(CtError::RateLimited);
            }
            let msg = o.get("message").and_then(Value::as_str).unwrap_or("");
            let text = clean_text(&format!("{code}: {msg}"));
            match (code.is_empty(), text) {
                (false, Some(t)) => Err(CtError::Api(t)),
                _ => Err(CtError::Malformed("unexpected object".into())),
            }
        }
        _ => Err(CtError::Malformed("unexpected JSON type".into())),
    }
}

/// The cursor for the next poll: the id of the last issuance returned.
pub fn next_cursor(list: &[Issuance]) -> Option<&str> {
    list.last().map(|i| i.id.as_str())
}

/// Map an HTTP status to an error. `None` for 2xx.
pub fn status_error(status: u16) -> Option<CtError> {
    match status {
        200..=299 => None,
        401 | 403 => Some(CtError::Auth),
        429 => Some(CtError::RateLimited),
        s => Some(CtError::Api(format!("HTTP {s}"))),
    }
}

/// True when a domain may be polled again. Never polled, or a clock that moved backwards, counts as due.
pub fn poll_due(last_poll_ms: Option<u64>, now_ms: u64) -> bool {
    match last_poll_ms {
        None => true,
        Some(t) => now_ms < t || now_ms - t >= POLL_INTERVAL_MS,
    }
}

/// Counts requests per UTC hour against a local budget.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HourlyBudget {
    pub hour: u64,
    pub used: u32,
}

impl HourlyBudget {
    /// Take one request from this hour's budget. False when it is used up. The count resets when the UTC
    /// hour changes; a clock that moves backwards does not reset it.
    pub fn take(&mut self, now_ms: u64, limit: u32) -> bool {
        let hour = now_ms / 3_600_000;
        if hour > self.hour {
            self.hour = hour;
            self.used = 0;
        }
        if self.used >= limit {
            return false;
        }
        self.used += 1;
        true
    }
}

/// Why a domain was not added to the watch-list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchError {
    Invalid,
    Duplicate,
    Full,
}

/// The user's watched domains, in the order added.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WatchList {
    domains: Vec<String>,
}

impl WatchList {
    /// Add a domain the user typed. Returns the normalised name.
    pub fn add(&mut self, input: &str) -> Result<String, WatchError> {
        let d = normalize_domain(input).ok_or(WatchError::Invalid)?;
        if self.domains.contains(&d) {
            return Err(WatchError::Duplicate);
        }
        if self.domains.len() >= MAX_WATCHED {
            return Err(WatchError::Full);
        }
        self.domains.push(d.clone());
        Ok(d)
    }

    /// Remove a domain. True when it was on the list.
    pub fn remove(&mut self, input: &str) -> bool {
        let before = self.domains.len();
        if let Some(d) = normalize_domain(input) {
            self.domains.retain(|x| *x != d);
        }
        self.domains.len() != before
    }

    pub fn domains(&self) -> &[String] {
        &self.domains
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = include_str!("../tests/fixtures/osint/certspotter/issuances-ok.json");
    const MESSY: &str = include_str!("../tests/fixtures/osint/certspotter/issuances-messy.json");
    const EMPTY: &str = include_str!("../tests/fixtures/osint/certspotter/issuances-empty.json");
    const LIMITED: &str =
        include_str!("../tests/fixtures/osint/certspotter/error-rate-limited.json");
    const BAD_DOMAIN: &str =
        include_str!("../tests/fixtures/osint/certspotter/error-bad-domain.json");
    const MALFORMED: &str = include_str!("../tests/fixtures/osint/certspotter/malformed.json");

    #[test]
    fn domains_are_normalised_or_rejected() {
        assert_eq!(
            normalize_domain("  Example.COM. ").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_domain("xn--bcher-kva.example").as_deref(),
            Some("xn--bcher-kva.example")
        );
        for bad in [
            "",
            "com",
            "*.example.com",
            "192.0.2.1",
            "::1",
            "exa mple.com",
            "example..com",
            "-a.example.com",
            "a-.example.com",
            "bücher.example",
            "example.com/path",
            "example.123",
            "user@example.com",
            "example.com:443",
        ] {
            assert_eq!(normalize_domain(bad), None, "{bad}");
        }
        assert_eq!(normalize_domain(&format!("{}.com", "a".repeat(64))), None);
    }

    #[test]
    fn request_path_is_built_only_from_checked_parts() {
        assert_eq!(
            watch_path("Example.com", None).as_deref(),
            Some("/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names&expand=issuer")
        );
        let p = watch_path("example.com", Some("12822827438")).unwrap();
        assert!(p.ends_with("&after=12822827438"));
        assert_eq!(watch_path("example.com", Some("1&x=2")), None);
        assert_eq!(watch_path("example.com", Some("")), None);
        assert_eq!(watch_path("not a domain", None), None);
    }

    #[test]
    fn parses_a_real_shaped_answer() {
        let list = parse_issuances(OK.as_bytes()).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, "12809115180");
        assert_eq!(list[0].dns_names.len(), 4);
        assert_eq!(list[0].issuer.as_deref(), Some("Sectigo"));
        assert_eq!(list[0].revoked, Some(true));
        assert_eq!(list[1].revoked, Some(false));
        assert!(list[1].dns_names.contains(&"*.example.net".to_string()));
        assert_eq!(next_cursor(&list), Some("12822827438"));
    }

    #[test]
    fn messy_entries_are_dropped_or_cleaned() {
        let list = parse_issuances(MESSY.as_bytes()).unwrap();
        assert_eq!(list.len(), 1);
        let i = &list[0];
        assert_eq!(i.id, "900");
        assert_eq!(i.dns_names, vec!["ok.example.com".to_string()]);
        assert_eq!(i.issuer.as_deref(), Some("Let's Encrypt"));
        assert_eq!(i.not_before, None);
        assert_eq!(i.not_after.as_deref(), Some("2027-01-01T00:00:00Z"));
        assert_eq!(i.revoked, None);
    }

    #[test]
    fn empty_page_means_nothing_new() {
        let list = parse_issuances(EMPTY.as_bytes()).unwrap();
        assert!(list.is_empty());
        assert_eq!(next_cursor(&list), None);
    }

    #[test]
    fn errors_are_classified() {
        assert_eq!(
            parse_issuances(LIMITED.as_bytes()),
            Err(CtError::RateLimited)
        );
        match parse_issuances(BAD_DOMAIN.as_bytes()) {
            Err(CtError::Api(t)) => assert!(t.contains("not_registered_domain")),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse_issuances(MALFORMED.as_bytes()),
            Err(CtError::Malformed(_))
        ));
        assert!(matches!(
            parse_issuances(b"\"text\""),
            Err(CtError::Malformed(_))
        ));
        assert!(matches!(parse_issuances(b"{}"), Err(CtError::Malformed(_))));
        let big = vec![b' '; MAX_BODY_BYTES + 1];
        assert!(matches!(parse_issuances(&big), Err(CtError::Malformed(_))));
    }

    #[test]
    fn lists_and_names_are_capped() {
        let names: Vec<String> = (0..80).map(|n| format!("\"h{n}.example.com\"")).collect();
        let one = format!("{{\"id\":\"1\",\"dns_names\":[{}]}}", names.join(","));
        let many: Vec<String> = (0..(MAX_ISSUANCES + 20)).map(|_| one.clone()).collect();
        let body = format!("[{}]", many.join(","));
        let list = parse_issuances(body.as_bytes()).unwrap();
        assert_eq!(list.len(), MAX_ISSUANCES);
        assert_eq!(list[0].dns_names.len(), MAX_NAMES);
    }

    #[test]
    fn http_status_maps_to_errors() {
        assert_eq!(status_error(200), None);
        assert_eq!(status_error(401), Some(CtError::Auth));
        assert_eq!(status_error(403), Some(CtError::Auth));
        assert_eq!(status_error(429), Some(CtError::RateLimited));
        assert_eq!(status_error(500), Some(CtError::Api("HTTP 500".into())));
    }

    #[test]
    fn poll_rule_and_budget() {
        assert!(poll_due(None, 5));
        assert!(!poll_due(Some(1_000), 1_000 + POLL_INTERVAL_MS - 1));
        assert!(poll_due(Some(1_000), 1_000 + POLL_INTERVAL_MS));
        assert!(poll_due(Some(9_000), 1_000), "clock moved backwards");
        let mut b = HourlyBudget::default();
        let t = 10 * 3_600_000;
        for _ in 0..LOCAL_HOURLY_BUDGET {
            assert!(b.take(t, LOCAL_HOURLY_BUDGET));
        }
        assert!(!b.take(t + 1, LOCAL_HOURLY_BUDGET));
        assert!(
            !b.take(t - 3_600_000, LOCAL_HOURLY_BUDGET),
            "backwards clock keeps the count"
        );
        assert!(
            b.take(t + 3_600_000, LOCAL_HOURLY_BUDGET),
            "next hour resets"
        );
    }

    #[test]
    fn watch_list_rules() {
        let mut w = WatchList::default();
        assert_eq!(w.add("Example.com"), Ok("example.com".to_string()));
        assert_eq!(w.add("example.com."), Err(WatchError::Duplicate));
        assert_eq!(w.add("nope"), Err(WatchError::Invalid));
        for n in 1..MAX_WATCHED {
            assert!(w.add(&format!("site{n}.example")).is_ok());
        }
        assert_eq!(w.add("one-too-many.example"), Err(WatchError::Full));
        assert_eq!(w.domains().len(), MAX_WATCHED);
        assert!(w.remove("EXAMPLE.com"));
        assert!(!w.remove("EXAMPLE.com"));
        assert!(w.add("one-too-many.example").is_ok());
    }
}
