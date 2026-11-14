//! ATLAS-OSINT-008 - Shodan InternetDB click enrichment.
//!
//! Pure functions for one-IP lookups: which addresses may be looked up, how to build the request
//! path, how to parse and bound the answer, and when a cached answer is still fresh. No network,
//! clock or file system here; the host worker does the request. See `docs/OSINT-TERMS-INTERNETDB.md`.
//!
//! Proposed registry values (the registry entry already exists in `osint.rs`): free for
//! non-commercial use only, no key, attribution link <https://internetdb.shodan.io/>, lookups only
//! when the user clicks an address, answers cached for 24 hours.
//!
//! Rules for the host: never look up a private, loopback, link-local, multicast, documentation or
//! otherwise non-public address; at most one request in flight; at least one second between requests
//! (Shodan's stated API rate is one request per second); do not retry a 404 (it means "no data").

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// How long a stored answer, including "no information", stays fresh: 24 hours.
pub const CACHE_TTL_MS: u64 = 24 * 60 * 60 * 1000;
/// Minimum gap between two requests from this application, in milliseconds.
pub const MIN_GAP_MS: u64 = 1_000;
/// Largest response body accepted. A real answer is a few hundred bytes.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

const MAX_PORTS: usize = 200;
const MAX_HOSTNAMES: usize = 20;
const MAX_CPES: usize = 50;
const MAX_TAGS: usize = 30;
const MAX_VULNS: usize = 200;
const MAX_HOSTNAME_LEN: usize = 253;
const MAX_CPE_LEN: usize = 200;
const MAX_TAG_LEN: usize = 40;

/// What InternetDB knows about one public IP address.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternetDbHost {
    pub ip: String,
    pub ports: Vec<u16>,
    pub hostnames: Vec<String>,
    pub cpes: Vec<String>,
    pub tags: Vec<String>,
    /// CVE identifiers only, e.g. `CVE-2021-44228`.
    pub vulns: Vec<String>,
}

/// Result of a lookup: data, or the provider's "no information" answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    Found(InternetDbHost),
    NoInformation,
}

#[derive(Deserialize)]
struct Raw {
    #[serde(default)]
    ip: String,
    #[serde(default)]
    ports: Vec<i64>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    cpes: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    vulns: Vec<String>,
}

#[derive(Deserialize)]
struct Detail {
    detail: String,
}

/// True for addresses the public internet can route to. Anything else must never be sent to a third
/// party: it would leak internal addressing and cannot have an answer.
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
                || (o[0] == 100 && (64..=127).contains(&o[1])) // carrier-grade NAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // IETF protocol assignments
                || (o[0] == 198 && (18..=19).contains(&o[1])) // benchmarking
                || o[0] >= 240) // reserved
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || v6.to_ipv4_mapped().is_some())
        }
    }
}

/// Request path for one address, for example `/1.1.1.1`. `None` when the address must not be sent.
/// The host is `internetdb.shodan.io`.
pub fn lookup_path(ip: IpAddr) -> Option<String> {
    is_lookup_allowed(ip).then(|| format!("/{ip}"))
}

/// True while a stored answer fetched at `fetched_ms` may still be shown without a new request.
/// A timestamp from the future counts as stale, so a bad clock cannot pin an old answer.
pub fn cache_fresh(fetched_ms: u64, now_ms: u64) -> bool {
    now_ms >= fetched_ms && now_ms - fetched_ms < CACHE_TTL_MS
}

/// True when a request may be sent now, given when the last one was sent.
pub fn gap_elapsed(last_request_ms: Option<u64>, now_ms: u64) -> bool {
    last_request_ms.is_none_or(|last| now_ms < last || now_ms - last >= MIN_GAP_MS)
}

fn clean(s: &str, max: usize) -> Option<String> {
    let t = s.trim();
    (!t.is_empty() && t.len() <= max && !t.chars().any(char::is_control)).then(|| t.to_string())
}

fn is_cve(s: &str) -> bool {
    let mut parts = s.split('-');
    let ok = parts.next() == Some("CVE")
        && parts
            .next()
            .is_some_and(|y| y.len() == 4 && y.bytes().all(|b| b.is_ascii_digit()))
        && parts
            .next()
            .is_some_and(|n| (4..=7).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()));
    ok && parts.next().is_none()
}

/// Parse an InternetDB response body (HTTP 200 or 404). Bad entries are dropped, lists are capped and
/// de-duplicated; a malformed body is an error, never a panic.
pub fn parse_internetdb(bytes: &[u8]) -> Result<Lookup, String> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err("InternetDB: response too large".into());
    }
    if let Ok(d) = serde_json::from_slice::<Detail>(bytes) {
        return if d.detail.trim() == "No information available" {
            Ok(Lookup::NoInformation)
        } else {
            Err("InternetDB: unexpected detail message".into())
        };
    }
    let raw: Raw = serde_json::from_slice(bytes).map_err(|e| format!("InternetDB JSON: {e}"))?;
    let ip: IpAddr = raw
        .ip
        .parse()
        .map_err(|_| "InternetDB: missing or invalid ip".to_string())?;
    let mut ports: Vec<u16> = raw
        .ports
        .into_iter()
        .filter_map(|p| u16::try_from(p).ok().filter(|p| *p != 0))
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports.truncate(MAX_PORTS);
    let mut vulns: Vec<String> = raw.vulns.into_iter().filter(|v| is_cve(v)).collect();
    vulns.sort();
    vulns.dedup();
    vulns.truncate(MAX_VULNS);
    Ok(Lookup::Found(InternetDbHost {
        ip: ip.to_string(),
        ports,
        hostnames: raw
            .hostnames
            .iter()
            .filter_map(|h| clean(h, MAX_HOSTNAME_LEN))
            .take(MAX_HOSTNAMES)
            .collect(),
        cpes: raw
            .cpes
            .iter()
            .filter_map(|c| clean(c, MAX_CPE_LEN))
            .take(MAX_CPES)
            .collect(),
        tags: raw
            .tags
            .iter()
            .filter_map(|t| clean(t, MAX_TAG_LEN))
            .take(MAX_TAGS)
            .collect(),
        vulns,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = include_str!("../tests/fixtures/osint/internetdb/ok-1.1.1.1.json");
    const NOT_FOUND: &str = include_str!("../tests/fixtures/osint/internetdb/not-found.json");
    const MESSY: &str = include_str!("../tests/fixtures/osint/internetdb/messy.json");
    const MALFORMED: &str = include_str!("../tests/fixtures/osint/internetdb/malformed.json");

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn real_answer_parses() {
        let Lookup::Found(h) = parse_internetdb(OK.as_bytes()).unwrap() else {
            panic!("expected data");
        };
        assert_eq!(h.ip, "1.1.1.1");
        assert!(h.ports.contains(&53) && h.ports.contains(&443));
        assert!(h.ports.windows(2).all(|w| w[0] < w[1]), "sorted and unique");
        assert!(h.hostnames.iter().any(|n| n == "one.one.one.one"));
        assert!(h.vulns.is_empty());
    }

    #[test]
    fn no_information_is_not_an_error() {
        assert_eq!(
            parse_internetdb(NOT_FOUND.as_bytes()),
            Ok(Lookup::NoInformation)
        );
    }

    #[test]
    fn messy_answer_is_cleaned_and_bounded() {
        let Lookup::Found(h) = parse_internetdb(MESSY.as_bytes()).unwrap() else {
            panic!("expected data");
        };
        assert_eq!(
            h.ports,
            vec![22, 80, 443],
            "bad and duplicate ports dropped"
        );
        assert_eq!(
            h.hostnames,
            vec!["ok.example.net"],
            "control chars and long names dropped"
        );
        assert_eq!(
            h.vulns,
            vec!["CVE-2019-0708", "CVE-2021-44228"],
            "only CVE ids, sorted"
        );
    }

    #[test]
    fn malformed_and_oversized_bodies_are_errors() {
        assert!(parse_internetdb(MALFORMED.as_bytes()).is_err());
        assert!(parse_internetdb(b"").is_err());
        assert!(parse_internetdb(br#"{"detail":"something else"}"#).is_err());
        assert!(parse_internetdb(br#"{"ip":"not an ip"}"#).is_err());
        assert!(parse_internetdb(&vec![b' '; MAX_BODY_BYTES + 1]).is_err());
    }

    #[test]
    fn only_public_addresses_may_be_looked_up() {
        for blocked in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "100.64.0.1",
            "198.18.0.1",
            "192.0.2.1",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_lookup_allowed(ip(blocked)), "{blocked} must be blocked");
            assert_eq!(lookup_path(ip(blocked)), None);
        }
        for allowed in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            assert!(is_lookup_allowed(ip(allowed)), "{allowed} must be allowed");
        }
        assert_eq!(lookup_path(ip("1.1.1.1")).as_deref(), Some("/1.1.1.1"));
        assert_eq!(
            lookup_path(ip("2606:4700:4700::1111")).as_deref(),
            Some("/2606:4700:4700::1111")
        );
    }

    #[test]
    fn cache_lasts_24_hours_and_distrusts_the_future() {
        assert!(cache_fresh(1_000, 1_000));
        assert!(cache_fresh(1_000, 1_000 + CACHE_TTL_MS - 1));
        assert!(!cache_fresh(1_000, 1_000 + CACHE_TTL_MS));
        assert!(!cache_fresh(5_000, 4_999), "fetched in the future is stale");
    }

    #[test]
    fn requests_keep_a_one_second_gap() {
        assert!(gap_elapsed(None, 0));
        assert!(!gap_elapsed(Some(10_000), 10_999));
        assert!(gap_elapsed(Some(10_000), 11_000));
        assert!(
            gap_elapsed(Some(10_000), 9_000),
            "clock went backwards: allow, do not stall"
        );
    }
}
