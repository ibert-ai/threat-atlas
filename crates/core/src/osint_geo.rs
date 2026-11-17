//! ATLAS-OSINT-004 - IP-to-ASN and country enrichment (Team Cymru DNS, optional GeoLite2 file).
//!
//! Pure functions: DNS query names, bounded parsers for Team Cymru's TXT answers, a longest-prefix cache,
//! an ASN filter, a query budget and the rule for how old a user-supplied GeoLite2 file may be. No network,
//! DNS, clock or file system here; the host does the lookups. See `docs/OSINT-TERMS-GEO.md`.
//!
//! Owner decision 14 Nov 2026 (`ATLAS-OWNER-OSINT-DECISIONS-20261114-01`): Team Cymru ASN is the default;
//! a GeoLite2 file is optional, supplied by the user under the user's own MaxMind account, and never
//! bundled. Reading the `.mmdb` file needs a new dependency (`maxminddb`) that CL must approve, licence
//! check and audit first, so it is not part of this module.
//!
//! Proposed registry values (entries exist in `osint.rs`): `TeamCymru` keeps its entry (no key, free
//! community service, attribution link); `MaxMind` stays "user-supplied file, attribution required".
//!
//! Important: the country in Team Cymru's answer is the **registry country of the announced prefix**, not
//! where the machine is. Show it as "registered in", never as a location.

use std::collections::VecDeque;
use std::net::IpAddr;

/// Suffix for IPv4 origin lookups: `<reversed octets>.origin.asn.cymru.com`.
pub const ORIGIN_V4_SUFFIX: &str = "origin.asn.cymru.com";
/// Suffix for IPv6 origin lookups: `<reversed nibbles>.origin6.asn.cymru.com`.
pub const ORIGIN_V6_SUFFIX: &str = "origin6.asn.cymru.com";
/// Suffix for ASN name lookups: `AS<number>.asn.cymru.com`.
pub const ASN_NAME_SUFFIX: &str = "asn.cymru.com";
/// How long a prefix answer stays fresh. Team Cymru refreshes its BGP data every 4 hours.
pub const CACHE_TTL_MS: u64 = 24 * 60 * 60 * 1000;
/// Most prefixes kept in the cache.
pub const CACHE_CAPACITY: usize = 4_096;
/// GeoLite2's licence requires deleting a database within 30 days of a newer release.
pub const GEOLITE_MAX_AGE_DAYS: u64 = 30;
/// Attribution line for GeoLite2 data (the licence requires attribution; wording per MaxMind).
pub const GEOLITE_ATTRIBUTION: &str =
    "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com";

const MAX_ORIGIN_ASNS: usize = 8;
const MAX_NAME: usize = 200;
const MAX_FILTER_ENTRIES: usize = 100;

/// What Team Cymru says about the prefix that announces an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginInfo {
    /// Origin AS numbers (usually one; several when the prefix has more than one origin).
    pub asns: Vec<u32>,
    pub prefix: Prefix,
    /// Two-letter country code from the registry record of the prefix. Not a location.
    pub registry_country: Option<String>,
    pub registry: String,
}

/// An AS number with its registered name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsnName {
    pub asn: u32,
    pub registry_country: Option<String>,
    pub name: String,
}

/// A network prefix: an address and a length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub network: IpAddr,
    pub len: u8,
}

impl Prefix {
    /// Parse `1.1.1.0/24` or `2606:4700:4700::/48`. The host bits must be zero.
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, len) = s.trim().split_once('/')?;
        let network: IpAddr = addr.parse().ok()?;
        let len: u8 = len.parse().ok()?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        let p = Prefix { network, len };
        (len <= max && p.mask_of(network) == bits(network)).then_some(p)
    }

    fn mask_of(&self, ip: IpAddr) -> u128 {
        let total = if ip.is_ipv4() { 32 } else { 128 };
        let keep = u32::from(self.len.min(total));
        let mask = if keep == 0 {
            0
        } else {
            (!0u128 << (128 - keep)) >> (128 - total)
        };
        bits(ip) & mask
    }

    /// True when `ip` is inside this prefix (the address families must match).
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.network.is_ipv4() == ip.is_ipv4() && self.mask_of(ip) == bits(self.network)
    }
}

fn bits(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// True for addresses the public internet can route to. A private address is never sent to a third
/// party. (Same rule as the click-lookup sources; the integrator may merge the copies.)
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

/// DNS name to look up for an address, or `None` when the address must not be sent.
pub fn origin_query(ip: IpAddr) -> Option<String> {
    if !is_lookup_allowed(ip) {
        return None;
    }
    Some(match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.{ORIGIN_V4_SUFFIX}", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let hex: String = v6.segments().iter().map(|s| format!("{s:04x}")).collect();
            let nibbles: Vec<String> = hex.chars().rev().map(String::from).collect();
            format!("{}.{ORIGIN_V6_SUFFIX}", nibbles.join("."))
        }
    })
}

/// DNS name for the registered name of an AS number.
pub fn asn_name_query(asn: u32) -> String {
    format!("AS{asn}.{ASN_NAME_SUFFIX}")
}

fn clean(s: &str, max: usize) -> Option<String> {
    let t = s.trim();
    (!t.is_empty() && t.len() <= max && !t.chars().any(char::is_control)).then(|| t.to_string())
}

/// A TXT answer may arrive in quotes, split in several quoted chunks; join them and drop the quotes.
fn txt_text(raw: &str) -> String {
    let t = raw.trim();
    if t.contains('"') {
        t.split('"').skip(1).step_by(2).collect::<Vec<_>>().concat()
    } else {
        t.to_string()
    }
}

fn country(s: &str) -> Option<String> {
    let c = s.trim();
    (c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()) && c != "ZZ").then(|| c.to_string())
}

fn date_ok(s: &str) -> bool {
    let d = s.trim();
    d.is_empty() || chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").is_ok()
}

/// Parse an origin answer: `13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11`. Anything that does not fit
/// (bad AS number, bad prefix, bad country, control characters, bad date) is `None`.
pub fn parse_origin(txt: &str) -> Option<OriginInfo> {
    let line = txt_text(txt);
    let f: Vec<&str> = line.split('|').map(str::trim).collect();
    if f.len() < 5 {
        return None;
    }
    let asns: Vec<u32> = f[0]
        .split_whitespace()
        .map(|a| a.parse::<u32>().ok())
        .collect::<Option<Vec<_>>>()?;
    if asns.is_empty() || asns.len() > MAX_ORIGIN_ASNS {
        return None;
    }
    let registry = clean(f[3], 16).filter(|r| r.bytes().all(|b| b.is_ascii_alphanumeric()))?;
    date_ok(f[4]).then_some(())?;
    Some(OriginInfo {
        asns,
        prefix: Prefix::parse(f[1])?,
        registry_country: country(f[2]),
        registry: registry.to_ascii_lowercase(),
    })
}

/// Parse an AS name answer: `13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US`.
pub fn parse_asn_name(txt: &str) -> Option<AsnName> {
    let line = txt_text(txt);
    let f: Vec<&str> = line.splitn(5, '|').map(str::trim).collect();
    if f.len() < 5 {
        return None;
    }
    date_ok(f[3]).then_some(())?;
    Some(AsnName {
        asn: f[0].parse().ok()?,
        registry_country: country(f[1]),
        name: clean(f[4], MAX_NAME)?,
    })
}

/// A set of AS numbers to match, typed by the user, for example `AS13335, 15169; as8075`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AsnFilter {
    asns: Vec<u32>,
}

impl AsnFilter {
    /// Parse a list separated by commas, semicolons or spaces. Each entry may start with `AS` in any case.
    /// An empty string is an empty filter (matches nothing). A bad entry or too many entries is an error.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut asns = Vec::new();
        for item in text
            .split([',', ';', ' ', '\t', '\n'])
            .filter(|s| !s.is_empty())
        {
            let digits = item
                .strip_prefix("AS")
                .or_else(|| item.strip_prefix("as"))
                .or_else(|| item.strip_prefix("As"))
                .or_else(|| item.strip_prefix("aS"))
                .unwrap_or(item);
            let n: u32 = digits.parse().map_err(|_| {
                format!(
                    "not an AS number: {}",
                    item.chars().take(20).collect::<String>()
                )
            })?;
            if !asns.contains(&n) {
                asns.push(n);
            }
            if asns.len() > MAX_FILTER_ENTRIES {
                return Err(format!("more than {MAX_FILTER_ENTRIES} AS numbers"));
            }
        }
        Ok(Self { asns })
    }

    pub fn is_empty(&self) -> bool {
        self.asns.is_empty()
    }

    /// True when any origin AS of the answer is in the filter.
    pub fn matches(&self, info: &OriginInfo) -> bool {
        info.asns.iter().any(|a| self.asns.contains(a))
    }
}

/// Longest-prefix cache of origin answers. One answer covers every address in its prefix, so the number
/// of DNS queries stays small.
#[derive(Debug, Default)]
pub struct PrefixCache {
    entries: VecDeque<(OriginInfo, u64)>,
}

impl PrefixCache {
    /// The freshest-enough, most specific answer that covers `ip`, if any.
    pub fn lookup(&self, ip: IpAddr, now_ms: u64) -> Option<&OriginInfo> {
        self.entries
            .iter()
            .filter(|(i, t)| now_ms >= *t && now_ms - *t < CACHE_TTL_MS && i.prefix.contains(ip))
            .max_by_key(|(i, _)| i.prefix.len)
            .map(|(i, _)| i)
    }

    /// Store an answer, replacing an older answer for the same prefix and dropping the oldest entry when full.
    pub fn insert(&mut self, info: OriginInfo, now_ms: u64) {
        self.entries.retain(|(i, _)| i.prefix != info.prefix);
        if self.entries.len() >= CACHE_CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back((info, now_ms));
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Limits DNS queries: a small burst, then one query per second. A clock that moves backwards adds nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryBudget {
    tokens_milli: u64,
    last_ms: u64,
}

impl QueryBudget {
    /// Most queries allowed in a burst.
    pub const BURST: u64 = 30;

    pub fn new(now_ms: u64) -> Self {
        Self {
            tokens_milli: Self::BURST * 1000,
            last_ms: now_ms,
        }
    }

    /// Take one query. False when the budget is empty; try again later.
    pub fn try_take(&mut self, now_ms: u64) -> bool {
        if now_ms > self.last_ms {
            self.tokens_milli =
                (self.tokens_milli + (now_ms - self.last_ms)).min(Self::BURST * 1000);
            self.last_ms = now_ms;
        }
        if self.tokens_milli >= 1000 {
            self.tokens_milli -= 1000;
            true
        } else {
            false
        }
    }
}

/// Age in whole days of a GeoLite2 database from its build time (epoch seconds, from the file's metadata)
/// and the current time. A build time in the future gives 0.
pub fn geolite_age_days(build_epoch_s: u64, now_s: u64) -> u64 {
    now_s.saturating_sub(build_epoch_s) / 86_400
}

/// True when the file is older than the licence allows. The user is responsible for updating it; the
/// application only warns, and does not use a stale file for new lookups.
pub fn geolite_is_stale(build_epoch_s: u64, now_s: u64) -> bool {
    geolite_age_days(build_epoch_s, now_s) > GEOLITE_MAX_AGE_DAYS
}

/// Cheap check that a path the user picked looks like a GeoLite2 database file (`.mmdb`, at most 200 MB).
pub fn looks_like_geolite_file(file_name: &str, size_bytes: u64) -> bool {
    let lower = file_name.to_ascii_lowercase();
    lower.ends_with(".mmdb") && (1..=200 * 1024 * 1024).contains(&size_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: &str = include_str!("../tests/fixtures/osint/geo/cymru-origin-v4.txt");
    const V4_GOOGLE: &str = include_str!("../tests/fixtures/osint/geo/cymru-origin-v4-google.txt");
    const V6: &str = include_str!("../tests/fixtures/osint/geo/cymru-origin-v6.txt");
    const MOAS: &str = include_str!("../tests/fixtures/osint/geo/cymru-origin-moas.txt");
    const ASN_CF: &str = include_str!("../tests/fixtures/osint/geo/cymru-asn-cloudflare.txt");
    const ASN_GOOGLE: &str = include_str!("../tests/fixtures/osint/geo/cymru-asn-google.txt");
    const MESSY: &str = include_str!("../tests/fixtures/osint/geo/cymru-messy.txt");

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn query_names_match_the_service_format() {
        assert_eq!(
            origin_query(ip("1.1.1.1")).as_deref(),
            Some("1.1.1.1.origin.asn.cymru.com")
        );
        assert_eq!(
            origin_query(ip("8.4.4.1")).as_deref(),
            Some("1.4.4.8.origin.asn.cymru.com")
        );
        assert_eq!(
            origin_query(ip("2606:4700:4700::1111")).as_deref(),
            Some("1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.origin6.asn.cymru.com")
        );
        assert_eq!(asn_name_query(13335), "AS13335.asn.cymru.com");
        for blocked in [
            "10.1.1.1",
            "192.168.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:1.2.3.4",
        ] {
            assert_eq!(origin_query(ip(blocked)), None, "{blocked}");
        }
    }

    #[test]
    fn real_answers_parse() {
        let a = parse_origin(V4).unwrap();
        assert_eq!(a.asns, vec![13335]);
        assert_eq!(a.prefix, Prefix::parse("1.1.1.0/24").unwrap());
        assert_eq!(a.registry_country.as_deref(), Some("AU"));
        assert_eq!(a.registry, "apnic");
        let g = parse_origin(V4_GOOGLE).unwrap();
        assert_eq!(
            (g.asns, g.registry_country.as_deref()),
            (vec![15169], Some("US"))
        );
        let v6 = parse_origin(V6).unwrap();
        assert_eq!(v6.prefix.len, 48);
        assert!(v6.prefix.contains(ip("2606:4700:4700::1111")));
        let n = parse_asn_name(ASN_CF).unwrap();
        assert_eq!((n.asn, n.registry_country.as_deref()), (13335, Some("US")));
        assert_eq!(n.name, "CLOUDFLARENET - Cloudflare, Inc., US");
        assert_eq!(
            parse_asn_name(ASN_GOOGLE).unwrap().name,
            "GOOGLE - Google LLC, US"
        );
    }

    #[test]
    fn several_origins_and_unknown_country() {
        let m = parse_origin(MOAS).unwrap();
        assert_eq!(m.asns, vec![64496, 64497, 64498]);
        assert_eq!(m.registry_country, None, "ZZ means unknown");
        assert_eq!(
            parse_origin("\"1 2 3 4 5 6 7 8 9 | 1.0.0.0/8 | US | arin | \""),
            None,
            "too many origins"
        );
        assert!(
            parse_origin("13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11").is_some(),
            "quotes are optional"
        );
        assert!(
            parse_origin("\"13335 | 1.1.1.0/24 | AU | \" \"apnic | 2011-08-11\"").is_some(),
            "chunks are joined"
        );
    }

    #[test]
    fn bad_answers_are_rejected() {
        for line in MESSY.lines().filter(|l| !l.is_empty()) {
            assert_eq!(parse_origin(line), None, "{line}");
        }
        // A bad country code is not fatal: the answer is kept without a country.
        let lenient =
            parse_origin("\"13335 | 1.1.1.0/24 | Australia | apnic | 2011-08-11\"").unwrap();
        assert_eq!(lenient.registry_country, None);
        assert_eq!(
            parse_asn_name("\"13335 | US | arin | 2010-07-14 | \""),
            None,
            "empty name"
        );
        assert_eq!(parse_asn_name("\"x | US | arin | 2010-07-14 | N\""), None);
        assert_eq!(parse_asn_name(""), None);
    }

    #[test]
    fn prefixes_are_checked_and_matched() {
        assert!(Prefix::parse("1.1.1.0/24").is_some());
        assert!(Prefix::parse("0.0.0.0/0").is_some());
        assert!(Prefix::parse("1.1.1.1/24").is_none(), "host bits set");
        assert!(Prefix::parse("1.1.1.0/33").is_none());
        assert!(Prefix::parse("::/129").is_none());
        let p = Prefix::parse("1.1.1.0/24").unwrap();
        assert!(p.contains(ip("1.1.1.200")) && !p.contains(ip("1.1.2.1")));
        assert!(!p.contains(ip("::1")), "families do not mix");
        assert!(Prefix::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
    }

    #[test]
    fn the_cache_uses_the_most_specific_fresh_prefix() {
        let mut c = PrefixCache::default();
        let wide = OriginInfo {
            asns: vec![1],
            prefix: Prefix::parse("8.0.0.0/8").unwrap(),
            registry_country: None,
            registry: "arin".into(),
        };
        let narrow = OriginInfo {
            asns: vec![15169],
            prefix: Prefix::parse("8.8.8.0/24").unwrap(),
            registry_country: Some("US".into()),
            registry: "arin".into(),
        };
        c.insert(wide.clone(), 1_000);
        c.insert(narrow.clone(), 1_000);
        assert_eq!(c.lookup(ip("8.8.8.8"), 2_000), Some(&narrow));
        assert_eq!(c.lookup(ip("8.9.9.9"), 2_000), Some(&wide));
        assert_eq!(c.lookup(ip("9.9.9.9"), 2_000), None);
        assert_eq!(
            c.lookup(ip("8.8.8.8"), 1_000 + CACHE_TTL_MS),
            None,
            "expired"
        );
        assert_eq!(c.lookup(ip("8.8.8.8"), 500), None, "from the future");
        c.insert(narrow.clone(), 5_000);
        assert_eq!(c.len(), 2, "same prefix replaces, does not add");
        for i in 0..(CACHE_CAPACITY + 10) {
            let [a, b] = [(i / 256) as u8, (i % 256) as u8];
            c.insert(
                OriginInfo {
                    asns: vec![i as u32],
                    prefix: Prefix::parse(&format!("10.{a}.{b}.0/24")).unwrap(),
                    registry_country: None,
                    registry: "x".into(),
                },
                9_000,
            );
        }
        assert_eq!(c.len(), CACHE_CAPACITY, "bounded");
    }

    #[test]
    fn the_asn_filter_accepts_typed_lists() {
        let f = AsnFilter::parse("AS13335, 15169; as8075 AS13335").unwrap();
        let info = |asns: Vec<u32>| OriginInfo {
            asns,
            prefix: Prefix::parse("1.1.1.0/24").unwrap(),
            registry_country: None,
            registry: "x".into(),
        };
        assert!(f.matches(&info(vec![13335])) && f.matches(&info(vec![1, 8075])));
        assert!(!f.matches(&info(vec![1, 2])));
        assert!(AsnFilter::parse("").unwrap().is_empty());
        assert!(!AsnFilter::parse("").unwrap().matches(&info(vec![13335])));
        assert!(AsnFilter::parse("AS13335, banana").is_err());
        assert!(AsnFilter::parse("-5").is_err());
        assert!(AsnFilter::parse("99999999999").is_err());
        let many = (1..=101)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert!(AsnFilter::parse(&many).is_err());
    }

    #[test]
    fn the_query_budget_allows_a_burst_then_one_per_second() {
        let mut b = QueryBudget::new(1_000_000);
        for _ in 0..QueryBudget::BURST {
            assert!(b.try_take(1_000_000));
        }
        assert!(!b.try_take(1_000_000), "burst used up");
        assert!(!b.try_take(1_000_500), "half a second is not enough");
        assert!(b.try_take(1_001_000), "one second later: one query");
        assert!(
            !b.try_take(999_000),
            "a clock that moves backwards adds nothing"
        );
        assert!(
            b.try_take(1_000_000 + 10_000_000)
                && (0..28).all(|_| b.try_take(1_000_000 + 10_000_000)),
            "refill is capped at the burst"
        );
    }

    #[test]
    fn the_geolite_age_rule() {
        let day = 86_400;
        assert_eq!(geolite_age_days(0, 3 * day + 5), 3);
        assert!(!geolite_is_stale(100 * day, 130 * day));
        assert!(geolite_is_stale(100 * day, 131 * day));
        assert_eq!(geolite_age_days(500, 100), 0, "a build time in the future");
        assert!(looks_like_geolite_file("GeoLite2-ASN.MMDB", 7_000_000));
        assert!(!looks_like_geolite_file("GeoLite2-ASN.csv", 7_000_000));
        assert!(!looks_like_geolite_file("a.mmdb", 0));
        assert!(!looks_like_geolite_file("a.mmdb", 300 * 1024 * 1024));
        assert!(GEOLITE_ATTRIBUTION.contains("maxmind.com"));
    }
}
