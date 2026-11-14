//! ATLAS-OSINT-012 - Spamhaus DROP (IPv4, IPv6) and ASN-DROP netblock lists.
//!
//! Pure functions: bounded parsers for the three public JSON-lines files, a lookup of an address against the
//! listed netblocks, an AS-number check, the list's age and the fetch-gap rules. No network, clock or file
//! system here; the host does the download. See `docs/OSINT-TERMS-SPAMHAUS.md` for the terms read on
//! 14 November 2026.
//!
//! The eDROP list was merged into DROP on 10 April 2024, so there is no separate eDROP file.
//!
//! Proposed registry values (the entry exists in `osint.rs`): name "Spamhaus DROP", free of charge under the DROP
//! Terms of Use, no key, attribution link <https://www.spamhaus.org/drop/>, one fetch per day (the provider's
//! hard floor is one hour), and **non_commercial_only: false** (the terms state no such restriction). The
//! licence text should add the naming rule: the Spamhaus name must not be used in marketing, promotional or
//! other commercial materials.
//!
//! Rules for the host: automated downloads at least one hour apart (once per day here), counting failures
//! too; excessive downloads can get the address firewalled by Spamhaus. Netblocks are advisory "do not route"
//! data: show them as "listed by Spamhaus DROP", never as proof that a machine is malicious.

use serde::Deserialize;
use std::net::IpAddr;

pub const HOST: &str = "www.spamhaus.org";
pub const DROP_V4_PATH: &str = "/drop/drop_v4.json";
pub const DROP_V6_PATH: &str = "/drop/drop_v6.json";
pub const ASN_DROP_PATH: &str = "/drop/asndrop.json";
/// The provider's rule: automated downloads must be at least one hour apart.
pub const PROVIDER_MIN_GAP_MS: u64 = 60 * 60 * 1000;
/// Our floor between successful downloads of one list: once per day (the provider calls this plenty).
pub const MIN_INTERVAL_MS: u64 = 24 * 60 * 60 * 1000;
/// Largest body accepted per list. The real files are about 110 KB, 6 KB and 40 KB.
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
/// After this age the data is shown with a warning and not used for decisions (allocations change).
pub const STALE_AFTER_S: u64 = 7 * 24 * 3600;

const MAX_ENTRIES: usize = 20_000;

// Our own floor must never be lower than the provider's.
const _: () = assert!(MIN_INTERVAL_MS >= PROVIDER_MIN_GAP_MS);

/// A network prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    pub network: IpAddr,
    pub len: u8,
}

fn bits(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

impl Cidr {
    fn mask(&self) -> u128 {
        let total: u32 = if self.network.is_ipv4() { 32 } else { 128 };
        let keep = u32::from(self.len).min(total);
        if keep == 0 {
            0
        } else {
            (!0u128 << (128 - keep)) >> (128 - total)
        }
    }

    /// Parse `1.10.16.0/20` or `2001:678:254::/48`. Host bits must be zero.
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, len) = s.trim().split_once('/')?;
        let network: IpAddr = addr.parse().ok()?;
        let len: u8 = len.parse().ok()?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        let c = Cidr { network, len };
        (len <= max && bits(network) & c.mask() == bits(network)).then_some(c)
    }

    /// True when `ip` lies inside this prefix (the address families must match).
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.network.is_ipv4() == ip.is_ipv4() && bits(ip) & self.mask() == bits(self.network)
    }
}

/// True when the network address is public routable space. A DROP list cannot list private or reserved
/// space; such a record is a data error and is dropped.
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

/// One listed netblock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DropEntry {
    pub cidr: Cidr,
    /// Spamhaus Blocklist record, for example `SBL256894`.
    pub sbl: String,
    /// Regional Internet Registry, lower case, for example `ripencc`.
    pub rir: String,
}

/// One listed AS number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsnEntry {
    pub asn: u32,
    pub rir: String,
    pub domain: Option<String>,
    /// Two-letter registry country, when valid.
    pub country: Option<String>,
    pub name: String,
}

/// The metadata line at the end of each file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListMeta {
    /// When Spamhaus generated the list, seconds since the Unix epoch.
    pub generated_s: u64,
    /// Number of records the provider says the file holds.
    pub records: u32,
}

/// A parsed netblock list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DropList {
    pub entries: Vec<DropEntry>,
    pub meta: Option<ListMeta>,
    /// Lines that were skipped (bad record, wrong address family, private space).
    pub skipped: u32,
}

/// A parsed AS list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AsnList {
    pub entries: Vec<AsnEntry>,
    pub meta: Option<ListMeta>,
    pub skipped: u32,
}

#[derive(Deserialize)]
struct Meta {
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    timestamp: u64,
    #[serde(default)]
    records: u64,
}

#[derive(Deserialize)]
struct RawNet {
    cidr: Option<String>,
    sblid: Option<String>,
    rir: Option<String>,
}

#[derive(Deserialize)]
struct RawAsn {
    asn: Option<u64>,
    rir: Option<String>,
    domain: Option<String>,
    cc: Option<String>,
    asname: Option<String>,
}

fn clean(s: &str, max: usize) -> Option<String> {
    let t = s.trim();
    (!t.is_empty() && t.len() <= max && !t.chars().any(char::is_control)).then(|| t.to_string())
}

fn rir(s: &str) -> Option<String> {
    clean(s, 16)
        .filter(|r| r.bytes().all(|b| b.is_ascii_alphanumeric()))
        .map(|r| r.to_ascii_lowercase())
}

fn text(bytes: &[u8], what: &str) -> Result<String, String> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err(format!("{what}: response too large"));
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| format!("{what}: not UTF-8"))
}

fn meta_of(line: &str) -> Option<ListMeta> {
    let m: Meta = serde_json::from_str(line).ok()?;
    (m.kind.as_deref() == Some("metadata")).then(|| ListMeta {
        generated_s: m.timestamp,
        records: u32::try_from(m.records).unwrap_or(u32::MAX),
    })
}

/// Parse a DROP netblock file. `ipv6` says which address family the file must contain; records of the other
/// family, with host bits set, in private or reserved space, with a bad SBL id or without a registry are
/// skipped and counted. A file without a single valid record and without metadata is an error.
pub fn parse_drop(bytes: &[u8], ipv6: bool) -> Result<DropList, String> {
    let body = text(bytes, "DROP")?;
    let mut list = DropList::default();
    for line in body.lines().filter(|l| !l.trim().is_empty()) {
        if let Some(meta) = meta_of(line) {
            list.meta = Some(meta);
            continue;
        }
        let parsed = serde_json::from_str::<RawNet>(line).ok().and_then(|r| {
            let cidr = Cidr::parse(r.cidr.as_deref()?)?;
            let sbl = clean(r.sblid.as_deref()?, 24).filter(|s| {
                s.strip_prefix("SBL")
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            })?;
            (cidr.network.is_ipv6() == ipv6 && is_public(cidr.network)).then_some(())?;
            Some(DropEntry {
                cidr,
                sbl,
                rir: rir(r.rir.as_deref()?)?,
            })
        });
        match parsed {
            Some(e) if list.entries.len() < MAX_ENTRIES => list.entries.push(e),
            _ => list.skipped += 1,
        }
    }
    if list.entries.is_empty() && list.meta.is_none() {
        return Err("DROP: no records and no metadata".into());
    }
    Ok(list)
}

/// Parse the ASN-DROP file. Bad records are skipped and counted.
pub fn parse_asndrop(bytes: &[u8]) -> Result<AsnList, String> {
    let body = text(bytes, "ASN-DROP")?;
    let mut list = AsnList::default();
    for line in body.lines().filter(|l| !l.trim().is_empty()) {
        if let Some(meta) = meta_of(line) {
            list.meta = Some(meta);
            continue;
        }
        let parsed = serde_json::from_str::<RawAsn>(line).ok().and_then(|r| {
            Some(AsnEntry {
                asn: u32::try_from(r.asn?).ok()?,
                rir: rir(r.rir.as_deref()?)?,
                domain: r.domain.as_deref().and_then(|d| clean(d, 253)),
                country: r
                    .cc
                    .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase())),
                name: clean(r.asname.as_deref()?, 100)?,
            })
        });
        match parsed {
            Some(e) if list.entries.len() < MAX_ENTRIES => list.entries.push(e),
            _ => list.skipped += 1,
        }
    }
    if list.entries.is_empty() && list.meta.is_none() {
        return Err("ASN-DROP: no records and no metadata".into());
    }
    Ok(list)
}

/// The netblock that lists `ip`, if any. A public address inside a listed range is "listed by DROP".
pub fn lookup<'a>(lists: &'a [&DropList], ip: IpAddr) -> Option<&'a DropEntry> {
    lists
        .iter()
        .flat_map(|l| l.entries.iter())
        .filter(|e| e.cidr.contains(ip))
        .max_by_key(|e| e.cidr.len)
}

/// True when the AS number is on the ASN-DROP list.
pub fn asn_listed(list: &AsnList, asn: u32) -> Option<&AsnEntry> {
    list.entries.iter().find(|e| e.asn == asn)
}

/// Age of a list in whole hours, from its generation time. A time in the future gives 0.
pub fn age_hours(meta: &ListMeta, now_s: u64) -> u64 {
    now_s.saturating_sub(meta.generated_s) / 3600
}

/// True when the list is too old to be used for decisions (allocations change over time).
pub fn is_stale(meta: &ListMeta, now_s: u64) -> bool {
    now_s.saturating_sub(meta.generated_s) > STALE_AFTER_S
}

/// True when a download may start. `last_attempt_ms` is the start of the last download attempt, successful or
/// not, so a failing download cannot be retried faster than the provider allows. `last_success_ms` is the last
/// success; the regular interval is once per day.
pub fn fetch_due(last_attempt_ms: Option<u64>, last_success_ms: Option<u64>, now_ms: u64) -> bool {
    let gap_ok = last_attempt_ms.is_none_or(|t| now_ms < t || now_ms - t >= PROVIDER_MIN_GAP_MS);
    let interval_ok = last_success_ms.is_none_or(|t| now_ms < t || now_ms - t >= MIN_INTERVAL_MS);
    gap_ok && interval_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: &str = include_str!("../tests/fixtures/osint/spamhaus/drop-v4.ndjson");
    const V6: &str = include_str!("../tests/fixtures/osint/spamhaus/drop-v6.ndjson");
    const ASN: &str = include_str!("../tests/fixtures/osint/spamhaus/asndrop.ndjson");
    const MESSY: &str = include_str!("../tests/fixtures/osint/spamhaus/drop-messy.ndjson");
    const ASN_MESSY: &str = include_str!("../tests/fixtures/osint/spamhaus/asndrop-messy.ndjson");

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn real_ipv4_excerpt_parses() {
        let l = parse_drop(V4.as_bytes(), false).unwrap();
        assert_eq!(l.entries.len(), 6);
        assert_eq!(l.skipped, 0);
        let first = &l.entries[0];
        assert_eq!(first.cidr, Cidr::parse("1.10.16.0/20").unwrap());
        assert_eq!(
            (first.sbl.as_str(), first.rir.as_str()),
            ("SBL256894", "apnic")
        );
        let meta = l.meta.unwrap();
        assert_eq!(meta.generated_s, 1_794_585_404);
        assert_eq!(meta.records, 1759);
    }

    #[test]
    fn real_ipv6_and_asn_excerpts_parse() {
        let v6 = parse_drop(V6.as_bytes(), true).unwrap();
        assert_eq!(v6.entries.len(), 2);
        assert_eq!(
            v6.entries[0].cidr,
            Cidr::parse("2001:678:254::/48").unwrap()
        );
        let a = parse_asndrop(ASN.as_bytes()).unwrap();
        assert_eq!(a.entries.len(), 4);
        assert_eq!(a.entries[0].asn, 245);
        assert_eq!(a.entries[0].country.as_deref(), Some("US"));
        assert_eq!(a.entries[0].name, "PRC-AS");
        assert_eq!(
            a.entries[0].domain.as_deref(),
            Some("planningresearchcorp.com")
        );
        assert_eq!(a.meta.unwrap().records, 455);
    }

    #[test]
    fn the_wrong_family_is_not_accepted() {
        let l = parse_drop(V4.as_bytes(), true);
        assert!(
            l.is_err() || l.unwrap().entries.is_empty(),
            "IPv4 records in an IPv6 file are dropped"
        );
        let l = parse_drop(V6.as_bytes(), false).unwrap();
        assert!(l.entries.is_empty() && l.skipped == 2);
    }

    #[test]
    fn messy_records_are_skipped_and_counted() {
        let l = parse_drop(MESSY.as_bytes(), false).unwrap();
        let nets: Vec<String> = l
            .entries
            .iter()
            .map(|e| e.cidr.network.to_string())
            .collect();
        assert_eq!(
            nets,
            vec!["1.10.16.0", "2.26.75.0"],
            "only the two valid public IPv4 records"
        );
        // host bits set, private space, bad sbl id, control character in rir, not json, missing fields,
        // an IPv6 record in a v4 file and loopback: 8 skipped; the metadata line is not a record.
        assert_eq!(l.skipped, 8);
        assert_eq!(l.meta.unwrap().records, 9);
        let a = parse_asndrop(ASN_MESSY.as_bytes()).unwrap();
        let asns: Vec<u32> = a.entries.iter().map(|e| e.asn).collect();
        assert_eq!(asns, vec![245, 65000, 65002]);
        assert_eq!(
            a.entries[1].country, None,
            "'United States' is not a country code"
        );
        assert_eq!(a.skipped, 3);
    }

    #[test]
    fn broken_input_is_an_error_never_a_panic() {
        assert!(parse_drop(b"", false).is_err());
        assert!(parse_drop(b"not json\n{broken", false).is_err());
        assert!(parse_drop(&[0xff, 0xfe], false).is_err());
        assert!(parse_drop(&vec![b' '; MAX_BODY_BYTES + 1], false).is_err());
        assert!(parse_asndrop(b"").is_err());
        assert!(parse_asndrop(&vec![b' '; MAX_BODY_BYTES + 1]).is_err());
        let only_meta = br#"{"type":"metadata","timestamp":5,"records":0}"#;
        assert!(
            parse_drop(only_meta, false).is_ok(),
            "an empty list with metadata is valid"
        );
    }

    #[test]
    fn lookup_finds_the_most_specific_listing() {
        let v4 = parse_drop(V4.as_bytes(), false).unwrap();
        let v6 = parse_drop(V6.as_bytes(), true).unwrap();
        let lists = [&v4, &v6];
        let hit = lookup(&lists, ip("1.10.20.7")).unwrap();
        assert_eq!(hit.sbl, "SBL256894");
        assert_eq!(lookup(&lists, ip("1.19.255.255")).unwrap().sbl, "SBL434604");
        assert!(
            lookup(&lists, ip("1.10.32.1")).is_none(),
            "just outside 1.10.16.0/20"
        );
        assert!(lookup(&lists, ip("8.8.8.8")).is_none());
        assert_eq!(
            lookup(&lists, ip("2001:678:254::99")).unwrap().rir,
            "ripencc"
        );
        assert!(lookup(&lists, ip("2001:678:255::1")).is_none());
        let a = parse_asndrop(ASN.as_bytes()).unwrap();
        assert_eq!(asn_listed(&a, 2601).unwrap().name, "RADIOLINK-AS");
        assert!(asn_listed(&a, 13335).is_none());
    }

    #[test]
    fn cidr_rules() {
        assert!(Cidr::parse("1.10.16.0/20").is_some());
        assert!(Cidr::parse("1.10.16.1/20").is_none(), "host bits");
        assert!(Cidr::parse("1.10.16.0/33").is_none());
        assert!(Cidr::parse("::/129").is_none());
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("9.9.9.9")));
        assert!(
            !Cidr::parse("1.10.16.0/20").unwrap().contains(ip("::1")),
            "families do not mix"
        );
    }

    #[test]
    fn age_and_staleness() {
        let m = ListMeta {
            generated_s: 1_000_000,
            records: 3,
        };
        assert_eq!(age_hours(&m, 1_000_000 + 5 * 3600 + 30), 5);
        assert_eq!(age_hours(&m, 10), 0, "generated in the future");
        assert!(!is_stale(&m, 1_000_000 + STALE_AFTER_S));
        assert!(is_stale(&m, 1_000_000 + STALE_AFTER_S + 1));
    }

    #[test]
    fn the_fetch_gap_counts_failures_and_keeps_a_daily_interval() {
        let h = 3_600_000u64;
        assert!(fetch_due(None, None, 0), "first fetch");
        assert!(
            !fetch_due(Some(100 * h), Some(100 * h), 100 * h + 23 * h),
            "within the daily interval"
        );
        assert!(fetch_due(Some(100 * h), Some(100 * h), 100 * h + 24 * h));
        // A failed attempt (no new success) may be retried after an hour, not sooner.
        assert!(!fetch_due(
            Some(130 * h),
            Some(100 * h),
            130 * h + 59 * 60_000
        ));
        assert!(fetch_due(Some(130 * h), Some(100 * h), 131 * h));
        assert!(
            fetch_due(Some(500), Some(500), 100),
            "clock went backwards: allow, do not stall"
        );
    }
}
