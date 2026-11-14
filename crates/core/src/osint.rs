//! Non-commercial OSINT source registry, rate gates and parsers.
//!
//! Network workers live in the platform host; this module owns the data contract, the licence
//! metadata and the parsers so every source is testable without a live connection.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// CISA Known Exploited Vulnerabilities catalogue.
pub const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
/// FIRST EPSS daily CSV. The EPSS API is lookup-only; bulk sync uses this file.
pub const EPSS_URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
/// Tor Project bulk exit list.
pub const TOR_EXIT_URL: &str = "https://check.torproject.org/torbulkexitlist";

/// The OSINT sources covered by the wishlist. Keep this list and `source_spec` in sync.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Source {
    CisaKev,
    Epss,
    TorExit,
    SansIsc,
    MaxMind,
    TeamCymru,
    Urlhaus,
    ThreatFox,
    Sslbl,
    Otx,
    RansomwareLive,
    ShodanInternetDb,
    AbuseIpdb,
    RipeRis,
    CertStream,
    SpamhausDrop,
    PhishTank,
}

pub const SOURCES: &[Source] = &[
    Source::CisaKev,
    Source::Epss,
    Source::TorExit,
    Source::SansIsc,
    Source::MaxMind,
    Source::TeamCymru,
    Source::Urlhaus,
    Source::ThreatFox,
    Source::Sslbl,
    Source::Otx,
    Source::RansomwareLive,
    Source::ShodanInternetDb,
    Source::AbuseIpdb,
    Source::RipeRis,
    Source::CertStream,
    Source::SpamhausDrop,
    Source::PhishTank,
];

/// Licence and rate-limit contract for one source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSpec {
    /// Stable identifier used in settings and caches.
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// Licence/terms summary shown in the UI.
    pub licence: &'static str,
    /// Attribution or terms link.
    pub attribution: &'static str,
    /// Minimum interval between successful requests, in milliseconds.
    pub min_interval_ms: u64,
    /// Whether the user must supply a key.
    pub requires_key: bool,
    /// True when the provider permits this project's non-commercial use only.
    pub non_commercial_only: bool,
}

/// The registry. Every source must have a non-zero interval and an attribution link.
pub fn source_spec(source: Source) -> SourceSpec {
    match source {
        Source::CisaKev => SourceSpec {
            id: "cisa-kev",
            name: "CISA Known Exploited Vulnerabilities",
            licence: "Public US government catalogue; see CISA terms.",
            attribution: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            min_interval_ms: 24 * 60 * 60 * 1000,
            requires_key: false,
            non_commercial_only: false,
        },
        Source::Epss => SourceSpec {
            id: "first-epss",
            name: "FIRST EPSS",
            licence: "Published free by FIRST/Empirical Security; attribution required.",
            attribution: "https://www.first.org/epss/data.html",
            min_interval_ms: 24 * 60 * 60 * 1000,
            requires_key: false,
            non_commercial_only: false,
        },
        Source::TorExit => SourceSpec {
            id: "tor-exit",
            name: "Tor exit nodes",
            licence: "Tor Project public bulk exit list; attribution required.",
            attribution: "https://check.torproject.org/torbulkexitlist",
            min_interval_ms: 30 * 60 * 1000,
            requires_key: false,
            non_commercial_only: false,
        },
        Source::SansIsc => SourceSpec {
            id: "sans-isc",
            name: "SANS ISC / DShield",
            licence: "CC BY-NC-SA 4.0; attribution, non-commercial, share-alike.",
            attribution: "https://isc.sans.edu/api/",
            min_interval_ms: 60 * 60 * 1000,
            requires_key: false,
            non_commercial_only: true,
        },
        Source::MaxMind => SourceSpec {
            id: "maxmind-geolite2",
            name: "MaxMind GeoLite2",
            licence: "GeoLite2 free database terms; attribution required.",
            attribution: "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data",
            min_interval_ms: 7 * 24 * 60 * 60 * 1000,
            requires_key: true,
            non_commercial_only: false,
        },
        Source::TeamCymru => SourceSpec {
            id: "team-cymru",
            name: "Team Cymru IP-to-ASN",
            licence: "Team Cymru free IP-to-ASN DNS service terms; attribution required.",
            attribution: "https://www.team-cymru.com/ip-asn-mapping",
            min_interval_ms: 60 * 1000,
            requires_key: false,
            non_commercial_only: false,
        },
        Source::Urlhaus => SourceSpec {
            id: "urlhaus",
            name: "abuse.ch URLhaus",
            licence: "abuse.ch community API fair use; commercial use may require a paid licence.",
            attribution: "https://urlhaus.abuse.ch/api/",
            min_interval_ms: 15 * 60 * 1000,
            requires_key: true,
            non_commercial_only: true,
        },
        Source::ThreatFox => SourceSpec {
            id: "threatfox",
            name: "abuse.ch ThreatFox",
            licence: "abuse.ch community API fair use; commercial use may require a paid licence.",
            attribution: "https://threatfox.abuse.ch/api/",
            min_interval_ms: 15 * 60 * 1000,
            requires_key: true,
            non_commercial_only: true,
        },
        Source::Sslbl => SourceSpec {
            id: "sslbl",
            name: "abuse.ch SSLBL",
            licence: "CC0 per abuse.ch Terms of Use 3.4; free for commercial and non-commercial use; no key.",
            attribution: "https://sslbl.abuse.ch/",
            min_interval_ms: 15 * 60 * 1000,
            requires_key: false,
            non_commercial_only: false,
        },
        Source::Otx => SourceSpec {
            id: "alienvault-otx",
            name: "AlienVault OTX",
            licence: "Free OTX API; pulse licences vary. Non-commercial use only.",
            attribution: "https://otx.alienvault.com/api",
            min_interval_ms: 15 * 60 * 1000,
            requires_key: true,
            non_commercial_only: true,
        },
        Source::RansomwareLive => SourceSpec {
            id: "ransomware-live",
            name: "ransomware.live",
            licence: "Free API v2 terms; non-commercial aggregate use.",
            attribution: "https://www.ransomware.live/api",
            min_interval_ms: 15 * 60 * 1000,
            requires_key: false,
            non_commercial_only: true,
        },
        Source::ShodanInternetDb => SourceSpec {
            id: "shodan-internetdb",
            name: "Shodan InternetDB",
            licence: "Free for non-commercial use only; commercial use needs a Shodan licence.",
            attribution: "https://internetdb.shodan.io/",
            min_interval_ms: 24 * 60 * 60 * 1000,
            requires_key: false,
            non_commercial_only: true,
        },
        Source::AbuseIpdb => SourceSpec {
            id: "abuseipdb",
            name: "AbuseIPDB",
            licence: "Free Individual plan: non-commercial personal use, one account per person, own key only.",
            attribution: "https://www.abuseipdb.com/api",
            min_interval_ms: 24 * 60 * 60 * 1000,
            requires_key: true,
            non_commercial_only: true,
        },
        Source::RipeRis => SourceSpec {
            id: "ripe-ris",
            name: "RIPE RIS Live (BGP)",
            licence: "RIPE NCC permission by default; accept RIPE NCC terms, show RIPE NCC and RIS attribution (link and boilerplate).",
            attribution: "https://www.ripe.net/ris",
            min_interval_ms: 5 * 60 * 1000,
            requires_key: false,
            non_commercial_only: false,
        },
        Source::CertStream => SourceSpec {
            id: "certstream",
            name: "Certificate Transparency / CertStream",
            licence: "Public CT logs. The hosted CertStream stream is not operating (14 Nov 2026); a crt.sh watch-list is proposed instead.",
            attribution: "https://github.com/CaliDog/certstream-server",
            min_interval_ms: 60 * 1000,
            requires_key: false,
            non_commercial_only: false,
        },
        Source::SpamhausDrop => SourceSpec {
            id: "spamhaus-drop",
            name: "Spamhaus DROP/EDROP",
            licence: "Free for non-commercial use with attribution; commercial licence required.",
            attribution: "https://www.spamhaus.org/drop/",
            min_interval_ms: 24 * 60 * 60 * 1000,
            requires_key: false,
            non_commercial_only: true,
        },
        Source::PhishTank => SourceSpec {
            id: "phishtank",
            name: "PhishTank",
            licence: "Free API terms; confirm non-commercial use and attribution.",
            attribution: "https://phishtank.org/developer_info.php",
            min_interval_ms: 60 * 60 * 1000,
            requires_key: true,
            non_commercial_only: true,
        },
    }
}

/// Per-source cooldown and backoff. Persist this next to the cache so restarts honour the floor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateGate {
    pub next_allowed_ms: u64,
    pub backoff_ms: u64,
}

impl RateGate {
    pub fn due(&self, now_ms: u64) -> bool {
        now_ms >= self.next_allowed_ms
    }

    /// A successful request opens the next window and clears backoff.
    pub fn success(&mut self, now_ms: u64, interval_ms: u64) {
        self.next_allowed_ms = now_ms.saturating_add(interval_ms.max(1));
        self.backoff_ms = 0;
    }

    /// A failed request backs off from the source interval, capped at 24 hours.
    pub fn failure(&mut self, now_ms: u64, interval_ms: u64) {
        let base = interval_ms.max(60_000);
        let next = if self.backoff_ms == 0 {
            base
        } else {
            self.backoff_ms.saturating_mul(2)
        };
        self.backoff_ms = next.min(24 * 60 * 60 * 1000);
        self.next_allowed_ms = now_ms.saturating_add(self.backoff_ms);
    }

    /// Honour `Retry-After` exactly, but never less than one second.
    pub fn retry_after(&mut self, now_ms: u64, seconds: u64) {
        self.backoff_ms = seconds.saturating_mul(1000).max(1000);
        self.next_allowed_ms = now_ms.saturating_add(self.backoff_ms);
    }
}

/// Build conditional request headers from a stored ETag/Last-Modified pair.
/// Values containing CR/LF are rejected so a provider cannot inject a header.
pub fn conditional_headers(etag: Option<&str>, last_modified: Option<&str>) -> String {
    let mut headers = String::new();
    for (name, value) in [
        ("If-None-Match", etag),
        ("If-Modified-Since", last_modified),
    ] {
        if let Some(value) = value {
            if !value.is_empty() && !value.contains(['\r', '\n']) {
                headers.push_str(name);
                headers.push_str(": ");
                headers.push_str(value);
                headers.push_str("\r\n");
            }
        }
    }
    headers
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct KevEntry {
    #[serde(rename = "cveID")]
    pub cve: String,
    #[serde(rename = "vendorProject", default)]
    pub vendor: String,
    #[serde(default)]
    pub product: String,
    #[serde(rename = "vulnerabilityName", default)]
    pub name: String,
    #[serde(rename = "dateAdded", default)]
    pub date_added: String,
    #[serde(rename = "dueDate", default)]
    pub due_date: String,
    #[serde(rename = "knownRansomwareCampaignUse", default)]
    pub ransomware: String,
    #[serde(rename = "shortDescription", default)]
    pub description: String,
}

impl KevEntry {
    fn sane(&self) -> bool {
        self.cve.starts_with("CVE-")
            && self.cve.len() <= 32
            && [&self.vendor, &self.product, &self.name, &self.description]
                .iter()
                .all(|s| s.len() <= 4096 && !s.chars().any(char::is_control))
    }
}

#[derive(Deserialize)]
struct KevCatalog {
    vulnerabilities: Vec<KevEntry>,
}

/// Parse the CISA KEV JSON. Invalid records are skipped, not fatal.
pub fn parse_kev(bytes: &[u8]) -> Result<Vec<KevEntry>, String> {
    let catalog: KevCatalog =
        serde_json::from_slice(bytes).map_err(|e| format!("KEV JSON: {e}"))?;
    Ok(catalog
        .vulnerabilities
        .into_iter()
        .filter(KevEntry::sane)
        .collect())
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EpssScore {
    pub cve: String,
    pub epss: f64,
    pub percentile: f64,
}

/// Parse the daily EPSS CSV (comments and the header are ignored).
pub fn parse_epss(bytes: &[u8]) -> Result<Vec<EpssScore>, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("EPSS UTF-8: {e}"))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("cve,") {
            continue;
        }
        let mut parts = line.split(',');
        let (Some(cve), Some(epss), Some(percentile)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let (Ok(epss), Ok(percentile)) = (epss.parse::<f64>(), percentile.parse::<f64>()) else {
            continue;
        };
        if !cve.starts_with("CVE-") || cve.len() > 32 {
            continue;
        }
        if !(0.0..=1.0).contains(&epss) || !(0.0..=1.0).contains(&percentile) {
            continue;
        }
        out.push(EpssScore {
            cve: cve.to_string(),
            epss,
            percentile,
        });
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KevWithEpss {
    pub kev: KevEntry,
    pub epss: Option<EpssScore>,
}

/// Join KEV and EPSS, newest/highest risk first, capped for the panel.
pub fn join_kev_epss(kev: Vec<KevEntry>, epss: Vec<EpssScore>, limit: usize) -> Vec<KevWithEpss> {
    use std::collections::HashMap;
    let scores: HashMap<String, EpssScore> = epss.into_iter().map(|s| (s.cve.clone(), s)).collect();
    let mut joined: Vec<KevWithEpss> = kev
        .into_iter()
        .map(|entry| KevWithEpss {
            epss: scores.get(&entry.cve).cloned(),
            kev: entry,
        })
        .collect();
    joined.sort_by(|a, b| {
        let ka = a.epss.as_ref().map_or(-1.0, |s| s.epss);
        let kb = b.epss.as_ref().map_or(-1.0, |s| s.epss);
        kb.total_cmp(&ka)
            .then_with(|| b.kev.date_added.cmp(&a.kev.date_added))
            .then_with(|| a.kev.cve.cmp(&b.kev.cve))
    });
    joined.truncate(limit.max(1));
    joined
}

/// One SANS ISC/DShield target-port aggregate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SansPort {
    pub rank: u32,
    pub target_port: u32,
    pub records: u64,
    pub targets: u64,
    pub sources: u64,
}

/// SANS ISC/DShield daily top-ports report.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SansReport {
    pub date: String,
    pub ports: Vec<SansPort>,
}

/// Parse the SANS ISC top-ports JSON object (`/api/topports/records/10?json`).
pub fn parse_sans_ports(bytes: &[u8]) -> Result<SansReport, String> {
    use serde_json::Value;
    let value: Value = serde_json::from_slice(bytes).map_err(|e| format!("SANS ISC JSON: {e}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "SANS ISC JSON is not an object".to_string())?;
    let date = object
        .get("date")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut ports = Vec::new();
    for (key, item) in object {
        if key == "date" || key == "limit" || key.parse::<u32>().is_err() {
            continue;
        }
        let Some(fields) = item.as_object() else {
            continue;
        };
        let field = |name: &str| fields.get(name).and_then(Value::as_u64);
        let (Some(rank), Some(target_port), Some(records), Some(targets), Some(sources)) = (
            field("rank"),
            field("targetport"),
            field("records"),
            field("targets"),
            field("sources"),
        ) else {
            continue;
        };
        if rank == 0 || rank > 100 || target_port > u16::MAX as u64 {
            continue;
        }
        ports.push(SansPort {
            rank: rank as u32,
            target_port: target_port as u32,
            records,
            targets,
            sources,
        });
    }
    ports.sort_by_key(|p| p.rank);
    ports.truncate(20);
    Ok(SansReport { date, ports })
}

/// Parse the Tor bulk exit list. Duplicate and invalid lines are ignored.
pub fn parse_tor_exits(bytes: &[u8]) -> Vec<IpAddr> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Ok(ip) = line.parse::<IpAddr>() else {
            continue;
        };
        if !out.contains(&ip) {
            out.push(ip);
        }
        if out.len() >= 100_000 {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_source_has_a_safe_spec() {
        for source in SOURCES {
            let spec = source_spec(*source);
            assert!(!spec.id.is_empty());
            assert!(!spec.name.is_empty());
            assert!(!spec.licence.is_empty());
            assert!(spec.attribution.starts_with("https://"));
            assert!(spec.min_interval_ms >= 60_000, "{:?}", source);
        }
    }

    #[test]
    fn registry_matches_the_terms_notes() {
        // Keys: only the user's own key, and only where the provider requires one (docs/OSINT-TERMS-*.md).
        for source in [
            Source::Urlhaus,
            Source::ThreatFox,
            Source::Otx,
            Source::AbuseIpdb,
            Source::PhishTank,
            Source::MaxMind,
        ] {
            assert!(
                source_spec(source).requires_key,
                "{source:?} needs the user's own key"
            );
        }
        for source in [
            Source::Sslbl,
            Source::ShodanInternetDb,
            Source::RipeRis,
            Source::TeamCymru,
            Source::CisaKev,
            Source::Epss,
            Source::TorExit,
            Source::SansIsc,
            Source::SpamhausDrop,
            Source::RansomwareLive,
            Source::CertStream,
        ] {
            assert!(!source_spec(source).requires_key, "{source:?} needs no key");
        }
        // SSLBL is CC0 (abuse.ch Terms of Use 3.4), so it is not restricted to non-commercial use.
        assert!(!source_spec(Source::Sslbl).non_commercial_only);
        assert!(source_spec(Source::AbuseIpdb).non_commercial_only);
        assert_eq!(
            source_spec(Source::RipeRis).attribution,
            "https://www.ripe.net/ris"
        );
    }

    #[test]
    fn rate_gate_enforces_floor_and_backoff() {
        let mut gate = RateGate::default();
        assert!(gate.due(1_000));
        gate.success(1_000, 60_000);
        assert!(!gate.due(2_000));
        assert!(gate.due(61_000));
        gate.failure(61_000, 60_000);
        assert!(!gate.due(62_000));
        assert!(gate.due(61_000 + 60_000));
        gate.failure(200_000, 60_000);
        assert_eq!(gate.backoff_ms, 120_000);
        gate.retry_after(300_000, 5);
        assert_eq!(gate.next_allowed_ms, 305_000);
        gate.success(305_000, 60_000);
        assert_eq!(gate.backoff_ms, 0);
    }

    #[test]
    fn conditional_headers_are_safe() {
        assert_eq!(
            conditional_headers(Some("\"abc\""), Some("Wed, 12 Nov 2026 10:00:00 GMT")),
            "If-None-Match: \"abc\"\r\nIf-Modified-Since: Wed, 12 Nov 2026 10:00:00 GMT\r\n"
        );
        assert!(conditional_headers(Some("x\r\nInjected: 1"), None).is_empty());
        assert!(conditional_headers(None, Some("x\ny")).is_empty());
    }

    #[test]
    fn kev_parser_skips_bad_records() {
        let json = br#"{"vulnerabilities":[
          {"cveID":"CVE-2026-0001","vendorProject":"Acme","product":"Widget","vulnerabilityName":"Bad","dateAdded":"2026-01-01","dueDate":"2026-01-22","knownRansomwareCampaignUse":"Known","shortDescription":"desc"},
          {"cveID":"not-a-cve","vendorProject":"X"}
        ]}"#;
        let entries = parse_kev(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cve, "CVE-2026-0001");
    }

    #[test]
    fn epss_parser_handles_comments_and_invalid_rows() {
        let csv = b"#model_version:v2026.06.15,score_date:2026-11-12T00:00:00Z\ncve,epss,percentile\nCVE-2026-0001,0.91,0.99\nCVE-2026-0002,1.2,0.5\nbad\n";
        let scores = parse_epss(csv).unwrap();
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].cve, "CVE-2026-0001");
    }

    #[test]
    fn join_orders_by_epss_descending() {
        let kev = vec![
            KevEntry {
                cve: "CVE-2026-0001".into(),
                vendor: "A".into(),
                product: "P".into(),
                name: "n".into(),
                date_added: "2026-01-01".into(),
                due_date: "2026-01-02".into(),
                ransomware: "Unknown".into(),
                description: "d".into(),
            },
            KevEntry {
                cve: "CVE-2026-0002".into(),
                vendor: "B".into(),
                product: "P".into(),
                name: "n".into(),
                date_added: "2026-01-02".into(),
                due_date: "2026-01-03".into(),
                ransomware: "Unknown".into(),
                description: "d".into(),
            },
        ];
        let epss = vec![
            EpssScore {
                cve: "CVE-2026-0001".into(),
                epss: 0.2,
                percentile: 0.5,
            },
            EpssScore {
                cve: "CVE-2026-0002".into(),
                epss: 0.8,
                percentile: 0.9,
            },
        ];
        let joined = join_kev_epss(kev, epss, 10);
        assert_eq!(joined[0].kev.cve, "CVE-2026-0002");
        assert_eq!(joined[1].kev.cve, "CVE-2026-0001");
    }

    #[test]
    fn sans_parser_accepts_the_document_object_shape() {
        let json = br#"{"0":{"rank":1,"targetport":22,"records":195959,"targets":269,"sources":8017},"1":{"rank":2,"targetport":8080,"records":172198,"targets":245,"sources":4484},"date":"2026-11-14","limit":10}"#;
        let report = parse_sans_ports(json).unwrap();
        assert_eq!(report.date, "2026-11-14");
        assert_eq!(report.ports.len(), 2);
        assert_eq!(report.ports[0].target_port, 22);
        assert_eq!(report.ports[1].target_port, 8080);
    }

    #[test]
    fn sans_parser_skips_bad_rows() {
        let json = br#"{"0":{"rank":0,"targetport":22,"records":1,"targets":1,"sources":1},"1":{"rank":2,"targetport":70000,"records":1,"targets":1,"sources":1},"2":{"rank":3,"targetport":443},"date":"2026-11-14"}"#;
        let report = parse_sans_ports(json).unwrap();
        assert!(report.ports.is_empty());
    }

    #[test]
    fn tor_parser_deduplicates_and_ignores_garbage() {
        let list = b"# comment\n1.2.3.4\n2001:db8::1\n1.2.3.4\nnot-an-ip\n\n";
        let exits = parse_tor_exits(list);
        assert_eq!(exits.len(), 2);
    }
}
