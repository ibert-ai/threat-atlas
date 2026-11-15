//! Robustness round for every OSINT parser that reads data from the network (RC1 hardening).
//!
//! The parsers must never panic, hang or allocate without bound on hostile or broken input: random
//! bytes, truncated and bit-flipped real-looking payloads, invalid UTF-8, NUL bytes, very deep
//! nesting and huge numbers. Results are ignored on purpose; only "no panic, finishes quickly" is
//! asserted. Deterministic (fixed seed), so a failure reproduces.
use threat_atlas_core::{
    osint, osint_abusech, osint_abuseipdb, osint_certstream, osint_geo, osint_internetdb,
    osint_otx, osint_phishtank, osint_ransomware, osint_spamhaus,
};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = (self.next() as usize) % (max + 1);
        (0..len).map(|_| self.next() as u8).collect()
    }
}

/// Real-looking seeds for each format; mutated below.
fn seeds() -> Vec<Vec<u8>> {
    let s: &[&str] = &[
        r#"{"vulnerabilities":[{"cveID":"CVE-2026-1","dateAdded":"2026-01-01","knownRansomwareCampaignUse":"Known"}]}"#,
        "#model_version:v2026,score_date:2026-01-01\ncve,epss,percentile\nCVE-2026-1,0.5,0.9\n",
        r#"[{"port":23,"records":12345,"targets":10,"sources":5},{"port":22,"records":99}]"#,
        "1.2.3.4\n5.6.7.8\n2001:db8::1\n",
        r#"{"query_status":"ok","urls":[{"url_status":"online","threat":"malware_download","tags":["elf","mirai"]}]}"#,
        r#"{"query_status":"ok","data":[{"ioc":"1.2.3.4:80","threat_type":"botnet_cc","malware_printable":"Mirai","confidence_level":75}]}"#,
        "# header\nlisted,sha1,reason\n2026-01-01 00:00:00,abcdef0123456789abcdef0123456789abcdef01,Botnet C&C\n",
        "################\n# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n\"1\",\"2026-01-01\",\"http://x/\",\"online\",\"2026-01-01\",\"malware_download\",\"elf\",\"https://urlhaus.abuse.ch/\",\"r\"\n",
        r#"{"count":1,"results":[{"id":"1","name":"p","adversary":"","TLP":"white","tags":["a"],"targeted_countries":["US"],"indicators":[{"type":"IPv4","indicator":"1.2.3.4"}]}]}"#,
        r#"{"abuseConfidenceScore":24,"countryCode":"AU","totalReports":28,"numDistinctUsers":8,"lastReportedAt":"2026-11-15T14:38:20+00:00","usageType":"Data Center","isTor":false}"#,
        r#"{"data":{"ipAddress":"1.2.3.4","abuseConfidenceScore":0,"countryCode":"SE","totalReports":0}}"#,
        r#"[{"id":"1","tbs_sha256":"ab","dns_names":["example.com"],"pubkey_sha256":"cd","not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","revoked":false}]"#,
        "{\"cpes\":[],\"hostnames\":[\"a.example\"],\"ip\":\"1.2.3.4\",\"ports\":[80,443],\"tags\":[],\"vulns\":[\"CVE-2026-1\"]}",
        "example.com\nphish.test\n# comment\n\n",
        r#"[{"victim":"x","group":"g","country":"US","activity":"Technology","discovered":"2026-11-01 00:00:00.000000","attackdate":"2026-10-30 00:00:00.000000"}]"#,
        "$SBL1 ; SBL123\n1.2.3.0/24 ; SBL1\n",
        r#"{"cidr":"1.2.3.0/24","sblid":"SBL1","rir":"arin"}"#,
        "AS1234 | NAME | US\n",
        "15169 | 8.8.8.0/24 | US | arin | 2000-03-30\n",
    ];
    s.iter().map(|x| x.as_bytes().to_vec()).collect()
}

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut b = seed.to_vec();
    match rng.next() % 6 {
        0 => b.truncate((rng.next() as usize) % (b.len() + 1)),
        1 => {
            for _ in 0..=(rng.next() % 8) {
                if !b.is_empty() {
                    let i = (rng.next() as usize) % b.len();
                    b[i] ^= 1 << (rng.next() % 8);
                }
            }
        }
        2 => {
            let i = if b.is_empty() {
                0
            } else {
                (rng.next() as usize) % b.len()
            };
            b.splice(i..i, rng.bytes(32));
        }
        3 => b.extend(std::iter::repeat(b'0').take((rng.next() % 4096) as usize)),
        4 => b = b.repeat(((rng.next() % 40) + 1) as usize),
        _ => {
            let i = if b.is_empty() {
                0
            } else {
                (rng.next() as usize) % b.len()
            };
            b.insert(i, 0);
        }
    }
    b
}

/// Feeds one input to every network-facing parser.
fn feed_all(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    let _ = osint::parse_kev(bytes);
    let _ = osint::parse_epss(bytes);
    let _ = osint::parse_sans_ports(bytes);
    let _ = osint::parse_tor_exits(bytes);
    let _ = osint_abusech::parse_urlhaus_recent(bytes);
    if let Ok(iocs) = osint_abusech::parse_threatfox(bytes) {
        let _ = osint_abusech::summarize_threatfox(&iocs);
    }
    let _ = osint_abusech::parse_sslbl_certs(bytes);
    let _ = osint_abusech::parse_urlhaus_csv(bytes);
    let _ = osint_abuseipdb::parse_check(bytes);
    let _ = osint_certstream::parse_issuances(bytes);
    let _ = osint_otx::parse_pulses(bytes);
    let _ = osint_phishtank::parse_list(bytes);
    let _ = osint_phishtank::host_from_text(&text);
    let _ = osint_internetdb::parse_internetdb(bytes);
    let _ = osint_internetdb::parse_ip_text(&text);
    let _ = osint_spamhaus::parse_drop(bytes, false);
    let _ = osint_spamhaus::parse_drop(bytes, true);
    let _ = osint_spamhaus::parse_asndrop(bytes);
    let _ = osint_geo::parse_origin(&text);
    let _ = osint_geo::parse_asn_name(&text);
    if let Ok(list) = osint_ransomware::parse_recent(bytes, 1_767_225_600_000) {
        let _ = osint_ransomware::summarize(&list, 1_767_225_600_000, 30, 5);
    }
}

#[test]
fn parsers_survive_random_bytes() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..3000 {
        let b = rng.bytes(2048);
        feed_all(&b);
    }
}

#[test]
fn parsers_survive_mutated_real_looking_payloads() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    let seeds = seeds();
    for seed in &seeds {
        feed_all(seed); // the unmodified seeds must also be harmless
    }
    for _ in 0..6000 {
        let seed = &seeds[(rng.next() as usize) % seeds.len()];
        let b = mutate(&mut rng, seed);
        feed_all(&b);
    }
}

#[test]
fn parsers_survive_pathological_shapes() {
    let deep_array = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    let deep_object = format!("{}1{}", "{\"a\":".repeat(50_000), "}".repeat(50_000));
    let huge_number = format!("{{\"abuseConfidenceScore\":{}}}", "9".repeat(10_000));
    let many_rows = "1.2.3.4\n".repeat(200_000);
    let long_line = "a".repeat(2_000_000);
    let invalid_utf8: Vec<u8> = (0..4096).map(|i| 0x80 | (i % 64) as u8).collect();
    let nuls = vec![0u8; 100_000];
    for input in [
        deep_array.as_bytes(),
        deep_object.as_bytes(),
        huge_number.as_bytes(),
        many_rows.as_bytes(),
        long_line.as_bytes(),
        &invalid_utf8,
        &nuls,
        b"",
    ] {
        feed_all(input);
    }
}
