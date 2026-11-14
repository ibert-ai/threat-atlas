//! ATLAS-OSINT-005 - abuse.ch ThreatFox, URLhaus and SSLBL.
//!
//! Pure functions: request builders, bounded parsers for the three feeds, display helpers and the key
//! rules. No network, clock or file system here; the host worker does the requests. See
//! `docs/OSINT-TERMS-ABUSECH.md` for the terms read on 14 November 2026.
//!
//! Proposed registry changes (the entries exist in `osint.rs`):
//! - `Urlhaus`, `ThreatFox`: user's own Auth-Key, non-commercial (fair use), minimum interval 15 minutes
//!   (the provider asks for at least 5). Keep as they are.
//! - `Sslbl`: **no key, CC0** ("free to use without limitations ... for both commercial and
//!   non-commercial purposes", abuse.ch Terms of Use section 3.4). Change `requires_key` to `false` and
//!   `non_commercial_only` to `false`, and the licence text to "CC0 (abuse.ch Terms of Use 3.4)".
//!
//! Rules for the host: the Auth-Key is the user's own, kept in the OS credential store, never logged and
//! never in Git. URLhaus puts the key inside the request path, so nothing that contains that path may
//! be logged or shown (`redact_key`). Never fetch or open a URL taken from the data: show it defanged
//! (`defang`) and link only to the abuse.ch page for the entry.

use serde::Deserialize;

/// Hosts.
pub const THREATFOX_HOST: &str = "threatfox-api.abuse.ch";
pub const URLHAUS_HOST: &str = "urlhaus-api.abuse.ch";
pub const SSLBL_HOST: &str = "sslbl.abuse.ch";
/// Public, keyless SSL certificate blacklist (SHA1 fingerprints).
pub const SSLBL_CERTS_PATH: &str = "/blacklist/sslblacklist.csv";
/// The providers regenerate their dumps every 5 minutes and ask not to be polled more often.
pub const PROVIDER_FLOOR_MS: u64 = 5 * 60 * 1000;
/// Our floor between two successful fetches of the same feed (the registry value).
pub const MIN_INTERVAL_MS: u64 = 15 * 60 * 1000;
// Our floor must never be below the provider's.
const _: () = assert!(MIN_INTERVAL_MS >= PROVIDER_FLOOR_MS);
/// Largest bodies accepted.
pub const MAX_THREATFOX_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_URLHAUS_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SSLBL_BYTES: usize = 4 * 1024 * 1024;

const MAX_IOCS: usize = 5_000;
const MAX_URLHAUS_ROWS: usize = 20_000;
const MAX_SSLBL_ROWS: usize = 5_000;
const MAX_TEXT: usize = 2_048;
const MAX_NAME: usize = 100;
const MAX_TAGS: usize = 20;
const MAX_TAG_LEN: usize = 40;

/// True when the string looks like an abuse.ch Auth-Key: 16 to 128 ASCII letters or digits. Only the
/// provider can tell whether a key is valid. Because URLhaus puts the key in a path, anything else
/// (slashes, dots, spaces) must be rejected, never escaped.
pub fn looks_like_auth_key(key: &str) -> bool {
    (16..=128).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Path for the URLhaus "recent URLs" CSV export. `None` when the key does not look like a key.
/// The returned path contains the secret: do not log it.
pub fn urlhaus_recent_path(key: &str) -> Option<String> {
    looks_like_auth_key(key).then(|| format!("/v2/files/exports/{key}/recent.csv"))
}

/// JSON body for the ThreatFox "recent IOCs" query. `days` is clamped to the documented 1 to 7.
/// Send it as `POST /api/v1/` with the header `Auth-Key: <key>`.
pub fn threatfox_recent_body(days: u8) -> String {
    format!(r#"{{"query":"get_iocs","days":{}}}"#, days.clamp(1, 7))
}

/// Replace every occurrence of the key in a message with `***`, so errors and logs cannot leak it.
pub fn redact_key(text: &str, key: &str) -> String {
    if key.is_empty() {
        text.to_string()
    } else {
        text.replace(key, "***")
    }
}

/// Make a URL or host safe to show: `http` becomes `hxxp`, dots become `[.]`, and `@`, spaces and control
/// characters are replaced, so it cannot be clicked or auto-linked by accident.
pub fn defang(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    let lower = s.to_ascii_lowercase();
    let rest = if lower.starts_with("http") {
        out.push_str("hxxp");
        &s[4..]
    } else if lower.starts_with("ftp") {
        out.push_str("fxp");
        &s[3..]
    } else {
        s
    };
    for c in rest.chars() {
        match c {
            '.' => out.push_str("[.]"),
            '@' => out.push_str("[at]"),
            c if c.is_control() || c.is_whitespace() => out.push('_'),
            c => out.push(c),
        }
    }
    out
}

fn clean(s: &str, max: usize) -> Option<String> {
    let t = s.trim();
    (!t.is_empty() && t.len() <= max && !t.chars().any(char::is_control)).then(|| t.to_string())
}

fn clean_tags<'a>(tags: impl Iterator<Item = &'a str>) -> Vec<String> {
    tags.filter_map(|t| clean(t, MAX_TAG_LEN))
        .take(MAX_TAGS)
        .collect()
}

/// `YYYY-MM-DD HH:MM:SS` with an optional trailing ` UTC`, as milliseconds since the Unix epoch.
fn time_ms(s: &str) -> Option<u64> {
    let t = s.trim().trim_end_matches("UTC").trim();
    let n = chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S").ok()?;
    u64::try_from(n.and_utc().timestamp_millis()).ok()
}

fn https_link(s: &str, prefix: &str) -> Option<String> {
    clean(s, MAX_TEXT).filter(|u| u.starts_with(prefix))
}

// ---------------------------------------------------------------- ThreatFox

/// One ThreatFox indicator of compromise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreatFoxIoc {
    pub id: u64,
    /// The indicator: domain, `ip:port`, URL or hash. Never fetch or open it.
    pub ioc: String,
    /// For example `domain`, `ip:port`, `url`, `sha256_hash`.
    pub ioc_type: String,
    /// For example `botnet_cc`, `payload_delivery`.
    pub threat_type: String,
    pub malware: String,
    /// 0 to 100; an out-of-range value becomes 0.
    pub confidence: u8,
    pub first_seen_ms: Option<u64>,
    pub tags: Vec<String>,
    /// A reference link, only when it is an https URL.
    pub reference: Option<String>,
}

#[derive(Deserialize)]
struct TfEnvelope {
    query_status: String,
    #[serde(default)]
    data: serde_json::Value,
}

#[derive(Deserialize)]
struct TfRaw {
    #[serde(default)]
    id: serde_json::Value,
    #[serde(default)]
    ioc: String,
    #[serde(default)]
    ioc_type: String,
    #[serde(default)]
    threat_type: String,
    #[serde(default)]
    malware_printable: Option<String>,
    #[serde(default)]
    malware: Option<String>,
    #[serde(default)]
    confidence_level: i64,
    #[serde(default)]
    first_seen: Option<String>,
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

/// Parse a ThreatFox `get_iocs` answer. `no_result` is an empty list; any other non-`ok` status (for
/// example an authentication problem) is an error that carries only the status word. Bad records are
/// skipped; the list is capped.
pub fn parse_threatfox(bytes: &[u8]) -> Result<Vec<ThreatFoxIoc>, String> {
    if bytes.len() > MAX_THREATFOX_BYTES {
        return Err("ThreatFox: response too large".into());
    }
    let env: TfEnvelope =
        serde_json::from_slice(bytes).map_err(|e| format!("ThreatFox JSON: {e}"))?;
    match env.query_status.as_str() {
        "ok" => {}
        "no_result" => return Ok(Vec::new()),
        other => {
            let word: String = other
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(40)
                .collect();
            return Err(format!("ThreatFox query_status: {word}"));
        }
    }
    let rows: Vec<serde_json::Value> = match env.data {
        serde_json::Value::Array(rows) => rows,
        _ => return Err("ThreatFox: data is not a list".into()),
    };
    Ok(rows
        .into_iter()
        .filter_map(|v| serde_json::from_value::<TfRaw>(v).ok())
        .filter_map(|r| {
            let id = match &r.id {
                serde_json::Value::String(s) => s.parse::<u64>().ok()?,
                serde_json::Value::Number(n) => n.as_u64()?,
                _ => return None,
            };
            let name = r
                .malware_printable
                .as_deref()
                .or(r.malware.as_deref())
                .and_then(|m| clean(m, MAX_NAME))
                .unwrap_or_else(|| "unknown".into());
            Some(ThreatFoxIoc {
                id,
                ioc: clean(&r.ioc, MAX_TEXT)?,
                ioc_type: clean(&r.ioc_type, 32)?,
                threat_type: clean(&r.threat_type, 40)?,
                malware: name,
                confidence: u8::try_from(r.confidence_level)
                    .ok()
                    .filter(|c| *c <= 100)
                    .unwrap_or(0),
                first_seen_ms: r.first_seen.as_deref().and_then(time_ms),
                tags: clean_tags(r.tags.iter().flatten().map(String::as_str)),
                reference: r
                    .reference
                    .as_deref()
                    .and_then(|u| https_link(u, "https://")),
            })
        })
        .take(MAX_IOCS)
        .collect())
}

/// The `n` most reported malware names with their IOC counts, most frequent first (ties by name).
pub fn top_malware(iocs: &[ThreatFoxIoc], n: usize) -> Vec<(String, u32)> {
    let mut counts: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
    for i in iocs {
        *counts.entry(i.malware.as_str()).or_insert(0) += 1;
    }
    let mut v: Vec<(String, u32)> = counts
        .into_iter()
        .map(|(k, c)| (k.to_string(), c))
        .collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

// ------------------------------------------------------------------- SSLBL

/// One blacklisted SSL certificate from SSLBL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SslblCert {
    pub listed_ms: u64,
    /// 40 lowercase hex characters.
    pub sha1: String,
    /// Why it is listed, for example `Vidar C&C`.
    pub reason: String,
}

/// Parse the SSLBL certificate blacklist CSV (`Listingdate,SHA1,Listingreason`, `#` comment lines).
/// Bad rows are skipped, the SHA1 is lower-cased, the newest rows come first, the list is capped.
pub fn parse_sslbl_certs(bytes: &[u8]) -> Result<Vec<SslblCert>, String> {
    if bytes.len() > MAX_SSLBL_BYTES {
        return Err("SSLBL: response too large".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "SSLBL: not UTF-8".to_string())?;
    let mut rows: Vec<SslblCert> = text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut p = l.splitn(3, ',');
            let (date, sha, reason) = (p.next()?, p.next()?.trim(), p.next()?);
            let sha = sha.to_ascii_lowercase();
            (sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit())).then_some(())?;
            Some(SslblCert {
                listed_ms: time_ms(date)?,
                sha1: sha,
                reason: clean(reason, MAX_NAME)?,
            })
        })
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.listed_ms));
    rows.truncate(MAX_SSLBL_ROWS);
    Ok(rows)
}

// ----------------------------------------------------------------- URLhaus

/// One URLhaus entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlhausEntry {
    pub id: u64,
    pub added_ms: u64,
    /// The malicious URL. Never fetch or open it; show `defang(&url)`.
    pub url: String,
    pub online: bool,
    pub threat: String,
    pub tags: Vec<String>,
    /// The abuse.ch page for this entry, always under `https://urlhaus.abuse.ch/`.
    pub link: String,
}

/// Split one CSV line with double-quoted fields (`""` is a quote inside a field).
fn split_csv(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// Parse the URLhaus recent-URLs CSV. The column layout is read from the `# id,dateadded,url,...`
/// header comment and columns are found by name; an unknown layout is an error rather than a guess.
/// (The column names are the commonly published ones and could not be checked against a live file,
/// because an Auth-Key is required.) Bad rows are skipped; URLs must be `http`, `https` or `ftp`; the
/// entry link must be under `https://urlhaus.abuse.ch/`.
pub fn parse_urlhaus_csv(bytes: &[u8]) -> Result<Vec<UrlhausEntry>, String> {
    if bytes.len() > MAX_URLHAUS_BYTES {
        return Err("URLhaus: response too large".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "URLhaus: not UTF-8".to_string())?;
    let header = text
        .lines()
        .find(|l| l.starts_with('#') && l.contains("dateadded") && l.contains("url"))
        .ok_or_else(|| "URLhaus: unknown CSV layout (no header line)".to_string())?;
    let names: Vec<String> = header
        .trim_start_matches('#')
        .split(',')
        .map(|n| n.trim().to_ascii_lowercase())
        .collect();
    let col = |name: &str| names.iter().position(|n| n == name);
    let (
        Some(c_id),
        Some(c_added),
        Some(c_url),
        Some(c_status),
        Some(c_threat),
        Some(c_tags),
        Some(c_link),
    ) = (
        col("id"),
        col("dateadded"),
        col("url"),
        col("url_status"),
        col("threat"),
        col("tags"),
        col("urlhaus_link"),
    )
    else {
        return Err("URLhaus: unknown CSV layout (missing columns)".into());
    };
    let need = [c_id, c_added, c_url, c_status, c_threat, c_tags, c_link]
        .into_iter()
        .max()
        .unwrap_or(0);
    Ok(text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let f = split_csv(l);
            if f.len() <= need {
                return None;
            }
            let url = clean(&f[c_url], MAX_TEXT)?;
            let lower = url.to_ascii_lowercase();
            (lower.starts_with("http://")
                || lower.starts_with("https://")
                || lower.starts_with("ftp://"))
            .then_some(())?;
            Some(UrlhausEntry {
                id: f[c_id].trim().parse().ok()?,
                added_ms: time_ms(&f[c_added])?,
                url,
                online: f[c_status].trim().eq_ignore_ascii_case("online"),
                threat: clean(&f[c_threat], 40).unwrap_or_else(|| "unknown".into()),
                tags: clean_tags(f[c_tags].split(',')),
                link: https_link(&f[c_link], "https://urlhaus.abuse.ch/")?,
            })
        })
        .take(MAX_URLHAUS_ROWS)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TF_OK: &str = include_str!("../tests/fixtures/osint/abusech/threatfox-ok.json");
    const TF_NONE: &str = include_str!("../tests/fixtures/osint/abusech/threatfox-no-result.json");
    const TF_ERR: &str = include_str!("../tests/fixtures/osint/abusech/threatfox-error.json");
    const TF_MESSY: &str = include_str!("../tests/fixtures/osint/abusech/threatfox-messy.json");
    const TF_BAD: &str = include_str!("../tests/fixtures/osint/abusech/threatfox-malformed.json");
    const SSL_OK: &str = include_str!("../tests/fixtures/osint/abusech/sslbl-certs.csv");
    const SSL_MESSY: &str = include_str!("../tests/fixtures/osint/abusech/sslbl-messy.csv");
    const UH_OK: &str = include_str!("../tests/fixtures/osint/abusech/urlhaus-recent.csv");
    const UH_MESSY: &str = include_str!("../tests/fixtures/osint/abusech/urlhaus-messy.csv");
    const UH_UNKNOWN: &str =
        include_str!("../tests/fixtures/osint/abusech/urlhaus-unknown-layout.csv");

    #[test]
    fn threatfox_documented_example_parses() {
        let iocs = parse_threatfox(TF_OK.as_bytes()).unwrap();
        assert_eq!(iocs.len(), 2);
        assert_eq!(iocs[0].id, 41);
        assert_eq!(iocs[0].ioc, "gaga.com");
        assert_eq!(iocs[0].ioc_type, "domain");
        assert_eq!(iocs[0].threat_type, "botnet_cc");
        assert_eq!(iocs[0].malware, "Dridex");
        assert_eq!(iocs[0].confidence, 50);
        assert_eq!(iocs[0].first_seen_ms, Some(1_607_434_587_000));
        assert_eq!(iocs[0].tags, vec!["exe", "test"]);
        assert_eq!(
            iocs[0].reference.as_deref(),
            Some("https://twitter.com/JAMESWT_MHT/status/1336229725082177536")
        );
        assert_eq!(iocs[1].reference, None);
        assert_eq!(top_malware(&iocs, 5), vec![("Dridex".to_string(), 2)]);
    }

    #[test]
    fn threatfox_status_words_are_handled() {
        assert_eq!(parse_threatfox(TF_NONE.as_bytes()), Ok(Vec::new()));
        let err = parse_threatfox(TF_ERR.as_bytes()).unwrap_err();
        assert_eq!(err, "ThreatFox query_status: unauthorized");
        assert!(parse_threatfox(TF_BAD.as_bytes()).is_err());
        assert!(parse_threatfox(b"").is_err());
        assert!(parse_threatfox(br#"{"query_status":"ok","data":"text"}"#).is_err());
        assert!(parse_threatfox(&vec![b' '; MAX_THREATFOX_BYTES + 1]).is_err());
    }

    #[test]
    fn threatfox_messy_records_are_skipped_or_cleaned() {
        let iocs = parse_threatfox(TF_MESSY.as_bytes()).unwrap();
        assert_eq!(
            iocs.len(),
            2,
            "bad id, over-long and control-character records dropped"
        );
        assert_eq!(iocs[0].ioc, "198.51.100.7:443");
        assert_eq!(iocs[0].malware, "Cobalt Strike");
        assert_eq!(iocs[0].reference, None, "javascript: is not a link");
        assert_eq!(
            iocs[0].tags.len(),
            MAX_TAGS,
            "tags capped, control-character tag dropped"
        );
        assert_eq!(iocs[1].ioc, "ok.example.net");
        assert_eq!(iocs[1].confidence, 0, "999 is out of range");
        assert_eq!(iocs[1].first_seen_ms, None);
        assert!(iocs[1].tags.is_empty());
    }

    #[test]
    fn sslbl_real_excerpt_parses_newest_first() {
        let rows = parse_sslbl_certs(SSL_OK.as_bytes()).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].sha1, "0d04a50138c74a1ecfa1a7b4a3afddeb2a4be571");
        assert_eq!(rows[0].reason, "QuasarRAT C&C");
        assert!(rows.windows(2).all(|w| w[0].listed_ms >= w[1].listed_ms));
        assert_eq!(rows[0].listed_ms, 1_794_645_311_000);
    }

    #[test]
    fn sslbl_messy_rows_are_skipped_or_normalised() {
        let rows = parse_sslbl_certs(SSL_MESSY.as_bytes()).unwrap();
        let reasons: Vec<&str> = rows.iter().map(|r| r.reason.as_str()).collect();
        assert_eq!(reasons, vec!["Upper case hash", "Reason, with a comma"]);
        assert_eq!(
            rows[0].sha1, "0d04a50138c74a1ecfa1a7b4a3afddeb2a4be572",
            "lower-cased"
        );
        assert!(parse_sslbl_certs(&[0xff, 0xfe]).is_err());
        assert!(parse_sslbl_certs(&vec![b' '; MAX_SSLBL_BYTES + 1]).is_err());
    }

    #[test]
    fn urlhaus_rows_parse_by_header_names() {
        let rows = parse_urlhaus_csv(UH_OK.as_bytes()).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].id, 1_000_001);
        assert!(rows[0].online && !rows[1].online);
        assert_eq!(rows[0].tags, vec!["elf", "Mozi"]);
        assert_eq!(
            rows[1].url, "https://dropper.example.invalid/a.exe?x=1,2",
            "comma inside quotes"
        );
        assert!(rows[2].tags.is_empty());
        assert_eq!(rows[0].link, "https://urlhaus.abuse.ch/url/1000001/");
        assert_eq!(rows[0].threat, "malware_download");
    }

    #[test]
    fn urlhaus_messy_rows_and_unknown_layouts() {
        let rows = parse_urlhaus_csv(UH_MESSY.as_bytes()).unwrap();
        assert!(rows.is_empty(), "every messy row is rejected: {rows:?}");
        assert!(parse_urlhaus_csv(UH_UNKNOWN.as_bytes()).is_err());
        assert!(parse_urlhaus_csv(b"").is_err());
        assert!(parse_urlhaus_csv(&vec![b' '; MAX_URLHAUS_BYTES + 1]).is_err());
        // A row whose link is off-site is dropped even when everything else is fine.
        let off = "# id,dateadded,url,url_status,threat,tags,urlhaus_link\n\"9\",\"2026-11-14 08:00:00\",\"http://a.example.invalid/\",\"online\",\"t\",\"\",\"https://evil.example/x\"\n";
        assert!(parse_urlhaus_csv(off.as_bytes()).unwrap().is_empty());
        // Columns may be in another order.
        let moved = "# urlhaus_link,tags,threat,url_status,url,dateadded,id\n\"https://urlhaus.abuse.ch/url/9/\",\"\",\"t\",\"offline\",\"http://a.example.invalid/\",\"2026-11-14 08:00:00\",\"9\"\n";
        let r = parse_urlhaus_csv(moved.as_bytes()).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, 9);
        assert!(!r[0].online);
    }

    #[test]
    fn key_rules_and_request_builders() {
        let key = "a1B2c3D4e5F6g7H8i9J0";
        assert!(looks_like_auth_key(key));
        assert!(!looks_like_auth_key("short"));
        assert!(!looks_like_auth_key("../../etc/passwd/aaaaaaaa"));
        assert!(!looks_like_auth_key(&"a".repeat(129)));
        assert_eq!(
            urlhaus_recent_path(key).as_deref(),
            Some("/v2/files/exports/a1B2c3D4e5F6g7H8i9J0/recent.csv")
        );
        assert_eq!(urlhaus_recent_path("a/b"), None);
        assert_eq!(threatfox_recent_body(0), r#"{"query":"get_iocs","days":1}"#);
        assert_eq!(threatfox_recent_body(3), r#"{"query":"get_iocs","days":3}"#);
        assert_eq!(
            threatfox_recent_body(200),
            r#"{"query":"get_iocs","days":7}"#
        );
        let path = urlhaus_recent_path(key).unwrap();
        let msg = format!("GET {path} failed");
        assert!(!redact_key(&msg, key).contains(key));
        assert_eq!(redact_key("no key here", ""), "no key here");
    }

    #[test]
    fn defang_makes_links_inert() {
        assert_eq!(
            defang("http://evil.example.invalid/a.exe"),
            "hxxp://evil[.]example[.]invalid/a[.]exe"
        );
        assert_eq!(defang("HTTPS://X.example"), "hxxpS://X[.]example");
        assert_eq!(defang("ftp://a.example"), "fxp://a[.]example");
        assert_eq!(defang("user@host.example"), "user[at]host[.]example");
        assert_eq!(defang("a b\tc"), "a_b_c");
        assert!(!defang("http://evil.example.invalid/").contains("http"));
    }
}
