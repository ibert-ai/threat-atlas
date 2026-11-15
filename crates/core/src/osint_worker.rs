//! OSINT worker: CISA KEV + FIRST EPSS, Tor exit count, SANS ISC top ports.
//!
//! Network work is kept off the render thread. Each source has a persisted rate gate so a
//! restart cannot bypass the provider's floor. Keys and provider terms live in the source
//! registry (`crate::osint`); this worker only fetches public, keyless data.

use crate::osint_net::{Fetch, Reply};
use crate::{
    feed::now_ms,
    osint::{self, EpssScore, KevWithEpss, RateGate, SansReport, Source},
    osint_abusech,
    osint_internetdb::{self, InternetDbHost, Lookup},
    osint_phishtank::{self, DomainSet, FeedState},
    osint_ransomware::{self, RansomError, Summary as RansomSummary},
    osint_spamhaus::{self, AsnList, DropList},
};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

static FETCH: std::sync::OnceLock<Fetch> = std::sync::OnceLock::new();

/// Fetches with the function the host supplied at start. No answer when none was set.
fn fetch_public(host: &str, path: &str, headers: &str, max_bytes: usize) -> Option<Reply> {
    (FETCH.get()?)(host, path, headers, max_bytes)
}

/// Writes next to the target and renames, so a crash never leaves a half-written file.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

const KEV_HOST: &str = "www.cisa.gov";
const KEV_PATH: &str = "/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_HOST: &str = "epss.empiricalsecurity.com";
const EPSS_PATH: &str = "/epss_scores-current.csv.gz";
const TOR_HOST: &str = "check.torproject.org";
const TOR_PATH: &str = "/torbulkexitlist";
const SANS_HOST: &str = "isc.sans.edu";
const SANS_PATH: &str = "/api/topports/records/10?json";
const MAX_KEV_BYTES: usize = 8 * 1024 * 1024;
const MAX_EPSS_BYTES: usize = 16 * 1024 * 1024;
const MAX_EPSS_UNPACKED: u64 = 64 * 1024 * 1024;
const MAX_TOR_BYTES: usize = 2 * 1024 * 1024;
const MAX_SANS_BYTES: usize = 2 * 1024 * 1024;
const KEV_LIMIT: usize = 2_000;
const MAX_RANSOM_BYTES: usize = osint_ransomware::MAX_BODY_BYTES;
const SPAMHAUS_FILES: [(&str, &str); 3] = [
    (osint_spamhaus::DROP_V4_PATH, "spamhaus-drop_v4.json"),
    (osint_spamhaus::DROP_V6_PATH, "spamhaus-drop_v6.json"),
    (osint_spamhaus::ASN_DROP_PATH, "spamhaus-asndrop.json"),
];
const EPSS_FILE: &str = "osint-epss.json";
const PHISH_FILE: &str = "phishingdb-domains.txt";
const INTERNETDB_HOST: &str = "internetdb.shodan.io";
const INTERNETDB_CACHE_MAX: usize = 200;

/// Data shown by the host. Cheap to clone; the host reads it once per frame.
#[derive(Clone, Debug, Default)]
pub struct View {
    pub kev: Vec<KevWithEpss>,
    pub kev_updated_ms: u64,
    pub epss_updated_ms: u64,
    pub tor_count: usize,
    pub tor_updated_ms: u64,
    pub sans: Option<SansReport>,
    pub sans_updated_ms: u64,
    pub note: String,
    /// Last problem per source, keyed by the source label used in the worker ("KEV", "Tor", ...).
    pub notes: std::collections::BTreeMap<String, String>,
    /// Ransomware incidents of the last 30 days as counts only (no victim data).
    pub ransom: Option<RansomSummary>,
    pub ransom_updated_ms: u64,
    pub spamhaus: Option<Arc<SpamhausData>>,
    pub phish: Option<Arc<DomainSet>>,
    pub phish_state: FeedState,
    pub sslbl_total: usize,
    pub sslbl_top: Vec<(String, u32)>,
    pub sslbl_newest_ms: u64,
    pub sslbl_updated_ms: u64,
    /// Last click-only InternetDB lookup, kept until the next one.
    pub lookup: Option<LookupView>,
    pub lookup_pending: bool,
}

/// Spamhaus DROP netblocks and ASN-DROP, parsed from the last good downloads.
#[derive(Clone, Debug, Default)]
pub struct SpamhausData {
    pub v4: DropList,
    pub v6: DropList,
    pub asn: AsnList,
    pub updated_ms: u64,
}

/// Result of one InternetDB lookup the user asked for.
#[derive(Clone, Debug)]
pub struct LookupView {
    pub ip: String,
    /// `Ok(None)` is the provider's "no information" answer.
    pub outcome: Result<Option<InternetDbHost>, String>,
    pub at_ms: u64,
    pub from_cache: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct Cache {
    kev: Vec<KevWithEpss>,
    kev_updated_ms: u64,
    /// About 400,000 scores. Kept in its own file (`osint-epss.json`) so the small cache is not rewritten
    /// with 25 MB every time a source updates; still read from an older cache file.
    #[serde(skip_serializing)]
    epss: Vec<EpssScore>,
    epss_updated_ms: u64,
    tor: Vec<IpAddr>,
    tor_updated_ms: u64,
    sans: Option<SansReport>,
    sans_updated_ms: u64,
    /// IP -> (fetched at, answer). `None` answer means "no information". At most 200 entries.
    internetdb: BTreeMap<String, (u64, Option<InternetDbHost>)>,
    ransom: Option<RansomSummary>,
    ransom_updated_ms: u64,
    spamhaus_updated_ms: u64,
    phish_state: FeedState,
    phish_fingerprint: String,
    sslbl_total: usize,
    sslbl_top: Vec<(String, u32)>,
    sslbl_newest_ms: u64,
    sslbl_updated_ms: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Validators {
    etag: Option<String>,
    last_modified: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Gates {
    gates: BTreeMap<String, RateGate>,
    validators: BTreeMap<String, Validators>,
}

struct Fetched {
    body: Vec<u8>,
    etag: Option<String>,
    last_modified: Option<String>,
}

enum Command {
    Refresh,
    Lookup(IpAddr),
}

/// One background OSINT worker. Started only after licence consent, never by the offline smoke.
pub struct Osint {
    shared: Arc<Mutex<View>>,
    wake: Sender<Command>,
    enabled: Arc<Mutex<Vec<String>>>,
}

/// Whether a source may make requests, given the ids the user turned on.
pub fn is_enabled(enabled: &[String], source: Source) -> bool {
    let id = osint::source_spec(source).id;
    // EPSS scores exist to enrich the KEV list, so the KEV switch covers them.
    let kev = source == Source::Epss && enabled.iter().any(|e| e == "cisa-kev");
    kev || enabled.iter().any(|e| e == id)
}

impl Osint {
    pub fn start(directory: PathBuf, enabled: Vec<String>, fetch: Fetch) -> Self {
        let _ = FETCH.set(fetch);
        let shared = Arc::new(Mutex::new(View::default()));
        let enabled = Arc::new(Mutex::new(enabled));
        let (wake, rx) = mpsc::channel();
        let state = shared.clone();
        let switches = enabled.clone();
        thread::spawn(move || worker(directory, state, rx, switches));
        Self {
            shared,
            wake,
            enabled,
        }
    }

    /// Replaces the set of sources that may make requests and wakes the worker. A source that is off
    /// makes no request at all, including no lookup.
    pub fn set_enabled(&self, enabled: Vec<String>) {
        *self.enabled.lock().unwrap() = enabled;
        let _ = self.wake.send(Command::Refresh);
    }

    pub fn view(&self) -> View {
        self.shared.lock().unwrap().clone()
    }

    pub fn refresh(&self) {
        let _ = self.wake.send(Command::Refresh);
    }

    /// Ids of the sources that are switched on.
    pub fn enabled(&self) -> Vec<String> {
        self.enabled.lock().unwrap().clone()
    }

    /// Queues one InternetDB lookup. Only the host's click handler calls this, after the user has
    /// confirmed that the address will be sent to Shodan.
    pub fn lookup(&self, ip: IpAddr) {
        if osint_internetdb::is_lookup_allowed(ip)
            && is_enabled(&self.enabled.lock().unwrap(), Source::ShodanInternetDb)
        {
            self.shared.lock().unwrap().lookup_pending = true;
            let _ = self.wake.send(Command::Lookup(ip));
        }
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    let meta = fs::metadata(path).ok()?;
    if meta.len() > 64 * 1024 * 1024 {
        return None;
    }
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

fn save<T: Serialize>(path: &Path, value: &T) {
    if let Ok(bytes) = serde_json::to_vec(value) {
        let _ = write_atomic(path, &bytes);
    }
}

fn publish(
    shared: &Mutex<View>,
    cache: &Cache,
    notes: &std::collections::BTreeMap<String, String>,
) {
    let mut view = shared.lock().unwrap();
    let spamhaus = view.spamhaus.take();
    let phish = view.phish.take();
    let lookup = view.lookup.take();
    let lookup_pending = view.lookup_pending;
    *view = View {
        kev: cache.kev.clone(),
        kev_updated_ms: cache.kev_updated_ms,
        epss_updated_ms: cache.epss_updated_ms,
        tor_count: cache.tor.len(),
        tor_updated_ms: cache.tor_updated_ms,
        sans: cache.sans.clone(),
        sans_updated_ms: cache.sans_updated_ms,
        note: notes.values().cloned().collect::<Vec<_>>().join(" | "),
        notes: notes.clone(),
        ransom: cache.ransom.clone(),
        ransom_updated_ms: cache.ransom_updated_ms,
        spamhaus,
        phish,
        phish_state: cache.phish_state.clone(),
        sslbl_total: cache.sslbl_total,
        sslbl_top: cache.sslbl_top.clone(),
        sslbl_newest_ms: cache.sslbl_newest_ms,
        sslbl_updated_ms: cache.sslbl_updated_ms,
        lookup,
        lookup_pending,
    };
}

fn load_spamhaus(directory: &Path, updated_ms: u64) -> Option<SpamhausData> {
    let read = |name: &str| fs::read(directory.join(name)).ok();
    Some(SpamhausData {
        v4: osint_spamhaus::parse_drop(&read(SPAMHAUS_FILES[0].1)?, false).ok()?,
        v6: osint_spamhaus::parse_drop(&read(SPAMHAUS_FILES[1].1)?, true).ok()?,
        asn: osint_spamhaus::parse_asndrop(&read(SPAMHAUS_FILES[2].1)?).ok()?,
        updated_ms,
    })
}

fn lookup_internetdb(ip: IpAddr, cache: &mut Cache, last_request: &mut Option<u64>) -> LookupView {
    let key = ip.to_string();
    let now = now_ms();
    let view = |outcome, at_ms, from_cache| LookupView {
        ip: key.clone(),
        outcome,
        at_ms,
        from_cache,
    };
    if let Some((at, host)) = cache.internetdb.get(&key) {
        if osint_internetdb::cache_fresh(*at, now) {
            return view(Ok(host.clone()), *at, true);
        }
    }
    let Some(path) = osint_internetdb::lookup_path(ip) else {
        return view(
            Err("Not a public address; nothing was sent.".into()),
            now,
            false,
        );
    };
    if !osint_internetdb::gap_elapsed(*last_request, now) {
        thread::sleep(Duration::from_millis(osint_internetdb::MIN_GAP_MS));
    }
    *last_request = Some(now_ms());
    let headers = "Accept: application/json\r\nUser-Agent: AtlasSOC-OSINT (+https://ibert.se)\r\n";
    let answer = match fetch_public(
        INTERNETDB_HOST,
        &path,
        headers,
        osint_internetdb::MAX_BODY_BYTES,
    ) {
        None => Err("InternetDB: no connection.".to_string()),
        Some(reply) if reply.status == 200 || reply.status == 404 => {
            match osint_internetdb::parse_internetdb(&reply.body) {
                Ok(Lookup::Found(host)) if host.ip == key => Ok(Some(host)),
                Ok(Lookup::Found(_)) => Err("InternetDB: answer is for another address.".into()),
                Ok(Lookup::NoInformation) => Ok(None),
                Err(error) => Err(error),
            }
        }
        Some(reply) if reply.status == 429 => {
            Err("InternetDB: rate limit reached. Try again later.".into())
        }
        Some(reply) => Err(format!("InternetDB: HTTP {}.", reply.status)),
    };
    let at = now_ms();
    if let Ok(host) = &answer {
        if cache.internetdb.len() >= INTERNETDB_CACHE_MAX {
            if let Some(oldest) = cache
                .internetdb
                .iter()
                .min_by_key(|(_, (t, _))| *t)
                .map(|(k, _)| k.clone())
            {
                cache.internetdb.remove(&oldest);
            }
        }
        cache.internetdb.insert(key.clone(), (at, host.clone()));
    }
    view(answer, at, false)
}

fn gate(gates: &mut Gates, source: Source) -> &mut RateGate {
    gates
        .gates
        .entry(osint::source_spec(source).id.to_owned())
        .or_default()
}

fn validators(gates: &Gates, source: Source) -> Validators {
    gates
        .validators
        .get(osint::source_spec(source).id)
        .cloned()
        .unwrap_or_default()
}

fn remember(gates: &mut Gates, source: Source, fetched: &Fetched) {
    gates.validators.insert(
        osint::source_spec(source).id.to_owned(),
        Validators {
            etag: fetched.etag.clone(),
            last_modified: fetched.last_modified.clone(),
        },
    );
}

fn get(
    host: &str,
    path: &str,
    max_bytes: usize,
    validators: &Validators,
) -> Result<Option<Fetched>, (u16, Option<u64>)> {
    let mut headers = String::from(
        "Accept: application/json\r\nUser-Agent: AtlasSOC-OSINT (+https://ibert.se)\r\n",
    );
    headers.push_str(&osint::conditional_headers(
        validators.etag.as_deref(),
        validators.last_modified.as_deref(),
    ));
    let reply = fetch_public(host, path, &headers, max_bytes).ok_or((0, None))?;
    match reply.status {
        200 => Ok(Some(Fetched {
            body: reply.body,
            etag: reply.etag,
            last_modified: reply.last_modified,
        })),
        304 => Ok(None),
        429 => Err((429, reply.retry_after_s)),
        300..=399 => Err((reply.status, None)),
        status => Err((status, reply.retry_after_s)),
    }
}

fn gunzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = GzDecoder::new(bytes);
    let mut out = Vec::new();
    decoder
        .by_ref()
        .take(MAX_EPSS_UNPACKED)
        .read_to_end(&mut out)
        .map_err(|e| format!("gzip: {e}"))?;
    if out.len() as u64 >= MAX_EPSS_UNPACKED {
        return Err("EPSS data exceeds the unpacked limit".into());
    }
    Ok(out)
}

fn worker(
    directory: PathBuf,
    shared: Arc<Mutex<View>>,
    rx: Receiver<Command>,
    enabled: Arc<Mutex<Vec<String>>>,
) {
    let on = |source: Source| is_enabled(&enabled.lock().unwrap(), source);
    let _ = fs::create_dir_all(&directory);
    let state_path = directory.join("osint-state.json");
    let cache_path = directory.join("osint-cache.json");
    let mut gates: Gates = read_json(&state_path).unwrap_or_default();
    let mut cache: Cache = read_json(&cache_path).unwrap_or_default();
    if cache.epss.is_empty() {
        cache.epss = read_json(&directory.join(EPSS_FILE)).unwrap_or_default();
    }
    let mut notes: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    let mut last_internetdb: Option<u64> = None;
    publish(&shared, &cache, &notes);
    if let Some(body) = on(Source::PhishTank)
        .then(|| fs::read(directory.join(PHISH_FILE)).ok())
        .flatten()
    {
        if let Ok(set) = osint_phishtank::parse_list(&body) {
            shared.lock().unwrap().phish = Some(Arc::new(set));
        }
    }
    if cache.spamhaus_updated_ms != 0 && on(Source::SpamhausDrop) {
        let loaded = load_spamhaus(&directory, cache.spamhaus_updated_ms).map(Arc::new);
        shared.lock().unwrap().spamhaus = loaded;
    }

    loop {
        let now = now_ms();
        let mut dirty = false;

        // EPSS first: KEV is joined against the latest usable scores.
        let epss_spec = osint::source_spec(Source::Epss);
        if on(Source::Epss) && gate(&mut gates, Source::Epss).due(now) {
            let saved = validators(&gates, Source::Epss);
            match get(EPSS_HOST, EPSS_PATH, MAX_EPSS_BYTES, &saved) {
                Ok(Some(fetched)) => {
                    match gunzip(&fetched.body).and_then(|csv| osint::parse_epss(&csv)) {
                        Ok(scores) => {
                            save(&directory.join(EPSS_FILE), &scores);
                            cache.epss = scores;
                            cache.epss_updated_ms = now;
                            remember(&mut gates, Source::Epss, &fetched);
                            gate(&mut gates, Source::Epss).success(now, epss_spec.min_interval_ms);
                            notes.remove("EPSS");
                        }
                        Err(error) => {
                            notes.insert("EPSS".to_string(), format!("EPSS: {error}"));
                            gate(&mut gates, Source::Epss).failure(now, epss_spec.min_interval_ms);
                        }
                    }
                }
                Ok(None) => {
                    gate(&mut gates, Source::Epss).success(now, epss_spec.min_interval_ms);
                }
                Err((status, retry)) => {
                    notes.insert("EPSS".to_string(), format!("EPSS: HTTP {status}"));
                    match retry {
                        Some(seconds) => gate(&mut gates, Source::Epss).retry_after(now, seconds),
                        None => {
                            gate(&mut gates, Source::Epss).failure(now, epss_spec.min_interval_ms)
                        }
                    }
                }
            }
            dirty = true;
        }

        let kev_spec = osint::source_spec(Source::CisaKev);
        if on(Source::CisaKev) && gate(&mut gates, Source::CisaKev).due(now) {
            let saved = validators(&gates, Source::CisaKev);
            match get(KEV_HOST, KEV_PATH, MAX_KEV_BYTES, &saved) {
                Ok(Some(fetched)) => match osint::parse_kev(&fetched.body) {
                    Ok(entries) => {
                        cache.kev = osint::join_kev_epss(entries, cache.epss.clone(), KEV_LIMIT);
                        cache.kev_updated_ms = now;
                        remember(&mut gates, Source::CisaKev, &fetched);
                        gate(&mut gates, Source::CisaKev).success(now, kev_spec.min_interval_ms);
                        notes.remove("KEV");
                    }
                    Err(error) => {
                        notes.insert("KEV".to_string(), format!("KEV: {error}"));
                        gate(&mut gates, Source::CisaKev).failure(now, kev_spec.min_interval_ms);
                    }
                },
                Ok(None) => {
                    gate(&mut gates, Source::CisaKev).success(now, kev_spec.min_interval_ms);
                }
                Err((status, retry)) => {
                    notes.insert("KEV".to_string(), format!("KEV: HTTP {status}"));
                    match retry {
                        Some(seconds) => {
                            gate(&mut gates, Source::CisaKev).retry_after(now, seconds)
                        }
                        None => {
                            gate(&mut gates, Source::CisaKev).failure(now, kev_spec.min_interval_ms)
                        }
                    }
                }
            }
            dirty = true;
        }

        let tor_spec = osint::source_spec(Source::TorExit);
        if on(Source::TorExit) && gate(&mut gates, Source::TorExit).due(now) {
            let saved = validators(&gates, Source::TorExit);
            match get(TOR_HOST, TOR_PATH, MAX_TOR_BYTES, &saved) {
                Ok(Some(fetched)) => {
                    cache.tor = osint::parse_tor_exits(&fetched.body);
                    cache.tor_updated_ms = now;
                    remember(&mut gates, Source::TorExit, &fetched);
                    gate(&mut gates, Source::TorExit).success(now, tor_spec.min_interval_ms);
                    notes.remove("Tor");
                }
                Ok(None) => {
                    gate(&mut gates, Source::TorExit).success(now, tor_spec.min_interval_ms);
                }
                Err((status, retry)) => {
                    notes.insert("Tor".to_string(), format!("Tor: HTTP {status}"));
                    match retry {
                        Some(seconds) => {
                            gate(&mut gates, Source::TorExit).retry_after(now, seconds)
                        }
                        None => {
                            gate(&mut gates, Source::TorExit).failure(now, tor_spec.min_interval_ms)
                        }
                    }
                }
            }
            dirty = true;
        }

        let sans_spec = osint::source_spec(Source::SansIsc);
        if on(Source::SansIsc) && gate(&mut gates, Source::SansIsc).due(now) {
            let saved = validators(&gates, Source::SansIsc);
            match get(SANS_HOST, SANS_PATH, MAX_SANS_BYTES, &saved) {
                Ok(Some(fetched)) => match osint::parse_sans_ports(&fetched.body) {
                    Ok(report) => {
                        cache.sans = Some(report);
                        cache.sans_updated_ms = now;
                        remember(&mut gates, Source::SansIsc, &fetched);
                        gate(&mut gates, Source::SansIsc).success(now, sans_spec.min_interval_ms);
                        notes.remove("SANS ISC");
                    }
                    Err(error) => {
                        notes.insert("SANS ISC".to_string(), format!("SANS ISC: {error}"));
                        gate(&mut gates, Source::SansIsc).failure(now, sans_spec.min_interval_ms);
                    }
                },
                Ok(None) => {
                    gate(&mut gates, Source::SansIsc).success(now, sans_spec.min_interval_ms);
                }
                Err((status, retry)) => {
                    notes.insert("SANS ISC".to_string(), format!("SANS ISC: HTTP {status}"));
                    match retry {
                        Some(seconds) => {
                            gate(&mut gates, Source::SansIsc).retry_after(now, seconds)
                        }
                        None => gate(&mut gates, Source::SansIsc)
                            .failure(now, sans_spec.min_interval_ms),
                    }
                }
            }
            dirty = true;
        }

        let ransom_spec = osint::source_spec(Source::RansomwareLive);
        if on(Source::RansomwareLive) && gate(&mut gates, Source::RansomwareLive).due(now) {
            let headers =
                "Accept: application/json\r\nUser-Agent: AtlasSOC-OSINT (+https://ibert.se)\r\n";
            match fetch_public(
                osint_ransomware::HOST,
                osint_ransomware::RECENT_PATH,
                headers,
                MAX_RANSOM_BYTES,
            ) {
                Some(reply) if reply.status == 200 => {
                    match osint_ransomware::parse_recent(&reply.body, now) {
                        Ok(incidents) => {
                            // Only counts are kept; victim names never reach the cache.
                            cache.ransom =
                                Some(osint_ransomware::summarize(&incidents, now, 30, 8));
                            cache.ransom_updated_ms = now;
                            gate(&mut gates, Source::RansomwareLive)
                                .success(now, ransom_spec.min_interval_ms);
                            notes.remove("ransomware.live");
                        }
                        Err(error) => {
                            notes.insert(
                                "ransomware.live".to_string(),
                                format!("ransomware.live: {error:?}"),
                            );
                            gate(&mut gates, Source::RansomwareLive)
                                .failure(now, ransom_spec.min_interval_ms);
                        }
                    }
                }
                Some(reply) => {
                    let error = osint_ransomware::classify_status(reply.status);
                    notes.insert(
                        "ransomware.live".to_string(),
                        format!("ransomware.live: {error:?}"),
                    );
                    match (error, reply.retry_after_s) {
                        (RansomError::RateLimited, Some(seconds)) => {
                            gate(&mut gates, Source::RansomwareLive).retry_after(now, seconds)
                        }
                        _ => gate(&mut gates, Source::RansomwareLive)
                            .failure(now, ransom_spec.min_interval_ms),
                    }
                }
                None => {
                    notes.insert(
                        "ransomware.live".to_string(),
                        "ransomware.live: no connection".into(),
                    );
                    gate(&mut gates, Source::RansomwareLive)
                        .failure(now, ransom_spec.min_interval_ms);
                }
            }
            dirty = true;
        }

        let phish_spec = osint::source_spec(Source::PhishTank);
        if on(Source::PhishTank) && gate(&mut gates, Source::PhishTank).due(now) {
            let saved = validators(&gates, Source::PhishTank);
            match get(
                osint_phishtank::HOST,
                osint_phishtank::LIST_PATH,
                osint_phishtank::MAX_BODY_BYTES,
                &saved,
            ) {
                Ok(Some(fetched)) => match osint_phishtank::parse_list(&fetched.body) {
                    Ok(set) => {
                        let fingerprint = fetched
                            .etag
                            .clone()
                            .unwrap_or_else(|| osint_phishtank::body_fingerprint(&fetched.body));
                        let _ = write_atomic(&directory.join(PHISH_FILE), &fetched.body);
                        cache.phish_state.observe(&fingerprint, now);
                        cache.phish_fingerprint = fingerprint;
                        shared.lock().unwrap().phish = Some(Arc::new(set));
                        remember(&mut gates, Source::PhishTank, &fetched);
                        gate(&mut gates, Source::PhishTank)
                            .success(now, phish_spec.min_interval_ms);
                        notes.remove("Phishing.Database");
                    }
                    Err(error) => {
                        notes.insert(
                            "Phishing.Database".to_string(),
                            format!("Phishing.Database: {error:?}"),
                        );
                        gate(&mut gates, Source::PhishTank)
                            .failure(now, phish_spec.min_interval_ms);
                    }
                },
                Ok(None) => {
                    // Not modified: the content is unchanged, so the change time must not move.
                    let fingerprint = cache.phish_fingerprint.clone();
                    cache.phish_state.observe(&fingerprint, now);
                    gate(&mut gates, Source::PhishTank).success(now, phish_spec.min_interval_ms);
                }
                Err((status, retry)) => {
                    notes.insert(
                        "Phishing.Database".to_string(),
                        format!("Phishing.Database: HTTP {status}"),
                    );
                    match retry {
                        Some(seconds) => {
                            gate(&mut gates, Source::PhishTank).retry_after(now, seconds)
                        }
                        None => gate(&mut gates, Source::PhishTank)
                            .failure(now, phish_spec.min_interval_ms),
                    }
                }
            }
            dirty = true;
        }

        let sslbl_spec = osint::source_spec(Source::Sslbl);
        if on(Source::Sslbl) && gate(&mut gates, Source::Sslbl).due(now) {
            match get(
                osint_abusech::SSLBL_HOST,
                osint_abusech::SSLBL_CERTS_PATH,
                osint_abusech::MAX_SSLBL_BYTES,
                &Validators::default(),
            ) {
                Ok(Some(fetched)) => match osint_abusech::parse_sslbl_certs(&fetched.body) {
                    Ok(certs) => {
                        cache.sslbl_total = certs.len();
                        cache.sslbl_newest_ms = certs.first().map_or(0, |c| c.listed_ms);
                        let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
                        for cert in &certs {
                            *counts.entry(cert.reason.as_str()).or_insert(0) += 1;
                        }
                        let mut top: Vec<(String, u32)> =
                            counts.into_iter().map(|(k, n)| (k.to_owned(), n)).collect();
                        top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                        top.truncate(8);
                        cache.sslbl_top = top;
                        cache.sslbl_updated_ms = now;
                        gate(&mut gates, Source::Sslbl).success(now, sslbl_spec.min_interval_ms);
                        notes.remove("SSLBL");
                    }
                    Err(error) => {
                        notes.insert("SSLBL".to_string(), format!("SSLBL: {error}"));
                        gate(&mut gates, Source::Sslbl).failure(now, sslbl_spec.min_interval_ms);
                    }
                },
                Ok(None) => {
                    gate(&mut gates, Source::Sslbl).success(now, sslbl_spec.min_interval_ms);
                }
                Err((status, retry)) => {
                    notes.insert("SSLBL".to_string(), format!("SSLBL: HTTP {status}"));
                    match retry {
                        Some(seconds) => gate(&mut gates, Source::Sslbl).retry_after(now, seconds),
                        None => {
                            gate(&mut gates, Source::Sslbl).failure(now, sslbl_spec.min_interval_ms)
                        }
                    }
                }
            }
            dirty = true;
        }

        let drop_spec = osint::source_spec(Source::SpamhausDrop);
        if on(Source::SpamhausDrop) && gate(&mut gates, Source::SpamhausDrop).due(now) {
            // One attempt covers all three files; any failure backs off for the full interval.
            let mut bodies = Vec::new();
            let mut failure = None;
            for (path, _) in SPAMHAUS_FILES {
                match get(
                    osint_spamhaus::HOST,
                    path,
                    osint_spamhaus::MAX_BODY_BYTES,
                    &Validators::default(),
                ) {
                    Ok(Some(fetched)) => bodies.push(fetched.body),
                    Ok(None) => failure = Some("unexpected 304".to_string()),
                    Err((status, _)) => failure = Some(format!("HTTP {status}")),
                }
                if failure.is_some() {
                    break;
                }
            }
            let parsed = failure.map_or_else(
                || {
                    Ok((
                        osint_spamhaus::parse_drop(&bodies[0], false)?,
                        osint_spamhaus::parse_drop(&bodies[1], true)?,
                        osint_spamhaus::parse_asndrop(&bodies[2])?,
                    ))
                },
                Err,
            );
            match parsed {
                Ok((v4, v6, asn)) => {
                    for (body, (_, name)) in bodies.iter().zip(SPAMHAUS_FILES) {
                        let _ = write_atomic(&directory.join(name), body);
                    }
                    cache.spamhaus_updated_ms = now;
                    shared.lock().unwrap().spamhaus = Some(Arc::new(SpamhausData {
                        v4,
                        v6,
                        asn,
                        updated_ms: now,
                    }));
                    gate(&mut gates, Source::SpamhausDrop).success(now, drop_spec.min_interval_ms);
                    notes.remove("Spamhaus DROP");
                }
                Err(error) => {
                    notes.insert(
                        "Spamhaus DROP".to_string(),
                        format!("Spamhaus DROP: {error}"),
                    );
                    gate(&mut gates, Source::SpamhausDrop).failure(now, drop_spec.min_interval_ms);
                }
            }
            dirty = true;
        }

        if dirty {
            save(&cache_path, &cache);
            save(&state_path, &gates);
            publish(&shared, &cache, &notes);
        }

        match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(Command::Refresh) => {}
            Ok(Command::Lookup(ip)) if on(Source::ShodanInternetDb) => {
                let result = lookup_internetdb(ip, &mut cache, &mut last_internetdb);
                save(&cache_path, &cache);
                let mut view = shared.lock().unwrap();
                view.lookup = Some(result);
                view.lookup_pending = false;
            }
            Ok(Command::Lookup(_)) => {
                shared.lock().unwrap().lookup_pending = false;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_that_is_not_listed_is_off() {
        let on = vec!["tor-exit".to_string()];
        assert!(is_enabled(&on, Source::TorExit));
        assert!(!is_enabled(&on, Source::ShodanInternetDb));
        assert!(!is_enabled(&[], Source::TorExit));
        assert!(!is_enabled(&on, Source::Epss));
    }

    #[test]
    fn the_kev_switch_also_covers_epss() {
        let on = vec!["cisa-kev".to_string()];
        assert!(is_enabled(&on, Source::Epss));
        assert!(!is_enabled(&["first-epss".to_string()], Source::CisaKev));
    }

    static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn counting_fetch(_: &str, _: &str, _: &str, _: usize) -> Option<Reply> {
        CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        None
    }

    /// Owner rule: a source that is switched off makes no request at all, and switching it on starts requests.
    #[test]
    fn nothing_is_requested_while_every_source_is_off() {
        use std::sync::atomic::Ordering::SeqCst;
        let dir = std::env::temp_dir().join(format!("atlassoc-offtest-{}", std::process::id()));
        let worker = Osint::start(dir.clone(), Vec::new(), counting_fetch);
        worker.lookup("1.1.1.1".parse().unwrap());
        worker.refresh();
        thread::sleep(Duration::from_millis(2500));
        assert_eq!(CALLS.load(SeqCst), 0, "a source that is off made a request");
        worker.set_enabled(vec!["tor-exit".to_string()]);
        let started = std::time::Instant::now();
        while CALLS.load(SeqCst) == 0 && started.elapsed() < Duration::from_secs(10) {
            thread::sleep(Duration::from_millis(100));
        }
        assert!(
            CALLS.load(SeqCst) > 0,
            "switching a source on did not start requests"
        );
        // Only the Tor list was switched on: no other host may have been asked.
        worker.set_enabled(Vec::new());
        let _ = std::fs::remove_dir_all(dir);
    }
}
