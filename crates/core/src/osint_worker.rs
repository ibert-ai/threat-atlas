//! OSINT worker: CISA KEV + FIRST EPSS, Tor exit count, SANS ISC top ports.
//!
//! Network work is kept off the render thread. Each source has a persisted rate gate so a
//! restart cannot bypass the provider's floor. Keys and provider terms live in the source
//! registry (`crate::osint`); this worker only fetches public, keyless data.

use crate::osint_net::{Fetch, Reply};
use crate::{
    feed::now_ms,
    osint::{self, EpssScore, KevWithEpss, RateGate, SansReport, Source},
    osint_abusech::{self, ThreatFoxSummary, UrlhausSummary},
    osint_abuseipdb::{self, CheckError, CheckResult},
    osint_certstream::{self, CtError},
    osint_internetdb::{self, InternetDbHost, Lookup},
    osint_otx::{self, OtxError},
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
/// POST hook, set by the host next to the GET hook. Without it a source that needs POST says so.
pub type Post = fn(&str, &str, &str, &[u8], usize) -> Option<Reply>;
static POST: std::sync::OnceLock<Post> = std::sync::OnceLock::new();

pub fn set_post(post: Post) {
    let _ = POST.set(post);
}

fn post_public(
    host: &str,
    path: &str,
    headers: &str,
    body: &[u8],
    max_bytes: usize,
) -> Option<Reply> {
    (POST.get()?)(host, path, headers, body, max_bytes)
}

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
    pub otx: Option<OtxSummary>,
    pub otx_updated_ms: u64,
    pub urlhaus: Option<UrlhausSummary>,
    pub urlhaus_updated_ms: u64,
    pub threatfox: Option<ThreatFoxSummary>,
    pub threatfox_updated_ms: u64,
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
    /// Last click-only AbuseIPDB check, kept until the next one.
    pub abuse: Option<AbuseView>,
    pub abuse_pending: bool,
    pub ct: Vec<CtDomain>,
}

/// Result of one AbuseIPDB check the user asked for.
#[derive(Clone, Debug)]
pub struct AbuseView {
    pub ip: String,
    pub outcome: Result<CheckResult, String>,
    pub at_ms: u64,
    pub from_cache: bool,
}

/// What the OTX poll keeps: counts and a few names, never indicators.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OtxSummary {
    pub pulses: u32,
    pub indicators: u64,
    pub families: Vec<(String, u32)>,
    pub countries: Vec<(String, u32)>,
    /// Names of the three newest pulses.
    pub newest: Vec<String>,
}

/// What is kept per watched domain from the CT log polls.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CtDomain {
    pub domain: String,
    /// Certificates counted so far (the first polls build the baseline page by page).
    pub known: u32,
    /// Certificates that appeared in the latest poll after the baseline was complete.
    pub new_last_poll: u32,
    pub new_total: u32,
    /// True while older history is still being paged in (a full page came back).
    pub catching_up: bool,
    pub last_poll_ms: u64,
    pub cursor: Option<String>,
    pub newest_issuer: Option<String>,
    pub newest_not_before: Option<String>,
    pub newest_names: Vec<String>,
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
    otx: Option<OtxSummary>,
    otx_updated_ms: u64,
    urlhaus: Option<UrlhausSummary>,
    urlhaus_updated_ms: u64,
    threatfox: Option<ThreatFoxSummary>,
    threatfox_updated_ms: u64,
    spamhaus_updated_ms: u64,
    phish_state: FeedState,
    phish_fingerprint: String,
    sslbl_total: usize,
    sslbl_top: Vec<(String, u32)>,
    sslbl_newest_ms: u64,
    sslbl_updated_ms: u64,
    /// AbuseIPDB checks used today (UTC day number, count), so a restart cannot reset the local budget.
    abuse_day: u64,
    abuse_used: u32,
    ct: BTreeMap<String, CtDomain>,
    ct_hour: u64,
    ct_used: u32,
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
    AbuseLookup(IpAddr),
}

/// One background OSINT worker. Started only after licence consent, never by the offline smoke.
pub struct Osint {
    shared: Arc<Mutex<View>>,
    wake: Sender<Command>,
    enabled: Arc<Mutex<Vec<String>>>,
    /// API keys by source id. Memory only: never written to disk, logged or put in a note.
    keys: Arc<Mutex<BTreeMap<String, String>>>,
    /// Domains the user watches in the certificate logs (at most 10, already normalised).
    watch: Arc<Mutex<Vec<String>>>,
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
        let keys = Arc::new(Mutex::new(BTreeMap::new()));
        let worker_keys = keys.clone();
        let watch = Arc::new(Mutex::new(Vec::new()));
        let worker_watch = watch.clone();
        thread::spawn(move || worker(directory, state, rx, switches, worker_keys, worker_watch));
        Self {
            shared,
            wake,
            enabled,
            keys,
            watch,
        }
    }

    /// Replaces the set of sources that may make requests and wakes the worker. A source that is off
    /// makes no request at all, including no lookup.
    pub fn set_enabled(&self, enabled: Vec<String>) {
        *self.enabled.lock().unwrap() = enabled;
        let _ = self.wake.send(Command::Refresh);
    }

    /// Gives a source its API key, or removes it with `None`. Held in memory only; the host keeps the
    /// key in the system's credential store.
    pub fn set_key(&self, source: Source, key: Option<String>) {
        let id = osint::source_spec(source).id.to_string();
        {
            let mut keys = self.keys.lock().unwrap();
            match key.filter(|k| !k.trim().is_empty()) {
                Some(k) => keys.insert(id, k.trim().to_owned()),
                None => keys.remove(&id),
            };
        }
        let _ = self.wake.send(Command::Refresh);
    }

    /// Replaces the certificate watch list (normalised, no duplicates, at most 10). Returns how many
    /// entries were accepted.
    pub fn set_watch(&self, domains: Vec<String>) -> usize {
        let mut list = osint_certstream::WatchList::default();
        for d in &domains {
            let _ = list.add(d);
        }
        let accepted = list.domains().to_vec();
        let count = accepted.len();
        *self.watch.lock().unwrap() = accepted;
        let _ = self.wake.send(Command::Refresh);
        count
    }

    /// Applies switches, keys and watch list as one update and wakes the worker once. All three are written while
    /// holding their locks together (always in the order switches, keys, watch), and the worker reads the ones it
    /// needs for a request under the same locks in the same order (`snapshot_key`, `snapshot_watch`). A request
    /// therefore sees either the old settings or the new ones, never a removed domain with a new key or a source
    /// that is off with a new key.
    pub fn apply_config(
        &self,
        enabled: Vec<String>,
        keys: Vec<(Source, Option<String>)>,
        watch: Vec<String>,
    ) {
        let mut list = osint_certstream::WatchList::default();
        for d in &watch {
            let _ = list.add(d);
        }
        let watch = list.domains().to_vec();
        let wanted: BTreeMap<String, String> = keys
            .into_iter()
            .filter_map(|(source, key)| {
                let key = key?.trim().to_owned();
                (!key.is_empty()).then(|| (osint::source_spec(source).id.to_owned(), key))
            })
            .collect();
        {
            let mut e = self.enabled.lock().unwrap();
            let mut k = self.keys.lock().unwrap();
            let mut w = self.watch.lock().unwrap();
            *e = enabled;
            *k = wanted;
            *w = watch;
        }
        let _ = self.wake.send(Command::Refresh);
    }

    /// The certificate watch list in use.
    pub fn watch(&self) -> Vec<String> {
        self.watch.lock().unwrap().clone()
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

    /// Queues one AbuseIPDB check. Only the host's click handler calls this, after the user has confirmed
    /// that the address will be sent to AbuseIPDB.
    pub fn lookup_abuse(&self, ip: IpAddr) {
        if osint_abuseipdb::is_lookup_allowed(ip)
            && is_enabled(&self.enabled.lock().unwrap(), Source::AbuseIpdb)
        {
            self.shared.lock().unwrap().abuse_pending = true;
            let _ = self.wake.send(Command::AbuseLookup(ip));
        }
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
    let abuse = view.abuse.take();
    let abuse_pending = view.abuse_pending;
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
        otx: cache.otx.clone(),
        otx_updated_ms: cache.otx_updated_ms,
        urlhaus: cache.urlhaus.clone(),
        urlhaus_updated_ms: cache.urlhaus_updated_ms,
        threatfox: cache.threatfox.clone(),
        threatfox_updated_ms: cache.threatfox_updated_ms,
        spamhaus,
        phish,
        phish_state: cache.phish_state.clone(),
        sslbl_total: cache.sslbl_total,
        sslbl_top: cache.sslbl_top.clone(),
        sslbl_newest_ms: cache.sslbl_newest_ms,
        sslbl_updated_ms: cache.sslbl_updated_ms,
        lookup,
        lookup_pending,
        abuse,
        abuse_pending,
        ct: cache.ct.values().cloned().collect(),
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

/// One AbuseIPDB check: 24 h memory cache, local daily budget (persisted), key from memory only.
fn lookup_abuse(
    ip: IpAddr,
    key: Option<String>,
    cache: &mut Cache,
    memory: &mut BTreeMap<String, (u64, CheckResult)>,
) -> AbuseView {
    let text = ip.to_string();
    let now = now_ms();
    let view = |outcome, at_ms, from_cache| AbuseView {
        ip: text.clone(),
        outcome,
        at_ms,
        from_cache,
    };
    if let Some((at, result)) = memory.get(&text) {
        if osint_abuseipdb::cache_fresh(*at, now) {
            return view(Ok(result.clone()), *at, true);
        }
    }
    let Some(key) = key.filter(|k| osint_abuseipdb::looks_like_key(k)) else {
        return view(
            Err("No AbuseIPDB API key yet. Add it in Settings. Nothing was sent.".into()),
            now,
            false,
        );
    };
    let Some(path) = osint_abuseipdb::check_path(ip) else {
        return view(
            Err("Not a public address; nothing was sent.".into()),
            now,
            false,
        );
    };
    let mut budget = osint_abuseipdb::DailyBudget {
        day: cache.abuse_day,
        used: cache.abuse_used,
    };
    let allowed = budget.take(now, osint_abuseipdb::LOCAL_DAILY_BUDGET);
    cache.abuse_day = budget.day;
    cache.abuse_used = budget.used;
    if !allowed {
        return view(
            Err("Today's local AbuseIPDB limit is used up. Try again tomorrow (UTC).".into()),
            now,
            false,
        );
    }
    let headers = format!(
        "Accept: application/json\r\nKey: {key}\r\nUser-Agent: AtlasSOC-OSINT (+https://ibert.se)\r\n"
    );
    let answer = match fetch_public(
        osint_abuseipdb::HOST,
        &path,
        &headers,
        osint_abuseipdb::MAX_BODY_BYTES,
    ) {
        None => Err("AbuseIPDB: no connection.".to_string()),
        Some(reply) if reply.status == 200 => {
            osint_abuseipdb::parse_check(&reply.body).map_err(|e| match e {
                CheckError::Auth => "AbuseIPDB: the API key was refused.".to_string(),
                CheckError::RateLimited => "AbuseIPDB: limit reached. Try later.".to_string(),
                CheckError::Api(d) | CheckError::Malformed(d) => format!("AbuseIPDB: {d}"),
            })
        }
        Some(reply) => Err(
            match osint_abuseipdb::classify_error(reply.status, &reply.body) {
                CheckError::Auth => "AbuseIPDB: the API key was refused.".to_string(),
                CheckError::RateLimited => "AbuseIPDB: limit reached. Try later.".to_string(),
                CheckError::Api(d) | CheckError::Malformed(d) => format!("AbuseIPDB: {d}"),
            },
        ),
    };
    if let Ok(result) = &answer {
        if memory.len() >= 200 {
            memory.clear();
        }
        memory.insert(text.clone(), (now, result.clone()));
    }
    view(answer, now, false)
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

/// Polls the OTX pulse feed (public, TLP white or green pulses only) and keeps counts and a few names.
fn poll_otx(key: &str, since_ms: u64) -> Result<OtxSummary, (OtxError, Option<u64>)> {
    let headers = format!(
        "Accept: application/json\r\nX-OTX-API-KEY: {key}\r\nUser-Agent: AtlasSOC-OSINT (+https://ibert.se)\r\n"
    );
    let mut path = osint_otx::first_page_path(since_ms);
    let mut pulses = Vec::new();
    for _ in 0..osint_otx::MAX_PAGES {
        let reply = fetch_public(osint_otx::HOST, &path, &headers, osint_otx::MAX_BODY_BYTES)
            .ok_or((OtxError::Api("no connection".into()), None))?;
        if reply.status != 200 {
            return Err((
                osint_otx::classify_error(reply.status, &reply.body),
                reply.retry_after_s,
            ));
        }
        let page = osint_otx::parse_pulses(&reply.body).map_err(|e| (e, None))?;
        pulses.extend(page.pulses);
        match page.next {
            Some(next) => path = next,
            None => break,
        }
    }
    let mut countries: BTreeMap<&str, u32> = BTreeMap::new();
    for pulse in &pulses {
        for country in &pulse.targeted_countries {
            *countries.entry(country.as_str()).or_insert(0) += 1;
        }
    }
    let mut countries: Vec<(String, u32)> = countries
        .into_iter()
        .map(|(c, n)| (c.to_owned(), n))
        .collect();
    countries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    countries.truncate(8);
    Ok(OtxSummary {
        pulses: pulses.len() as u32,
        indicators: pulses.iter().map(|p| u64::from(p.indicator_count)).sum(),
        families: osint_otx::top_malware_families(&pulses, 8),
        countries,
        newest: pulses.iter().take(3).map(|p| p.name.clone()).collect(),
    })
}

/// The key for `source` as the settings stand right now, or `None` when the source is off or has no key. Reads the
/// switches and the keys under both locks (same order as `apply_config`).
fn snapshot_key(
    enabled: &Mutex<Vec<String>>,
    keys: &Mutex<BTreeMap<String, String>>,
    source: Source,
) -> Option<String> {
    let e = enabled.lock().unwrap();
    let k = keys.lock().unwrap();
    if !is_enabled(&e, source) {
        return None;
    }
    k.get(osint::source_spec(source).id).cloned()
}

/// The certificate watch list and the key as one coherent pair; empty and `None` while the source is off.
fn snapshot_watch(
    enabled: &Mutex<Vec<String>>,
    keys: &Mutex<BTreeMap<String, String>>,
    watch: &Mutex<Vec<String>>,
) -> (Vec<String>, Option<String>) {
    let e = enabled.lock().unwrap();
    let k = keys.lock().unwrap();
    let w = watch.lock().unwrap();
    if !is_enabled(&e, Source::CertStream) {
        return (Vec::new(), None);
    }
    (
        w.clone(),
        k.get(osint::source_spec(Source::CertStream).id).cloned(),
    )
}

fn worker(
    directory: PathBuf,
    shared: Arc<Mutex<View>>,
    rx: Receiver<Command>,
    enabled: Arc<Mutex<Vec<String>>>,
    keys: Arc<Mutex<BTreeMap<String, String>>>,
    watch: Arc<Mutex<Vec<String>>>,
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
    let mut abuse_memory: BTreeMap<String, (u64, CheckResult)> = BTreeMap::new();
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

        let otx_spec = osint::source_spec(Source::Otx);
        if on(Source::Otx) && gate(&mut gates, Source::Otx).due(now) {
            let key = snapshot_key(&enabled, &keys, Source::Otx);
            match key {
                None => {
                    notes.insert(
                        "OTX".to_string(),
                        "OTX: no API key yet. Add it in Settings.".to_string(),
                    );
                    dirty = true;
                }
                Some(key) => {
                    let last = (cache.otx_updated_ms != 0).then_some(cache.otx_updated_ms);
                    match poll_otx(&key, osint_otx::since_ms(last, now)) {
                        Ok(summary) => {
                            cache.otx = Some(summary);
                            cache.otx_updated_ms = now;
                            gate(&mut gates, Source::Otx).success(now, otx_spec.min_interval_ms);
                            notes.remove("OTX");
                        }
                        Err((error, retry)) => {
                            let text = match &error {
                                OtxError::Auth => "OTX: the API key was refused".to_string(),
                                OtxError::Throttled => "OTX: throttled, waiting".to_string(),
                                OtxError::Api(detail) => format!("OTX: {detail}"),
                                OtxError::Malformed(detail) => format!("OTX: {detail}"),
                            };
                            notes.insert("OTX".to_string(), text);
                            match (&error, retry) {
                                (OtxError::Throttled, Some(seconds)) => {
                                    gate(&mut gates, Source::Otx).retry_after(now, seconds)
                                }
                                _ => gate(&mut gates, Source::Otx)
                                    .failure(now, otx_spec.min_interval_ms),
                            }
                        }
                    }
                    dirty = true;
                }
            }
        }

        let urlhaus_spec = osint::source_spec(Source::Urlhaus);
        if on(Source::Urlhaus) && gate(&mut gates, Source::Urlhaus).due(now) {
            let key = snapshot_key(&enabled, &keys, Source::Urlhaus);
            match key {
                None => {
                    notes.insert(
                        "URLhaus".to_string(),
                        "URLhaus: no abuse.ch Auth-Key yet. Add it in Settings.".to_string(),
                    );
                    dirty = true;
                }
                Some(key) if !osint_abusech::looks_like_auth_key(&key) => {
                    notes.insert(
                        "URLhaus".to_string(),
                        "URLhaus: the key does not look like an abuse.ch Auth-Key".to_string(),
                    );
                    dirty = true;
                }
                Some(key) => {
                    let headers = format!(
                        "Accept: application/json\r\nAuth-Key: {key}\r\nUser-Agent: AtlasSOC-OSINT (+https://ibert.se)\r\n"
                    );
                    match fetch_public(
                        osint_abusech::URLHAUS_HOST,
                        osint_abusech::URLHAUS_RECENT_PATH,
                        &headers,
                        osint_abusech::MAX_URLHAUS_BYTES,
                    ) {
                        Some(reply) if reply.status == 200 => {
                            match osint_abusech::parse_urlhaus_recent(&reply.body) {
                                Ok(summary) => {
                                    cache.urlhaus = Some(summary);
                                    cache.urlhaus_updated_ms = now;
                                    gate(&mut gates, Source::Urlhaus)
                                        .success(now, urlhaus_spec.min_interval_ms);
                                    notes.remove("URLhaus");
                                }
                                Err(error) => {
                                    notes
                                        .insert("URLhaus".to_string(), format!("URLhaus: {error}"));
                                    gate(&mut gates, Source::Urlhaus)
                                        .failure(now, urlhaus_spec.min_interval_ms);
                                }
                            }
                        }
                        Some(reply) => {
                            let text = match reply.status {
                                401 | 403 => {
                                    "URLhaus: the abuse.ch Auth-Key was refused".to_string()
                                }
                                429 => "URLhaus: throttled, waiting".to_string(),
                                status => format!("URLhaus: HTTP {status}"),
                            };
                            notes.insert("URLhaus".to_string(), text);
                            match (reply.status, reply.retry_after_s) {
                                (429, Some(seconds)) => {
                                    gate(&mut gates, Source::Urlhaus).retry_after(now, seconds)
                                }
                                _ => gate(&mut gates, Source::Urlhaus)
                                    .failure(now, urlhaus_spec.min_interval_ms),
                            }
                        }
                        None => {
                            notes.insert(
                                "URLhaus".to_string(),
                                "URLhaus: no connection".to_string(),
                            );
                            gate(&mut gates, Source::Urlhaus)
                                .failure(now, urlhaus_spec.min_interval_ms);
                        }
                    }
                    dirty = true;
                }
            }
        }

        let threatfox_spec = osint::source_spec(Source::ThreatFox);
        if on(Source::ThreatFox) && gate(&mut gates, Source::ThreatFox).due(now) {
            let key = snapshot_key(&enabled, &keys, Source::ThreatFox);
            match key {
                None => {
                    notes.insert(
                        "ThreatFox".to_string(),
                        "ThreatFox: no abuse.ch Auth-Key yet. Add it in Settings.".to_string(),
                    );
                }
                Some(key) if !osint_abusech::looks_like_auth_key(&key) => {
                    notes.insert(
                        "ThreatFox".to_string(),
                        "ThreatFox: the key does not look like an abuse.ch Auth-Key".to_string(),
                    );
                }
                Some(key) => {
                    let headers = format!(
                        "Accept: application/json\r\nContent-Type: application/json\r\nAuth-Key: {key}\r\nUser-Agent: AtlasSOC-OSINT (+https://ibert.se)\r\n"
                    );
                    let body = osint_abusech::threatfox_recent_body(1);
                    match post_public(
                        osint_abusech::THREATFOX_HOST,
                        osint_abusech::THREATFOX_PATH,
                        &headers,
                        body.as_bytes(),
                        osint_abusech::MAX_THREATFOX_BYTES,
                    ) {
                        Some(reply) if reply.status == 200 => {
                            match osint_abusech::parse_threatfox(&reply.body) {
                                Ok(iocs) => {
                                    cache.threatfox =
                                        Some(osint_abusech::summarize_threatfox(&iocs));
                                    cache.threatfox_updated_ms = now;
                                    gate(&mut gates, Source::ThreatFox)
                                        .success(now, threatfox_spec.min_interval_ms);
                                    notes.remove("ThreatFox");
                                }
                                Err(error) => {
                                    notes.insert("ThreatFox".to_string(), error);
                                    gate(&mut gates, Source::ThreatFox)
                                        .failure(now, threatfox_spec.min_interval_ms);
                                }
                            }
                        }
                        Some(reply) => {
                            let text = match reply.status {
                                401 | 403 => {
                                    "ThreatFox: the abuse.ch Auth-Key was refused".to_string()
                                }
                                429 => "ThreatFox: throttled, waiting".to_string(),
                                status => format!("ThreatFox: HTTP {status}"),
                            };
                            notes.insert("ThreatFox".to_string(), text);
                            match (reply.status, reply.retry_after_s) {
                                (429, Some(seconds)) => {
                                    gate(&mut gates, Source::ThreatFox).retry_after(now, seconds)
                                }
                                _ => gate(&mut gates, Source::ThreatFox)
                                    .failure(now, threatfox_spec.min_interval_ms),
                            }
                        }
                        None => {
                            notes.insert(
                                "ThreatFox".to_string(),
                                "ThreatFox: no connection (or this host has no POST support)"
                                    .to_string(),
                            );
                            gate(&mut gates, Source::ThreatFox)
                                .failure(now, threatfox_spec.min_interval_ms);
                        }
                    }
                }
            }
            dirty = true;
        }

        if on(Source::CertStream) {
            let (domains, key) = snapshot_watch(&enabled, &keys, &watch);
            // Forget domains that are no longer watched.
            let before = cache.ct.len();
            cache.ct.retain(|d, _| domains.contains(d));
            if cache.ct.len() != before {
                dirty = true;
            }
            if domains.is_empty() {
                notes.insert(
                    "Cert watch".to_string(),
                    "Cert watch: no domains to watch yet. Add up to 10 in Settings.".to_string(),
                );
                dirty = true;
            } else if key.is_none() {
                notes.insert(
                    "Cert watch".to_string(),
                    "Cert watch: no SSLMate API key yet. Add it in Settings.".to_string(),
                );
                dirty = true;
            } else if let Some(key) = key {
                let mut budget = osint_certstream::HourlyBudget {
                    hour: cache.ct_hour,
                    used: cache.ct_used,
                };
                for domain in &domains {
                    let last = cache
                        .ct
                        .get(domain)
                        .map(|d| d.last_poll_ms)
                        .filter(|t| *t != 0);
                    if !osint_certstream::poll_due(last, now) {
                        continue;
                    }
                    if !budget.take(now, osint_certstream::LOCAL_HOURLY_BUDGET) {
                        break;
                    }
                    let entry = cache.ct.entry(domain.clone()).or_insert_with(|| CtDomain {
                        domain: domain.clone(),
                        ..CtDomain::default()
                    });
                    let Some(path) = osint_certstream::watch_path(domain, entry.cursor.as_deref())
                    else {
                        continue;
                    };
                    let headers = format!(
                        "Accept: application/json\r\nAuthorization: Bearer {key}\r\nUser-Agent: AtlasSOC-OSINT (+https://ibert.se)\r\n"
                    );
                    entry.last_poll_ms = now;
                    let answer = fetch_public(
                        osint_certstream::HOST,
                        &path,
                        &headers,
                        osint_certstream::MAX_BODY_BYTES,
                    );
                    let problem = match answer {
                        None => Some("Cert watch: no connection".to_string()),
                        Some(reply) => match osint_certstream::status_error(reply.status) {
                            Some(CtError::Auth) => {
                                Some("Cert watch: the SSLMate API key was refused".to_string())
                            }
                            Some(CtError::RateLimited) => {
                                Some("Cert watch: throttled, waiting for the next hour".to_string())
                            }
                            Some(CtError::Api(d)) | Some(CtError::Malformed(d)) => {
                                Some(format!("Cert watch: {d}"))
                            }
                            None => match osint_certstream::parse_issuances(&reply.body) {
                                Err(CtError::Auth) | Err(CtError::RateLimited) => {
                                    Some("Cert watch: the provider refused the request".to_string())
                                }
                                Err(CtError::Api(d)) | Err(CtError::Malformed(d)) => {
                                    Some(format!("Cert watch: {d}"))
                                }
                                Ok(list) => {
                                    let baseline_done =
                                        !entry.catching_up && entry.cursor.is_some();
                                    let count = list.len() as u32;
                                    entry.known += count;
                                    entry.new_last_poll = if baseline_done { count } else { 0 };
                                    entry.new_total += entry.new_last_poll;
                                    entry.catching_up = count as usize >= 100;
                                    if let Some(c) = osint_certstream::next_cursor(&list) {
                                        entry.cursor = Some(c.to_owned());
                                    }
                                    if let Some(last) = list.last() {
                                        entry.newest_issuer = last.issuer.clone();
                                        entry.newest_not_before = last.not_before.clone();
                                        entry.newest_names =
                                            last.dns_names.iter().take(3).cloned().collect();
                                    }
                                    None
                                }
                            },
                        },
                    };
                    match problem {
                        Some(text) => {
                            notes.insert("Cert watch".to_string(), text);
                        }
                        None => {
                            notes.remove("Cert watch");
                        }
                    }
                }
                cache.ct_hour = budget.hour;
                cache.ct_used = budget.used;
                dirty = true;
            }
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
            Ok(Command::AbuseLookup(ip)) if on(Source::AbuseIpdb) => {
                let key = keys
                    .lock()
                    .unwrap()
                    .get(osint::source_spec(Source::AbuseIpdb).id)
                    .cloned();
                let result = lookup_abuse(ip, key, &mut cache, &mut abuse_memory);
                save(&cache_path, &cache);
                let mut view = shared.lock().unwrap();
                view.abuse = Some(result);
                view.abuse_pending = false;
            }
            Ok(Command::AbuseLookup(_)) => {
                shared.lock().unwrap().abuse_pending = false;
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
    #[test]
    fn requests_see_one_generation_of_settings() {
        let worker = Osint::start(
            std::env::temp_dir().join("atlas-snapshot"),
            Vec::new(),
            |_, _, _, _| None,
        );
        let ct = osint::source_spec(Source::CertStream).id.to_string();
        worker.apply_config(
            vec![ct.clone()],
            vec![(Source::CertStream, Some("old-key-0123456789".into()))],
            vec!["old.example".into()],
        );
        let (domains, key) = snapshot_watch(&worker.enabled, &worker.keys, &worker.watch);
        assert_eq!(domains, vec!["old.example".to_string()]);
        assert_eq!(key.as_deref(), Some("old-key-0123456789"));
        worker.apply_config(
            vec![ct],
            vec![(Source::CertStream, Some("new-key-0123456789".into()))],
            vec!["new.example".into()],
        );
        let (domains, key) = snapshot_watch(&worker.enabled, &worker.keys, &worker.watch);
        assert_eq!(domains, vec!["new.example".to_string()]);
        assert_eq!(key.as_deref(), Some("new-key-0123456789"));
        // Switched off: no domain and no key are handed out, whatever is stored.
        worker.apply_config(
            Vec::new(),
            vec![(Source::CertStream, Some("new-key-0123456789".into()))],
            vec!["new.example".into()],
        );
        assert_eq!(
            snapshot_watch(&worker.enabled, &worker.keys, &worker.watch),
            (Vec::new(), None)
        );
        assert_eq!(
            snapshot_key(&worker.enabled, &worker.keys, Source::Otx),
            None
        );
    }

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

    static SEEN: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

    fn counting_fetch(host: &str, _: &str, headers: &str, _: usize) -> Option<Reply> {
        CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        SEEN.lock().unwrap().push((host.into(), headers.into()));
        None
    }

    /// Owner rule: a source that is switched off makes no request at all, and switching it on starts requests.
    #[test]
    fn nothing_is_requested_while_every_source_is_off() {
        use std::sync::atomic::Ordering::SeqCst;
        let dir = std::env::temp_dir().join(format!("atlassoc-offtest-{}", std::process::id()));
        let worker = Osint::start(dir.clone(), Vec::new(), counting_fetch);
        worker.lookup("1.1.1.1".parse().unwrap());
        worker.lookup_abuse("8.8.8.8".parse().unwrap());
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
        assert!(SEEN
            .lock()
            .unwrap()
            .iter()
            .all(|(host, _)| host == "check.torproject.org"));
        // A keyed source that is on but has no key asks nobody and says what is missing.
        worker.set_enabled(vec!["alienvault-otx".to_string()]);
        thread::sleep(Duration::from_millis(2500));
        let otx =
            |seen: &[(String, String)]| seen.iter().filter(|(h, _)| h == osint_otx::HOST).count();
        assert_eq!(otx(&SEEN.lock().unwrap()), 0, "OTX was asked without a key");
        assert!(worker
            .view()
            .notes
            .get("OTX")
            .is_some_and(|n| n.contains("no API key")));
        // With a key the request carries it in the header and nowhere in the notes or view text.
        worker.set_key(Source::Otx, Some("k".repeat(40)));
        let started = std::time::Instant::now();
        while otx(&SEEN.lock().unwrap()) == 0 && started.elapsed() < Duration::from_secs(10) {
            thread::sleep(Duration::from_millis(100));
        }
        let seen = SEEN.lock().unwrap().clone();
        let call = seen
            .iter()
            .find(|(h, _)| h == osint_otx::HOST)
            .expect("OTX asked after key");
        assert!(call
            .1
            .contains(&format!("X-OTX-API-KEY: {}", "k".repeat(40))));
        thread::sleep(Duration::from_millis(500));
        let view = worker.view();
        assert!(
            !view.note.contains(&"k".repeat(40)),
            "the key leaked into a note"
        );
        worker.set_enabled(Vec::new());
        let _ = std::fs::remove_dir_all(dir);
    }
}
