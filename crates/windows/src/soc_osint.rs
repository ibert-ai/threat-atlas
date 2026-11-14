//! FAS 1 OSINT worker: CISA KEV + FIRST EPSS, Tor exit count, SANS ISC top ports.
//!
//! Network work is kept off the render thread. Each source has a persisted rate gate so a
//! restart cannot bypass the provider's floor. Keys and provider terms live in the source
//! registry (`threat_atlas_core::osint`); this worker only fetches public, keyless data.

use crate::soc_config::write_atomic;
use crate::soc_radar::https_get_public;
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
use threat_atlas_core::{
    feed::now_ms,
    osint::{self, EpssScore, KevWithEpss, RateGate, SansReport, Source},
    osint_internetdb::{self, InternetDbHost, Lookup},
};

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
    /// Last click-only InternetDB lookup, kept until the next one.
    pub lookup: Option<LookupView>,
    pub lookup_pending: bool,
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
    epss: Vec<EpssScore>,
    epss_updated_ms: u64,
    tor: Vec<IpAddr>,
    tor_updated_ms: u64,
    sans: Option<SansReport>,
    sans_updated_ms: u64,
    /// IP -> (fetched at, answer). `None` answer means "no information". At most 200 entries.
    internetdb: BTreeMap<String, (u64, Option<InternetDbHost>)>,
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
}

impl Osint {
    pub fn start(directory: PathBuf) -> Self {
        let shared = Arc::new(Mutex::new(View::default()));
        let (wake, rx) = mpsc::channel();
        let state = shared.clone();
        thread::spawn(move || worker(directory, state, rx));
        Self { shared, wake }
    }

    pub fn view(&self) -> View {
        self.shared.lock().unwrap().clone()
    }

    pub fn refresh(&self) {
        let _ = self.wake.send(Command::Refresh);
    }

    /// Queues one InternetDB lookup. Only the host's click handler calls this, after the user has
    /// confirmed that the address will be sent to Shodan.
    pub fn lookup(&self, ip: IpAddr) {
        if osint_internetdb::is_lookup_allowed(ip) {
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

fn publish(shared: &Mutex<View>, cache: &Cache, note: &str) {
    let mut view = shared.lock().unwrap();
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
        note: note.to_owned(),
        lookup,
        lookup_pending,
    };
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
    let answer = match https_get_public(
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
    let reply = https_get_public(host, path, &headers, max_bytes).ok_or((0, None))?;
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

fn worker(directory: PathBuf, shared: Arc<Mutex<View>>, rx: Receiver<Command>) {
    let _ = fs::create_dir_all(&directory);
    let state_path = directory.join("osint-state.json");
    let cache_path = directory.join("osint-cache.json");
    let mut gates: Gates = read_json(&state_path).unwrap_or_default();
    let mut cache: Cache = read_json(&cache_path).unwrap_or_default();
    let mut note = String::new();
    let mut last_internetdb: Option<u64> = None;
    publish(&shared, &cache, &note);

    loop {
        let now = now_ms();
        let mut dirty = false;

        // EPSS first: KEV is joined against the latest usable scores.
        let epss_spec = osint::source_spec(Source::Epss);
        if gate(&mut gates, Source::Epss).due(now) {
            let saved = validators(&gates, Source::Epss);
            match get(EPSS_HOST, EPSS_PATH, MAX_EPSS_BYTES, &saved) {
                Ok(Some(fetched)) => {
                    match gunzip(&fetched.body).and_then(|csv| osint::parse_epss(&csv)) {
                        Ok(scores) => {
                            cache.epss = scores;
                            cache.epss_updated_ms = now;
                            remember(&mut gates, Source::Epss, &fetched);
                            gate(&mut gates, Source::Epss).success(now, epss_spec.min_interval_ms);
                            note.clear();
                        }
                        Err(error) => {
                            note = format!("EPSS: {error}");
                            gate(&mut gates, Source::Epss).failure(now, epss_spec.min_interval_ms);
                        }
                    }
                }
                Ok(None) => {
                    gate(&mut gates, Source::Epss).success(now, epss_spec.min_interval_ms);
                }
                Err((status, retry)) => {
                    note = format!("EPSS: HTTP {status}");
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
        if gate(&mut gates, Source::CisaKev).due(now) {
            let saved = validators(&gates, Source::CisaKev);
            match get(KEV_HOST, KEV_PATH, MAX_KEV_BYTES, &saved) {
                Ok(Some(fetched)) => match osint::parse_kev(&fetched.body) {
                    Ok(entries) => {
                        cache.kev = osint::join_kev_epss(entries, cache.epss.clone(), KEV_LIMIT);
                        cache.kev_updated_ms = now;
                        remember(&mut gates, Source::CisaKev, &fetched);
                        gate(&mut gates, Source::CisaKev).success(now, kev_spec.min_interval_ms);
                        note.clear();
                    }
                    Err(error) => {
                        note = format!("KEV: {error}");
                        gate(&mut gates, Source::CisaKev).failure(now, kev_spec.min_interval_ms);
                    }
                },
                Ok(None) => {
                    gate(&mut gates, Source::CisaKev).success(now, kev_spec.min_interval_ms);
                }
                Err((status, retry)) => {
                    note = format!("KEV: HTTP {status}");
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
        if gate(&mut gates, Source::TorExit).due(now) {
            let saved = validators(&gates, Source::TorExit);
            match get(TOR_HOST, TOR_PATH, MAX_TOR_BYTES, &saved) {
                Ok(Some(fetched)) => {
                    cache.tor = osint::parse_tor_exits(&fetched.body);
                    cache.tor_updated_ms = now;
                    remember(&mut gates, Source::TorExit, &fetched);
                    gate(&mut gates, Source::TorExit).success(now, tor_spec.min_interval_ms);
                    note.clear();
                }
                Ok(None) => {
                    gate(&mut gates, Source::TorExit).success(now, tor_spec.min_interval_ms);
                }
                Err((status, retry)) => {
                    note = format!("Tor: HTTP {status}");
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
        if gate(&mut gates, Source::SansIsc).due(now) {
            let saved = validators(&gates, Source::SansIsc);
            match get(SANS_HOST, SANS_PATH, MAX_SANS_BYTES, &saved) {
                Ok(Some(fetched)) => match osint::parse_sans_ports(&fetched.body) {
                    Ok(report) => {
                        cache.sans = Some(report);
                        cache.sans_updated_ms = now;
                        remember(&mut gates, Source::SansIsc, &fetched);
                        gate(&mut gates, Source::SansIsc).success(now, sans_spec.min_interval_ms);
                        note.clear();
                    }
                    Err(error) => {
                        note = format!("SANS ISC: {error}");
                        gate(&mut gates, Source::SansIsc).failure(now, sans_spec.min_interval_ms);
                    }
                },
                Ok(None) => {
                    gate(&mut gates, Source::SansIsc).success(now, sans_spec.min_interval_ms);
                }
                Err((status, retry)) => {
                    note = format!("SANS ISC: HTTP {status}");
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

        if dirty {
            save(&cache_path, &cache);
            save(&state_path, &gates);
            publish(&shared, &cache, &note);
        }

        match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(Command::Refresh) => {}
            Ok(Command::Lookup(ip)) => {
                let result = lookup_internetdb(ip, &mut cache, &mut last_internetdb);
                save(&cache_path, &cache);
                let mut view = shared.lock().unwrap();
                view.lookup = Some(result);
                view.lookup_pending = false;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}
