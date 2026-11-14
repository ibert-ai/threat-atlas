//! FAS 1 OSINT worker: CISA KEV + FIRST EPSS, Tor exit count.
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
    osint::{self, EpssScore, KevWithEpss, RateGate, Source},
};

const KEV_HOST: &str = "www.cisa.gov";
const KEV_PATH: &str = "/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_HOST: &str = "epss.empiricalsecurity.com";
const EPSS_PATH: &str = "/epss_scores-current.csv.gz";
const TOR_HOST: &str = "check.torproject.org";
const TOR_PATH: &str = "/torbulkexitlist";
const MAX_KEV_BYTES: usize = 8 * 1024 * 1024;
const MAX_EPSS_BYTES: usize = 16 * 1024 * 1024;
const MAX_EPSS_UNPACKED: u64 = 64 * 1024 * 1024;
const MAX_TOR_BYTES: usize = 2 * 1024 * 1024;
const KEV_LIMIT: usize = 2_000;

/// Data shown by the host. Cheap to clone; the host reads it once per frame.
#[derive(Clone, Debug, Default)]
pub struct View {
    pub kev: Vec<KevWithEpss>,
    pub kev_updated_ms: u64,
    pub epss_updated_ms: u64,
    pub tor_count: usize,
    pub tor_updated_ms: u64,
    pub note: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Cache {
    kev: Vec<KevWithEpss>,
    kev_updated_ms: u64,
    epss: Vec<EpssScore>,
    epss_updated_ms: u64,
    tor: Vec<IpAddr>,
    tor_updated_ms: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Gates {
    gates: BTreeMap<String, RateGate>,
}

enum Command {
    Refresh,
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
    *view = View {
        kev: cache.kev.clone(),
        kev_updated_ms: cache.kev_updated_ms,
        epss_updated_ms: cache.epss_updated_ms,
        tor_count: cache.tor.len(),
        tor_updated_ms: cache.tor_updated_ms,
        note: note.to_owned(),
    };
}

fn gate(gates: &mut Gates, source: Source) -> &mut RateGate {
    gates
        .gates
        .entry(osint::source_spec(source).id.to_owned())
        .or_default()
}

fn get(host: &str, path: &str, max_bytes: usize) -> Result<Vec<u8>, (u16, Option<u64>)> {
    let reply = https_get_public(
        host,
        path,
        "Accept: */*\r\nUser-Agent: AtlasSOC-OSINT\r\n",
        max_bytes,
    )
    .ok_or((0, None))?;
    match reply.status {
        200 => Ok(reply.body),
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
    publish(&shared, &cache, &note);

    loop {
        let now = now_ms();
        let mut changed = false;

        // EPSS first: KEV is joined against the latest usable scores.
        let epss_spec = osint::source_spec(Source::Epss);
        if gate(&mut gates, Source::Epss).due(now) {
            match get(EPSS_HOST, EPSS_PATH, MAX_EPSS_BYTES) {
                Ok(bytes) => match gunzip(&bytes).and_then(|csv| osint::parse_epss(&csv)) {
                    Ok(scores) => {
                        cache.epss = scores;
                        cache.epss_updated_ms = now;
                        gate(&mut gates, Source::Epss).success(now, epss_spec.min_interval_ms);
                        changed = true;
                    }
                    Err(error) => {
                        note = format!("EPSS: {error}");
                        gate(&mut gates, Source::Epss).failure(now, epss_spec.min_interval_ms);
                    }
                },
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
        }

        let kev_spec = osint::source_spec(Source::CisaKev);
        if gate(&mut gates, Source::CisaKev).due(now) {
            match get(KEV_HOST, KEV_PATH, MAX_KEV_BYTES) {
                Ok(bytes) => match osint::parse_kev(&bytes) {
                    Ok(entries) => {
                        cache.kev = osint::join_kev_epss(entries, cache.epss.clone(), KEV_LIMIT);
                        cache.kev_updated_ms = now;
                        gate(&mut gates, Source::CisaKev).success(now, kev_spec.min_interval_ms);
                        changed = true;
                    }
                    Err(error) => {
                        note = format!("KEV: {error}");
                        gate(&mut gates, Source::CisaKev).failure(now, kev_spec.min_interval_ms);
                    }
                },
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
        }

        let tor_spec = osint::source_spec(Source::TorExit);
        if gate(&mut gates, Source::TorExit).due(now) {
            match get(TOR_HOST, TOR_PATH, MAX_TOR_BYTES) {
                Ok(bytes) => {
                    cache.tor = osint::parse_tor_exits(&bytes);
                    cache.tor_updated_ms = now;
                    gate(&mut gates, Source::TorExit).success(now, tor_spec.min_interval_ms);
                    changed = true;
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
        }

        if changed {
            save(&cache_path, &cache);
            save(&state_path, &gates);
            publish(&shared, &cache, &note);
        } else if !note.is_empty() {
            publish(&shared, &cache, &note);
        }

        match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(Command::Refresh) => {}
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}
