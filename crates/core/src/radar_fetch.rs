//! Cloudflare Radar request worker for hosts without their own (the Windows SOC Desktop). Same
//! policy as the macOS beta worker: opt-in, the user's own Account/Radar/Read token from the host's
//! secure store, at most one request every 15 minutes (persisted before any I/O), exponential
//! backoff with Retry-After and Ratelimit honoured, no redirects, verified TLS to api.cloudflare.com
//! only, a single worker per profile, and polling stops on 401/403. Responses are validated by
//! `radar::parse`; only accepted aggregates are cached and shown.
use crate::radar;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::Duration,
};

pub const HOST: &str = "api.cloudflare.com";
pub const PATH: &str =
    "/client/v4/radar/attacks/layer3/top/attacks?dateRange=1d&limit=20&format=JSON";
/// Request floor shared with the macOS worker.
pub const INTERVAL_MS: u64 = 15 * 60 * 1000;
const MAX_DELAY_MS: u64 = 21_630_000;

/// One HTTP response: status, the two rate headers and the (de-chunked) body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub retry_after: Option<String>,
    pub ratelimit: Option<String>,
    pub body: Vec<u8>,
}

/// Next-request delay after a response, matching macOS `PollPolicy.delay` without jitter.
pub fn delay_ms(retry_after: Option<&str>, ratelimit: Option<&str>, failures: u32) -> u64 {
    let backoff = 60_000u64
        .saturating_mul(1 << failures.min(9))
        .min(21_600_000);
    let mut delay = backoff.max(INTERVAL_MS);
    if let Some(seconds) = retry_after.and_then(|v| v.trim().parse::<f64>().ok()) {
        if seconds.is_finite() && seconds > 0. {
            delay = delay.max((seconds * 1000.) as u64);
        }
    }
    for part in ratelimit.unwrap_or_default().split(';') {
        if let Some(seconds) = part
            .trim()
            .strip_prefix("t=")
            .and_then(|v| v.parse::<f64>().ok())
        {
            if seconds.is_finite() && seconds >= 0. {
                delay = delay.max(((seconds + 5.) * 1000.) as u64);
            }
        }
    }
    delay.min(MAX_DELAY_MS)
}

/// Parse a complete HTTP/1.1 response (Connection: close): status line, headers and body,
/// decoding chunked transfer encoding and honouring Content-Length. Bodies above
/// `radar::MAX_BYTES` are rejected.
pub fn parse_response(raw: &[u8]) -> Result<Response, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("incomplete HTTP response")?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| "non-UTF-8 HTTP header")?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("bad HTTP status line")?;
    let (mut chunked, mut length, mut retry_after, mut ratelimit) = (false, None, None, None);
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "transfer-encoding" => chunked = value.to_ascii_lowercase().contains("chunked"),
            "content-length" => length = value.parse::<usize>().ok(),
            "retry-after" => retry_after = Some(value.chars().take(64).collect()),
            "ratelimit" => ratelimit = Some(value.chars().take(256).collect()),
            _ => {}
        }
    }
    let rest = &raw[split + 4..];
    let body = if chunked {
        dechunk(rest)?
    } else if let Some(length) = length {
        rest.get(..length).ok_or("truncated HTTP body")?.to_vec()
    } else {
        rest.to_vec()
    };
    if body.len() > radar::MAX_BYTES {
        return Err("HTTP body too large".into());
    }
    Ok(Response {
        status,
        retry_after,
        ratelimit,
        body,
    })
}

fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let end = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("bad chunk header")?;
        let size_text = std::str::from_utf8(&data[..end]).map_err(|_| "bad chunk header")?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "bad chunk size")?;
        data = &data[end + 2..];
        if size == 0 {
            return Ok(body);
        }
        if body.len() + size > radar::MAX_BYTES {
            return Err("HTTP body too large".into());
        }
        body.extend_from_slice(data.get(..size).ok_or("truncated chunk")?);
        data = data.get(size + 2..).ok_or("truncated chunk")?;
    }
}

/// One verified-TLS GET to the fixed Radar endpoint with the bearer token. No redirects are
/// followed (a 3xx is returned as is), no cookies, no proxy, no cache.
pub fn https_get(token: &str, timeout: Duration) -> Result<Response, String> {
    if token.is_empty() || token.len() > 4096 || token.chars().any(|c| c.is_control()) {
        return Err("invalid token".into());
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(HOST)
        .map_err(|e| e.to_string())?
        .to_owned();
    let connection =
        rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    let address = (HOST, 443)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or("no address")?;
    let socket = TcpStream::connect_timeout(&address, timeout).map_err(|e| e.to_string())?;
    socket.set_read_timeout(Some(timeout)).ok();
    socket.set_write_timeout(Some(timeout)).ok();
    let mut tls = rustls::StreamOwned::new(connection, socket);
    let request = format!(
        "GET {PATH} HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {token}\r\nAccept: application/json\r\nUser-Agent: AtlasSOC-Desktop/{}\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    tls.write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let limit = (radar::MAX_BYTES + 65_536) as u64;
    match (&mut tls).take(limit).read_to_end(&mut raw) {
        Ok(_) => {}
        // Some servers close without TLS close_notify; the HTTP framing below still validates.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => {}
        Err(e) => return Err(e.to_string()),
    }
    parse_response(&raw)
}

/// What the host shows: the last accepted aggregate body and its receipt time, plus state.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Status {
    pub enabled: bool,
    /// The saved token got HTTP 200 since it was saved (persisted).
    pub verified: bool,
    pub busy: bool,
    pub message: String,
    pub body: Option<Vec<u8>>,
    pub received_ms: u64,
    pub next_ms: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Persisted {
    next_ms: u64,
    enabled: bool,
    verified: bool,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Cached {
    received_ms: u64,
    body: String,
}

/// Token source and fetcher are injected so tests run offline without any secret store.
pub type TokenSource = Box<dyn Fn() -> Option<String> + Send>;
pub type Fetcher = Box<dyn FnMut(&str) -> Result<Response, String> + Send>;

pub struct Worker {
    shared: Arc<Mutex<Status>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    dir: PathBuf,
    /// Held for the worker's lifetime: one Radar worker per profile directory.
    _lock: Option<fs::File>,
}

impl Worker {
    /// Start the worker for a profile directory. If another worker holds the profile lock, this
    /// one never requests and reports that instead.
    pub fn start(dir: &Path, token: TokenSource, fetch: Fetcher, now_ms: fn() -> u64) -> Self {
        let _ = fs::create_dir_all(dir);
        let persisted: Persisted = fs::read(dir.join("radar-state.json"))
            .ok()
            .and_then(|d| serde_json::from_slice(&d).ok())
            .unwrap_or_default();
        let mut status = Status {
            enabled: persisted.enabled,
            verified: persisted.verified,
            next_ms: persisted.next_ms,
            message: "Cloudflare Radar off. Add your own token to start.".into(),
            ..Status::default()
        };
        if let Some(cached) = fs::read(dir.join("radar-snapshot.json"))
            .ok()
            .and_then(|d| serde_json::from_slice::<Cached>(&d).ok())
            .filter(|c| radar::parse(c.body.as_bytes()).is_ok())
        {
            status.body = Some(cached.body.into_bytes());
            status.received_ms = cached.received_ms;
            status.message = "Saved aggregate data. Not live individual events.".into();
        }
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("radar-worker.lock"))
            .ok()
            .filter(|file| file.try_lock().is_ok());
        let shared = Arc::new(Mutex::new(status));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = if lock.is_some() {
            let (shared, stop, dir) = (shared.clone(), stop.clone(), dir.to_path_buf());
            Some(std::thread::spawn(move || {
                run(&shared, &stop, &dir, token, fetch, now_ms)
            }))
        } else {
            let mut s = shared.lock().unwrap();
            s.enabled = false;
            s.message = "Another AtlasSOC Radar worker is running. Use its window.".into();
            None
        };
        Self {
            shared,
            stop,
            handle,
            dir: dir.to_path_buf(),
            _lock: lock,
        }
    }
    pub fn status(&self) -> Status {
        self.shared.lock().map(|s| s.clone()).unwrap_or_default()
    }
    /// User choice: Start or Pause. Kept across launches; a request still waits for the floor.
    pub fn set_enabled(&self, enabled: bool) {
        if self.handle.is_none() {
            return;
        }
        let mut s = self.shared.lock().unwrap();
        s.enabled = enabled;
        s.message = if enabled {
            "Polling enabled. At most one request every 15 minutes.".into()
        } else {
            "Paused. Saved data remains visible.".into()
        };
        save(&self.dir, &s);
    }
    /// A new token was saved (or removed): it is unverified until Cloudflare accepts it.
    pub fn token_changed(&self, saved: bool) {
        let mut s = self.shared.lock().unwrap();
        s.verified = false;
        s.message = if saved {
            "Token saved. Start Radar when ready.".into()
        } else {
            "Token removed. Radar stopped.".into()
        };
        if !saved {
            s.enabled = false;
        }
        save(&self.dir, &s);
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn save(dir: &Path, s: &Status) {
    let persisted = Persisted {
        next_ms: s.next_ms,
        enabled: s.enabled,
        verified: s.verified,
    };
    if let Ok(data) = serde_json::to_vec(&persisted) {
        let tmp = dir.join("radar-state.json.tmp");
        if fs::write(&tmp, data).is_ok() {
            let _ = fs::rename(tmp, dir.join("radar-state.json"));
        }
    }
}

fn run(
    shared: &Mutex<Status>,
    stop: &AtomicBool,
    dir: &Path,
    token: TokenSource,
    mut fetch: Fetcher,
    now_ms: fn() -> u64,
) {
    let mut failures = 0u32;
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
        let now = now_ms();
        let due = {
            let s = shared.lock().unwrap();
            s.enabled && now >= s.next_ms
        };
        if !due {
            continue;
        }
        tick(shared, dir, &token, &mut fetch, now, &mut failures);
    }
}

/// One eligible request (also driven directly by the offline policy tests).
fn tick(
    shared: &Mutex<Status>,
    dir: &Path,
    token: &TokenSource,
    fetch: &mut Fetcher,
    now: u64,
    failures: &mut u32,
) {
    let Some(secret) = token().filter(|t| !t.trim().is_empty()) else {
        let mut s = shared.lock().unwrap();
        s.enabled = false;
        s.message = "Cloudflare token required. No request sent.".into();
        save(dir, &s);
        return;
    };
    {
        // Persist the floor BEFORE I/O: relaunch, sleep/wake or a manual retry cannot bypass it.
        let mut s = shared.lock().unwrap();
        s.next_ms = now + INTERVAL_MS;
        s.busy = true;
        s.message = "Fetching Cloudflare Radar aggregate data...".into();
        save(dir, &s);
    }
    let result = fetch(secret.trim());
    drop(secret);
    let mut s = shared.lock().unwrap();
    s.busy = false;
    match result {
        Ok(r) if r.status == 401 || r.status == 403 => {
            s.enabled = false;
            s.verified = false;
            s.message = format!(
                "Authorization denied ({}). Polling stopped; check the token's Radar Read permission.",
                r.status
            );
        }
        Ok(r) if r.status == 200 => match radar::parse(&r.body) {
            Ok(_) => {
                *failures = 0;
                s.verified = true;
                s.received_ms = now;
                s.message =
                    "Cloudflare Radar | aggregated network-layer attack origins | past day".into();
                if r.ratelimit.as_deref().is_some_and(|h| h.contains("r=0")) {
                    s.next_ms = now + delay_ms(None, r.ratelimit.as_deref(), 0);
                }
                let cached = Cached {
                    received_ms: now,
                    body: String::from_utf8_lossy(&r.body).into_owned(),
                };
                if let Ok(data) = serde_json::to_vec(&cached) {
                    let tmp = dir.join("radar-snapshot.json.tmp");
                    if fs::write(&tmp, data).is_ok() {
                        let _ = fs::rename(tmp, dir.join("radar-snapshot.json"));
                    }
                }
                s.body = Some(r.body);
            }
            Err(_) => {
                *failures += 1;
                s.next_ms = now + delay_ms(None, None, *failures);
                s.message =
                    "Response validation failed. Saved data retained; retry after cooldown.".into();
            }
        },
        Ok(r) => {
            *failures += 1;
            s.next_ms = now + delay_ms(r.retry_after.as_deref(), r.ratelimit.as_deref(), *failures);
            let permanent = (300..500).contains(&r.status) && r.status != 429;
            if permanent {
                s.enabled = false;
            }
            s.message = format!(
                "HTTP {}. Saved data retained; cooldown applies.{}",
                r.status,
                if permanent { " Polling stopped." } else { "" }
            );
        }
        Err(_) => {
            *failures += 1;
            s.next_ms = now + delay_ms(None, None, *failures);
            s.message = "Network request failed. Saved data retained; retry after cooldown.".into();
        }
    }
    save(dir, &s);
}

#[cfg(test)]
mod tests {
    use super::*;
    // Synthetic fixture only: never presented as telemetry.
    const BODY: &str = r#"{"success":true,"errors":[],"messages":[],"result":{"meta":{"lastUpdated":"2026-01-01T00:00:00Z","normalization":"PERCENTAGE","dateRange":[{"startTime":"2025-12-31T00:00:00Z","endTime":"2026-01-01T00:00:00Z"}]},"top_0":[{"originCountryAlpha2":"FR","originCountryName":"France","value":"4.3"}]}}"#;

    fn ok(body: &str) -> Response {
        Response {
            status: 200,
            retry_after: None,
            ratelimit: None,
            body: body.as_bytes().to_vec(),
        }
    }
    fn status(code: u16) -> Response {
        Response {
            status: code,
            ..ok("")
        }
    }
    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("atlas-radar-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
    fn shared(enabled: bool) -> Mutex<Status> {
        Mutex::new(Status {
            enabled,
            ..Status::default()
        })
    }
    fn token(value: Option<&'static str>) -> TokenSource {
        Box::new(move || value.map(String::from))
    }
    fn fetcher(responses: Vec<Result<Response, String>>) -> (Fetcher, Arc<Mutex<Vec<String>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (log, mut queue) = (seen.clone(), responses.into_iter());
        (
            Box::new(move |token: &str| {
                log.lock().unwrap().push(token.to_string());
                queue.next().unwrap_or(Err("no stub".into()))
            }),
            seen,
        )
    }

    #[test]
    fn http_parsing_handles_length_chunked_and_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nRatelimit: \"default\";r=0;t=30\r\n\r\nhelloEXTRA";
        let r = parse_response(raw).unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, b"hello".as_slice()));
        assert_eq!(r.ratelimit.as_deref(), Some("\"default\";r=0;t=30"));
        let chunked = b"HTTP/1.1 429 Too Many\r\nTransfer-Encoding: chunked\r\nRetry-After: 120\r\n\r\n4\r\nWiki\r\n5;x=y\r\npedia\r\n0\r\n\r\n";
        let r = parse_response(chunked).unwrap();
        assert_eq!(r.body, b"Wikipedia");
        assert_eq!((r.status, r.retry_after.as_deref()), (429, Some("120")));
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort").is_err());
        assert!(parse_response(b"garbage").is_err());
        assert!(
            parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n").is_err()
        );
    }

    #[test]
    fn delay_matches_the_macos_policy() {
        assert_eq!(delay_ms(None, None, 0), INTERVAL_MS);
        assert_eq!(delay_ms(None, None, 3), INTERVAL_MS); // 8 min backoff -> 15 min floor
        assert_eq!(delay_ms(None, None, 4), 960_000); // 60 s * 2^4 = 16 min
        assert_eq!(delay_ms(None, None, 5), 1_920_000); // 60 s * 2^5 = 32 min
        assert_eq!(delay_ms(None, None, 9), 21_600_000);
        assert_eq!(delay_ms(Some("3600"), None, 0), 3_600_000);
        assert_eq!(delay_ms(None, Some("\"default\";r=0;t=2000"), 0), 2_005_000);
        assert_eq!(delay_ms(Some("999999"), None, 0), MAX_DELAY_MS);
    }

    #[test]
    fn success_caches_verifies_and_persists_the_floor_before_io() {
        let dir = temp("ok");
        let s = shared(true);
        let (mut fetch, seen) = fetcher(vec![Ok(ok(BODY))]);
        let mut failures = 0;
        tick(
            &s,
            &dir,
            &token(Some(" fake-token ")),
            &mut fetch,
            1_000,
            &mut failures,
        );
        let st = s.lock().unwrap().clone();
        assert!(st.verified && st.enabled && st.body.is_some() && st.received_ms == 1_000);
        assert_eq!(st.next_ms, 1_000 + INTERVAL_MS);
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            ["fake-token"],
            "token trimmed, sent once"
        );
        let persisted: Persisted =
            serde_json::from_slice(&fs::read(dir.join("radar-state.json")).unwrap()).unwrap();
        assert!(persisted.verified && persisted.next_ms == 1_000 + INTERVAL_MS);
        let cached = fs::read_to_string(dir.join("radar-snapshot.json")).unwrap();
        assert!(cached.contains("France") && !cached.contains("fake-token"));
        // A restarted worker reloads the cache and the floor.
        let worker = Worker::start(
            &dir,
            token(None),
            Box::new(|_: &str| Err("no".into())),
            || 2_000,
        );
        let st = worker.status();
        assert!(st.body.is_some() && st.verified && st.next_ms == 1_000 + INTERVAL_MS);
        drop(worker);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn denial_missing_token_and_errors_follow_the_policy() {
        let dir = temp("policy");
        let mut failures = 0;
        for code in [401u16, 403] {
            let s = shared(true);
            let (mut fetch, _) = fetcher(vec![Ok(status(code))]);
            tick(&s, &dir, &token(Some("t")), &mut fetch, 0, &mut failures);
            let st = s.lock().unwrap().clone();
            assert!(!st.enabled && !st.verified && st.message.contains(&code.to_string()));
        }
        let s = shared(true);
        let (mut fetch, seen) = fetcher(vec![]);
        tick(&s, &dir, &token(None), &mut fetch, 0, &mut failures);
        assert!(
            !s.lock().unwrap().enabled && seen.lock().unwrap().is_empty(),
            "no token, no request"
        );
        let s = shared(true);
        let (mut fetch, _) = fetcher(vec![Ok(status(404))]);
        tick(&s, &dir, &token(Some("t")), &mut fetch, 0, &mut failures);
        assert!(!s.lock().unwrap().enabled, "permanent client error stops");
        let s = shared(true);
        let mut limited = status(429);
        limited.retry_after = Some("7200".into());
        let (mut fetch, _) = fetcher(vec![Ok(limited)]);
        failures = 0;
        tick(&s, &dir, &token(Some("t")), &mut fetch, 0, &mut failures);
        let st = s.lock().unwrap().clone();
        assert!(
            st.enabled && st.next_ms == 7_200_000,
            "429 keeps polling after Retry-After"
        );
        let s = shared(true);
        s.lock().unwrap().body = Some(BODY.into());
        let (mut fetch, _) = fetcher(vec![Ok(ok("{not json")), Err("timeout".into())]);
        tick(&s, &dir, &token(Some("t")), &mut fetch, 0, &mut failures);
        tick(&s, &dir, &token(Some("t")), &mut fetch, 0, &mut failures);
        let st = s.lock().unwrap().clone();
        assert!(
            st.enabled && st.body.as_deref() == Some(BODY.as_bytes()),
            "bad data never replaces good"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn one_worker_per_profile_and_paused_workers_never_request() {
        let dir = temp("lock");
        let (fetch, seen) = fetcher(vec![Ok(ok(BODY))]);
        let first = Worker::start(&dir, token(Some("t")), fetch, || 10_000_000);
        let (fetch2, seen2) = fetcher(vec![Ok(ok(BODY))]);
        let second = Worker::start(&dir, token(Some("t")), fetch2, || 10_000_000);
        assert!(second
            .status()
            .message
            .contains("Another AtlasSOC Radar worker"));
        second.set_enabled(true);
        std::thread::sleep(Duration::from_millis(600));
        assert!(
            seen.lock().unwrap().is_empty(),
            "paused by default: no request"
        );
        assert!(seen2.lock().unwrap().is_empty());
        first.set_enabled(true);
        std::thread::sleep(Duration::from_millis(800));
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "one request, then the 15-minute floor"
        );
        assert!(first.status().verified);
        drop((first, second));
        let _ = fs::remove_dir_all(dir);
    }
}
