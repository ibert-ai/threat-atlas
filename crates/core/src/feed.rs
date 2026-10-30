use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    net::{TcpStream, ToSocketAddrs},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tungstenite::{protocol::WebSocketConfig, stream::MaybeTlsStream, Message};
pub const ENDPOINT: &str = "wss://threat-map-api.greynoise.io/ws";
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Location {
    pub latitude: f64,
    pub longitude: f64,
    pub country: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Record {
    pub source: Location,
    pub destination: Location,
    #[serde(default)]
    pub spoofable: bool,
    #[serde(default = "unknown")]
    pub intention: String,
}
fn unknown() -> String {
    "unknown".into()
}
impl Record {
    pub fn valid(&self) -> bool {
        self.intention.len() <= 32
            && !self.intention.chars().any(char::is_control)
            && [&self.source, &self.destination].iter().all(|p| {
                p.latitude.is_finite()
                    && p.longitude.is_finite()
                    && p.latitude.abs() <= 90.
                    && p.longitude.abs() <= 180.
                    && p.country.len() <= 120
                    && !p.country.chars().any(char::is_control)
            })
    }
    pub fn class(&self) -> usize {
        match self.intention.as_str() {
            "malicious" => 0,
            "suspicious" => 1,
            "benign" => 2,
            _ => 3,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Received {
    pub record: Record,
    pub received_ms: u64,
    pub sequence: u64,
}
#[derive(Clone, Serialize)]
pub struct Snapshot {
    pub status: String,
    pub error: String,
    pub now_ms: u64,
    pub last_record_ms: u64,
    pub last_batch_ms: u64,
    pub records: u64,
    pub batches: u64,
    pub changed_batches: u64,
    pub rejected: u64,
    pub reconnects: u64,
    pub counts: [u64; 4],
    pub recent: Vec<Received>,
    pub rate: Vec<u64>,
    pub last_digest: String,
}
#[derive(Default)]
pub struct State {
    connected: bool,
    error: String,
    last_record_ms: u64,
    last_batch_ms: u64,
    records: u64,
    batches: u64,
    changed_batches: u64,
    rejected: u64,
    reconnects: u64,
    counts: [u64; 4],
    recent: VecDeque<Received>,
    rate: VecDeque<(u64, u64)>,
    last_digest: String,
}
impl State {
    pub fn ingest(&mut self, text: &str, now: u64) {
        if text.len() > 1024 * 1024 {
            self.rejected += 1;
            return;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
            self.rejected += 1;
            return;
        };
        let rows = match value {
            serde_json::Value::Array(rows) => rows,
            serde_json::Value::Object(_) => vec![value],
            _ => {
                self.rejected += 1;
                return;
            }
        };
        if rows.len() > 10_000 {
            self.rejected += 1;
            return;
        }
        // Receipt count is not a unique-attack count: the provider gives no IDs or event timestamps.
        self.batches += 1;
        self.last_batch_ms = now;
        let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
        if digest != self.last_digest {
            self.changed_batches += 1;
        }
        self.last_digest = digest;
        for row in rows {
            let Ok(record) = serde_json::from_value::<Record>(row) else {
                self.rejected += 1;
                continue;
            };
            if !record.valid() {
                self.rejected += 1;
                continue;
            }
            self.records += 1;
            self.counts[record.class()] += 1;
            self.last_record_ms = now;
            self.recent.push_back(Received {
                record,
                received_ms: now,
                sequence: self.records,
            });
            if self.recent.len() > 600 {
                self.recent.pop_front();
            }
            let sec = now / 1000;
            if self.rate.back().map(|p| p.0) == Some(sec) {
                self.rate.back_mut().unwrap().1 += 1;
            } else {
                self.rate.push_back((sec, 1));
            }
            while self.rate.len() > 120 {
                self.rate.pop_front();
            }
        }
    }
    pub fn snapshot(&self, now: u64) -> Snapshot {
        let status = if !self.connected {
            if self.error.is_empty() {
                "CONNECTING"
            } else {
                "OFFLINE"
            }
        } else if self.last_record_ms == 0 {
            "WAITING"
        } else if now.saturating_sub(self.last_record_ms) > 10_000 {
            "STALE"
        } else {
            "LIVE"
        };
        let rate = (0..90)
            .map(|i| {
                let s = (now / 1000).saturating_sub(89 - i);
                self.rate
                    .iter()
                    .find(|p| p.0 == s)
                    .map(|p| p.1)
                    .unwrap_or(0)
            })
            .collect();
        Snapshot {
            status: status.into(),
            error: self.error.clone(),
            now_ms: now,
            last_record_ms: self.last_record_ms,
            last_batch_ms: self.last_batch_ms,
            records: self.records,
            batches: self.batches,
            changed_batches: self.changed_batches,
            rejected: self.rejected,
            reconnects: self.reconnects,
            counts: self.counts,
            recent: self.recent.iter().rev().cloned().collect(),
            rate,
            last_digest: self.last_digest.clone(),
        }
    }
}
pub struct Feed {
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
}
impl Drop for Feed {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}
impl Feed {
    pub fn shared() -> Arc<Self> {
        static SHARED: OnceLock<Mutex<Weak<Feed>>> = OnceLock::new();
        let mut weak = SHARED
            .get_or_init(|| Mutex::new(Weak::new()))
            .lock()
            .unwrap();
        if let Some(feed) = weak.upgrade() {
            return feed;
        }
        let feed = Arc::new(Self {
            state: Arc::new(Mutex::new(State::default())),
            stop: Arc::new(AtomicBool::new(false)),
        });
        let state = feed.state.clone();
        let stop = feed.stop.clone();
        let worker_state = state.clone();
        if let Err(error) = thread::Builder::new()
            .name("threat-atlas-feed".into())
            .spawn(move || worker(worker_state, stop))
        {
            state.lock().unwrap().error = format!("Cannot start feed: {error}");
        }
        *weak = Arc::downgrade(&feed);
        feed
    }
    pub fn snapshot(&self) -> Snapshot {
        self.state.lock().unwrap().snapshot(now_ms())
    }
}
fn connect() -> Result<tungstenite::WebSocket<MaybeTlsStream<TcpStream>>, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let addresses = ("threat-map-api.greynoise.io", 443)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?;
    let mut tcp = None;
    for addr in addresses.take(3) {
        if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            tcp = Some(s);
            break;
        }
    }
    let tcp = tcp.ok_or("Cannot reach live feed")?;
    tcp.set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let config = WebSocketConfig::default()
        .max_message_size(Some(1024 * 1024))
        .max_frame_size(Some(1024 * 1024));
    let (mut socket, _) = tungstenite::client_tls_with_config(ENDPOINT, tcp, Some(config), None)
        .map_err(|e| e.to_string())?;
    match socket.get_mut() {
        MaybeTlsStream::Plain(s) => s.set_read_timeout(Some(Duration::from_secs(1))),
        MaybeTlsStream::Rustls(s) => s.sock.set_read_timeout(Some(Duration::from_secs(1))),
        _ => Ok(()),
    }
    .map_err(|e| e.to_string())?;
    Ok(socket)
}
fn worker(state: Arc<Mutex<State>>, stop: Arc<AtomicBool>) {
    let mut delay = 2u64;
    while !stop.load(Ordering::Relaxed) {
        let outcome = (|| -> Result<(), String> {
            let mut socket = connect()?;
            {
                let mut s = state.lock().unwrap();
                s.connected = true;
                s.error.clear();
            }
            let mut last_data = Instant::now();
            let mut received_valid = false;
            while !stop.load(Ordering::Relaxed) {
                match socket.read() {
                    Ok(Message::Text(text)) => {
                        let mut s = state.lock().unwrap();
                        let before = s.records;
                        s.ingest(&text, now_ms());
                        if s.records > before {
                            last_data = Instant::now();
                            received_valid = true;
                            delay = 2;
                        }
                    }
                    Ok(Message::Ping(_)) => {
                        let _ = socket.flush();
                    }
                    Ok(Message::Close(_)) => return Err("Feed closed connection".into()),
                    Ok(_) => (),
                    Err(tungstenite::Error::Io(e))
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(e) => return Err(e.to_string()),
                }
                if last_data.elapsed() > Duration::from_secs(30) {
                    return Err(if received_valid {
                        "No new records for 30 seconds"
                    } else {
                        "Feed supplied no valid records"
                    }
                    .into());
                }
            }
            let _ = socket.close(None);
            Ok(())
        })();
        {
            let mut s = state.lock().unwrap();
            s.connected = false;
            if let Err(e) = outcome {
                s.error = e.chars().take(180).collect();
                s.reconnects += 1;
            }
        }
        for _ in 0..delay * 10 {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        delay = (delay * 2).min(60);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const ROW: &str = r#"[{"source":{"latitude":52.2,"longitude":4.7,"country":"Netherlands"},"destination":{"latitude":38.8,"longitude":-77.0,"country":"United States"},"intention":"malicious","spoofable":true}]"#;
    #[test]
    fn counts_real_receipts_and_staleness() {
        let mut s = State {
            connected: true,
            ..Default::default()
        };
        s.ingest(ROW, 1000);
        assert_eq!(s.snapshot(2000).status, "LIVE");
        assert_eq!(s.snapshot(12000).status, "STALE");
        assert_eq!(s.records, 1);
        assert_eq!(s.counts, [1, 0, 0, 0]);
        s.ingest(ROW, 2000);
        assert_eq!(s.records, 2);
        assert_eq!(s.changed_batches, 1);
        assert_eq!(s.snapshot(2000).rate.iter().sum::<u64>(), 2);
    }
    #[test]
    fn rejects_bad_coordinates_and_schema() {
        let mut s = State::default();
        s.ingest(&ROW.replace("52.2", "152.2"), 1000);
        s.ingest("<html>cookie prompt</html>", 1000);
        assert_eq!(s.records, 0);
        assert_eq!(s.rejected, 2);
    }
    #[test]
    fn rejects_oversized_and_control_text() {
        for bad in [
            ROW.replace("malicious", &"x".repeat(33)),
            ROW.replace("Netherlands", "Netherlands\\nInjected"),
        ] {
            let mut state = State::default();
            state.ingest(&bad, 1000);
            assert_eq!(state.records, 0);
            assert_eq!(state.rejected, 1);
        }
        let mut state = State::default();
        state.ingest(&" ".repeat(1024 * 1024 + 1), 1000);
        assert_eq!(state.rejected, 1);
    }
    #[test]
    fn buffers_remain_bounded() {
        let mut s = State::default();
        for i in 0..2000 {
            s.ingest(ROW, i * 1000);
        }
        assert_eq!(s.recent.len(), 600);
        assert_eq!(s.rate.len(), 120);
        assert_eq!(s.snapshot(2_000_000).recent.len(), 600);
    }
    #[test]
    fn offline_is_not_live() {
        let mut s = State::default();
        s.ingest(ROW, 1000);
        s.error = "Disconnected".into();
        assert_eq!(s.snapshot(1001).status, "OFFLINE");
    }
}
