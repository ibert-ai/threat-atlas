//! Checks GitHub once at startup for a newer AtlasSOC and hands an approved update to the
//! embedded script. The app never installs anything by itself.
use crate::soc_config::{BUILD, VERSION};
use crate::soc_radar::https_get;
use std::{
    env, fs,
    path::PathBuf,
    process::{self, Command},
    sync::{Arc, Mutex},
    thread,
};
use threat_atlas_core::update::{self, Available, Version};

const IDENTITY: &str = include_str!("../../../atlassoc-beta-version.json");
const SCRIPT: &str = include_str!("../../../scripts/update-atlassoc.ps1");
const HEADERS: &str = "Accept: application/vnd.github+json\r\n";

#[derive(Clone, PartialEq, Eq)]
pub enum Status {
    Checking,
    Current,
    Failed,
    Available(Available),
}

impl Status {
    pub fn label(&self) -> String {
        match self {
            Status::Checking => "Checking for updates...".into(),
            Status::Current => format!("AtlasSOC {VERSION} (build {BUILD}) is up to date"),
            Status::Failed => "Could not check for updates".into(),
            Status::Available(found) => format!(
                "Update available: {}.{}.{} (build {})...",
                found.version.major, found.version.minor, found.version.patch, found.version.build
            ),
        }
    }
}

fn beta() -> bool {
    update::is_prerelease(IDENTITY)
}

fn check() -> Status {
    let Some(current) = Version::parse(VERSION, BUILD) else {
        return Status::Failed;
    };
    match https_get(update::HOST, update::PATH, HEADERS, update::MAX_BYTES) {
        Some(reply) if reply.status == 200 => {
            serde_json::from_slice::<serde_json::Value>(&reply.body)
                .ok()
                .filter(serde_json::Value::is_array)
                .map_or(Status::Failed, |_| {
                    update::newer(&reply.body, current, beta())
                        .map_or(Status::Current, Status::Available)
                })
        }
        _ => Status::Failed,
    }
}

/// Created only after licence consent, and never by the offline smoke test.
pub struct Updater {
    status: Arc<Mutex<Status>>,
}

impl Updater {
    pub fn start() -> Self {
        let status = Arc::new(Mutex::new(Status::Checking));
        let shared = status.clone();
        thread::spawn(move || {
            let result = check();
            if let Ok(mut status) = shared.lock() {
                *status = result;
            }
        });
        Self { status }
    }

    pub fn status(&self) -> Status {
        self.status
            .lock()
            .map_or(Status::Failed, |status| status.clone())
    }
}

/// Starts the update in a visible PowerShell window. The script waits for this process to end.
pub fn launch() -> Result<(), String> {
    let root = env::var_os("SystemRoot").ok_or("SystemRoot is unavailable")?;
    let powershell = PathBuf::from(root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let script = env::temp_dir().join(format!("update-atlassoc-{}.ps1", process::id()));
    fs::write(&script, SCRIPT).map_err(|error| error.to_string())?;
    Command::new(powershell)
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&script)
        .args(["-Channel", if beta() { "beta" } else { "stable" }])
        .arg("-Silent")
        .args(["-WaitPid", &process::id().to_string()])
        .spawn()
        .map(drop)
        .map_err(|error| error.to_string())
}
