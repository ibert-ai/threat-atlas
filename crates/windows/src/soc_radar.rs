//! Windows Cloudflare Radar worker. The token lives in Windows Credential Manager and is never
//! written to disk here. TLS, proxy and certificate checks are the operating system's, through WinHTTP.
use crate::soc_config::write_atomic;
use std::{
    fs,
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{
        mpsc::{self, RecvTimeoutError, Sender},
        Arc, Mutex,
    },
    time::Duration,
};
use threat_atlas_core::{
    feed::now_ms,
    i18n::{self, Language},
    radar::{self, Aggregate},
    radar_poll::{self, PollState, Response, Status},
};
use windows_sys::Win32::{
    Foundation::HWND,
    Networking::WinHttp::*,
    Security::Credentials::*,
    UI::WindowsAndMessaging::{MessageBoxW, MB_ICONWARNING, MB_OK},
};

const TARGET: &str = "AtlasSOC/CloudflareRadar";
const ACCOUNT: &str = "RadarRead";
const TICK: Duration = Duration::from_secs(30);
/// CREDUI_MAX_PASSWORD_LENGTH in wincred.h; windows-sys does not export it.
const MAX_SECRET_LENGTH: u32 = 256;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn valid_token(token: &str) -> bool {
    !token.is_empty() && token.len() < 512 && token.bytes().all(|b| b.is_ascii_graphic())
}

fn read_token() -> Option<String> {
    let target = wide(TARGET);
    let mut out = std::mem::MaybeUninit::<*mut CREDENTIALW>::uninit();
    // SAFETY: CredReadW writes the pointer when it returns non-zero; only then is it read. The
    // pointer is checked for null, an empty or missing blob is never turned into a slice (a null
    // pointer is not a valid slice pointer even for length 0), the blob is copied before
    // CredFree, and the credential is released exactly once.
    unsafe {
        if CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, out.as_mut_ptr()) == 0 {
            return None;
        }
        let found = out.assume_init();
        let credential = found.as_ref()?;
        let (data, size) = (
            credential.CredentialBlob,
            credential.CredentialBlobSize as usize,
        );
        let token = if data.is_null() || size == 0 {
            None
        } else {
            String::from_utf8(std::slice::from_raw_parts(data, size).to_vec()).ok()
        };
        CredFree(found.cast());
        token.filter(|t| valid_token(t))
    }
}

fn write_token(token: &str) -> bool {
    let mut target = wide(TARGET);
    let mut account = wide(ACCOUNT);
    let mut blob = token.as_bytes().to_vec();
    // SAFETY: all pointers stay valid for the call; a zeroed CREDENTIALW is the documented base.
    unsafe {
        let mut credential: CREDENTIALW = std::mem::zeroed();
        credential.Type = CRED_TYPE_GENERIC;
        credential.TargetName = target.as_mut_ptr();
        credential.UserName = account.as_mut_ptr();
        credential.CredentialBlob = blob.as_mut_ptr();
        credential.CredentialBlobSize = blob.len() as u32;
        credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
        CredWriteW(&credential, 0) != 0
    }
}

fn delete_token() {
    let target = wide(TARGET);
    // SAFETY: `target` is a valid NUL-terminated string. A missing item is fine.
    unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
}

/// Asks with the Windows credential prompt, so the token never passes through app UI text.
fn prompt_token(owner: HWND, lang: Language) -> Option<String> {
    let caption = wide(i18n::tr(lang, "radar.token_title"));
    let message = wide(i18n::tr(lang, "radar.token_body"));
    let target = wide(TARGET);
    let mut user = wide(ACCOUNT);
    user.resize(CREDUI_MAX_USERNAME_LENGTH as usize + 1, 0);
    let mut secret = vec![0u16; MAX_SECRET_LENGTH as usize + 1];
    // SAFETY: buffers are sized as declared and outlive the call; a zeroed info struct is valid.
    let result = unsafe {
        let mut info: CREDUI_INFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<CREDUI_INFOW>() as u32;
        info.hwndParent = owner;
        info.pszMessageText = message.as_ptr();
        info.pszCaptionText = caption.as_ptr();
        CredUIPromptForCredentialsW(
            &info,
            target.as_ptr(),
            std::ptr::null_mut(),
            0,
            user.as_mut_ptr(),
            CREDUI_MAX_USERNAME_LENGTH + 1,
            secret.as_mut_ptr(),
            MAX_SECRET_LENGTH + 1,
            std::ptr::null_mut(),
            CREDUI_FLAGS_GENERIC_CREDENTIALS
                | CREDUI_FLAGS_DO_NOT_PERSIST
                | CREDUI_FLAGS_ALWAYS_SHOW_UI
                | CREDUI_FLAGS_EXCLUDE_CERTIFICATES
                | CREDUI_FLAGS_KEEP_USERNAME,
        )
    };
    let end = secret.iter().position(|&c| c == 0).unwrap_or(secret.len());
    let token = String::from_utf16(&secret[..end]).ok();
    secret.fill(0);
    if result == 0 {
        token.map(|t| t.trim().to_owned())
    } else {
        None
    }
}

struct Handle(*mut core::ffi::c_void);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle came from WinHTTP and is closed once.
            unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

pub(crate) struct Reply {
    pub(crate) status: u16,
    retry_after_s: Option<u64>,
    quota_reset_s: Option<u64>,
    pub(crate) body: Vec<u8>,
}

fn header(request: &Handle, name: &str) -> Option<String> {
    let name = wide(name);
    let mut buffer = vec![0u16; 256];
    let mut size = (buffer.len() * 2) as u32;
    let mut index = 0u32;
    // SAFETY: the buffer and sizes describe the same allocation.
    let ok = unsafe {
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_CUSTOM,
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut size,
            &mut index,
        )
    };
    (ok != 0).then(|| String::from_utf16_lossy(&buffer[..size as usize / 2]))
}

fn fetch(token: &str) -> Option<Reply> {
    let headers = format!("Authorization: Bearer {token}\r\nAccept: application/json\r\n");
    https_get(
        radar_poll::HOST,
        radar_poll::PATH,
        &headers,
        radar::MAX_BYTES,
    )
}

/// HTTPS GET with redirects and cookies off. A failed option stops before anything is sent.
pub(crate) fn https_get(host: &str, path: &str, headers: &str, max_bytes: usize) -> Option<Reply> {
    let agent = wide("AtlasSOC/Windows");
    let host = wide(host);
    let path = wide(path);
    let verb = wide("GET");
    let headers = wide(headers);
    // SAFETY: strings outlive the calls; handles are closed by `Handle` in reverse order.
    unsafe {
        let session = Handle(WinHttpOpen(
            agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            std::ptr::null(),
            std::ptr::null(),
            0,
        ));
        if session.0.is_null() {
            return None;
        }
        WinHttpSetTimeouts(session.0, 20_000, 20_000, 20_000, 20_000);
        let connection = Handle(WinHttpConnect(session.0, host.as_ptr(), 443, 0));
        if connection.0.is_null() {
            return None;
        }
        let request = Handle(WinHttpOpenRequest(
            connection.0,
            verb.as_ptr(),
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        ));
        if request.0.is_null() {
            return None;
        }
        let never: u32 = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        let no_cookies: u32 = WINHTTP_DISABLE_COOKIES;
        // A token must never follow a redirect or sit in a cookie store, so a failed option stops here.
        if WinHttpSetOption(
            request.0,
            WINHTTP_OPTION_REDIRECT_POLICY,
            (&never as *const u32).cast(),
            4,
        ) == 0
            || WinHttpSetOption(
                request.0,
                WINHTTP_OPTION_DISABLE_FEATURE,
                (&no_cookies as *const u32).cast(),
                4,
            ) == 0
        {
            return None;
        }
        if WinHttpAddRequestHeaders(
            request.0,
            headers.as_ptr(),
            u32::MAX,
            WINHTTP_ADDREQ_FLAG_ADD,
        ) == 0
            || WinHttpSendRequest(request.0, std::ptr::null(), 0, std::ptr::null(), 0, 0, 0) == 0
            || WinHttpReceiveResponse(request.0, std::ptr::null_mut()) == 0
        {
            return None;
        }
        let mut status = 0u32;
        let mut size = 4u32;
        let mut index = 0u32;
        if WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            std::ptr::null(),
            (&mut status as *mut u32).cast(),
            &mut size,
            &mut index,
        ) == 0
        {
            return None;
        }
        let mut body = Vec::new();
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            let mut read = 0u32;
            if WinHttpReadData(
                request.0,
                chunk.as_mut_ptr().cast(),
                chunk.len() as u32,
                &mut read,
            ) == 0
            {
                return None;
            }
            if read == 0 {
                break;
            }
            if body.len() + read as usize > max_bytes {
                return None;
            }
            body.extend_from_slice(&chunk[..read as usize]);
        }
        Some(Reply {
            status: status as u16,
            retry_after_s: header(&request, "Retry-After").and_then(|v| v.trim().parse().ok()),
            quota_reset_s: header(&request, "Ratelimit")
                .and_then(|v| radar_poll::quota_reset_s(&v)),
            body,
        })
    }
}

#[derive(Default)]
struct Shared {
    data: Option<Arc<Aggregate>>,
    state: PollState,
    has_token: bool,
    fetching: bool,
    other_worker: bool,
}

enum Command {
    Wake,
}

/// One background worker. Created only after licence consent, and never by the offline smoke test.
pub struct Radar {
    shared: Arc<Mutex<Shared>>,
    state_path: PathBuf,
    wake: Sender<Command>,
}

fn save_state(path: &Path, state: &PollState) {
    if let Ok(text) = serde_json::to_vec(state) {
        let _ = write_atomic(path, &text);
    }
}

fn worker(directory: PathBuf, shared: Arc<Mutex<Shared>>, wake: mpsc::Receiver<Command>) {
    let _ = fs::create_dir_all(&directory);
    // Windows refuses a second open with no sharing, so only one worker can hold this file.
    let Ok(_lock) = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .share_mode(0)
        .open(directory.join("radar.lock"))
    else {
        shared.lock().unwrap().other_worker = true;
        return;
    };
    let state_path = directory.join("radar-state.json");
    let snapshot_path = directory.join("radar-snapshot.json");
    let mut state: PollState = fs::read(&state_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    state.sanitize(now_ms());
    let cached = fs::metadata(&snapshot_path)
        .ok()
        .filter(|m| m.len() <= radar::MAX_BYTES as u64)
        .and_then(|_| fs::read(&snapshot_path).ok())
        .and_then(|b| radar::parse(&b).ok());
    {
        let mut s = shared.lock().unwrap();
        s.data = cached.map(Arc::new);
        s.state = state;
    }
    loop {
        let token = read_token();
        let now = now_ms();
        let due = {
            let mut s = shared.lock().unwrap();
            s.has_token = token.is_some();
            let due = s.state.may_request(s.has_token, now);
            if due {
                s.state.begin(now);
                s.fetching = true;
                save_state(&state_path, &s.state);
            }
            due
        };
        if due {
            let reply = token.as_deref().and_then(fetch);
            let mut parsed = None;
            let response = match reply {
                None => Response::Failed,
                Some(r) if r.status == 200 => match radar::parse(&r.body) {
                    Ok(data) => {
                        let _ = write_atomic(&snapshot_path, &r.body);
                        parsed = Some(Arc::new(data));
                        Response::Data {
                            quota_reset_s: r.quota_reset_s,
                        }
                    }
                    Err(_) => Response::Failed,
                },
                Some(r) => Response::Status {
                    code: r.status,
                    retry_after_s: r.retry_after_s,
                },
            };
            let mut s = shared.lock().unwrap();
            s.state.finish(response, now_ms());
            if parsed.is_some() {
                s.data = parsed;
            }
            s.fetching = false;
            save_state(&state_path, &s.state);
        }
        match wake.recv_timeout(TICK) {
            Ok(Command::Wake) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

impl Radar {
    pub fn start(directory: PathBuf) -> Self {
        let shared = Arc::new(Mutex::new(Shared::default()));
        let (wake, receiver) = mpsc::channel();
        let state_path = directory.join("radar-state.json");
        let thread_shared = shared.clone();
        std::thread::spawn(move || worker(directory, thread_shared, receiver));
        Self {
            shared,
            state_path,
            wake,
        }
    }
    pub fn data(&self) -> (Option<Arc<Aggregate>>, u64) {
        let s = self.shared.lock().unwrap();
        (s.data.clone(), s.state.received_ms)
    }
    pub fn collecting(&self) -> bool {
        !self.shared.lock().unwrap().state.paused
    }
    pub fn note(&self) -> String {
        let s = self.shared.lock().unwrap();
        if s.other_worker {
            return "ANOTHER ATLASSOC WINDOW IS COLLECTING RADAR DATA".into();
        }
        if s.fetching {
            return "FETCHING RADAR DATA".into();
        }
        let now = now_ms();
        match s.state.status(s.has_token, s.data.is_some(), now) {
            Status::NeedsToken => "RIGHT-CLICK > SET CLOUDFLARE RADAR TOKEN".into(),
            Status::Refused => "TOKEN REFUSED: SET A NEW RADAR TOKEN".into(),
            Status::Paused => "RADAR PAUSED: RIGHT-CLICK TO RESUME".into(),
            Status::Stopped => "RADAR STOPPED BY A CLOUDFLARE ERROR".into(),
            Status::Waiting(next) => format!(
                "WAITING: NEXT REQUEST IN {} MIN",
                next.saturating_sub(now) / 60_000 + 1
            ),
            Status::Unavailable => "RADAR UNAVAILABLE: WILL RETRY".into(),
            Status::Current | Status::Stale => String::new(),
        }
    }
    fn update(&self, change: impl FnOnce(&mut PollState)) {
        let mut s = self.shared.lock().unwrap();
        change(&mut s.state);
        save_state(&self.state_path, &s.state);
        drop(s);
        let _ = self.wake.send(Command::Wake);
    }
    pub fn toggle_collecting(&self) {
        self.update(|state| {
            if state.paused {
                state.resume()
            } else {
                state.paused = true
            }
        });
    }
    pub fn set_token(&self, owner: HWND, lang: Language) {
        let Some(token) = prompt_token(owner, lang) else {
            return;
        };
        if !valid_token(&token) || !write_token(&token) {
            let text = wide(i18n::tr(lang, "radar.save_error"));
            let title = wide(i18n::tr(lang, "radar.token_title"));
            // SAFETY: both strings are NUL-terminated and outlive the call.
            unsafe { MessageBoxW(owner, text.as_ptr(), title.as_ptr(), MB_OK | MB_ICONWARNING) };
            return;
        }
        self.update(PollState::resume);
    }
    pub fn remove_token(&self) {
        delete_token();
        self.shared.lock().unwrap().has_token = false;
        let _ = self.wake.send(Command::Wake);
    }
}
