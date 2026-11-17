//! SP3: the C interface a screensaver host uses to run the data worker next to `ta_saver_*` (session and frame).
//!
//! Order for a host: `ta_saver_new`, `ta_saver_worker_start`, then about once a second `ta_saver_set_intel(session,
//! ta_saver_worker_osint(worker))` and `ta_saver_frame`, about every 10 s `ta_saver_worker_reload`, and at the end
//! `ta_saver_worker_stop` then `ta_saver_drop`. All calls for one session and its worker come from one thread and
//! never overlap. Strings are NUL-terminated UTF-8. The old `ta_*` and `ta_osint_*` calls are unchanged.
use crate::{
    osint::Source,
    osint_ffi::OsintHandle,
    osint_net,
    osint_worker::Osint,
    saver_config::{Applier, KeyStore, SaverSettings},
};
use std::{
    ffi::{c_char, c_void, CStr},
    path::PathBuf,
};

/// Host callback that looks one API key up in the system credential store. It writes the key (UTF-8, no NUL) into
/// `out` (capacity `cap`) and returns its length, or 0 when there is no key. The core never logs it or writes it to
/// disk; it clears its scratch buffer after the call, but the resolved keys stay in worker memory until stop.
pub type KeyFn =
    unsafe extern "C" fn(id: *const c_char, out: *mut u8, cap: usize, user: *mut c_void) -> usize;

const KEY_CAP: usize = 1024;

struct CallbackKeys {
    f: Option<KeyFn>,
    user: *mut c_void,
}
impl KeyStore for CallbackKeys {
    fn key(&self, source: Source) -> Option<String> {
        let f = self.f?;
        let id = std::ffi::CString::new(crate::osint::source_spec(source).id).ok()?;
        let mut buf = vec![0u8; KEY_CAP];
        // SAFETY: the host promised `f` and `user` stay valid until `ta_saver_worker_stop`.
        let n = unsafe { f(id.as_ptr(), buf.as_mut_ptr(), KEY_CAP, self.user) };
        let key = (n > 0 && n <= KEY_CAP)
            .then(|| String::from_utf8(buf[..n].to_vec()).ok())
            .flatten();
        buf.fill(0);
        key
    }
}

/// The OSINT worker of a screensaver host plus the settings it follows. Rust hosts (Windows) use this directly;
/// C hosts go through the `ta_saver_worker_*` functions.
pub struct SaverWorker {
    handle: OsintHandle,
    settings_path: PathBuf,
    keys: Box<dyn KeyStore>,
    applier: Applier,
}
impl SaverWorker {
    /// Starts with everything OFF and reads the settings file once. `fetch` and `post` are the host's HTTPS
    /// functions (WinHTTP on Windows); `None` uses the core's own client.
    pub fn start(
        data_dir: PathBuf,
        settings_path: PathBuf,
        keys: Box<dyn KeyStore>,
        fetch: Option<osint_net::Fetch>,
    ) -> Self {
        if fetch.is_none() {
            crate::osint_worker::set_post(osint_net::https_post);
        }
        let osint = Osint::start(data_dir, Vec::new(), fetch.unwrap_or(osint_net::https_get));
        let mut worker = Self {
            handle: OsintHandle::new(osint),
            settings_path,
            keys,
            applier: Applier::default(),
        };
        worker.reload();
        worker
    }
    /// Re-reads the settings file and the keys; applies only what changed.
    pub fn reload(&mut self) {
        let settings = SaverSettings::load(&self.settings_path);
        self.applier
            .apply(self.handle.osint(), settings, self.keys.as_ref());
    }
    pub fn osint(&self) -> &Osint {
        self.handle.osint()
    }
}

unsafe fn text<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        None
    } else {
        CStr::from_ptr(ptr).to_str().ok()
    }
}

/// Starts the worker with everything OFF, then reads the settings file once. `data_dir` holds the caches,
/// `settings_path` is AtlasSOC's `settings.json` (read only). `key_fn` may be null (no keys). Returns null on bad
/// input. The worker makes no request until the settings turn a source on.
/// # Safety
/// Both strings valid and NUL-terminated; `key_fn` and `user` stay valid until `ta_saver_worker_stop`.
#[no_mangle]
pub unsafe extern "C" fn ta_saver_worker_start(
    data_dir: *const c_char,
    settings_path: *const c_char,
    key_fn: Option<KeyFn>,
    user: *mut c_void,
) -> *mut SaverWorker {
    let (Some(dir), Some(path)) = (text(data_dir), text(settings_path)) else {
        return std::ptr::null_mut();
    };
    let (dir, path) = (PathBuf::from(dir), PathBuf::from(path));
    std::panic::catch_unwind(move || {
        let keys = Box::new(CallbackKeys { f: key_fn, user });
        Box::into_raw(Box::new(SaverWorker::start(dir, path, keys, None)))
    })
    .unwrap_or(std::ptr::null_mut())
}

/// Re-reads the settings file and the keys and applies any change. Cheap when nothing changed; call about every
/// 10 seconds so a change in AtlasSOC Settings reaches a running saver.
/// # Safety
/// `worker` must be null or a live pointer from `ta_saver_worker_start`.
#[no_mangle]
pub unsafe extern "C" fn ta_saver_worker_reload(worker: *mut SaverWorker) {
    if let Some(w) = worker.as_mut() {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| w.reload()));
    }
}

/// The worker's OSINT handle, for `ta_saver_set_intel`. Borrowed: valid until `ta_saver_worker_stop`, never free it.
/// # Safety
/// `worker` must be null or a live pointer from `ta_saver_worker_start`.
#[no_mangle]
pub unsafe extern "C" fn ta_saver_worker_osint(worker: *mut SaverWorker) -> *mut OsintHandle {
    match worker.as_mut() {
        Some(w) => &mut w.handle as *mut OsintHandle,
        None => std::ptr::null_mut(),
    }
}

/// Stops the worker and releases it. Call after the last `ta_saver_set_intel` and before dropping the session.
/// # Safety
/// `worker` must be null or a pointer from `ta_saver_worker_start`, stopped exactly once.
#[no_mangle]
pub unsafe extern "C" fn ta_saver_worker_stop(worker: *mut SaverWorker) {
    if !worker.is_null() {
        drop(Box::from_raw(worker));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    unsafe extern "C" fn no_key(
        _id: *const c_char,
        _out: *mut u8,
        _cap: usize,
        _user: *mut c_void,
    ) -> usize {
        0
    }

    #[test]
    fn missing_settings_start_with_everything_off_and_stop_cleanly() {
        let dir = CString::new(
            std::env::temp_dir()
                .join("atlas-saver-ffi")
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let missing = CString::new("/nonexistent/atlas/settings.json").unwrap();
        unsafe {
            let w = ta_saver_worker_start(
                dir.as_ptr(),
                missing.as_ptr(),
                Some(no_key),
                std::ptr::null_mut(),
            );
            assert!(!w.is_null());
            assert!(!ta_saver_worker_osint(w).is_null());
            ta_saver_worker_reload(w);
            ta_saver_worker_stop(w);
        }
    }

    #[test]
    fn null_inputs_are_refused_or_ignored() {
        unsafe {
            assert!(ta_saver_worker_start(
                std::ptr::null(),
                std::ptr::null(),
                None,
                std::ptr::null_mut()
            )
            .is_null());
            assert!(ta_saver_worker_osint(std::ptr::null_mut()).is_null());
            ta_saver_worker_reload(std::ptr::null_mut());
            ta_saver_worker_stop(std::ptr::null_mut());
        }
    }

    #[test]
    fn the_header_declares_every_exported_saver_function() {
        let header = include_str!("../include/threat_atlas_saver.h");
        let source = [include_str!("saver.rs"), include_str!("saver_ffi.rs")].concat();
        let mut found = 0;
        for line in source.lines() {
            if let Some(rest) = line.split("extern \"C\" fn ").nth(1) {
                let name = rest.split('(').next().unwrap().trim();
                if name.starts_with("ta_saver_") {
                    assert!(header.contains(name), "header misses {name}");
                    found += 1;
                }
            }
        }
        assert!(found >= 9, "only {found} functions found");
    }
}
