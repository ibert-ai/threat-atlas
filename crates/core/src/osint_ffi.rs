//! C interface to the shared OSINT worker for the macOS app (Swift). Strings are NUL-terminated UTF-8.
//! Keys are not handled here yet: a source that needs one is not listed as live.

use crate::{
    feed::now_ms,
    osint::{self, Source},
    osint_net, osint_text,
    osint_worker::Osint,
};
use std::{
    ffi::{c_char, CStr},
    path::PathBuf,
};

/// Sources with a working integration in this build, in menu order.
pub const LIVE_SOURCES: [Source; 13] = [
    Source::CisaKev,
    Source::TorExit,
    Source::SansIsc,
    Source::RansomwareLive,
    Source::ShodanInternetDb,
    Source::SpamhausDrop,
    Source::PhishTank,
    Source::Sslbl,
    Source::Otx,
    Source::Urlhaus,
    Source::ThreatFox,
    Source::AbuseIpdb,
    Source::CertStream,
];

pub struct OsintHandle {
    osint: Osint,
}

impl OsintHandle {
    pub(crate) fn new(osint: Osint) -> Self {
        Self { osint }
    }
    pub(crate) fn osint(&self) -> &Osint {
        &self.osint
    }
}

unsafe fn text<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok()
}

fn ids(json: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(json).unwrap_or_default()
}

/// Copies `s` into `out` (at most `cap` bytes, no NUL) and returns the full length of `s`.
unsafe fn copy_out(s: &str, out: *mut u8, cap: usize) -> usize {
    if !out.is_null() {
        let n = s.len().min(cap);
        std::ptr::copy_nonoverlapping(s.as_ptr(), out, n);
    }
    s.len()
}

/// Gives one source its API key (memory only), or removes it when `key` is null or empty. The host
/// reads the key from the system credential store; it is never logged, stored or shown by the core.
/// # Safety
/// `handle` must come from `ta_osint_start`; `id` and `key` must be valid NUL-terminated strings or null.
#[no_mangle]
pub unsafe extern "C" fn ta_osint_set_key(
    handle: *mut OsintHandle,
    id: *const c_char,
    key: *const c_char,
) -> i32 {
    let (Some(h), Some(id)) = (handle.as_ref(), text(id)) else {
        return 0;
    };
    let Some(source) = LIVE_SOURCES
        .iter()
        .find(|s| osint::source_spec(**s).id == id && osint::source_spec(**s).requires_key)
    else {
        return 0;
    };
    h.osint.set_key(*source, text(key).map(str::to_owned));
    1
}

/// Starts the worker. `enabled_json` is a JSON array of source ids; only those make requests.
/// # Safety
/// `directory` and `enabled_json` must be valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn ta_osint_start(
    directory: *const c_char,
    enabled_json: *const c_char,
) -> *mut OsintHandle {
    let (Some(dir), Some(json)) = (text(directory), text(enabled_json)) else {
        return std::ptr::null_mut();
    };
    std::panic::catch_unwind(|| {
        Box::into_raw(Box::new(OsintHandle {
            osint: {
                crate::osint_worker::set_post(osint_net::https_post);
                Osint::start(PathBuf::from(dir), ids(json), osint_net::https_get)
            },
        }))
    })
    .unwrap_or(std::ptr::null_mut())
}

/// # Safety
/// `handle` must be a live pointer from `ta_osint_start`; `enabled_json` a valid string.
#[no_mangle]
pub unsafe extern "C" fn ta_osint_set_enabled(
    handle: *mut OsintHandle,
    enabled_json: *const c_char,
) {
    if let (Some(h), Some(json)) = (handle.as_ref(), text(enabled_json)) {
        h.osint.set_enabled(ids(json));
    }
}

/// # Safety
/// `handle` must be a live pointer from `ta_osint_start`.
#[no_mangle]
pub unsafe extern "C" fn ta_osint_refresh(handle: *mut OsintHandle) {
    if let Some(h) = handle.as_ref() {
        h.osint.refresh();
    }
}

/// Queues an InternetDB lookup. Returns 0 when queued, -1 when refused (not a public address, source off,
/// bad input). The caller must have asked the user first.
/// # Safety
/// `handle` must be a live pointer from `ta_osint_start`; `ip` a valid string.
#[no_mangle]
pub unsafe extern "C" fn ta_osint_lookup(handle: *mut OsintHandle, ip: *const c_char) -> i32 {
    let (Some(h), Some(ip)) = (handle.as_ref(), text(ip)) else {
        return -1;
    };
    match crate::osint_internetdb::parse_ip_text(ip) {
        Some(ip) if crate::osint_internetdb::is_lookup_allowed(ip) => {
            h.osint.lookup(ip);
            0
        }
        _ => -1,
    }
}

/// Replaces the certificate watch list from a JSON array of domains (at most 10 are kept). Returns how many
/// were accepted.
/// # Safety
/// `handle` must be a live pointer; `json` a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn ta_osint_set_watch(handle: *mut OsintHandle, json: *const c_char) -> i32 {
    let (Some(h), Some(json)) = (handle.as_ref(), text(json)) else {
        return -1;
    };
    h.osint.set_watch(ids(json)) as i32
}

/// Queues one AbuseIPDB check for the address in `ip`. Returns 0 when queued, -1 when refused (not a
/// public address, source off). The host asks the user to confirm first.
/// # Safety
/// `handle` must be a live pointer; `ip` a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn ta_osint_lookup_abuse(handle: *mut OsintHandle, ip: *const c_char) -> i32 {
    let (Some(h), Some(ip)) = (handle.as_ref(), text(ip)) else {
        return -1;
    };
    match crate::osint_internetdb::parse_ip_text(ip) {
        Some(ip) if crate::osint_abuseipdb::is_lookup_allowed(ip) => {
            h.osint.lookup_abuse(ip);
            0
        }
        _ => -1,
    }
}

/// Writes the text page of one source into `out` and returns its full length in bytes.
/// # Safety
/// `handle` must be a live pointer; strings valid; `out` writable for `cap` bytes (or null).
#[no_mangle]
pub unsafe extern "C" fn ta_osint_page(
    handle: *mut OsintHandle,
    source_id: *const c_char,
    clipboard: *const c_char,
    out: *mut u8,
    cap: usize,
) -> usize {
    let (Some(h), Some(id)) = (handle.as_ref(), text(source_id)) else {
        return 0;
    };
    let Some(source) = LIVE_SOURCES
        .iter()
        .find(|s| osint::source_spec(**s).id == id)
    else {
        return 0;
    };
    let clip = text(clipboard).unwrap_or("");
    copy_out(
        &osint_text::page(*source, &h.osint.view(), clip, now_ms()),
        out,
        cap,
    )
}

/// One status line for a source (what has arrived and when). Returns the full length in bytes.
/// # Safety
/// `handle` must be a live pointer; `source_id` a valid string; `out` writable for `cap` bytes or null.
#[no_mangle]
pub unsafe extern "C" fn ta_osint_status(
    handle: *mut OsintHandle,
    source_id: *const c_char,
    out: *mut u8,
    cap: usize,
) -> usize {
    let (Some(h), Some(id)) = (handle.as_ref(), text(source_id)) else {
        return 0;
    };
    let Some(source) = LIVE_SOURCES
        .iter()
        .find(|s| osint::source_spec(**s).id == id)
    else {
        return 0;
    };
    copy_out(
        &osint_text::status(*source, &h.osint.view(), now_ms()),
        out,
        cap,
    )
}

/// JSON array describing the live sources: id, name, licence, attribution, min_minutes, requires_key,
/// default_on. Returns the full length in bytes.
/// # Safety
/// `out` must be writable for `cap` bytes, or null to ask for the length.
#[no_mangle]
pub unsafe extern "C" fn ta_osint_sources(out: *mut u8, cap: usize) -> usize {
    let list: Vec<serde_json::Value> = LIVE_SOURCES
        .iter()
        .map(|s| {
            let spec = osint::source_spec(*s);
            serde_json::json!({
                "id": spec.id,
                "name": spec.name,
                "licence": spec.licence,
                "attribution": spec.attribution,
                "min_minutes": spec.min_interval_ms / 60_000,
                "requires_key": spec.requires_key,
                "default_on": osint::default_enabled(*s),
                "what": osint_text::what(*s),
                "clipboard": matches!(s, Source::ShodanInternetDb | Source::SpamhausDrop | Source::PhishTank | Source::AbuseIpdb),
            })
        })
        .collect();
    copy_out(&serde_json::Value::Array(list).to_string(), out, cap)
}

/// # Safety
/// `handle` must be null or a live pointer from `ta_osint_start`; it must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn ta_osint_drop(handle: *mut OsintHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_list_is_valid_json_and_matches_the_registry() {
        let len = unsafe { ta_osint_sources(std::ptr::null_mut(), 0) };
        let mut buf = vec![0u8; len];
        assert_eq!(unsafe { ta_osint_sources(buf.as_mut_ptr(), len) }, len);
        let value: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(value.as_array().unwrap().len(), LIVE_SOURCES.len());
        // Only a keyed source may need a key, and the list must say so for the Settings screens.
        for (source, entry) in LIVE_SOURCES.iter().zip(value.as_array().unwrap()) {
            assert_eq!(
                entry["requires_key"].as_bool(),
                Some(osint::source_spec(*source).requires_key)
            );
        }
        assert!(LIVE_SOURCES
            .iter()
            .filter(|s| osint::source_spec(**s).requires_key)
            .all(|s| matches!(
                *s,
                Source::Otx
                    | Source::Urlhaus
                    | Source::ThreatFox
                    | Source::AbuseIpdb
                    | Source::CertStream
            )));
    }

    #[test]
    fn lookup_and_page_refuse_bad_input() {
        assert_eq!(
            unsafe { ta_osint_lookup(std::ptr::null_mut(), std::ptr::null()) },
            -1
        );
        assert_eq!(
            unsafe {
                ta_osint_page(
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    0,
                )
            },
            0
        );
    }
}
