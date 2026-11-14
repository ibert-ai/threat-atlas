//! The OSINT worker lives in `threat_atlas_core::osint_worker` and is shared with macOS. Windows supplies
//! its own HTTPS client (WinHTTP, system proxy and trust store) through [`winhttp_fetch`].

use threat_atlas_core::osint_net::Reply;
pub use threat_atlas_core::osint_worker::*;

/// WinHTTP fetch for the shared worker.
pub fn winhttp_fetch(host: &str, path: &str, headers: &str, max_bytes: usize) -> Option<Reply> {
    crate::soc_radar::https_get_public(host, path, headers, max_bytes).map(|r| Reply {
        status: r.status,
        retry_after_s: r.retry_after_s,
        etag: r.etag,
        last_modified: r.last_modified,
        body: r.body,
    })
}
