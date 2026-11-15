//! Small HTTPS GET client for the OSINT worker on hosts without their own (macOS, Linux).
//!
//! HTTP/1.1 over rustls with the bundled web roots, `Connection: close`, identity encoding, bounded body,
//! a handful of redirects, and a refusal to connect to non-public addresses. The Windows host passes its
//! WinHTTP client instead; both give the worker the same [`Reply`].

use std::{
    io::{Read, Write},
    net::{IpAddr, TcpStream, ToSocketAddrs},
    sync::Arc,
    time::{Duration, Instant},
};

/// One answer. Redirects are already followed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub retry_after_s: Option<u64>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub body: Vec<u8>,
}

/// The shape of a fetch function, so a host can supply its own.
pub type Fetch = fn(host: &str, path: &str, headers: &str, max_bytes: usize) -> Option<Reply>;

const MAX_HEAD: usize = 32 * 1024;
const MAX_REDIRECTS: usize = 3;
const OVERALL: Duration = Duration::from_secs(60);

pub(crate) struct Head {
    pub status: u16,
    pub content_length: Option<usize>,
    pub chunked: bool,
    pub location: Option<String>,
    pub retry_after_s: Option<u64>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

/// Parses the status line and headers (everything before the blank line).
pub(crate) fn parse_head(head: &str) -> Option<Head> {
    let mut lines = head.split("\r\n");
    let status_line = lines.next()?;
    let mut parts = status_line.splitn(3, ' ');
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let status: u16 = parts.next()?.trim().parse().ok()?;
    let mut out = Head {
        status,
        content_length: None,
        chunked: false,
        location: None,
        retry_after_s: None,
        etag: None,
        last_modified: None,
    };
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => out.content_length = value.parse().ok(),
            "transfer-encoding" => out.chunked = value.to_ascii_lowercase().contains("chunked"),
            "location" => out.location = Some(value.to_owned()),
            "retry-after" => out.retry_after_s = value.parse().ok(),
            "etag" => out.etag = Some(value.to_owned()),
            "last-modified" => out.last_modified = Some(value.to_owned()),
            _ => {}
        }
    }
    Some(out)
}

/// Decodes a complete chunked body. `None` when malformed or larger than `max`.
pub(crate) fn dechunk(raw: &[u8], max: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let line_end = raw[i..].windows(2).position(|w| w == b"\r\n")? + i;
        let size_text = std::str::from_utf8(&raw[i..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        i = line_end + 2;
        if size == 0 {
            return Some(out);
        }
        if out.len().checked_add(size)? > max || i.checked_add(size)?.checked_add(2)? > raw.len() {
            return None;
        }
        out.extend_from_slice(&raw[i..i + size]);
        i += size;
        if &raw[i..i + 2] != b"\r\n" {
            return None;
        }
        i += 2;
    }
}

/// Splits a redirect target into (host, path). Only `https://` and absolute paths are followed.
pub(crate) fn redirect_target(
    location: &str,
    current_host: &str,
    current_path: &str,
) -> Option<(String, String)> {
    if let Some(rest) = location.strip_prefix("https://") {
        let (host, path) = rest
            .split_once('/')
            .map_or((rest, "/".to_owned()), |(h, p)| (h, format!("/{p}")));
        (!host.is_empty() && !host.contains(['@', ':'])).then(|| (host.to_ascii_lowercase(), path))
    } else if location.starts_with('/') && !location.starts_with("//") {
        Some((current_host.to_owned(), location.to_owned()))
    } else if !location.is_empty()
        && !location.contains([':', '\\', ' ', '\r', '\n'])
        && !location.starts_with(['/', '.', '?', '#'])
    {
        // A relative file name: same directory as the current path.
        let dir = current_path.split(['?', '#']).next().unwrap_or("/");
        let dir = &dir[..dir.rfind('/').map_or(0, |i| i + 1)];
        Some((current_host.to_owned(), format!("{dir}{location}")))
    } else {
        None
    }
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn connect(host: &str) -> Option<TcpStream> {
    let addresses: Vec<_> = (host, 443).to_socket_addrs().ok()?.take(4).collect();
    // Never connect to a private or reserved address, whatever the name resolves to.
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|a| !crate::osint_internetdb::is_lookup_allowed(a.ip()))
    {
        return None;
    }
    let stream = addresses
        .iter()
        .find_map(|a| TcpStream::connect_timeout(a, Duration::from_secs(8)).ok())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    Some(stream)
}

fn get_once(
    host: &str,
    path: &str,
    headers: &str,
    max_bytes: usize,
    deadline: Instant,
    post_body: Option<&[u8]>,
) -> Option<(Head, Vec<u8>)> {
    if host.is_empty()
        || host.parse::<IpAddr>().is_ok()
        || !path.starts_with('/')
        || path.contains(['\r', '\n', ' '])
    {
        return None;
    }
    if headers.contains("\r\n\r\n") {
        return None;
    }
    let name = rustls::pki_types::ServerName::try_from(host.to_owned()).ok()?;
    let conn = rustls::ClientConnection::new(tls_config(), name).ok()?;
    let mut tls = rustls::StreamOwned::new(conn, connect(host)?);
    let (method, length) = match post_body {
        Some(body) => ("POST", format!("Content-Length: {}\r\n", body.len())),
        None => ("GET", String::new()),
    };
    let request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept-Encoding: identity\r\nConnection: close\r\n{length}{headers}\r\n");
    tls.write_all(request.as_bytes()).ok()?;
    if let Some(body) = post_body {
        tls.write_all(body).ok()?;
    }
    let mut raw = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    let mut head: Option<(Head, usize)> = None;
    // Hard stop: header plus body, with the body bound plus chunk framing slack.
    let limit = max_bytes
        .saturating_add(MAX_HEAD)
        .saturating_add(max_bytes / 8 + 4096);
    loop {
        if Instant::now() > deadline {
            return None;
        }
        let n = match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            // Servers that close without a TLS close_notify still delivered what they sent.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(_) => return None,
        };
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > limit {
            return None;
        }
        if head.is_none() {
            if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                if end > MAX_HEAD {
                    return None;
                }
                let parsed = parse_head(std::str::from_utf8(&raw[..end]).ok()?)?;
                head = Some((parsed, end + 4));
            } else if raw.len() > MAX_HEAD {
                return None;
            }
        }
    }
    let (head, body_at) = head?;
    let body_raw = &raw[body_at..];
    let body = if head.chunked {
        dechunk(body_raw, max_bytes)?
    } else {
        if head.content_length.is_some_and(|l| l > max_bytes) || body_raw.len() > max_bytes {
            return None;
        }
        if head.content_length.is_some_and(|l| body_raw.len() < l) {
            return None;
        }
        body_raw.to_vec()
    };
    Some((head, body))
}

/// HTTPS POST of a small body (for example JSON), no redirects, bounded answer and time limit. A redirect
/// answer is returned as it is and never followed, so a body is never re-sent to another place.
pub fn https_post(
    host: &str,
    path: &str,
    headers: &str,
    body: &[u8],
    max_bytes: usize,
) -> Option<Reply> {
    if body.len() > 64 * 1024 {
        return None;
    }
    let deadline = Instant::now() + OVERALL;
    let (head, answer) = get_once(
        &host.to_ascii_lowercase(),
        path,
        headers,
        max_bytes,
        deadline,
        Some(body),
    )?;
    Some(Reply {
        status: head.status,
        retry_after_s: head.retry_after_s,
        etag: head.etag,
        last_modified: head.last_modified,
        body: answer,
    })
}

/// HTTPS GET with redirects (https only, at most three), bounded body and an overall time limit.
pub fn https_get(host: &str, path: &str, headers: &str, max_bytes: usize) -> Option<Reply> {
    let deadline = Instant::now() + OVERALL;
    let (mut host, mut path) = (host.to_ascii_lowercase(), path.to_owned());
    for _ in 0..=MAX_REDIRECTS {
        let (head, body) = get_once(&host, &path, headers, max_bytes, deadline, None)?;
        if (301..=308).contains(&head.status) && head.status != 304 {
            let (next_host, next_path) = redirect_target(head.location.as_deref()?, &host, &path)?;
            host = next_host;
            path = next_path;
            continue;
        }
        return Some(Reply {
            status: head.status,
            retry_after_s: head.retry_after_s,
            etag: head.etag,
            last_modified: head.last_modified,
            body,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_is_parsed() {
        let h = parse_head("HTTP/1.1 200 OK\r\nContent-Length: 12\r\nETag: \"abc\"\r\nRetry-After: 30\r\nX-Other: 1").unwrap();
        assert_eq!(
            (h.status, h.content_length, h.chunked),
            (200, Some(12), false)
        );
        assert_eq!(h.etag.as_deref(), Some("\"abc\""));
        assert_eq!(h.retry_after_s, Some(30));
        assert!(parse_head("garbage").is_none());
        assert!(parse_head("HTTP/1.1 abc OK").is_none());
        assert!(
            parse_head("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked")
                .unwrap()
                .chunked
        );
    }

    #[test]
    fn chunked_bodies_are_decoded_and_bounded() {
        assert_eq!(
            dechunk(b"5\r\nhello\r\n6;x=1\r\n world\r\n0\r\n\r\n", 100).unwrap(),
            b"hello world"
        );
        assert!(
            dechunk(b"5\r\nhello\r\n0\r\n\r\n", 4).is_none(),
            "over the limit"
        );
        assert!(dechunk(b"zz\r\nhello\r\n", 100).is_none(), "bad size");
        assert!(dechunk(b"5\r\nhel", 100).is_none(), "truncated");
        assert!(dechunk(b"ffffffffffffffff\r\n", 100).is_none(), "huge size");
        assert!(dechunk(b"", 100).is_none());
    }

    #[test]
    fn redirects_stay_on_https() {
        assert_eq!(
            redirect_target("https://B.example/x?y=1", "a.example", "/"),
            Some(("b.example".into(), "/x?y=1".into()))
        );
        assert_eq!(
            redirect_target("/new", "a.example", "/"),
            Some(("a.example".into(), "/new".into()))
        );
        assert_eq!(
            redirect_target("http://evil.example/", "a.example", "/"),
            None
        );
        assert_eq!(redirect_target("//evil.example/", "a.example", "/"), None);
        assert_eq!(
            redirect_target("https://user@evil.example/", "a.example", "/"),
            None
        );
        assert_eq!(
            redirect_target("https://127.0.0.1:8443/", "a.example", "/"),
            None
        );
    }

    #[test]
    fn relative_redirects_stay_in_the_directory() {
        assert_eq!(
            redirect_target("f.gz", "a.example", "/d/x.gz"),
            Some(("a.example".into(), "/d/f.gz".into()))
        );
        assert_eq!(
            redirect_target("f.gz", "a.example", "/x.gz?y=1"),
            Some(("a.example".into(), "/f.gz".into()))
        );
        assert_eq!(redirect_target("../up", "a.example", "/d/x"), None);
        assert_eq!(
            redirect_target("javascript:alert(1)", "a.example", "/"),
            None
        );
    }

    #[test]
    fn requests_to_ip_literals_and_bad_paths_are_refused() {
        let far = Instant::now() + Duration::from_secs(1);
        assert!(get_once("127.0.0.1", "/", "", 10, far, None).is_none());
        assert!(get_once("example.com", "no-slash", "", 10, far, None).is_none());
        assert!(get_once("example.com", "/a b", "", 10, far, None).is_none());
        assert!(get_once("example.com", "/", "X: 1\r\n\r\nGET /evil", 10, far, None).is_none());
    }

    /// Deterministic fuzzing: random and mutated input must never panic and never exceed the body limit.
    #[test]
    fn parsers_survive_random_and_mutated_input() {
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let seeds: [&[u8]; 3] = [
            b"5\r\nhello\r\n6;x=1\r\n world\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nETag: \"a\"\r\nTransfer-Encoding: chunked",
            b"ffffffff\r\n",
        ];
        for round in 0..20_000 {
            let mut data: Vec<u8> = if round % 2 == 0 {
                (0..(next() % 200)).map(|_| next() as u8).collect()
            } else {
                seeds[(next() % 3) as usize].to_vec()
            };
            for _ in 0..(next() % 4) {
                if !data.is_empty() {
                    let i = (next() as usize) % data.len();
                    data[i] = next() as u8;
                }
            }
            if let Some(body) = dechunk(&data, 64) {
                assert!(body.len() <= 64);
            }
            if let Ok(text) = std::str::from_utf8(&data) {
                let _ = parse_head(text);
                let _ = redirect_target(text, "a.example", "/d/x");
            }
        }
    }
}
