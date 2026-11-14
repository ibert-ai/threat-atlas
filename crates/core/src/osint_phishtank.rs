//! ATLAS-OSINT-013 - phishing domain list (Phishing.Database).
//!
//! Replaces PhishTank, which no longer takes registrations (see `docs/OSINT-PHISHTANK-RESEARCH.md`). The
//! owner approved this change on 14 November 2026. The host downloads the community `phishing-domains-ACTIVE`
//! list (MIT licence) once a day and matches domains locally. Pure functions only: a bounded parser that
//! keeps 64-bit hashes of domains, host matching, a stale-feed rule and defanging. No network, clock or file
//! system here. See `docs/OSINT-TERMS-PHISHINGDB.md`.
//!
//! Proposed registry values: name "Phishing.Database", no key, MIT licence, minimum interval 24 hours,
//! attribution "Phishing.Database (MIT licence)" with link <https://github.com/Phishing-Database/Phishing.Database>.
//!
//! Rules for the host: download at most once per 24 hours (conditional on the ETag when the host allows),
//! stop using the list when it has not changed for 7 days, never fetch a listed domain, show listed names
//! defanged, and describe a hit as "on the community phishing list", not as proof.

use std::collections::HashSet;
use std::net::IpAddr;

/// Host for the download.
pub const HOST: &str = "raw.githubusercontent.com";
/// Path of the domains list on that host (about 11 MB on 14 Nov 2026).
pub const LIST_PATH: &str = "/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt";
/// Largest body accepted.
pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Most domains kept (the list held about 0.5 million on 14 Nov 2026).
pub const MAX_DOMAINS: usize = 1_000_000;
/// Download at most this often: 24 hours.
pub const REFRESH_INTERVAL_MS: u64 = 24 * 60 * 60 * 1000;
/// Stop using a list that has not changed for 7 days.
pub const STALE_AFTER_MS: u64 = 7 * 24 * 60 * 60 * 1000;

// A refresh must happen well inside the stale window.
const _: () = assert!(REFRESH_INTERVAL_MS * 2 < STALE_AFTER_MS);

/// Hosting services where a listed parent does not mean every subdomain is bad. A listed name under one of
/// these matches exactly only.
const SHARED_HOSTS: &[&str] = &[
    "000webhostapp.com",
    "blogspot.com",
    "firebaseapp.com",
    "github.io",
    "herokuapp.com",
    "netlify.app",
    "pages.dev",
    "vercel.app",
    "web.app",
    "weebly.com",
    "wixsite.com",
];

/// Why a downloaded body was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListError {
    TooLarge,
    /// Not a list of domains (an HTML error page, or nothing usable).
    NotAList,
    TooManyEntries,
}

fn fnv1a64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn valid_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Normalise a host name for matching: trimmed, lower case, one trailing dot removed, ASCII letters, digits
/// and hyphens, at least two labels, not an IP address. `None` for anything else.
pub fn normalise_host(input: &str) -> Option<String> {
    let s = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 || s.parse::<IpAddr>().is_ok() {
        return None;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 || !labels.iter().all(|l| valid_label(l)) {
        return None;
    }
    if labels.last()?.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(s)
}

fn is_shared_host(name: &str) -> bool {
    SHARED_HOSTS.contains(&name)
}

/// The listed domains, as 64-bit hashes (about 8 bytes each instead of a string).
#[derive(Clone, Debug, Default)]
pub struct DomainSet {
    hashes: HashSet<u64>,
    /// Lines that were not comments but could not be used.
    pub skipped: usize,
}

impl DomainSet {
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Is this exact name listed?
    pub fn contains(&self, host: &str) -> bool {
        normalise_host(host).is_some_and(|h| self.hashes.contains(&fnv1a64(&h)))
    }

    /// The listed name that matches `host`: the host itself, or a listed parent with at least two labels.
    /// A parent that is a shared hosting service does not match its subdomains. `None` when nothing matches.
    pub fn lookup(&self, host: &str) -> Option<String> {
        let h = normalise_host(host)?;
        if self.hashes.contains(&fnv1a64(&h)) {
            return Some(h);
        }
        let mut rest = h.as_str();
        while let Some(i) = rest.find('.') {
            rest = &rest[i + 1..];
            if !rest.contains('.') {
                break;
            }
            if self.hashes.contains(&fnv1a64(rest)) && !is_shared_host(rest) {
                return Some(rest.to_string());
            }
        }
        None
    }
}

/// Parse the downloaded list: one domain per line, `#` comment lines allowed. Unusable lines are counted
/// and skipped. An HTML page or a body with no usable line is rejected.
pub fn parse_list(body: &[u8]) -> Result<DomainSet, ListError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(ListError::TooLarge);
    }
    let text = String::from_utf8_lossy(body);
    let mut set = DomainSet::default();
    let mut first = true;
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if first && t.starts_with('<') {
            return Err(ListError::NotAList);
        }
        first = false;
        match normalise_host(t) {
            Some(h) => {
                set.hashes.insert(fnv1a64(&h));
                if set.hashes.len() > MAX_DOMAINS {
                    return Err(ListError::TooManyEntries);
                }
            }
            None => set.skipped += 1,
        }
    }
    if set.is_empty() {
        return Err(ListError::NotAList);
    }
    Ok(set)
}

/// A short fingerprint of a body, for hosts that cannot read an ETag: the length and a 64-bit hash.
pub fn body_fingerprint(body: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in body {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{}-{h:016x}", body.len())
}

/// How usable the list is right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedStatus {
    /// Never downloaded.
    Missing,
    Fresh,
    /// Unchanged for 7 days or more: do not use it, tell the user.
    Stale,
}

/// What the host remembers about the list between downloads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeedState {
    fingerprint: Option<String>,
    changed_at_ms: u64,
    fetched_at_ms: Option<u64>,
}

impl FeedState {
    /// Record a successful download. `fingerprint` is the ETag or `body_fingerprint`. The change time moves
    /// only when the fingerprint differs from the last one, so a frozen feed grows stale.
    pub fn observe(&mut self, fingerprint: &str, now_ms: u64) {
        if self.fingerprint.as_deref() != Some(fingerprint) {
            self.fingerprint = Some(fingerprint.to_string());
            self.changed_at_ms = now_ms;
        }
        self.fetched_at_ms = Some(now_ms);
    }

    /// Time for the next download? A clock that moved backwards counts as due.
    pub fn refresh_due(&self, now_ms: u64) -> bool {
        match self.fetched_at_ms {
            None => true,
            Some(t) => now_ms < t || now_ms - t >= REFRESH_INTERVAL_MS,
        }
    }

    pub fn status(&self, now_ms: u64) -> FeedStatus {
        match self.fetched_at_ms {
            None => FeedStatus::Missing,
            Some(_) if now_ms.saturating_sub(self.changed_at_ms) >= STALE_AFTER_MS => {
                FeedStatus::Stale
            }
            Some(_) => FeedStatus::Fresh,
        }
    }
}

/// Show a host name so it cannot be clicked or resolved by accident: each dot becomes `[.]`.
pub fn defang(host: &str) -> String {
    host.replace('.', "[.]")
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = include_str!("../tests/fixtures/osint/phishingdb/domains-ok.txt");
    const MESSY: &str = include_str!("../tests/fixtures/osint/phishingdb/domains-messy.txt");
    const HTML: &str = include_str!("../tests/fixtures/osint/phishingdb/html-instead-of-list.txt");

    #[test]
    fn parses_the_list_and_lowercases() {
        let set = parse_list(OK.as_bytes()).unwrap();
        assert_eq!(set.len(), 6);
        assert_eq!(set.skipped, 0);
        assert!(set.contains("secure-bank.example"));
        assert!(set.contains("SECURE-BANK.EXAMPLE."));
    }

    #[test]
    fn messy_lines_are_skipped_and_counted() {
        let set = parse_list(MESSY.as_bytes()).unwrap();
        assert_eq!(set.len(), 4);
        assert_eq!(set.skipped, 7);
        for d in [
            "padded.example",
            "xn--punycode-ok.example",
            "trailing-dot.example",
            "good.example",
        ] {
            assert!(set.contains(d), "{d}");
        }
        assert!(!set.contains("192.0.2.7"));
    }

    #[test]
    fn html_empty_and_oversized_bodies_are_rejected() {
        assert_eq!(parse_list(HTML.as_bytes()).err(), Some(ListError::NotAList));
        assert_eq!(parse_list(b"").err(), Some(ListError::NotAList));
        assert_eq!(
            parse_list(b"# only a comment\n").err(),
            Some(ListError::NotAList)
        );
        assert_eq!(
            parse_list(b"garbage line\n").err(),
            Some(ListError::NotAList)
        );
        let big = vec![b'a'; MAX_BODY_BYTES + 1];
        assert_eq!(parse_list(&big).err(), Some(ListError::TooLarge));
    }

    #[test]
    fn lookup_matches_host_and_listed_parents() {
        let set = parse_list(OK.as_bytes()).unwrap();
        assert_eq!(
            set.lookup("evil-login.example").as_deref(),
            Some("evil-login.example")
        );
        assert_eq!(
            set.lookup("www.secure-bank.example").as_deref(),
            Some("secure-bank.example")
        );
        assert_eq!(
            set.lookup("login.sub.phish-kit.example.org").as_deref(),
            Some("sub.phish-kit.example.org")
        );
        assert_eq!(set.lookup("example.org"), None);
        assert_eq!(
            set.lookup("phish-kit.example.org"),
            None,
            "a child listing does not list its parent"
        );
        assert_eq!(set.lookup("not a host"), None);
        assert_eq!(set.lookup("192.0.2.7"), None);
    }

    #[test]
    fn shared_hosting_parents_match_exactly_only() {
        let set = parse_list(OK.as_bytes()).unwrap();
        assert_eq!(
            set.lookup("fake-bank.000webhostapp.com").as_deref(),
            Some("fake-bank.000webhostapp.com")
        );
        assert_eq!(set.lookup("innocent.000webhostapp.com"), None);
        assert_eq!(
            set.lookup("000webhostapp.com").as_deref(),
            Some("000webhostapp.com")
        );
    }

    #[test]
    fn entry_count_is_capped() {
        let mut text = String::new();
        for n in 0..=MAX_DOMAINS {
            text.push_str(&format!("h{n}.ex\n"));
        }
        assert!(
            text.len() < MAX_BODY_BYTES,
            "test list must fit the byte cap"
        );
        assert_eq!(
            parse_list(text.as_bytes()).err(),
            Some(ListError::TooManyEntries)
        );
    }

    #[test]
    fn stale_feed_rule() {
        let day = 24 * 3600 * 1000;
        let mut s = FeedState::default();
        assert_eq!(s.status(0), FeedStatus::Missing);
        assert!(s.refresh_due(0));
        s.observe("etag-a", 10 * day);
        assert_eq!(s.status(10 * day), FeedStatus::Fresh);
        assert!(!s.refresh_due(10 * day + day - 1));
        assert!(s.refresh_due(11 * day));
        // Downloaded daily, but the content never changes: stale after 7 days.
        for d in 11..17 {
            s.observe("etag-a", d * day);
            assert_eq!(s.status(d * day), FeedStatus::Fresh, "day {d}");
        }
        s.observe("etag-a", 17 * day);
        assert_eq!(s.status(17 * day), FeedStatus::Stale);
        // A change brings it back.
        s.observe("etag-b", 18 * day);
        assert_eq!(s.status(18 * day), FeedStatus::Fresh);
        assert!(s.refresh_due(5 * day), "clock moved backwards");
    }

    #[test]
    fn fingerprint_changes_with_content() {
        assert_ne!(
            body_fingerprint(b"a.example\n"),
            body_fingerprint(b"b.example\n")
        );
        assert_eq!(
            body_fingerprint(b"a.example\n"),
            body_fingerprint(b"a.example\n")
        );
    }

    #[test]
    fn defang_replaces_every_dot() {
        assert_eq!(defang("evil.example.org"), "evil[.]example[.]org");
    }
}
