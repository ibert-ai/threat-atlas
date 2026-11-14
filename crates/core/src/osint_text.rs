//! Plain-text pages for each OSINT source, shared by hosts that show them in their own windows (macOS now,
//! Windows later). Pure: the caller passes the worker's [`View`], the clipboard text and the current time.

use crate::{
    osint::{self, Source},
    osint_internetdb,
    osint_phishtank::{self, FeedStatus},
    osint_spamhaus,
    osint_worker::View,
};

/// "never", "just now", "12 min ago", "3 h ago", "2 days ago".
pub fn age(updated_ms: u64, now_ms: u64) -> String {
    if updated_ms == 0 {
        return "never".into();
    }
    let secs = now_ms.saturating_sub(updated_ms) / 1000;
    match secs {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", secs / 60),
        3600..=172_799 => format!("{} h ago", secs / 3600),
        _ => format!("{} days ago", secs / 86_400),
    }
}

fn join_counts(items: &[(String, u32)]) -> String {
    if items.is_empty() {
        "none".into()
    } else {
        items
            .iter()
            .map(|(k, n)| format!("{k} {n}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The page for one source. `clipboard` is what the user copied (used by the check-style sources).
pub fn page(source: Source, view: &View, clipboard: &str, now_ms: u64) -> String {
    let spec = osint::source_spec(source);
    let mut text = match source {
        Source::CisaKev | Source::Epss => kev(view, now_ms),
        Source::TorExit => format!(
            "Tor exit nodes: {}\nUpdated: {}\n\nSource: Tor Project bulk exit list. Exit nodes are public Tor infrastructure, not malicious hosts.",
            view.tor_count,
            age(view.tor_updated_ms, now_ms)
        ),
        Source::SansIsc => sans(view, now_ms),
        Source::RansomwareLive => ransomware(view, now_ms),
        Source::SpamhausDrop => spamhaus(view, clipboard, now_ms),
        Source::PhishTank => phishing(view, clipboard, now_ms),
        Source::Sslbl => sslbl(view, now_ms),
        Source::ShodanInternetDb => internetdb(view, now_ms),
        _ => "This source is not available in this build yet.".into(),
    };
    if !view.note.is_empty() {
        text.push_str(&format!("\n\nLast note: {}", view.note));
    }
    text.push_str(&format!(
        "\n\nSource: {} ({}). {}",
        spec.name, spec.attribution, spec.licence
    ));
    text
}

/// One line for the Settings list: what has arrived, when, or what is missing.
pub fn status(source: Source, view: &View, now_ms: u64) -> String {
    let waiting = |updated: u64, what: String| {
        if updated == 0 {
            if view.note.is_empty() {
                "Waiting for the first download...".to_string()
            } else {
                format!("No data yet. Last problem: {}", view.note)
            }
        } else {
            format!("{what}, updated {}", age(updated, now_ms))
        }
    };
    match source {
        Source::CisaKev | Source::Epss => waiting(
            view.kev_updated_ms,
            format!("{} known-exploited vulnerabilities", view.kev.len()),
        ),
        Source::TorExit => waiting(
            view.tor_updated_ms,
            format!("{} exit nodes", view.tor_count),
        ),
        Source::SansIsc => waiting(
            view.sans_updated_ms,
            view.sans
                .as_ref()
                .map_or("top ports".into(), |r| format!("top ports for {}", r.date)),
        ),
        Source::RansomwareLive => waiting(
            view.ransom_updated_ms,
            format!(
                "{} incidents in 30 days",
                view.ransom.as_ref().map_or(0, |r| r.total)
            ),
        ),
        Source::SpamhausDrop => waiting(
            view.spamhaus.as_ref().map_or(0, |d| d.updated_ms),
            view.spamhaus.as_ref().map_or(String::new(), |d| {
                format!(
                    "{} IPv4 / {} IPv6 netblocks",
                    d.v4.entries.len(),
                    d.v6.entries.len()
                )
            }),
        ),
        Source::PhishTank => waiting(
            view.phish_state.fetched_at_ms().unwrap_or(0),
            format!("{} domains", view.phish.as_ref().map_or(0, |s| s.len())),
        ),
        Source::Sslbl => waiting(
            view.sslbl_updated_ms,
            format!("{} certificates", view.sslbl_total),
        ),
        Source::ShodanInternetDb => match (&view.lookup, view.lookup_pending) {
            (_, true) => "Looking up...".into(),
            (Some(l), false) => format!("Last lookup: {} ({})", l.ip, age(l.at_ms, now_ms)),
            (None, false) => "On demand: copy an IP address and press Look up.".into(),
        },
        _ => String::new(),
    }
}

/// What the source tells you, in one sentence.
pub fn what(source: Source) -> &'static str {
    match source {
        Source::CisaKev | Source::Epss => "Vulnerabilities that attackers are known to be exploiting, with a score for how likely exploitation is.",
        Source::TorExit => "Addresses of Tor exit nodes: traffic from them is anonymised, not necessarily malicious.",
        Source::SansIsc => "The ports that internet honeypots see attacked most today.",
        Source::RansomwareLive => "How many ransomware incidents were published in the last 30 days: countries, groups and sectors. No victim names.",
        Source::ShodanInternetDb => "For an IP address you choose: open ports, software and known vulnerabilities Shodan has seen.",
        Source::SpamhausDrop => "Network ranges Spamhaus advises never to route. Check whether an IP address is inside one.",
        Source::PhishTank => "A public list of known phishing domains. Check whether a domain or link is on it.",
        Source::Sslbl => "SSL certificates abuse.ch links to botnet command servers.",
        _ => "",
    }
}

fn kev(view: &View, now: u64) -> String {
    let mut text = format!(
        "CISA Known Exploited Vulnerabilities + FIRST EPSS\nKEV updated: {}\nEPSS updated: {}\n\n",
        age(view.kev_updated_ms, now),
        age(view.epss_updated_ms, now)
    );
    if view.kev.is_empty() {
        text.push_str("No data yet. The first refresh is scheduled within 24 hours.");
    }
    for item in view.kev.iter().take(12) {
        let epss = item
            .epss
            .as_ref()
            .map_or_else(|| "n/a".to_string(), |s| format!("{:.2}", s.epss));
        text.push_str(&format!(
            "{}  EPSS {}  due {}\n  {} - {}: {}\n",
            item.kev.cve, epss, item.kev.due_date, item.kev.vendor, item.kev.product, item.kev.name
        ));
    }
    text.push_str("\nContext only; not confirmation that your assets are affected.");
    text
}

fn sans(view: &View, now: u64) -> String {
    let Some(report) = &view.sans else {
        return "No SANS ISC data yet.".into();
    };
    let mut text = format!(
        "SANS ISC / DShield top target ports\nDate: {}\nUpdated: {}\n\n",
        report.date,
        age(view.sans_updated_ms, now)
    );
    for port in &report.ports {
        text.push_str(&format!(
            "#{}  port {:>5}  records {}  targets {}  sources {}\n",
            port.rank, port.target_port, port.records, port.targets, port.sources
        ));
    }
    text.push_str("\nHoneypot observations, not unique attacks.");
    text
}

fn ransomware(view: &View, now: u64) -> String {
    let Some(sum) = &view.ransom else {
        return "No data yet. The first request is made shortly after start, then at most every 15 minutes.".into();
    };
    format!(
        "Disclosed ransomware incidents, last {} days: {}\nUpdated: {}\n\nCountries: {}\nGroups: {}\nSectors: {}\n\nCounts of what attackers published on leak sites, not confirmed incidents. No victim names are kept or shown. Personal, non-commercial use only.",
        sum.window_days,
        sum.total,
        age(view.ransom_updated_ms, now),
        join_counts(&sum.by_country),
        join_counts(&sum.by_group),
        join_counts(&sum.by_sector)
    )
}

fn spamhaus(view: &View, clipboard: &str, now: u64) -> String {
    let Some(data) = &view.spamhaus else {
        return "The Spamhaus DROP lists have not been downloaded yet. They are fetched once a day.".into();
    };
    let mut text = format!(
        "Spamhaus DROP: {} IPv4 and {} IPv6 netblocks, {} listed AS numbers.\nDownloaded: {}\n",
        data.v4.entries.len(),
        data.v6.entries.len(),
        data.asn.entries.len(),
        age(data.updated_ms, now)
    );
    let now_s = now / 1000;
    if [data.v4.meta.as_ref(), data.v6.meta.as_ref()]
        .into_iter()
        .flatten()
        .any(|m| osint_spamhaus::is_stale(m, now_s))
    {
        text.push_str("Warning: a list is more than 7 days old; do not rely on it.\n");
    }
    match osint_internetdb::parse_ip_text(clipboard) {
        Some(ip) if osint_internetdb::is_lookup_allowed(ip) => {
            match osint_spamhaus::lookup(&[&data.v4, &data.v6], ip) {
                Some(e) => text.push_str(&format!(
                    "\n{ip} is inside a netblock listed by Spamhaus DROP: {}/{} (record {}, registry {}).\nA listing is advice not to route that space, not proof that this machine is malicious.",
                    e.cidr.network, e.cidr.len, e.sbl, e.rir
                )),
                None => text.push_str(&format!("\n{ip} is not inside any listed DROP netblock. That does not mean it is safe.")),
            }
        }
        Some(_) => {
            text.push_str("\nThe copied address is not a public address; it was not checked.")
        }
        None => text.push_str(
            "\nTo check an address, copy it and open this page again. Nothing is sent anywhere.",
        ),
    }
    text
}

fn phishing(view: &View, clipboard: &str, now: u64) -> String {
    let Some(set) = &view.phish else {
        return "The phishing domain list has not been downloaded yet. It is fetched once a day (about 11 MB).".into();
    };
    let mut text = format!("Phishing.Database: {} listed domains.\n", set.len());
    let stale = view.phish_state.status(now) == FeedStatus::Stale;
    if stale {
        text.push_str("Warning: the list has not changed for 7 days or more; the feed may have stopped. It is not used for answers.\n");
    }
    match osint_phishtank::host_from_text(clipboard) {
        Some(host) if !stale => match set.lookup(&host) {
            Some(listed) => text.push_str(&format!(
                "\n{} is on the list (matched {}). Do not open it; the list can contain errors and old entries.",
                osint_phishtank::defang(&host),
                osint_phishtank::defang(&listed)
            )),
            None => text.push_str(&format!("\n{} is not on the list. That does not mean it is safe.", osint_phishtank::defang(&host))),
        },
        Some(_) => {}
        None => text.push_str("\nTo check a domain or link, copy it and open this page again. Nothing is opened or sent."),
    }
    text
}

fn sslbl(view: &View, now: u64) -> String {
    if view.sslbl_updated_ms == 0 {
        return "No data yet. The list is fetched shortly after start, then at most every 15 minutes.".into();
    }
    format!(
        "SSL certificates blacklisted by abuse.ch: {}\nNewest listing: {}\nUpdated: {}\n\nMost common reasons:\n  {}\n\nCertificates linked to botnet command servers; context only.",
        view.sslbl_total,
        age(view.sslbl_newest_ms, now),
        age(view.sslbl_updated_ms, now),
        view.sslbl_top
            .iter()
            .map(|(k, n)| format!("{k} {n}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    )
}

fn internetdb(view: &View, now: u64) -> String {
    let mut text = match &view.lookup {
        None if view.lookup_pending => {
            "Lookup in progress. Open this page again in a few seconds.".into()
        }
        None => {
            "No lookup yet. Copy an IP address and use \"Look up the copied IP address\".".into()
        }
        Some(found) => {
            let mut t = match &found.outcome {
                Ok(Some(host)) => osint_internetdb::describe(host),
                Ok(None) => format!("{}\nShodan has no information about this address. That does not mean it is safe.\n", found.ip),
                Err(error) => format!("{}\n{error}\n", found.ip),
            };
            t.push_str(&format!(
                "\nFetched: {}{}",
                age(found.at_ms, now),
                if found.from_cache {
                    " (stored answer)"
                } else {
                    ""
                }
            ));
            t
        }
    };
    if view.lookup_pending && view.lookup.is_some() {
        text.push_str("\nA newer lookup is in progress.");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages_read_naturally() {
        assert_eq!(age(0, 5), "never");
        assert_eq!(age(1_000, 30_000), "just now");
        assert_eq!(age(1, 61_001), "1 min ago");
        assert_eq!(age(1, 3 * 3_600_000 + 1), "3 h ago");
        assert_eq!(age(1, 3 * 86_400_000 + 1), "3 days ago");
    }

    #[test]
    fn empty_view_gives_a_page_for_every_live_source() {
        let view = View::default();
        for source in [
            Source::CisaKev,
            Source::TorExit,
            Source::SansIsc,
            Source::RansomwareLive,
            Source::SpamhausDrop,
            Source::PhishTank,
            Source::Sslbl,
            Source::ShodanInternetDb,
        ] {
            let text = page(source, &view, "", 1_000_000);
            assert!(text.contains("Source:"), "{source:?}");
        }
    }
}
