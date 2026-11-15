//! Plain-text pages for each OSINT source, shared by hosts that show them in their own windows (macOS now,
//! Windows later). Pure: the caller passes the worker's [`View`], the clipboard text and the current time.

use crate::{
    osint::{self, Source},
    osint_internetdb,
    osint_phishtank::{self, FeedStatus},
    osint_spamhaus,
    osint_worker::{is_enabled, View},
    render::soc::{IntelCard, IntelRow},
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
        Source::Otx => otx(view, now_ms),
        Source::ShodanInternetDb => internetdb(view, now_ms),
        _ => "This source is not available in this build yet.".into(),
    };
    if let Some(note) = note_for(view, source) {
        text.push_str(&format!("\n\nLast problem: {note}"));
    }
    text.push_str(&format!(
        "\n\nSource: {} ({}). {}",
        spec.name, spec.attribution, spec.licence
    ));
    text
}

/// The last problem recorded for one source, if any.
fn note_for(view: &View, source: Source) -> Option<&str> {
    let key = match source {
        Source::CisaKev => "KEV",
        Source::Epss => "EPSS",
        Source::TorExit => "Tor",
        Source::SansIsc => "SANS ISC",
        Source::RansomwareLive => "ransomware.live",
        Source::PhishTank => "Phishing.Database",
        Source::Sslbl => "SSLBL",
        Source::SpamhausDrop => "Spamhaus DROP",
        Source::Otx => "OTX",
        _ => return None,
    };
    view.notes.get(key).map(String::as_str)
}

/// One line for the Settings list: what has arrived, when, or what is missing.
pub fn status(source: Source, view: &View, now_ms: u64) -> String {
    let waiting = |updated: u64, what: String| {
        if updated == 0 {
            match note_for(view, source) {
                None => "Waiting for the first download...".to_string(),
                Some(note) => format!("No data yet. Last problem: {note}"),
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
        Source::Otx => waiting(
            view.otx_updated_ms,
            format!("{} pulses", view.otx.as_ref().map_or(0, |o| o.pulses)),
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
        Source::Otx => "Recent public threat reports from the AlienVault OTX community: malware families and targeted countries. Needs your own free API key.",
        _ => "",
    }
}

fn up(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c.to_ascii_uppercase()
            } else {
                '?'
            }
        })
        .collect()
}

fn bars(items: &[(String, u32)], n: usize) -> Vec<IntelRow> {
    let max = items.iter().map(|(_, v)| *v).max().unwrap_or(1).max(1) as f32;
    items
        .iter()
        .take(n)
        .map(|(k, v)| IntelRow {
            label: up(k),
            fraction: Some(*v as f32 / max),
            value: v.to_string(),
        })
        .collect()
}

/// The live cards for the SOC view, one per source that is switched on and has data. Information
/// only: nothing here uses severity colours. Order is stable so the rotation is calm.
pub fn cards(view: &View, enabled: &[String], now_ms: u64) -> Vec<IntelCard> {
    let on = |s: Source| is_enabled(enabled, s);
    let mut out = Vec::new();
    if let Some(l) = view
        .lookup
        .as_ref()
        .filter(|l| on(Source::ShodanInternetDb) && now_ms.saturating_sub(l.at_ms) < 10 * 60_000)
    {
        if let Ok(Some(h)) = &l.outcome {
            out.push(IntelCard {
                title: format!("SHODAN / {}", up(&l.ip)),
                headline: format!("{} OPEN PORTS", h.ports.len()),
                caption: if h.vulns.is_empty() {
                    "NO KNOWN CVES LISTED".into()
                } else {
                    format!("{} KNOWN CVES", h.vulns.len())
                },
                rows: h
                    .vulns
                    .iter()
                    .take(3)
                    .map(|v| IntelRow {
                        label: up(v),
                        fraction: None,
                        value: String::new(),
                    })
                    .collect(),
            });
        }
    }
    if let Some(s) = view.ransom.as_ref().filter(|_| on(Source::RansomwareLive)) {
        out.push(IntelCard {
            title: format!("RANSOMWARE / LAST {} DAYS", s.window_days),
            headline: format!("{} INCIDENTS", s.total),
            caption: format!(
                "TOP GROUP: {}",
                s.by_group.first().map_or("N/A".into(), |g| up(&g.0))
            ),
            rows: bars(&s.by_country, 3),
        });
    }
    if view.kev_updated_ms != 0 && on(Source::CisaKev) {
        let mut top: Vec<&crate::osint::KevWithEpss> =
            view.kev.iter().filter(|k| k.epss.is_some()).collect();
        top.sort_by(|a, b| {
            b.epss
                .as_ref()
                .map_or(0., |e| e.epss)
                .total_cmp(&a.epss.as_ref().map_or(0., |e| e.epss))
        });
        out.push(IntelCard {
            title: "KNOWN EXPLOITED / CISA".into(),
            headline: format!("{} VULNERABILITIES", view.kev.len()),
            caption: "HIGHEST EXPLOIT LIKELIHOOD (EPSS)".into(),
            rows: top
                .iter()
                .take(3)
                .map(|k| {
                    let e = k.epss.as_ref().map_or(0., |e| e.epss) as f32;
                    IntelRow {
                        label: up(&k.kev.cve),
                        fraction: Some(e),
                        value: format!("{e:.2}"),
                    }
                })
                .collect(),
        });
    }
    if let Some(r) = view.sans.as_ref().filter(|_| on(Source::SansIsc)) {
        let max = r.ports.iter().map(|p| p.records).max().unwrap_or(1).max(1) as f32;
        out.push(IntelCard {
            title: "TOP ATTACKED PORTS / DSHIELD".into(),
            headline: r
                .ports
                .first()
                .map_or("N/A".into(), |p| format!("PORT {}", p.target_port)),
            caption: format!("HONEYPOT RECORDS, {}", up(&r.date)),
            rows: r
                .ports
                .iter()
                .take(5)
                .map(|p| IntelRow {
                    label: format!("PORT {}", p.target_port),
                    fraction: Some(p.records as f32 / max),
                    value: p.records.to_string(),
                })
                .collect(),
        });
    }
    if let Some(o) = view.otx.as_ref().filter(|_| on(Source::Otx)) {
        let max = o.families.iter().map(|f| f.1).max().unwrap_or(1).max(1) as f32;
        out.push(IntelCard {
            title: "OTX COMMUNITY PULSES / 24 H".into(),
            headline: format!("{} PULSES", o.pulses),
            caption: format!("{} INDICATORS, COMMUNITY REPORTS", o.indicators),
            rows: o
                .families
                .iter()
                .take(5)
                .map(|(name, count)| IntelRow {
                    label: up(name).chars().take(16).collect(),
                    fraction: Some(*count as f32 / max),
                    value: count.to_string(),
                })
                .collect(),
        });
    }
    if view.tor_updated_ms != 0 && on(Source::TorExit) {
        out.push(IntelCard {
            title: "TOR EXIT NODES".into(),
            headline: format!("{} NODES", view.tor_count),
            caption: "ANONYMISED TRAFFIC, NOT NECESSARILY MALICIOUS".into(),
            rows: Vec::new(),
        });
    }
    let mut lists = Vec::new();
    if let Some(d) = view.spamhaus.as_ref().filter(|_| on(Source::SpamhausDrop)) {
        lists.push(IntelRow {
            label: "SPAMHAUS DROP".into(),
            fraction: None,
            value: (d.v4.entries.len() + d.v6.entries.len()).to_string(),
        });
    }
    if let Some(p) = view.phish.as_ref().filter(|_| on(Source::PhishTank)) {
        lists.push(IntelRow {
            label: "PHISHING DOMAINS".into(),
            fraction: None,
            value: p.len().to_string(),
        });
    }
    if view.sslbl_updated_ms != 0 && on(Source::Sslbl) {
        lists.push(IntelRow {
            label: "BAD SSL CERTS".into(),
            fraction: None,
            value: view.sslbl_total.to_string(),
        });
    }
    if !lists.is_empty() {
        out.push(IntelCard {
            title: "THREAT LISTS".into(),
            headline: format!("{} LISTS LOADED", lists.len()),
            caption: "CHECK AN ITEM IN SETTINGS > VIEW".into(),
            rows: lists,
        });
    }
    out
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

fn otx(view: &View, now: u64) -> String {
    let Some(o) = &view.otx else {
        return "No data yet. Add your free OTX API key in Settings; the first poll follows."
            .into();
    };
    let list = |items: &[(String, u32)]| {
        if items.is_empty() {
            "none".to_string()
        } else {
            items
                .iter()
                .map(|(n, c)| format!("{n} ({c})"))
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    format!(
        "Public OTX pulses, last 24 hours: {}\nIndicators in them: {}\nUpdated: {}\n\nMalware families: {}\nTargeted countries: {}\n\nNewest pulses:\n  {}\n\nCommunity reports; quality varies. Indicators are not shown or fetched. Non-commercial use only.",
        o.pulses,
        o.indicators,
        age(view.otx_updated_ms, now),
        list(&o.families),
        list(&o.countries),
        if o.newest.is_empty() { "none".to_string() } else { o.newest.join("\n  ") },
    )
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

    #[test]
    fn cards_follow_the_switches_and_the_data() {
        let mut view = View::default();
        let all: Vec<String> = ["tor-exit", "ransomware-live", "sslbl"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(
            cards(&view, &all, 1_000_000).is_empty(),
            "no data, no cards"
        );
        view.tor_count = 1259;
        view.tor_updated_ms = 500_000;
        view.ransom = Some(crate::osint_ransomware::Summary {
            total: 100,
            window_days: 30,
            by_country: vec![("US".into(), 38), ("CA".into(), 7)],
            by_group: vec![("akira".into(), 6)],
            ..Default::default()
        });
        let on = cards(&view, &all, 1_000_000);
        assert_eq!(on.len(), 2);
        assert_eq!(on[0].headline, "100 INCIDENTS");
        assert_eq!(on[0].rows[0].fraction, Some(1.0));
        assert!(on[0].rows[1].fraction.unwrap() < 0.2);
        let off = cards(&view, &["tor-exit".to_string()], 1_000_000);
        assert_eq!(off.len(), 1, "a source that is off shows no card");
        assert!(cards(&view, &[], 1_000_000).is_empty());
    }
}
