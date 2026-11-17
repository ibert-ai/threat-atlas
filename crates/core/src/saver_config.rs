//! SP2: what a screensaver host may read from the AtlasSOC settings file.
//!
//! The saver never writes settings; it only reads the file AtlasSOC saves (the same `settings.json`), takes the
//! two fields it needs and ignores the rest. A missing, oversized or corrupt file means every source is OFF:
//! the saver makes no request until the user has chosen sources in AtlasSOC Settings. Request intervals are not
//! read from the file; each source's minimum interval is fixed in the registry (`osint::source_spec`).
//! API keys are never in the file. The host looks them up in the system credential store through [`KeyStore`].
use crate::osint::{self, Source};
use crate::osint_worker::Osint;
use std::{fs, io::Read, path::Path};

/// Same cap as AtlasSOC's own settings reader.
pub const MAX_SETTINGS_BYTES: u64 = 16 * 1024;
/// Certificate watch domains: at most 10, each at most 253 bytes (the DNS limit).
pub const MAX_WATCH_DOMAINS: usize = 10;
const MAX_DOMAIN_BYTES: usize = 253;

/// One key (or none) per source, in registry order.
pub type ResolvedKeys = Vec<(Source, Option<String>)>;

/// What the saver took from the file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SaverSettings {
    /// Ids of the sources that may make requests. Unknown ids are dropped.
    pub enabled_sources: Vec<String>,
    /// Domains watched in the certificate logs.
    pub watch_domains: Vec<String>,
}

/// Read-only credential lookup, implemented by the host (Windows Credential Manager, macOS Keychain, ...).
/// Returns `None` when there is no key. The value is passed to the worker in memory only.
pub trait KeyStore {
    fn key(&self, source: Source) -> Option<String>;
}

/// A store with no keys, for hosts that have none yet and for tests.
pub struct NoKeys;
impl KeyStore for NoKeys {
    fn key(&self, _source: Source) -> Option<String> {
        None
    }
}

fn known_id(id: &str) -> bool {
    osint::SOURCES
        .iter()
        .any(|s| osint::source_spec(*s).id == id)
}

impl SaverSettings {
    /// Everything off. This is also the answer for a missing or broken file.
    pub fn off() -> Self {
        Self::default()
    }

    /// Parses the bytes of an AtlasSOC settings file. Anything that is not a JSON object, or has the wrong field
    /// types, gives [`SaverSettings::off`]. Unknown fields are ignored so a newer AtlasSOC does not break the saver.
    pub fn parse(bytes: &[u8]) -> Self {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return Self::off();
        };
        let strings = |name: &str| -> Option<Vec<String>> {
            match value.get(name) {
                None => Some(Vec::new()),
                Some(serde_json::Value::Array(items)) => items
                    .iter()
                    .map(|i| i.as_str().map(str::to_owned))
                    .collect(),
                Some(_) => None,
            }
        };
        let (Some(sources), Some(domains)) = (strings("enabled_sources"), strings("watch_domains"))
        else {
            return Self::off();
        };
        let mut enabled: Vec<String> = Vec::new();
        for id in sources {
            if known_id(&id) && !enabled.contains(&id) {
                enabled.push(id);
            }
        }
        let watch = domains
            .into_iter()
            .filter(|d| !d.is_empty() && d.len() <= MAX_DOMAIN_BYTES)
            .take(MAX_WATCH_DOMAINS)
            .collect();
        Self {
            enabled_sources: enabled,
            watch_domains: watch,
        }
    }

    /// Reads the settings file. Missing, unreadable, too large or corrupt all give [`SaverSettings::off`].
    pub fn load(path: &Path) -> Self {
        let Ok(file) = fs::File::open(path) else {
            return Self::off();
        };
        let mut bytes = Vec::new();
        if file
            .take(MAX_SETTINGS_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > MAX_SETTINGS_BYTES
        {
            return Self::off();
        }
        Self::parse(&bytes)
    }

    /// The key for every source that is on and needs one, from the credential store. A source that is off gets
    /// none, so it can never make an authenticated request.
    pub fn resolve_keys(&self, keys: &dyn KeyStore) -> ResolvedKeys {
        osint::SOURCES
            .iter()
            .map(|source| {
                let on = crate::osint_worker::is_enabled(&self.enabled_sources, *source);
                let key = if on && osint::source_spec(*source).requires_key {
                    keys.key(*source).filter(|k| !k.trim().is_empty())
                } else {
                    None
                };
                (*source, key)
            })
            .collect()
    }
}

/// Applies settings to a running worker, and only when something changed, so a host can call it every few
/// seconds without waking the worker each time.
#[derive(Default)]
pub struct Applier {
    last: Option<(SaverSettings, ResolvedKeys)>,
}
impl Applier {
    /// Returns true when the worker was updated.
    pub fn apply(&mut self, osint: &Osint, settings: SaverSettings, keys: &dyn KeyStore) -> bool {
        let resolved = settings.resolve_keys(keys);
        if self.last.as_ref() == Some(&(settings.clone(), resolved.clone())) {
            return false;
        }
        // One call: the worker never sees new keys with old switches or the reverse (see `apply_config`).
        osint.apply_config(
            settings.enabled_sources.clone(),
            resolved.clone(),
            settings.watch_domains.clone(),
        );
        self.last = Some((settings, resolved));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_means_everything_off() {
        let p = std::env::temp_dir().join("atlas-saver-config-does-not-exist.json");
        assert_eq!(SaverSettings::load(&p), SaverSettings::off());
    }

    #[test]
    fn corrupt_or_wrongly_typed_files_mean_everything_off() {
        for bad in [
            &b""[..],
            b"not json",
            b"[1,2,3]",
            br#"{"enabled_sources":"cisa-kev"}"#,
            br#"{"enabled_sources":["cisa-kev",3]}"#,
            br#"{"watch_domains":{"a":1}}"#,
        ] {
            assert_eq!(SaverSettings::parse(bad), SaverSettings::off(), "{bad:?}");
        }
    }

    #[test]
    fn oversized_file_means_everything_off() {
        let dir = std::env::temp_dir().join("atlas-saver-config-big");
        let _ = fs::create_dir_all(&dir);
        let p = dir.join("settings.json");
        let pad = " ".repeat(MAX_SETTINGS_BYTES as usize);
        fs::write(&p, format!(r#"{{"enabled_sources":["cisa-kev"]}}{pad}"#)).unwrap();
        assert_eq!(SaverSettings::load(&p), SaverSettings::off());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn reads_sources_and_domains_and_ignores_the_rest() {
        let s = SaverSettings::parse(
            br#"{"schema_version":1,"width":1280,"fps":10,"future_field":{"x":1},
                 "enabled_sources":["cisa-kev","made-up","cisa-kev","first-epss"],
                 "watch_domains":["example.org",""]}"#,
        );
        assert_eq!(s.enabled_sources, vec!["cisa-kev", "first-epss"]);
        assert_eq!(s.watch_domains, vec!["example.org"]);
    }

    #[test]
    fn a_file_without_the_fields_gives_everything_off() {
        let s = SaverSettings::parse(br#"{"schema_version":1}"#);
        assert!(s.enabled_sources.is_empty() && s.watch_domains.is_empty());
    }

    #[test]
    fn watch_domains_are_capped() {
        let list: Vec<String> = (0..30).map(|i| format!("\"d{i}.example\"")).collect();
        let json = format!(r#"{{"watch_domains":[{}]}}"#, list.join(","));
        assert_eq!(
            SaverSettings::parse(json.as_bytes()).watch_domains.len(),
            MAX_WATCH_DOMAINS
        );
    }

    #[test]
    fn the_saver_defaults_are_off_not_the_desktop_defaults() {
        // AtlasSOC enables four sources on a fresh install; a saver without a settings file must not.
        assert!(!osint::default_enabled_ids().is_empty());
        assert!(SaverSettings::off().enabled_sources.is_empty());
    }

    #[test]
    fn key_store_is_only_asked_for_sources_that_are_on_and_need_one() {
        struct Spy(std::cell::RefCell<Vec<Source>>);
        impl KeyStore for Spy {
            fn key(&self, source: Source) -> Option<String> {
                self.0.borrow_mut().push(source);
                Some("k".into())
            }
        }
        let spy = Spy(Default::default());
        let dir = std::env::temp_dir().join("atlas-saver-config-apply");
        let _ = fs::create_dir_all(&dir);
        let worker = Osint::start(dir, Vec::new(), |_, _, _, _| None);
        let s = SaverSettings {
            enabled_sources: vec!["cisa-kev".into(), "abuseipdb".into()],
            watch_domains: Vec::new(),
        };
        let mut applier = Applier::default();
        assert!(applier.apply(&worker, s.clone(), &spy));
        assert_eq!(*spy.0.borrow(), vec![Source::AbuseIpdb]);
        // Nothing changed: the worker is not touched again.
        assert!(!applier.apply(&worker, s, &spy));
        // A changed key is applied.
        struct Other;
        impl KeyStore for Other {
            fn key(&self, _s: Source) -> Option<String> {
                Some("k2".into())
            }
        }
        let s2 = SaverSettings {
            enabled_sources: vec!["abuseipdb".into()],
            watch_domains: Vec::new(),
        };
        assert!(applier.apply(&worker, s2, &Other));
    }

    #[test]
    fn a_reload_that_turns_a_source_off_and_drops_a_domain_takes_effect() {
        let dir = std::env::temp_dir().join("atlas-saver-config-reload");
        let _ = fs::create_dir_all(&dir);
        let worker = Osint::start(dir, Vec::new(), |_, _, _, _| None);
        let mut applier = Applier::default();
        let on = SaverSettings {
            enabled_sources: vec!["cisa-kev".into(), "abuseipdb".into()],
            watch_domains: vec!["example.org".into(), "example.net".into()],
        };
        assert!(applier.apply(&worker, on.clone(), &NoKeys));
        assert_eq!(worker.enabled(), on.enabled_sources);
        assert_eq!(worker.watch().len(), 2);
        let off = SaverSettings {
            enabled_sources: vec!["cisa-kev".into()],
            watch_domains: vec!["example.org".into()],
        };
        assert!(applier.apply(&worker, off, &NoKeys));
        assert_eq!(worker.enabled(), vec!["cisa-kev".to_string()]);
        assert_eq!(worker.watch(), vec!["example.org".to_string()]);
        assert!(applier.apply(&worker, SaverSettings::off(), &NoKeys));
        assert!(worker.enabled().is_empty() && worker.watch().is_empty());
    }
}
