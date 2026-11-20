//! SP4: pieces the Windows screensaver needs to run the shared SOC view and the OSINT worker.
//! The saver only reads. Keys are read from Windows Credential Manager, where AtlasSOC saved them, and are never
//! written, prompted for or logged here.
use std::path::PathBuf;
use threat_atlas_core::{osint::Source, saver_config::KeyStore};
use windows_sys::Win32::Security::Credentials::{
    CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
};

/// AtlasSOC's settings file (read only) and the saver's own cache folder.
/// Separate caches mean a running AtlasSOC and a saver never write the same files.
pub fn paths() -> Option<(PathBuf, PathBuf)> {
    let root = PathBuf::from(std::env::var_os("LOCALAPPDATA")?);
    Some((
        root.join("ThreatAtlasSOC").join("settings.json"),
        root.join("ThreatAtlasSaver"),
    ))
}

/// The Credential Manager account AtlasSOC uses for a source's key (`AtlasSOC/OSINT/<account>`).
pub fn account(source: Source) -> Option<&'static str> {
    match source {
        Source::Otx => Some("otx"),
        Source::Urlhaus | Source::ThreatFox => Some("abusech"),
        Source::AbuseIpdb => Some("abuseipdb"),
        Source::CertStream => Some("certspotter"),
        _ => None,
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

/// Same shape check AtlasSOC applies when it saves a key.
fn plausible(key: &str) -> bool {
    key.len() >= 16 && key.len() < 512 && key.bytes().all(|b| b.is_ascii_graphic())
}

pub struct CredentialKeys;
impl KeyStore for CredentialKeys {
    fn key(&self, source: Source) -> Option<String> {
        let target = wide(&format!("AtlasSOC/OSINT/{}", account(source)?));
        let mut out = std::mem::MaybeUninit::<*mut CREDENTIALW>::uninit();
        // SAFETY: CredReadW writes the pointer when it returns non-zero; only then is it read. The blob is copied
        // before CredFree and the credential is released exactly once.
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
            let key = if data.is_null() || size == 0 {
                None
            } else {
                String::from_utf8(std::slice::from_raw_parts(data, size).to_vec()).ok()
            };
            CredFree(found.cast());
            key.map(|k| k.trim().to_owned()).filter(|k| plausible(k))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_source_that_needs_a_key_has_an_account() {
        for source in threat_atlas_core::osint::SOURCES {
            let spec = threat_atlas_core::osint::source_spec(*source);
            if spec.requires_key && threat_atlas_core::osint_ffi::LIVE_SOURCES.contains(source) {
                assert!(account(*source).is_some(), "{} has no account", spec.id);
            }
        }
    }

    #[test]
    fn key_shape_check() {
        assert!(plausible("0123456789abcdef"));
        assert!(!plausible("short"));
        assert!(!plausible("has space 0123456789"));
    }
}
