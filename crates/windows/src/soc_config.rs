//! Disk state has no tokens or telemetry. Consent is independent of resettable UI settings.
#![cfg_attr(not(windows), allow(dead_code))]
use serde::{Deserialize, Serialize};
use std::{fs, io, path::Path};

pub const VERSION: &str = env!("ATLAS_SOC_VERSION");
include!(concat!(env!("OUT_DIR"), "/soc_build.rs"));
pub const MAX_STATE_BYTES: u64 = 16 * 1024;

#[derive(Deserialize)]
pub struct Terms {
    pub notice: String,
    pub notice_sha256: String,
    pub legal_sha256: String,
    pub notice_url: String,
    pub license_url: String,
    pub scope: String,
}
impl Terms {
    pub fn reviewed() -> Self {
        serde_json::from_str(include_str!("../../../docs/CLOUDFLARE-LICENSE.json"))
            .expect("embedded reviewed licence record")
    }
    pub fn key(&self, version: &str, build: u32) -> String {
        format!(
            "{version}+{build}:{}:{}",
            self.notice_sha256, self.legal_sha256
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Motion {
    Calm,
    Still,
    #[default]
    Realtime,
}

/// Layout theme around the shared map (ATLAS-SOC-LAYOUT-001). Classic stays the default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    Classic,
    Dashboard,
}
impl Theme {
    pub fn is_classic(&self) -> bool {
        *self == Theme::Classic
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub schema_version: u32,
    pub width: u32,
    pub height: u32,
    pub fullscreen: bool,
    pub always_on_top: bool,
    pub fps: u32,
    pub severities: [bool; 3],
    pub motion: Motion,
    pub mirror_all_displays: bool,
    /// Omitted while Classic, so settings files stay readable by earlier builds.
    #[serde(skip_serializing_if = "Theme::is_classic")]
    pub theme: Theme,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            schema_version: 1,
            width: 1280,
            height: 800,
            fullscreen: false,
            always_on_top: false,
            fps: 10,
            severities: [true; 3],
            motion: Motion::Realtime,
            mirror_all_displays: false,
            theme: Theme::Classic,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> bool {
        self.schema_version == 1
            && (640..=3840).contains(&self.width)
            && (400..=2160).contains(&self.height)
            && [5, 10, 20].contains(&self.fps)
    }
    pub fn load(path: &Path) -> (Self, Option<String>) {
        match read_bounded(path) {
            Ok(bytes) => match serde_json::from_slice::<Self>(&bytes) {
                Ok(value) if value.validate() => (value, None),
                _ => (Self::default(), Some("Invalid settings; using defaults. Original file preserved until you save a change.".into())),
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => (Self::default(), None),
            Err(_) => (Self::default(), Some("Settings unavailable or too large; using defaults.".into())),
        }
    }
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if !self.validate() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid settings",
            ));
        }
        write_atomic(path, &serde_json::to_vec_pretty(self)?)
    }
}

pub fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "State too large",
        ));
    }
    Ok(bytes)
}

pub fn accepted(path: &Path, key: &str) -> bool {
    read_bounded(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| {
            value
                .get("consent_key")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .is_some_and(|saved| saved == key)
}

/// Called only after an affirmative native user action. No CLI consent bypass exists.
pub fn record_acceptance(path: &Path, key: &str) -> io::Result<()> {
    write_atomic(
        path,
        &serde_json::to_vec_pretty(&serde_json::json!({"consent_key": key}))?,
    )
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let result = (|| {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
            };
            let from: Vec<u16> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
            let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            if unsafe {
                MoveFileExW(
                    from.as_ptr(),
                    to.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        #[cfg(not(windows))]
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

/// UI mapping uses integer bounds so tiny/minimized and letterboxed windows are safe.
/// Standard 1440x900 fit; the host uses `layout_frame` with the current frame width.
#[cfg(test)]
pub fn layout(width: u32, height: u32) -> (u32, u32, u32, u32) {
    layout_frame(width, height, 1440, 900)
}
/// Aspect-fit a `frame_w` x `frame_h` frame inside a `width` x `height` window: (w, h, x, y).
pub fn layout_frame(width: u32, height: u32, frame_w: u32, frame_h: u32) -> (u32, u32, u32, u32) {
    let (fw, fh) = (u64::from(frame_w.max(1)), u64::from(frame_h.max(1)));
    let (w, h) = if u64::from(width) * fh <= u64::from(height) * fw {
        (width, (u64::from(width) * fh / fw) as u32)
    } else {
        ((u64::from(height) * fw / fh) as u32, height)
    };
    (w, h, (width - w) / 2, (height - h) / 2)
}
/// SOC frame width for a window's shape (height 900): at least the standard 1440, at most 4320,
/// in steps of 8 px. Wider windows get the wide layout and fill edge to edge.
pub fn frame_width(width: u32, height: u32) -> u32 {
    if width == 0 || height == 0 {
        return 1440;
    }
    let wanted = (u64::from(width) * 900 / u64::from(height) / 8 * 8) as u32;
    wanted.clamp(1440, 4320)
}

pub fn inspection_label(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    Some(format!(
        "{} ({}) - {} malicious / {} suspicious / {} benign in {} minutes",
        value.get("name")?.as_str()?,
        value.get("code")?.as_str()?,
        value.get("malicious")?.as_u64()?,
        value.get("suspicious")?.as_u64()?,
        value.get("benign")?.as_u64()?,
        value.get("window_minutes")?.as_u64()?
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("atlas-soc-{}-{name}", std::process::id()))
    }
    #[test]
    fn licence_identity_invalidates_every_changed_component() {
        let mut terms = Terms::reviewed();
        let key = terms.key(VERSION, BUILD);
        assert_ne!(key, terms.key("0.7.1", BUILD));
        assert_ne!(key, terms.key(VERSION, BUILD + 1));
        terms.notice_sha256.push('x');
        assert_ne!(key, terms.key(VERSION, BUILD));
        terms.notice_sha256.pop();
        terms.legal_sha256.push('x');
        assert_ne!(key, terms.key(VERSION, BUILD));
    }
    #[test]
    fn consent_starts_closed_and_malformed_or_old_records_do_not_open_it() {
        let path = scratch("consent.json");
        let _ = fs::remove_file(&path);
        let key = Terms::reviewed().key(VERSION, BUILD);
        assert!(!accepted(&path, &key));
        // Synthetic store only; no user consent is recorded by this test.
        record_acceptance(&path, "synthetic-old-consent").unwrap();
        assert!(!accepted(&path, &key));
        record_acceptance(&path, "synthetic-test-consent").unwrap();
        assert!(accepted(&path, "synthetic-test-consent"));
        fs::write(&path, b"not json").unwrap();
        assert!(!accepted(&path, &key));
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn settings_roundtrip_reset_and_invalid_recovery() {
        let path = scratch("settings.json");
        let settings = Settings {
            motion: Motion::Still,
            fps: 5,
            fullscreen: true,
            ..Settings::default()
        };
        settings.save(&path).unwrap();
        assert_eq!(Settings::load(&path).0, settings);
        Settings::default().save(&path).unwrap();
        assert_eq!(Settings::load(&path).0, Settings::default());
        let invalid = br#"{"schema_version":100,"fps":999999999}"#;
        fs::write(&path, invalid).unwrap();
        assert!(Settings::load(&path).1.is_some());
        assert_eq!(fs::read(&path).unwrap(), invalid);
        fs::write(&path, vec![b'x'; MAX_STATE_BYTES as usize + 1]).unwrap();
        assert!(Settings::load(&path).1.is_some());
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn layout_theme_persists_and_classic_files_stay_readable_by_older_builds() {
        let path = scratch("theme.json");
        // Classic is the default and is not written, so pre-theme builds still accept the file.
        Settings::default().save(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("theme"), "{text}");
        let dashboard = Settings {
            theme: Theme::Dashboard,
            ..Settings::default()
        };
        dashboard.save(&path).unwrap();
        assert!(fs::read_to_string(&path)
            .unwrap()
            .contains(r#""theme": "dashboard""#));
        assert_eq!(Settings::load(&path), (dashboard, None));
        // Files from earlier builds (no theme key) load as Classic.
        fs::write(&path, br#"{"schema_version":1,"motion":"calm"}"#).unwrap();
        assert_eq!(Settings::load(&path).0.theme, Theme::Classic);
        fs::write(&path, br#"{"schema_version":1,"theme":"neon"}"#).unwrap();
        assert!(
            Settings::load(&path).1.is_some(),
            "unknown theme falls back to defaults"
        );
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn resolution_mapping_fits_portrait_ultrawide_and_tiny_windows() {
        for (w, h) in [
            (1, 1),
            (0, 0),
            (1280, 800),
            (1920, 1080),
            (1080, 1920),
            (3440, 1440),
        ] {
            let (dw, dh, x, y) = layout(w, h);
            assert!(dw + x <= w && dh + y <= h);
            assert!(w - dw - x <= x + 1 && h - dh - y <= y + 1);
        }
    }

    #[test]
    fn wide_windows_get_a_frame_of_their_shape() {
        assert_eq!(frame_width(1440, 900), 1440);
        assert_eq!(frame_width(1280, 1024), 1440); // narrower than 16:10: standard frame, letterboxed
        assert_eq!(frame_width(1920, 1080), 1600); // 16:9 fills edge to edge
        assert_eq!(frame_width(3440, 1440), 2144); // ultrawide
        assert_eq!(frame_width(0, 0), 1440);
        assert_eq!(frame_width(100_000, 10), 4320);
        assert_eq!(layout_frame(1920, 1080, 1600, 900), (1920, 1080, 0, 0));
        assert_eq!(layout_frame(1920, 1080, 1440, 900), layout(1920, 1080));
    }

    #[test]
    fn country_inspection_has_readable_counts_and_rejects_invalid_data() {
        assert_eq!(inspection_label(r#"{"name":"India","code":"IN","malicious":2,"suspicious":3,"benign":4,"window_minutes":5}"#).as_deref(),
            Some("India (IN) - 2 malicious / 3 suspicious / 4 benign in 5 minutes"));
        assert!(inspection_label("not json").is_none());
        assert!(inspection_label("{}").is_none());
    }
}
