//! Picks the newest AtlasSOC installer from the public GitHub releases list. No network here.
use serde::Deserialize;

pub const HOST: &str = "api.github.com";
pub const PATH: &str = "/repos/ibert-ai/threat-atlas/releases?per_page=30";
pub const MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub build: u32,
}

impl Version {
    pub fn parse(version: &str, build: u32) -> Option<Self> {
        let mut parts = version.split('.').map(|part| part.parse().ok());
        let (major, minor, patch) = (parts.next()??, parts.next()??, parts.next()??);
        parts.next().is_none().then_some(Self {
            major,
            minor,
            patch,
            build,
        })
    }

    fn from_asset(name: &str) -> Option<Self> {
        let rest = name.strip_prefix("AtlasSOC-Setup-")?.strip_suffix(".exe")?;
        let (version, build) = rest.split_once("-build")?;
        Self::parse(version, build.parse().ok()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Available {
    pub version: Version,
    pub title: String,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<Asset>,
}

/// True when this build came from a pre-release identity, so it follows the beta channel.
pub fn is_prerelease(identity: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(identity)
        .is_ok_and(|value| value["prerelease"].is_string())
}

/// Returns the newest published installer that is newer than `current`, if any.
pub fn newer(body: &[u8], current: Version, include_prerelease: bool) -> Option<Available> {
    let releases: Vec<Release> = serde_json::from_slice(body).ok()?;
    releases
        .into_iter()
        .filter(|release| {
            !release.draft
                && release.tag_name.starts_with("atlassoc-v")
                && (include_prerelease || !release.prerelease)
        })
        .filter_map(|release| {
            let version = release
                .assets
                .iter()
                .find_map(|asset| Version::from_asset(&asset.name))?;
            Some(Available {
                version,
                title: release.name.unwrap_or(release.tag_name),
            })
        })
        .filter(|found| found.version > current)
        .max_by_key(|found| found.version)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT: Version = Version {
        major: 0,
        minor: 7,
        patch: 0,
        build: 11,
    };

    fn release(tag: &str, asset: &str, prerelease: bool, draft: bool) -> String {
        format!(
            r#"{{"tag_name":"{tag}","name":"{tag} title","draft":{draft},"prerelease":{prerelease},"assets":[{{"name":"{asset}"}}]}}"#
        )
    }

    fn list(items: &[String]) -> Vec<u8> {
        format!("[{}]", items.join(",")).into_bytes()
    }

    #[test]
    fn finds_a_newer_build_of_the_same_version() {
        let body = list(&[release(
            "atlassoc-v0.7.0-beta.3",
            "AtlasSOC-Setup-0.7.0-build12.exe",
            true,
            false,
        )]);
        let found = newer(&body, CURRENT, true).unwrap();
        assert_eq!(found.version.build, 12);
        assert_eq!(found.title, "atlassoc-v0.7.0-beta.3 title");
    }

    #[test]
    fn same_or_older_versions_are_not_updates() {
        let body = list(&[
            release(
                "atlassoc-v0.7.0-beta.2",
                "AtlasSOC-Setup-0.7.0-build11.exe",
                true,
                false,
            ),
            release(
                "atlassoc-v0.6.0",
                "AtlasSOC-Setup-0.6.0-build99.exe",
                false,
                false,
            ),
        ]);
        assert_eq!(newer(&body, CURRENT, true), None);
    }

    #[test]
    fn stable_channel_ignores_prereleases() {
        let body = list(&[
            release(
                "atlassoc-v0.8.0-beta.1",
                "AtlasSOC-Setup-0.8.0-build20.exe",
                true,
                false,
            ),
            release(
                "atlassoc-v0.7.1",
                "AtlasSOC-Setup-0.7.1-build15.exe",
                false,
                false,
            ),
        ]);
        assert_eq!(newer(&body, CURRENT, false).unwrap().version.build, 15);
        assert_eq!(newer(&body, CURRENT, true).unwrap().version.build, 20);
    }

    #[test]
    fn ignores_drafts_other_products_and_missing_installers() {
        let body = list(&[
            release(
                "atlassoc-v0.9.0",
                "AtlasSOC-Setup-0.9.0-build30.exe",
                false,
                true,
            ),
            release("v0.9.0", "AtlasSOC-Setup-0.9.0-build30.exe", false, false),
            release(
                "atlassoc-v0.9.1",
                "AtlasSOC-Windows-x64-v0.9.1-build31.zip",
                false,
                false,
            ),
        ]);
        assert_eq!(newer(&body, CURRENT, true), None);
    }

    #[test]
    fn bad_input_finds_nothing() {
        assert_eq!(
            newer(b"{\"message\":\"rate limited\"}", CURRENT, true),
            None
        );
        assert_eq!(newer(b"not json", CURRENT, true), None);
        assert_eq!(Version::parse("1.2", 1), None);
        assert_eq!(Version::parse("1.2.3.4", 1), None);
    }

    #[test]
    fn reads_the_release_identity() {
        assert!(is_prerelease(r#"{"prerelease":"beta.2"}"#));
        assert!(!is_prerelease(r#"{"version":"1.0.0"}"#));
    }
}
