//! Update feed (see docs/UPDATE-CHANNELS.md): channel resolution with fallback, withdrawn versions and
//! strict download-URL checks. No network and no file access here; callers pass the feed bytes.
//!
//! The feed is only a pointer list. It never authorises an installation by itself: callers must still
//! verify the SHA-256 and the operating-system signature of what they download.
use serde::Deserialize;
use std::collections::HashMap;

/// Public feed location (the `update-feed` branch). Nothing is published there yet.
pub const FEED_URL: &str =
    "https://raw.githubusercontent.com/Ibert-Iam/threat-atlas/update-feed/feed.json";
pub const OWNER: &str = "Ibert-Iam";
pub const REPO: &str = "threat-atlas";
pub const MAX_FEED_BYTES: usize = 1_000_000;
/// Largest file the feed may announce; the downloader uses `size` as its cap, so a bad entry cannot ask for more.
pub const MAX_ASSET_BYTES: u64 = 512 * 1024 * 1024;
const SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Channel {
    #[default]
    Stable,
    Rc,
    Beta,
}

impl Channel {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "stable" => Some(Self::Stable),
            "rc" => Some(Self::Rc),
            "beta" => Some(Self::Beta),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Rc => "rc",
            Self::Beta => "beta",
        }
    }

    /// Channels a user on `self` may be offered releases from (newest version wins): beta -> rc -> stable.
    fn allowed(self) -> &'static [Channel] {
        match self {
            Self::Stable => &[Self::Stable],
            Self::Rc => &[Self::Stable, Self::Rc],
            Self::Beta => &[Self::Stable, Self::Rc, Self::Beta],
        }
    }
}

/// Semantic version with pre-releases that sort below their release: beta < rc < final.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    rank: u8,
    pub pre: u32,
}

impl SemVer {
    pub fn parse(text: &str) -> Option<Self> {
        let (core, pre) = match text.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (text, None),
        };
        let mut parts = core.split('.');
        let (major, minor, patch) = (
            number(parts.next()?)?,
            number(parts.next()?)?,
            number(parts.next()?)?,
        );
        if parts.next().is_some() {
            return None;
        }
        let (rank, pre) = match pre {
            None => (2, 0),
            Some(pre) => {
                let (kind, n) = pre.split_once('.')?;
                (
                    match kind {
                        "beta" => 0,
                        "rc" => 1,
                        _ => return None,
                    },
                    number(n)?,
                )
            }
        };
        Some(Self {
            major,
            minor,
            patch,
            rank,
            pre,
        })
    }

    pub fn channel(self) -> Channel {
        match self.rank {
            0 => Channel::Beta,
            1 => Channel::Rc,
            _ => Channel::Stable,
        }
    }
}

/// Digits only: no sign, no empty string and no leading zeros ("01" would tie with "1" in ordering but
/// differ as text, which breaks the withdrawn-version match); `str::parse` alone would accept "+1".
fn number(text: &str) -> Option<u32> {
    (!text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0')))
    .then(|| text.parse().ok())
    .flatten()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Auto,
    Installer,
    Portable,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Asset {
    pub platform: String,
    pub kind: String,
    pub name: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub tag: String,
    pub channel: String,
    #[serde(default)]
    pub build: Option<u32>,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct Product {
    #[serde(default)]
    pub releases: Vec<Release>,
    #[serde(default)]
    pub withdrawn: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Feed {
    pub schema_version: u32,
    #[serde(default)]
    pub products: HashMap<String, Product>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedError {
    TooLarge,
    Syntax,
    Schema,
    Invalid(String),
}

/// What the resolver selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selected {
    pub version: String,
    /// The release's own channel (a Beta user may be offered an RC or Stable).
    pub channel: Channel,
    pub tag: String,
    pub build: Option<u32>,
    pub asset: Asset,
}

/// True only for `https://github.com/Ibert-Iam/threat-atlas/releases/download/<tag>/<name>`.
///
/// A prefix test is not enough: `..` segments, percent-encoding, user-info, ports, queries and fragments
/// all let a URL that starts with the right text point elsewhere once a client normalises it. The old
/// owner name `ibert-ai` is an empty reserved organisation and is deliberately not accepted.
pub fn download_url_ok(url: &str, tags: &[&str], name: &str) -> bool {
    if url
        .chars()
        .any(|c| matches!(c, '\\' | '%' | '?' | '#' | '@') || c.is_whitespace() || c.is_control())
    {
        return false;
    }
    let Some(path) = url.strip_prefix("https://github.com/") else {
        return false;
    };
    let parts: Vec<&str> = path.split('/').collect();
    let [owner, repo, "releases", "download", tag, file] = parts[..] else {
        return false;
    };
    owner == OWNER
        && repo == REPO
        && tags.contains(&tag)
        && file == name
        && safe_segment(tag)
        && safe_segment(file)
}

fn safe_segment(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && !text.contains("..")
}

/// Parses and security-checks a feed. Anything wrong rejects the whole feed (fail closed).
pub fn parse_feed(bytes: &[u8]) -> Result<Feed, FeedError> {
    if bytes.len() > MAX_FEED_BYTES {
        return Err(FeedError::TooLarge);
    }
    let feed: Feed = serde_json::from_slice(bytes).map_err(|_| FeedError::Syntax)?;
    if feed.schema_version != SCHEMA {
        return Err(FeedError::Schema);
    }
    for (product, block) in &feed.products {
        for version in &block.withdrawn {
            SemVer::parse(version)
                .ok_or_else(|| FeedError::Invalid(format!("{product}: bad withdrawn version")))?;
        }
        for release in &block.releases {
            let semver = SemVer::parse(&release.version).ok_or_else(|| {
                FeedError::Invalid(format!("{product}: bad version {}", release.version))
            })?;
            if Channel::parse(&release.channel) != Some(semver.channel()) {
                return Err(FeedError::Invalid(format!(
                    "{product} {}: channel does not match the version",
                    release.version
                )));
            }
            let linux_tag = format!("{}-linux", release.tag);
            let tags = [release.tag.as_str(), linux_tag.as_str()];
            for asset in &release.assets {
                let sha_ok = asset.sha256.len() == 64
                    && asset
                        .sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
                if !sha_ok
                    || asset.size == 0
                    || asset.size > MAX_ASSET_BYTES
                    || !download_url_ok(&asset.url, &tags, &asset.name)
                {
                    return Err(FeedError::Invalid(format!(
                        "{product} {}: bad asset {}",
                        release.version, asset.name
                    )));
                }
            }
        }
    }
    Ok(feed)
}

fn pick_asset<'a>(release: &'a Release, platform: &str, kind: Kind) -> Option<&'a Asset> {
    let kinds: &[&str] = match kind {
        Kind::Auto => &["installer", "portable"],
        Kind::Installer => &["installer"],
        Kind::Portable => &["portable"],
    };
    kinds.iter().find_map(|wanted| {
        release
            .assets
            .iter()
            .find(|a| a.platform == platform && a.kind == *wanted)
    })
}

/// The newest non-withdrawn release the channel may offer that has a file for platform and kind.
pub fn resolve(
    feed: &Feed,
    product: &str,
    channel: Channel,
    platform: &str,
    kind: Kind,
) -> Option<Selected> {
    let block = feed.products.get(product)?;
    let allowed = channel.allowed();
    let mut best: Option<(SemVer, &Release, &Asset)> = None;
    for release in &block.releases {
        if block.withdrawn.contains(&release.version) {
            continue;
        }
        let (Some(semver), Some(asset)) = (
            SemVer::parse(&release.version),
            pick_asset(release, platform, kind),
        ) else {
            continue;
        };
        if !allowed.contains(&semver.channel()) {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(current, _, _)| semver > *current)
        {
            best = Some((semver, release, asset));
        }
    }
    best.map(|(semver, release, asset)| Selected {
        version: release.version.clone(),
        channel: semver.channel(),
        tag: release.tag.clone(),
        build: release.build,
        asset: asset.clone(),
    })
}

/// What to offer a user who has `installed` (and, when known, its build number): a strictly newer version,
/// or the same version with a higher build. There is never an automatic downgrade (switching to Stable
/// from a pre-release is a separate, confirmed reinstall; a withdrawn installed version has
/// [`safe_alternative`]).
pub fn update_for(
    feed: &Feed,
    product: &str,
    channel: Channel,
    platform: &str,
    kind: Kind,
    installed: SemVer,
    installed_build: Option<u32>,
) -> Option<Selected> {
    let selected = resolve(feed, product, channel, platform, kind)?;
    let candidate = SemVer::parse(&selected.version)?;
    let rebuilt = candidate == installed
        && matches!((selected.build, installed_build), (Some(new), Some(old)) if new > old);
    (candidate > installed || rebuilt).then_some(selected)
}

/// For a withdrawn installed version: what the banner offers instead (decision Q5). This may be an older
/// version, so callers must show it as a user-approved move, never apply it silently. `None` when the
/// installed version is not withdrawn or nothing else is available.
pub fn safe_alternative(
    feed: &Feed,
    product: &str,
    channel: Channel,
    platform: &str,
    kind: Kind,
    installed_version: &str,
) -> Option<Selected> {
    installed_is_withdrawn(feed, product, installed_version)
        .then(|| resolve(feed, product, channel, platform, kind))
        .flatten()
}

/// True when the installed version has been withdrawn, so the app should show the banner (decision Q5).
pub fn installed_is_withdrawn(feed: &Feed, product: &str, installed_version: &str) -> bool {
    feed.products
        .get(product)
        .is_some_and(|block| block.withdrawn.iter().any(|v| v == installed_version))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../testdata/update-feed-sample.json");
    const CASES: &str = include_str!("../testdata/update-feed-cases.json");

    fn feed() -> Feed {
        parse_feed(SAMPLE.as_bytes()).expect("fixture feed is valid")
    }

    /// The sample feed as bytes after a mutation of its parsed JSON (robust against asset order).
    fn mutated(change: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut value: serde_json::Value = serde_json::from_str(SAMPLE).unwrap();
        change(&mut value);
        serde_json::to_vec(&value).unwrap()
    }

    fn set(value: &mut serde_json::Value, pointer: &str, to: serde_json::Value) {
        *value.pointer_mut(pointer).expect("pointer exists") = to;
    }

    fn v(text: &str) -> SemVer {
        SemVer::parse(text).expect("test version")
    }

    #[test]
    fn version_precedence_puts_prereleases_below_their_release() {
        let order = [
            "0.8.0-beta.1",
            "0.8.0-beta.2",
            "0.8.0-rc.1",
            "0.8.0",
            "0.8.1-beta.1",
            "0.10.0",
        ];
        let parsed: Vec<SemVer> = order.iter().map(|t| v(t)).collect();
        assert!(parsed.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn bad_versions_are_rejected() {
        for bad in [
            "1.0",
            "v1.0.0",
            "1.0.0-alpha.1",
            "1.0.0-rc",
            "1.0.0+x",
            "+1.0.0",
            "1.0.0-rc.+1",
            "1..0",
            "",
        ] {
            assert!(SemVer::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn every_shared_fixture_case_resolves_as_recorded() {
        let feed = feed();
        let cases: serde_json::Value = serde_json::from_str(CASES).unwrap();
        let cases = cases["cases"].as_array().unwrap();
        assert!(cases.len() >= 15);
        for case in cases {
            let channel = Channel::parse(case["channel"].as_str().unwrap()).unwrap();
            let got = resolve(
                &feed,
                case["product"].as_str().unwrap(),
                channel,
                case["platform"].as_str().unwrap(),
                Kind::Auto,
            );
            assert_eq!(
                got.as_ref()
                    .map(|s| (s.version.as_str(), s.asset.name.as_str())),
                Some((
                    case["version"].as_str().unwrap(),
                    case["asset"].as_str().unwrap()
                )),
                "{case}"
            );
        }
    }

    #[test]
    fn beta_falls_back_to_rc_then_stable_and_withdrawn_is_skipped() {
        let feed = feed();
        let beta = resolve(&feed, "atlassoc", Channel::Beta, "windows-x64", Kind::Auto).unwrap();
        assert_eq!(beta.version, "0.9.0-beta.1");
        assert_eq!(beta.channel, Channel::Beta);
        // 0.8.0-rc.2 is withdrawn in the fixture: the RC channel resolves to rc.1, never rc.2.
        let rc = resolve(&feed, "atlassoc", Channel::Rc, "windows-x64", Kind::Auto).unwrap();
        assert_eq!(rc.version, "0.8.0-rc.1");
        let stable = resolve(
            &feed,
            "atlassoc",
            Channel::Stable,
            "windows-x64",
            Kind::Auto,
        )
        .unwrap();
        assert_eq!(stable.version, "0.7.0");
    }

    #[test]
    fn no_release_for_an_unknown_product_or_platform() {
        let feed = feed();
        assert!(resolve(&feed, "nothing", Channel::Stable, "windows-x64", Kind::Auto).is_none());
        assert!(resolve(&feed, "atlassoc", Channel::Stable, "plan9", Kind::Auto).is_none());
    }

    #[test]
    fn kind_filter_skips_releases_without_that_kind() {
        let feed = feed();
        // The macOS files are portable zips only: an installer request has no macOS answer.
        assert!(resolve(
            &feed,
            "atlassoc",
            Channel::Stable,
            "macos-universal",
            Kind::Installer
        )
        .is_none());
        assert!(resolve(
            &feed,
            "atlassoc",
            Channel::Stable,
            "macos-universal",
            Kind::Portable
        )
        .is_some());
    }

    #[test]
    fn update_for_never_offers_the_same_or_an_older_version() {
        let feed = feed();
        let offer = |installed: &str, channel| {
            update_for(
                &feed,
                "atlassoc",
                channel,
                "windows-x64",
                Kind::Auto,
                v(installed),
                None,
            )
        };
        assert_eq!(offer("0.6.0", Channel::Stable).unwrap().version, "0.7.0");
        assert!(offer("0.7.0", Channel::Stable).is_none());
        assert!(
            offer("0.9.0-beta.1", Channel::Stable).is_none(),
            "no automatic downgrade"
        );
        assert!(
            offer("0.9.0-beta.1", Channel::Beta).is_none(),
            "already on the newest"
        );
        assert_eq!(
            offer("0.8.0-rc.1", Channel::Beta).unwrap().version,
            "0.9.0-beta.1"
        );
    }

    #[test]
    fn a_higher_build_of_the_same_version_is_an_update_only_when_both_builds_are_known() {
        let feed = feed();
        let offer = |build| {
            update_for(
                &feed,
                "atlassoc",
                Channel::Beta,
                "windows-x64",
                Kind::Auto,
                v("0.9.0-beta.1"),
                build,
            )
        };
        assert!(offer(Some(16)).is_some(), "fixture build is 17");
        assert!(offer(Some(17)).is_none());
        assert!(offer(Some(18)).is_none());
        assert!(offer(None).is_none(), "unknown installed build: no guess");
    }

    #[test]
    fn a_withdrawn_installed_version_gets_a_safe_alternative_and_others_do_not() {
        let feed = feed();
        let alt = |channel, installed| {
            safe_alternative(
                &feed,
                "atlassoc",
                channel,
                "windows-x64",
                Kind::Auto,
                installed,
            )
        };
        assert_eq!(
            alt(Channel::Rc, "0.8.0-rc.2").unwrap().version,
            "0.8.0-rc.1"
        );
        assert_eq!(alt(Channel::Stable, "0.8.0-rc.2").unwrap().version, "0.7.0");
        assert!(
            alt(Channel::Rc, "0.7.0").is_none(),
            "not withdrawn: no alternative"
        );
    }

    #[test]
    fn leading_zeros_are_rejected_so_equal_versions_cannot_differ_as_text() {
        for bad in ["01.0.0", "1.00.0", "1.0.01", "0.8.0-rc.01"] {
            assert!(SemVer::parse(bad).is_none(), "{bad}");
        }
        assert!(SemVer::parse("0.0.0").is_some());
    }

    #[test]
    fn withdrawn_installed_version_is_reported() {
        let feed = feed();
        assert!(installed_is_withdrawn(&feed, "atlassoc", "0.8.0-rc.2"));
        assert!(!installed_is_withdrawn(&feed, "atlassoc", "0.7.0"));
    }

    #[test]
    fn download_urls_are_compared_by_parts_not_by_prefix() {
        let tags = ["atlassoc-v0.7.0", "atlassoc-v0.7.0-linux"];
        let good = "https://github.com/Ibert-Iam/threat-atlas/releases/download/atlassoc-v0.7.0/AtlasSOC-Setup-0.7.0.exe";
        let name = "AtlasSOC-Setup-0.7.0.exe";
        assert!(download_url_ok(good, &tags, name));
        let base = "https://github.com/Ibert-Iam/threat-atlas/releases/download/";
        for bad in [
            format!("{base}../../../evil/x/atlassoc-v0.7.0/{name}"),
            format!("{base}%2e%2e/%2e%2e/evil/atlassoc-v0.7.0/{name}"),
            format!("{base}atlassoc-v0.7.0/../{name}"),
            format!("https://github.com@evil.example/Ibert-Iam/threat-atlas/releases/download/atlassoc-v0.7.0/{name}"),
            format!("https://evil.example/Ibert-Iam/threat-atlas/releases/download/atlassoc-v0.7.0/{name}"),
            format!("https://github.com:8443/Ibert-Iam/threat-atlas/releases/download/atlassoc-v0.7.0/{name}"),
            format!("{good}?x=1"),
            format!("{good}#frag"),
            good.replace("https", "http"),
            good.replace("Ibert-Iam", "ibert-ai"),
            good.replace("Ibert-Iam", "other-org"),
            good.replacen('/', "\\", 3),
            "https://github.com/Ibert-Iam/threat-atlas/releases/download/atlassoc-v9.9.9/AtlasSOC-Setup-0.7.0.exe".to_string(),
        ] {
            assert!(!download_url_ok(&bad, &tags, name), "{bad}");
        }
        assert!(!download_url_ok(good, &tags, "Other.exe"));
    }

    #[test]
    fn a_feed_with_one_bad_asset_is_rejected_whole() {
        let url = "/products/atlassoc/releases/0/assets/0/url";
        let old_owner = mutated(|v| {
            let text = v
                .pointer(url)
                .unwrap()
                .as_str()
                .unwrap()
                .replace("Ibert-Iam", "ibert-ai");
            set(v, url, text.into());
        });
        let bad_hash = mutated(|v| {
            set(
                v,
                "/products/atlassoc/releases/0/assets/0/sha256",
                "Z".into(),
            )
        });
        let zero_size =
            mutated(|v| set(v, "/products/atlassoc/releases/0/assets/0/size", 0.into()));
        let huge = mutated(|v| {
            set(
                v,
                "/products/atlassoc/releases/0/assets/0/size",
                (MAX_ASSET_BYTES + 1).into(),
            )
        });
        for bad in [old_owner, bad_hash, zero_size, huge] {
            assert!(matches!(parse_feed(&bad), Err(FeedError::Invalid(_))));
        }
        assert!(parse_feed(SAMPLE.as_bytes()).is_ok());
    }

    #[test]
    fn oversized_wrong_schema_and_garbage_feeds_are_rejected() {
        assert_eq!(
            parse_feed(&vec![b' '; MAX_FEED_BYTES + 1]),
            Err(FeedError::TooLarge)
        );
        assert_eq!(parse_feed(b"not json"), Err(FeedError::Syntax));
        assert_eq!(
            parse_feed(br#"{"schema_version":2,"products":{}}"#),
            Err(FeedError::Schema)
        );
        assert!(parse_feed(br#"{"schema_version":1}"#).is_ok());
    }

    #[test]
    fn channel_and_version_must_agree() {
        let bad = mutated(|v| set(v, "/products/atlassoc/releases/0/channel", "stable".into()));
        assert!(matches!(parse_feed(&bad), Err(FeedError::Invalid(_))));
    }

    #[test]
    fn channel_parsing_and_default() {
        assert_eq!(Channel::default(), Channel::Stable);
        for c in [Channel::Stable, Channel::Rc, Channel::Beta] {
            assert_eq!(Channel::parse(c.as_str()), Some(c));
        }
        assert!(Channel::parse("nightly").is_none());
    }
}
