//! UI language catalog shared by the native hosts.
//!
//! The JSON file beside this crate is the single source of truth. English is the
//! default and the fallback when a language or key is missing. Documentation is
//! intentionally not translated.

use serde::{Deserialize, Serialize};
use serde_json;
use std::{collections::HashMap, sync::OnceLock};

pub const LANGUAGES: [&str; 5] = ["en", "sv", "de", "es", "it"];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    #[default]
    En,
    Sv,
    De,
    Es,
    It,
}

impl Language {
    pub fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Sv => "sv",
            Self::De => "de",
            Self::Es => "es",
            Self::It => "it",
        }
    }

    pub fn from_code(code: &str) -> Self {
        match code.to_ascii_lowercase().as_str() {
            "sv" => Self::Sv,
            "de" => Self::De,
            "es" => Self::Es,
            "it" => Self::It,
            _ => Self::En,
        }
    }

    pub fn is_english(&self) -> bool {
        *self == Self::En
    }

    /// Endonym shown in the language selector, independent of the current UI language.
    pub fn native_name(self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Sv => "Svenska",
            Self::De => "Deutsch",
            Self::Es => "Español",
            Self::It => "Italiano",
        }
    }
}

type Catalog = HashMap<String, HashMap<String, String>>;

static CATALOG: OnceLock<Catalog> = OnceLock::new();

fn catalog() -> &'static Catalog {
    CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("../i18n/ui.json"))
            .expect("embedded UI language catalog is valid JSON")
    })
}

/// Look up a UI string. Missing language or key falls back to English; a key
/// missing everywhere returns an empty string so callers can keep a literal.
pub fn tr(lang: Language, key: &str) -> &'static str {
    let catalog = catalog();
    if let Some(value) = catalog.get(lang.code()).and_then(|map| map.get(key)) {
        return value.as_str();
    }
    if let Some(value) = catalog.get("en").and_then(|map| map.get(key)) {
        return value.as_str();
    }
    ""
}

pub fn tr_code(code: &str, key: &str) -> &'static str {
    tr(Language::from_code(code), key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_english_key_exists_in_every_language() {
        let catalog = catalog();
        let english = catalog.get("en").expect("English catalog");
        assert!(!english.is_empty());
        for code in LANGUAGES {
            let language = catalog
                .get(code)
                .unwrap_or_else(|| panic!("{code} catalog"));
            for key in english.keys() {
                let value = language
                    .get(key)
                    .unwrap_or_else(|| panic!("{code} is missing {key}"));
                assert!(!value.trim().is_empty(), "{code} has an empty {key}");
            }
        }
    }

    #[test]
    fn unknown_values_fall_back_to_english() {
        assert_eq!(tr_code("xx", "sheet.done"), "Done");
        assert_eq!(tr(Language::De, "not-a-key"), "");
        assert_eq!(Language::from_code("XX"), Language::En);
    }

    #[test]
    fn language_codes_and_native_names_are_stable() {
        assert_eq!(Language::from_code("sv"), Language::Sv);
        assert_eq!(Language::from_code("DE"), Language::De);
        assert_eq!(Language::It.code(), "it");
        assert_eq!(Language::It.native_name(), "Italiano");
        assert_eq!(LANGUAGES.len(), 5);
    }
}
