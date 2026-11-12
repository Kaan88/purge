//! Loaders for the two knowledge-base files the identity code needs (§5.4):
//!
//! - `kb/generic-tokens.json`: a JSON array of name tokens that are too generic to identify an app
//!   (`update`, `helper`, `tools`, …). The tokenizer classes them as [`TokenClass::Generic`].
//! - `kb/mega-vendors.json`: a JSON array of `{ "vendor": …, "aliases": [...] }` objects naming publishers
//!   with many unrelated products. A vendor-only match on such a publisher weighs 0 and name matching needs
//!   two distinctive tokens. The rule for membership is "many unrelated products under one publisher name";
//!   Mozilla is deliberately absent (Firefox and Thunderbird are told apart by tokens and anchors).
//!
//! Both files are compiled in with `include_str!` and validated on load: every entry must already be in
//! normalised form (lowercase, see [`normalize`]) and must not repeat. The shipped data is checked by a unit
//! test, so [`Kb::shipped`] cannot fail at run time.
//!
//! [`TokenClass::Generic`]: crate::tokenizer::TokenClass::Generic

use std::collections::BTreeSet;
use std::fmt;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::tokenizer::{lex, normalize, vendor_key};

const GENERIC_TOKENS_JSON: &str = include_str!("../../../kb/generic-tokens.json");
const MEGA_VENDORS_JSON: &str = include_str!("../../../kb/mega-vendors.json");

/// Why a knowledge-base file was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KbDataError {
    /// The file is not valid JSON of the expected shape.
    Json(String),
    /// An entry is empty.
    Empty,
    /// An entry is not in normalised form (lowercase NFKC, and for vendors: no legal suffix or punctuation).
    NotNormalized(String),
    /// A generic token contains whitespace or would be split or dropped by the tokenizer.
    NotASingleToken(String),
    /// An entry appears twice (for vendors: across all names and aliases).
    Duplicate(String),
}

impl fmt::Display for KbDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(e) => write!(f, "invalid JSON: {e}"),
            Self::Empty => write!(f, "empty entry"),
            Self::NotNormalized(s) => write!(f, "entry {s:?} is not in normalised form"),
            Self::NotASingleToken(s) => write!(f, "entry {s:?} is not a single token"),
            Self::Duplicate(s) => write!(f, "duplicate entry {s:?}"),
        }
    }
}

impl std::error::Error for KbDataError {}

/// The set of generic name tokens (`kb/generic-tokens.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GenericTokens(BTreeSet<String>);

impl GenericTokens {
    /// An empty set: no token is generic.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parses and validates a JSON array of tokens.
    pub fn from_json(json: &str) -> Result<Self, KbDataError> {
        let raw: Vec<String> =
            serde_json::from_str(json).map_err(|e| KbDataError::Json(e.to_string()))?;
        Self::from_tokens(raw)
    }

    /// Validates a list of tokens: each non-empty, normalised, a single token, and unique.
    pub fn from_tokens<I, S>(tokens: I) -> Result<Self, KbDataError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut set = BTreeSet::new();
        for token in tokens {
            let token: String = token.into();
            if token.is_empty() {
                return Err(KbDataError::Empty);
            }
            if normalize(&token) != token {
                return Err(KbDataError::NotNormalized(token));
            }
            let lexed = lex(&token);
            if lexed.len() != 1 || lexed[0].text != token {
                return Err(KbDataError::NotASingleToken(token));
            }
            if set.contains(&token) {
                return Err(KbDataError::Duplicate(token));
            }
            set.insert(token);
        }
        Ok(Self(set))
    }

    /// Whether `token` (already normalised) is generic.
    pub fn contains(&self, token: &str) -> bool {
        self.0.contains(token)
    }

    /// Number of tokens.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The tokens in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }
}

/// One entry of `kb/mega-vendors.json`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MegaVendor {
    /// The vendor's usual name as a vendor key (see [`vendor_key`]), e.g. `microsoft`.
    pub vendor: String,
    /// Other vendor keys the same publisher goes by, e.g. `advanced micro devices` for `amd`.
    #[serde(default)]
    pub aliases: Vec<String>,
}

/// The mega-vendor list (`kb/mega-vendors.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MegaVendors {
    entries: Vec<MegaVendor>,
    keys: BTreeSet<String>,
}

impl MegaVendors {
    /// An empty list: no publisher is a mega-vendor.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parses and validates the JSON array of [`MegaVendor`] entries.
    pub fn from_json(json: &str) -> Result<Self, KbDataError> {
        let entries: Vec<MegaVendor> =
            serde_json::from_str(json).map_err(|e| KbDataError::Json(e.to_string()))?;
        Self::from_entries(entries)
    }

    /// Validates entries: every name and alias is a non-empty vendor key and appears only once overall.
    pub fn from_entries(entries: Vec<MegaVendor>) -> Result<Self, KbDataError> {
        let mut keys = BTreeSet::new();
        for entry in &entries {
            for name in std::iter::once(&entry.vendor).chain(&entry.aliases) {
                if name.is_empty() {
                    return Err(KbDataError::Empty);
                }
                if vendor_key(name) != *name {
                    return Err(KbDataError::NotNormalized(name.clone()));
                }
                if !keys.insert(name.clone()) {
                    return Err(KbDataError::Duplicate(name.clone()));
                }
            }
        }
        Ok(Self { entries, keys })
    }

    /// Whether a publisher or vendor name (raw, e.g. `Microsoft Corporation`) is a mega-vendor: its vendor
    /// key is a listed key, or starts with one at a token boundary (`Oracle and/or its affiliates`,
    /// `Adobe Systems Software Ireland Ltd`, `Microsoft Open Technologies`). The prefix rule can only make
    /// matching stricter for a publisher that merely shares the first word.
    pub fn is_mega(&self, vendor: &str) -> bool {
        let key = vendor_key(vendor);
        self.keys.iter().any(|k| {
            key.strip_prefix(k.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
        })
    }

    /// Whether an already computed vendor key is a mega-vendor.
    pub fn contains_key(&self, key: &str) -> bool {
        self.keys.contains(key)
    }

    /// The validated entries, in file order.
    pub fn entries(&self) -> &[MegaVendor] {
        &self.entries
    }
}

/// The knowledge-base data the tokenizer and matcher need.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Kb {
    /// Generic name tokens.
    pub generic: GenericTokens,
    /// Mega-vendors.
    pub mega_vendors: MegaVendors,
}

impl Kb {
    /// Parses the two compiled-in files. Fails only if the shipped data is invalid.
    pub fn load_shipped() -> Result<Self, KbDataError> {
        Ok(Self {
            generic: GenericTokens::from_json(GENERIC_TOKENS_JSON)?,
            mega_vendors: MegaVendors::from_json(MEGA_VENDORS_JSON)?,
        })
    }

    /// The compiled-in data, parsed once.
    ///
    /// # Panics
    /// If the shipped files are invalid, which the `shipped_data_is_valid` unit test rules out.
    pub fn shipped() -> &'static Kb {
        static KB: OnceLock<Kb> = OnceLock::new();
        KB.get_or_init(|| Self::load_shipped().expect("shipped kb token data is valid"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_data_is_valid() {
        let kb = Kb::load_shipped().expect("shipped data");
        assert!(kb.generic.len() > 20);
        for t in [
            "update", "updater", "helper", "launcher", "service", "data", "config", "common",
            "bin", "app", "install", "tools", "plugins",
        ] {
            assert!(kb.generic.contains(t), "{t}");
        }
        // `setup` is a stopword of the tokenizer, not a kb token; `code` and `studio` are product words.
        for t in ["setup", "code", "studio", "git", "firefox"] {
            assert!(!kb.generic.contains(t), "{t}");
        }
        assert_eq!(Kb::shipped(), &kb);
    }

    #[test]
    fn shipped_mega_vendors() {
        let mv = &Kb::shipped().mega_vendors;
        for v in [
            "Microsoft Corporation",
            "Microsoft",
            "Google LLC",
            "Google Inc.",
            "Adobe Inc.",
            "Adobe Systems Incorporated",
            "Oracle Corporation",
            "Apple Inc.",
            "Intel Corporation",
            "Intel(R) Corporation",
            "NVIDIA Corporation",
            "Advanced Micro Devices, Inc.",
            "ＭＩＣＲＯＳＯＦＴ　Corporation",
            "Oracle and/or its affiliates",
            "Adobe Systems Software Ireland Ltd",
            "Microsoft Open Technologies, Inc.",
        ] {
            assert!(mv.is_mega(v), "{v}");
        }
        for v in [
            "Mozilla",
            "Mozilla Corporation",
            "Valve Corporation",
            "Igor Pavlov",
            "",
            "Micro",
            "Microsofty",
            "Applesoft",
            "The Not Google Company",
        ] {
            assert!(!mv.is_mega(v), "{v}");
        }
    }

    #[test]
    fn generic_tokens_validation() {
        assert!(matches!(
            GenericTokens::from_json("{}"),
            Err(KbDataError::Json(_))
        ));
        assert_eq!(GenericTokens::from_tokens([""]), Err(KbDataError::Empty));
        assert_eq!(
            GenericTokens::from_tokens(["Update"]),
            Err(KbDataError::NotNormalized("Update".into()))
        );
        assert_eq!(
            GenericTokens::from_tokens(["add on"]),
            Err(KbDataError::NotASingleToken("add on".into()))
        );
        assert_eq!(
            GenericTokens::from_tokens(["add-on"]),
            Err(KbDataError::NotASingleToken("add-on".into()))
        );
        assert_eq!(
            GenericTokens::from_tokens(["update", "helper", "update"]),
            Err(KbDataError::Duplicate("update".into()))
        );
        let ok = GenericTokens::from_json(r#"["update","helper"]"#).unwrap();
        assert_eq!(ok.iter().collect::<Vec<_>>(), ["helper", "update"]);
        assert!(GenericTokens::empty().is_empty());
    }

    #[test]
    fn mega_vendor_validation() {
        let e = |json: &str| MegaVendors::from_json(json).unwrap_err();
        assert!(matches!(
            e(r#"[{"vendor":"a","alias":[]}]"#),
            KbDataError::Json(_)
        ));
        assert_eq!(e(r#"[{"vendor":""}]"#), KbDataError::Empty);
        assert_eq!(
            e(r#"[{"vendor":"Microsoft"}]"#),
            KbDataError::NotNormalized("Microsoft".into())
        );
        assert_eq!(
            e(r#"[{"vendor":"microsoft corporation"}]"#),
            KbDataError::NotNormalized("microsoft corporation".into())
        );
        assert_eq!(
            e(
                r#"[{"vendor":"amd","aliases":["advanced micro devices"]},{"vendor":"advanced micro devices"}]"#
            ),
            KbDataError::Duplicate("advanced micro devices".into())
        );
        let ok =
            MegaVendors::from_json(r#"[{"vendor":"amd","aliases":["advanced micro devices"]}]"#)
                .unwrap();
        assert_eq!(ok.entries().len(), 1);
        assert!(
            ok.contains_key("amd") && ok.is_mega("AMD") && !MegaVendors::empty().is_mega("AMD")
        );
    }
}
