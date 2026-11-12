//! Name and vendor matching for one app (ENGINE_PLAN §5.4, steps 6 to 9, and the mega-vendor rule).
//!
//! An [`AppMatcher`] is built once per app from its names and vendors, either against the installed-apps
//! [`Corpus`] ([`AppMatcher::build`]) or from the token set stored in a fingerprint
//! ([`AppMatcher::from_parts`], so a scan after the uninstall matches exactly as the harvest did). It then
//! answers, for one path or key **segment** (a folder or key name, never a whole path):
//!
//! - [`AppMatcher::match_name`]: whole-token match → `NameTokenExact`;
//! - [`AppMatcher::match_full_name`]: the segment is the app's full name → `ExactFullName`;
//! - [`AppMatcher::match_product_subfolder`]: `<VendorAlias>\<ProductToken>` → `ProductSubfolderOfVendor`;
//! - [`AppMatcher::match_vendor`]: the segment is a vendor alias → `VendorContainer` (weight 0 for a
//!   mega-vendor).
//!
//! # Rules
//!
//! **Product tokens.** For each name: its significant tokens (tokenizer steps 1 to 4), minus tokens the
//! [`Corpus`] calls common (step 5), minus the vendor: when the name starts with one of the app's vendor
//! keys (`Mozilla Firefox` by `Mozilla`), that prefix is not a product token. Only when the name **is**
//! the vendor key and the vendor is not a mega-vendor is the unstripped set used (`Zotero` by `Zotero`).
//! A name that is the vendor plus generic words only (`Mozilla Maintenance Service` by `Mozilla`,
//! `Docker Desktop` by `Docker`) has no product token: it must not turn the vendor folder, which other
//! products share, into a name match. For a mega-vendor every vendor token is removed wherever it stands.
//!
//! **Vendors.** A vendor string whose key is made of generic tokens only (`Software Inc.`, `Tools`) is
//! ignored: it would make folders such as `Software` look like the vendor container. A vendor is a
//! mega-vendor when its key is, or starts with, a listed key (see [`MegaVendors::is_mega`]).
//!
//! **Segments.** Every `match_*` function takes one segment. A string containing a backslash is a path,
//! not a segment, and never matches (its tokens would be the union of several folder names).
//!
//! [`MegaVendors::is_mega`]: crate::kbdata::MegaVendors::is_mega
//!
//! **Distinctiveness (step 6).** A name is usable only with at least [`MIN_TOKENS`] product token
//! ([`MIN_TOKENS_MEGA_VENDOR`] when a vendor is a mega-vendor). The threshold is applied per name, which
//! is at least as strict as applying it to the app as a whole. With no usable name the app is
//! [`NameMatching::Disabled`]: the three name-based matches never fire and [`AppMatcher::tokens`] is empty.
//!
//! **Whole tokens (step 7).** A segment matches a name when its significant tokens include **every**
//! product token and contain nothing foreign: each must be a token of that name or of a vendor. Generic
//! tokens, stopwords and noise in the segment are ignored. So `Notepad++` and `Notepad` never match each
//! other, `Firefox` does not match `Firefox Developer Edition`, and `Mozilla Firefox` matches both
//! `Firefox` and `Mozilla Firefox`.
//!
//! **Short names (step 8).** When the product tokens of a name add up to [`SHORT_NAME_MAX_CHARS`]
//! characters or fewer (`Git`, `Code`, `7-Zip`), the name matches only through
//! [`AppMatcher::match_full_name`], and the result carries `needs_tier_ab_neighbour`: the caller may use
//! it only next to Tier A/B evidence. The plan text says "3 characters or fewer" but names `Code` as an
//! example, so the bound is 4.
//!
//! **Sift4 (step 9)** never decides a match. [`NameMatch::distance`] is the Sift4 distance between the
//! segment's and the name's full-name keys; it picks the closest of several matching names and lets
//! callers order equal candidates with [`order_ties`].

use std::collections::BTreeSet;

use purge_model::EvidenceKind;

use crate::kbdata::Kb;
use crate::sift4;
use crate::tokenizer::{Corpus, TokenClass, full_name_key, tokenize, vendor_key};

/// Distinctive tokens a name needs for name-based evidence.
pub const MIN_TOKENS: usize = 1;
/// Distinctive tokens a name needs when the publisher is a mega-vendor.
pub const MIN_TOKENS_MEGA_VENDOR: usize = 2;
/// Product tokens of this total length or shorter match only as an exact full name.
pub const SHORT_NAME_MAX_CHARS: usize = 4;

/// Whether name-based evidence (`NameTokenExact`, `ExactFullName`, `ProductSubfolderOfVendor`) is
/// available for an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameMatching {
    /// At least one name has enough distinctive tokens.
    Enabled,
    /// Too few distinctive tokens: no name-based evidence for this app.
    Disabled,
}

/// Which name rule matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameMatchKind {
    /// Every product token, as whole tokens.
    TokenExact,
    /// The segment's full-name key equals the name's.
    ExactFullName,
    /// A whole-token match directly under a vendor-alias segment.
    ProductSubfolder,
}

impl NameMatchKind {
    /// The §5.3 evidence kind this match supports.
    pub fn evidence_kind(self) -> EvidenceKind {
        match self {
            Self::TokenExact => EvidenceKind::NameTokenExact,
            Self::ExactFullName => EvidenceKind::ExactFullName,
            Self::ProductSubfolder => EvidenceKind::ProductSubfolderOfVendor,
        }
    }
}

/// A name-based match of one segment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NameMatch {
    /// The rule that matched.
    pub kind: NameMatchKind,
    /// The app name that matched, as given to the matcher.
    pub name: String,
    /// The name is short (step 8): only valid next to Tier A or Tier B evidence on the same target.
    pub needs_tier_ab_neighbour: bool,
    /// Sift4 distance between the segment and the name (full-name keys). Ordering only.
    pub distance: usize,
}

impl NameMatch {
    /// The §5.3 evidence kind.
    pub fn evidence_kind(&self) -> EvidenceKind {
        self.kind.evidence_kind()
    }

    /// The §5.3 weight of that kind.
    pub fn weight(&self) -> i8 {
        self.evidence_kind().default_weight()
    }
}

/// A segment that is one of the app's vendor aliases.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VendorMatch {
    /// The vendor key that matched (see [`vendor_key`]).
    pub alias: String,
    /// The app's vendor is a mega-vendor: this match weighs 0.
    pub mega_vendor: bool,
}

impl VendorMatch {
    /// Always `VendorContainer`.
    pub fn evidence_kind(&self) -> EvidenceKind {
        EvidenceKind::VendorContainer
    }

    /// The `VendorContainer` weight, or 0 for a mega-vendor.
    pub fn weight(&self) -> i8 {
        if self.mega_vendor {
            EvidenceKind::MEGA_VENDOR_WEIGHT
        } else {
            EvidenceKind::VendorContainer.default_weight()
        }
    }
}

/// One usable name of the app.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NameSpec {
    name: String,
    full_key: String,
    /// Tokens a segment must contain.
    product: BTreeSet<String>,
    /// Tokens a segment may contain: every non-noise token of the name, plus the vendor tokens.
    allowed: BTreeSet<String>,
    short: bool,
}

/// The name and vendor matcher of one app; see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppMatcher<'kb> {
    kb: &'kb Kb,
    names: Vec<NameSpec>,
    vendors: Vec<String>,
    mega_vendor: bool,
}

impl<'kb> AppMatcher<'kb> {
    /// Builds the matcher at harvest time: the IDF rule comes from `corpus`, which must already contain
    /// this app.
    pub fn build<N, V>(names: &[N], vendors: &[V], corpus: &Corpus, kb: &'kb Kb) -> Self
    where
        N: AsRef<str>,
        V: AsRef<str>,
    {
        let mega = vendors.iter().any(|v| kb.mega_vendors.is_mega(v.as_ref()));
        Self::assemble(names, vendors, mega, kb, &|t| !corpus.is_common(t))
    }

    /// Rebuilds the matcher from stored parts (`IdentitySnapshot`): only `tokens` count as distinctive, and
    /// an empty `tokens` means name matching is disabled. The stored `mega_vendor` flag can only add
    /// strictness: a vendor the current knowledge base lists is a mega-vendor even when the flag is `false`.
    pub fn from_parts<N, V, T>(
        names: &[N],
        vendors: &[V],
        tokens: &[T],
        mega_vendor: bool,
        kb: &'kb Kb,
    ) -> Self
    where
        N: AsRef<str>,
        V: AsRef<str>,
        T: AsRef<str>,
    {
        let keep: BTreeSet<&str> = tokens.iter().map(AsRef::as_ref).collect();
        let mega = mega_vendor || vendors.iter().any(|v| kb.mega_vendors.is_mega(v.as_ref()));
        Self::assemble(names, vendors, mega, kb, &|t| keep.contains(t))
    }

    fn assemble<N, V>(
        names: &[N],
        vendors: &[V],
        mega_vendor: bool,
        kb: &'kb Kb,
        distinctive: &dyn Fn(&str) -> bool,
    ) -> Self
    where
        N: AsRef<str>,
        V: AsRef<str>,
    {
        let mut vendor_keys: Vec<String> = Vec::new();
        for v in vendors {
            let key = vendor_key(v.as_ref());
            // A key of generic words only (`software`, `tools`) names no vendor.
            let only_generic = key.split(' ').all(|t| kb.generic.contains(t));
            if !key.is_empty() && !only_generic && !vendor_keys.contains(&key) {
                vendor_keys.push(key);
            }
        }
        let vendor_tokens: BTreeSet<String> = vendor_keys
            .iter()
            .flat_map(|k| k.split(' ').map(str::to_owned))
            .collect();
        let min = if mega_vendor {
            MIN_TOKENS_MEGA_VENDOR
        } else {
            MIN_TOKENS
        };

        let mut specs: Vec<NameSpec> = Vec::new();
        for name in names {
            let name = name.as_ref();
            let tokens = tokenize(name, &kb.generic);
            // The name without noise and stopwords: the sequence a vendor key can be a prefix of.
            let words: Vec<_> = tokens
                .iter()
                .filter(|t| t.class > TokenClass::Stopword)
                .collect();
            let prefix = vendor_keys
                .iter()
                .map(|k| k.split(' ').collect::<Vec<_>>())
                .filter(|k| {
                    k.len() <= words.len() && k.iter().zip(&words).all(|(a, b)| *a == b.text)
                })
                .map(|k| k.len())
                .max()
                .unwrap_or(0);
            let product_from = |skip: usize| -> BTreeSet<String> {
                words
                    .iter()
                    .skip(skip)
                    .filter(|t| t.class == TokenClass::Significant && distinctive(&t.text))
                    .filter(|t| !(mega_vendor && vendor_tokens.contains(&t.text)))
                    .map(|t| t.text.clone())
                    .collect()
            };
            let mut product = product_from(prefix);
            // The name is exactly the vendor (`Zotero` by `Zotero`). Vendor plus generic words is not
            // enough: that would make the shared vendor folder a name match.
            if product.is_empty() && !mega_vendor && prefix > 0 && prefix == words.len() {
                product = product_from(0);
            }
            let full_key = full_name_key(name);
            if product.len() < min || full_key.is_empty() {
                continue;
            }
            if specs.iter().any(|s| s.full_key == full_key) {
                continue;
            }
            let short =
                product.iter().map(|t| t.chars().count()).sum::<usize>() <= SHORT_NAME_MAX_CHARS;
            let allowed = tokens
                .iter()
                .filter(|t| t.class != TokenClass::Noise)
                .map(|t| t.text.clone())
                .chain(vendor_tokens.iter().cloned())
                .collect();
            specs.push(NameSpec {
                name: name.to_owned(),
                full_key,
                product,
                allowed,
                short,
            });
        }
        Self {
            kb,
            names: specs,
            vendors: vendor_keys,
            mega_vendor,
        }
    }

    /// Whether name-based evidence is available (step 6).
    pub fn name_matching(&self) -> NameMatching {
        if self.names.is_empty() {
            NameMatching::Disabled
        } else {
            NameMatching::Enabled
        }
    }

    /// The distinctive tokens of all usable names, sorted; empty when name matching is disabled. This is
    /// what the fingerprint's identity snapshot stores.
    pub fn tokens(&self) -> Vec<String> {
        let all: BTreeSet<&String> = self.names.iter().flat_map(|s| &s.product).collect();
        all.into_iter().cloned().collect()
    }

    /// Whether one of the app's vendors is a mega-vendor.
    pub fn mega_vendor(&self) -> bool {
        self.mega_vendor
    }

    /// The app's vendor keys, in the order given, without duplicates.
    pub fn vendor_keys(&self) -> &[String] {
        &self.vendors
    }

    fn token_match(&self, segment: &str, kind: NameMatchKind) -> Option<NameMatch> {
        if is_path(segment) {
            return None;
        }
        let seg: BTreeSet<String> = tokenize(segment, &self.kb.generic)
            .into_iter()
            .filter(|t| t.class == TokenClass::Significant)
            .map(|t| t.text)
            .collect();
        if seg.is_empty() {
            return None;
        }
        let seg_key = full_name_key(segment);
        self.names
            .iter()
            .filter(|s| !s.short && s.product.is_subset(&seg) && seg.is_subset(&s.allowed))
            .map(|s| NameMatch {
                kind,
                name: s.name.clone(),
                needs_tier_ab_neighbour: false,
                distance: sift4::distance(&seg_key, &s.full_key),
            })
            .min_by_key(|m| m.distance)
    }

    /// Whole-token match of a segment (`NameTokenExact`). Never fires for short names.
    pub fn match_name(&self, segment: &str) -> Option<NameMatch> {
        self.token_match(segment, NameMatchKind::TokenExact)
    }

    /// The segment is the app's full name (`ExactFullName`): equal full-name keys, so versions,
    /// architecture and locale tags do not matter but every word does. For a short name the result has
    /// `needs_tier_ab_neighbour` set.
    pub fn match_full_name(&self, segment: &str) -> Option<NameMatch> {
        if is_path(segment) {
            return None;
        }
        let seg_key = full_name_key(segment);
        self.names
            .iter()
            .find(|s| s.full_key == seg_key)
            .map(|s| NameMatch {
                kind: NameMatchKind::ExactFullName,
                name: s.name.clone(),
                needs_tier_ab_neighbour: s.short,
                distance: 0,
            })
    }

    /// `<VendorAlias>\<ProductToken>` (`ProductSubfolderOfVendor`): `vendor_segment` is one of the app's
    /// vendor aliases and `product_segment`, directly below it, is a whole-token match.
    pub fn match_product_subfolder(
        &self,
        vendor_segment: &str,
        product_segment: &str,
    ) -> Option<NameMatch> {
        self.match_vendor(vendor_segment)?;
        self.token_match(product_segment, NameMatchKind::ProductSubfolder)
    }

    /// The segment is one of the app's vendor aliases (`VendorContainer`). Independent of
    /// [`NameMatching`]; for a mega-vendor the match weighs 0.
    pub fn match_vendor(&self, segment: &str) -> Option<VendorMatch> {
        if is_path(segment) {
            return None;
        }
        let key = vendor_key(segment);
        self.vendors
            .iter()
            .find(|v| **v == key)
            .map(|alias| VendorMatch {
                alias: alias.clone(),
                mega_vendor: self.mega_vendor,
            })
    }
}

/// A string with a backslash is a path, not one segment.
fn is_path(segment: &str) -> bool {
    segment.contains('\\')
}

/// Orders candidates that are otherwise equal by their Sift4 distance to `reference` (closest first),
/// comparing full-name keys. The sort is stable, so callers sort by their real criteria first.
pub fn order_ties<T>(reference: &str, candidates: &mut [T], text: impl Fn(&T) -> &str) {
    let reference = full_name_key(reference);
    candidates.sort_by_cached_key(|c| sift4::distance(&reference, &full_name_key(text(c))));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (DisplayName, Publisher) pairs.
    type Apps = &'static [(&'static str, &'static str)];

    fn corpus(apps: Apps) -> Corpus {
        Corpus::from_apps(apps.iter().map(|(n, p)| [*n, *p]))
    }

    fn matcher(apps: Apps, name: &str) -> AppMatcher<'static> {
        let (n, p) = apps
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("{name} not in corpus"));
        AppMatcher::build(&[*n], &[*p], &corpus(apps), Kb::shipped())
    }

    fn solo<'a>(names: &[&str], vendors: &[&str]) -> AppMatcher<'a> {
        let mut c = Corpus::new();
        c.add_app(names.iter().chain(vendors));
        AppMatcher::build(names, vendors, &c, Kb::shipped())
    }

    /// Every VC++ redistributable generation installed side by side (inline copy of real ARP names).
    const VCREDISTS: Apps = &[
        (
            "Microsoft Visual C++ 2005 Redistributable",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2005 Redistributable (x64)",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2008 Redistributable - x64 9.0.30729.6161",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2010  x86 Redistributable - 10.0.40219",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2012 Redistributable (x86) - 11.0.61030",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2012 Redistributable (x64) - 11.0.61030",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2012 x64 Minimum Runtime - 11.0.61030",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2012 x64 Additional Runtime - 11.0.61030",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2013 Redistributable (x86) - 12.0.40664",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2013 Redistributable (x64) - 12.0.40664",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2013 x64 Minimum Runtime - 12.0.40664",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2013 x64 Additional Runtime - 12.0.40664",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.44.35211",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.44.35211",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.44.35211",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2022 X64 Additional Runtime - 14.44.35211",
            "Microsoft Corporation",
        ),
        (
            "Microsoft Visual C++ 2022 X86 Debug Runtime - 14.44.35211",
            "Microsoft Corporation",
        ),
    ];

    /// The dirty-base VM's ARP list (inline copy of the `arp` names in `vm/truth/dirty-base.json`, with the
    /// publishers from the installers' signatures; the Python component lists are abridged).
    const DIRTY_BASE: Apps = &[
        ("Mozilla Thunderbird (x64 en-US) 160.0", "Mozilla"),
        ("Mozilla Maintenance Service", "Mozilla"),
        ("NVDA 2026.3.1", "NV Access Limited"),
        ("Steam", "Valve Corporation"),
        ("Zotero 10.0.8", "Zotero"),
        (
            "Python 3.13.1 Standard Library (64-bit)",
            "Python Software Foundation",
        ),
        (
            "Python 3.13.1 Documentation (64-bit)",
            "Python Software Foundation",
        ),
        (
            "Python 3.13.1 pip Bootstrap (64-bit)",
            "Python Software Foundation",
        ),
        (
            "Python 3.13.1 Executables (64-bit)",
            "Python Software Foundation",
        ),
        (
            "Python 3.13.1 Add to Path (64-bit)",
            "Python Software Foundation",
        ),
        (
            "Python 3.13.1 Core Interpreter (64-bit)",
            "Python Software Foundation",
        ),
        (
            "Python 3.13.1 Tcl/Tk Support (64-bit)",
            "Python Software Foundation",
        ),
        (
            "Python 3.13.1 Development Libraries (64-bit)",
            "Python Software Foundation",
        ),
        ("Python 3.13.1 (64-bit)", "Python Software Foundation"),
        (
            "Python 3.11.9 Core Interpreter (64-bit)",
            "Python Software Foundation",
        ),
        (
            "Python 3.11.9 Utility Scripts (64-bit)",
            "Python Software Foundation",
        ),
        ("Python 3.11.9 (64-bit)", "Python Software Foundation"),
        ("Python Launcher", "Python Software Foundation"),
        ("Node.js", "Node.js Foundation"),
        ("Microsoft Visual Studio Code", "Microsoft Corporation"),
        ("Visual Studio Build Tools 2022", "Microsoft Corporation"),
    ];

    /// The same VM with the two entries the Visual Studio bootstrapper usually adds next to Build Tools.
    const DIRTY_BASE_WITH_VS_INSTALLER: Apps = &[
        ("Microsoft Visual Studio Code", "Microsoft Corporation"),
        ("Visual Studio Build Tools 2022", "Microsoft Corporation"),
        ("Microsoft Visual Studio Installer", "Microsoft Corporation"),
        (
            "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.44.35211",
            "Microsoft Corporation",
        ),
        ("Mozilla Thunderbird (x64 en-US) 160.0", "Mozilla"),
        ("Steam", "Valve Corporation"),
    ];

    const MOZILLA: Apps = &[
        ("Mozilla Firefox (x64 en-US)", "Mozilla"),
        ("Mozilla Thunderbird (x64 en-US) 160.0", "Mozilla"),
        ("Mozilla Maintenance Service", "Mozilla"),
        ("7-Zip 24.08 (x64)", "Igor Pavlov"),
    ];

    #[test]
    fn every_vc_redist_installed_together_disables_name_matching() {
        for (name, _) in VCREDISTS {
            let m = matcher(VCREDISTS, name);
            assert!(m.mega_vendor(), "{name}");
            assert_eq!(m.name_matching(), NameMatching::Disabled, "{name}");
            assert!(m.tokens().is_empty(), "{name}: {:?}", m.tokens());
            for seg in [
                *name,
                "Microsoft Visual C++",
                "Visual C++",
                "VC",
                "Microsoft",
                "Redistributable",
                "",
            ] {
                assert_eq!(m.match_name(seg), None, "{name} vs {seg}");
                assert_eq!(m.match_full_name(seg), None, "{name} vs {seg}");
                assert_eq!(
                    m.match_product_subfolder("Microsoft", seg),
                    None,
                    "{name} vs {seg}"
                );
            }
            // The vendor still matches, with weight 0.
            let v = m.match_vendor("Microsoft").expect("vendor");
            assert_eq!((v.weight(), v.mega_vendor), (0, true));
        }
    }

    /// Even alone, a redistributable has one distinctive token pair at most; with its x86 twin (two apps,
    /// below the IDF bound) `visual` and `c++` survive and matching stays strict about `c++`.
    #[test]
    fn two_vc_redists_keep_symbol_tokens() {
        let apps: Apps = &VCREDISTS[14..16];
        let m = matcher(apps, apps[0].0);
        assert_eq!(m.tokens(), ["c++", "visual"]);
        assert_eq!(m.match_name("Visual C"), None);
        assert_eq!(m.match_name("Visual Studio"), None);
        assert!(m.match_name("Microsoft Visual C++").is_some());
    }

    #[test]
    fn git_and_code_match_only_as_exact_full_names() {
        for (name, vendor) in [("Git", "The Git Development Community"), ("Code", "")] {
            let vendors: Vec<&str> = [vendor].into_iter().filter(|v| !v.is_empty()).collect();
            let m = solo(&[name], &vendors);
            assert_eq!(m.name_matching(), NameMatching::Enabled, "{name}");
            assert_eq!(m.tokens(), [name.to_lowercase()]);

            let full = m.match_full_name(name).expect("exact full name");
            assert_eq!(full.kind, NameMatchKind::ExactFullName);
            assert_eq!(full.evidence_kind(), EvidenceKind::ExactFullName);
            assert!(full.needs_tier_ab_neighbour, "{name}");
            assert!(m.match_full_name(&name.to_uppercase()).is_some());
            assert!(m.match_full_name(&format!("{name} 2.51.0 (x64)")).is_some());

            // Never as a token match, not even for the identical segment.
            assert_eq!(m.match_name(name), None, "{name}");
            for seg in [
                format!("{name}Hub"),
                format!("{name} Extensions"),
                format!("{name} for Windows"),
                format!("My {name}"),
                format!("{name}.Tools"),
                format!("Visual Studio {name}"),
            ] {
                assert_eq!(m.match_name(&seg), None, "{name} vs {seg}");
                assert_eq!(m.match_full_name(&seg), None, "{name} vs {seg}");
            }
        }
        let git = solo(&["Git"], &["The Git Development Community"]);
        assert_eq!(
            git.match_product_subfolder("Git Development Community", "Git"),
            None
        );
    }

    #[test]
    fn short_bound_is_on_product_tokens() {
        // `7-Zip` → {7, zip}: short. `Zip` alone is a different full name.
        let m = matcher(MOZILLA, "7-Zip 24.08 (x64)");
        assert_eq!(m.tokens(), ["7", "zip"]);
        assert_eq!(m.match_name("7-Zip"), None);
        assert!(
            m.match_full_name("7-Zip")
                .is_some_and(|x| x.needs_tier_ab_neighbour)
        );
        assert_eq!(m.match_full_name("Zip"), None);
        // Five characters is not short.
        let m = solo(&["Steam"], &["Valve Corporation"]);
        let hit = m.match_name("Steam").expect("token match");
        assert!(!hit.needs_tier_ab_neighbour);
        assert_eq!((hit.kind, hit.weight()), (NameMatchKind::TokenExact, 3));
        assert!(
            m.match_full_name("steam")
                .is_some_and(|x| !x.needs_tier_ab_neighbour && x.weight() == 4)
        );
        // `steamapps` is another token (regression list: Steam / steamapps).
        assert_eq!(m.match_name("steamapps"), None);
        assert_eq!(m.match_full_name("steamapps"), None);
    }

    #[test]
    fn notepad_plus_plus_never_matches_notepad() {
        let npp = solo(
            &["Notepad++ (64-bit x64)", "notepad++"],
            &["Notepad++ Team"],
        );
        assert_eq!(npp.tokens(), ["notepad++"]);
        for seg in [
            "Notepad",
            "notepad",
            "Notepad.lnk",
            "Notepad+",
            "Notepad 2",
            "Windows Notepad",
        ] {
            assert_eq!(npp.match_name(seg), None, "{seg}");
            assert_eq!(npp.match_full_name(seg), None, "{seg}");
            assert_eq!(
                npp.match_product_subfolder("Notepad++ Team", seg),
                None,
                "{seg}"
            );
        }
        assert!(npp.match_name("Notepad++").is_some());
        assert!(npp.match_name("Ｎｏｔｅｐａｄ＋＋").is_some());
        assert!(
            npp.match_name("Notepad++ Plugins").is_some(),
            "generic extras are ignored"
        );
        assert!(npp.match_full_name("NOTEPAD++").is_some());

        // And the other way round.
        let notepad = solo(&["Notepad"], &["Example Vendor"]);
        assert!(notepad.match_name("Notepad").is_some());
        assert_eq!(notepad.match_name("Notepad++"), None);
        assert_eq!(notepad.match_full_name("Notepad++"), None);
    }

    #[test]
    fn firefox_and_thunderbird_share_only_the_vendor() {
        let firefox = matcher(MOZILLA, "Mozilla Firefox (x64 en-US)");
        let thunderbird = matcher(MOZILLA, "Mozilla Thunderbird (x64 en-US) 160.0");
        assert_eq!(firefox.tokens(), ["firefox"]);
        assert_eq!(thunderbird.tokens(), ["thunderbird"]);
        assert!(!firefox.mega_vendor() && !thunderbird.mega_vendor());

        for (m, own, other) in [
            (&firefox, "Firefox", "Thunderbird"),
            (&thunderbird, "Thunderbird", "Firefox"),
        ] {
            assert!(m.match_name(own).is_some());
            assert!(m.match_name(&format!("Mozilla {own}")).is_some());
            assert!(m.match_full_name(&format!("Mozilla {own}")).is_some());
            let sub = m
                .match_product_subfolder("Mozilla", own)
                .expect("product subfolder");
            assert_eq!(sub.evidence_kind(), EvidenceKind::ProductSubfolderOfVendor);
            assert_eq!(sub.weight(), 3);

            assert_eq!(m.match_name(other), None);
            assert_eq!(m.match_name(&format!("Mozilla {other}")), None);
            assert_eq!(m.match_full_name(other), None);
            assert_eq!(m.match_full_name(&format!("Mozilla {other}")), None);
            assert_eq!(m.match_product_subfolder("Mozilla", other), None);
            assert_eq!(m.match_product_subfolder("Mozilla", "Mozilla"), None);
            assert_eq!(
                m.match_name("Mozilla"),
                None,
                "the vendor alone is not a name match"
            );
            assert_eq!(m.match_name("Mozilla Maintenance Service"), None);

            // Both share the vendor container, at the non-mega weight.
            let v = m.match_vendor("Mozilla").expect("vendor");
            assert_eq!(
                (v.alias.as_str(), v.weight(), v.mega_vendor),
                ("mozilla", 2, false)
            );
            assert_eq!(v.evidence_kind(), EvidenceKind::VendorContainer);
            assert!(m.match_vendor("Mozilla Corporation").is_some());
            assert_eq!(
                m.match_vendor("mozilla.org"),
                None,
                "aliases come from the caller"
            );
            assert_eq!(
                m.match_vendor("Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38"),
                None
            );
            assert_eq!(m.match_vendor(own), None);
        }
        // An extra product word is foreign: Firefox is not "Firefox Developer Edition" or "Firefox Nightly".
        assert_eq!(firefox.match_name("Firefox Developer Edition"), None);
        assert_eq!(firefox.match_name("Firefox Nightly"), None);
    }

    /// Documented outcome for VS Code (publisher Microsoft, a mega-vendor, so two distinctive tokens are
    /// needed and `microsoft` never counts):
    /// - corpus without other Visual Studio products → `visual`, `studio`, `code` → enabled;
    /// - dirty-base as captured (VS Code + Build Tools: `visual`/`studio` in 2 apps, not above the IDF
    ///   bound) → still enabled, and Build Tools' folders do not match because `code` is required;
    /// - dirty-base plus the Visual Studio Installer entry (3 apps) → only `code` survives → disabled.
    #[test]
    fn vs_code_under_a_mega_vendor() {
        const NAME: &str = "Microsoft Visual Studio Code";
        const CLEAN: Apps = &[
            (NAME, "Microsoft Corporation"),
            ("Mozilla Firefox (x64 en-US)", "Mozilla"),
            ("Steam", "Valve Corporation"),
        ];
        for apps in [CLEAN, DIRTY_BASE] {
            let m = matcher(apps, NAME);
            assert!(m.mega_vendor());
            assert_eq!(m.name_matching(), NameMatching::Enabled);
            assert_eq!(m.tokens(), ["code", "studio", "visual"]);
            assert!(m.match_name("Microsoft Visual Studio Code").is_some());
            assert!(m.match_name("Visual Studio Code").is_some());
            assert!(m.match_full_name("Microsoft Visual Studio Code").is_some());
            assert!(
                m.match_product_subfolder("Microsoft", "Visual Studio Code")
                    .is_some()
            );
            for seg in [
                "Code",
                "Visual Studio",
                "Visual Studio Build Tools",
                "Microsoft",
                "VSCode",
            ] {
                assert_eq!(m.match_name(seg), None, "{seg}");
                assert_eq!(m.match_full_name(seg), None, "{seg}");
            }
            assert_eq!(m.match_vendor("Microsoft").map(|v| v.weight()), Some(0));
        }

        let m = matcher(DIRTY_BASE_WITH_VS_INSTALLER, NAME);
        let c = corpus(DIRTY_BASE_WITH_VS_INSTALLER);
        assert!(c.is_common("visual") && c.is_common("studio") && !c.is_common("code"));
        assert_eq!(m.name_matching(), NameMatching::Disabled);
        assert!(m.tokens().is_empty());
        assert_eq!(m.match_name(NAME), None);
        assert_eq!(m.match_full_name(NAME), None);
        assert_eq!(
            m.match_product_subfolder("Microsoft", "Visual Studio Code"),
            None
        );

        // Build Tools itself: `build` is its own, `visual` and `studio` survive in dirty-base as captured.
        let bt = matcher(DIRTY_BASE, "Visual Studio Build Tools 2022");
        assert_eq!(bt.tokens(), ["build", "studio", "visual"]);
        assert_eq!(bt.match_name("Microsoft Visual Studio Code"), None);
    }

    #[test]
    fn dirty_base_python_components() {
        // `python` is in far more than two entries: it is common, and so is nothing else of
        // "Python 3.13.1 (64-bit)", which therefore has name matching disabled.
        let c = corpus(DIRTY_BASE);
        assert!(c.is_common("python") && !c.is_common("mozilla"));
        let bare = matcher(DIRTY_BASE, "Python 3.13.1 (64-bit)");
        assert_eq!(bare.name_matching(), NameMatching::Disabled);
        assert_eq!(bare.match_name("Python"), None);
        assert_eq!(bare.match_name("Python313"), None);
        assert_eq!(bare.match_full_name("Python 3.13.1 (64-bit)"), None);
        // The vendor container still matches (regression list: Python 3.12 + 3.13 share it).
        assert_eq!(
            bare.match_vendor("Python Software Foundation")
                .map(|v| v.weight()),
            Some(2)
        );

        // A component keeps only its own word and no longer matches a bare "Python" folder.
        let tcl = matcher(DIRTY_BASE, "Python 3.13.1 Tcl/Tk Support (64-bit)");
        assert_eq!(tcl.tokens(), ["tcl", "tk"]);
        assert_eq!(tcl.match_name("Python"), None);

        // Unrelated single-word apps are untouched by the corpus.
        for (name, seg) in [
            ("Steam", "Steam"),
            ("Zotero 10.0.8", "Zotero"),
            ("Mozilla Thunderbird (x64 en-US) 160.0", "Thunderbird"),
        ] {
            assert!(
                matcher(DIRTY_BASE, name).match_name(seg).is_some(),
                "{name}"
            );
        }
        // `NVDA` is four characters: exact full name only.
        let nvda = matcher(DIRTY_BASE, "NVDA 2026.3.1");
        assert_eq!(nvda.match_name("nvda"), None);
        assert!(
            nvda.match_full_name("nvda")
                .is_some_and(|m| m.needs_tier_ab_neighbour)
        );
    }

    #[test]
    fn dotnet_hosting_does_not_match_microsoft_net_folder() {
        // Regression list: ".NET Hosting vs Microsoft.NET". `.net` is not `net`, and the app is disabled
        // anyway under the mega-vendor rule unless two distinctive tokens remain.
        let m = solo(
            &["Microsoft .NET Host FX Resolver - 8.0.11 (x64)"],
            &["Microsoft Corporation"],
        );
        assert_eq!(m.tokens(), [".net", "fx", "host", "resolver"]);
        assert_eq!(m.match_name("Microsoft.NET"), None);
        assert_eq!(m.match_full_name("Microsoft.NET"), None);
        assert_eq!(
            m.match_product_subfolder("Microsoft", "Microsoft.NET"),
            None
        );
        let m = solo(
            &["Microsoft .NET Runtime - 8.0.11 (x64)"],
            &["Microsoft Corporation"],
        );
        assert_eq!(
            m.name_matching(),
            NameMatching::Disabled,
            "{:?}",
            m.tokens()
        );
    }

    #[test]
    fn distinctiveness_thresholds() {
        // No distinctive token at all: disabled for an ordinary vendor too.
        for names in [&["Update Helper"][..], &["Setup 1.0 (x64)"], &[""], &[]] {
            let m = solo(names, &["Some Vendor"]);
            assert_eq!(m.name_matching(), NameMatching::Disabled, "{names:?}");
            assert_eq!(m.match_name("Update Helper"), None);
            assert_eq!(m.match_full_name("Update Helper"), None);
            assert_eq!(m.match_full_name(""), None);
        }
        // One distinctive token: enough for an ordinary vendor, not for a mega-vendor.
        assert_eq!(
            solo(&["Chromium"], &["The Chromium Authors"]).name_matching(),
            NameMatching::Enabled
        );
        for (name, vendor) in [
            ("Google Chrome", "Google LLC"),
            ("Microsoft Edge", "Microsoft Corporation"),
            ("Microsoft 365", "Microsoft"),
        ] {
            let m = solo(&[name], &[vendor]);
            assert_eq!(m.name_matching(), NameMatching::Disabled, "{name}");
            assert_eq!(m.match_full_name(name), None);
        }
        // The mega-vendor's own token never counts, wherever it stands.
        let m = solo(&["Teams by Microsoft"], &["Microsoft Corporation"]);
        assert_eq!(
            m.name_matching(),
            NameMatching::Disabled,
            "{:?}",
            m.tokens()
        );
        // Name equal to the vendor, ordinary vendor: kept.
        let m = solo(&["Zotero"], &["Zotero"]);
        assert_eq!(m.tokens(), ["zotero"]);
        assert!(m.match_name("Zotero").is_some());
    }

    #[test]
    fn vendor_prefix_is_not_a_product_token() {
        let m = solo(&["Acme Rocket Skates"], &["Acme Inc."]);
        assert_eq!(m.tokens(), ["rocket", "skates"]);
        assert!(m.match_name("Rocket Skates").is_some());
        assert!(m.match_name("Acme Rocket Skates").is_some());
        assert_eq!(m.match_name("Rocket"), None, "every token is needed");
        assert_eq!(m.match_name("Rocket Skates Deluxe"), None, "foreign token");
        // A vendor key that is not a prefix of the name is left alone.
        let m = solo(&["Git Bash"], &["The Git Development Community"]);
        assert_eq!(m.tokens(), ["bash", "git"]);
        assert_eq!(m.match_name("Bash"), None);
    }

    /// Review regression: with only Firefox and the Maintenance Service installed `mozilla` is not common,
    /// and the service's name is the vendor plus generic words. It must not claim the `Mozilla` folder.
    #[test]
    fn vendor_plus_generic_words_is_not_a_name() {
        const APPS: Apps = &[
            ("Mozilla Firefox (x64 en-US)", "Mozilla"),
            ("Mozilla Maintenance Service", "Mozilla"),
        ];
        assert!(!corpus(APPS).is_common("mozilla"));
        let m = matcher(APPS, "Mozilla Maintenance Service");
        assert_eq!(
            m.name_matching(),
            NameMatching::Disabled,
            "{:?}",
            m.tokens()
        );
        for seg in [
            "Mozilla",
            "Mozilla Maintenance Service",
            "Maintenance Service",
        ] {
            assert_eq!(m.match_name(seg), None, "{seg}");
            assert_eq!(m.match_full_name(seg), None, "{seg}");
            assert_eq!(m.match_product_subfolder("Mozilla", seg), None, "{seg}");
        }
        assert!(m.match_vendor("Mozilla").is_some());
        assert_eq!(
            matcher(APPS, "Mozilla Firefox (x64 en-US)").match_name("Mozilla"),
            None
        );

        let m = solo(&["Docker Desktop"], &["Docker Inc."]);
        assert_eq!(m.name_matching(), NameMatching::Disabled);
        assert_eq!(m.match_name("Docker"), None);
        // The name is exactly the vendor: kept (also with a version behind it).
        let m = solo(&["Zotero 10.0.8"], &["Zotero"]);
        assert!(m.match_name("Zotero").is_some());
    }

    #[test]
    fn generic_only_vendor_is_ignored() {
        let m = solo(
            &["Foobar Editor"],
            &["Software Inc.", "Tools", "Foobar Soft"],
        );
        assert_eq!(m.vendor_keys(), ["foobar soft"]);
        for seg in ["Software", "SOFTWARE", "Tools", "Inc", ""] {
            assert_eq!(m.match_vendor(seg), None, "{seg}");
            assert_eq!(
                m.match_product_subfolder(seg, "Foobar Editor"),
                None,
                "{seg}"
            );
        }
        assert!(m.match_vendor("Foobar Soft").is_some());
    }

    #[test]
    fn a_path_is_not_a_segment() {
        let m = solo(&["Mozilla Firefox"], &["Mozilla"]);
        assert!(m.match_name("Firefox").is_some());
        for seg in [
            "Mozilla\\Firefox",
            "Firefox\\",
            "\\Firefox",
            "C:\\Mozilla\\Firefox",
        ] {
            assert_eq!(m.match_name(seg), None, "{seg}");
            assert_eq!(m.match_full_name(seg), None, "{seg}");
            assert_eq!(m.match_product_subfolder("Mozilla", seg), None, "{seg}");
        }
        assert_eq!(m.match_vendor("Mozilla\\"), None);
        assert_eq!(m.match_product_subfolder("Mozilla\\x", "Firefox"), None);
    }

    /// Review regression: publishers and signers that only start with a mega-vendor's name.
    #[test]
    fn mega_vendor_by_prefix_and_stored_flag() {
        let m = solo(
            &["Oracle VM VirtualBox 7.0.20"],
            &["Oracle and/or its affiliates"],
        );
        assert!(m.mega_vendor());
        assert_eq!(m.tokens(), ["virtualbox", "vm"]);
        assert_eq!(m.match_name("VirtualBox"), None, "both tokens are needed");
        assert!(m.match_name("Oracle VM VirtualBox").is_some());
        let m = solo(&["Adobe Acrobat"], &["Adobe Systems Software Ireland Ltd"]);
        assert!(m.mega_vendor());
        assert_eq!(m.name_matching(), NameMatching::Disabled);

        // A stored `false` cannot switch the rule off for a listed vendor.
        let m = AppMatcher::from_parts(
            &["Google Chrome"],
            &["Google LLC"],
            &["chrome"],
            false,
            Kb::shipped(),
        );
        assert!(m.mega_vendor());
        assert_eq!(m.name_matching(), NameMatching::Disabled);
        assert_eq!(m.match_vendor("Google").map(|v| v.weight()), Some(0));
    }

    #[test]
    fn idf_dropped_tokens_may_still_appear_in_the_segment() {
        const APPS: Apps = &[
            ("Foo Player", "Foo Soft"),
            ("Bar Player", "Bar Soft"),
            ("Baz Player", "Baz Soft"),
        ];
        let m = matcher(APPS, "Foo Player");
        assert_eq!(m.tokens(), ["foo"], "`player` is in three apps");
        assert_eq!(m.match_name("Foo"), None, "three characters: short");
        assert!(m.match_full_name("Foo Player").is_some());
        let m = solo(&["Foobar Player", "foobar"], &["Foobar Soft"]);
        assert!(m.match_name("Foobar Player").is_some());
        assert_eq!(m.match_name("Player"), None);
    }

    #[test]
    fn several_names_pick_the_closest_and_ties_are_ordered_by_sift4() {
        let m = solo(
            &[
                "WinMerge 2.16.44.0 x64",
                "WinMergeU",
                "winmerge.org WinMerge",
            ],
            &["Thingamahoochie"],
        );
        assert_eq!(m.tokens(), ["org", "winmerge", "winmergeu"]);
        let hit = m.match_name("WinMerge").expect("match");
        assert_eq!(
            (hit.name.as_str(), hit.distance),
            ("WinMerge 2.16.44.0 x64", 0)
        );
        assert_eq!(
            m.match_name("WinMergeU").map(|h| h.name),
            Some("WinMergeU".to_owned())
        );

        let mut candidates = vec![
            "Mozilla Thunderbird",
            "Firefox",
            "Mozilla Firefox ESR",
            "mozilla firefox",
        ];
        order_ties("Mozilla Firefox", &mut candidates, |c| c);
        assert_eq!(candidates[0], "mozilla firefox");
        assert_eq!(candidates[1], "Mozilla Firefox ESR");
    }

    #[test]
    fn non_ascii_names() {
        // Full-width and mixed case fold onto the same tokens.
        let m = solo(&["Ｆｏｏｂａｒ　Ｅｄｉｔｏｒ"], &["Example"]);
        assert_eq!(m.tokens(), ["editor", "foobar"]);
        assert!(m.match_name("foobar editor").is_some());
        assert!(m.match_full_name("FOOBAR EDITOR").is_some());
        // Turkish: any casing of the i's matches.
        let m = solo(&["Dizi İzleyici"], &["Örnek Yazılım"]);
        assert_eq!(m.tokens(), ["dizi", "izleyici"]);
        for seg in [
            "DİZİ İZLEYİCİ",
            "DIZI IZLEYICI",
            "dizi izleyici",
            "dızı ızleyıcı",
        ] {
            assert!(m.match_name(seg).is_some(), "{seg}");
        }
        assert!(m.match_vendor("ÖRNEK YAZILIM").is_some());
        // CJK: one token per run; two characters are short.
        let m = solo(&["微信"], &["Tencent"]);
        assert_eq!(m.match_name("微信"), None);
        assert!(
            m.match_full_name("微信")
                .is_some_and(|h| h.needs_tier_ab_neighbour)
        );
        let m = solo(&["テキストエディタ"], &["Example"]);
        assert!(m.match_name("テキストエディタ").is_some());
        assert_eq!(m.match_name("テキスト"), None);
    }

    #[test]
    fn from_parts_reproduces_the_harvest_matcher() {
        for (apps, name) in [
            (MOZILLA, "Mozilla Firefox (x64 en-US)"),
            (MOZILLA, "7-Zip 24.08 (x64)"),
            (DIRTY_BASE, "Microsoft Visual Studio Code"),
            (DIRTY_BASE_WITH_VS_INSTALLER, "Microsoft Visual Studio Code"),
            (DIRTY_BASE, "Python 3.13.1 (64-bit)"),
            (DIRTY_BASE, "Python 3.13.1 Tcl/Tk Support (64-bit)"),
            (VCREDISTS, VCREDISTS[0].0),
        ] {
            let built = matcher(apps, name);
            let vendor = apps
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, p)| *p)
                .unwrap();
            let again = AppMatcher::from_parts(
                &[name],
                &[vendor],
                &built.tokens(),
                built.mega_vendor(),
                Kb::shipped(),
            );
            assert_eq!(again, built, "{name}");
        }
        // Empty stored tokens mean disabled, whatever the names say.
        let m =
            AppMatcher::from_parts(&["Steam"], &["Valve"], &[] as &[&str], false, Kb::shipped());
        assert_eq!(m.name_matching(), NameMatching::Disabled);
        assert!(m.match_vendor("Valve").is_some());
    }
}
