//! App identity assembly (ENGINE_PLAN §5.4 "Names", "Vendors"; §5.3 for the evidence rows).
//!
//! [`AppIdentity::resolve`] turns one inventory entry into the names and vendors the app goes by, builds
//! the installed-apps [`Corpus`] from every entry and hands both to the [`AppMatcher`]. Scanners then ask
//! [`AppIdentity::matches_name`], [`AppIdentity::matches_full_name`],
//! [`AppIdentity::matches_product_subfolder`] and [`AppIdentity::matches_vendor`] about one path or key
//! segment and get the §5.3 evidence kind, tier and weight back. [`AppIdentity::snapshot`] is what the
//! fingerprint stores; [`AppIdentity::from_snapshot`] rebuilds an identity that matches exactly as the
//! resolved one did, so the scan after the uninstall needs no live resolution.
//!
//! # Names
//!
//! Registry-sourced names are taken as found: `DisplayName`, the MSI `ProductName` and the Inno `AppName`
//! (both supplied by the caller through [`IdentityHints`] or [`AppIdentity::with_inno`], because the
//! inventory entry does not carry them), the Inno AppId and the ARP key name (which is also the NSIS key
//! name; an `_is1` suffix is removed). A name made of noise only (a GUID key name) is dropped.
//!
//! File-sourced names come from the main exes (see [`mainexe`]): the file name without `.exe`, and the
//! `ProductName` and `FileDescription` of the version resource. Such a string is added **only when it
//! shares a product token with a registry-sourced name**. A product token is a significant token of the
//! name that is not its leading `Publisher` part (for a mega-vendor: not a publisher token at all). The rule keeps a component from taking over its parent product's name:
//! a maintenance service whose version resource says `ProductName = Firefox`, or an app whose only exe is
//! named after its vendor, gains no name from the file. File-sourced names therefore add spellings of the
//! app's own name (`Git for Windows` next to `Git`, `Visual Studio Code` next to `Microsoft Visual Studio
//! Code (User)`), never a new identity.
//!
//! Every name other than the primary ones (DisplayName, MSI ProductName, Inno AppName) is also dropped when
//! it is the name of **another installed app**: a launcher-style key name (`Steam App 620` next to `Steam`)
//! or the strings of a host's exe that a component points at. A `DisplayIcon` target inside another
//! entry's `InstallLocation` is not read at all (see [`mainexe`]).
//!
//! # Vendors
//!
//! `Publisher`, then for each related main exe the signer CN and the `CompanyName`, then the registrable
//! domain label of `URLInfoAbout` and `HelpLink` (shared hosting sites give none), then
//! the knowledge-base aliases the caller passes. The **vendor aliases** ([`AppIdentity::vendor_aliases`])
//! are these strings as vendor keys: legal suffixes removed, duplicates folded (`Mozilla Corporation` and
//! `Mozilla` are both `mozilla`). An exe selected only because it is the largest gives no vendor.
//!
//! # Trust (Rule T)
//!
//! Everything read here can be user-writable: a per-user Uninstall key, an install folder in the profile.
//! That is acceptable because identity evidence is at most Tier B (`ExactFullName`,
//! `ProductSubfolderOfVendor`) or Tier C (`NameTokenExact`, `VendorContainer`): Rule T only lowers Tier A,
//! and the policy never preselects on name or vendor evidence alone. Nothing in this module produces
//! Tier A evidence.
//!
//! # Caller duties
//!
//! Every `matches_*` function takes **one** segment (a folder or key name), with file extensions already
//! removed. A result with `needs_tier_ab_neighbour` set (a short name such as `Git`) may be used only next
//! to Tier A or Tier B evidence on the same target.

pub mod mainexe;
mod urlhost;

use std::collections::{BTreeMap, BTreeSet};

use purge_inventory::kind;
use purge_model::{EvidenceKind, IdentitySnapshot, InventoryEntry, Tier};
use purge_source::filesystem::FileSystemSource;
use purge_source::registry::RegistrySource;
use purge_win::env::EnvMap;

use crate::kbdata::Kb;
use crate::matcher::{AppMatcher, NameMatch, NameMatching, VendorMatch};
use crate::tokenizer::{
    Corpus, TokenClass, full_name_key, significant_tokens, tokenize, vendor_key,
};

pub use mainexe::{MAX_MAIN_EXES, MainExe, MainExeBasis};

/// Facts about an app that the inventory entry does not carry. All optional; an empty value changes
/// nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityHints {
    /// The MSI `ProductName` property.
    pub msi_product_name: Option<String>,
    /// The Inno Setup `AppName` (from the `Inno Setup: …` values or the uninstall log).
    pub inno_app_name: Option<String>,
    /// The `URLInfoAbout` value of the Uninstall key.
    pub url_info_about: Option<String>,
    /// The `HelpLink` value of the Uninstall key.
    pub help_link: Option<String>,
    /// Knowledge-base vendor aliases for this app (e.g. `mozilla.org`).
    pub kb_aliases: Vec<String>,
    /// Environment of the user the entry belongs to (names upper-cased, as `SystemSource::env` gives
    /// them), for `InstallLocation` and `DisplayIcon` values that hold `%VARIABLES%`. Without it such
    /// values are ignored.
    pub env: BTreeMap<String, String>,
}

impl IdentityHints {
    /// Fills [`url_info_about`](Self::url_info_about) and [`help_link`](Self::help_link) from the entry's
    /// Uninstall key. Missing or unreadable values are left as they were.
    #[must_use]
    pub fn with_arp_urls(mut self, reg: &dyn RegistrySource, entry: &InventoryEntry) -> Self {
        let read = |name: &str| {
            reg.value(&entry.key_path, name)
                .ok()
                .and_then(|d| d.string())
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
        };
        if let Some(url) = read("URLInfoAbout") {
            self.url_info_about = Some(url);
        }
        if let Some(url) = read("HelpLink") {
            self.help_link = Some(url);
        }
        self
    }
}

/// One identity match of a segment: the §5.3 row it supports.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdentityMatch {
    /// The evidence kind (`NameTokenExact`, `ExactFullName`, `ProductSubfolderOfVendor` or
    /// `VendorContainer`).
    pub kind: EvidenceKind,
    /// The tier of that kind (B or C; never A).
    pub tier: Tier,
    /// The weight: the §5.3 value, or 0 for a `VendorContainer` match of a mega-vendor.
    pub weight: i8,
    /// A short name matched (§5.4 step 8): valid only next to Tier A or Tier B evidence on the same target.
    pub needs_tier_ab_neighbour: bool,
    /// What matched: the app name as found, or the vendor alias.
    pub matched: String,
    /// Sift4 distance between the segment and the matched name; for ordering equal candidates only.
    pub distance: usize,
}

impl IdentityMatch {
    fn from_name(m: NameMatch) -> Self {
        Self {
            kind: m.evidence_kind(),
            tier: m.evidence_kind().default_tier(),
            weight: m.weight(),
            needs_tier_ab_neighbour: m.needs_tier_ab_neighbour,
            matched: m.name,
            distance: m.distance,
        }
    }

    fn from_vendor(m: VendorMatch) -> Self {
        Self {
            kind: m.evidence_kind(),
            tier: m.evidence_kind().default_tier(),
            weight: m.weight(),
            needs_tier_ab_neighbour: false,
            matched: m.alias,
            distance: 0,
        }
    }
}

/// What decides which tokens are distinctive when the matcher is (re)built.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Distinctive {
    /// Harvest time: the IDF rule over the installed apps.
    Corpus(Corpus),
    /// Reloaded from a fingerprint: exactly the stored tokens.
    Stored {
        tokens: Vec<String>,
        mega_vendor: bool,
    },
}

/// The resolved identity of one app; see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppIdentity {
    names: Vec<String>,
    vendors: Vec<String>,
    distinctive: Distinctive,
    matcher: AppMatcher<'static>,
    main_exes: Vec<MainExe>,
    warnings: Vec<String>,
}

/// Appends `s` (trimmed) unless it is empty or already present, ignoring case.
fn push_unique(list: &mut Vec<String>, s: &str) {
    let s = s.trim();
    if !s.is_empty() && !list.iter().any(|x| x.to_lowercase() == s.to_lowercase()) {
        list.push(s.to_owned());
    }
}

/// Appends a name unless it is noise only (a GUID, a version).
fn push_name(list: &mut Vec<String>, s: &str) {
    if !full_name_key(s).is_empty() {
        push_unique(list, s);
    }
}

/// The strings one app contributes to the corpus: its name, publisher and key name (§5.4 step 5).
fn corpus_strings(entry: &InventoryEntry) -> impl Iterator<Item = &str> {
    [
        Some(entry.display_name.as_str()),
        entry.publisher.as_deref(),
        Some(entry.program_id.key_name()),
    ]
    .into_iter()
    .flatten()
}

/// The product tokens of a registry-sourced name, by the matcher's rule: the significant tokens, without
/// a leading vendor key (`Mozilla Firefox` by `Mozilla` leaves `firefox`) and, for a mega-vendor, without
/// any vendor token. Unlike the matcher, a name that is only the vendor has no product token here.
fn product_tokens(
    name: &str,
    vendor_keys: &[Vec<String>],
    mega_vendor: bool,
    kb: &Kb,
) -> Vec<String> {
    let tokens = tokenize(name, &kb.generic);
    let words: Vec<_> = tokens
        .iter()
        .filter(|t| t.class > TokenClass::Stopword)
        .collect();
    let prefix = vendor_keys
        .iter()
        .filter(|k| k.len() <= words.len() && k.iter().zip(&words).all(|(a, b)| *a == b.text))
        .map(Vec::len)
        .max()
        .unwrap_or(0);
    words
        .iter()
        .skip(prefix)
        .filter(|t| t.class == TokenClass::Significant)
        .filter(|t| !(mega_vendor && vendor_keys.iter().flatten().any(|v| *v == t.text)))
        .map(|t| t.text.clone())
        .collect()
}

/// The names of the other installed apps, for the rule that a **secondary** name of this app (its key
/// name, Inno AppId, an exe name or a version-resource string) must not be one of them.
///
/// A secondary name is *claimed* when another app's `DisplayName` holds every significant token of it,
/// so that a folder named after that other app would match the secondary name, while none of this app's
/// primary names (DisplayName, MSI ProductName, Inno AppName) would match that folder. Examples: the
/// key name `Steam App 620` of a game next to `Steam`; `ProductName = Quillfeather` in the borrowed
/// exe of `Quillfeather Thesaurus` next to `Quillfeather`. Two versions of one product
/// (`Python 3.12`, `Python 3.13`) already share their primary name, so nothing is claimed there.
struct OtherApps {
    /// Significant tokens of each other app's `DisplayName`, without the sets a primary name of this
    /// app already covers.
    foreign: Vec<BTreeSet<String>>,
}

impl OtherApps {
    fn new(
        entry: &InventoryEntry,
        all_entries: &[InventoryEntry],
        primary_names: &[String],
        vendor_keys: &[Vec<String>],
        mega_vendor: bool,
        kb: &Kb,
    ) -> Self {
        let primary: Vec<BTreeSet<String>> = primary_names
            .iter()
            .map(|n| product_tokens(n, vendor_keys, mega_vendor, kb))
            .map(|t| t.into_iter().collect::<BTreeSet<_>>())
            .filter(|t| !t.is_empty())
            .collect();
        let mut foreign: Vec<BTreeSet<String>> = Vec::new();
        for other in all_entries
            .iter()
            .filter(|e| e.program_id != entry.program_id)
        {
            let tokens: BTreeSet<String> = significant_tokens(&other.display_name, &kb.generic)
                .into_iter()
                .collect();
            if !tokens.is_empty()
                && !primary.iter().any(|p| p.is_subset(&tokens))
                && !foreign.contains(&tokens)
            {
                foreign.push(tokens);
            }
        }
        Self { foreign }
    }

    /// Whether `name` is claimed by another app; see the type documentation.
    fn claims(&self, name: &str, kb: &Kb) -> bool {
        let tokens: BTreeSet<String> = significant_tokens(name, &kb.generic).into_iter().collect();
        !tokens.is_empty() && self.foreign.iter().any(|f| tokens.is_subset(f))
    }
}

impl AppIdentity {
    /// Resolves the identity of `entry` among `all_entries` (the whole inventory; `entry` is added to the
    /// corpus when the slice does not contain it). Reads the file system only for main-exe selection.
    pub fn resolve(
        entry: &InventoryEntry,
        all_entries: &[InventoryEntry],
        fs: &dyn FileSystemSource,
    ) -> AppIdentity {
        Self::resolve_with(entry, all_entries, fs, &IdentityHints::default())
    }

    /// Like [`resolve`](Self::resolve), with the facts the entry does not carry.
    pub fn resolve_with(
        entry: &InventoryEntry,
        all_entries: &[InventoryEntry],
        fs: &dyn FileSystemSource,
        hints: &IdentityHints,
    ) -> AppIdentity {
        let kb = Kb::shipped();
        let mut warnings = Vec::new();

        // Registry-sourced vendors.
        let mut vendors: Vec<String> = Vec::new();
        if let Some(publisher) = &entry.publisher {
            push_unique(&mut vendors, publisher);
        }
        let publisher_is_mega = vendors.iter().any(|v| kb.mega_vendors.is_mega(v));
        let publisher_keys: Vec<Vec<String>> = vendors
            .iter()
            .chain(&hints.kb_aliases)
            .map(|v| vendor_key(v))
            .filter(|k| !k.is_empty() && !k.split(' ').all(|t| kb.generic.contains(t)))
            .map(|k| k.split(' ').map(str::to_owned).collect())
            .collect();

        // Primary names: what the installer calls the product.
        let key_name = entry.program_id.key_name();
        let mut names: Vec<String> = Vec::new();
        push_name(&mut names, &entry.display_name);
        for name in [&hints.msi_product_name, &hints.inno_app_name]
            .into_iter()
            .flatten()
        {
            push_name(&mut names, name);
        }

        // Secondary names (Inno AppId, key name, and the file-sourced names below) must not be another
        // installed app's name.
        let others = OtherApps::new(
            entry,
            all_entries,
            &names,
            &publisher_keys,
            publisher_is_mega,
            kb,
        );
        let key_base = kind::strip_inno_suffix(key_name).unwrap_or(key_name);
        for name in [entry.inno_app_id.as_deref(), Some(key_base)]
            .into_iter()
            .flatten()
        {
            if !others.claims(name, kb) {
                push_name(&mut names, name);
            }
        }

        // Product tokens of the registry names: what a file-sourced string must share.
        let name_tokens: BTreeSet<String> = names
            .iter()
            .flat_map(|n| significant_tokens(n, &kb.generic))
            .collect();
        let product_ref: BTreeSet<String> = names
            .iter()
            .flat_map(|n| product_tokens(n, &publisher_keys, publisher_is_mega, kb))
            .collect();
        // For choosing main exes (not for names) an app named after its vendor may use the vendor token.
        let select_ref = if product_ref.is_empty() && !publisher_is_mega {
            &name_tokens
        } else {
            &product_ref
        };
        let shares = |set: &BTreeSet<String>, s: &str| {
            significant_tokens(s, &kb.generic)
                .iter()
                .any(|t| set.contains(t))
        };

        // Main exes.
        let mut env = EnvMap::new();
        for (name, value) in &hints.env {
            env.insert(name.to_uppercase(), value.clone());
        }
        let uninstaller = entry
            .uninstall_string
            .as_deref()
            .and_then(kind::uninstaller)
            .map(|c| c.exe);
        let foreign_roots = mainexe::foreign_roots(
            all_entries
                .iter()
                .filter(|e| e.program_id != entry.program_id)
                .filter_map(|e| e.install_location.as_deref()),
            &env,
        );
        let main_exes = mainexe::select(
            fs,
            &mainexe::ExeQuery {
                install_location: entry.install_location.as_deref(),
                display_icon: entry.display_icon.as_deref(),
                uninstaller_exe: uninstaller.as_deref(),
                foreign_roots: &foreign_roots,
                env: &env,
            },
            &|s| shares(select_ref, s),
            &mut warnings,
        );

        // File-sourced names and vendors.
        for exe in main_exes.iter().filter(|e| e.basis.is_related()) {
            let info = exe.version_info.as_ref();
            let strings = [
                Some(&exe.stem),
                info.and_then(|v| v.product_name.as_ref()),
                info.and_then(|v| v.file_description.as_ref()),
            ];
            for s in strings.into_iter().flatten() {
                if shares(&product_ref, s) && !others.claims(s, kb) {
                    push_name(&mut names, s);
                }
            }
        }
        for exe in main_exes.iter().filter(|e| e.basis.is_related()) {
            if let Some(cn) = &exe.signer_cn {
                push_unique(&mut vendors, cn);
            }
        }
        for exe in main_exes.iter().filter(|e| e.basis.is_related()) {
            if let Some(company) = exe
                .version_info
                .as_ref()
                .and_then(|v| v.company_name.as_ref())
            {
                push_unique(&mut vendors, company);
            }
        }
        for url in [&hints.url_info_about, &hints.help_link]
            .into_iter()
            .flatten()
        {
            if let Some(label) = urlhost::registrable_label(url) {
                push_unique(&mut vendors, &label);
            }
        }
        for alias in &hints.kb_aliases {
            push_unique(&mut vendors, alias);
        }

        // The corpus: one document per installed app.
        let mut corpus = Corpus::from_apps(all_entries.iter().map(corpus_strings));
        if !all_entries.iter().any(|e| e.program_id == entry.program_id) {
            corpus.add_app(corpus_strings(entry));
        }

        let matcher = AppMatcher::build(&names, &vendors, &corpus, kb);
        AppIdentity {
            names,
            vendors,
            distinctive: Distinctive::Corpus(corpus),
            matcher,
            main_exes,
            warnings,
        }
    }

    /// Rebuilds an identity from a fingerprint's snapshot. It matches exactly as the identity the snapshot
    /// was taken from, except that a vendor the current knowledge base lists as a mega-vendor is one even
    /// when the snapshot says otherwise. [`main_exes`](Self::main_exes) is empty: the fingerprint's exe
    /// set holds them.
    pub fn from_snapshot(snapshot: &IdentitySnapshot) -> AppIdentity {
        let kb = Kb::shipped();
        AppIdentity {
            names: snapshot.names.clone(),
            vendors: snapshot.vendors.clone(),
            matcher: AppMatcher::from_parts(
                &snapshot.names,
                &snapshot.vendors,
                &snapshot.tokens,
                snapshot.mega_vendor,
                kb,
            ),
            distinctive: Distinctive::Stored {
                tokens: snapshot.tokens.clone(),
                mega_vendor: snapshot.mega_vendor,
            },
            main_exes: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// The identity snapshot the fingerprint stores.
    pub fn snapshot(&self) -> IdentitySnapshot {
        IdentitySnapshot {
            names: self.names.clone(),
            vendors: self.vendors.clone(),
            tokens: self.matcher.tokens(),
            mega_vendor: self.matcher.mega_vendor(),
        }
    }

    fn rebuild(&mut self) {
        let kb = Kb::shipped();
        self.matcher = match &self.distinctive {
            Distinctive::Corpus(corpus) => {
                AppMatcher::build(&self.names, &self.vendors, corpus, kb)
            }
            Distinctive::Stored {
                tokens,
                mega_vendor,
            } => AppMatcher::from_parts(&self.names, &self.vendors, tokens, *mega_vendor, kb),
        };
    }

    /// Adds the Inno Setup `AppName`, which the harvest reads after the identity was resolved. A
    /// registry-sourced name: it is added as found. On an identity reloaded from a snapshot the stored
    /// token set still decides what is distinctive, so a new name cannot add tokens there.
    #[must_use]
    pub fn with_inno(mut self, app_name: &str) -> Self {
        let before = self.names.len();
        push_name(&mut self.names, app_name);
        if self.names.len() != before {
            self.rebuild();
        }
        self
    }

    /// Adds knowledge-base vendor aliases (e.g. `mozilla.org`) found after the identity was resolved.
    #[must_use]
    pub fn with_kb_aliases<S: AsRef<str>>(mut self, aliases: &[S]) -> Self {
        let before = self.vendors.len();
        for alias in aliases {
            push_unique(&mut self.vendors, alias.as_ref());
        }
        if self.vendors.len() != before {
            self.rebuild();
        }
        self
    }

    /// Every name the app goes by, as found, registry-sourced names first.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Every vendor string, as found (Publisher, signer CN, CompanyName, URL label, KB aliases).
    pub fn vendors(&self) -> &[String] {
        &self.vendors
    }

    /// The vendor aliases: the vendor strings as normalised vendor keys, without duplicates and without
    /// keys made of generic words only.
    pub fn vendor_aliases(&self) -> &[String] {
        self.matcher.vendor_keys()
    }

    /// The distinctive name tokens, sorted. Empty when name matching is disabled.
    pub fn tokens(&self) -> Vec<String> {
        self.matcher.tokens()
    }

    /// Whether name-based evidence is available for this app (§5.4 step 6).
    pub fn name_matching(&self) -> NameMatching {
        self.matcher.name_matching()
    }

    /// Whether one of the app's vendors is a mega-vendor: vendor-only matches weigh 0.
    pub fn mega_vendor(&self) -> bool {
        self.matcher.mega_vendor()
    }

    /// The main exes found at resolution, strongest basis first; empty after a reload.
    pub fn main_exes(&self) -> &[MainExe] {
        &self.main_exes
    }

    /// What could not be read while resolving, for the fingerprint's warnings.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// The underlying matcher, for callers that need its own result types.
    pub fn matcher(&self) -> &AppMatcher<'static> {
        &self.matcher
    }

    /// Whole-token name match of one segment: `NameTokenExact` (Tier C, weight 3). Never fires for a
    /// short name.
    pub fn matches_name(&self, segment: &str) -> Option<IdentityMatch> {
        self.matcher
            .match_name(segment)
            .map(IdentityMatch::from_name)
    }

    /// The segment is the app's full name: `ExactFullName` (Tier B, weight 4).
    pub fn matches_full_name(&self, segment: &str) -> Option<IdentityMatch> {
        self.matcher
            .match_full_name(segment)
            .map(IdentityMatch::from_name)
    }

    /// `<VendorAlias>\<Product>`: `ProductSubfolderOfVendor` (Tier B, weight 3) for `product_segment`
    /// directly below `vendor_segment`.
    pub fn matches_product_subfolder(
        &self,
        vendor_segment: &str,
        product_segment: &str,
    ) -> Option<IdentityMatch> {
        self.matcher
            .match_product_subfolder(vendor_segment, product_segment)
            .map(IdentityMatch::from_name)
    }

    /// The segment is one of the app's vendor aliases: `VendorContainer` (Tier C, weight 2, or 0 for a
    /// mega-vendor).
    pub fn matches_vendor(&self, segment: &str) -> Option<IdentityMatch> {
        self.matcher
            .match_vendor(segment)
            .map(IdentityMatch::from_vendor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use purge_inventory::arp::{ArpOptions, enumerate};
    use purge_model::Fingerprint;
    use purge_source::fixture::{Fixture, FixtureBuilder};
    use purge_source::types::VersionInfo;
    use serde_json::json;

    const HKLM_UNINSTALL: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    const SID: &str = "S-1-5-21-1-2-3-1001";

    fn hku_uninstall() -> String {
        format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Uninstall")
    }

    /// Adds one Uninstall key with string values.
    fn arp(b: FixtureBuilder, root: &str, key: &str, values: &[(&str, &str)]) -> FixtureBuilder {
        let path = format!("{root}\\{key}");
        values
            .iter()
            .fold(b.key(&path), |b, (name, data)| b.sz(&path, name, data))
    }

    /// Adds an exe with a version resource (`product`, `description`, `company`; empty = absent) and an
    /// optional signer.
    fn exe(
        b: FixtureBuilder,
        path: &str,
        size: u64,
        version: Option<(&str, &str, &str)>,
        signer: Option<&str>,
    ) -> FixtureBuilder {
        let mut b = b.file(path, size);
        if let Some((product, description, company)) = version {
            let opt = |s: &str| (!s.is_empty()).then(|| s.to_owned());
            b = b.version_info(
                path,
                VersionInfo {
                    product_name: opt(product),
                    file_description: opt(description),
                    company_name: opt(company),
                    ..VersionInfo::default()
                },
            );
        }
        if let Some(cn) = signer {
            b = b.signer(path, cn);
        }
        b
    }

    fn entries(f: &Fixture) -> Vec<InventoryEntry> {
        let scan = enumerate(f, f, &ArpOptions::default());
        assert!(!scan.entries.is_empty());
        scan.entries
    }

    fn entry<'a>(all: &'a [InventoryEntry], display_name: &str) -> &'a InventoryEntry {
        all.iter()
            .find(|e| e.display_name == display_name)
            .unwrap_or_else(|| panic!("no entry named {display_name}"))
    }

    fn resolve(f: &Fixture, display_name: &str) -> AppIdentity {
        let all = entries(f);
        let e = entry(&all, display_name);
        let hints = IdentityHints::default().with_arp_urls(f, e);
        AppIdentity::resolve_with(e, &all, f, &hints)
    }

    fn kinds(id: &AppIdentity, segment: &str) -> Vec<EvidenceKind> {
        [
            id.matches_name(segment),
            id.matches_full_name(segment),
            id.matches_vendor(segment),
        ]
        .into_iter()
        .flatten()
        .map(|m| m.kind)
        .collect()
    }

    const FIREFOX: &str = "Mozilla Firefox (x64 en-US)";
    const FIREFOX_DIR: &str = r"C:\Program Files\Mozilla Firefox";

    fn firefox(b: FixtureBuilder) -> FixtureBuilder {
        let b = arp(
            b,
            HKLM_UNINSTALL,
            "Mozilla Firefox 146.0 (x64 en-US)",
            &[
                ("DisplayName", FIREFOX),
                ("DisplayVersion", "146.0"),
                ("Publisher", "Mozilla"),
                ("InstallLocation", FIREFOX_DIR),
                (
                    "DisplayIcon",
                    r"C:\Program Files\Mozilla Firefox\firefox.exe,0",
                ),
                (
                    "UninstallString",
                    r#""C:\Program Files\Mozilla Firefox\uninstall\helper.exe""#,
                ),
                ("URLInfoAbout", "https://www.mozilla.org"),
                ("HelpLink", "https://support.mozilla.org"),
            ],
        );
        let moz = Some("Mozilla Corporation");
        let b = exe(
            b,
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            700_000,
            Some(("Firefox", "Firefox", "Mozilla Corporation")),
            moz,
        );
        let b = exe(
            b,
            r"C:\Program Files\Mozilla Firefox\updater.exe",
            400_000,
            Some(("Firefox", "Firefox Software Updater", "Mozilla Foundation")),
            moz,
        );
        let b = exe(
            b,
            r"C:\Program Files\Mozilla Firefox\crashreporter.exe",
            300_000,
            Some(("Firefox", "", "Mozilla Foundation")),
            moz,
        );
        exe(
            b,
            r"C:\Program Files\Mozilla Firefox\uninstall\helper.exe",
            1_200_000,
            Some(("Firefox", "Firefox Helper", "Mozilla")),
            moz,
        )
    }

    fn thunderbird(b: FixtureBuilder) -> FixtureBuilder {
        let b = arp(
            b,
            HKLM_UNINSTALL,
            "Mozilla Thunderbird 140.0 (x64 en-US)",
            &[
                ("DisplayName", "Mozilla Thunderbird (x64 en-US)"),
                ("Publisher", "Mozilla"),
                ("InstallLocation", r"C:\Program Files\Mozilla Thunderbird"),
                (
                    "DisplayIcon",
                    r"C:\Program Files\Mozilla Thunderbird\thunderbird.exe,0",
                ),
                ("URLInfoAbout", "https://www.thunderbird.net/"),
            ],
        );
        let b = exe(
            b,
            r"C:\Program Files\Mozilla Thunderbird\thunderbird.exe",
            600_000,
            Some(("Thunderbird", "Thunderbird", "Mozilla Corporation")),
            Some("Mozilla Corporation"),
        );
        // The maintenance service both products share; its version resource names the product it was
        // built with.
        let b = arp(
            b,
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "MozillaMaintenanceService",
            &[
                ("DisplayName", "Mozilla Maintenance Service"),
                ("Publisher", "Mozilla"),
                (
                    "DisplayIcon",
                    r"C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe,0",
                ),
                (
                    "UninstallString",
                    r#""C:\Program Files (x86)\Mozilla Maintenance Service\uninstall.exe""#,
                ),
            ],
        );
        exe(
            b,
            r"C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe",
            250_000,
            Some((
                "Firefox",
                "Mozilla Maintenance Service",
                "Mozilla Foundation",
            )),
            Some("Mozilla Corporation"),
        )
    }

    #[test]
    fn firefox_names_vendors_and_main_exes() {
        let f = firefox(Fixture::builder()).build();
        let id = resolve(&f, FIREFOX);

        assert_eq!(id.vendor_aliases(), ["mozilla"]);
        assert_eq!(id.tokens(), ["firefox"]);
        assert_eq!(id.name_matching(), NameMatching::Enabled);
        assert!(!id.mega_vendor());
        assert_eq!(
            id.names(),
            [
                FIREFOX,
                "Mozilla Firefox 146.0 (x64 en-US)",
                "firefox",
                "Firefox Software Updater",
            ]
        );
        assert_eq!(
            id.vendors(),
            ["Mozilla", "Mozilla Corporation", "Mozilla Foundation"]
        );

        // The DisplayIcon target leads; the uninstaller, though the largest exe, is never a main exe.
        let main: Vec<(&str, MainExeBasis)> = id
            .main_exes()
            .iter()
            .map(|e| (e.path.as_str(), e.basis))
            .collect();
        assert_eq!(
            main,
            [
                (
                    r"C:\Program Files\Mozilla Firefox\firefox.exe",
                    MainExeBasis::DisplayIcon
                ),
                (
                    r"C:\Program Files\Mozilla Firefox\updater.exe",
                    MainExeBasis::VersionInfo
                ),
                (
                    r"C:\Program Files\Mozilla Firefox\crashreporter.exe",
                    MainExeBasis::VersionInfo
                ),
            ]
        );
        assert!(id.warnings().is_empty(), "{:?}", id.warnings());

        let m = id.matches_name("Firefox").unwrap();
        assert_eq!(
            (m.kind, m.tier, m.weight, m.needs_tier_ab_neighbour),
            (EvidenceKind::NameTokenExact, Tier::C, 3, false)
        );
        let m = id.matches_full_name("Mozilla Firefox").unwrap();
        assert_eq!(
            (m.kind, m.tier, m.weight),
            (EvidenceKind::ExactFullName, Tier::B, 4)
        );
        let m = id.matches_product_subfolder("Mozilla", "Firefox").unwrap();
        assert_eq!(
            (m.kind, m.tier, m.weight),
            (EvidenceKind::ProductSubfolderOfVendor, Tier::B, 3)
        );
        assert!(id.matches_product_subfolder("Google", "Firefox").is_none());
        let m = id.matches_vendor("Mozilla").unwrap();
        assert_eq!(
            (m.kind, m.tier, m.weight, m.matched.as_str()),
            (EvidenceKind::VendorContainer, Tier::C, 2, "mozilla")
        );
        // A whole path is not a segment.
        assert!(id.matches_name(r"Mozilla\Firefox").is_none());

        // A knowledge-base alias is one more vendor spelling.
        assert!(id.matches_vendor("mozilla.org").is_none());
        let id = id.with_kb_aliases(&["mozilla.org"]);
        assert_eq!(id.vendor_aliases(), ["mozilla", "mozilla org"]);
        assert_eq!(kinds(&id, "mozilla.org"), [EvidenceKind::VendorContainer]);
        assert_eq!(id.tokens(), ["firefox"]);
    }

    #[test]
    fn firefox_next_to_thunderbird_shares_only_the_vendor_container() {
        let f = thunderbird(firefox(Fixture::builder())).build();
        let id = resolve(&f, FIREFOX);

        assert_eq!(id.tokens(), ["firefox"]);
        assert!(id.matches_name("Thunderbird").is_none());
        assert!(id.matches_full_name("Thunderbird").is_none());
        assert!(id.matches_full_name("Mozilla Thunderbird").is_none());
        assert!(
            id.matches_product_subfolder("Mozilla", "Thunderbird")
                .is_none()
        );
        // `Mozilla` is the vendor container and nothing more.
        assert_eq!(kinds(&id, "Mozilla"), [EvidenceKind::VendorContainer]);
        assert_eq!(id.matches_vendor("Mozilla").unwrap().weight, 2);
        assert_eq!(
            kinds(&id, "Firefox"),
            [EvidenceKind::NameTokenExact, EvidenceKind::ExactFullName]
        );

        // And the other way round.
        let tb = resolve(&f, "Mozilla Thunderbird (x64 en-US)");
        assert_eq!(tb.tokens(), ["thunderbird"]);
        assert!(tb.vendor_aliases().contains(&"mozilla".to_owned()));
        assert!(tb.vendor_aliases().contains(&"thunderbird".to_owned()));
        assert!(tb.matches_name("Firefox").is_none());
        assert_eq!(kinds(&tb, "Mozilla"), [EvidenceKind::VendorContainer]);
    }

    #[test]
    fn component_does_not_take_the_product_name_from_its_version_resource() {
        let f = thunderbird(firefox(Fixture::builder())).build();
        let id = resolve(&f, "Mozilla Maintenance Service");

        // The exe is found (DisplayIcon) and gives the vendor, but `ProductName = Firefox` is not a name.
        assert_eq!(id.main_exes().len(), 1);
        assert_eq!(id.main_exes()[0].basis, MainExeBasis::DisplayIcon);
        assert!(!id.names().iter().any(|n| n == "Firefox"));
        assert!(id.vendor_aliases().contains(&"mozilla".to_owned()));
        // Vendor plus generic words is no name; only the one-word ARP key name identifies it.
        assert_eq!(id.tokens(), ["mozillamaintenanceservice"]);
        for segment in ["Firefox", "Mozilla Firefox", "Mozilla Maintenance Service"] {
            assert!(id.matches_name(segment).is_none(), "{segment}");
            assert!(id.matches_full_name(segment).is_none(), "{segment}");
        }
        assert!(id.matches_name("MozillaMaintenanceService").is_some());
        assert_eq!(kinds(&id, "Mozilla"), [EvidenceKind::VendorContainer]);
    }

    fn git(b: FixtureBuilder) -> FixtureBuilder {
        let b = arp(
            b,
            HKLM_UNINSTALL,
            "Git_is1",
            &[
                ("DisplayName", "Git"),
                ("DisplayVersion", "2.52.0"),
                ("Publisher", "The Git Development Community"),
                ("InstallLocation", r"C:\Program Files\Git\"),
                (
                    "DisplayIcon",
                    r"C:\Program Files\Git\mingw64\share\git\git-for-windows.ico",
                ),
                ("UninstallString", r#""C:\Program Files\Git\unins000.exe""#),
                ("Inno Setup: App Path", r"C:\Program Files\Git"),
                ("URLInfoAbout", "https://gitforwindows.org/"),
            ],
        );
        let gfw = Some((
            "Git for Windows",
            "Git for Windows",
            "The Git Development Community",
        ));
        let b = exe(b, r"C:\Program Files\Git\git-bash.exe", 140_000, gfw, None);
        let b = exe(b, r"C:\Program Files\Git\cmd\git.exe", 45_000, gfw, None);
        let b = exe(
            b,
            r"C:\Program Files\Git\unins000.exe",
            3_000_000,
            None,
            None,
        );
        // A bundled tool below the depth limit is not looked at.
        exe(
            b,
            r"C:\Program Files\Git\mingw64\bin\curl.exe",
            9_000_000,
            Some((
                "The curl executable",
                "The curl executable",
                "curl, https://curl.se/",
            )),
            None,
        )
    }

    #[test]
    fn git_short_name_rule_is_active() {
        let f = git(Fixture::builder()).build();
        let id = resolve(&f, "Git");

        assert_eq!(id.tokens(), ["bash", "git"]);
        // `Git` alone never matches by tokens; as an exact full name it needs a Tier A/B neighbour.
        assert!(id.matches_name("Git").is_none());
        let m = id.matches_full_name("Git").unwrap();
        assert_eq!(m.kind, EvidenceKind::ExactFullName);
        assert!(m.needs_tier_ab_neighbour);
        let m = id.matches_full_name("Git for Windows").unwrap();
        assert!(m.needs_tier_ab_neighbour);
        assert!(id.matches_name("Git for Windows").is_none());
        assert!(id.matches_name("GitHub Desktop").is_none());
        assert!(id.matches_name("GitKraken").is_none());
        // The longer exe name is an ordinary name.
        let m = id.matches_name("Git Bash").unwrap();
        assert!(!m.needs_tier_ab_neighbour);

        assert_eq!(
            id.main_exes()
                .iter()
                .map(|e| (e.stem.as_str(), e.basis))
                .collect::<Vec<_>>(),
            [
                ("git-bash", MainExeBasis::FileName),
                ("git", MainExeBasis::FileName)
            ]
        );
        assert!(id.names().iter().any(|n| n == "Git for Windows"));
        assert!(!id.names().iter().any(|n| n.contains("curl")));
        assert_eq!(
            id.vendor_aliases(),
            ["git development community", "gitforwindows"]
        );
        assert!(id.matches_vendor("Git").is_none());
    }

    const VSCODE: &str = "Microsoft Visual Studio Code (User)";
    const VSCODE_DIR: &str = r"C:\Users\kaan\AppData\Local\Programs\Microsoft VS Code";

    fn vscode(b: FixtureBuilder) -> FixtureBuilder {
        let b = arp(
            b,
            &hku_uninstall(),
            "{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1",
            &[
                ("DisplayName", VSCODE),
                ("Publisher", "Microsoft Corporation"),
                ("InstallLocation", &format!("{VSCODE_DIR}\\")),
                ("DisplayIcon", &format!("{VSCODE_DIR}\\Code.exe")),
                (
                    "UninstallString",
                    &format!("\"{VSCODE_DIR}\\unins000.exe\""),
                ),
                ("Inno Setup: App Path", VSCODE_DIR),
                ("URLInfoAbout", "https://code.visualstudio.com/"),
            ],
        );
        exe(
            b,
            &format!("{VSCODE_DIR}\\Code.exe"),
            180_000_000,
            Some((
                "Visual Studio Code",
                "Visual Studio Code",
                "Microsoft Corporation",
            )),
            Some("Microsoft Corporation"),
        )
    }

    #[test]
    fn vscode_mega_vendor_weighs_nothing_and_is_never_a_name() {
        let f = vscode(Fixture::builder()).build();
        let id = resolve(&f, VSCODE);

        assert!(id.mega_vendor());
        assert_eq!(id.name_matching(), NameMatching::Enabled);
        assert_eq!(id.tokens(), ["code", "studio", "visual"]);
        assert_eq!(id.main_exes()[0].basis, MainExeBasis::DisplayIcon);
        assert!(id.names().iter().any(|n| n == "Visual Studio Code"));

        let m = id.matches_vendor("Microsoft").unwrap();
        assert_eq!((m.kind, m.weight), (EvidenceKind::VendorContainer, 0));
        assert_eq!(
            id.matches_vendor("Microsoft Corporation").unwrap().weight,
            0
        );
        for segment in [
            "Microsoft",
            "Microsoft Corporation",
            "Code",
            "Visual Studio",
        ] {
            assert!(id.matches_name(segment).is_none(), "{segment}");
            assert!(id.matches_full_name(segment).is_none(), "{segment}");
        }
        assert!(
            id.matches_product_subfolder("Microsoft", "Microsoft")
                .is_none()
        );
        assert_eq!(
            id.matches_name("Visual Studio Code").unwrap().kind,
            EvidenceKind::NameTokenExact
        );
        assert_eq!(
            id.matches_full_name("Microsoft Visual Studio Code")
                .map(|m| m.kind),
            None,
            "`(User)` is part of the full name"
        );
        assert!(id.matches_full_name("Visual Studio Code").is_some());
    }

    #[test]
    fn notepad_plus_plus_keeps_its_symbol_token() {
        let b = arp(
            Fixture::builder(),
            HKLM_UNINSTALL,
            "Notepad++",
            &[
                ("DisplayName", "Notepad++ (64-bit x64)"),
                ("Publisher", "Notepad++ Team"),
                ("DisplayIcon", r"C:\Program Files\Notepad++\notepad++.exe"),
                (
                    "UninstallString",
                    r"C:\Program Files\Notepad++\uninstall.exe",
                ),
                ("URLInfoAbout", "https://notepad-plus-plus.org/"),
            ],
        );
        let f = exe(
            b,
            r"C:\Program Files\Notepad++\notepad++.exe",
            7_000_000,
            Some(("Notepad++", "Notepad++", "Don HO don.h@free.fr")),
            Some("Notepad++"),
        )
        .build();
        let id = resolve(&f, "Notepad++ (64-bit x64)");

        assert_eq!(id.tokens(), ["notepad++"]);
        assert_eq!(kinds(&id, "Notepad"), []);
        assert!(
            id.matches_product_subfolder("Notepad++", "Notepad")
                .is_none()
        );
        assert_eq!(
            kinds(&id, "Notepad++"),
            [
                EvidenceKind::NameTokenExact,
                EvidenceKind::ExactFullName,
                EvidenceKind::VendorContainer
            ]
        );
        assert!(id.vendor_aliases().contains(&"notepad++".to_owned()));
        // The URL label is a vendor spelling, not a name.
        assert!(id.matches_vendor("notepad-plus-plus").is_some());
        assert!(id.matches_name("notepad-plus-plus").is_none());
    }

    #[test]
    fn vc_redistributables_have_name_matching_disabled() {
        let rows = [
            (
                "{8bdfe669-9705-4184-9368-db9ce581e0e7}",
                "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810",
            ),
            (
                "{47109d57-d746-4f8b-9618-ed6a17cc922b}",
                "Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.40.33810",
            ),
            (
                "{050d4fc8-5d48-4b8f-8972-47c82c46020f}",
                "Microsoft Visual C++ 2013 Redistributable (x64) - 12.0.40664",
            ),
            (
                "{ca67548a-5ebe-413a-b50c-4b9ceb6d66c6}",
                "Microsoft Visual C++ 2012 Redistributable (x64) - 11.0.61030",
            ),
            (
                "{D5D19E2F-7189-42FE-8103-92CD1FA457C2}",
                "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.40.33810",
            ),
            (
                "{59CED48F-EBFE-480C-8A38-FC079C2BEC0F}",
                "Microsoft Visual C++ 2022 X64 Additional Runtime - 14.40.33810",
            ),
        ];
        let mut b = Fixture::builder();
        for (key, name) in rows {
            let icon = format!(r"C:\ProgramData\Package Cache\{key}\VC_redist.x64.exe");
            b = arp(
                b,
                HKLM_UNINSTALL,
                key,
                &[
                    ("DisplayName", name),
                    ("Publisher", "Microsoft Corporation"),
                    ("DisplayIcon", &format!("{icon},0")),
                ],
            );
            b = exe(
                b,
                &icon,
                25_000_000,
                Some((name, name, "Microsoft Corporation")),
                Some("Microsoft Corporation"),
            );
        }
        let f = b.build();
        for (_, name) in rows {
            let id = resolve(&f, name);
            assert!(id.mega_vendor(), "{name}");
            assert_eq!(id.name_matching(), NameMatching::Disabled, "{name}");
            assert!(id.tokens().is_empty(), "{name}");
            // The bundle exe is known, but its file name is not a name of the app.
            assert_eq!(id.main_exes().len(), 1, "{name}");
            assert!(
                !id.names().iter().any(|n| n.starts_with("VC_redist")),
                "{name}"
            );
            for segment in [
                name,
                "Microsoft Visual C++ 2015-2022 Redistributable",
                "Visual C++",
                "VC_redist.x64",
                "VC",
                "Microsoft",
            ] {
                assert!(id.matches_name(segment).is_none(), "{name}: {segment}");
                assert!(id.matches_full_name(segment).is_none(), "{name}: {segment}");
                assert!(
                    id.matches_product_subfolder("Microsoft", segment).is_none(),
                    "{name}: {segment}"
                );
            }
            assert_eq!(id.matches_vendor("Microsoft").unwrap().weight, 0, "{name}");
            // Disabled survives the snapshot.
            let reloaded = AppIdentity::from_snapshot(&id.snapshot());
            assert_eq!(reloaded.name_matching(), NameMatching::Disabled, "{name}");
        }
    }

    #[test]
    fn no_publisher_and_unsigned_exe_gives_no_vendor() {
        let b = arp(
            Fixture::builder(),
            HKLM_UNINSTALL,
            "ZealNotes",
            &[
                ("DisplayName", "Zeal Notes 2.1"),
                ("InstallLocation", r"D:\Tools\Zeal Notes"),
                ("UninstallString", r"D:\Tools\Zeal Notes\uninstall.exe"),
            ],
        );
        let b = exe(b, r"D:\Tools\Zeal Notes\zealnotes.exe", 900_000, None, None);
        let b = exe(b, r"D:\Tools\Zeal Notes\zeal.exe", 100_000, None, None);
        let f = exe(b, r"D:\Tools\Zeal Notes\uninstall.exe", 50_000, None, None).build();
        let id = resolve(&f, "Zeal Notes 2.1");

        assert!(id.vendors().is_empty());
        assert!(id.vendor_aliases().is_empty());
        assert!(!id.mega_vendor());
        assert_eq!(id.tokens(), ["notes", "zeal", "zealnotes"]);
        assert_eq!(id.names(), ["Zeal Notes 2.1", "ZealNotes", "zeal"]);
        for segment in ["Zeal Notes", "Zeal", "ZealNotes", "Notes", ""] {
            assert!(id.matches_vendor(segment).is_none(), "{segment}");
            assert!(
                id.matches_product_subfolder(segment, "Zeal Notes")
                    .is_none(),
                "{segment}"
            );
        }
        assert_eq!(
            kinds(&id, "Zeal Notes"),
            [EvidenceKind::NameTokenExact, EvidenceKind::ExactFullName]
        );
        assert!(id.matches_name("Notes").is_none());
        // Both exes relate by file name (the key name is `ZealNotes`); the uninstaller is left out.
        assert_eq!(
            id.main_exes()
                .iter()
                .map(|e| (e.stem.as_str(), e.basis, e.signer_cn.as_deref()))
                .collect::<Vec<_>>(),
            [
                ("zealnotes", MainExeBasis::FileName, None),
                ("zeal", MainExeBasis::FileName, None)
            ]
        );
    }

    #[test]
    fn non_ascii_publisher() {
        let b = arp(
            Fixture::builder(),
            HKLM_UNINSTALL,
            "CagriNotlar",
            &[
                ("DisplayName", "Çağrı Notlar Defteri"),
                ("Publisher", "Çağrı Yazılım Ltd."),
                (
                    "InstallLocation",
                    r"C:\Program Files\Çağrı Yazılım\Notlar Defteri",
                ),
                (
                    "DisplayIcon",
                    r"C:\Program Files\Çağrı Yazılım\Notlar Defteri\Defter.exe",
                ),
            ],
        );
        let f = exe(
            b,
            r"C:\Program Files\Çağrı Yazılım\Notlar Defteri\Defter.exe",
            500_000,
            Some(("Notlar Defteri", "Notlar Defteri", "ÇAĞRI YAZILIM LTD.")),
            Some("Çağrı Yazılım Limited"),
        )
        .build();
        let id = resolve(&f, "Çağrı Notlar Defteri");

        // Publisher, signer and CompanyName are one alias: case, the Turkish i's and the legal suffix
        // do not matter.
        assert_eq!(id.vendors().len(), 3);
        assert_eq!(id.vendor_aliases(), [vendor_key("çağrı yazılım")]);
        // The publisher is not a whole prefix of the name, so its first word stays a name token.
        assert_eq!(id.tokens(), ["cagrinotlar", "defteri", "notlar", "çağri"]);
        for segment in [
            "Çağrı Yazılım",
            "ÇAĞRI YAZILIM",
            "çağri yazilim",
            "Çağrı Yazılım Ltd",
        ] {
            assert_eq!(
                kinds(&id, segment),
                [EvidenceKind::VendorContainer],
                "{segment}"
            );
        }
        assert!(id.matches_vendor("Cagri Yazilim").is_none());
        assert_eq!(
            id.matches_product_subfolder("Çağrı Yazılım", "Notlar Defteri")
                .unwrap()
                .kind,
            EvidenceKind::ProductSubfolderOfVendor
        );
        assert!(id.matches_full_name("ÇAĞRI NOTLAR DEFTERİ").is_some());
        assert!(id.matches_name("Çağrı").is_none());

        let reloaded = AppIdentity::from_snapshot(&id.snapshot());
        assert_eq!(reloaded.vendor_aliases(), id.vendor_aliases());
        assert!(reloaded.matches_vendor("ÇAĞRI YAZILIM").is_some());
    }

    /// Segments that exercise every rule against every test app.
    const PROBES: &[&str] = &[
        "Mozilla",
        "mozilla.org",
        "Mozilla Corporation",
        "Firefox",
        "firefox",
        "Mozilla Firefox",
        "Mozilla Firefox 146.0 (x64 en-US)",
        "Firefox Developer Edition",
        "Thunderbird",
        "Mozilla Thunderbird",
        "Mozilla Maintenance Service",
        "Git",
        "Git for Windows",
        "Git Bash",
        "GitHub",
        "Microsoft",
        "Microsoft Corporation",
        "Code",
        "Visual Studio Code",
        "Microsoft Visual Studio Code (User)",
        "VisualStudio",
        "Visual Studio",
        "Notepad",
        "Notepad++",
        "",
    ];

    fn all_matches(id: &AppIdentity) -> Vec<Option<IdentityMatch>> {
        let mut out = Vec::new();
        for s in PROBES {
            out.push(id.matches_name(s));
            out.push(id.matches_full_name(s));
            out.push(id.matches_vendor(s));
            for v in PROBES {
                out.push(id.matches_product_subfolder(v, s));
            }
        }
        out
    }

    #[test]
    fn snapshot_round_trips_through_fingerprint_json() {
        let f = vscode(git(thunderbird(firefox(Fixture::builder())))).build();
        let all = entries(&f);
        assert_eq!(all.len(), 5);
        for e in &all {
            let hints = IdentityHints {
                kb_aliases: vec!["mozilla.org".into()],
                ..IdentityHints::default()
            }
            .with_arp_urls(&f, e);
            let id = AppIdentity::resolve_with(e, &all, &f, &hints);
            let snapshot = id.snapshot();

            let doc = json!({
                "schema": "purge.fp/0",
                "app": {"program_id": e.program_id, "display_name": e.display_name},
                "identity": snapshot,
                "os": {"edition": "Professional", "build": 26340, "ubr": 9882},
                "user_sid": SID,
                "verify_gone": null
            });
            let fp: Fingerprint = serde_json::from_value(doc).unwrap();
            let text = serde_json::to_string_pretty(&fp).unwrap();
            let fp: Fingerprint = serde_json::from_str(&text).unwrap();
            assert_eq!(fp.identity, snapshot, "{}", e.display_name);

            let reloaded = AppIdentity::from_snapshot(&fp.identity);
            assert_eq!(reloaded.names(), id.names());
            assert_eq!(reloaded.vendors(), id.vendors());
            assert_eq!(reloaded.vendor_aliases(), id.vendor_aliases());
            assert_eq!(reloaded.tokens(), id.tokens());
            assert_eq!(reloaded.name_matching(), id.name_matching());
            assert_eq!(reloaded.mega_vendor(), id.mega_vendor());
            assert_eq!(
                all_matches(&reloaded),
                all_matches(&id),
                "{}",
                e.display_name
            );
            // A second trip changes nothing.
            assert_eq!(reloaded.snapshot(), snapshot);
            assert!(reloaded.main_exes().is_empty());
        }
    }

    #[test]
    fn with_inno_adds_the_app_name() {
        let f = git(Fixture::builder()).build();
        let all = entries(&f);
        let e = entry(&all, "Git");
        let id = AppIdentity::resolve(e, &all, &f);
        assert!(id.matches_full_name("Git SCM").is_none());

        let with = id.clone().with_inno("Git SCM");
        assert_eq!(with.names().last().map(String::as_str), Some("Git SCM"));
        assert!(with.matches_full_name("Git SCM").is_some());
        assert_eq!(with.tokens(), ["bash", "git", "scm"]);
        // The same name again, a blank one or a GUID change nothing.
        assert_eq!(with.clone().with_inno("git scm"), with);
        assert_eq!(id.clone().with_inno("  "), id);
        assert_eq!(
            id.clone()
                .with_inno("{771FD6B0-FA20-440A-A002-3B3BAC16DC50}"),
            id
        );

        // Supplying it up front is the same as adding it later.
        let hints = IdentityHints {
            inno_app_name: Some("Git SCM".into()),
            ..IdentityHints::default()
        };
        let upfront = AppIdentity::resolve_with(e, &all, &f, &hints);
        assert!(upfront.matches_full_name("Git SCM").is_some());
        assert_eq!(upfront.tokens(), with.tokens());

        // After a reload the stored tokens decide: a new name cannot add any.
        let reloaded = AppIdentity::from_snapshot(&id.snapshot()).with_inno("Git SCM");
        assert_eq!(reloaded.tokens(), id.tokens());
    }

    #[test]
    fn bundled_and_unrelated_executables_give_no_identity() {
        let b = arp(
            Fixture::builder(),
            HKLM_UNINSTALL,
            "Lumen Studio",
            &[
                ("DisplayName", "Lumen Studio"),
                ("Publisher", "Lumen Labs"),
                ("InstallLocation", "\"C:\\Program Files\\Lumen Studio\\\""),
            ],
        );
        // Only bundled tools, none related to the app's names.
        let b = exe(
            b,
            r"C:\Program Files\Lumen Studio\bin\node.exe",
            80_000_000,
            Some(("Node.js", "Node.js JavaScript Runtime", "Node.js")),
            Some("OpenJS Foundation"),
        );
        let f = exe(
            b,
            r"C:\Program Files\Lumen Studio\ffmpeg.exe",
            60_000_000,
            Some(("FFmpeg", "FFmpeg", "FFmpeg Project")),
            None,
        )
        .build();
        let id = resolve(&f, "Lumen Studio");

        assert_eq!(id.names(), ["Lumen Studio"]);
        assert_eq!(id.vendors(), ["Lumen Labs"]);
        assert_eq!(id.main_exes().len(), 1);
        assert_eq!(id.main_exes()[0].basis, MainExeBasis::LargestOnly);
        assert_eq!(id.main_exes()[0].stem, "node");
        assert!(id.main_exes()[0].signer_cn.is_none());
        assert!(id.matches_name("Node.js").is_none());
        assert!(id.matches_vendor("OpenJS").is_none());
        assert!(id.matches_vendor("Node.js").is_none());

        // With a related exe present the bundled ones are not main exes at all.
        let mut f = f;
        f.add_file(r"C:\Program Files\Lumen Studio\Lumen.exe", 1_000);
        let id = resolve(&f, "Lumen Studio");
        assert_eq!(
            id.main_exes()
                .iter()
                .map(|e| (e.stem.as_str(), e.basis))
                .collect::<Vec<_>>(),
            [("Lumen", MainExeBasis::FileName)]
        );
    }

    #[test]
    fn shared_or_unresolved_install_locations_are_not_listed() {
        for location in [
            r"C:\Program Files",
            r"C:\Windows\System32",
            r"C:\",
            r"%ProgramFiles%\Tool",
            r"..\Tool",
        ] {
            let b = arp(
                Fixture::builder(),
                HKLM_UNINSTALL,
                "Orbit Tool",
                &[
                    ("DisplayName", "Orbit Tool"),
                    ("Publisher", "Orbit"),
                    ("InstallLocation", location),
                    ("DisplayIcon", r"C:\Windows\System32\orbit.exe,0"),
                ],
            );
            let b = exe(
                b,
                r"C:\Program Files\orbit.exe",
                10,
                None,
                Some("Someone Else"),
            );
            let b = exe(
                b,
                r"C:\Program Files\Tool\orbit.exe",
                10,
                None,
                Some("Someone Else"),
            );
            let f = exe(
                b,
                r"C:\Windows\System32\orbit.exe",
                10,
                None,
                Some("Someone Else"),
            )
            .build();
            let id = resolve(&f, "Orbit Tool");
            assert!(id.main_exes().is_empty(), "{location}");
            assert_eq!(id.vendors(), ["Orbit"], "{location}");
        }

        // With the user's environment the variable resolves.
        let b = arp(
            Fixture::builder(),
            HKLM_UNINSTALL,
            "Orbit Tool",
            &[
                ("DisplayName", "Orbit Tool"),
                ("Publisher", "Orbit"),
                ("InstallLocation", r"%ProgramFiles%\Tool"),
            ],
        );
        let f = exe(
            b,
            r"C:\Program Files\Tool\orbit.exe",
            10,
            None,
            Some("Orbit GmbH"),
        )
        .build();
        let all = entries(&f);
        let hints = IdentityHints {
            env: BTreeMap::from([("ProgramFiles".to_owned(), r"C:\Program Files".to_owned())]),
            ..IdentityHints::default()
        };
        let id = AppIdentity::resolve_with(&all[0], &all, &f, &hints);
        assert_eq!(id.main_exes().len(), 1);
        assert_eq!(id.vendors(), ["Orbit", "Orbit GmbH"]);
        assert_eq!(id.vendor_aliases(), ["orbit"]);
    }

    #[test]
    fn entry_missing_from_the_inventory_slice_is_still_counted() {
        let f = firefox(Fixture::builder()).build();
        let all = entries(&f);
        let alone = AppIdentity::resolve(&all[0], &[], &f);
        let listed = AppIdentity::resolve(&all[0], &all, &f);
        assert_eq!(alone, listed);
    }

    #[test]
    fn launcher_style_key_name_is_not_the_launchers_name() {
        let b = arp(
            Fixture::builder(),
            HKLM_UNINSTALL,
            "Steam",
            &[
                ("DisplayName", "Steam"),
                ("Publisher", "Valve Corporation"),
                ("InstallLocation", r"C:\Program Files (x86)\Steam"),
                ("DisplayIcon", r"C:\Program Files (x86)\Steam\steam.exe"),
            ],
        );
        let b = exe(
            b,
            r"C:\Program Files (x86)\Steam\steam.exe",
            4_000_000,
            Some(("Steam", "Steam", "Valve Corporation")),
            Some("Valve Corp."),
        );
        let f = arp(
            b,
            HKLM_UNINSTALL,
            "Steam App 620",
            &[
                ("DisplayName", "Portal 2"),
                ("Publisher", "Valve"),
                (
                    "InstallLocation",
                    r"C:\Program Files (x86)\Steam\steamapps\common\Portal 2",
                ),
                // Borrowed from the launcher, whose folder is another entry's InstallLocation.
                ("DisplayIcon", r"C:\Program Files (x86)\Steam\steam.exe"),
                (
                    "UninstallString",
                    r#""C:\Program Files (x86)\Steam\steam.exe" steam://uninstall/620"#,
                ),
            ],
        )
        .build();
        let id = resolve(&f, "Portal 2");

        assert_eq!(id.names(), ["Portal 2"]);
        assert_eq!(id.tokens(), ["portal"]);
        assert!(id.main_exes().is_empty());
        for segment in ["Steam", "Steam App 620", "steam"] {
            assert!(id.matches_name(segment).is_none(), "{segment}");
            assert!(id.matches_full_name(segment).is_none(), "{segment}");
        }
        assert!(id.matches_full_name("Portal 2").is_some());

        // The launcher keeps its own key name and exe.
        let steam = resolve(&f, "Steam");
        assert_eq!(steam.tokens(), ["steam"]);
        assert_eq!(steam.main_exes().len(), 1);
        assert!(steam.matches_name("Portal 2").is_none());
    }

    #[test]
    fn component_with_a_borrowed_exe_does_not_take_the_host_identity() {
        let host = |b: FixtureBuilder| {
            let b = arp(
                b,
                HKLM_UNINSTALL,
                "Quillfeather",
                &[
                    ("DisplayName", "Quillfeather 4.2"),
                    ("Publisher", "Inkwell Works"),
                    ("InstallLocation", r"C:\Program Files\Quillfeather\"),
                ],
            );
            exe(
                b,
                r"C:\Program Files\Quillfeather\quillfeather.exe",
                3_000_000,
                Some(("Quillfeather", "Quillfeather", "Inkwell Works")),
                Some("Inkwell Works LLC"),
            )
        };
        let component = |b: FixtureBuilder, values: &[(&str, &str)]| {
            let mut all = vec![
                ("DisplayName", "Quillfeather Thesaurus Rex"),
                ("Publisher", "Third Party Words"),
            ];
            all.extend_from_slice(values);
            arp(
                b,
                HKLM_UNINSTALL,
                "{0F7C2A54-93B1-4E0E-8E55-7D2A6C1B9E10}",
                &all,
            )
        };

        // The icon points into the host's folder: the exe is not this app's at all.
        let f = component(
            host(Fixture::builder()),
            &[(
                "DisplayIcon",
                r"c:\program files\QUILLFEATHER\quillfeather.exe,0",
            )],
        )
        .build();
        let id = resolve(&f, "Quillfeather Thesaurus Rex");
        assert!(id.main_exes().is_empty());
        assert_eq!(id.names(), ["Quillfeather Thesaurus Rex"]);
        assert_eq!(id.vendors(), ["Third Party Words"]);
        assert!(id.matches_vendor("Inkwell Works").is_none());

        // The component claims the host's folder as its own InstallLocation: the exe is listed, but
        // its name and version strings are the host's name and stay out.
        let f = component(
            host(Fixture::builder()),
            &[("InstallLocation", r"C:\Program Files\Quillfeather")],
        )
        .build();
        let id = resolve(&f, "Quillfeather Thesaurus Rex");
        assert_eq!(id.main_exes().len(), 1);
        assert_eq!(id.names(), ["Quillfeather Thesaurus Rex"]);
        for segment in ["Quillfeather", "quillfeather", "Quillfeather 4.2"] {
            assert!(id.matches_name(segment).is_none(), "{segment}");
            assert!(id.matches_full_name(segment).is_none(), "{segment}");
        }
        assert!(id.matches_name("Quillfeather Thesaurus Rex").is_some());

        // Without the host installed the same strings are ordinary spellings of the app's name.
        let b = component(
            Fixture::builder(),
            &[("InstallLocation", r"C:\Program Files\Quillfeather")],
        );
        let f = exe(
            b,
            r"C:\Program Files\Quillfeather\quillfeather.exe",
            3_000_000,
            Some(("Quillfeather", "Quillfeather", "Inkwell Works")),
            None,
        )
        .build();
        let id = resolve(&f, "Quillfeather Thesaurus Rex");
        assert!(id.names().iter().any(|n| n == "quillfeather"));

        // The host itself is unaffected by the component.
        let f = component(
            host(Fixture::builder()),
            &[("InstallLocation", r"C:\Program Files\Quillfeather")],
        )
        .build();
        let id = resolve(&f, "Quillfeather 4.2");
        assert!(id.matches_full_name("Quillfeather").is_some());
        assert_eq!(id.main_exes().len(), 1);
    }

    #[test]
    fn two_versions_of_one_product_keep_their_file_names() {
        let mut b = Fixture::builder();
        for v in ["3.12", "3.13"] {
            let dir = format!(r"C:\Program Files\Pythia{v}");
            b = arp(
                b,
                HKLM_UNINSTALL,
                &format!("Pythia {v}"),
                &[
                    ("DisplayName", &format!("Pythia {v} (64-bit)")),
                    ("InstallLocation", &dir),
                ],
            );
            b = exe(b, &format!(r"{dir}\pythia.exe"), 100_000, None, None);
        }
        let f = b.build();
        let id = resolve(&f, "Pythia 3.12 (64-bit)");
        assert_eq!(id.main_exes().len(), 1);
        assert!(id.names().iter().any(|n| n == "pythia"));
    }

    #[test]
    fn install_location_that_win32_would_rewrite_is_ignored() {
        for location in [
            r"C:\Program Files.",
            r"C:\Windows \System32",
            r"C:\PROGRA~1",
        ] {
            let b = arp(
                Fixture::builder(),
                HKLM_UNINSTALL,
                "Orbit Tool",
                &[
                    ("DisplayName", "Orbit Tool"),
                    ("Publisher", "Orbit"),
                    ("InstallLocation", location),
                ],
            );
            let b = exe(b, &format!(r"{location}\orbit.exe"), 10, None, Some("X"));
            let f = exe(
                b,
                &format!(r"{location}\Sub\orbit.exe"),
                10,
                None,
                Some("X"),
            )
            .build();
            let id = resolve(&f, "Orbit Tool");
            assert!(id.main_exes().is_empty(), "{location}");
            assert_eq!(id.vendors(), ["Orbit"], "{location}");
        }
    }

    #[test]
    fn unreadable_file_facts_are_warnings_not_failures() {
        let mut f = firefox(Fixture::builder()).build();
        f.set_unknown_file_facts(true);
        f.add_file(r"C:\Program Files\Mozilla Firefox\firefox-agent.exe", 5);
        let id = resolve(&f, FIREFOX);
        assert_eq!(id.tokens(), ["agent", "firefox"]);
        assert!(id.matches_name("Firefox").is_some());
        assert!(
            id.warnings()
                .iter()
                .any(|w| w.contains("firefox-agent.exe")),
            "{:?}",
            id.warnings()
        );
    }
}
