//! The reference scan: a bounded walk over the reference-index scope that reports every registry value
//! referring to one of an app's anchors (ENGINE_PLAN.md §5.5 "Reference index", §5.1, §1.3).
//!
//! It runs twice per uninstall: once at harvest, where its hits become the pre-uninstall reference
//! snapshot, and once after the uninstall. Both runs go through a [`RegistrySource`], so the scan works
//! the same on the live registry and on a fixture.
//!
//! # Scope
//!
//! [`Scope::standard`] is the §5.5 scope, in this fixed order:
//!
//! 1. `HKLM\SOFTWARE` (the 32-bit view is its `WOW6432Node` subtree),
//! 2. `HKLM\SYSTEM\ControlSet00N\Services` and
//!    `HKLM\SYSTEM\ControlSet00N\Control\Session Manager\Environment`, for the current control set only,
//! 3. for every loaded user hive: `HKU\<SID>\Software`, `HKU\<SID>\Environment`, `HKU\<SID>_Classes`.
//!
//! Nothing outside the scope's roots is read. A root that does not exist is skipped.
//!
//! # What is tested
//!
//! For every value of every key: the value **name**, `REG_SZ` / `REG_EXPAND_SZ` data, **each**
//! `REG_MULTI_SZ` segment, and the UTF-16 strings inside the first 4 KB of `REG_BINARY` (and `REG_NONE` or
//! unknown-type) data. `REG_DWORD`, `REG_QWORD` and `REG_LINK` data is not tested. The matching itself is
//! the [`RefMatcher`]'s (case-insensitive, separator-aware, environment expanded).
//!
//! # Data the scan sees only in part
//!
//! A binary value longer than the 4 KB window, and a value whose data the source holds only a prefix of
//! (a rig snapshot's preview), end where the scan stops reading, not where the data ends. A string that
//! reaches that edge may go on: `C:\Program Files\App` may be the start of `C:\Program Files\App Two\x.exe`.
//! A hit that would not survive such a continuation has [`RefHit::cut_edge`] set. It is a possible
//! reference, not a proven one: it must never attribute the value to the app, and it must still count
//! when the question is whether something else may refer to an anchor.
//!
//! # What is never done
//!
//! - **Links are not followed.** A key that is a registry link is counted and skipped, with its values
//!   and whatever the source lists below it. `HKU\<SID>\Software\Classes` is such a link; its content is
//!   scanned once, as `HKU\<SID>_Classes`.
//! - **Pruned keys are not entered.** The scope carries a prune list ([`default_prune`]) of large stores
//!   that other mechanisms own (the MSI and AppX registration stores, component servicing). This is for
//!   speed only: a caller that wants them scanned passes its own list.
//!
//! # Order and completeness
//!
//! Roots are walked in scope order, keys depth first, subkeys and values in case-insensitive name order,
//! and for one value the name is reported before the data. Two scans of the same registry give the same
//! hits in the same order whatever order the source lists things in.
//!
//! # Speed
//!
//! Keys are read through the source's [`KeyWalker`] (on the live registry: one open per key, below
//! the keys of the previous path still open). A scan without progress reports and without a key
//! budget reads on up to eight threads: the scope is split into subtrees in walk order, the subtrees
//! are walked at once, and the pieces are put together in walk order, so the hits, their order and
//! the statistics are exactly those of the one-thread walk.
//!
//! A scan never fails as a whole. Keys that could not be read are listed in
//! [`RefScanStats::unreadable`]; [`RefScan::is_complete`] says whether the hits cover the whole scope. A
//! consumer that concludes "nothing references this anchor" must check it.

use std::ops::ControlFlow;

use purge_model::{AnchorKind, AnchorRef, RefCarrier};
use purge_source::registry::{KeyWalker, RegistrySource};
use purge_source::types::{
    BINARY_UTF16_SCAN_MAX, KeyInfo, REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_EXPAND_SZ, REG_LINK,
    REG_MULTI_SZ, REG_QWORD, REG_SZ, RegValue, SourceError, SourceResult,
};

use crate::matcher::{MIN_BINARY_RUN, MatchHow, RefMatch, RefMatcher, utf16_runs};
use crate::queries::data_hash;

// ---------------------------------------------------------------------------------------------------------
// Hits
// ---------------------------------------------------------------------------------------------------------

/// Where in a value a reference was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RefWhere {
    /// The value's name.
    Name,
    /// `REG_SZ` or `REG_EXPAND_SZ` data.
    Data,
    /// The `REG_MULTI_SZ` segment with this zero-based index (empty segments in the middle of the list
    /// count, as in [`purge_source::types::RegData::multi_sz`]).
    Segment(u32),
    /// A UTF-16 string inside binary data.
    Binary,
}

impl RefWhere {
    /// The carrier as the fingerprint records it.
    pub fn carrier(self) -> RefCarrier {
        match self {
            RefWhere::Name => RefCarrier::ValueName,
            RefWhere::Data => RefCarrier::Data,
            RefWhere::Segment(_) => RefCarrier::Segment,
            RefWhere::Binary => RefCarrier::Binary,
        }
    }

    /// The segment index of a `REG_MULTI_SZ` hit.
    pub fn segment(self) -> Option<u32> {
        match self {
            RefWhere::Segment(i) => Some(i),
            _ => None,
        }
    }
}

/// One registry value that refers to an anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefHit {
    /// Canonical path of the value's key, built from the scope root and the subkey names as the source
    /// spells them.
    pub key: String,
    /// The value's name; empty for the default value.
    pub value_name: String,
    /// Where in the value the reference is.
    pub location: RefWhere,
    /// The anchor it refers to (kind and text as added to the anchor set).
    pub anchor: AnchorRef,
    /// How the tested string relates to the anchor.
    pub how: MatchHow,
    /// The match needed `%NAME%` expansion.
    pub via_env: bool,
    /// The anchor is a bare exe name, which says nothing about the directory.
    pub name_only: bool,
    /// For a root or exe-path match: the path the string names, in the matcher's folded form.
    pub path: Option<String>,
    /// The value's registry type.
    pub value_type: u32,
    /// Hash of the value's data ([`data_hash`]): the first 16 hex digits of its SHA-256, as a number.
    pub data_hash: Option<u64>,
    /// The source had the value's full data. When `false` the data was cut short or unknown, and
    /// references in the missing part are not reported.
    pub data_complete: bool,
    /// The matched text reaches the point where the scan stopped reading the data (the end of a cut
    /// preview, or of the binary window of a longer value), and the match depends on the data ending
    /// there. The full data may name something else (`...\App` cut from `...\App Two\x.exe`), so the hit
    /// is a possible reference only. Never set for a hit in a value name or in fully read data.
    pub cut_edge: bool,
    /// Number of values the key has.
    pub parent_values: u32,
    /// Number of subkeys the key has.
    pub parent_subkeys: u32,
}

impl RefHit {
    /// The kind of the matched anchor.
    pub fn anchor_kind(&self) -> AnchorKind {
        self.anchor.kind
    }

    /// The carrier as the fingerprint records it.
    pub fn carrier(&self) -> RefCarrier {
        self.location.carrier()
    }
}

// ---------------------------------------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------------------------------------

/// How values are tested and how far a scan may go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefScanOptions {
    /// Report every anchor a string refers to. By default only the strongest one is reported for each
    /// name, data string, segment or binary value (the order of [`RefMatcher::find`]).
    pub all_anchors: bool,
    /// How many leading bytes of a binary value are searched for UTF-16 strings (§5.5: 4 KB).
    pub binary_scan_max: usize,
    /// Stop after visiting this many keys; the scan is then [`RefScanStats::truncated`]. `None` for no
    /// budget.
    pub max_keys: Option<u64>,
    /// Call the progress callback after every this many keys (and at the start of each root).
    pub progress_every: u32,
}

impl Default for RefScanOptions {
    fn default() -> Self {
        Self {
            all_anchors: false,
            binary_scan_max: BINARY_UTF16_SCAN_MAX,
            max_keys: None,
            progress_every: 4096,
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------------------------------------

/// The default prune list: stores that are large, hold no leftovers this engine removes by reference, and
/// are owned by another mechanism.
///
/// - the MSI registration stores (`Classes\Installer`, `Installer\UserData`): Windows Installer's own
///   bookkeeping, handled through the MSI API;
/// - component servicing and side-by-side;
/// - the AppX package stores and the WinRT class registrations of packages.
///
/// An entry is a full key path; a `*` segment stands for exactly one key name (a SID, for instance).
pub fn default_prune() -> Vec<String> {
    [
        r"HKLM\SOFTWARE\Classes\Installer",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore",
        r"HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository",
        r"HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository",
        r"HKLM\SOFTWARE\Classes\ActivatableClasses",
        r"HKU\*\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository",
        r"HKU\*\ActivatableClasses",
        // Restart Manager sessions: Windows' own short-lived state, written while an installer or
        // uninstaller runs (the files it asked about) and removed by Windows. Never an app's leftover.
        r"HKU\*\Software\Microsoft\RestartManager",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn fold_segments(path: &str) -> Vec<String> {
    path.split('\\')
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// Whether `key` is `root` or lies below it (both folded).
fn at_or_below(key: &[String], root: &[String]) -> bool {
    key.len() >= root.len() && key[..root.len()] == *root
}

/// The keys a reference scan walks: a list of root keys and a list of keys not to enter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    roots: Vec<String>,
    roots_folded: Vec<Vec<String>>,
    prune: Vec<String>,
    prune_folded: Vec<Vec<String>>,
}

impl Scope {
    /// The §5.5 scope for every user hive the source reports as loaded, with the [`default_prune`] list.
    pub fn standard(reg: &dyn RegistrySource) -> SourceResult<Self> {
        let sids = reg.loaded_user_sids()?;
        Self::for_sids(reg, &sids)
    }

    /// The §5.5 scope for the given user SIDs only (the machine roots are always included), with the
    /// [`default_prune`] list.
    pub fn for_sids<S: AsRef<str>>(reg: &dyn RegistrySource, sids: &[S]) -> SourceResult<Self> {
        let n = reg.current_control_set()?;
        let mut roots = vec![
            r"HKLM\SOFTWARE".to_string(),
            format!(r"HKLM\SYSTEM\ControlSet{n:03}\Services"),
            format!(r"HKLM\SYSTEM\ControlSet{n:03}\Control\Session Manager\Environment"),
        ];
        let mut sids: Vec<&str> = sids
            .iter()
            .map(|s| s.as_ref().trim_matches('\\'))
            .filter(|s| !s.is_empty() && !s.contains('\\'))
            .collect();
        sids.sort_by_key(|s| s.to_lowercase());
        for sid in sids {
            roots.push(format!(r"HKU\{sid}\Software"));
            roots.push(format!(r"HKU\{sid}\Environment"));
            roots.push(format!(r"HKU\{sid}_Classes"));
        }
        Ok(Self::custom(roots, default_prune()))
    }

    /// A scope over the given root keys and prune list. Roots keep their order; a root that repeats an
    /// earlier one, or lies below another root of the list, is dropped, so no key is walked twice.
    pub fn custom<R, P>(roots: R, prune: P) -> Self
    where
        R: IntoIterator,
        R::Item: Into<String>,
        P: IntoIterator,
        P::Item: Into<String>,
    {
        let all: Vec<(String, Vec<String>)> = roots
            .into_iter()
            .map(|r| {
                let r: String = r.into();
                let folded = fold_segments(&r);
                (r.trim_end_matches('\\').to_string(), folded)
            })
            .filter(|(_, folded)| !folded.is_empty())
            .collect();
        let mut kept: Vec<(String, Vec<String>)> = Vec::new();
        for (i, (root, folded)) in all.iter().enumerate() {
            let covered = all.iter().enumerate().any(|(j, (_, other))| {
                j != i && at_or_below(folded, other) && (other.len() < folded.len() || j < i)
            });
            if !covered {
                kept.push((root.clone(), folded.clone()));
            }
        }
        let (roots, roots_folded) = kept.into_iter().unzip();
        let mut scope = Self {
            roots,
            roots_folded,
            prune: Vec::new(),
            prune_folded: Vec::new(),
        };
        scope.set_prune(prune);
        scope
    }

    fn set_prune<P>(&mut self, prune: P)
    where
        P: IntoIterator,
        P::Item: Into<String>,
    {
        self.prune = prune.into_iter().map(Into::into).collect();
        self.prune_folded = self
            .prune
            .iter()
            .map(|p| fold_segments(p))
            .filter(|p| !p.is_empty())
            .collect();
    }

    /// The same roots with another prune list (see [`default_prune`] for the entry syntax). An empty list
    /// scans everything below the roots.
    pub fn with_prune<P>(mut self, prune: P) -> Self
    where
        P: IntoIterator,
        P::Item: Into<String>,
    {
        self.set_prune(prune);
        self
    }

    /// The root keys, in walk order.
    pub fn roots(&self) -> &[String] {
        &self.roots
    }

    /// The prune list.
    pub fn prune(&self) -> &[String] {
        &self.prune
    }

    /// Whether the key itself is on the prune list (a key below a pruned key is not, but the walk never
    /// reaches it).
    pub fn is_pruned(&self, key: &str) -> bool {
        self.is_pruned_folded(&fold_segments(key))
    }

    fn is_pruned_folded(&self, key: &[String]) -> bool {
        self.prune_folded.iter().any(|pattern| {
            pattern.len() == key.len() && pattern.iter().zip(key).all(|(p, k)| p == "*" || p == k)
        })
    }

    /// Whether a scan of this scope would walk the key: it is at or below a root, and neither it nor one
    /// of its ancestors is pruned. (Links are a property of the registry, not of the scope.)
    pub fn contains(&self, key: &str) -> bool {
        let folded = fold_segments(key);
        self.roots_folded.iter().any(|r| at_or_below(&folded, r))
            && (1..=folded.len()).all(|n| !self.is_pruned_folded(&folded[..n]))
    }
}

// ---------------------------------------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------------------------------------

/// A key the scan could not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable {
    /// The key.
    pub key: String,
    /// Why (access denied, not captured by a fixture, …).
    pub error: SourceError,
}

/// At most this many unreadable keys are listed; [`RefScanStats::unreadable_total`] counts all of them.
pub const MAX_UNREADABLE_LISTED: usize = 1024;

/// Counters of one scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefScanStats {
    /// Keys whose values were read (or tried).
    pub keys_visited: u64,
    /// Values tested.
    pub values_tested: u64,
    /// Values whose data the source did not have in full (cut short or unknown). Their names were still
    /// tested, and the known prefix of cut data.
    pub incomplete_values: u64,
    /// Hits with [`RefHit::cut_edge`] set: possible references the scan could not prove.
    pub cut_edge_hits: u64,
    /// Keys skipped because of the prune list.
    pub pruned: u64,
    /// Registry links skipped.
    pub links_skipped: u64,
    /// Scope roots that do not exist.
    pub roots_missing: Vec<String>,
    /// Keys whose metadata, values or subkey list could not be read (first error per key), up to
    /// [`MAX_UNREADABLE_LISTED`].
    pub unreadable: Vec<Unreadable>,
    /// Number of unreadable keys, including those not listed.
    pub unreadable_total: u64,
    /// The progress callback stopped the scan.
    pub cancelled: bool,
    /// The key budget ([`RefScanOptions::max_keys`]) ran out.
    pub truncated: bool,
}

/// The outcome of a reference scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefScan {
    /// The hits, in walk order.
    pub hits: Vec<RefHit>,
    /// What was walked and what was not.
    pub stats: RefScanStats,
}

impl RefScan {
    /// Whether the hits cover the whole scope: the scan was neither cancelled nor cut by its key budget
    /// and every key could be read. Missing roots, pruned keys and links do not make a scan incomplete;
    /// values with incomplete data do not either (see [`RefScanStats::incomplete_values`]), nor does the
    /// 4 KB bound on binary data: references past it are outside the index by design (§5.5).
    pub fn is_complete(&self) -> bool {
        !self.stats.cancelled && !self.stats.truncated && self.stats.unreadable_total == 0
    }
}

/// What the progress callback is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefScanProgress<'a> {
    /// The scope root being walked.
    pub root: &'a str,
    /// Zero-based index of that root in the scope.
    pub root_index: usize,
    /// Number of roots in the scope.
    pub root_count: usize,
    /// The key about to be read.
    pub key: &'a str,
    /// Keys visited so far.
    pub keys_visited: u64,
    /// Values tested so far.
    pub values_tested: u64,
    /// Hits so far.
    pub hits: usize,
}

/// The progress callback: called at the start of each root and every
/// [`RefScanOptions::progress_every`] keys; returning [`ControlFlow::Break`] cancels the scan.
pub type ProgressFn<'a> = dyn FnMut(&RefScanProgress<'_>) -> ControlFlow<()> + 'a;

// ---------------------------------------------------------------------------------------------------------
// Testing one value
// ---------------------------------------------------------------------------------------------------------

/// What a string cut at the edge of the known data is continued with to see which matches depend on the
/// cut: a letter (ends a path segment, a file name, an identifier or a token that stopped at the edge)
/// followed by a step back out of whatever directory the string was naming.
const CUT_PROBE: &str = r"x\..\x";

/// Splits the matches of a cut string into proven ones (they also hold when the string goes on; reported
/// with the relation and path of the continued string, so never as "the whole string") and those that
/// depend on the cut (flagged `true`). Proven matches come first; each group keeps the matcher's order.
fn split_by_probe(plain: Vec<RefMatch>, probed: &[RefMatch]) -> Vec<(RefMatch, bool)> {
    let mut proven = Vec::with_capacity(plain.len());
    let mut at_edge = Vec::new();
    for m in plain {
        match probed
            .iter()
            .find(|p| p.anchor == m.anchor && p.name_only == m.name_only)
        {
            Some(p) => proven.push((p.clone(), false)),
            None => at_edge.push((m, true)),
        }
    }
    proven.extend(at_edge);
    proven
}

/// The matches of one string, each with its cut-edge flag. `cut` says the string may go on past its end.
fn string_matches(matcher: &RefMatcher, s: &str, cut: bool) -> Vec<(RefMatch, bool)> {
    let plain = matcher.find_all(s);
    if !cut || plain.is_empty() {
        return plain.into_iter().map(|m| (m, false)).collect();
    }
    let probed = matcher.find_all(&format!("{s}{CUT_PROBE}"));
    split_by_probe(plain, &probed)
}

/// The UTF-16 run that reaches the end of `window`, for each byte alignment that has one of at least
/// [`MIN_BINARY_RUN`] characters; spelled exactly as [`utf16_runs`] spells it.
fn edge_runs(window: &[u8]) -> Vec<String> {
    // One unit is printable exactly when `utf16_runs` makes a run of it.
    let printable = |unit: [u8; 2]| !utf16_runs(&unit, 1).is_empty();
    let mut runs = Vec::new();
    for offset in 0..2.min(window.len()) {
        let mut chars: Vec<char> = window[offset..]
            .chunks_exact(2)
            .rev()
            .map(|pair| [pair[0], pair[1]])
            .take_while(|&unit| printable(unit))
            .filter_map(|unit| char::from_u32(u32::from(u16::from_le_bytes(unit))))
            .collect();
        if chars.len() >= MIN_BINARY_RUN {
            chars.reverse();
            runs.push(chars.into_iter().collect());
        }
    }
    runs
}

/// The matches in a binary window, each with its cut-edge flag. `cut` says data follows the window.
fn binary_matches(matcher: &RefMatcher, window: &[u8], cut: bool) -> Vec<(RefMatch, bool)> {
    let plain = matcher.find_in_binary(window);
    if !cut || plain.is_empty() {
        return plain.into_iter().map(|m| (m, false)).collect();
    }
    // Runs that end inside the window are complete; the one at the edge (per alignment) may go on.
    let mut inner = utf16_runs(window, MIN_BINARY_RUN);
    let edges = edge_runs(window);
    for edge in &edges {
        if let Some(at) = inner.iter().rposition(|run| run == edge) {
            inner.remove(at);
        }
    }
    let mut probed: Vec<RefMatch> = Vec::new();
    for run in &inner {
        probed.extend(matcher.find_all(run));
    }
    for edge in &edges {
        probed.extend(matcher.find_all(&format!("{edge}{CUT_PROBE}")));
    }
    split_by_probe(plain, &probed)
}

/// Tests one value against the matcher: its name, then its data by type (see the module documentation).
///
/// `parent_values` and `parent_subkeys` are copied into the hits. This is the unit both the scan and the
/// targeted queries are built from; scanners that already hold a value may call it directly.
pub fn value_hits(
    matcher: &RefMatcher,
    key: &str,
    value: &RegValue,
    parent_values: u32,
    parent_subkeys: u32,
    options: &RefScanOptions,
) -> Vec<RefHit> {
    // Proven matches come first, so the single reported anchor is a proven one whenever there is one.
    let pick = |matches: Vec<(RefMatch, bool)>| -> Vec<(RefMatch, bool)> {
        if options.all_anchors {
            matches
        } else {
            matches.into_iter().take(1).collect()
        }
    };
    let mut found: Vec<(RefWhere, RefMatch, bool)> = Vec::new();
    found.extend(
        pick(string_matches(matcher, &value.name, false))
            .into_iter()
            .map(|(m, cut)| (RefWhere::Name, m, cut)),
    );
    let data = &value.data;
    if !data.data_unknown {
        match data.ty {
            REG_SZ | REG_EXPAND_SZ => {
                if let Some(s) = data.string() {
                    // The string ends at its first NUL; without one in the known prefix it is cut.
                    let terminated = data.bytes.chunks_exact(2).any(|unit| unit == [0, 0]);
                    let cut = data.truncated && !terminated;
                    found.extend(
                        pick(string_matches(matcher, &s, cut))
                            .into_iter()
                            .map(|(m, cut)| (RefWhere::Data, m, cut)),
                    );
                }
            }
            REG_MULTI_SZ => {
                let segments = data.multi_sz().unwrap_or_default();
                // A cut list goes on in its last segment unless the known prefix ends with a NUL.
                let ends_with_nul = data
                    .bytes
                    .chunks_exact(2)
                    .next_back()
                    .is_none_or(|unit| unit == [0, 0]);
                let cut_last = data.truncated && !ends_with_nul;
                for (i, segment) in segments.iter().enumerate() {
                    let at = RefWhere::Segment(u32::try_from(i).unwrap_or(u32::MAX));
                    let cut = cut_last && i + 1 == segments.len();
                    found.extend(
                        pick(string_matches(matcher, segment, cut))
                            .into_iter()
                            .map(|(m, cut)| (at, m, cut)),
                    );
                }
            }
            REG_DWORD | REG_DWORD_BIG_ENDIAN | REG_QWORD | REG_LINK => {}
            _ => {
                let window = &data.bytes[..data.bytes.len().min(options.binary_scan_max)];
                let cut = data.truncated || data.bytes.len() > window.len();
                found.extend(
                    pick(binary_matches(matcher, window, cut))
                        .into_iter()
                        .map(|(m, cut)| (RefWhere::Binary, m, cut)),
                );
            }
        }
    }
    if found.is_empty() {
        return Vec::new();
    }
    let hash = data_hash(data);
    found
        .into_iter()
        .map(|(location, m, cut_edge)| RefHit {
            key: key.to_string(),
            value_name: value.name.clone(),
            location,
            anchor: m.anchor,
            how: m.how,
            via_env: m.via_env,
            name_only: m.name_only,
            path: m.path,
            value_type: data.ty,
            data_hash: hash,
            data_complete: data.is_complete(),
            cut_edge,
            parent_values,
            parent_subkeys,
        })
        .collect()
}

/// Sorts values by case-insensitive name (then by the name as written), the order hits are reported in.
pub(crate) fn sort_values(values: &mut [RegValue]) {
    values.sort_by_cached_key(|v| (v.name.to_lowercase(), v.name.clone()));
}

/// Sorts key names case-insensitively (then as written).
pub(crate) fn sort_names(names: &mut [String]) {
    names.sort_by_cached_key(|n| (n.to_lowercase(), n.clone()));
}

// ---------------------------------------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------------------------------------

/// What a walk adds up. `raw_unreadable`, when set, records every unreadable key as it comes instead of
/// applying the listing rules ([`Tally::unreadable`]): a part of a parallel scan keeps the events, and the
/// merge replays them in walk order, so the listing and its cap come out as one sequential walk makes
/// them.
#[derive(Default)]
struct Tally {
    scan: RefScan,
    raw_unreadable: Option<Vec<Unreadable>>,
}

impl Tally {
    fn for_part() -> Self {
        Self {
            scan: RefScan::default(),
            raw_unreadable: Some(Vec::new()),
        }
    }

    fn unreadable(&mut self, key: &str, error: SourceError) {
        match &mut self.raw_unreadable {
            Some(raw) => raw.push(Unreadable {
                key: key.to_string(),
                error,
            }),
            None => list_unreadable(&mut self.scan.stats, key, error),
        }
    }

    /// Adds a later part of the same walk (see [`Tally`]).
    fn absorb(&mut self, part: Tally) {
        let Tally {
            scan,
            raw_unreadable,
        } = part;
        let (stats, from) = (&mut self.scan.stats, scan.stats);
        self.scan.hits.extend(scan.hits);
        stats.keys_visited += from.keys_visited;
        stats.values_tested += from.values_tested;
        stats.incomplete_values += from.incomplete_values;
        stats.cut_edge_hits += from.cut_edge_hits;
        stats.pruned += from.pruned;
        stats.links_skipped += from.links_skipped;
        stats.roots_missing.extend(from.roots_missing);
        for u in raw_unreadable.unwrap_or_default() {
            list_unreadable(stats, &u.key, u.error);
        }
        // A part's own listing (when it kept none raw) follows the same rules.
        for u in from.unreadable {
            list_unreadable(stats, &u.key, u.error);
        }
    }
}

/// Counts an unreadable key and lists it, once per key in a row and at most
/// [`MAX_UNREADABLE_LISTED`] in all.
fn list_unreadable(stats: &mut RefScanStats, key: &str, error: SourceError) {
    if stats.unreadable.last().is_some_and(|u| u.key == key) {
        return;
    }
    stats.unreadable_total += 1;
    if stats.unreadable.len() < MAX_UNREADABLE_LISTED {
        stats.unreadable.push(Unreadable {
            key: key.to_string(),
            error,
        });
    }
}

/// How one key is read: the scope, the matcher and the options of the scan.
#[derive(Clone, Copy)]
struct Visit<'a> {
    matcher: &'a RefMatcher,
    scope: &'a Scope,
    options: &'a RefScanOptions,
}

impl Visit<'_> {
    /// Opens `key`. `None` when there is nothing to read: the key is missing (a missing scope root is
    /// listed), unreadable (listed) or a link (counted).
    fn enter(
        &self,
        walker: &mut dyn KeyWalker,
        key: &str,
        at_root: bool,
        out: &mut Tally,
    ) -> Option<KeyInfo> {
        let info = match walker.enter(key) {
            Ok(info) => info,
            Err(SourceError::NotFound) => {
                if at_root {
                    out.scan.stats.roots_missing.push(key.to_string());
                }
                return None;
            }
            Err(error) => {
                out.unreadable(key, error);
                return None;
            }
        };
        if info.is_link {
            out.scan.stats.links_skipped += 1;
            return None;
        }
        Some(info)
    }

    /// Reads the values of the key [`Visit::enter`] opened and tests them, then lists its subkeys:
    /// `children` gets those to walk, in walk order (first name first); pruned ones are counted.
    fn read(
        &self,
        walker: &mut dyn KeyWalker,
        key: &str,
        info: &KeyInfo,
        out: &mut Tally,
        children: &mut Vec<String>,
    ) {
        out.scan.stats.keys_visited += 1;
        if info.n_values > 0 {
            match walker.values() {
                Ok(mut values) => {
                    sort_values(&mut values);
                    for value in &values {
                        out.scan.stats.values_tested += 1;
                        if !value.data.is_complete() {
                            out.scan.stats.incomplete_values += 1;
                        }
                        let hits = value_hits(
                            self.matcher,
                            key,
                            value,
                            info.n_values,
                            info.n_subkeys,
                            self.options,
                        );
                        out.scan.stats.cut_edge_hits +=
                            hits.iter().filter(|h| h.cut_edge).count() as u64;
                        out.scan.hits.extend(hits);
                    }
                }
                // The key went away under the scan: nothing below it either.
                Err(SourceError::NotFound) => return,
                Err(error) => out.unreadable(key, error),
            }
        }
        if info.n_subkeys > 0 {
            match walker.subkeys() {
                Ok(mut names) => {
                    sort_names(&mut names);
                    let mut folded = fold_segments(key);
                    for name in &names {
                        folded.push(name.to_lowercase());
                        if self.scope.is_pruned_folded(&folded) {
                            out.scan.stats.pruned += 1;
                        } else {
                            children.push(format!("{key}\\{name}"));
                        }
                        folded.pop();
                    }
                }
                Err(SourceError::NotFound) => {}
                Err(error) => out.unreadable(key, error),
            }
        }
    }

    /// Walks the subtree of `key` depth first, without progress reports or a key budget.
    fn subtree(&self, walker: &mut dyn KeyWalker, key: String, at_root: bool, out: &mut Tally) {
        let mut stack = vec![(key, at_root)];
        let mut children = Vec::new();
        while let Some((key, at_root)) = stack.pop() {
            let Some(info) = self.enter(walker, &key, at_root, out) else {
                continue;
            };
            children.clear();
            self.read(walker, &key, &info, out, &mut children);
            // Reversed, so that the first name is popped first.
            stack.extend(children.drain(..).rev().map(|child| (child, false)));
        }
    }
}

struct Walk<'a, 'p> {
    reg: &'a dyn RegistrySource,
    visit: Visit<'a>,
    progress: Option<&'a mut ProgressFn<'p>>,
    out: Tally,
}

impl Walk<'_, '_> {
    fn report(&mut self, root: &str, root_index: usize, key: &str) -> ControlFlow<()> {
        let Some(progress) = self.progress.as_mut() else {
            return ControlFlow::Continue(());
        };
        let stats = &self.out.scan.stats;
        let flow = progress(&RefScanProgress {
            root,
            root_index,
            root_count: self.visit.scope.roots.len(),
            key,
            keys_visited: stats.keys_visited,
            values_tested: stats.values_tested,
            hits: self.out.scan.hits.len(),
        });
        if flow.is_break() {
            self.out.scan.stats.cancelled = true;
        }
        flow
    }

    /// Walks one root. `Break` when the scan must stop (cancelled or out of budget).
    fn root(&mut self, root_index: usize) -> ControlFlow<()> {
        let visit = self.visit;
        let root = visit.scope.roots[root_index].as_str();
        self.report(root, root_index, root)?;
        if visit.scope.is_pruned(root) {
            self.out.scan.stats.pruned += 1;
            return ControlFlow::Continue(());
        }
        let every = u64::from(visit.options.progress_every.max(1));
        let mut walker = self.reg.walker();
        let mut stack: Vec<String> = vec![root.to_string()];
        let mut children = Vec::new();
        let mut is_root = true;
        while let Some(key) = stack.pop() {
            let at_root = std::mem::replace(&mut is_root, false);
            let Some(info) = visit.enter(walker.as_mut(), &key, at_root, &mut self.out) else {
                continue;
            };
            let visited = self.out.scan.stats.keys_visited;
            if visit.options.max_keys.is_some_and(|max| visited >= max) {
                self.out.scan.stats.truncated = true;
                return ControlFlow::Break(());
            }
            if visited > 0 && visited % every == 0 {
                self.report(root, root_index, &key)?;
            }
            children.clear();
            visit.read(walker.as_mut(), &key, &info, &mut self.out, &mut children);
            // Reversed, so that the first name is popped first.
            stack.extend(children.drain(..).rev());
        }
        ControlFlow::Continue(())
    }
}

/// The most threads a scan reads the registry with.
const MAX_THREADS: usize = 8;

/// A parallel scan splits the scope into subtrees until it has this many per thread (or
/// [`MAX_SPLIT_ROUNDS`] levels), so that the threads stay busy to the end.
const SUBTREES_PER_THREAD: usize = 64;

/// The deepest a parallel scan splits the scope, in levels below the roots.
const MAX_SPLIT_ROUNDS: usize = 4;

/// Fewer pieces than this are read on the calling thread.
const MIN_PARALLEL_ITEMS: usize = 32;

/// The number of threads a scan without progress reports and key budget uses.
fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .clamp(1, MAX_THREADS)
}

/// `f` over `items` on at most `threads` threads, each with its own `W` from `init`; the results in the
/// order of `items`.
fn parallel_map<T, W, R>(
    items: Vec<T>,
    threads: usize,
    init: impl Fn() -> W + Sync,
    f: impl Fn(&mut W, T) -> R + Sync,
) -> Vec<R>
where
    T: Send,
    R: Send,
{
    let threads = threads.clamp(1, items.len().max(1));
    // A short list is not worth starting threads for.
    if threads == 1 || items.len() < MIN_PARALLEL_ITEMS {
        let mut w = init();
        return items.into_iter().map(|item| f(&mut w, item)).collect();
    }
    let n = items.len();
    let queue: Vec<std::sync::Mutex<Option<T>>> = items
        .into_iter()
        .map(|item| std::sync::Mutex::new(Some(item)))
        .collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut done: Vec<(usize, R)> = std::thread::scope(|s| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                s.spawn(|| {
                    let mut w = init();
                    let mut out = Vec::new();
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(slot) = queue.get(i) else {
                            break;
                        };
                        let item = slot
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take();
                        if let Some(item) = item {
                            out.push((i, f(&mut w, item)));
                        }
                    }
                    out
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|w| match w.join() {
                Ok(out) => out,
                Err(panic) => std::panic::resume_unwind(panic),
            })
            .collect()
    });
    done.sort_by_key(|(i, _)| *i);
    debug_assert_eq!(done.len(), n);
    done.into_iter().map(|(_, r)| r).collect()
}

/// One piece of a parallel scan, in walk order: what is already read, or a subtree still to walk.
enum Part {
    Done(Tally),
    Subtree { key: String, at_root: bool },
}

/// [`scan`] without progress reports or key budget, on `threads` threads. Gives exactly the hits and
/// statistics of the sequential walk: the scope is split into subtrees in walk order (reading the keys
/// above them, level by level), the subtrees are walked in parallel, and the pieces are put together in
/// walk order.
fn scan_parallel(reg: &dyn RegistrySource, visit: Visit<'_>, threads: usize) -> RefScan {
    let scope = visit.scope;
    let mut parts: Vec<Part> = scope
        .roots
        .iter()
        .map(|root| {
            if scope.is_pruned(root) {
                let mut t = Tally::for_part();
                t.scan.stats.pruned += 1;
                Part::Done(t)
            } else {
                Part::Subtree {
                    key: root.clone(),
                    at_root: true,
                }
            }
        })
        .collect();
    let walker = || reg.walker();
    for _ in 0..MAX_SPLIT_ROUNDS {
        let open = parts
            .iter()
            .filter(|p| matches!(p, Part::Subtree { .. }))
            .count();
        if open == 0 || open >= threads * SUBTREES_PER_THREAD {
            break;
        }
        // One level: each subtree becomes its top key, read, followed by the subtrees of its children.
        parts = parallel_map(parts, threads, walker, |w, part| match part {
            Part::Done(t) => vec![Part::Done(t)],
            Part::Subtree { key, at_root } => {
                let mut t = Tally::for_part();
                let mut children = Vec::new();
                if let Some(info) = visit.enter(w.as_mut(), &key, at_root, &mut t) {
                    visit.read(w.as_mut(), &key, &info, &mut t, &mut children);
                }
                let mut out = vec![Part::Done(t)];
                out.extend(children.into_iter().map(|key| Part::Subtree {
                    key,
                    at_root: false,
                }));
                out
            }
        })
        .into_iter()
        .flatten()
        .collect();
    }
    let tallies = parallel_map(parts, threads, walker, |w, part| match part {
        Part::Done(t) => t,
        Part::Subtree { key, at_root } => {
            let mut t = Tally::for_part();
            visit.subtree(w.as_mut(), key, at_root, &mut t);
            t
        }
    });
    let mut total = Tally::default();
    for t in tallies {
        total.absorb(t);
    }
    total.scan
}

/// Runs a reference scan over `scope` and reports every value that refers to an anchor of `matcher`.
///
/// See the module documentation for what is tested, the order of the hits and what an incomplete scan
/// means. `progress` may be `None`; without it and without a key budget the scan reads the registry on
/// several threads, with the same result.
pub fn scan(
    reg: &dyn RegistrySource,
    matcher: &RefMatcher,
    scope: &Scope,
    options: &RefScanOptions,
    progress: Option<&mut ProgressFn<'_>>,
) -> RefScan {
    let threads = if progress.is_none() && options.max_keys.is_none() {
        default_threads()
    } else {
        1
    };
    scan_with_threads(reg, matcher, scope, options, progress, threads)
}

/// [`scan`] on at most `threads` threads (1: the sequential walk, which progress reports and a key
/// budget need).
fn scan_with_threads(
    reg: &dyn RegistrySource,
    matcher: &RefMatcher,
    scope: &Scope,
    options: &RefScanOptions,
    progress: Option<&mut ProgressFn<'_>>,
    threads: usize,
) -> RefScan {
    let visit = Visit {
        matcher,
        scope,
        options,
    };
    if threads > 1 && progress.is_none() && options.max_keys.is_none() {
        return scan_parallel(reg, visit, threads);
    }
    let mut walk = Walk {
        reg,
        visit,
        progress,
        out: Tally::default(),
    };
    for index in 0..scope.roots.len() {
        if walk.root(index).is_break() {
            break;
        }
    }
    walk.out.scan
}

/// [`scan`] over [`Scope::standard`] with default options and no progress callback. Fails only when the
/// source cannot say which user hives are loaded or which control set is current.
pub fn scan_standard(reg: &dyn RegistrySource, matcher: &RefMatcher) -> SourceResult<RefScan> {
    let scope = Scope::standard(reg)?;
    Ok(scan(reg, matcher, &scope, &RefScanOptions::default(), None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::AnchorSet;
    use purge_source::fixture::{Fixture, FixtureBuilder};
    use purge_source::types::RegData;

    const SID: &str = "S-1-5-21-100-200-300-1001";
    const FF: &str = r"C:\Program Files\Mozilla Firefox";
    const TOKEN: &str = "308046B0AF4A39CB";

    fn firefox_anchors() -> AnchorSet {
        let mut set = AnchorSet::new();
        assert!(set.add_root(FF));
        assert!(set.add_exe_path(&format!(r"{FF}\firefox.exe")));
        assert!(set.add_progid(&format!("FirefoxURL-{TOKEN}")));
        assert!(set.add_aumid(&format!("FirefoxToast-{TOKEN}")));
        assert!(set.add_clsid("{11111111-2222-3333-4444-555555555555}"));
        assert!(set.add_token(TOKEN));
        set
    }

    fn matcher() -> RefMatcher {
        RefMatcher::with_env(&firefox_anchors(), [("ProgramFiles", r"C:\Program Files")])
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn hku(rest: &str) -> String {
        format!(r"HKU\{SID}\{rest}")
    }

    fn base() -> FixtureBuilder {
        Fixture::builder()
            .key(r"HKLM\SOFTWARE")
            .key(&hku("Software"))
    }

    fn run(f: &Fixture) -> RefScan {
        let scan = scan_standard(f, &matcher()).unwrap();
        assert!(scan.is_complete(), "{:?}", scan.stats);
        scan
    }

    /// (key, value name, location, anchor text) of every hit.
    fn brief(scan: &RefScan) -> Vec<(String, String, RefWhere, String)> {
        scan.hits
            .iter()
            .map(|h| {
                (
                    h.key.clone(),
                    h.value_name.clone(),
                    h.location,
                    h.anchor.text.clone(),
                )
            })
            .collect()
    }

    #[test]
    fn finds_all_four_carriers_and_no_decoy() {
        let mut blob = vec![0x01, 0x00, 0x02, 0x00, 0x00, 0x00];
        blob.extend(utf16(&format!(r"{FF}\browser\omni.ja")));
        blob.extend([0, 0, 0xff, 0xff]);
        let mut decoy_blob = vec![0u8; 4];
        decoy_blob.extend(utf16(r"C:\Program Files\Mozilla Firefox Nightly\x.dll"));
        let key = r"HKLM\SOFTWARE\Vendor\Carriers";
        let decoys = r"HKLM\SOFTWARE\Vendor\Decoys";
        let f = base()
            // name
            .dword(key, &format!(r"{FF}\firefox.exe|Image"), 1)
            // data
            .sz(
                key,
                "Command",
                &format!(r#""{FF}\firefox.exe" -osint -url "%1""#),
            )
            // multi_sz segment
            .multi_sz(
                key,
                "List",
                &["C:\\Other\\a.dll", "", &format!(r"{FF}\b.dll")],
            )
            // binary
            .binary(key, "Blob", blob)
            // near misses, one per carrier
            .dword(
                decoys,
                r"C:\Program Files\Mozilla Firefox Nightly\firefox.exe|Image",
                1,
            )
            .sz(
                decoys,
                "Command",
                r"C:\Program Files\Mozilla FirefoxESR\firefox.exe",
            )
            .sz(decoys, "Up", &format!(r"{FF}\..\Other\x.exe"))
            .sz(decoys, "Hex", &format!("A{TOKEN}0"))
            .sz(decoys, "Guid", "{11111111-2222-3333-4444-555555555556}")
            .multi_sz(
                decoys,
                "List",
                &[r"C:\Program Files\Mozilla", r"D:\Mozilla Firefox\b.dll"],
            )
            .binary(decoys, "Blob", decoy_blob)
            // numbers are never read as text
            .value(decoys, "Dword", RegData::new(REG_DWORD, utf16("C:")))
            .build();
        let scan = run(&f);
        let exe = format!(r"{FF}\firefox.exe");
        assert_eq!(
            brief(&scan),
            vec![
                (
                    key.to_string(),
                    "Blob".to_string(),
                    RefWhere::Binary,
                    FF.to_string()
                ),
                // A name starting `c:` sorts before `command`.
                (
                    key.to_string(),
                    format!(r"{FF}\firefox.exe|Image"),
                    RefWhere::Name,
                    exe.clone()
                ),
                (key.to_string(), "Command".to_string(), RefWhere::Data, exe),
                (
                    key.to_string(),
                    "List".to_string(),
                    RefWhere::Segment(2),
                    FF.to_string()
                ),
            ]
        );
        for hit in &scan.hits {
            assert_eq!((hit.parent_values, hit.parent_subkeys), (4, 0));
            assert!(hit.data_complete && hit.data_hash.is_some());
        }
        assert_eq!(scan.hits[0].anchor_kind(), AnchorKind::Root);
        assert_eq!(scan.hits[1].anchor_kind(), AnchorKind::Exe);
        assert_eq!(scan.hits[1].carrier(), RefCarrier::ValueName);
        assert_eq!(scan.hits[2].carrier(), RefCarrier::Data);
        assert_eq!(scan.hits[3].location.segment(), Some(2));
        assert_eq!(scan.hits[3].value_type, REG_MULTI_SZ);
        assert_eq!(scan.stats.values_tested, 12);
    }

    #[test]
    fn firefox_taskbar_ids_and_launcher_names() {
        let taskbar = hku(r"Software\Mozilla\Firefox\TaskBarIDs");
        let launcher = hku(r"Software\Mozilla\Firefox\Launcher");
        let f = base()
            .sz(&taskbar, FF, TOKEN)
            .sz(
                &taskbar,
                r"C:\Program Files\Mozilla Thunderbird",
                "D78BF5DD33499EC2",
            )
            .qword(&launcher, &format!(r"{FF}\firefox.exe|Browser"), 7)
            .dword(&launcher, &format!(r"{FF}\firefox.exe|Launcher"), 1)
            .qword(
                &launcher,
                r"C:\Program Files\Mozilla Thunderbird\thunderbird.exe|Launcher",
                1,
            )
            .build();
        let scan = run(&f);
        let exe = format!(r"{FF}\firefox.exe");
        assert_eq!(
            brief(&scan),
            vec![
                (
                    launcher.clone(),
                    format!("{exe}|Browser"),
                    RefWhere::Name,
                    exe.clone()
                ),
                (
                    launcher.clone(),
                    format!("{exe}|Launcher"),
                    RefWhere::Name,
                    exe
                ),
                // The name is a root path and the data is the install hash: two carriers, two hits.
                (
                    taskbar.clone(),
                    FF.to_string(),
                    RefWhere::Name,
                    FF.to_string()
                ),
                (
                    taskbar.clone(),
                    FF.to_string(),
                    RefWhere::Data,
                    TOKEN.to_string()
                ),
            ]
        );
        assert_eq!(scan.hits[2].how, MatchHow::Whole);
        assert_eq!(
            (scan.hits[2].parent_values, scan.hits[2].parent_subkeys),
            (2, 0)
        );
    }

    #[test]
    fn vscode_openwithprogids_names_with_empty_data() {
        let mut set = AnchorSet::new();
        set.add_progid("VSCode.txt");
        set.add_progid("VSCode.json");
        let m = RefMatcher::new(&set);
        let machine = r"HKLM\SOFTWARE\Classes\.txt\OpenWithProgids";
        let user = format!(r"HKU\{SID}_Classes\.json\OpenWithProgids");
        let f = base()
            .value(machine, "VSCode.txt", RegData::new(0, Vec::new()))
            .value(machine, "txtfile", RegData::new(0, Vec::new()))
            .value(machine, "VSCode.txt2", RegData::new(0, Vec::new()))
            .value(machine, "NotVSCode.txt", RegData::from_sz(""))
            .sz(&user, "VSCode.json", "")
            .sz(&user, "VSCodeInsiders.json", "")
            .build();
        let scan = scan_standard(&f, &m).unwrap();
        assert_eq!(
            brief(&scan),
            vec![
                (
                    machine.to_string(),
                    "VSCode.txt".into(),
                    RefWhere::Name,
                    "VSCode.txt".into()
                ),
                (
                    user,
                    "VSCode.json".into(),
                    RefWhere::Name,
                    "VSCode.json".into()
                ),
            ]
        );
        assert_eq!(scan.hits[0].value_type, 0);
        assert_eq!(scan.hits[0].parent_values, 4);
        assert_eq!(scan.hits[0].anchor_kind(), AnchorKind::ProgId);
    }

    #[test]
    fn scope_limits() {
        let hit = format!(r"{FF}\firefox.exe");
        let f = base()
            // in scope
            .sz(r"HKLM\SOFTWARE\WOW6432Node\Vendor", "a", &hit)
            .expand_sz(
                r"HKLM\SYSTEM\ControlSet001\Services\MozSvc",
                "ImagePath",
                &hit,
            )
            .expand_sz(
                r"HKLM\SYSTEM\ControlSet001\Control\Session Manager\Environment",
                "Path",
                &format!(r"C:\Windows;{FF}\bin;C:\Tools"),
            )
            .expand_sz(
                &hku("Environment"),
                "MOZ_HOME",
                r"%ProgramFiles%\Mozilla Firefox",
            )
            .sz(
                &format!(r"HKU\{SID}_Classes\FirefoxURL-{TOKEN}\shell\open\command"),
                "",
                &hit,
            )
            .sz(&hku(r"Software\Vendor"), "a", &hit)
            // out of scope
            .sz(
                r"HKLM\SYSTEM\ControlSet001\Control\Session Manager",
                "a",
                &hit,
            )
            .sz(r"HKLM\SYSTEM\ControlSet001\Control\Other", "a", &hit)
            .sz(r"HKLM\SYSTEM\ControlSet001\Enum\X", "a", &hit)
            .sz(
                r"HKLM\SYSTEM\ControlSet002\Services\MozSvc",
                "ImagePath",
                &hit,
            )
            .sz(r"HKLM\SYSTEM\Setup", "a", &hit)
            .sz(r"HKLM\SAM\X", "a", &hit)
            .sz(&hku("Console"), "a", &hit)
            .sz(&hku("Volatile Environment"), "a", &hit)
            .sz(&format!(r"HKU\{SID}"), "a", &hit)
            .sz(r"HKU\.DEFAULT\Software\Vendor", "a", &hit)
            .build();
        let scan = run(&f);
        let keys: Vec<&str> = scan.hits.iter().map(|h| h.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                r"HKLM\SOFTWARE\WOW6432Node\Vendor",
                r"HKLM\SYSTEM\ControlSet001\Services\MozSvc",
                r"HKLM\SYSTEM\ControlSet001\Control\Session Manager\Environment",
                &hku(r"Software\Vendor"),
                &hku("Environment"),
                &format!(r"HKU\{SID}_Classes\FirefoxURL-{TOKEN}\shell\open\command"),
            ]
        );
        assert!(scan.hits[4].via_env);
        // The PATH-style list names a directory below the root.
        assert_eq!(scan.hits[2].how, MatchHow::Below);
        assert_eq!(scan.hits[2].value_name, "Path");

        // The other control set is the scope when it is the current one.
        let mut f2 = f.clone();
        f2.set_current_control_set(2);
        let scan = run(&f2);
        assert!(
            scan.hits
                .iter()
                .any(|h| h.key == r"HKLM\SYSTEM\ControlSet002\Services\MozSvc")
        );
        assert!(!scan.hits.iter().any(|h| h.key.contains("ControlSet001")));
        assert_eq!(
            scan.stats.roots_missing,
            vec![r"HKLM\SYSTEM\ControlSet002\Control\Session Manager\Environment"]
        );
    }

    #[test]
    fn scope_per_sid_and_custom() {
        let other = "S-1-5-21-100-200-300-1002";
        let hit = format!(r"{FF}\firefox.exe");
        let f = base()
            .sz(&hku(r"Software\A"), "a", &hit)
            .sz(&format!(r"HKU\{other}\Software\B"), "a", &hit)
            .sz(&format!(r"HKU\{other}_Classes\x"), "a", &hit)
            .build();
        assert_eq!(run(&f).hits.len(), 3);

        let scope = Scope::for_sids(&f, &[other]).unwrap();
        assert_eq!(
            scope.roots()[3..],
            [
                format!(r"HKU\{other}\Software"),
                format!(r"HKU\{other}\Environment"),
                format!(r"HKU\{other}_Classes"),
            ]
        );
        let scan = scan(&f, &matcher(), &scope, &RefScanOptions::default(), None);
        assert_eq!(scan.hits.len(), 2);
        assert!(scan.hits.iter().all(|h| h.key.contains(other)));
        assert!(scope.contains(&format!(r"hku\{other}\software\b")));
        assert!(!scope.contains(&hku(r"Software\A")));
        assert!(!scope.contains(r"HKLM\SOFTWARE\Classes\Installer\Products"));
        assert!(!scope.contains(r"HKLM\SOFTWAREX"));

        // Overlapping and repeated roots are walked once.
        let custom = Scope::custom(
            [
                hku(r"Software\A"),
                hku("Software"),
                hku(r"software\"),
                String::new(),
            ],
            Vec::<String>::new(),
        );
        assert_eq!(custom.roots(), [hku("Software")]);
        let scan = super::scan(&f, &matcher(), &custom, &RefScanOptions::default(), None);
        assert_eq!(scan.hits.len(), 1);
    }

    #[test]
    fn prune_list() {
        let hit = format!(r"{FF}\firefox.exe");
        let repo = format!(
            r"HKU\{SID}_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\P"
        );
        let f = base()
            .sz(r"HKLM\SOFTWARE\Classes\Installer\Products\ABC", "ProductIcon", &hit)
            .sz(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\P",
                "a",
                &hit,
            )
            .sz(&repo, "a", &hit)
            .sz(r"HKLM\SOFTWARE\Vendor\Classes\Installer", "a", &hit)
            .sz(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders", &format!(r"{FF}\"), "")
            .build();
        let scan = run(&f);
        let keys: Vec<&str> = scan.hits.iter().map(|h| h.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders",
                r"HKLM\SOFTWARE\Vendor\Classes\Installer",
            ]
        );
        assert_eq!(scan.stats.pruned, 3);

        // The list is configurable: none, or the caller's own.
        let all = Scope::standard(&f)
            .unwrap()
            .with_prune(Vec::<String>::new());
        let scan = super::scan(&f, &matcher(), &all, &RefScanOptions::default(), None);
        assert_eq!(scan.hits.len(), 5);
        assert_eq!(scan.stats.pruned, 0);

        let own = Scope::standard(&f)
            .unwrap()
            .with_prune([r"hklm\software\*\classes", r"HKU\*\Local Settings\"]);
        assert!(own.is_pruned(r"HKLM\SOFTWARE\Vendor\Classes"));
        assert!(!own.is_pruned(r"HKLM\SOFTWARE\Vendor\Classes\Installer"));
        assert!(!own.contains(r"HKLM\SOFTWARE\Vendor\Classes\Installer"));
        let scan = super::scan(&f, &matcher(), &own, &RefScanOptions::default(), None);
        assert_eq!(scan.hits.len(), 3);
        assert_eq!(scan.stats.pruned, 2);

        // A pruned root is not walked either.
        let root = Scope::custom([r"HKLM\SOFTWARE\Classes\Installer"], default_prune());
        let scan = super::scan(&f, &matcher(), &root, &RefScanOptions::default(), None);
        assert!(scan.hits.is_empty());
        assert_eq!((scan.stats.pruned, scan.stats.keys_visited), (1, 0));
    }

    #[test]
    fn links_are_not_followed() {
        let hit = format!(r"{FF}\firefox.exe");
        let link = hku(r"Software\Classes");
        let f = base()
            .sz(&format!(r"{link}\Below"), "a", &hit)
            .link(&link, &format!(r"\REGISTRY\USER\{SID}_Classes"))
            .sz(&format!(r"HKU\{SID}_Classes\Below"), "a", &hit)
            .build();
        let scan = run(&f);
        assert_eq!(
            brief(&scan),
            vec![(
                format!(r"HKU\{SID}_Classes\Below"),
                "a".to_string(),
                RefWhere::Data,
                hit.clone()
            )]
        );
        assert_eq!(scan.stats.links_skipped, 1);

        // A root that is itself a link is skipped as well.
        let scope = Scope::custom([link], Vec::<String>::new());
        let scan = super::scan(&f, &matcher(), &scope, &RefScanOptions::default(), None);
        assert!(scan.hits.is_empty());
        assert_eq!((scan.stats.links_skipped, scan.stats.keys_visited), (1, 0));
    }

    #[test]
    fn deterministic_order() {
        let hit = format!(r"{FF}\firefox.exe");
        let keys = [
            r"HKLM\SOFTWARE\b\Z",
            r"HKLM\SOFTWARE\B\a",
            r"HKLM\SOFTWARE\a",
            r"HKLM\SOFTWARE\C",
            r"HKLM\SOFTWARE\a\b\c",
        ];
        let names = ["zeta", "Alpha", "", "beta"];
        let build = |reverse: bool| {
            let mut pairs: Vec<(&str, &str)> = keys
                .iter()
                .flat_map(|k| names.iter().map(move |n| (*k, *n)))
                .collect();
            if reverse {
                pairs.reverse();
            }
            let mut b = base();
            for (k, n) in pairs {
                b = b.sz(k, n, &hit);
            }
            b.build()
        };
        let first = run(&build(false));
        let second = run(&build(true));
        assert_eq!(first.hits.len(), 20);
        assert_eq!(
            brief(&first)
                .iter()
                .map(|h| (h.0.to_lowercase(), h.1.clone()))
                .collect::<Vec<_>>(),
            brief(&second)
                .iter()
                .map(|h| (h.0.to_lowercase(), h.1.clone()))
                .collect::<Vec<_>>()
        );
        let order: Vec<String> = first
            .hits
            .iter()
            .map(|h| h.key.to_lowercase())
            .collect::<Vec<_>>()
            .chunks(4)
            .map(|c| c[0].clone())
            .collect();
        assert_eq!(
            order,
            vec![
                r"hklm\software\a",
                r"hklm\software\a\b\c",
                r"hklm\software\b\a",
                r"hklm\software\b\z",
                r"hklm\software\c",
            ]
        );
        let value_order: Vec<&str> = first.hits[..4]
            .iter()
            .map(|h| h.value_name.as_str())
            .collect();
        assert_eq!(value_order, vec!["", "Alpha", "beta", "zeta"]);
        // And the same scan twice is identical.
        let f = build(false);
        assert_eq!(run(&f), run(&f));
    }

    #[test]
    fn key_budget_sets_truncated() {
        let hit = format!(r"{FF}\firefox.exe");
        let mut b = base();
        for i in 0..20 {
            b = b.sz(&format!(r"HKLM\SOFTWARE\K{i:02}"), "a", &hit);
        }
        let f = b.build();
        let scope = Scope::standard(&f).unwrap();
        let options = RefScanOptions {
            max_keys: Some(6),
            ..RefScanOptions::default()
        };
        let cut = scan(&f, &matcher(), &scope, &options, None);
        assert!(cut.stats.truncated && !cut.is_complete());
        assert_eq!(cut.stats.keys_visited, 6);
        // HKLM\SOFTWARE itself plus K00..K04.
        assert_eq!(cut.hits.len(), 5);

        let full = scan(&f, &matcher(), &scope, &RefScanOptions::default(), None);
        assert!(!full.stats.truncated && full.is_complete());
        assert_eq!(full.hits.len(), 20);
        assert_eq!(full.hits[..5], cut.hits[..]);
    }

    #[test]
    fn progress_and_cancel() {
        let hit = format!(r"{FF}\firefox.exe");
        let mut b = base();
        for i in 0..10 {
            b = b.sz(&format!(r"HKLM\SOFTWARE\K{i:02}"), "a", &hit);
        }
        let f = b.build();
        let scope = Scope::standard(&f).unwrap();
        let options = RefScanOptions {
            progress_every: 4,
            ..RefScanOptions::default()
        };
        let mut calls: Vec<(usize, String, u64)> = Vec::new();
        let mut cb = |p: &RefScanProgress<'_>| {
            assert_eq!(p.root_count, 6);
            calls.push((p.root_index, p.key.to_string(), p.keys_visited));
            ControlFlow::Continue(())
        };
        let done = scan(&f, &matcher(), &scope, &options, Some(&mut cb));
        assert!(done.is_complete());
        assert_eq!(done.hits.len(), 10);
        // One call per root, plus one every four keys.
        let roots: Vec<usize> = calls
            .iter()
            .filter(|c| scope.roots().contains(&c.1))
            .map(|c| c.0)
            .collect();
        assert_eq!(roots, vec![0, 1, 2, 3, 4, 5]);
        let ticks: Vec<u64> = calls
            .iter()
            .filter(|c| c.2 > 0 && c.0 == 0)
            .map(|c| c.2)
            .collect();
        assert_eq!(ticks, vec![4, 8]);

        let mut cancel = |p: &RefScanProgress<'_>| {
            if p.keys_visited >= 4 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        };
        let stopped = scan(&f, &matcher(), &scope, &options, Some(&mut cancel));
        assert!(stopped.stats.cancelled && !stopped.is_complete());
        assert_eq!(stopped.stats.keys_visited, 4);
        assert_eq!(stopped.hits.len(), 3);
    }

    #[test]
    fn unreadable_keys_are_reported_not_fatal() {
        let hit = format!(r"{FF}\firefox.exe");
        let f = base()
            .sz(r"HKLM\SOFTWARE\Open", "a", &hit)
            .sz(r"HKLM\SOFTWARE\Secret", "a", &hit)
            .sz(r"HKLM\SOFTWARE\Secret\Deeper", "a", &hit)
            .denied(r"HKLM\SOFTWARE\Secret")
            .build();
        let scan = scan_standard(&f, &matcher()).unwrap();
        assert!(!scan.is_complete());
        assert_eq!(scan.hits.len(), 1);
        assert_eq!(scan.stats.unreadable_total, 1);
        assert_eq!(
            scan.stats.unreadable,
            vec![Unreadable {
                key: r"HKLM\SOFTWARE\Secret".to_string(),
                error: SourceError::AccessDenied
            }]
        );
    }

    #[test]
    fn incomplete_data_and_binary_bound() {
        let hit = format!(r"{FF}\firefox.exe");
        let key = r"HKLM\SOFTWARE\V";
        let mut cut = RegData::from_sz(&hit);
        cut.truncated = true;
        cut.len = 4000;
        cut.hash = Some(0xabcd);
        let mut far = vec![0u8; 4096];
        far.extend(utf16(&hit));
        let mut near = vec![0u8; 4096 - utf16(&hit).len()];
        near.extend(utf16(&hit));
        let f = base()
            .value(key, "Cut", cut)
            .value(key, &hit, RegData::unknown(3, 64))
            .binary(key, "Far", far)
            .binary(key, "Near", near)
            .build();
        let scan = run(&f);
        assert_eq!(
            brief(&scan),
            vec![
                (key.to_string(), hit.clone(), RefWhere::Name, hit.clone()),
                (
                    key.to_string(),
                    "Cut".to_string(),
                    RefWhere::Data,
                    hit.clone()
                ),
                (
                    key.to_string(),
                    "Near".to_string(),
                    RefWhere::Binary,
                    hit.clone()
                ),
            ]
        );
        assert_eq!(scan.stats.incomplete_values, 2);
        assert!(!scan.hits[0].data_complete && scan.hits[0].data_hash.is_none());
        assert!(!scan.hits[1].data_complete);
        assert_eq!(scan.hits[1].data_hash, Some(0xabcd));
        assert!(scan.hits[2].data_complete);
    }

    /// A string that stops where the known data stops may go on: such a hit is flagged, never proven.
    #[test]
    fn cut_strings_flag_hits_that_depend_on_the_cut() {
        let key = r"HKLM\SOFTWARE\V";
        // A preview without its terminator.
        let cut_sz = |s: &str| {
            let mut d = RegData::new(REG_SZ, utf16(s));
            d.truncated = true;
            d.len = 9000;
            d
        };
        let exe = format!(r"{FF}\firefox.exe");
        let mut list = RegData::from_multi_sz(&[exe.as_str(), FF]);
        // Drop both terminators: the second segment is cut, the first is not.
        list.bytes.truncate(list.bytes.len() - 4);
        list.truncated = true;
        // Cut right after a segment's terminator: that segment is whole.
        let mut list_done = RegData::from_multi_sz(&[FF]);
        list_done.bytes.truncate(list_done.bytes.len() - 2);
        list_done.truncated = true;
        let f = base()
            // `...\Mozilla Firefox` may be the start of `...\Mozilla Firefox Nightly\x.exe`.
            .value(key, "a-root", cut_sz(FF))
            // `...\Mozilla Firefox\brow` may go on with `ser\..\..\Other`.
            .value(key, "b-below", cut_sz(&format!(r"{FF}\brow")))
            // `firefox.exe` may be the start of `firefox.exe.bak`, and the root may be left again.
            .value(key, "c-exe", cut_sz(&exe))
            // A token may be the start of a longer one.
            .value(key, "d-token", cut_sz(&format!("id={TOKEN}")))
            // Closed by a quote before the cut: proven, but not "the whole string".
            .value(
                key,
                "e-quoted",
                cut_sz(&format!(r#""{exe}" -url http://exam"#)),
            )
            .value(key, "f-list", list)
            .value(key, "g-list-done", list_done)
            // Complete data is never flagged.
            .sz(key, "h-complete", FF)
            .build();
        let scan = run(&f);
        let got: Vec<(&str, RefWhere, AnchorKind, bool)> = scan
            .hits
            .iter()
            .map(|h| {
                (
                    h.value_name.as_str(),
                    h.location,
                    h.anchor_kind(),
                    h.cut_edge,
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("a-root", RefWhere::Data, AnchorKind::Root, true),
                ("b-below", RefWhere::Data, AnchorKind::Root, true),
                ("c-exe", RefWhere::Data, AnchorKind::Exe, true),
                ("d-token", RefWhere::Data, AnchorKind::Token, true),
                ("e-quoted", RefWhere::Data, AnchorKind::Exe, false),
                ("f-list", RefWhere::Segment(0), AnchorKind::Exe, false),
                ("f-list", RefWhere::Segment(1), AnchorKind::Root, true),
                ("g-list-done", RefWhere::Segment(0), AnchorKind::Root, false),
                ("h-complete", RefWhere::Data, AnchorKind::Root, false),
            ]
        );
        assert_eq!(scan.stats.cut_edge_hits, 5);
        let by_name = |n: &str| scan.hits.iter().find(|h| h.value_name == n).unwrap();
        assert_eq!(by_name("e-quoted").how, MatchHow::Embedded);
        assert_eq!(by_name("h-complete").how, MatchHow::Whole);
        assert!(
            scan.hits
                .iter()
                .filter(|h| h.cut_edge)
                .all(|h| !h.data_complete)
        );

        // With every anchor reported, the proven ones come first.
        let options = RefScanOptions {
            all_anchors: true,
            ..RefScanOptions::default()
        };
        let value = RegValue {
            name: "v".to_string(),
            data: cut_sz(&format!(r#""{exe}" {TOKEN}"#)),
        };
        let hits = value_hits(&matcher(), key, &value, 1, 0, &options);
        let got: Vec<(AnchorKind, bool)> =
            hits.iter().map(|h| (h.anchor_kind(), h.cut_edge)).collect();
        assert_eq!(
            got,
            vec![
                (AnchorKind::Exe, false),
                (AnchorKind::Root, false),
                (AnchorKind::Token, true),
            ]
        );
    }

    /// A UTF-16 string that runs into the end of the 4 KB window of a longer binary value.
    #[test]
    fn binary_window_edge_flags_hits() {
        let key = r"HKLM\SOFTWARE\V";
        let root = utf16(FF);
        // The root's last character is the last unit of the window, at either alignment; the data goes
        // on with ` Nightly\x.dll`.
        let straddle = |lead: usize| {
            let mut b = vec![0u8; lead];
            b.extend(&root);
            b.extend(utf16(r" Nightly\x.dll"));
            b.extend([0, 0]);
            b
        };
        let even = straddle(4096 - root.len());
        let odd = straddle(4095 - root.len());
        // The same, but the root is also named in full earlier in the window.
        let mut twice = vec![0u8; 2];
        twice.extend(utf16(&format!(r"{FF}\a.dll")));
        twice.extend(vec![0u8; 4096 - root.len() - twice.len()]);
        twice.extend(&root);
        twice.extend(utf16(" Nightly"));
        // Ends inside the window; more data follows.
        let mut inside = vec![0u8; 8];
        inside.extend(utf16(&format!(r"{FF}\a.dll")));
        inside.extend(vec![0u8; 5000]);
        // Exactly fills the window and the value: nothing follows.
        let mut exact = vec![0u8; 4096 - root.len()];
        exact.extend(&root);
        let f = base()
            .binary(key, "a-even", even)
            .binary(key, "b-odd", odd)
            .binary(key, "c-twice", twice)
            .binary(key, "d-inside", inside)
            .binary(key, "e-exact", exact)
            .build();
        let scan = run(&f);
        let got: Vec<(&str, RefWhere, bool)> = scan
            .hits
            .iter()
            .map(|h| (h.value_name.as_str(), h.location, h.cut_edge))
            .collect();
        assert_eq!(
            got,
            vec![
                ("a-even", RefWhere::Binary, true),
                ("b-odd", RefWhere::Binary, true),
                ("c-twice", RefWhere::Binary, false),
                ("d-inside", RefWhere::Binary, false),
                ("e-exact", RefWhere::Binary, false),
            ]
        );
        // The source had all the bytes, and still the hit is only a possible reference.
        assert!(scan.hits[0].data_complete && scan.hits[0].cut_edge);
        assert_eq!(scan.stats.cut_edge_hits, 2);
    }

    #[test]
    fn all_anchors_option() {
        let key = r"HKLM\SOFTWARE\V";
        let f = base()
            .sz(
                key,
                "a",
                &format!(r#""{FF}\firefox.exe" -url FirefoxURL-{TOKEN}"#),
            )
            .build();
        let scope = Scope::standard(&f).unwrap();
        let one = scan(&f, &matcher(), &scope, &RefScanOptions::default(), None);
        assert_eq!(one.hits.len(), 1);
        assert_eq!(one.hits[0].anchor_kind(), AnchorKind::Exe);
        let options = RefScanOptions {
            all_anchors: true,
            ..RefScanOptions::default()
        };
        let all = scan(&f, &matcher(), &scope, &options, None);
        let kinds: Vec<AnchorKind> = all.hits.iter().map(RefHit::anchor_kind).collect();
        assert_eq!(
            kinds,
            vec![AnchorKind::Exe, AnchorKind::Root, AnchorKind::ProgId]
        );
    }

    /// With `PURGE_RUNS_DIR` (e.g. `vm/runs`): a reference scan of the VS Code post-install snapshot
    /// with VS Code's anchors. Reports hit counts and time.
    #[test]
    #[ignore = "needs PURGE_RUNS_DIR with the vscode run"]
    fn perf_refscan_vscode_snapshot() {
        let Some(runs) = std::env::var_os("PURGE_RUNS_DIR") else {
            eprintln!("PURGE_RUNS_DIR not set; skipping");
            return;
        };
        let dir = std::path::Path::new(&runs).join("vscode");
        let snap = dir.join("snap-vscode-1.tsv.gz");
        let lists = dir.join("lists-vscode-1.json");
        let t = std::time::Instant::now();
        let f =
            Fixture::from_snap(&snap, lists.is_file().then_some(lists.as_path()), None).unwrap();
        eprintln!(
            "fixture loaded in {:?}: {} keys, {} values",
            t.elapsed(),
            f.key_count(),
            f.value_count()
        );

        let root = r"C:\Program Files\Microsoft VS Code";
        let mut set = AnchorSet::new();
        set.add_root(root);
        set.add_exe_path(&format!(r"{root}\Code.exe"));
        set.add_exe_path(&format!(r"{root}\unins000.exe"));
        set.add_exe_name("Code.exe");
        for ext in [
            "txt",
            "json",
            "ascx",
            "asp",
            "aspx",
            "md",
            "py",
            "SourceFile",
        ] {
            set.add_progid(&format!("VSCode.{ext}"));
        }
        set.add_token("{EA457B21-F73E-494C-ACAB-524FDE069978}");
        let m = RefMatcher::with_env(&set, [("ProgramFiles", r"C:\Program Files")]);
        let scope = Scope::standard(&f).unwrap();
        eprintln!("scope: {:?}", scope.roots());

        let mut ticks = 0u32;
        let mut cb = |_: &RefScanProgress<'_>| {
            ticks += 1;
            ControlFlow::Continue(())
        };
        let t = std::time::Instant::now();
        let result = scan(&f, &m, &scope, &RefScanOptions::default(), Some(&mut cb));
        let took = t.elapsed();
        let count =
            |w: fn(&RefWhere) -> bool| result.hits.iter().filter(|h| w(&h.location)).count();
        eprintln!(
            "refscan: {took:?}; {} keys, {} values ({} incomplete), {} pruned, {} links, {} unreadable, {ticks} progress calls",
            result.stats.keys_visited,
            result.stats.values_tested,
            result.stats.incomplete_values,
            result.stats.pruned,
            result.stats.links_skipped,
            result.stats.unreadable_total,
        );
        eprintln!(
            "hits: {} (name {}, data {}, segment {}, binary {})",
            result.hits.len(),
            count(|w| matches!(w, RefWhere::Name)),
            count(|w| matches!(w, RefWhere::Data)),
            count(|w| matches!(w, RefWhere::Segment(_))),
            count(|w| matches!(w, RefWhere::Binary)),
        );
        for kind in [
            AnchorKind::Root,
            AnchorKind::Exe,
            AnchorKind::ProgId,
            AnchorKind::Token,
        ] {
            eprintln!(
                "  {kind:?}: {}",
                result
                    .hits
                    .iter()
                    .filter(|h| h.anchor_kind() == kind)
                    .count()
            );
        }
        for u in result.stats.unreadable.iter().take(5) {
            eprintln!("  unreadable: {} ({})", u.key, u.error);
        }
        assert!(!result.stats.cancelled && !result.stats.truncated);
        assert!(
            result.hits.len() > 100,
            "VS Code registers hundreds of references"
        );
        assert!(
            result.hits.iter().any(|h| h.location == RefWhere::Name
                && h.key.to_lowercase().ends_with(r"\openwithprogids"))
        );
        let again = scan(&f, &m, &scope, &RefScanOptions::default(), None);
        assert_eq!(again.hits, result.hits);
    }

    /// A source over a fixture whose keys named `flaky…` can be opened but neither their values nor
    /// their subkeys listed: two unreadable reports for one key.
    struct Flaky<'a>(&'a Fixture);

    impl Flaky<'_> {
        fn flaky(key: &str) -> bool {
            key.rsplit('\\')
                .next()
                .is_some_and(|leaf| leaf.starts_with("flaky"))
        }
    }

    impl RegistrySource for Flaky<'_> {
        fn key_info(&self, key: &str) -> SourceResult<KeyInfo> {
            self.0.key_info(key)
        }
        fn subkeys(&self, key: &str) -> SourceResult<Vec<String>> {
            if Self::flaky(key) {
                return Err(SourceError::AccessDenied);
            }
            self.0.subkeys(key)
        }
        fn values(&self, key: &str) -> SourceResult<Vec<RegValue>> {
            if Self::flaky(key) {
                return Err(SourceError::AccessDenied);
            }
            self.0.values(key)
        }
        fn value(&self, key: &str, name: &str) -> SourceResult<RegData> {
            self.0.value(key, name)
        }
        fn loaded_user_sids(&self) -> SourceResult<Vec<String>> {
            self.0.loaded_user_sids()
        }
        fn current_control_set(&self) -> SourceResult<u32> {
            self.0.current_control_set()
        }
    }

    /// A tree of a few thousand keys, five levels deep, with hits, decoys, a pruned store, a link,
    /// denied keys and `flaky` keys (more than [`MAX_UNREADABLE_LISTED`] of them when `flaky` is large).
    fn big_tree(flaky: usize) -> Fixture {
        let hit = format!(r"{FF}\firefox.exe");
        let mut b = base()
            .sz(r"HKLM\SOFTWARE\Classes\Installer\P\Q", "a", &hit)
            .link(
                &hku(r"Software\Classes"),
                &format!(r"\REGISTRY\USER\{SID}_Classes"),
            )
            .sz(
                &format!(r"HKU\{SID}_Classes\FirefoxURL-{TOKEN}\shell\open\command"),
                "",
                &hit,
            );
        for v in 0..12 {
            for p in 0..9 {
                let product = format!(r"HKLM\SOFTWARE\Vendor{v:02}\Product{p}");
                b = b.sz(&product, "InstallDir", &format!(r"{FF}\v{v}\p{p}"));
                for d in 0..4 {
                    let deep = format!(r"{product}\L1-{d}\L2\L3\L4");
                    b = b
                        .sz(&deep, "Path", &format!(r"C:\Other\{v}{p}{d}"))
                        .sz(&deep, &format!("{TOKEN}-{d}"), "named after the token")
                        .dword(&format!(r"{product}\L1-{d}"), "n", d);
                }
                if (v + p) % 7 == 0 {
                    b = b
                        .sz(&format!(r"{product}\Locked\Inner"), "a", &hit)
                        .denied(&format!(r"{product}\Locked"));
                }
            }
        }
        for i in 0..flaky {
            let key = format!(r"HKLM\SOFTWARE\Flakes\G{:02}\flaky{i:04}", i % 13);
            b = b
                .sz(&key, "a", &hit)
                .sz(&format!(r"{key}\Below"), "b", &hit);
        }
        b.build()
    }

    /// The parallel scan gives exactly the hits and statistics of the sequential walk, in the same
    /// order, whatever the number of threads, with more unreadable keys than are listed.
    #[test]
    fn parallel_scans_equal_the_sequential_walk() {
        for flaky in [0, 40, MAX_UNREADABLE_LISTED + 77] {
            let f = big_tree(flaky);
            let source = Flaky(&f);
            let m = matcher();
            let scope = Scope::standard(&f).unwrap();
            for options in [
                RefScanOptions::default(),
                RefScanOptions {
                    all_anchors: true,
                    ..RefScanOptions::default()
                },
            ] {
                let one = scan_with_threads(&source, &m, &scope, &options, None, 1);
                assert!(one.hits.len() > 100, "{}", one.hits.len());
                assert!(one.stats.pruned > 0 && one.stats.links_skipped > 0);
                if flaky > MAX_UNREADABLE_LISTED {
                    assert_eq!(one.stats.unreadable.len(), MAX_UNREADABLE_LISTED);
                    assert!(one.stats.unreadable_total > MAX_UNREADABLE_LISTED as u64);
                }
                for threads in [2, 3, 8, 32] {
                    let many = scan_with_threads(&source, &m, &scope, &options, None, threads);
                    assert_eq!(many.hits, one.hits, "{threads} threads, {flaky} flaky");
                    assert_eq!(many.stats, one.stats, "{threads} threads, {flaky} flaky");
                }
            }
        }
    }

    /// Roots that are pruned, missing or links, in any position, come out of a parallel scan as out
    /// of the sequential one.
    #[test]
    fn parallel_scans_keep_root_order_and_root_facts() {
        let f = big_tree(5);
        let link = hku(r"Software\Classes");
        let scope = Scope::custom(
            [
                r"HKLM\SOFTWARE\Missing".to_string(),
                r"HKLM\SOFTWARE\Vendor03".to_string(),
                link,
                r"HKLM\SOFTWARE\Nothing\Here".to_string(),
                r"HKLM\SOFTWARE\Classes\Installer".to_string(),
                r"HKLM\SOFTWARE\Flakes".to_string(),
            ],
            default_prune(),
        );
        let source = Flaky(&f);
        let options = RefScanOptions::default();
        let one = scan_with_threads(&source, &matcher(), &scope, &options, None, 1);
        assert_eq!(
            one.stats.roots_missing,
            [r"HKLM\SOFTWARE\Missing", r"HKLM\SOFTWARE\Nothing\Here"]
        );
        assert_eq!((one.stats.pruned, one.stats.links_skipped), (1, 1));
        for threads in [2, 4, 16] {
            let many = scan_with_threads(&source, &matcher(), &scope, &options, None, threads);
            assert_eq!(many.hits, one.hits);
            assert_eq!(many.stats, one.stats);
        }
        // The public entry point picks its own number of threads and agrees too.
        let auto = scan(&source, &matcher(), &scope, &options, None);
        assert_eq!((auto.hits, auto.stats), (one.hits, one.stats));
    }

    #[test]
    fn parallel_map_keeps_order_and_bounds_threads() {
        let seen = std::sync::Mutex::new(std::collections::HashSet::new());
        let out = parallel_map(
            (0..500u32).collect(),
            4,
            || std::thread::current().id(),
            |id, i| {
                seen.lock().unwrap().insert(*id);
                i * 2
            },
        );
        assert_eq!(out, (0..500u32).map(|i| i * 2).collect::<Vec<_>>());
        let threads = seen.lock().unwrap().len();
        assert!((1..=4).contains(&threads), "{threads}");
        assert!(parallel_map(Vec::<u32>::new(), 4, || (), |(), i| i).is_empty());
    }
}
