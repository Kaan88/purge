//! The harvest context shared by the second half of the harvest, and the pre-uninstall reference
//! snapshot (ENGINE_PLAN.md §5.2 "Fingerprint", §5.3 `InPreUninstallRefSnapshot`, §5.5).
//!
//! # The context
//!
//! [`HarvestCtx`] bundles what [`crate::refsnap`], [`crate::subtree`], [`crate::assoc`] and
//! [`crate::coproducts`] read: the three sources, the app's anchors, its validated roots, its Inno
//! records, the baseline and the inventory. Every function of these modules takes it explicitly, so they
//! run on a fixture without the rest of the harvest.
//!
//! # The reference snapshot
//!
//! [`capture`] runs the reference scan of `purge-index` with the app's anchor set (roots, exe paths, the
//! ProgID set P, CLSIDs, AUMIDs, tokens) while the app is still installed, and keeps every registry value
//! that refers to an anchor as a [`RefSnapEntry`]: the value, where in it the reference is, the anchor,
//! the value and subkey counts of its key and the hash of its data.
//!
//! After the uninstall an entry is Tier A evidence that the value was the app's
//! (`InPreUninstallRefSnapshot`), so only **proven** references are kept. A hit is left out when
//!
//! - the matched text reaches the point where the scan stopped reading the data (`RefHit::cut_edge`): the
//!   full data may name something else;
//! - the data was read only in part and the hit is in the data, not in the value name;
//! - the anchor is a bare exe name, which says nothing about the directory.
//!
//! Left-out hits are counted in [`RefSnap::weak_hits`].
//!
//! # List-like values
//!
//! A hit in one string of a `REG_MULTI_SZ` becomes a [`Target::RegMultiSzSegment`] with the segment's
//! text and index. The `;`-separated lists of the two `Environment` keys (`Path` and its like) are split
//! the same way: one entry per segment that refers to an anchor, never one for the value as a whole,
//! because the fix for such a value is an edit and not a deletion.
//!
//! # The walk starts early
//!
//! The scan's walk over the scope is most of a harvest's time and does not depend on the app: only
//! the test of what it reads does. [`EarlyWalk`] therefore starts the walk as soon as the users are
//! known, on threads of its own, while the harvest works out the roots, the exes and the anchors;
//! the walk holds what it reads until [`capture_report_ahead`] hands it the matcher
//! (`purge_index::refscan::scan_late`). The snapshot is the one [`capture_report`] makes: the same
//! keys are read through the same walker in the same order, every value is tested in walk order,
//! and the hits, the statistics and the completeness are those of the scan that starts with its
//! matcher. An early walk is only ever read-only, like the scan; it is not started when a source
//! meter is installed (`PURGE_TIMING`: every phase counts its own reads), and it is abandoned when
//! the app turns out to have no anchors or the scope is not the one the snapshot asks for.
//!
//! # Scope and completeness
//!
//! The scan covers the machine roots of §5.5 and the hives of the interactive user (and of the user the
//! app is installed for, when that is someone else). [`RefSnap::complete`] says whether every key of
//! that scope could be read; a snapshot that is not complete still holds only proven references, but
//! its silence about a key proves nothing.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use purge_guard::prefix;
use purge_index::baseline_view::{Absence, BaselineTrust, BaselineView};
use purge_index::matcher::{AnchorSet, RefMatcher};
use purge_index::queries::hash_hex;
use purge_index::refscan::{
    self, LateMatcher, RefHit, RefScan, RefScanOptions, RefScanStats, RefWhere, Scope,
    default_prune,
};
use purge_model::{
    AnchorKind, InnoRecord, InventoryEntry, RefCarrier, RefSnapEntry, Root, RootKind, Target,
};
use purge_source::filesystem::FileSystemSource;
use purge_source::registry::RegistrySource;
use purge_source::system::SystemSource;
use purge_source::types::{KeyInfo, REG_EXPAND_SZ, REG_SZ, RegData, RegValue, SourceResult};

use crate::anchors::ComCutoff;
use crate::harvest::SharedIndexes;

/// Everything the second half of the harvest reads.
///
/// The fields are public: the orchestrator builds the context with a struct literal once the first half
/// (roots, exe set, anchors, tokens, Inno records) is done.
#[derive(Clone, Copy)]
pub struct HarvestCtx<'a> {
    /// The registry.
    pub reg: &'a dyn RegistrySource,
    /// The file system.
    pub fs: &'a dyn FileSystemSource,
    /// Machine and session facts.
    pub sys: &'a dyn SystemSource,
    /// The app's anchors: roots, exe paths, the ProgID set P, CLSIDs, AUMIDs and tokens.
    pub anchors: &'a AnchorSet,
    /// The app's validated roots.
    pub roots: &'a [Root],
    /// The records of the app's Inno Setup uninstall log, with user-hive records already bound to
    /// `HKU\<sid>`; empty when it has none.
    pub inno: &'a [InnoRecord],
    /// The baseline view ([`BaselineView::empty`] without one). Presence is asked of
    /// [`HarvestCtx::presence`]; absence only through [`HarvestCtx::key_absence`] and
    /// [`HarvestCtx::has_exact_baseline`]. An Exact view is used only when it is for exactly the
    /// Windows the sources describe.
    pub baseline: &'a BaselineView,
    /// Every entry of the inventory, the target included.
    pub inventory: &'a [InventoryEntry],
    /// The entry being harvested.
    pub target: &'a InventoryEntry,
    /// When the app was installed, for "this key is older than the app" ([`ComCutoff`]); `None`
    /// when nothing is known, and then no key is taken for older.
    pub cutoff: Option<ComCutoff>,
    /// The machine-wide indexes of the engine call, built from the same sources and inventory, for
    /// the harvests of the co-product candidates ([`crate::coproducts`]); `None` makes each candidate
    /// harvest build its own.
    pub shared: Option<&'a SharedIndexes<'a>>,
}

/// A registry that reads each key once: the metadata, the values and the subkey names of a key are
/// read from the registry the first time they are asked for and handed out again after that, with
/// the answer they had then, an error included.
///
/// The steps of a harvest that follow the reference snapshot ask about the same keys many times
/// over: a ProgID's subtree is captured for the ProgID key and again for each key below it that
/// holds a reference, every capture reads each key once to record it and again to judge it, and the
/// keys older than the install are the keys just captured. Through this they are read once. What
/// is read is what the registry held at the first read; the steps take well under a second, and a
/// harvest is not atomic anyway. Single values, the loaded hives and the control set go to the
/// registry as before. A key is known by its path as written, so two spellings of a key are read
/// once each. Lives for the steps of one harvest.
pub struct ReadOnce<'a> {
    reg: &'a dyn RegistrySource,
    infos: Mutex<BTreeMap<String, SourceResult<KeyInfo>>>,
    values: Mutex<BTreeMap<String, SourceResult<Vec<RegValue>>>>,
    subkeys: Mutex<BTreeMap<String, SourceResult<Vec<String>>>>,
}

impl<'a> ReadOnce<'a> {
    /// Nothing read yet.
    pub fn new(reg: &'a dyn RegistrySource) -> Self {
        Self {
            reg,
            infos: Mutex::new(BTreeMap::new()),
            values: Mutex::new(BTreeMap::new()),
            subkeys: Mutex::new(BTreeMap::new()),
        }
    }

    /// The answer kept for `key`, or the one `read` gives now, which is kept.
    fn once<T: Clone>(
        kept: &Mutex<BTreeMap<String, SourceResult<T>>>,
        key: &str,
        read: impl FnOnce() -> SourceResult<T>,
    ) -> SourceResult<T> {
        let known = kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .cloned();
        if let Some(answer) = known {
            return answer;
        }
        // Not under the lock: a second reader of the same key meanwhile reads it too, and one of
        // the two answers is kept.
        let answer = read();
        kept.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(key.to_owned())
            .or_insert(answer)
            .clone()
    }
}

impl RegistrySource for ReadOnce<'_> {
    fn key_info(&self, key: &str) -> SourceResult<KeyInfo> {
        Self::once(&self.infos, key, || self.reg.key_info(key))
    }

    fn subkeys(&self, key: &str) -> SourceResult<Vec<String>> {
        Self::once(&self.subkeys, key, || self.reg.subkeys(key))
    }

    fn values(&self, key: &str) -> SourceResult<Vec<RegValue>> {
        Self::once(&self.values, key, || self.reg.values(key))
    }

    fn value(&self, key: &str, name: &str) -> SourceResult<RegData> {
        self.reg.value(key, name)
    }

    fn loaded_user_sids(&self) -> SourceResult<Vec<String>> {
        self.reg.loaded_user_sids()
    }

    fn current_control_set(&self) -> SourceResult<u32> {
        self.reg.current_control_set()
    }
}

/// [`HarvestCtx::user_sids`] of a harvest of `target`: the interactive user, then the user the app
/// is installed for when that is someone else.
pub fn user_sids_of(sys: &dyn SystemSource, target: &InventoryEntry) -> Vec<String> {
    let mut sids: Vec<String> = Vec::new();
    let candidates = sys
        .user_sid()
        .ok()
        .into_iter()
        .chain(target.hive_sid.clone());
    for sid in candidates {
        if !sid.is_empty() && !sids.iter().any(|s| s.eq_ignore_ascii_case(&sid)) {
            sids.push(sid);
        }
    }
    sids
}

impl<'a> HarvestCtx<'a> {
    /// The users whose hives the harvest reads: the interactive user, then the user the app is
    /// installed for when that is someone else.
    pub fn user_sids(&self) -> Vec<String> {
        user_sids_of(self.sys, self.target)
    }

    /// The user an unbound `HKCU` path of the target's own records is bound to: the user the app is
    /// installed for when the inventory knows one, otherwise the interactive user.
    pub fn bind_sid(&self) -> Option<String> {
        self.target
            .hive_sid
            .clone()
            .filter(|sid| !sid.is_empty())
            .or_else(|| self.user_sids().into_iter().next())
    }

    /// The reference matcher of the anchor set, with the interactive user's environment.
    pub fn matcher(&self) -> RefMatcher {
        let env: BTreeMap<String, String> = self.sys.env().unwrap_or_default();
        RefMatcher::with_env(self.anchors, env)
    }

    /// The ProgID set P, in anchor order.
    pub fn progids(&self) -> impl Iterator<Item = &'a str> + 'a {
        self.anchors
            .anchors()
            .iter()
            .filter(|a| a.kind == AnchorKind::ProgId)
            .map(|a| a.text.as_str())
    }

    /// Whether `name` is a ProgID of P (case-insensitive, whole name).
    pub fn is_progid(&self, name: &str) -> bool {
        self.progids().any(|p| prefix::eq_ci(p, name))
    }

    /// The full paths of the exe set.
    pub fn exe_paths(&self) -> impl Iterator<Item = &'a str> + 'a {
        self.anchors
            .anchors()
            .iter()
            .filter(|a| a.kind == AnchorKind::Exe && a.text.contains('\\'))
            .map(|a| a.text.as_str())
    }

    /// The bare exe names of the anchor set (the main exes).
    pub fn exe_names(&self) -> impl Iterator<Item = &'a str> + 'a {
        self.anchors
            .anchors()
            .iter()
            .filter(|a| a.kind == AnchorKind::Exe && !a.text.contains(['\\', '/']))
            .map(|a| a.text.as_str())
    }

    /// **A.** Whether the view is the exact shipped baseline of the Windows the sources describe: the
    /// only view whose absence is proof. A baseline of another edition or build proves nothing about
    /// this machine.
    pub fn has_exact_baseline(&self) -> bool {
        self.baseline.trust() == BaselineTrust::Exact
            && self
                .sys
                .os_info()
                .is_ok_and(|os| self.baseline.is_exact_for(&os.edition, os.build, os.ubr))
    }

    /// **P.** The view to ask "is this Windows' own?": the context's view at any trust, except an
    /// Exact view of another Windows, which is treated as absent ([`BaselineView::empty`]).
    pub fn presence(&self) -> &'a BaselineView {
        if self.baseline.trust() == BaselineTrust::Exact && !self.has_exact_baseline() {
            BaselineView::empty()
        } else {
            self.baseline
        }
    }

    /// **A.** What the harvest may conclude about `key` not being Windows' own: the one place of this
    /// crate that asks the view for absence (`cargo xtask baseline-sites`). The local baseline is
    /// presence-only (DECISIONS.md, Post-M1b, 2026-11-21): `Proven` comes from the exact baseline of
    /// this Windows alone, and what a view below Exact infers is handed out as `Unknown`, so an
    /// absence fact is recorded below Exact exactly as it was without a baseline. Never `Inferred`.
    pub fn key_absence(&self, key: &str) -> Absence {
        match self.presence().key_absent(key) {
            Absence::Inferred(_) => Absence::Unknown,
            answer @ (Absence::Present | Absence::Proven | Absence::Unknown) => answer,
        }
    }

    /// The Classes roots the app can have registered under: `HKLM\SOFTWARE\Classes`, then
    /// `HKU\<sid>_Classes` for each of [`HarvestCtx::user_sids`].
    pub fn classes_roots(&self) -> Vec<String> {
        let mut roots = vec![HKLM_CLASSES.to_owned()];
        roots.extend(
            self.user_sids()
                .into_iter()
                .map(|sid| format!(r"HKU\{sid}_Classes")),
        );
        roots
    }

    /// The InstallRoot that `path` is, or lies in.
    pub fn install_root_of(&self, path: &str) -> Option<&'a Root> {
        self.roots.iter().find(|root| {
            root.kind == RootKind::InstallRoot && prefix::is_same_or_inside(path, &root.path)
        })
    }

    /// Whether a hit proves that its value refers to the app, strongly enough to attribute the value
    /// with Tier A: the reference is proven (see the module documentation) and, for a root anchor, the
    /// root is an InstallRoot. An inferred root or a referenced data directory gives no Tier A fact
    /// (§5.2 "Root kinds").
    pub fn attributes(&self, hit: &RefHit) -> bool {
        is_proven(hit)
            && (hit.anchor.kind != AnchorKind::Root
                || self.install_root_of(&hit.anchor.text).is_some())
    }
}

/// `HKLM\SOFTWARE\Classes`.
pub(crate) const HKLM_CLASSES: &str = r"HKLM\SOFTWARE\Classes";

/// The key path in the form the sources list it: a user's `Software\Classes` (a registry link) is
/// rewritten to the `HKU\<sid>_Classes` hive it points to, and an unbound `HKCU` root is bound to `sid`.
/// Everything else is returned unchanged (without a trailing separator). That includes
/// `Software\Classes` of a hive without a classes hive (`.DEFAULT` and the service accounts,
/// [`purge_model::has_classes_hive`]): it is an ordinary key, listed and canonical where it is.
pub fn source_key(key: &str, sid: Option<&str>) -> String {
    let key = key.trim_matches(prefix::SEP);
    let mut segs: Vec<&str> = prefix::segments(key).collect();
    if let (Some(first), Some(sid)) = (segs.first(), sid) {
        if prefix::eq_ci(first, "HKCU") || prefix::eq_ci(first, "HKEY_CURRENT_USER") {
            segs[0] = "HKU";
            segs.insert(1, sid);
        }
    }
    let user_classes = segs.len() >= 4
        && prefix::eq_ci(segs[0], "HKU")
        && !segs[1].to_ascii_lowercase().ends_with("_classes")
        && purge_model::has_classes_hive(segs[1])
        && prefix::eq_ci(segs[2], "Software")
        && prefix::eq_ci(segs[3], "Classes");
    if user_classes {
        let mut out = format!(r"HKU\{}_Classes", segs[1]);
        for seg in &segs[4..] {
            out.push(prefix::SEP);
            out.push_str(seg);
        }
        out
    } else {
        segs.join("\\")
    }
}

/// Whether a hit is a proven reference (see the module documentation).
pub fn is_proven(hit: &RefHit) -> bool {
    !hit.cut_edge && !hit.name_only && (hit.location == RefWhere::Name || hit.data_complete)
}

/// The outcome of [`capture_report`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefSnap {
    /// The snapshot, in scan order (scope root by root, keys depth first, names case-insensitively).
    pub entries: Vec<RefSnapEntry>,
    /// Every key of the scope could be read.
    pub complete: bool,
    /// Hits that were not kept because they are possible references only.
    pub weak_hits: usize,
    /// What the scan walked.
    pub stats: RefScanStats,
    /// Things worth a line in the fingerprint's warnings.
    pub warnings: Vec<String>,
}

/// Whether the key is one of the two `Environment` keys, whose string values are `;`-separated lists.
fn is_environment_key(key: &str) -> bool {
    let segs: Vec<&str> = prefix::segments(key).collect();
    // A class named `Environment` in a user's Classes hive is not the user's environment.
    let user = segs.len() == 3
        && prefix::eq_ci(segs[0], "HKU")
        && !segs[1].to_ascii_lowercase().ends_with("_classes");
    let machine = segs.len() == 6
        && prefix::eq_ci(segs[0], "HKLM")
        && prefix::eq_ci(segs[1], "SYSTEM")
        && prefix::eq_ci(segs[3], "Control")
        && prefix::eq_ci(segs[4], "Session Manager");
    (user || machine) && segs.last().is_some_and(|s| prefix::eq_ci(s, "Environment"))
}

fn entry(hit: &RefHit, target: Target, carrier: RefCarrier) -> RefSnapEntry {
    RefSnapEntry {
        target,
        carrier,
        anchor: hit.anchor.clone(),
        parent_values: hit.parent_values,
        parent_subkeys: hit.parent_subkeys,
        data_hash: hit.data_hash.map(hash_hex),
    }
}

/// Turns the hits of a reference scan into snapshot entries, in the order of the hits. Possible
/// references are dropped; the second result is how many.
pub fn entries_from_hits(ctx: &HarvestCtx<'_>, hits: &[RefHit]) -> (Vec<RefSnapEntry>, usize) {
    let matcher = ctx.matcher();
    // The environment the matcher expands with: what an entry of a list leads to is read from it.
    let env: BTreeMap<String, String> = ctx.sys.env().unwrap_or_default();
    let mut entries = Vec::with_capacity(hits.len());
    let mut weak = 0usize;
    // The `;`-lists already split: (folded key, folded value name).
    let mut lists_done: Vec<(String, String)> = Vec::new();
    for hit in hits {
        if !is_proven(hit) {
            weak += 1;
            continue;
        }
        let value = || Target::RegValue {
            path: hit.key.clone(),
            name: hit.value_name.clone(),
        };
        match hit.location {
            RefWhere::Name => entries.push(entry(hit, value(), RefCarrier::ValueName)),
            RefWhere::Binary => entries.push(entry(hit, value(), RefCarrier::Binary)),
            RefWhere::Segment(index) => {
                let segment = ctx
                    .reg
                    .value(&hit.key, &hit.value_name)
                    .ok()
                    .and_then(|data| data.multi_sz())
                    .and_then(|segments| segments.get(index as usize).cloned())
                    // The string must still be one that refers to the app.
                    .filter(|segment| matcher.find_all(segment).iter().any(|m| !m.name_only));
                // The value changed under the scan, or cannot be read as a list any more. One string
                // of a list never proves the whole value, so there is nothing to record: an entry on
                // the value would make every other string of it look like the app's.
                let Some(segment) = segment else {
                    weak += 1;
                    continue;
                };
                let target = Target::RegMultiSzSegment {
                    path: hit.key.clone(),
                    name: hit.value_name.clone(),
                    segment,
                    index: Some(index),
                };
                entries.push(entry(hit, target, RefCarrier::Segment));
            }
            RefWhere::Data => {
                let list = is_environment_key(&hit.key)
                    && matches!(hit.value_type, REG_SZ | REG_EXPAND_SZ);
                if !list {
                    entries.push(entry(hit, value(), RefCarrier::Data));
                    continue;
                }
                let id = (prefix::fold(&hit.key), prefix::fold(&hit.value_name));
                if lists_done.contains(&id) {
                    continue;
                }
                lists_done.push(id);
                let text = ctx
                    .reg
                    .value(&hit.key, &hit.value_name)
                    .ok()
                    .and_then(|data| data.string())
                    .unwrap_or_default();
                for (index, piece) in prefix::list_entries(&text).into_iter().enumerate() {
                    let piece = piece.trim();
                    // Not one plainly written directory, as written or with its references
                    // expanded (`prefix::ListEntry::read`, which REG-ENV reads entries with too):
                    // never recorded as an entry of the app.
                    if prefix::ListEntry::read(piece, &env).is_none() {
                        continue;
                    }
                    let Some(found) = matcher.find(piece) else {
                        continue;
                    };
                    if found.name_only {
                        weak += 1;
                        continue;
                    }
                    entries.push(RefSnapEntry {
                        target: Target::RegMultiSzSegment {
                            path: hit.key.clone(),
                            name: hit.value_name.clone(),
                            segment: piece.to_owned(),
                            index: u32::try_from(index).ok(),
                        },
                        carrier: RefCarrier::Segment,
                        anchor: found.anchor,
                        parent_values: hit.parent_values,
                        parent_subkeys: hit.parent_subkeys,
                        data_hash: hit.data_hash.map(hash_hex),
                    });
                }
            }
        }
    }
    (entries, weak)
}

/// The scope of the harvest's reference scan: the machine roots of §5.5 and the hives of
/// [`HarvestCtx::user_sids`]. Falls back to the roots that do not depend on the control set when the
/// source cannot tell which one is current.
pub fn scope(ctx: &HarvestCtx<'_>, warnings: &mut Vec<String>) -> Scope {
    scope_for_sids(ctx.reg, &ctx.user_sids(), warnings)
}

/// [`scope`] for the given users: what the harvest's reference scan walks when it reads the hives of
/// `sids` (also the scope of the engine's `walk-floor` measurement, which must walk the same keys).
pub fn scope_for_sids(
    reg: &dyn RegistrySource,
    sids: &[String],
    warnings: &mut Vec<String>,
) -> Scope {
    match Scope::for_sids(reg, sids) {
        Ok(scope) => scope,
        Err(error) => {
            warnings.push(format!(
                "refsnap: current control set unknown ({error}); services and the machine \
                 environment were not scanned"
            ));
            let mut roots = vec![r"HKLM\SOFTWARE".to_owned()];
            for sid in sids {
                roots.push(format!(r"HKU\{sid}\Software"));
                roots.push(format!(r"HKU\{sid}\Environment"));
                roots.push(format!(r"HKU\{sid}_Classes"));
            }
            Scope::custom(roots, default_prune())
        }
    }
}

/// The reference walk of a harvest, started before the app's anchors are known (see the module
/// documentation). Dropped without [`capture_report_ahead`], it ends its walk.
pub struct EarlyWalk<'scope> {
    late: Arc<LateMatcher>,
    /// What the walk reads.
    scope: Scope,
    walk: Option<std::thread::ScopedJoinHandle<'scope, Option<RefScan>>>,
}

impl<'scope> EarlyWalk<'scope> {
    /// Starts the walk over [`scope_for_sids`] of `sids` ([`user_sids_of`] the harvest's target) on
    /// a thread of `threads`. `None`, and nothing started, when a source meter is installed or the
    /// system refuses the thread: the harvest then walks when it has its anchors, as before.
    pub fn start<'env>(
        threads: &'scope std::thread::Scope<'scope, 'env>,
        reg: &'env dyn RegistrySource,
        sids: &[String],
    ) -> Option<Self> {
        if purge_source::metered::installed().is_some() {
            return None;
        }
        // The snapshot works the scope out again, with its warnings, and takes this walk only for
        // that very scope.
        let scope = scope_for_sids(reg, sids, &mut Vec::new());
        let late = Arc::new(LateMatcher::new());
        let (walk_late, walk_scope) = (Arc::clone(&late), scope.clone());
        let walk = std::thread::Builder::new()
            .spawn_scoped(threads, move || {
                refscan::scan_late(reg, &walk_late, &walk_scope, &RefScanOptions::default())
            })
            .ok()?;
        Some(Self {
            late,
            scope,
            walk: Some(walk),
        })
    }

    /// Gives the walk the matcher of the scan of `scope`; `false`, and nothing given, when the
    /// walk reads another scope (dropped, it ends).
    fn give(&self, scope: &Scope, matcher: &RefMatcher) -> bool {
        if self.scope != *scope {
            return false;
        }
        self.late.set(matcher.clone());
        true
    }

    /// The scan of the walk that was given its matcher ([`EarlyWalk::give`]), when it is done.
    fn join(mut self) -> Option<RefScan> {
        match self.walk.take()?.join() {
            Ok(scan) => scan,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}

impl Drop for EarlyWalk<'_> {
    fn drop(&mut self) {
        if self.walk.is_some() {
            self.late.abandon();
        }
    }
}

/// Runs the reference scan and reports the snapshot together with what the scan could not do.
pub fn capture_report(ctx: &HarvestCtx<'_>) -> RefSnap {
    capture_report_ahead(ctx, None)
}

/// [`capture_report`], taking the scan from `early` when a walk of the same scope was started ahead
/// ([`EarlyWalk`]); the snapshot is the same either way.
pub fn capture_report_ahead(ctx: &HarvestCtx<'_>, early: Option<EarlyWalk<'_>>) -> RefSnap {
    capture_begin(ctx, early).finish(ctx)
}

/// A reference snapshot that is being made ([`capture_begin`]).
pub struct Capturing<'scope> {
    warnings: Vec<String>,
    /// The scope and the matcher of the scan; `None` for an app without anchors.
    scan: Option<(Scope, RefMatcher)>,
    /// The walk started ahead, now with its matcher.
    walking: Option<EarlyWalk<'scope>>,
}

/// The first half of [`capture_report_ahead`]: a walk started ahead for the scope of the snapshot
/// is given its matcher and goes on reading on its own threads. Until [`Capturing::finish`] the
/// caller can do what does not need the snapshot.
pub fn capture_begin<'scope>(
    ctx: &HarvestCtx<'_>,
    early: Option<EarlyWalk<'scope>>,
) -> Capturing<'scope> {
    let mut warnings = Vec::new();
    if ctx.anchors.is_empty() {
        warnings.push("refsnap: the app has no anchors; the reference snapshot is empty".into());
        return Capturing {
            warnings,
            scan: None,
            walking: None,
        };
    }
    let scope = scope(ctx, &mut warnings);
    let matcher = ctx.matcher();
    let walking = early.filter(|early| early.give(&scope, &matcher));
    Capturing {
        warnings,
        scan: Some((scope, matcher)),
        walking,
    }
}

impl Capturing<'_> {
    /// Whether a walk started ahead is reading for this snapshot: [`Capturing::finish`] will wait
    /// for it.
    pub fn is_walking(&self) -> bool {
        self.walking.is_some()
    }

    /// The snapshot: from the walk started ahead when there is one, else from a scan made now.
    pub fn finish(self, ctx: &HarvestCtx<'_>) -> RefSnap {
        let Capturing {
            warnings,
            scan,
            walking,
        } = self;
        let Some((scope, matcher)) = scan else {
            return RefSnap {
                complete: true,
                warnings,
                ..RefSnap::default()
            };
        };
        let scan = walking.and_then(EarlyWalk::join).unwrap_or_else(|| {
            refscan::scan(ctx.reg, &matcher, &scope, &RefScanOptions::default(), None)
        });
        Self::report(ctx, scan, warnings)
    }

    /// The snapshot of a finished scan.
    fn report(ctx: &HarvestCtx<'_>, scan: RefScan, mut warnings: Vec<String>) -> RefSnap {
        let complete = scan.is_complete();
        if !complete {
            let first = scan
                .stats
                .unreadable
                .first()
                .map(|u| format!(", first: {} ({})", u.key, u.error))
                .unwrap_or_default();
            warnings.push(format!(
                "refsnap: the reference scan is incomplete ({} keys unreadable{first})",
                scan.stats.unreadable_total
            ));
        }
        let (entries, weak_hits) = entries_from_hits(ctx, &scan.hits);
        if weak_hits > 0 {
            warnings.push(format!(
            "refsnap: {weak_hits} possible references were not recorded (cut data or bare exe name)"
        ));
        }
        RefSnap {
            entries,
            complete,
            weak_hits,
            stats: scan.stats,
            warnings,
        }
    }
}

/// The pre-uninstall reference snapshot: every registry value in scope that provably refers to one of
/// the app's anchors. See [`capture_report`] for the completeness of the scan behind it.
pub fn capture(ctx: &HarvestCtx<'_>) -> Vec<RefSnapEntry> {
    capture_report(ctx).entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_source::fixture::Fixture;
    use purge_source::types::SourceError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SID: &str = "S-1-5-21-1-2-3-1001";

    /// A registry that counts its reads by kind.
    struct Counted<'f> {
        inner: &'f Fixture,
        infos: AtomicUsize,
        subkeys: AtomicUsize,
        values: AtomicUsize,
        value: AtomicUsize,
        other: AtomicUsize,
    }

    impl RegistrySource for Counted<'_> {
        fn key_info(&self, key: &str) -> SourceResult<KeyInfo> {
            self.infos.fetch_add(1, Ordering::SeqCst);
            self.inner.key_info(key)
        }
        fn subkeys(&self, key: &str) -> SourceResult<Vec<String>> {
            self.subkeys.fetch_add(1, Ordering::SeqCst);
            self.inner.subkeys(key)
        }
        fn values(&self, key: &str) -> SourceResult<Vec<RegValue>> {
            self.values.fetch_add(1, Ordering::SeqCst);
            self.inner.values(key)
        }
        fn value(&self, key: &str, name: &str) -> SourceResult<RegData> {
            self.value.fetch_add(1, Ordering::SeqCst);
            self.inner.value(key, name)
        }
        fn loaded_user_sids(&self) -> SourceResult<Vec<String>> {
            self.other.fetch_add(1, Ordering::SeqCst);
            self.inner.loaded_user_sids()
        }
        fn current_control_set(&self) -> SourceResult<u32> {
            self.other.fetch_add(1, Ordering::SeqCst);
            self.inner.current_control_set()
        }
    }

    /// `ReadOnce` asks the registry once per key and kind of read and hands the same answer out
    /// after that, an error as well; the three kinds are kept apart; another spelling of a key is
    /// another key; single values and the hive facts go to the registry every time.
    #[test]
    fn read_once_reads_each_key_once_per_kind_and_keeps_errors() {
        const KEY: &str = r"HKLM\SOFTWARE\Vendor\App";
        const LOCKED: &str = r"HKLM\SOFTWARE\Vendor\Locked";
        const MISSING: &str = r"HKLM\SOFTWARE\Vendor\Gone";
        let f = Fixture::builder()
            .user_sid(SID)
            .key(r"HKLM\SYSTEM\ControlSet001\Services")
            .sz(KEY, "Path", r"C:\App")
            .sz(KEY, "", "default")
            .sz(&format!(r"{KEY}\Sub"), "a", "b")
            .sz(&format!(r"{LOCKED}\Inner"), "a", "b")
            .denied(LOCKED)
            .build();
        let counted = Counted {
            inner: &f,
            infos: AtomicUsize::new(0),
            subkeys: AtomicUsize::new(0),
            values: AtomicUsize::new(0),
            value: AtomicUsize::new(0),
            other: AtomicUsize::new(0),
        };
        let once = ReadOnce::new(&counted);
        let counts = || {
            (
                counted.infos.load(Ordering::SeqCst),
                counted.subkeys.load(Ordering::SeqCst),
                counted.values.load(Ordering::SeqCst),
            )
        };

        // Each kind of read of a key: once, with the registry's answer, whatever is asked first.
        assert_eq!(once.values(KEY), f.values(KEY));
        assert_eq!(counts(), (0, 0, 1));
        assert_eq!(once.key_info(KEY), f.key_info(KEY));
        assert_eq!(once.subkeys(KEY), f.subkeys(KEY));
        assert_eq!(counts(), (1, 1, 1));
        for _ in 0..3 {
            assert_eq!(once.key_info(KEY), f.key_info(KEY));
            assert_eq!(once.subkeys(KEY), f.subkeys(KEY));
            assert_eq!(once.values(KEY), f.values(KEY));
            assert!(once.key_exists(KEY).is_present());
        }
        assert_eq!(counts(), (1, 1, 1));
        assert_eq!(once.values(KEY).unwrap().len(), 2);

        // Errors are answers too: a missing key and a refused key are asked once per kind.
        for key in [MISSING, LOCKED] {
            let before = counts();
            let (info, subkeys, values) = (once.key_info(key), once.subkeys(key), once.values(key));
            assert_eq!(info, f.key_info(key), "{key}");
            assert_eq!(subkeys, f.subkeys(key), "{key}");
            assert_eq!(values, f.values(key), "{key}");
            assert!(values.is_err(), "{key}");
            for _ in 0..2 {
                assert_eq!(once.key_info(key), info, "{key}");
                assert_eq!(once.subkeys(key), subkeys, "{key}");
                assert_eq!(once.values(key), values, "{key}");
            }
            assert_eq!(
                counts(),
                (before.0 + 1, before.1 + 1, before.2 + 1),
                "{key}"
            );
        }
        assert_eq!(once.key_info(MISSING), Err(SourceError::NotFound));
        assert!(!once.key_exists(MISSING).is_present());

        // A key is known by its path as written.
        let before = counts();
        assert_eq!(
            once.values(&KEY.to_lowercase()),
            f.values(&KEY.to_lowercase())
        );
        assert_eq!(counts(), (before.0, before.1, before.2 + 1));

        // Single values and the hive facts are not kept.
        for n in 1..=3 {
            assert_eq!(once.value(KEY, "Path"), f.value(KEY, "Path"));
            assert_eq!(counted.value.load(Ordering::SeqCst), n);
        }
        assert!(once.value(KEY, "Nope").is_err());
        assert_eq!(counted.value.load(Ordering::SeqCst), 4);
        assert_eq!(once.loaded_user_sids(), f.loaded_user_sids());
        assert_eq!(once.loaded_user_sids(), f.loaded_user_sids());
        assert_eq!(once.current_control_set(), f.current_control_set());
        assert_eq!(counted.other.load(Ordering::SeqCst), 3);
        assert_eq!(counts(), (before.0, before.1, before.2 + 1));
    }

    #[test]
    fn source_key_rewrites_user_classes_and_binds_hkcu() {
        assert_eq!(
            source_key(r"HKCU\Software\Classes\.txt\OpenWithProgids", Some(SID)),
            format!(r"HKU\{SID}_Classes\.txt\OpenWithProgids")
        );
        assert_eq!(
            source_key(&format!(r"HKU\{SID}\SOFTWARE\classes"), None),
            format!(r"HKU\{SID}_Classes")
        );
        assert_eq!(
            source_key(&format!(r"HKU\{SID}\Software\Vendor\"), None),
            format!(r"HKU\{SID}\Software\Vendor")
        );
        assert_eq!(
            source_key(&format!(r"HKU\{SID}_Classes\Software\Classes\x"), None),
            format!(r"HKU\{SID}_Classes\Software\Classes\x")
        );
        assert_eq!(
            source_key(r"HKLM\Software\Classes\x", Some(SID)),
            r"HKLM\Software\Classes\x"
        );
        // Without a user, HKCU stays unbound.
        assert_eq!(source_key(r"HKCU\Software\X", None), r"HKCU\Software\X");
    }

    /// `source_key` gives a key below a user's `Software\Classes` the spelling `purge-guard` calls
    /// canonical, for the in-place and for the canonical input: the `_Classes` hive for a user, the key
    /// where it is for a hive without a classes hive. The same table as `purge-guard`'s
    /// `classes_spellings_agree` and `purge-source`'s
    /// `canonical_and_in_place_classes_spellings_open_the_same_key`.
    #[test]
    fn source_key_agrees_with_the_canonical_form() {
        use purge_guard::canon::{GuardEnv, canon_key};
        let env = GuardEnv::sample();
        let canonical = |key: &str| {
            canon_key(key, None, &env, None)
                .map(|k| k.key_path())
                .unwrap()
        };
        let mut rows: Vec<(String, String)> = vec![
            (
                format!(r"HKU\{SID}\Software\Classes\Vendor.Doc\shell"),
                format!(r"HKU\{SID}_Classes\Vendor.Doc\shell"),
            ),
            (
                format!(r"HKU\{SID}\Software\Classes\WOW6432Node\CLSID\{{X}}"),
                format!(r"HKU\{SID}_Classes\WOW6432Node\CLSID\{{X}}"),
            ),
        ];
        for sid in [".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20"] {
            for tail in [r"Vendor.Doc\shell", r"WOW6432Node\CLSID\{X}"] {
                let key = format!(r"HKU\{sid}\Software\Classes\{tail}");
                rows.push((key.clone(), key));
            }
        }
        for (in_place, want) in &rows {
            assert_eq!(&source_key(in_place, None), want, "{in_place}");
            assert_eq!(&source_key(want, None), want, "{want}");
            assert_eq!(&canonical(in_place), want, "{in_place}");
            assert_eq!(&canonical(want), want, "{want}");
        }
        // Any letter case of the hive name, and the root key itself.
        assert_eq!(
            source_key(r"HKU\.default\SOFTWARE\classes\x", None),
            r"HKU\.default\SOFTWARE\classes\x"
        );
        assert_eq!(
            source_key(r"HKU\S-1-5-18\Software\Classes", None),
            r"HKU\S-1-5-18\Software\Classes"
        );
        // Only the exact names.
        assert_eq!(
            source_key(r"HKU\S-1-5-18-1\Software\Classes\x", None),
            r"HKU\S-1-5-18-1_Classes\x"
        );
    }

    #[test]
    fn environment_keys() {
        assert!(is_environment_key(&format!(r"HKU\{SID}\Environment")));
        assert!(is_environment_key(
            r"HKLM\SYSTEM\ControlSet001\Control\Session Manager\Environment"
        ));
        assert!(!is_environment_key(&format!(
            r"HKU\{SID}\Software\Vendor\Environment"
        )));
        assert!(!is_environment_key(r"HKLM\SOFTWARE\Environment"));
        // A ProgID that happens to be called `Environment`.
        assert!(!is_environment_key(&format!(
            r"HKU\{SID}_Classes\Environment"
        )));
    }
}
