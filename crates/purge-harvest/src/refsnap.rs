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
//! # Scope and completeness
//!
//! The scan covers the machine roots of §5.5 and the hives of the interactive user (and of the user the
//! app is installed for, when that is someone else). [`RefSnap::complete`] says whether every key of
//! that scope could be read; a snapshot that is not complete still holds only proven references, but
//! its silence about a key proves nothing.

use std::collections::BTreeMap;

use purge_guard::prefix;
use purge_index::baseline_view::{Absence, BaselineTrust, BaselineView};
use purge_index::matcher::{AnchorSet, RefMatcher};
use purge_index::queries::hash_hex;
use purge_index::refscan::{
    self, RefHit, RefScanOptions, RefScanStats, RefWhere, Scope, default_prune,
};
use purge_model::{
    AnchorKind, InnoRecord, InventoryEntry, RefCarrier, RefSnapEntry, Root, RootKind, Target,
};
use purge_source::filesystem::FileSystemSource;
use purge_source::registry::RegistrySource;
use purge_source::system::SystemSource;
use purge_source::types::{REG_EXPAND_SZ, REG_SZ};

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

impl<'a> HarvestCtx<'a> {
    /// The users whose hives the harvest reads: the interactive user, then the user the app is
    /// installed for when that is someone else.
    pub fn user_sids(&self) -> Vec<String> {
        let mut sids: Vec<String> = Vec::new();
        let candidates = self
            .sys
            .user_sid()
            .ok()
            .into_iter()
            .chain(self.target.hive_sid.clone());
        for sid in candidates {
            if !sid.is_empty() && !sids.iter().any(|s| s.eq_ignore_ascii_case(&sid)) {
                sids.push(sid);
            }
        }
        sids
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
    let sids = ctx.user_sids();
    match Scope::for_sids(ctx.reg, &sids) {
        Ok(scope) => scope,
        Err(error) => {
            warnings.push(format!(
                "refsnap: current control set unknown ({error}); services and the machine \
                 environment were not scanned"
            ));
            let mut roots = vec![r"HKLM\SOFTWARE".to_owned()];
            for sid in &sids {
                roots.push(format!(r"HKU\{sid}\Software"));
                roots.push(format!(r"HKU\{sid}\Environment"));
                roots.push(format!(r"HKU\{sid}_Classes"));
            }
            Scope::custom(roots, default_prune())
        }
    }
}

/// Runs the reference scan and reports the snapshot together with what the scan could not do.
pub fn capture_report(ctx: &HarvestCtx<'_>) -> RefSnap {
    let mut warnings = Vec::new();
    if ctx.anchors.is_empty() {
        warnings.push("refsnap: the app has no anchors; the reference snapshot is empty".into());
        return RefSnap {
            complete: true,
            warnings,
            ..RefSnap::default()
        };
    }
    let scope = scope(ctx, &mut warnings);
    let matcher = ctx.matcher();
    let scan = refscan::scan(ctx.reg, &matcher, &scope, &RefScanOptions::default(), None);
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

/// The pre-uninstall reference snapshot: every registry value in scope that provably refers to one of
/// the app's anchors. See [`capture_report`] for the completeness of the scan behind it.
pub fn capture(ctx: &HarvestCtx<'_>) -> Vec<RefSnapEntry> {
    capture_report(ctx).entries
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "S-1-5-21-1-2-3-1001";

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
