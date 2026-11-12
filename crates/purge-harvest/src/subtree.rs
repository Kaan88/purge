//! Subtree baselines of harvested keys (ENGINE_PLAN.md §5.2 "subtree baselines", §5.3
//! `ProvenOwnedSkeleton`).
//!
//! An uninstaller that removes only the leaves it wrote leaves empty parents behind: an `.ext` key with
//! an empty `OpenWithProgids`, a `shell` key whose verbs are gone. Once empty, such a key carries no
//! value and no reference, so nothing can attribute it any more. The harvest therefore records, while
//! the app is still installed, what each such key holds and whether **all** of it is the app's.
//!
//! # Which keys ([`keys`])
//!
//! 1. every key an Inno record creates (`RegDeleteEntireKey` / `RegDeleteKeyIfEmpty` with `key_create`);
//! 2. every ProgID of P under the Classes roots;
//! 3. every key that holds a value of the reference snapshot, and its ancestors up to the first
//!    structural container (exclusive) or the first key of the clean-Windows baseline (inclusive, as a
//!    shallow record). Without a baseline for this Windows there is nothing to stop the climb at, and
//!    nothing a skeleton could be proven against, so only the key itself is taken.
//!
//! Value containers (`Run`, `Environment`, ...) and the top keys of a hive are never captured.
//!
//! # What is recorded ([`capture`])
//!
//! A [`SubtreeBaseline`] per key: every value (name, type and data hash), every subkey, the key's
//! LastWriteTime, its TrustedInstaller flag and `fully_attributed`.
//!
//! `fully_attributed` is true only when every value and every subkey of the subtree is attributed to
//! the app by a Tier A fact:
//!
//! - a **value** is attributed when it is a proven reference to an anchor (what the reference snapshot
//!   records; a root anchor must be an InstallRoot, and one string of a `REG_MULTI_SZ` does not make
//!   the whole value the app's), when an Inno record deletes or clears exactly that value, or when it
//!   lies in a covered key;
//! - a key is **covered**, with everything below it, when it is a ProgID of P under a Classes root or
//!   an Inno record deletes it entirely;
//! - a **subkey** is attributed when it is covered, when an Inno record creates it, when it is named
//!   like a ProgID of P, or when it is a pure skeleton: it holds something and all it holds is
//!   attributed. An empty key nobody declares is nobody's.
//!
//! and none of the following holds: the capture hit a cap or an unreadable key, the subtree contains a
//! registry link, the key is in the baseline, an Inno record says the key existed before the install,
//! a key of the subtree is TrustedInstaller-owned, or the source can tell owners but could not for a
//! key of the subtree.
//!
//! # Decisions on open points
//!
//! - **Value hashes.** [`SubtreeValue::hash`] is `<type in hex>:<16 hex digits>` ([`value_hash`]): the
//!   registry type, then the rig's data hash (first 16 hex digits of the SHA-256 of the data). It covers
//!   type and data as the model asks, and the data part stays comparable with the hashes rig snapshots
//!   and baselines record. `?` stands for a hash the source could not give.
//! - **Unknown owners.** A source that records no owners at all (a rig snapshot, a plain fixture) gives
//!   `ti_owned = false` and does not affect `fully_attributed`; the scan checks the live owner again.
//!   A source that does record owners but cannot tell for one key makes that subtree not fully
//!   attributed.

use std::collections::BTreeSet;

use purge_guard::canon::GuardEnv;
use purge_guard::containers::is_value_container;
use purge_guard::prefix;
use purge_index::baseline::Baseline;
use purge_index::queries::{self, SubtreeLimits, hash_hex, values_referencing};
use purge_index::refscan::RefScanOptions;
use purge_model::{InnoRecordKind, RefSnapEntry, SubtreeBaseline, SubtreeValue, Target};
use purge_source::types::{ExistsState, SourceError};

use crate::refsnap::{HarvestCtx, source_key};

/// Limits of the subtree harvest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubtreeOptions {
    /// Caps of one capture. A capture that hits one is kept, with `fully_attributed = false`.
    pub limits: SubtreeLimits,
    /// How many ancestors of a referencing key are considered.
    pub max_ancestors: u32,
    /// How many subtrees one harvest records; further keys are dropped with a warning.
    pub max_subtrees: usize,
}

impl Default for SubtreeOptions {
    fn default() -> Self {
        Self {
            limits: SubtreeLimits {
                max_keys: 512,
                max_values: 2048,
                max_depth: 16,
            },
            max_ancestors: 8,
            max_subtrees: 4096,
        }
    }
}

/// The outcome of [`capture_with`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubtreeCapture {
    /// The baselines, ordered by key (case-insensitively).
    pub subtrees: Vec<SubtreeBaseline>,
    /// Things worth a line in the fingerprint's warnings.
    pub warnings: Vec<String>,
}

/// [`SubtreeValue::hash`] for a value of registry type `ty` whose data hashes to `hash`.
pub fn value_hash(ty: u32, hash: Option<u64>) -> String {
    match hash {
        Some(hash) => format!("{ty:x}:{}", hash_hex(hash)),
        None => format!("{ty:x}:?"),
    }
}

/// The registry type and data hash of a [`SubtreeValue::hash`] written by [`value_hash`].
pub fn parse_value_hash(text: &str) -> Option<(u32, Option<u64>)> {
    let (ty, hash) = text.split_once(':')?;
    let ty = u32::from_str_radix(ty, 16).ok()?;
    if hash == "?" {
        return Some((ty, None));
    }
    (hash.len() == 16)
        .then(|| u64::from_str_radix(hash, 16).ok())
        .flatten()
        .map(|hash| (ty, Some(hash)))
}

/// The minimal guard environment the structural-container test needs.
fn container_env(ctx: &HarvestCtx<'_>) -> GuardEnv {
    let mut loaded = ctx.reg.loaded_user_sids().unwrap_or_default();
    for sid in ctx.user_sids() {
        if !loaded.iter().any(|s| s.eq_ignore_ascii_case(&sid)) {
            loaded.push(sid);
        }
    }
    GuardEnv {
        current_control_set: ctx.reg.current_control_set().unwrap_or(0),
        loaded_sids: loaded,
        ..GuardEnv::default()
    }
}

/// Whether a key is too close to the top of its hive to be anyone's own: the hive roots, `SOFTWARE`,
/// the Classes roots, `SOFTWARE\Microsoft`, the 32-bit view roots and the top of a control set.
fn too_shallow(key: &str) -> bool {
    let segs: Vec<String> = prefix::segments(key).map(prefix::fold).collect();
    let segs: Vec<&str> = segs.iter().map(String::as_str).collect();
    let wow = |s: &&str| *s == "wow6432node";
    match segs.as_slice() {
        ["hklm", "software", rest @ ..] => {
            let rest: Vec<&str> = rest.iter().filter(|s| !wow(s)).copied().collect();
            match rest.as_slice() {
                [] | ["classes"] | ["microsoft"] => true,
                // `Classes\WOW6432Node` and the like were reduced above; a view root alone is shallow.
                _ => false,
            }
        }
        ["hklm", "system", rest @ ..] => rest.len() < 3,
        ["hklm", ..] => true,
        ["hku", hive, rest @ ..] if hive.ends_with("_classes") => {
            rest.iter().filter(|s| !wow(s)).count() == 0
        }
        ["hku", _, "software", rest @ ..] => {
            let rest: Vec<&str> = rest.iter().filter(|s| !wow(s)).copied().collect();
            matches!(rest.as_slice(), [] | ["classes"] | ["microsoft"])
        }
        ["hku", _, rest @ ..] => rest.is_empty(),
        _ => true,
    }
}

fn in_baseline(baseline: Option<&Baseline>, key: &str) -> bool {
    baseline.is_some_and(|b| Baseline::key_in_scope(key) && b.has_key(key))
}

/// The keys whose subtrees the harvest records (see the module documentation), ordered
/// case-insensitively, each once. `snapshot` is the reference snapshot of this harvest.
pub fn keys(ctx: &HarvestCtx<'_>, snapshot: &[RefSnapEntry]) -> Vec<String> {
    keys_with(ctx, snapshot, &SubtreeOptions::default())
}

/// [`keys`] with explicit limits.
pub fn keys_with(
    ctx: &HarvestCtx<'_>,
    snapshot: &[RefSnapEntry],
    options: &SubtreeOptions,
) -> Vec<String> {
    let env = container_env(ctx);
    let baseline = ctx.matching_baseline();
    let bound = ctx.bind_sid();
    let sid = bound.as_deref();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<String> = Vec::new();
    let mut add = |key: String| {
        if seen.insert(prefix::fold(&key)) {
            out.push(key);
        }
    };
    let capturable = |key: &str| !too_shallow(key) && !is_value_container(key, &env);

    // 1. Keys an Inno record creates.
    for record in ctx.inno {
        let key_kind = matches!(
            record.kind,
            InnoRecordKind::RegDeleteEntireKey | InnoRecordKind::RegDeleteKeyIfEmpty
        );
        if let (true, true, Target::RegKey { path }) = (key_kind, record.key_create, &record.target)
        {
            let key = source_key(path, sid);
            if capturable(&key) {
                add(key);
            }
        }
    }

    // 2. The ProgIDs of P.
    for classes in ctx.classes_roots() {
        for progid in ctx.progids() {
            let key = format!("{classes}\\{progid}");
            if ctx.reg.key_exists(&key) == ExistsState::Present {
                add(key);
            }
        }
    }

    // 3. Keys holding a snapshot value, and their ancestors.
    for entry in snapshot {
        let (Target::RegValue { path, .. } | Target::RegMultiSzSegment { path, .. }) =
            &entry.target
        else {
            continue;
        };
        let mut key = source_key(path, sid);
        for _ in 0..=options.max_ancestors {
            if !capturable(&key) {
                break;
            }
            let known = in_baseline(baseline, &key);
            add(key.clone());
            // A baseline key ends the climb; without a baseline there is nothing to end it at.
            if known || baseline.is_none() || !Baseline::key_in_scope(&key) {
                break;
            }
            match prefix::parent(&key) {
                Some(parent) => key = parent.to_owned(),
                None => break,
            }
        }
    }

    out.sort_by_key(|key| prefix::fold(key));
    out
}

/// What the Inno log and the ProgID set say about keys and values, in folded form.
struct Attribution {
    /// Keys an Inno record deletes entirely.
    entire: Vec<String>,
    /// Keys an Inno record deletes when empty.
    if_empty: Vec<String>,
    /// Keys an Inno record says existed before the install.
    existed: Vec<String>,
    /// (key, value name) pairs an Inno record deletes or clears.
    values: BTreeSet<(String, String)>,
    /// `<Classes root>\<ProgID>` for every ProgID of P.
    progid_keys: Vec<String>,
}

impl Attribution {
    fn new(ctx: &HarvestCtx<'_>) -> Self {
        let bound = ctx.bind_sid();
        let sid = bound.as_deref();
        let norm = |path: &str| prefix::fold(&source_key(path, sid));
        let mut out = Self {
            entire: Vec::new(),
            if_empty: Vec::new(),
            existed: Vec::new(),
            values: BTreeSet::new(),
            progid_keys: Vec::new(),
        };
        for record in ctx.inno {
            match (&record.target, record.kind) {
                (
                    Target::RegKey { path },
                    InnoRecordKind::RegDeleteEntireKey | InnoRecordKind::RegDeleteKeyIfEmpty,
                ) => {
                    if record.existed_before {
                        out.existed.push(norm(path));
                    } else if record.key_create {
                        if record.kind == InnoRecordKind::RegDeleteEntireKey {
                            out.entire.push(norm(path));
                        } else {
                            out.if_empty.push(norm(path));
                        }
                    }
                }
                (
                    Target::RegValue { path, name },
                    InnoRecordKind::RegDeleteValue | InnoRecordKind::RegClearValue,
                ) if !record.existed_before => {
                    out.values.insert((norm(path), prefix::fold(name)));
                }
                _ => {}
            }
        }
        for classes in ctx.classes_roots() {
            for progid in ctx.progids() {
                out.progid_keys
                    .push(prefix::fold(&format!("{classes}\\{progid}")));
            }
        }
        out
    }

    /// The key and everything below it is the app's. A key that a record says existed before the
    /// install is never covered, and neither is anything below it, whatever another record says.
    fn covered(&self, key: &str) -> bool {
        !self.existed_at_or_above(key)
            && self
                .entire
                .iter()
                .chain(&self.progid_keys)
                .any(|owner| prefix::is_same_or_inside(key, owner))
    }

    /// `key`, or a key above it, is one a record says existed before the install.
    fn existed_at_or_above(&self, key: &str) -> bool {
        self.existed
            .iter()
            .any(|old| prefix::is_same_or_inside(key, old))
    }
}

/// Captures the subtree baselines of `keys` (as [`keys`] lists them). Keys that do not exist are
/// skipped. The result is ordered by key, case-insensitively; a key given twice is captured once.
pub fn capture<K: AsRef<str>>(ctx: &HarvestCtx<'_>, keys: &[K]) -> Vec<SubtreeBaseline> {
    capture_with(ctx, keys, &SubtreeOptions::default()).subtrees
}

/// [`capture`] with explicit limits, reporting what could not be done.
pub fn capture_with<K: AsRef<str>>(
    ctx: &HarvestCtx<'_>,
    keys: &[K],
    options: &SubtreeOptions,
) -> SubtreeCapture {
    let mut out = SubtreeCapture::default();
    let bound = ctx.bind_sid();
    let sid = bound.as_deref();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut wanted: Vec<String> = keys
        .iter()
        .map(|key| source_key(key.as_ref(), sid))
        .filter(|key| !key.is_empty() && seen.insert(prefix::fold(key)))
        .collect();
    wanted.sort_by_key(|key| prefix::fold(key));
    if wanted.len() > options.max_subtrees {
        out.warnings.push(format!(
            "subtree: {} keys to record, only the first {} were",
            wanted.len(),
            options.max_subtrees
        ));
        wanted.truncate(options.max_subtrees);
    }

    let state = State {
        ctx,
        matcher: ctx.matcher(),
        attribution: Attribution::new(ctx),
        baseline: ctx.matching_baseline(),
        env: container_env(ctx),
        // Whether this source records key owners at all. `HKLM\SOFTWARE` exists on every Windows.
        owners_known: ctx
            .reg
            .key_info(r"HKLM\SOFTWARE")
            .is_ok_and(|info| info.ti_owned.is_some()),
    };
    let mut unknown_owners = 0usize;
    let mut truncated = 0usize;
    for key in wanted {
        // A baseline key is recorded for its own values only: it can never be a skeleton.
        let limits = if in_baseline(state.baseline, &key) {
            SubtreeLimits {
                max_depth: 0,
                ..options.limits
            }
        } else {
            options.limits
        };
        let tree = match queries::subtree(ctx.reg, &key, &limits) {
            Ok(tree) => tree,
            Err(SourceError::NotFound) => continue,
            Err(error) => {
                out.warnings
                    .push(format!("subtree: {key} could not be read ({error})"));
                continue;
            }
        };
        if tree.truncated {
            truncated += 1;
        }
        let fully_attributed = state.fully_attributed(&tree, &mut unknown_owners);
        out.subtrees.push(SubtreeBaseline {
            key: tree.key.clone(),
            values: tree
                .values
                .iter()
                .map(|value| SubtreeValue {
                    subkey: value.subkey.clone(),
                    name: value.name.clone(),
                    hash: value_hash(value.ty, value.hash),
                })
                .collect(),
            subkeys: tree.subkeys.clone(),
            lwt: tree.lwt,
            ti_owned: tree.ti_owned == Some(true),
            fully_attributed,
        });
    }
    if truncated > 0 {
        out.warnings.push(format!(
            "subtree: {truncated} subtrees were recorded in part (size caps or baseline keys)"
        ));
    }
    if unknown_owners > 0 {
        out.warnings.push(format!(
            "subtree: the owner of {unknown_owners} keys could not be read; their subtrees are not \
             attributed"
        ));
    }
    if !state.owners_known && !out.subtrees.is_empty() {
        out.warnings.push(
            "subtree: the source records no key owners; TrustedInstaller ownership was not checked"
                .into(),
        );
    }
    out
}

struct State<'a, 'c> {
    ctx: &'c HarvestCtx<'a>,
    matcher: purge_index::matcher::RefMatcher,
    attribution: Attribution,
    baseline: Option<&'a Baseline>,
    env: GuardEnv,
    owners_known: bool,
}

impl State<'_, '_> {
    /// Whether an owner flag lets the key be attributed; counts owners that should be known and are not.
    fn owner_ok(&self, ti_owned: Option<bool>, unknown: &mut usize) -> bool {
        match ti_owned {
            Some(true) => false,
            Some(false) => true,
            None if self.owners_known => {
                *unknown += 1;
                false
            }
            None => true,
        }
    }

    fn fully_attributed(&self, tree: &queries::Subtree, unknown_owners: &mut usize) -> bool {
        let ctx = self.ctx;
        let root = prefix::fold(&tree.key);
        if !tree.is_complete()
            || !tree.links.is_empty()
            || in_baseline(self.baseline, &tree.key)
            || self.attribution.existed.contains(&root)
            // A hive top or a value container is shared by everyone, whatever it holds right now.
            || too_shallow(&tree.key)
            || is_value_container(&tree.key, &self.env)
            || !self.owner_ok(tree.ti_owned, unknown_owners)
        {
            return false;
        }
        let full = |rel: &str| {
            if rel.is_empty() {
                tree.key.clone()
            } else {
                format!("{}\\{rel}", tree.key)
            }
        };

        // Owners and links of the subkeys. A subkey that existed before the install is not the app's,
        // even when all it holds now is.
        for rel in &tree.subkeys {
            if self.attribution.existed.contains(&prefix::fold(&full(rel))) {
                return false;
            }
            match ctx.reg.key_info(&full(rel)) {
                Ok(info) => {
                    if info.is_link || !self.owner_ok(info.ti_owned, unknown_owners) {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }

        // The values that provably refer to an anchor.
        let all_keys: Vec<String> = std::iter::once(tree.key.clone())
            .chain(tree.subkeys.iter().map(|rel| full(rel)))
            .collect();
        let options = RefScanOptions {
            all_anchors: true,
            ..RefScanOptions::default()
        };
        let referencing = values_referencing(ctx.reg, &self.matcher, &all_keys, &options);
        if !referencing.is_complete() || !referencing.links.is_empty() {
            return false;
        }
        let referring: BTreeSet<(String, String)> = referencing
            .hits
            .iter()
            // One string of a list says nothing about the other strings: the value is not ours.
            .filter(|hit| ctx.attributes(hit) && hit.location.segment().is_none())
            .map(|hit| (prefix::fold(&hit.key), prefix::fold(&hit.value_name)))
            .collect();

        // Every value.
        for value in &tree.values {
            let key = prefix::fold(&full(&value.subkey));
            let id = (key, prefix::fold(&value.name));
            let attributed = referring.contains(&id)
                || self.attribution.values.contains(&id)
                || self.attribution.covered(&id.0);
            if !attributed {
                return false;
            }
        }

        // Every key: declared by a record or by P, or a skeleton that holds something. Since every
        // value is attributed by now and every subkey is tested here, "holds something" is enough.
        let holds_something = |rel: &str| {
            tree.values.iter().any(|value| value.subkey == rel)
                || tree
                    .subkeys
                    .iter()
                    .any(|sub| prefix::parent(sub).unwrap_or("") == rel)
        };
        let declared = |rel: &str| {
            let key = prefix::fold(&full(rel));
            self.attribution.covered(&key)
                || self.attribution.if_empty.contains(&key)
                || prefix::leaf(rel).is_some_and(|name| ctx.is_progid(name))
        };
        std::iter::once("")
            .chain(tree.subkeys.iter().map(String::as_str))
            .all(|rel| declared(rel) || holds_something(rel))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "S-1-5-21-1-2-3-1001";

    #[test]
    fn value_hash_round_trips() {
        assert_eq!(
            value_hash(1, Some(0x9f86_d081_884c_7d65)),
            "1:9f86d081884c7d65"
        );
        assert_eq!(value_hash(11, Some(1)), "b:0000000000000001");
        assert_eq!(value_hash(3, None), "3:?");
        for (ty, hash) in [(1, Some(0x9f86_d081_884c_7d65)), (11, Some(1)), (3, None)] {
            assert_eq!(parse_value_hash(&value_hash(ty, hash)), Some((ty, hash)));
        }
        assert_eq!(parse_value_hash("aa11"), None);
        assert_eq!(parse_value_hash("1:abc"), None);
        assert_eq!(parse_value_hash("x:0000000000000001"), None);
    }

    #[test]
    fn shallow_keys() {
        for key in [
            "HKLM".to_owned(),
            r"HKLM\SOFTWARE".to_owned(),
            r"HKLM\Software\Classes".to_owned(),
            r"HKLM\SOFTWARE\WOW6432Node".to_owned(),
            r"HKLM\SOFTWARE\Classes\WOW6432Node".to_owned(),
            r"HKLM\SOFTWARE\Microsoft".to_owned(),
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft".to_owned(),
            r"HKLM\SYSTEM\ControlSet001\Services".to_owned(),
            r"HKLM\SAM\x\y\z".to_owned(),
            format!(r"HKU\{SID}"),
            format!(r"HKU\{SID}\Software"),
            format!(r"HKU\{SID}\Software\Classes"),
            format!(r"HKU\{SID}\Software\Microsoft"),
            format!(r"HKU\{SID}_Classes"),
            r"C:\Program Files".to_owned(),
        ] {
            assert!(too_shallow(&key), "{key}");
        }
        for key in [
            r"HKLM\SOFTWARE\Mozilla".to_owned(),
            r"HKLM\SOFTWARE\Classes\.txt".to_owned(),
            r"HKLM\SOFTWARE\WOW6432Node\Vendor".to_owned(),
            r"HKLM\SOFTWARE\Microsoft\Windows".to_owned(),
            r"HKLM\SYSTEM\ControlSet001\Services\MozillaMaintenance".to_owned(),
            format!(r"HKU\{SID}\Software\Vendor"),
            format!(r"HKU\{SID}\Environment"),
            format!(r"HKU\{SID}_Classes\.txt"),
        ] {
            assert!(!too_shallow(&key), "{key}");
        }
    }
}
