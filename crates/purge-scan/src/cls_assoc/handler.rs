//! The file-association handler (ENGINE_PLAN.md §5.7.1 steps 2 to 4): the rules CLS-ASSOC, CLS-FILEEXTS
//! and CLS-TOASTS share.
//!
//! Everything here is driven by the fingerprint's extension journal ([`ExtJournalEntry`], written by the
//! harvest before the uninstall) and by the ProgID set P (`Fingerprint::anchors.progids`). The handler
//! never decides a band; it only states what is known:
//!
//! - **Values named exactly in P** ([`progid_value`]): a `RegValue` candidate with `ChainedRef` to the
//!   owned ProgID and `InPreUninstallRefSnapshot`, both Value scope. The snapshot evidence comes from the
//!   reference snapshot when the harvest recorded the value there, otherwise from the journal when the
//!   journal lists exactly this value name in exactly this key ([`journal_value_evidence`]); the two are
//!   the same harvest, so only one of them is ever attached.
//! - **Skeleton keys** ([`skeleton`]): `OpenWithProgids`, or the whole `.ext` key, that the uninstaller
//!   left empty. A key is a skeleton when the journal shows that only the app's values lived in it and
//!   it is value-free now. What the candidate then carries depends on the baseline
//!   ([`Standing`]): `ProvenOwnedSkeleton` with a baseline of exactly this (edition, build.ubr) that does
//!   not contain the key; the X-SYSTIDY fallback of step 3 without one; the hard blocker
//!   `TrustedInstallerOwned` when the key has a TrustedInstaller owner or ACE.
//!
//! # The X-SYSTIDY fallback
//!
//! The X-SYSTIDY scanner proper (unattributed empty skeletons, opt-in) is an M4 scanner. What is emitted
//! here under its id is only the §5.7.1 step-3 fallback: a skeleton key of this app that cannot be proven
//! "not Windows' own" because no matching baseline is loaded. It carries a Key-scope `ChainedRef` lowered
//! to Tier B, which is band-neutral: enough for the policy to list the key (Likely, unticked), never
//! enough for Safe.
//!
//! # Known limit: an empty `.ext` key that was there before the install
//!
//! A key somebody made before the install is not the app's skeleton, and [`skeleton`] refuses one
//! the harvest found to be older than the install (`ScanCtx::predates_install`, from the key's and
//! its parent's LastWriteTime; `purge-harvest`, `subtree`, "Keys older than the install"). That
//! clock cannot see one case: an **empty** `.ext` key that existed before the install and that the
//! installer then wrote into directly, by setting its default value or by creating
//! `OpenWithProgids` in it. Either write moves the key's time past the start of the install, and
//! the key reads exactly like one the installer created. With a baseline that does not have the
//! key it is offered as `ProvenOwnedSkeleton` and is Safe.
//!
//! This is accepted, not fixed (decided for M1a). The alternative is to take the proof away from
//! every skeleton that rests on the journal alone, which would list every `.ext` key an app made
//! as Likely for the sake of this one. What is at stake is small and bounded by the conditions
//! above: the key is on no clean Windows of this build (it is not in the baseline), it held
//! nothing of anybody else's at harvest (no other value, no other subkey, no other default, no
//! vendor backup) and it is empty now, so deleting it loses a key name and no content. The rig
//! reports such a key as the non-blocking class `old_empty_ext_key`. No cheap signal tells the two
//! cases apart: the registry keeps no creation time, the parent's time only proves age while
//! nothing else was created in `Classes` since, an owner is the same for both on a machine-wide
//! install, and the Inno log records what to delete, not what existed. A record of the machine from
//! before the install (the remembered manifest of a later milestone) would.
//!
//! Without a matching baseline none of this arises: the key is then the X-SYSTIDY fallback above,
//! Tier B, listed and never preselected.
//!
//! # TrustedInstaller on rig snapshots
//!
//! The journal records the owner of the `.ext` key only, and a rig snapshot does not record owners at
//! all (`KeyInfo::ti_owned` is `None`). A key is treated as TrustedInstaller-owned when the journal says
//! so for its extension or when the source says so now for the key or its `OpenWithProgids` child. An
//! owner the source cannot tell is accepted, because the harvest looked at the extension and the key is
//! additionally required to be absent from the baseline.
//!
//! # Grouping
//!
//! A candidate has no fact list of its own, so [`finish`] writes `group = "File associations"` (and the
//! extension) into the detail of every piece of evidence; the UI builds its one group node from it
//! (§5.7.1 step 4).

use purge_guard::prefix;
use purge_index::baseline_view::Absence;
use purge_model::{
    Action, AnchorKind, Blocker, Candidate, Category, Evidence, EvidenceKind, ExtJournalEntry,
    Facts, Scope, Target, Tier,
};
use purge_source::types::{RegValue, SourceError};

use crate::framework::{CandidateBuilder, ScanCtx, app_trust, candidate_id};

/// The UI group every association candidate belongs to.
pub(crate) const GROUP: &str = "File associations";
/// The evidence-detail key of the group.
pub(crate) const GROUP_KEY: &str = "group";
/// The evidence-detail key that says what executing the candidate means beyond its `Action`:
/// [`ACTION_RESTORE`] or [`ACTION_REPORT`].
pub(crate) const ACTION_KEY: &str = "action";
/// The value is to be set back to an earlier default, not deleted.
pub(crate) const ACTION_RESTORE: &str = "restore";
/// The item is shown for information only.
pub(crate) const ACTION_REPORT: &str = "report";
/// The scanner id of the §5.7.1 step-3 fallback (see the module documentation).
pub(crate) const SYSTIDY_ID: &str = "X-SYSTIDY";
/// Name of the subkey that lists the ProgIDs offered for an extension.
pub(crate) const OPEN_WITH_PROGIDS: &str = "OpenWithProgids";
/// Name of the subkey (Classes) or value list (FileExts) that names exes offered for an extension.
pub(crate) const OPEN_WITH_LIST: &str = "OpenWithList";

/// `<key>\<name>`.
pub(crate) fn subkey(key: &str, name: &str) -> String {
    format!("{key}{}{name}", prefix::SEP)
}

/// The ProgID of P that `name` is, exactly (case-insensitively), in P's own spelling.
pub(crate) fn progid_in_p<'a>(ctx: &ScanCtx<'a>, name: &str) -> Option<&'a str> {
    ctx.fp
        .anchors
        .progids
        .iter()
        .map(String::as_str)
        .find(|progid| !progid.is_empty() && prefix::eq_ci(progid, name))
}

/// The file name of a **main** exe of the app that `name` is, unless another installed app has an exe of
/// that name. Only main exes count: helper and library names are shared by many apps.
pub(crate) fn own_exe_name<'a>(ctx: &ScanCtx<'a>, name: &str) -> Option<&'a str> {
    let own = ctx
        .fp
        .exes
        .iter()
        .filter(|exe| exe.main)
        .filter_map(|exe| prefix::leaf(&exe.path))
        .find(|leaf| prefix::eq_ci(leaf, name))?;
    ctx.other_apps
        .claimant(AnchorKind::Exe, name)
        .is_none()
        .then_some(own)
}

/// The Classes root a journal entry's key lies directly under, when the entry is well formed: its key is
/// `<root>\<.ext>` and the root is one of the Classes roots the harvest journals, spelled either way:
/// `HKLM\SOFTWARE\Classes`, `HKU\<SID>_Classes` or `HKU\<SID>\Software\Classes`. Anything else is
/// ignored by the scanners: a key that merely ends in `Classes` somewhere else in the registry is not an
/// extension key, whatever a (remembered, possibly forged) journal says.
pub(crate) fn classes_root(entry: &ExtJournalEntry) -> Option<&str> {
    let leaf = prefix::leaf(&entry.key)?;
    if !entry.ext.starts_with('.') || entry.ext.len() < 2 || !prefix::eq_ci(leaf, &entry.ext) {
        return None;
    }
    let root = prefix::parent(&entry.key)?;
    is_classes_root(root).then_some(root)
}

/// Whether `root` is `HKLM\SOFTWARE\Classes`, `HKU\<SID>_Classes` or `HKU\<SID>\Software\Classes`.
fn is_classes_root(root: &str) -> bool {
    let folded = prefix::fold(root);
    let segments: Vec<&str> = folded.split(prefix::SEP).collect();
    match segments.as_slice() {
        ["hklm", "software", "classes"] => true,
        ["hku", hive] => hive
            .strip_suffix("_classes")
            .is_some_and(|sid| sid.starts_with("s-1-")),
        ["hku", sid, "software", "classes"] => {
            sid.starts_with("s-1-") && !sid.ends_with("_classes")
        }
        _ => false,
    }
}

/// What a key looks like now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyState {
    /// The source proves the key absent.
    Absent,
    /// The key could not be read completely, is a registry link, or is larger than the scan limits:
    /// nothing is concluded from it.
    Unknown,
    /// The key exists and was read completely.
    Present {
        /// Its values.
        values: Vec<RegValue>,
        /// The names of its subkeys.
        subkeys: Vec<String>,
        /// Whether TrustedInstaller owns it or holds an ACE on it, when the source can tell.
        ti_owned: Option<bool>,
    },
}

impl KeyState {
    /// The key exists and holds neither a value nor a subkey.
    pub(crate) fn is_empty(&self) -> bool {
        matches!(self, Self::Present { values, subkeys, .. } if values.is_empty() && subkeys.is_empty())
    }

    /// The source says the key is TrustedInstaller-owned.
    fn ti_owned(&self) -> bool {
        matches!(
            self,
            Self::Present {
                ti_owned: Some(true),
                ..
            }
        )
    }

    /// The values of a present key; none otherwise.
    pub(crate) fn values(&self) -> &[RegValue] {
        match self {
            Self::Present { values, .. } => values,
            _ => &[],
        }
    }

    /// The subkey names of a present key; none otherwise.
    pub(crate) fn subkeys(&self) -> &[String] {
        match self {
            Self::Present { subkeys, .. } => subkeys,
            _ => &[],
        }
    }
}

/// Reads `key`. A key whose listing disagrees with its own counts is [`KeyState::Unknown`]: a value or
/// subkey the source knows of but did not return must not make the key look empty.
pub(crate) fn key_state(ctx: &ScanCtx<'_>, key: &str) -> KeyState {
    let info = match ctx.reg.key_info(key) {
        Ok(info) => info,
        Err(SourceError::NotFound) => return KeyState::Absent,
        Err(_) => return KeyState::Unknown,
    };
    if info.is_link {
        return KeyState::Unknown;
    }
    let (Ok(values), Ok(subkeys)) = (ctx.reg.values(key), ctx.reg.subkeys(key)) else {
        return KeyState::Unknown;
    };
    let counts_agree = usize::try_from(info.n_values).is_ok_and(|n| n == values.len())
        && usize::try_from(info.n_subkeys).is_ok_and(|n| n == subkeys.len());
    if !counts_agree || values.len() + subkeys.len() > ctx.limits.max_key_children {
        return KeyState::Unknown;
    }
    KeyState::Present {
        values,
        subkeys,
        ti_owned: info.ti_owned,
    }
}

/// The complete text of a string value, trimmed; `None` for other types and for data a snapshot cut
/// short.
pub(crate) fn complete_string(value: &RegValue) -> Option<String> {
    if !value.data.is_complete() {
        return None;
    }
    value.data.string().map(|s| s.trim().to_owned())
}

/// **A.** The name (`<edition>-<build>.<ubr>`) of the exact baseline of this Windows, when the scan's
/// view is that: the only view whose absence is proof. The machine as it is now decides; the
/// fingerprint's record of it is the fallback.
pub(crate) fn matching_baseline(ctx: &ScanCtx<'_>) -> Option<String> {
    ctx.matching_exact_baseline()
}

/// `InPreUninstallRefSnapshot` from the extension journal: the harvest listed the value `name` of `key`
/// as one naming `progid`. The caller has checked that the journal really lists exactly this value.
pub(crate) fn journal_value_evidence(
    ctx: &ScanCtx<'_>,
    key: &str,
    name: &str,
    progid: &str,
) -> Option<Evidence> {
    Evidence::new(
        EvidenceKind::InPreUninstallRefSnapshot,
        Scope::Value,
        app_trust(ctx.fp),
        format!("extjournal:{key}|{name}"),
    )
    .map(|e| e.with_detail(Facts::new().with("anchor", progid)))
}

/// Finishes a candidate: puts `extra` evidence in front of the builder's, then writes the group and `facts` into the detail of
/// every piece of evidence (never replacing a detail that is already there). `None` when the candidate
/// has no positive evidence at all: such an item is not the handler's to offer.
pub(crate) fn finish(
    builder: CandidateBuilder<'_>,
    extra: impl IntoIterator<Item = Evidence>,
    facts: &Facts,
) -> Option<Candidate> {
    // Evidence from the journal goes first: it is the record the candidate rests on. It is added
    // before the candidate is finished, so that `CandidateBuilder::build` judges all of it.
    let mut builder = builder;
    builder.evidence_first(extra);
    let mut candidate = builder.build();
    if !candidate.evidence.iter().any(|e| e.weight > 0) {
        return None;
    }
    for evidence in &mut candidate.evidence {
        let detail = &mut evidence.detail.0;
        detail
            .entry(GROUP_KEY.to_owned())
            .or_insert_with(|| GROUP.to_owned());
        for (key, value) in &facts.0 {
            detail.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }
    Some(candidate)
}

/// The candidate for a value named exactly by a ProgID of P (an `OpenWithProgids` value, a toast value):
/// delete the value.
///
/// `journal_listed` says that the extension journal lists exactly this value name for exactly this key;
/// it then stands in for a missing reference-snapshot entry. Without either, the value has only the
/// `ChainedRef` to the owned ProgID and stays below Safe.
pub(crate) fn progid_value(
    ctx: &ScanCtx<'_>,
    scanner: &str,
    key: &str,
    name: &str,
    progid: &str,
    journal_listed: bool,
    facts: &Facts,
) -> Option<Candidate> {
    let target = Target::RegValue {
        path: key.to_owned(),
        name: name.to_owned(),
    };
    let mut builder = ctx.candidate(scanner, target, Action::DeleteValue, Category::Association);
    let in_snapshot = builder.in_ref_snapshot();
    builder.chained_ref(Tier::A, progid);
    builder.common_blockers();
    if let Some(blocker) = ctx.other_apps.anchor_blocker(AnchorKind::ProgId, progid) {
        builder.blocker(blocker);
    }
    let journal = (!in_snapshot && journal_listed)
        .then(|| journal_value_evidence(ctx, key, name, progid))
        .flatten();
    finish(builder, journal, &facts.clone().with("progid", progid))
}

/// The candidate for a key named after one of the app's exes (`OpenWithList\<exe>`), for every such
/// subkey of `list_key`. A bare exe name says nothing about the directory, so the `ChainedRef` is Tier B.
pub(crate) fn exe_named_subkeys(
    ctx: &ScanCtx<'_>,
    scanner: &str,
    list_key: &str,
    facts: &Facts,
) -> Vec<Candidate> {
    let state = key_state(ctx, list_key);
    let mut out = Vec::new();
    for name in state.subkeys() {
        let Some(exe) = own_exe_name(ctx, name) else {
            continue;
        };
        let key = subkey(list_key, name);
        let inside = key_state(ctx, &key);
        let target = Target::RegKey { path: key };
        let mut builder = ctx.candidate(scanner, target, Action::DeleteKey, Category::Association);
        builder.chained_ref(Tier::B, exe);
        builder.common_blockers();
        if let KeyState::Present {
            values, subkeys, ..
        } = &inside
        {
            builder.child_count(u32::try_from(values.len() + subkeys.len()).unwrap_or(u32::MAX));
        }
        out.extend(finish(builder, None, &facts.clone().with("exe", exe)));
    }
    out
}

// ---------------------------------------------------------------------------------------------------------
// Skeletons
// ---------------------------------------------------------------------------------------------------------

/// What can be said about a skeleton key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Standing {
    /// A baseline of exactly this (edition, build.ubr) is loaded and has neither the key nor its
    /// remaining child: `ProvenOwnedSkeleton`.
    Proven {
        /// The baseline's name.
        baseline: String,
    },
    /// No matching baseline: the X-SYSTIDY fallback (§5.7.1 step 3).
    NoBaseline,
    /// The key has a TrustedInstaller owner or ACE: never deleted.
    TrustedInstaller,
}

/// An empty key the uninstaller left behind for one extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Skeleton {
    /// The key to remove: the `.ext` key or its `OpenWithProgids`.
    pub(crate) key: String,
    /// The still-present `OpenWithProgids` child a whole-`.ext` skeleton takes with it.
    pub(crate) child: Option<String>,
    /// What the candidate may claim.
    pub(crate) standing: Standing,
}

/// The standing of a skeleton made of `keys` as far as the baseline goes; `None` when a matching
/// baseline has one of the keys, or cannot speak about one, so that no key candidate is offered.
fn baseline_standing(ctx: &ScanCtx<'_>, keys: &[&str]) -> Option<Standing> {
    // A: below Exact this is the no-baseline standing, whatever the view infers.
    let Some(name) = matching_baseline(ctx) else {
        return Some(Standing::NoBaseline);
    };
    if keys
        .iter()
        .any(|key| !matches!(ctx.key_absence(key), Absence::Proven))
    {
        return None;
    }
    Some(Standing::Proven { baseline: name })
}

/// The skeleton of `entry`'s extension, if there is one (§5.7.1 step 2, second and third bullet).
///
/// `OpenWithProgids` is a skeleton when it is empty now and the journal shows only the app's values in
/// it. The `.ext` key is one when the same holds for its whole subtree: at harvest it held nothing but
/// `OpenWithProgids` with the app's values and, at most, a default naming a ProgID of P; now it holds no
/// value and nothing but an empty `OpenWithProgids`. The larger key wins. When a matching baseline has
/// the `.ext` key (the extension is Windows' own), only `OpenWithProgids` can still qualify.
pub(crate) fn skeleton(
    ctx: &ScanCtx<'_>,
    entry: &ExtJournalEntry,
    ext_state: &KeyState,
    owp_state: &KeyState,
) -> Option<Skeleton> {
    let only_ours = !entry.openwith_ours.is_empty()
        && entry.openwith_others.is_empty()
        && entry
            .openwith_ours
            .iter()
            .all(|name| progid_in_p(ctx, name).is_some());
    if !only_ours {
        return None;
    }
    let owp_key = subkey(&entry.key, OPEN_WITH_PROGIDS);
    // A key somebody made before the install is no skeleton of the app, although the app's value
    // was the only thing in it (rig run x1-vscode-userstate: the user's empty
    // `.gemspec\OpenWithProgids`). The harvest marks `OpenWithProgids` as older when it or the
    // extension key is; then neither key qualifies.
    if ctx.predates_install(&owp_key) {
        return None;
    }
    let owp_empty = owp_state.is_empty();
    let ti = entry.ti_owned || ext_state.ti_owned() || owp_state.ti_owned();
    let with_ti = |standing: Standing| {
        if ti {
            Standing::TrustedInstaller
        } else {
            standing
        }
    };

    let default_is_ours = entry
        .default
        .as_deref()
        .is_none_or(|d| d.trim().is_empty() || progid_in_p(ctx, d.trim()).is_some());
    let ext_was_ours = entry.other_values.is_empty()
        && entry.other_subkeys.is_empty()
        && entry.subkey_count <= 1
        && entry.vendor_backup.is_none()
        && entry.previous_default.is_none()
        && default_is_ours;
    let ext_is_bare = match ext_state {
        KeyState::Present {
            values, subkeys, ..
        } => {
            values.is_empty()
                && match subkeys.as_slice() {
                    [] => *owp_state == KeyState::Absent,
                    [only] => prefix::eq_ci(only, OPEN_WITH_PROGIDS) && owp_empty,
                    _ => false,
                }
        }
        _ => false,
    };

    if ext_was_ours && ext_is_bare && !ctx.predates_install(&entry.key) {
        let child = owp_empty.then(|| owp_key.clone());
        let mut keys = vec![entry.key.as_str()];
        keys.extend(child.as_deref());
        if let Some(standing) = baseline_standing(ctx, &keys) {
            return Some(Skeleton {
                key: entry.key.clone(),
                child,
                standing: with_ti(standing),
            });
        }
    }
    if owp_empty {
        let standing = baseline_standing(ctx, &[owp_key.as_str()])?;
        return Some(Skeleton {
            key: owp_key,
            child: None,
            standing: with_ti(standing),
        });
    }
    None
}

/// The candidate for a [`Skeleton`]: delete the key. `scanner` is the id used when the key is proven or
/// blocked; the no-baseline fallback always goes out under [`SYSTIDY_ID`].
pub(crate) fn skeleton_candidate(
    ctx: &ScanCtx<'_>,
    scanner: &str,
    entry: &ExtJournalEntry,
    skeleton: &Skeleton,
    facts: &Facts,
) -> Option<Candidate> {
    // `skeleton` guarantees a journal value; it is the ProgID the fallback chains to.
    let anchor = entry
        .openwith_ours
        .iter()
        .find_map(|name| progid_in_p(ctx, name))?;
    let scanner = match skeleton.standing {
        Standing::NoBaseline => SYSTIDY_ID,
        Standing::Proven { .. } | Standing::TrustedInstaller => scanner,
    };
    let target = Target::RegKey {
        path: skeleton.key.clone(),
    };
    let mut builder = ctx.candidate(scanner, target, Action::DeleteKey, Category::Association);
    let mut facts = facts.clone();
    let mut proof = None;
    match &skeleton.standing {
        Standing::Proven { baseline } => {
            let detail = Facts::new()
                .with("key", skeleton.key.clone())
                .with("via", "ext-journal")
                .with("baseline", baseline.clone());
            proof = Evidence::new(
                EvidenceKind::ProvenOwnedSkeleton,
                Scope::Key,
                app_trust(ctx.fp),
                format!("extjournal:{}", entry.key),
            )
            .map(|e| e.with_detail(detail));
        }
        Standing::NoBaseline => {
            builder.chained_ref(Tier::B, anchor);
            facts = facts.with("skeleton", "no-baseline");
        }
        Standing::TrustedInstaller => {
            builder.chained_ref(Tier::B, anchor);
            builder.blocker(Blocker::TrustedInstallerOwned);
        }
    }
    builder.common_blockers();
    // A ProgID another installed app claims as well: the key is not this app's alone to remove.
    for name in &entry.openwith_ours {
        if let Some(blocker) = ctx.other_apps.anchor_blocker(AnchorKind::ProgId, name) {
            builder.blocker(blocker);
        }
    }
    match &skeleton.child {
        Some(child) => {
            let id = candidate_id(&Target::RegKey {
                path: child.clone(),
            });
            builder.child(id).child_count(1);
        }
        None => {
            builder.child_count(0);
        }
    }
    finish(builder, proof, &facts)
}
