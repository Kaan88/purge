//! Plan input: hash binding, selection, resolve to exec ops (M2-X-EXEC; ENGINE_PLAN.md §7.1).
//!
//! [`bind`] turns an [`ExecRequest`] (the scan document of a plan, the confirm hash the user's consent
//! produced, and the selection) into a [`BoundPlan`]: the selected items in plan order, each with its op
//! id and the executor op it resolved to. It reads nothing from the system and changes nothing, so every
//! refusal ([`PlanRefusal`]) comes before a session exists.
//!
//! # What is checked, in this order
//!
//! 1. **The plan is the one that was hashed.** `scan.plan_hash` is 64 lower-case hex digits and equals
//!    `purge_plan::hash::plan_hash(items, policy_version, mode)` recomputed here. The hash covers the
//!    order, target, action, band, preselection, scanner, category, id and child ids of every item.
//! 2. **Ids are unique** over the top-level items and the absorbed children.
//! 3. **Absorbed children ride with their parent.** Every id in an item's `children` names a candidate
//!    in `scan.absorbed` whose target nests in the parent's (`purge_plan::collapse::nests_in`).
//! 4. **Selection.** [`Selection::Preselected`] is every item in band Safe that the plan preselected.
//!    [`Selection::Ids`] may add Likely and Weak items; empty ids are dropped and repeated ids count
//!    once; an id that names no top-level item (unknown, or an absorbed child) is refused. No selected
//!    item may be undecided, in the Blocked band, carry a hard blocker, be report-only, or have a target
//!    and action that resolve to no executor op. The one exception is a service, scheduled task or
//!    firewall rule without its scan-time digest (`Candidate::object_fp`, `Mismatch::NoObjectFp`): it may
//!    be selected and is journalled as skipped (`ChangedSinceScan`) before any backup
//!    ([`BoundItem::exec_op`] is `None`). A selected whole-tree removal must not
//!    hold a protected plan item below it (`purge_guard::live::check_protected_descendants`). An empty
//!    selection is refused.
//! 5. **Order.** For any two selected items where one nests in the other, the inner one comes first.
//! 6. **Confirmation.** The request's confirm hash equals [`confirm_hash`] of the plan hash and the
//!    [`selection_hash`] of the selected ids.
//!
//! # The confirm recipe
//!
//! ```text
//! selection_hash = SHA-256( ids, de-duplicated, sorted ordinally (by UTF-16 code unit), joined with "\n", as UTF-8 )
//! confirm        = SHA-256( lower-case hex of plan_hash  ||  lower-case hex of selection_hash, as UTF-8 text )
//! ```
//!
//! Both are written as 64 lower-case hex digits. This is byte for byte the recipe of the VM rig
//! (`vm/guest/riglib.ps1`, `Get-M2SelectionHash` and `Get-M2Confirm`). Fixed vector:
//!
//! ```text
//! ids            = c-2, c-10, c-1, c-2          (sorted and de-duplicated: c-1, c-10, c-2)
//! selection_hash = 2f2400bd148f06ab24831566736224e0608bbd75547ce869857bd1f5d3d53901
//! plan_hash      = 10e9da8690be9214c32b5379a6688586b78ff5b221b3877b2f59cfefc3f149b2
//! confirm        = 005cd48e39de487e9536e5ab5ff917582763f70d7c04a5614db1d7f57aa43788
//! ```

use std::collections::{BTreeMap, BTreeSet};

use purge_guard::live;
use purge_model::ObjectKind;
use purge_model::exec::journal::{RestorePointPolicy, RunSettings};
use purge_model::exec::op::{ExecOp, Mismatch, OpId, Sha256Hex, resolve};
use purge_model::{Action, Band, Blocker, Candidate, CandidateId};
use purge_plan::collapse::nests_in;
use purge_plan::emit::ScanDoc;

use crate::journal::{JournalState, sha256_bytes};
use crate::prepare::RestorePointSetting;
use crate::regbackup;

#[cfg(test)]
pub(crate) mod tests;

/// Which items of the plan to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// Every item in band Safe that the plan preselected.
    Preselected,
    /// Exactly these top-level items (Safe, Likely or Weak).
    Ids(Vec<CandidateId>),
}

/// The settings of one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecSettings {
    /// When to ask for a restore point.
    pub restore_point: RestorePointSetting,
    /// The SID of the user the scan ran for, as the scan gave it to `purge_plan::decide`.
    pub user_sid: Option<String>,
    /// Whether the scan resolved 8.3 names, as the scan gave it to `purge_plan::decide`.
    pub long_names_resolved: bool,
    /// The most keys a registry tree may hold to be deleted ([`regbackup::DEFAULT_KEY_LIMIT`]).
    pub key_limit: usize,
    /// The roots of the app the plan removes leftovers of (its fingerprint's install roots), for the
    /// journal header (`Header::program_roots`): a service, task or firewall rule whose program is not
    /// inside one is neither deleted nor created again. The header records them only when the run
    /// selects an object op; a resumed run reads them from the header. Empty refuses every object
    /// delete (fail closed).
    pub program_roots: Vec<String>,
    /// The M1b exemption lists of the run ([`GoneLists`]), journalled in the `settings` record. Empty
    /// keeps every exemption they open closed.
    pub gone: GoneLists,
}

impl Default for ExecSettings {
    fn default() -> ExecSettings {
        ExecSettings {
            restore_point: RestorePointSetting::default(),
            user_sid: None,
            long_names_resolved: true,
            key_limit: regbackup::DEFAULT_KEY_LIMIT,
            program_roots: Vec::new(),
            gone: GoneLists::default(),
        }
    }
}

/// The M1b exemption lists of a run (C-GUARD): the gone MSI products, Package Cache directories and Burn
/// bundles and packages of the app, as `purge_plan::decide::M1bDecide` computes them from the
/// fingerprint and fresh system queries. The caller of a run computes them when the run starts (never
/// from the plan); the run journals them in its `settings` record, and the act-time gate, undo and
/// recovery take them from there (`GateCtx::set_gone`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoneLists {
    /// Packed codes of MSI products Windows Installer knows in no context.
    pub msi_products: Vec<String>,
    /// Package Cache directories of gone bundles and packages.
    pub cache_dirs: Vec<String>,
    /// Bundle ids and provider keys of gone Burn bundles and packages.
    pub burn: Vec<String>,
}

impl GoneLists {
    /// The lists of `decide`.
    pub fn from_decide(decide: &purge_plan::decide::M1bDecide) -> GoneLists {
        GoneLists {
            msi_products: decide.gone_msi_products().to_vec(),
            cache_dirs: decide.gone_cache_dirs().to_vec(),
            burn: decide.gone_burn().to_vec(),
        }
    }

    /// The lists a journal's `settings` record holds.
    pub fn from_journal(settings: &RunSettings) -> GoneLists {
        GoneLists {
            msi_products: settings.gone_msi_products.clone(),
            cache_dirs: settings.gone_cache_dirs.clone(),
            burn: settings.gone_burn.clone(),
        }
    }

    /// Whether all three lists are empty.
    pub fn is_empty(&self) -> bool {
        self.msi_products.is_empty() && self.cache_dirs.is_empty() && self.burn.is_empty()
    }
}

impl ExecSettings {
    /// The journal form of the settings, for the run's `settings` record (written right after the
    /// header). [`ExecSettings::from_journal`] is the exact inverse. The selected ids are not settings:
    /// the run fills them in.
    pub fn to_journal(&self) -> RunSettings {
        RunSettings {
            selected: Vec::new(),
            user_sid: self.user_sid.clone(),
            long_names_resolved: self.long_names_resolved,
            key_limit: u64::try_from(self.key_limit).unwrap_or(u64::MAX),
            restore_point: match self.restore_point {
                RestorePointSetting::Off => RestorePointPolicy::Off,
                RestorePointSetting::HighRiskOnly => RestorePointPolicy::HighRiskOnly,
                RestorePointSetting::Always => RestorePointPolicy::Always,
            },
            gone_msi_products: self.gone.msi_products.clone(),
            gone_cache_dirs: self.gone.cache_dirs.clone(),
            gone_burn: self.gone.burn.clone(),
        }
    }

    /// The settings a journal's `settings` record holds: what a resumed run works with, instead of
    /// settings its caller supplies.
    pub fn from_journal(settings: &RunSettings) -> ExecSettings {
        ExecSettings {
            restore_point: match settings.restore_point {
                RestorePointPolicy::Off => RestorePointSetting::Off,
                RestorePointPolicy::HighRiskOnly => RestorePointSetting::HighRiskOnly,
                RestorePointPolicy::Always => RestorePointSetting::Always,
            },
            user_sid: settings.user_sid.clone(),
            long_names_resolved: settings.long_names_resolved,
            key_limit: usize::try_from(settings.key_limit).unwrap_or(usize::MAX),
            // The header's, which `Run::resume` fills in.
            program_roots: Vec::new(),
            gone: GoneLists::from_journal(settings),
        }
    }
}

/// Everything a run is asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    /// The scan document of the plan (`plan.scan.json`).
    pub scan: ScanDoc,
    /// The confirm hash the consent produced ([`confirm_hash`]), 64 lower-case hex digits.
    pub confirm: String,
    /// Which items to act on.
    pub selection: Selection,
    /// Whether the user acknowledged that selected removals without an undo (packages) are final.
    pub allow_irreversible: bool,
    /// The settings of the run.
    pub settings: ExecSettings,
}

/// Why a selected item may not be acted on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotSelectable {
    /// The plan never decided the item.
    Undecided,
    /// The item is in the Blocked band.
    Blocked,
    /// The item carries a hard blocker.
    HardBlocker(Blocker),
    /// The item is report-only.
    ReportOnly,
    /// The item's target and action resolve to no executor op.
    Unresolvable(Mismatch),
    /// A protected plan item lies below this whole-tree removal.
    ProtectedDescendant(Blocker),
}

impl std::fmt::Display for NotSelectable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotSelectable::Undecided => f.write_str("the plan never decided it"),
            NotSelectable::Blocked => f.write_str("it is in the Blocked band"),
            NotSelectable::HardBlocker(blocker) => write!(f, "it is blocked: {blocker:?}"),
            NotSelectable::ReportOnly => f.write_str("it is report-only"),
            NotSelectable::Unresolvable(mismatch) => write!(f, "{mismatch}"),
            NotSelectable::ProtectedDescendant(blocker) => {
                write!(f, "a protected plan item lies below it: {blocker:?}")
            }
        }
    }
}

/// Why a request was refused. Nothing was read from the system or changed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanRefusal {
    /// `scan.plan_hash` is not 64 lower-case hex digits.
    #[error("the plan hash {0:?} is not 64 lower-case hex digits")]
    PlanHashForm(String),
    /// The scan document is not the one its plan hash was computed over.
    #[error(
        "the plan was changed after it was hashed: it states {stated}, its items hash to {computed}"
    )]
    PlanHashMismatch {
        /// The hash the document states.
        stated: String,
        /// The hash of its items.
        computed: String,
    },
    /// Two candidates of the document share an id.
    #[error("candidate id {} appears more than once in the plan", .0.0)]
    DuplicateId(CandidateId),
    /// An item lists a child that is not among the absorbed candidates.
    #[error("item {} lists child {} that the plan does not hold", .parent.0, .child.0)]
    ChildMissing {
        /// The absorbing item.
        parent: CandidateId,
        /// The listed child.
        child: CandidateId,
    },
    /// An item lists a child whose target is not inside its own.
    #[error("child {} of item {} does not lie inside it", .child.0, .parent.0)]
    ChildOutside {
        /// The absorbing item.
        parent: CandidateId,
        /// The listed child.
        child: CandidateId,
    },
    /// A selected id names no item of the plan.
    #[error("selected id {} is not an item of the plan", .0.0)]
    UnknownId(CandidateId),
    /// A selected id names an absorbed child, which only rides with its parent.
    #[error("selected id {} is an absorbed child; select its parent", .0.0)]
    AbsorbedSelected(CandidateId),
    /// A selected item may not be acted on.
    #[error("item {} cannot be selected: {why}", .id.0)]
    NotSelectable {
        /// The item.
        id: CandidateId,
        /// Why.
        why: NotSelectable,
    },
    /// Nothing is selected.
    #[error("nothing is selected")]
    EmptySelection,
    /// A selected item comes before a selected item inside it.
    #[error("item {} comes before item {} that lies inside it; the plan order is wrong", .outer.0, .inner.0)]
    Order {
        /// The item inside.
        inner: CandidateId,
        /// The item around it.
        outer: CandidateId,
    },
    /// The confirm hash is not 64 lower-case hex digits.
    #[error("the confirm hash is not 64 lower-case hex digits")]
    ConfirmForm,
    /// The confirm hash is not the one of this plan and this selection.
    #[error("the confirmation does not match this plan and selection")]
    ConfirmMismatch,
    /// More items are selected than a session can number.
    #[error("{0} items are selected, more than a session can hold")]
    TooManyItems(usize),
    /// A journal does not belong to this scan document (resume only).
    #[error("the journal does not belong to this plan: {0}")]
    JournalMismatch(String),
}

/// One selected item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundItem {
    /// Its op id in the session: 1 for the first selected item in plan order, and so on.
    pub op: OpId,
    /// Its index in `scan.items`.
    pub index: usize,
    /// The executor op it resolved to; `None` for a service, scheduled task or firewall rule without its
    /// scan-time digest, which the run journals as skipped.
    pub exec_op: Option<ExecOp>,
}

/// A request that passed every check of [`bind`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundPlan {
    scan: ScanDoc,
    plan_hash: Sha256Hex,
    selection_hash: Sha256Hex,
    items: Vec<BoundItem>,
    allow_irreversible: bool,
}

impl BoundPlan {
    /// The scan document.
    pub fn scan(&self) -> &ScanDoc {
        &self.scan
    }

    /// The plan hash.
    pub fn plan_hash(&self) -> Sha256Hex {
        self.plan_hash
    }

    /// The hash of the selected ids ([`selection_hash`]).
    pub fn selection_hash(&self) -> Sha256Hex {
        self.selection_hash
    }

    /// The selected items in plan order (op order).
    pub fn items(&self) -> &[BoundItem] {
        &self.items
    }

    /// The selected item with op id `op`.
    pub fn item(&self, op: OpId) -> Option<&BoundItem> {
        let index = usize::try_from(op.0).ok()?.checked_sub(1)?;
        self.items.get(index).filter(|item| item.op == op)
    }

    /// The plan's candidate of a selected item.
    pub fn candidate(&self, item: &BoundItem) -> Option<&Candidate> {
        self.scan.items.get(item.index)
    }

    /// The candidates absorbed by `parent`, in the order its `children` lists them.
    pub fn children<'a>(&'a self, parent: &'a Candidate) -> impl Iterator<Item = &'a Candidate> {
        parent
            .children
            .iter()
            .filter_map(|id| self.scan.absorbed.iter().find(|c| &c.id == id))
    }

    /// Whether the user acknowledged removals without an undo.
    pub fn allow_irreversible(&self) -> bool {
        self.allow_irreversible
    }

    /// The executor ops of the selected items, in op order (items without one left out).
    pub fn exec_ops(&self) -> Vec<ExecOp> {
        self.items
            .iter()
            .filter_map(|item| item.exec_op.clone())
            .collect()
    }
}

/// The hash of a selection: SHA-256 of the ids, empty ones dropped, de-duplicated, sorted ordinally (by
/// UTF-16 code unit, as .NET's `StringComparer.Ordinal` sorts) and joined with `\n`, as UTF-8. See the
/// module docs for a fixed vector.
pub fn selection_hash<'a>(ids: impl IntoIterator<Item = &'a CandidateId>) -> Sha256Hex {
    let unique: BTreeSet<&str> = ids
        .into_iter()
        .map(|id| id.0.as_str())
        .filter(|id| !id.is_empty())
        .collect();
    let mut sorted: Vec<&str> = unique.into_iter().collect();
    sorted.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    sha256_bytes(sorted.join("\n").as_bytes())
}

/// The confirm hash of a plan and a selection: SHA-256 over the UTF-8 text of the plan hash followed by
/// the selection hash, both as lower-case hex. See the module docs for a fixed vector.
pub fn confirm_hash(plan_hash: Sha256Hex, selection_hash: Sha256Hex) -> Sha256Hex {
    sha256_bytes(format!("{plan_hash}{selection_hash}").as_bytes())
}

/// Checks `request` (see the module docs) and returns the selected items in plan order. Pure: reads and
/// changes nothing.
pub fn bind(request: &ExecRequest) -> Result<BoundPlan, PlanRefusal> {
    let scan = &request.scan;
    let plan_hash = check_plan_hash(scan)?;
    check_structure(scan)?;
    let selected = select(scan, &request.selection)?;
    let items = bind_items(scan, &selected)?;
    check_order(scan, &items)?;
    let selection_hash = selection_hash(items.iter().map(|item| &scan.items[item.index].id));
    let confirm: Sha256Hex = request
        .confirm
        .parse()
        .map_err(|_| PlanRefusal::ConfirmForm)?;
    if confirm != confirm_hash(plan_hash, selection_hash) {
        return Err(PlanRefusal::ConfirmMismatch);
    }
    Ok(BoundPlan {
        scan: scan.clone(),
        plan_hash,
        selection_hash,
        items,
        allow_irreversible: request.allow_irreversible,
    })
}

/// The bound plan of a session that already has a journal, for resuming it: `scan` is the session's copy
/// of the scan document and `state` what its journal says. The confirmation was checked when the run
/// started; here the document must hash to the header's plan hash, the validated ops must name
/// top-level items of it with the same targets, in plan order, and their ids must hash to the header's
/// selection hash. The items are checked as [`bind`] checks a selection.
pub fn rebind(scan: &ScanDoc, state: &JournalState) -> Result<BoundPlan, PlanRefusal> {
    let mismatch = |text: String| PlanRefusal::JournalMismatch(text);
    let header = state.header();
    let plan_hash = check_plan_hash(scan)?;
    if plan_hash != header.plan_hash {
        return Err(mismatch(format!(
            "the journal names plan {}, the document hashes to {plan_hash}",
            header.plan_hash
        )));
    }
    check_structure(scan)?;
    let ids: Vec<CandidateId> = state.ops().map(|op| op.item.clone()).collect();
    let selected = select(scan, &Selection::Ids(ids.clone()))?;
    let items = bind_items(scan, &selected)?;
    check_order(scan, &items)?;
    if items.len() != ids.len() {
        return Err(mismatch("an item is journalled twice".into()));
    }
    for (item, op) in items.iter().zip(state.ops()) {
        let candidate = &scan.items[item.index];
        if item.op != op.op || candidate.id != op.item || candidate.target != op.target {
            return Err(mismatch(format!(
                "op {} is not item {} of the document",
                op.op, op.item.0
            )));
        }
    }
    let selection_hash = selection_hash(&ids);
    if selection_hash != header.selection_hash {
        return Err(mismatch(
            "the journalled ops do not hash to the header's selection hash".into(),
        ));
    }
    Ok(BoundPlan {
        scan: scan.clone(),
        plan_hash,
        selection_hash,
        items,
        allow_irreversible: header.allow_irreversible,
    })
}

/// How many selections [`rebind_interrupted`] hashes at most before it gives up.
pub const MAX_SELECTION_TRIES: u64 = 1 << 16;

/// The bound plan of a session whose run stopped before every selected item was validated (a crash
/// at the journal header or in the validate pass), for resuming it: as [`rebind`] when every item has
/// its `validated` record.
///
/// The journal's `settings` record holds the selected ids in op order (`RunSettings::selected`): the
/// selection is bound from them as [`bind`] binds one, and they must be the header's number of items,
/// hash to the header's selection hash, and begin with the journalled ops (same ids and targets).
///
/// A journal written before the settings record held the ids is read as before: the header's item
/// count and selection hash, and the `validated` records written so far, which are the first
/// selected items in plan order. The rest of the selection is found again: the items that complete
/// it are selectable top-level items after the last validated one, and the selection is the one, of
/// that count, whose ids hash to the header's selection hash. At most [`MAX_SELECTION_TRIES`]
/// selections are hashed, in plan order; a selection not found among them refuses the resume
/// ([`PlanRefusal::JournalMismatch`]), and nothing is guessed.
pub fn rebind_interrupted(scan: &ScanDoc, state: &JournalState) -> Result<BoundPlan, PlanRefusal> {
    let header = state.header();
    if state.validated_count() == header.items {
        return rebind(scan, state);
    }
    let mismatch = |text: &str| PlanRefusal::JournalMismatch(text.to_owned());
    let plan_hash = check_plan_hash(scan)?;
    if plan_hash != header.plan_hash {
        return Err(PlanRefusal::JournalMismatch(format!(
            "the journal names plan {}, the document hashes to {plan_hash}",
            header.plan_hash
        )));
    }
    check_structure(scan)?;
    if let Some(selected) = state
        .settings()
        .map(|settings| settings.selected.as_slice())
        .filter(|selected| !selected.is_empty())
    {
        return rebind_selected(scan, state, plan_hash, selected);
    }
    let known: Vec<CandidateId> = state.ops().map(|op| op.item.clone()).collect();
    let total = usize::try_from(header.items).map_err(|_| mismatch("too many items"))?;
    let missing = total
        .checked_sub(known.len())
        .ok_or_else(|| mismatch("the journal holds more validated records than items"))?;
    let top: BTreeMap<&CandidateId, usize> = scan
        .items
        .iter()
        .enumerate()
        .map(|(index, c)| (&c.id, index))
        .collect();
    let mut prefix = Vec::with_capacity(total);
    for (op, id) in state.ops().zip(&known) {
        let index = *top.get(id).filter(|_| !id.0.is_empty()).ok_or_else(|| {
            PlanRefusal::JournalMismatch(format!("op {} names no top-level item", op.op))
        })?;
        if prefix.last().is_some_and(|last| *last >= index) || scan.items[index].target != op.target
        {
            return Err(PlanRefusal::JournalMismatch(format!(
                "op {} is not item {} of the document",
                op.op, op.item.0
            )));
        }
        prefix.push(index);
    }
    let start = prefix.last().map_or(0, |last| last + 1);
    let pool: Vec<usize> = (start..scan.items.len())
        .filter(|&index| {
            let candidate = &scan.items[index];
            !candidate.id.0.is_empty() && selectable(scan, candidate).is_ok()
        })
        .collect();
    let chosen = find_selection(&pool, missing, |rest| {
        let ids = known
            .iter()
            .chain(rest.iter().map(|&index| &scan.items[index].id));
        selection_hash(ids) == header.selection_hash
    })
    .ok_or_else(|| {
        mismatch("the rest of the selection cannot be found from the header's selection hash")
    })?;
    prefix.extend(chosen);
    let items = bind_items(scan, &prefix)?;
    check_order(scan, &items)?;
    Ok(BoundPlan {
        scan: scan.clone(),
        plan_hash,
        selection_hash: header.selection_hash,
        items,
        allow_irreversible: header.allow_irreversible,
    })
}

/// [`rebind_interrupted`] of a journal whose settings record holds the selected ids in op order.
fn rebind_selected(
    scan: &ScanDoc,
    state: &JournalState,
    plan_hash: Sha256Hex,
    selected: &[CandidateId],
) -> Result<BoundPlan, PlanRefusal> {
    let mismatch = |text: String| PlanRefusal::JournalMismatch(text);
    let header = state.header();
    let chosen = select(scan, &Selection::Ids(selected.to_vec()))?;
    let items = bind_items(scan, &chosen)?;
    check_order(scan, &items)?;
    let ids: Vec<&CandidateId> = items
        .iter()
        .filter_map(|item| scan.items.get(item.index).map(|c| &c.id))
        .collect();
    if !ids.iter().copied().eq(selected) || u32::try_from(ids.len()).ok() != Some(header.items) {
        return Err(mismatch(
            "the journalled selection is not the header's items in plan order".into(),
        ));
    }
    if selection_hash(selected) != header.selection_hash {
        return Err(mismatch(
            "the journalled selection does not hash to the header's selection hash".into(),
        ));
    }
    for op in state.ops() {
        let item = usize::try_from(op.op.0)
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|position| items.get(position))
            .and_then(|item| scan.items.get(item.index));
        if !item.is_some_and(|c| c.id == op.item && c.target == op.target) {
            return Err(mismatch(format!(
                "op {} is not item {} of the document",
                op.op, op.item.0
            )));
        }
    }
    Ok(BoundPlan {
        scan: scan.clone(),
        plan_hash,
        selection_hash: header.selection_hash,
        items,
        allow_irreversible: header.allow_irreversible,
    })
}

/// The first `count` elements of `pool` (as a combination, in order) that `fits`, trying at most
/// [`MAX_SELECTION_TRIES`] combinations in lexicographic order.
fn find_selection(
    pool: &[usize],
    count: usize,
    mut fits: impl FnMut(&[usize]) -> bool,
) -> Option<Vec<usize>> {
    if count > pool.len() {
        return None;
    }
    let mut at: Vec<usize> = (0..count).collect();
    let mut chosen: Vec<usize> = Vec::with_capacity(count);
    for _ in 0..MAX_SELECTION_TRIES {
        chosen.clear();
        chosen.extend(at.iter().map(|&i| pool[i]));
        if fits(&chosen) {
            return Some(chosen);
        }
        // The next combination: the rightmost position that can move one step right.
        let n = pool.len();
        let move_at = (0..count).rev().find(|&i| at[i] < n - count + i)?;
        at[move_at] += 1;
        for i in move_at + 1..count {
            at[i] = at[i - 1] + 1;
        }
    }
    None
}

/// Step 1: the stated plan hash is well formed and is the hash of the document's items.
fn check_plan_hash(scan: &ScanDoc) -> Result<Sha256Hex, PlanRefusal> {
    let stated: Sha256Hex = scan
        .plan_hash
        .parse()
        .map_err(|_| PlanRefusal::PlanHashForm(scan.plan_hash.clone()))?;
    let computed = purge_plan::hash::plan_hash(&scan.items, &scan.policy_version, scan.mode);
    if computed != scan.plan_hash {
        return Err(PlanRefusal::PlanHashMismatch {
            stated: scan.plan_hash.clone(),
            computed,
        });
    }
    Ok(stated)
}

/// Steps 2 and 3: unique ids, and every listed child is an absorbed candidate inside its parent.
fn check_structure(scan: &ScanDoc) -> Result<(), PlanRefusal> {
    let mut seen = BTreeSet::new();
    for candidate in scan.items.iter().chain(&scan.absorbed) {
        if !seen.insert(&candidate.id) {
            return Err(PlanRefusal::DuplicateId(candidate.id.clone()));
        }
    }
    let absorbed: BTreeMap<&CandidateId, &Candidate> =
        scan.absorbed.iter().map(|c| (&c.id, c)).collect();
    for parent in &scan.items {
        for child in &parent.children {
            let pair = || (parent.id.clone(), child.clone());
            let Some(candidate) = absorbed.get(child) else {
                let (parent, child) = pair();
                return Err(PlanRefusal::ChildMissing { parent, child });
            };
            if !nests_in(&candidate.target, &parent.target) {
                let (parent, child) = pair();
                return Err(PlanRefusal::ChildOutside { parent, child });
            }
        }
    }
    Ok(())
}

/// Step 4, first half: the indexes into `scan.items` of the selected items, in plan order.
fn select(scan: &ScanDoc, selection: &Selection) -> Result<Vec<usize>, PlanRefusal> {
    let indexes: Vec<usize> = match selection {
        Selection::Preselected => scan
            .items
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                c.decision
                    .as_ref()
                    .is_some_and(|d| d.band == Band::Safe && d.preselected)
            })
            .map(|(index, _)| index)
            .collect(),
        Selection::Ids(ids) => {
            let top: BTreeMap<&CandidateId, usize> = scan
                .items
                .iter()
                .enumerate()
                .map(|(index, c)| (&c.id, index))
                .collect();
            let mut chosen = BTreeSet::new();
            for id in ids.iter().filter(|id| !id.0.is_empty()) {
                match top.get(id) {
                    Some(index) => chosen.insert(*index),
                    None if scan.absorbed.iter().any(|c| &c.id == id) => {
                        return Err(PlanRefusal::AbsorbedSelected(id.clone()));
                    }
                    None => return Err(PlanRefusal::UnknownId(id.clone())),
                };
            }
            chosen.into_iter().collect()
        }
    };
    if indexes.is_empty() {
        return Err(PlanRefusal::EmptySelection);
    }
    Ok(indexes)
}

/// Step 4, second half: every selected item may be acted on; each gets its op id and executor op.
fn bind_items(scan: &ScanDoc, selected: &[usize]) -> Result<Vec<BoundItem>, PlanRefusal> {
    let mut items = Vec::with_capacity(selected.len());
    for (position, &index) in selected.iter().enumerate() {
        let candidate = &scan.items[index];
        let refuse = |why: NotSelectable| PlanRefusal::NotSelectable {
            id: candidate.id.clone(),
            why,
        };
        let exec_op = selectable(scan, candidate).map_err(refuse)?;
        let number =
            u32::try_from(position + 1).map_err(|_| PlanRefusal::TooManyItems(selected.len()))?;
        items.push(BoundItem {
            op: OpId(number),
            index,
            exec_op,
        });
    }
    Ok(items)
}

/// Whether `candidate` may be selected, and the executor op it resolves to (`None`: a service, task or
/// firewall item without its scan-time digest, which the run skips).
fn selectable(scan: &ScanDoc, candidate: &Candidate) -> Result<Option<ExecOp>, NotSelectable> {
    let decision = candidate
        .decision
        .as_ref()
        .ok_or(NotSelectable::Undecided)?;
    if decision.band == Band::Blocked {
        return Err(NotSelectable::Blocked);
    }
    if let Some(blocker) = candidate.blockers.iter().find(|b| b.is_hard()) {
        return Err(NotSelectable::HardBlocker(blocker.clone()));
    }
    if candidate.action == Action::ReportOnly {
        return Err(NotSelectable::ReportOnly);
    }
    let exec_op = match resolve(
        &candidate.target,
        candidate.action,
        candidate.object_fp.as_ref(),
    ) {
        Ok(op) => Some(op),
        // A service, task or firewall item without its scan-time digest stays selectable without an
        // executor op: the run journals it as skipped (`ChangedSinceScan`, "no object fingerprint")
        // before any backup, and never acts on it.
        Err(Mismatch::NoObjectFp) if ObjectKind::of(&candidate.target).is_some() => None,
        Err(Mismatch::ReportOnly) => return Err(NotSelectable::ReportOnly),
        Err(other) => return Err(NotSelectable::Unresolvable(other)),
    };
    live::check_protected_descendants(candidate, scan.items.iter().chain(&scan.absorbed))
        .map_err(|refusal| NotSelectable::ProtectedDescendant(refusal.blocker))?;
    Ok(exec_op)
}

/// Step 5: of two selected items where one lies inside the other, the inner one comes first.
fn check_order(scan: &ScanDoc, items: &[BoundItem]) -> Result<(), PlanRefusal> {
    for (position, outer) in items.iter().enumerate() {
        let outer = &scan.items[outer.index];
        for inner in &items[position + 1..] {
            let inner = &scan.items[inner.index];
            if nests_in(&inner.target, &outer.target) {
                return Err(PlanRefusal::Order {
                    inner: inner.id.clone(),
                    outer: outer.id.clone(),
                });
            }
        }
    }
    Ok(())
}
