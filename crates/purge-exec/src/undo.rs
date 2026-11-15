//! Undo of a session (M2-X-UNDO; ENGINE_PLAN.md §7.8).
//!
//! [`undo`] puts back what a finished session changed: all of it, or the items the caller names. It
//! works from the session's journal alone and writes what it does to that journal, one op at a time.
//!
//! # The sequence
//!
//! 1. The store is checked, the session opened, and its journal read against the mark of its index
//!    entry ([`journal::read_indexed`]): a journal cut at a line boundary is refused as damaged. An
//!    unavailable index is a warning, never a guess.
//! 2. The run must have ended (`commit` or `aborted`) and no retry of a held item may be in flight;
//!    otherwise the session needs [`crate::recover`] first.
//! 3. The selection is turned into ops. A partial selection pulls in the ops its restores depend on
//!    ([`dependencies`]): a file needs the directories above it that this session removed or moved, a
//!    key or value needs the keys above it that this session deleted.
//! 4. The gate context is filled from the journal's `validated` records only
//!    ([`OpState::validated`], `GateCtx::record`). An op without an accepted record ends as a conflict
//!    in its module.
//! 5. Boot-time moves that are still pending are reconciled first ([`locked::reconcile`]); every
//!    verdict but "still pending" and "cannot be told" is journalled.
//! 6. The ops are undone in the exact reverse order of the journal's `done` records, the
//!    `RecreateDir` inverses before all others ([`undo_order`]). Each op is
//!    `undo_intent` -> inverse -> `undo_done` or `undo_conflict`; what is decided without running an
//!    inverse is journalled without an `undo_intent`.
//! 7. The session's standing ([`standing`]) goes into its index entry, and the ops the caller asked
//!    for and got back are written as false-positive labels ([`UndoLabels`]) into the session
//!    directory.
//!
//! # One op
//!
//! | The op | What happens |
//! |---|---|
//! | its undo settled before | skipped, listed in [`UndoOutput::already_undone`] |
//! | neither intent nor `done` | skipped: the journal takes no undo record for it |
//! | `done` without intent | `NothingToUndo` |
//! | data deleted by expiry | conflict `Expired` |
//! | held for a retry, never moved | `NothingToUndo` |
//! | boot-time move still registered | the pair is taken back ([`locked::remove_boot_move`]) |
//! | boot-time move, state cannot be told | `Failed{VerifyFailed}`, to be tried again |
//! | reconcile left it needing attention | the conflict of [`locked::undo_locked`] |
//! | file op | [`act_fs::plan_undo_fs`], [`act_fs::undo_fs`] |
//! | registry op | [`act_reg::prepare_undo_reg`] (which reads the backup hash-checked), [`act_reg::run_undo_reg`] |
//! | package removal | [`act_typed::undo_typed`]: an `Irreversible` record, not an error |
//!
//! Nothing existing is overwritten and no conflict is forced: those rules live in the modules the
//! inverses belong to. An undo that was interrupted (an `undo_intent` with nothing after it) or that
//! failed is run again in the completing form: a key tree is completed from its backup
//! (`restore_missing`) instead of restored whole.
//!
//! A journal record that cannot be written stops the run at once ([`UndoOutput::stopped`]); every
//! other failure is the result of its op, and the run goes on.

// The store's and the journal's errors carry paths and are over clippy's size threshold wherever
// they are returned in this crate.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use purge_guard::deny::{DenyList, Exemptions};
use purge_guard::prefix;
use purge_model::exec::journal::{ReconcileResult, Record, UndoConflict, UndoOutcome};
use purge_model::exec::op::{ExecOp, FailCode, Inverse, ItemOutcome, OpId, Sha256Hex};
use purge_model::exec::session::{
    SessionId, SessionIndex, SessionState, SessionSummary, UndoCounts, UndoItemReport, UndoReport,
    UndoReportSchema, UndoResult,
};
use purge_model::{Blocker, CandidateId, FileTime, Target};
use serde::{Deserialize, Serialize};

use crate::act_fs::{self, FsUndo, FsUndoPlan, Retry};
use crate::act_reg::{self, RegUndoPrepared, RegUndoResult};
use crate::act_typed::{self, TypedUndo};
use crate::execute;
use crate::gate::{GateCtx, GateItem, GateSetupError};
use crate::journal::{
    self, JournalError, JournalState, JournalWriter, OpState, OpStatus, UndoState, UndoToken,
};
use crate::locked::{self, LockUndo, PendingRenames, ReconcileVerdict, StoreLadder};
use crate::report;
use crate::storage::{SessionDir, StorageError, StorageRoots, now};

#[cfg(test)]
mod tests;

/// What an undo run works with.
pub struct UndoEnv<'a> {
    /// Purge's store.
    pub roots: &'a StorageRoots,
    /// The deny-list compiled from the live `GuardEnv`.
    pub deny: &'a DenyList,
    /// The boot-time move list (`SystemPendingRenames` in the product).
    pub pending_renames: &'a mut dyn PendingRenames,
    /// How a move back that finds its item in use is retried.
    pub retry: Retry,
}

impl<'a> UndoEnv<'a> {
    /// An environment with the standard retries.
    pub fn new(
        roots: &'a StorageRoots,
        deny: &'a DenyList,
        pending_renames: &'a mut dyn PendingRenames,
    ) -> UndoEnv<'a> {
        UndoEnv {
            roots,
            deny,
            pending_renames,
            retry: Retry::standard(),
        }
    }
}

impl std::fmt::Debug for UndoEnv<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UndoEnv")
            .field("roots", &self.roots)
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

/// Which items of the session to undo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoSelection {
    /// Every item.
    All,
    /// These items, by candidate id, and what their restores depend on.
    Items(Vec<CandidateId>),
}

/// One undo request (`undo --session <id> [--items ..] [--confirm <plan hash>]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoRequest {
    /// The session to undo.
    pub session: SessionId,
    /// What to undo.
    pub selection: UndoSelection,
    /// The plan hash the caller confirmed; when given it must be the one in the session's journal
    /// header, or nothing is done.
    pub plan_hash: Option<Sha256Hex>,
}

/// How an undo run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoOutput {
    /// The report: one entry per op the run covered, in the order they were undone, each result read
    /// back from the journal.
    pub report: UndoReport,
    /// Ops that were not selected and were undone because a selected restore depends on them.
    pub pulled_in: Vec<OpId>,
    /// Selected ops whose undo had settled before this run; nothing was done for them.
    pub already_undone: Vec<OpId>,
    /// Whether the session's index entry states the session's standing now.
    pub index_updated: bool,
    /// The session file the false-positive labels were written to, when there were any.
    pub labels_file: Option<String>,
    /// Set when the run stopped early because the journal could not be written: the error. The ops
    /// after the failure were not touched.
    pub stopped: Option<String>,
}

/// Why an undo run did not start. Nothing was changed.
#[derive(Debug, thiserror::Error)]
pub enum UndoError {
    /// The store refused (integrity, a missing session, I/O).
    #[error(transparent)]
    Store(#[from] StorageError),
    /// The journal cannot be read or opened: it is damaged, cut (its index mark does not fit) or
    /// held by another writer.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The gate could not be set up.
    #[error(transparent)]
    Gate(#[from] GateSetupError),
    /// The confirmed plan hash is not the session's.
    #[error("the session executed plan {actual}, not the confirmed plan {confirmed}")]
    PlanMismatch {
        /// The hash the caller confirmed.
        confirmed: Sha256Hex,
        /// The hash in the journal header.
        actual: Sha256Hex,
    },
    /// A named item is not part of the session.
    #[error("item {0:?} is not part of the session")]
    UnknownItem(String),
    /// The run did not end, or a retry is in flight: crash recovery comes first.
    #[error("the session needs recovery first: {0}")]
    NeedsRecovery(String),
    /// The journal changed between reading it and opening it to append.
    #[error("the journal changed while it was being opened")]
    JournalChanged,
}

/// The schema id of [`UndoLabels`].
pub const LABELS_SCHEMA: &str = "purge.undo-labels/1";

/// The false-positive labels of one undo run (ENGINE_PLAN.md §7.8, "learning signal"): the items the
/// user asked to have back and got back. Written as `undo-labels-<time>.json` into the session
/// directory, through the store; never sent anywhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndoLabels {
    /// Always [`LABELS_SCHEMA`].
    pub schema: String,
    /// The session.
    pub session: SessionId,
    /// The app id of the plan the session executed.
    pub app: String,
    /// The plan's hash.
    pub plan_hash: Sha256Hex,
    /// The policy version that selected the items.
    pub policy_version: String,
    /// When the undo run started.
    pub at: FileTime,
    /// One label per item.
    pub labels: Vec<UndoLabel>,
}

/// One item the user undid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndoLabel {
    /// The op.
    pub op: OpId,
    /// The candidate id of the plan item.
    pub item: CandidateId,
    /// What the item acted on.
    pub target: Target,
    /// How its undo ended: `Restored` or `AlreadyRestored`.
    pub outcome: UndoOutcome,
}

// ---------------------------------------------------------------------------------------------------
// What the journal says about an op
// ---------------------------------------------------------------------------------------------------

/// The outcome an op stands at: its `done` outcome as its `reconcile` records changed it (a retry's
/// outcome replaces `HeldRetry`, a completed boot-time move is `Done`). `None` for an op without a
/// `done`.
pub(crate) fn effective_outcome(op: &OpState) -> Option<ItemOutcome> {
    let mut outcome = op.outcome.clone()?;
    for result in &op.reconciles {
        match result {
            ReconcileResult::Retried { outcome: retried } => outcome = retried.clone(),
            ReconcileResult::Completed => outcome = ItemOutcome::Done,
            _ => {}
        }
    }
    Some(outcome)
}

/// Whether the op left (or may have left) the system changed, so that something stands to be undone:
/// an intent with no `done`, `Done`, `VerifyFailed`, a registered or completed boot-time move, an
/// item reconcile could not put right. Never for an op without an intent.
pub(crate) fn stands_changed(op: &OpState) -> bool {
    if op.intent.is_none() {
        return false;
    }
    let of = |outcome: &ItemOutcome| match outcome {
        ItemOutcome::Failed { code, .. } => *code == FailCode::VerifyFailed,
        other => other.changed_system(),
    };
    let mut changed = op.outcome.as_ref().is_none_or(of);
    for result in &op.reconciles {
        changed = match result {
            ReconcileResult::StillPending => changed,
            ReconcileResult::Completed
            | ReconcileResult::MismatchKept { .. }
            | ReconcileResult::Lost { .. } => true,
            ReconcileResult::MismatchMovedBack
            | ReconcileResult::Cancelled
            | ReconcileResult::NotMoved { .. } => false,
            ReconcileResult::Retried { outcome } => of(outcome),
        };
    }
    changed
}

/// Where a restore puts something back.
enum Place<'a> {
    /// A file or directory at this path.
    Path(&'a str),
    /// This key.
    Key(&'a str),
    /// A value or segment inside this key.
    Inside(&'a str),
}

fn place(op: &ExecOp) -> Option<Place<'_>> {
    Some(match op {
        ExecOp::QuarantineMove { path } | ExecOp::RemoveDirIfEmpty { path } => Place::Path(path),
        ExecOp::DeleteKeyTree { key } | ExecOp::DeleteKeyIfEmpty { key } => Place::Key(key),
        ExecOp::DeleteValue { key, .. } | ExecOp::EditSegment { key, .. } => Place::Inside(key),
        ExecOp::RemovePackage { .. } => return None,
    })
}

/// Whether the restore of `of` needs what `dependency` removed to be back first.
fn depends_on(of: &ExecOp, dependency: &ExecOp) -> bool {
    match (place(of), place(dependency)) {
        (Some(Place::Path(path)), Some(Place::Path(above))) => prefix::is_ancestor(above, path),
        (Some(Place::Key(key)), Some(Place::Key(above))) => prefix::is_ancestor(above, key),
        (Some(Place::Inside(key)), Some(Place::Key(above))) => {
            prefix::is_ancestor(above, key) || prefix::is_same(above, key)
        }
        _ => false,
    }
}

/// The ops outside `selected` that the restores of `selected` depend on: every op of the session
/// that removed, moved or deleted a directory or key above a selected op's item (for a value or
/// segment also the key holding it), still stands changed, and whose undo has not settled. "Above" is
/// transitive, so one pass finds the whole closure.
pub(crate) fn dependencies(ops: &[&OpState], selected: &BTreeSet<OpId>) -> BTreeSet<OpId> {
    fn exec_op<'a>(op: &&'a OpState) -> Option<&'a ExecOp> {
        op.intent.as_ref().map(|intent| &intent.exec_op)
    }
    let wanted: Vec<&ExecOp> = ops
        .iter()
        .filter(|op| selected.contains(&op.op))
        .filter_map(exec_op)
        .collect();
    ops.iter()
        .filter(|op| !selected.contains(&op.op) && !op.undo.is_settled() && stands_changed(op))
        .filter(|op| {
            exec_op(op).is_some_and(|dependency| wanted.iter().any(|of| depends_on(of, dependency)))
        })
        .map(|op| op.op)
        .collect()
}

/// The order `ops` are undone in: the exact reverse of the journal's `done` records (an op with an
/// intent and no `done` counts at its intent), with every op whose inverse is `RecreateDir` before all
/// others. Ops with neither record are left out.
pub(crate) fn undo_order(records: &[Record], ops: &BTreeSet<OpId>) -> Vec<OpId> {
    // Per op: where it counts in the journal, and whether its inverse recreates a directory.
    let mut ranked: BTreeMap<OpId, (usize, bool)> = BTreeMap::new();
    for (line, record) in records.iter().enumerate() {
        match record {
            Record::Intent(intent) if ops.contains(&intent.op) => {
                let recreate = matches!(intent.inverse, Inverse::RecreateDir { .. });
                ranked.insert(intent.op, (line, recreate));
            }
            Record::Done(done) if ops.contains(&done.op) => {
                let recreate = ranked.get(&done.op).is_some_and(|(_, recreate)| *recreate);
                ranked.insert(done.op, (line, recreate));
            }
            _ => {}
        }
    }
    let mut order: Vec<(OpId, usize, bool)> = ranked
        .into_iter()
        .map(|(op, (line, recreate))| (op, line, recreate))
        .collect();
    order.sort_by(|a, b| b.2.cmp(&a.2).then(b.1.cmp(&a.1)));
    order.into_iter().map(|(op, _, _)| op).collect()
}

/// Journals the `undo_plan` of an undo run over `order` (the selected and pulled-in ops in undo order),
/// flushed before the first undo record, so that recovery can finish an interrupted run
/// ([`JournalState::undo_unfinished`]). Nothing is written when every op of `order` is already settled.
/// Returns `order`.
fn plan_undo(journal: &mut JournalWriter, order: &[OpId]) -> Result<Vec<OpId>, JournalError> {
    let unsettled = order.iter().any(|op| {
        journal
            .state()
            .op(*op)
            .is_some_and(|state| !state.undo.is_settled())
    });
    if unsettled {
        journal.undo_plan(now(), order.to_vec())?;
    }
    Ok(order.to_vec())
}

/// Where a session stands after undo records were written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Standing {
    /// `Undone` or `PartiallyUndone` once any op has an undo record; `None` before.
    pub(crate) state: Option<SessionState>,
    /// Ops whose undo ended `Restored` or `AlreadyRestored`.
    pub(crate) undone: u32,
}

/// The standing of a session from its ops: `Undone` when no op that stands changed is left with an
/// unsettled undo, `PartiallyUndone` otherwise; `None` while no op has any undo record.
pub(crate) fn standing<'a>(ops: impl Iterator<Item = &'a OpState>) -> Standing {
    let mut touched = false;
    let mut outstanding = false;
    let mut undone = 0u32;
    for op in ops {
        touched |= op.undo != UndoState::NotStarted;
        if matches!(
            op.undo,
            UndoState::Finished(UndoOutcome::Restored | UndoOutcome::AlreadyRestored)
        ) {
            undone = undone.saturating_add(1);
        }
        outstanding |= stands_changed(op) && !op.undo.is_settled();
    }
    let state = touched.then_some(if outstanding {
        SessionState::PartiallyUndone
    } else {
        SessionState::Undone
    });
    Standing { state, undone }
}

// ---------------------------------------------------------------------------------------------------
// The store and the gate
// ---------------------------------------------------------------------------------------------------

/// The session index, or `None` with a warning when it is unavailable; any other failure is the
/// store's.
pub(crate) fn read_index(
    roots: &StorageRoots,
    warnings: &mut Vec<String>,
) -> Result<Option<SessionIndex>, StorageError> {
    match roots.read_index() {
        Ok(index) => Ok(Some(index)),
        Err(e) if e.is_index_unavailable() => {
            warnings.push(format!(
                "the session index is unavailable ({e}); the journal was not checked against it and \
                 the index was not updated"
            ));
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Why [`gate_ctx`] could not make a gate context.
#[derive(Debug)]
pub(crate) enum CtxError {
    /// The store refused the session's scope.
    Store(StorageError),
    /// The gate could not be set up.
    Gate(GateSetupError),
}

impl From<CtxError> for UndoError {
    fn from(error: CtxError) -> UndoError {
        match error {
            CtxError::Store(e) => UndoError::Store(e),
            CtxError::Gate(e) => UndoError::Gate(e),
        }
    }
}

/// The gate context of an undo or recovery run over `state`: the session's own store scope from the
/// journal header's volumes, and every op's journalled `validated` record, as written. A record the
/// gate does not accept is a warning; its op then has no record and ends as a conflict.
pub(crate) fn gate_ctx(
    roots: &StorageRoots,
    deny: &DenyList,
    session: &SessionDir,
    state: &JournalState,
    warnings: &mut Vec<String>,
) -> Result<GateCtx, CtxError> {
    let exec_ops: Vec<ExecOp> = state
        .ops()
        .filter_map(|op| op.intent.as_ref().map(|intent| intent.exec_op.clone()))
        .collect();
    let volume_roots: Vec<&str> = state
        .header()
        .volumes
        .iter()
        .map(|volume| volume.root.as_str())
        .collect();
    let scope = roots
        .store_scope(session.id(), &volume_roots)
        .map_err(CtxError::Store)?;
    let mut ctx = GateCtx::new(deny.clone(), &exec_ops, scope).map_err(CtxError::Gate)?;
    for op in state.ops() {
        let Some(intent) = &op.intent else {
            continue;
        };
        let max_files = GateItem::new(&intent.exec_op, Exemptions::default()).max_files;
        if let Err(refusal) = ctx.record(&intent.exec_op, &op.validated(), max_files) {
            warnings.push(format!(
                "the validated record of op {} was not accepted: {refusal}",
                op.op
            ));
        }
    }
    Ok(ctx)
}

/// The index entry `state` calls for: the summary of the journal ([`report::summary`]: standing,
/// undone count, the bytes still kept and their volumes, counts, end, the journal's mark). The owner
/// and the classes expiry marked purged are kept from the existing entry; without one the owner is
/// read from the session's scan copy. `Err` when there is no entry and the scan copy cannot be read.
pub(crate) fn index_entry(
    session: &SessionDir,
    state: &JournalState,
    existing: Option<&SessionSummary>,
) -> Result<SessionSummary, String> {
    let data = report::data_volume(session.roots());
    let entry = match existing {
        Some(existing) => {
            let mut entry =
                report::summary_with_owner(state, existing.owner.clone(), data.as_ref());
            entry.purged = existing.purged.clone();
            entry
        }
        None => {
            let scan = execute::read_scan_copy(session)
                .map_err(|e| format!("the session's scan copy cannot be read ({e})"))?;
            report::summary(state, &scan, data.as_ref())
        }
    };
    Ok(entry)
}

/// Brings the session's index entry up to `state`, whose every line is flushed. Writes only when the
/// entry differs, so a second call changes nothing. Returns whether the entry is current afterwards;
/// a failure is a warning.
pub(crate) fn update_index(
    session: &SessionDir,
    state: &JournalState,
    warnings: &mut Vec<String>,
) -> bool {
    let roots = session.roots();
    let index = match roots.read_index() {
        Ok(index) => index,
        Err(e) => {
            warnings.push(format!("the session index was not updated: {e}"));
            return false;
        }
    };
    let existing = index.get(session.id());
    let entry = match index_entry(session, state, existing) {
        Ok(entry) => entry,
        Err(e) => {
            warnings.push(format!("the session index was not updated: {e}"));
            return false;
        }
    };
    if existing == Some(&entry) {
        return true;
    }
    match roots.update_index(|index| index.upsert(entry)) {
        Ok(_) => true,
        Err(e) => {
            warnings.push(format!("the session index was not updated: {e}"));
            false
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------------------------------

/// The undo records of one op: the token of its `undo_intent` once one is written, and the calls that
/// end it. An inverse runs only under [`Step::token`].
struct Step<'j> {
    journal: &'j mut JournalWriter,
    op: OpId,
    token: Option<UndoToken>,
}

impl Step<'_> {
    /// The token of the op's `undo_intent`, written now if none is open.
    fn token(&mut self) -> Result<&UndoToken, JournalError> {
        let token = match self.token.take() {
            Some(token) => token,
            None => self.journal.undo_intent(self.op)?,
        };
        Ok(self.token.insert(token))
    }

    /// Ends the op's undo with `outcome`: with the token when an intent is open, without an intent
    /// for what is decided without an inverse, and otherwise after an intent written now.
    fn done(mut self, outcome: UndoOutcome, detail: String) -> Result<String, JournalError> {
        let decided = matches!(
            outcome,
            UndoOutcome::NothingToUndo | UndoOutcome::AlreadyRestored
        );
        if self.token.is_none() && decided {
            self.journal.undo_done_without_intent(self.op, outcome)?;
            return Ok(detail);
        }
        self.token()?;
        if let Some(token) = self.token.take() {
            self.journal.undo_done(token, outcome)?;
        }
        Ok(detail)
    }

    /// Ends the op's undo with a conflict.
    fn conflict(self, conflict: UndoConflict, detail: String) -> Result<String, JournalError> {
        match self.token {
            Some(token) => self
                .journal
                .undo_conflict(token, conflict, detail.clone())?,
            None => {
                self.journal
                    .undo_conflict_without_intent(self.op, conflict, detail.clone())?;
            }
        }
        Ok(detail)
    }

    fn failed(self, code: FailCode, detail: String) -> Result<String, JournalError> {
        self.done(
            UndoOutcome::Failed {
                code,
                os_error: None,
                detail: detail.clone(),
            },
            detail,
        )
    }
}

/// What a driver run covered.
#[derive(Debug)]
pub(crate) struct Covered {
    /// One entry per op an undo record was written for, in order, each result read back from the
    /// journal.
    pub(crate) items: Vec<UndoItemReport>,
    /// The journal error that stopped the run, when one did.
    pub(crate) stopped: Option<JournalError>,
}

/// The undo of ops of one session: the journal open to append, the gate context filled from its
/// `validated` records, and the boot-time move list. [`undo`] and crash recovery both run it.
pub(crate) struct Driver<'a> {
    pub(crate) session: &'a SessionDir,
    pub(crate) journal: &'a mut JournalWriter,
    pub(crate) ctx: &'a GateCtx,
    pub(crate) pending: &'a mut dyn PendingRenames,
    pub(crate) retry: &'a Retry,
}

impl Driver<'_> {
    /// Reconciles the session's pending boot-time moves and journals what was found. "Still pending"
    /// and "cannot be told" decide nothing and are not journalled, so reconciling twice writes
    /// nothing the second time.
    pub(crate) fn reconcile(&mut self, warnings: &mut Vec<String>) -> Result<(), JournalError> {
        if self.journal.state().pending_reboot().next().is_none() {
            return Ok(());
        }
        let found = {
            let ladder = StoreLadder::new(self.ctx, self.session);
            locked::reconcile(
                self.journal.state(),
                self.session,
                self.ctx,
                &ladder,
                &*self.pending,
            )
        };
        for reconciled in found {
            if let Some(alert) = &reconciled.alert {
                warnings.push(format!(
                    "op {}: another object than the recorded one was found in quarantine at {} ({}): {}",
                    reconciled.op,
                    alert.quarantine_path,
                    if alert.moved_back {
                        "moved back"
                    } else {
                        "kept there"
                    },
                    reconciled.detail
                ));
            }
            match reconciled.verdict {
                ReconcileVerdict::StillPending => {}
                ReconcileVerdict::Indeterminate => warnings.push(format!(
                    "op {}: the state of its boot-time move cannot be told: {}",
                    reconciled.op, reconciled.detail
                )),
                _ => {
                    if let Some(record) = reconciled.record(now()) {
                        self.journal.reconcile(record)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Undoes `order`, op by op, and stops at the first journal error.
    pub(crate) fn run(&mut self, order: &[OpId]) -> Covered {
        let mut items = Vec::new();
        for &id in order {
            let Some(op) = self.journal.state().op(id).cloned() else {
                continue;
            };
            if op.undo.is_settled() || op.status() == OpStatus::Validated {
                continue;
            }
            let detail = match self.undo_op(&op) {
                Ok(detail) => detail,
                Err(e) => {
                    return Covered {
                        items,
                        stopped: Some(e),
                    };
                }
            };
            let state = self.journal.state();
            let result = match state.op(id).map(|after| &after.undo) {
                Some(UndoState::Finished(outcome)) => UndoResult::Finished {
                    outcome: outcome.clone(),
                },
                Some(UndoState::Conflict(conflict)) => UndoResult::Conflict {
                    conflict: conflict.clone(),
                    detail: state.undo_conflict_detail(id).map_or(detail, str::to_owned),
                },
                // `undo_op` returned without ending the op's undo; it never does.
                _ => continue,
            };
            items.push(UndoItemReport {
                op: id,
                item: op.item,
                target: op.target,
                result,
            });
        }
        Covered {
            items,
            stopped: None,
        }
    }

    /// Undoes one op whose undo has not settled and which has an intent or a `done`, ending with its
    /// `undo_done` or `undo_conflict`. Returns the text for the report; `Err` only for the journal.
    fn undo_op(&mut self, op: &OpState) -> Result<String, JournalError> {
        let mut step = Step {
            journal: &mut *self.journal,
            op: op.op,
            token: None,
        };
        let Some(intent) = &op.intent else {
            return step.done(
                UndoOutcome::NothingToUndo,
                "the op was decided before anything was changed".to_owned(),
            );
        };
        if !op.expired.is_empty() {
            return step.conflict(
                UndoConflict::Expired,
                format!(
                    "the data of op {} was deleted by expiry; it cannot be put back",
                    op.op
                ),
            );
        }
        // An inverse that may have run in part (interrupted, or failed) is run again in its completing
        // form.
        let again = matches!(
            op.undo,
            UndoState::InProgress | UndoState::Finished(UndoOutcome::Failed { .. })
        );
        if op.undo == UndoState::InProgress {
            step.token = step.journal.resume_undo(op.op);
        }
        match &intent.exec_op {
            ExecOp::QuarantineMove { .. } | ExecOp::RemoveDirIfEmpty { .. } => {
                match locked::undo_locked(op, &*self.pending) {
                    Some(LockUndo::Done(outcome)) => return step.done(outcome, String::new()),
                    Some(LockUndo::Conflict { conflict, detail }) => {
                        return step.conflict(conflict, detail);
                    }
                    Some(LockUndo::ReconcileFirst { detail }) => {
                        // Nothing can be undone before reconcile has decided where the item is; the
                        // conflict is not settled, so a later undo tries again.
                        return step.conflict(
                            UndoConflict::GateBlocked {
                                blocker: Blocker::DenyListed {
                                    rule: locked::reason::BOOT_MOVE_INDETERMINATE.to_owned(),
                                },
                            },
                            detail,
                        );
                    }
                    Some(LockUndo::RemovePair(removal)) => {
                        let outcome =
                            locked::remove_boot_move(removal, step.token()?, &mut *self.pending);
                        return step.done(
                            outcome,
                            "the registered boot-time move was taken back".to_owned(),
                        );
                    }
                    None => {}
                }
                let done = effective_outcome(op);
                match act_fs::plan_undo_fs(intent, done.as_ref()) {
                    None => {
                        step.failed(FailCode::Internal, format!("op {} is not a file op", op.op))
                    }
                    Some(FsUndoPlan::Decided(FsUndo::Done { outcome, detail })) => {
                        step.done(outcome, detail)
                    }
                    Some(FsUndoPlan::Decided(FsUndo::Conflict { conflict, detail })) => {
                        step.conflict(conflict, detail)
                    }
                    Some(FsUndoPlan::Run(job)) => {
                        let ran =
                            act_fs::undo_fs(self.ctx, self.session, job, self.retry, step.token()?);
                        match ran {
                            Ok(FsUndo::Done { outcome, detail }) => step.done(outcome, detail),
                            Ok(FsUndo::Conflict { conflict, detail }) => {
                                step.conflict(conflict, detail)
                            }
                            Err(e) => step.failed(
                                FailCode::Internal,
                                format!("the store refused the undo of op {}: {e}", op.op),
                            ),
                        }
                    }
                }
            }
            ExecOp::RemovePackage { .. } => {
                match act_typed::undo_typed(&intent.exec_op, &intent.inverse, op.outcome.as_ref()) {
                    Some(TypedUndo::Done(outcome)) => step.done(outcome, String::new()),
                    Some(TypedUndo::Conflict { conflict, detail }) => {
                        step.conflict(conflict, detail)
                    }
                    None => step.failed(
                        FailCode::Internal,
                        format!("op {} is not a typed op", op.op),
                    ),
                }
            }
            ExecOp::DeleteKeyTree { .. }
            | ExecOp::DeleteKeyIfEmpty { .. }
            | ExecOp::DeleteValue { .. }
            | ExecOp::EditSegment { .. } => {
                let done = match &op.outcome {
                    Some(ItemOutcome::Done) if again => None,
                    other => other.as_ref(),
                };
                match act_reg::prepare_undo_reg(self.ctx, self.session, intent, done) {
                    None => step.failed(
                        FailCode::Internal,
                        format!("op {} is not a registry op", op.op),
                    ),
                    Some(RegUndoPrepared::Decided(RegUndoResult::Done { outcome, detail })) => {
                        step.done(outcome, detail)
                    }
                    Some(RegUndoPrepared::Decided(RegUndoResult::Conflict {
                        conflict,
                        detail,
                    })) => step.conflict(conflict, detail),
                    Some(RegUndoPrepared::Ready(inverse)) => {
                        match act_reg::run_undo_reg(inverse, step.token()?) {
                            RegUndoResult::Done { outcome, detail } => step.done(outcome, detail),
                            RegUndoResult::Conflict { conflict, detail } => {
                                step.conflict(conflict, detail)
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------------------------------

/// The ops the request selects: every op with an intent or a `done`, or those of the named items.
fn select(state: &JournalState, selection: &UndoSelection) -> Result<BTreeSet<OpId>, UndoError> {
    match selection {
        UndoSelection::All => Ok(state
            .ops()
            .filter(|op| op.status() != OpStatus::Validated)
            .map(|op| op.op)
            .collect()),
        UndoSelection::Items(items) => items
            .iter()
            .map(|item| {
                state
                    .ops()
                    .find(|op| &op.item == item)
                    .map(|op| op.op)
                    .ok_or_else(|| UndoError::UnknownItem(item.0.clone()))
            })
            .collect(),
    }
}

/// Writes the labels as a new session file and returns its name.
fn write_labels(session: &SessionDir, labels: &UndoLabels) -> Result<String, String> {
    let name = format!("undo-labels-{}.json", labels.at.0);
    let text = serde_json::to_vec_pretty(labels).map_err(|e| e.to_string())?;
    let mut file = session.create_file(&name).map_err(|e| e.to_string())?;
    let written = file
        .write_all(&text)
        .map_err(|e| e.to_string())
        .and_then(|()| file.sync().map_err(|e| e.to_string()))
        .and_then(|()| file.sync_dir().map_err(|e| e.to_string()));
    match written {
        Ok(()) => Ok(name),
        Err(e) => {
            // The file is Purge's own, created a moment ago.
            let _ = file.discard();
            Err(e)
        }
    }
}

/// Undoes a session, or the named items of it (see the module docs for every step).
///
/// `Err` means the run did not start: nothing was changed. Otherwise the result is an [`UndoOutput`]
/// whose report lists every op an undo record was written for; conflicts and failures are results in
/// it, never errors.
pub fn undo(request: &UndoRequest, env: UndoEnv<'_>) -> Result<UndoOutput, UndoError> {
    let started = now();
    let mut warnings = Vec::new();
    env.roots.check()?;
    let session = env.roots.open_session(&request.session)?;
    let index = read_index(env.roots, &mut warnings)?;
    let mark = index
        .as_ref()
        .and_then(|index| index.get(&request.session))
        .and_then(|entry| entry.journal.as_ref());
    let read = journal::read_indexed(&session, mark)?;
    let header = read.state.header();
    if let Some(confirmed) = request.plan_hash {
        if confirmed != header.plan_hash {
            return Err(UndoError::PlanMismatch {
                confirmed,
                actual: header.plan_hash,
            });
        }
    }
    if !read.state.is_finished() {
        return Err(UndoError::NeedsRecovery(
            "its run ended with neither commit nor aborted".to_owned(),
        ));
    }
    if read.state.retries_in_flight().next().is_some() {
        return Err(UndoError::NeedsRecovery(
            "a retry of a held item was interrupted".to_owned(),
        ));
    }
    let requested = select(&read.state, &request.selection)?;
    let ops: Vec<&OpState> = read.state.ops().collect();
    let pulled_in = dependencies(&ops, &requested);
    let already_undone: Vec<OpId> = ops
        .iter()
        .filter(|op| requested.contains(&op.op) && op.undo.is_settled())
        .map(|op| op.op)
        .collect();

    let mut journal = JournalWriter::open_append(&session)?;
    if journal.state().mark() != read.state.mark() {
        return Err(UndoError::JournalChanged);
    }
    let ctx = gate_ctx(env.roots, env.deny, &session, &read.state, &mut warnings)?;
    let UndoEnv {
        pending_renames,
        retry,
        ..
    } = env;
    let mut driver = Driver {
        session: &session,
        journal: &mut journal,
        ctx: &ctx,
        pending: pending_renames,
        retry: &retry,
    };
    let all: BTreeSet<OpId> = requested.union(&pulled_in).copied().collect();
    let covered = match driver
        .reconcile(&mut warnings)
        .and_then(|()| plan_undo(driver.journal, &undo_order(&read.records, &all)))
    {
        Ok(order) => driver.run(&order),
        Err(e) => Covered {
            items: Vec::new(),
            stopped: Some(e),
        },
    };
    let state = journal.state().clone();
    drop(journal);

    let stopped = covered.stopped.map(|e| e.to_string());
    let index_updated = match (&stopped, &index) {
        (None, Some(_)) => update_index(&session, &state, &mut warnings),
        (Some(e), _) => {
            warnings.push(format!(
                "the undo run stopped because the journal could not be written ({e}); the session \
                 index was not updated"
            ));
            false
        }
        (None, None) => false,
    };

    let labels: Vec<UndoLabel> = covered
        .items
        .iter()
        .filter(|item| requested.contains(&item.op))
        .filter_map(|item| match &item.result {
            UndoResult::Finished {
                outcome: outcome @ (UndoOutcome::Restored | UndoOutcome::AlreadyRestored),
            } => Some(UndoLabel {
                op: item.op,
                item: item.item.clone(),
                target: item.target.clone(),
                outcome: outcome.clone(),
            }),
            _ => None,
        })
        .collect();
    let labels_file = if labels.is_empty() {
        None
    } else {
        let header = state.header();
        let labels = UndoLabels {
            schema: LABELS_SCHEMA.to_owned(),
            session: header.session.clone(),
            app: header.app.clone(),
            plan_hash: header.plan_hash,
            policy_version: header.policy_version.clone(),
            at: started,
            labels,
        };
        match write_labels(&session, &labels) {
            Ok(name) => Some(name),
            Err(e) => {
                warnings.push(format!("the false-positive labels were not written: {e}"));
                None
            }
        }
    };

    let standing = standing(state.ops());
    let mut counts = UndoCounts::default();
    for item in &covered.items {
        counts.record(&item.result);
    }
    Ok(UndoOutput {
        report: UndoReport {
            schema: UndoReportSchema,
            session: request.session.clone(),
            state: standing
                .state
                .unwrap_or_else(|| report::session_state(&state)),
            started,
            finished: now(),
            items: covered.items,
            counts,
            warnings,
        },
        pulled_in: pulled_in.into_iter().collect(),
        already_undone,
        index_updated,
        labels_file,
        stopped,
    })
}
