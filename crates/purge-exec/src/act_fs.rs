//! File actions: quarantine move, remove-dir-if-empty, and their inverses (M2-X-FS; ENGINE_PLAN.md §7.5,
//! §7.8, §10.1 nested delete).
//!
//! # What happens to an item
//!
//! - **Quarantine move** ([`ExecOp::QuarantineMove`]): the item is renamed **by handle** into this
//!   session's op directory on its own volume, `<quarantine root>\<session>\<op>\<leaf>`, under its
//!   original leaf name. Nothing is copied and nothing is ever replaced. A directory moves as one rename,
//!   with everything below it; that is only done when the gate's validation counted the tree below it
//!   (a manifest-backed absorbing parent, §7.1) and the act-time walk is complete. A reparse point as the
//!   item (junction, symbolic link, mount point, cloud placeholder) is refused by the gate, so it is never
//!   moved as a tree and never traversed; a reparse point *inside* a moved tree moves as the link it is.
//! - **Remove-dir-if-empty** ([`ExecOp::RemoveDirIfEmpty`]): the gate's handle on the directory deletes
//!   it, non-recursively. A directory that has entries now is `Skipped{NoLongerEmpty}`.
//!
//! The same handle is open from the act-time gate check ([`gate::open_and_check_path`]) to the rename or
//! delete: nothing is reopened by path in between, and the destination is the directory handle the gate
//! checked ([`CheckedDest`]).
//!
//! # Outcomes
//!
//! | Condition | Result |
//! |---|---|
//! | not found when the acting handle is opened | `Vanished` (success) |
//! | sharing violation on the acting handle (or access denied on a directory), after 3 retries at 100, 300 and 1000 ms | [`LockedItem`] for the locked-file ladder (`locked.rs`), stage [`LockedStage::Open`], no intent |
//! | file id, volume serial, reparse state or kind changed since validation | `Skipped{ChangedSinceScan}` |
//! | any other gate refusal | `Skipped{GateBlocked{blocker}}` |
//! | the system refused the open (access denied on a file, ...) | `Failed{AccessDenied}` / `Failed{Os}` |
//! | volume serial 0 (unknown) | `Skipped{GateBlocked{CannotBackUp}}` |
//! | source volume cannot hold a quarantine, or the op directory is on another volume | `Skipped{GateBlocked{CannotBackUp}}` (never copied) |
//! | a directory whose tree the validation did not count | `Skipped{GateBlocked{HardLinkOutsidePlan}}` |
//! | moved and verified (handle at the destination, same file id, not at the source) | `Done` |
//! | directory rename refused while something below is open, after 3 retries | [`LockedItem`], stage [`LockedStage::Act`], intent written |
//! | rename refused as another volume / destination taken | `Skipped{GateBlocked{CannotBackUp}}` |
//! | directory not empty at the delete | `Skipped{NoLongerEmpty}` |
//! | the act ran but the verify does not hold | `Failed{VerifyFailed}` |
//!
//! # Journal contract
//!
//! This module never writes the journal. It returns values the executor journals, in the order
//! [`crate::journal`] fixes (the same shape as [`crate::act_typed`]):
//!
//! 0. Before: the executor wrote the op's journal `validated` record (or read it back on resume) and
//!    handed that record to `GateCtx::record`. Everything [`prepare_fs`] acts with (op, plan item, stamp,
//!    exemptions, recorded facts) comes from that record (`GateCtx::journalled`); an op id without one
//!    is `Failed{Internal}` and nothing is opened.
//! 1. [`prepare_fs`] runs the act-time gate (with the retries), creates the op's quarantine directory
//!    and checks the destination, and returns [`FsPrepared::Decided`] (journal it with
//!    `JournalWriter::done_without_intent`; every decided outcome passes
//!    `ItemOutcome::allowed_without_intent`), [`FsPrepared::Locked`] (hand it to the locked-file ladder,
//!    which writes its own intent if it acts), [`FsPrepared::Ready`], or a [`StorageError`] that concerns
//!    the whole run (abort with `StorageIntegrity` on [`StorageError::Integrity`]).
//! 2. For `Ready`, the executor writes [`FsAction::intent`] with `JournalWriter::intent` (the inverse
//!    carries the facts read from the acting handle), which returns the token after the flush, then hits
//!    `act.before`.
//! 3. [`act_fs`] takes the token as proof of the durable intent, renames or deletes, hits `act.after`,
//!    verifies, and returns [`FsActed::Finished`] (pass the outcome to `JournalWriter::done` with the
//!    token) or [`FsActed::Locked`] (the ladder decides; its outcome goes to `done` with the same token).
//!
//! No backup file is written for a file action (the item itself is the backup), so `backup.written` and
//! `backup.verified` are not hit here.
//!
//! # Undo
//!
//! The undo driver hands every `validated` record of the session to its `GateCtx::record` first; the
//! undo of an op is gated with the exemptions of that record (`GateCtx::exemptions`), and an op without
//! one is a conflict. [`plan_undo_fs`] decides from the journal alone ([`FsUndoPlan::Decided`]: journal with
//! `undo_done_without_intent` or `undo_conflict_without_intent`) or asks to run ([`FsUndoPlan::Run`]: the
//! undo driver writes `undo_intent`, then calls [`undo_fs`] with the token and journals the [`FsUndo`] with
//! `undo_done` or `undo_conflict`). The driver runs every `RecreateDir` inverse of the session first, in
//! reverse op order (parents before children), then the `MoveBack` inverses in reverse op order.
//!
//! - **Move back**: the op directory is opened through the store's checks, the quarantined item by handle
//!   with its file id and volume serial compared with the journal, the original path's parent checked
//!   by the gate ([`gate::check_undo_path`]), and the item renamed by handle into that checked directory
//!   under its original leaf. Nothing is overwritten: an occupied original path is
//!   `UndoConflict::DestinationExists`. No directory is created here; a missing parent is a conflict.
//! - **Recreate dir**: the directory is created with the recorded owner, group and DACL, then its
//!   recorded attributes are set through a handle on it. An existing plain directory is `AlreadyRestored`.
//!   Creation and last-write times are recorded in the inverse but cannot be set back (no API for it).

use std::fmt;
use std::path::Path;
use std::time::Duration;

use purge_guard::deny::Exemptions;
use purge_guard::live::{
    Binding, FileIdentity, PathStamp, Refusal, StoreOp, reason as live_reason,
};
use purge_guard::prefix;
use purge_model::exec::journal::{FileFacts, Intent, ItemFacts, UndoConflict, UndoOutcome};
use purge_model::exec::op::{ExecOp, FailCode, FileIdHex, Inverse, ItemOutcome, OpId, SkipReason};
use purge_model::{Blocker, CandidateId, FileTime};
use purge_win::fs::FileHandle;
use purge_win::fs_write::{
    CHANGEABLE_ATTRIBUTES, FsError, MoveHandle, create_dir_secure, extended_path,
};
use purge_win::os::Win32Error;

use crate::fault;
use crate::gate::{self, CheckedDest, CheckedPath, GateCtx, GateOutcome, LockedPath, Stamp};
use crate::journal::{IntentToken, UndoToken};
use crate::storage::{SessionDir, StorageError};

#[cfg(test)]
mod tests;

/// Codes of the refusals this module raises itself, reported as `DenyListed{rule: <code>}` the way the
/// gate reports refusals that have no dedicated blocker.
pub mod reason {
    /// The volume serial of the item's handle is 0, which means unknown: same volume cannot be proven.
    pub const SERIAL_UNKNOWN: &str = "act_fs.volume-serial-unknown";
    /// The original path's parent directory does not exist; `move_back` creates no directory.
    pub const UNDO_PARENT_MISSING: &str = "act_fs.undo-parent-missing";
    /// The journal's intent does not hang together (`Intent::is_consistent`).
    pub const INTENT_INCONSISTENT: &str = "act_fs.intent-inconsistent";
}

/// The waits between the attempts on an item in use (§7.5): three retries.
pub const RETRY_DELAYS: [Duration; 3] = [
    Duration::from_millis(100),
    Duration::from_millis(300),
    Duration::from_millis(1000),
];

/// `ERROR_INVALID_OWNER`: the recorded owner cannot be assigned by this token.
const ERROR_INVALID_OWNER: u32 = 1307;
/// `ERROR_INVALID_PRIMARY_GROUP`: the recorded group cannot be assigned by this token.
const ERROR_INVALID_PRIMARY_GROUP: u32 = 1308;

// ---------------------------------------------------------------------------------------------------
// Retries
// ---------------------------------------------------------------------------------------------------

/// How an item in use is retried: one wait per retry, and the function that waits. [`Retry::standard`]
/// is the §7.5 policy; tests inject a sleep that records the waits instead of sleeping.
pub struct Retry {
    delays: Vec<Duration>,
    sleep: Box<dyn Fn(Duration) + Send + Sync>,
}

impl Retry {
    /// Three retries after 100, 300 and 1000 ms ([`RETRY_DELAYS`]), sleeping the thread.
    pub fn standard() -> Retry {
        Retry::with(RETRY_DELAYS.to_vec(), std::thread::sleep)
    }

    /// One retry per entry of `delays`, each after `sleep(delay)`.
    pub fn with(delays: Vec<Duration>, sleep: impl Fn(Duration) + Send + Sync + 'static) -> Retry {
        Retry {
            delays,
            sleep: Box::new(sleep),
        }
    }

    /// The waits, one per retry.
    pub fn delays(&self) -> &[Duration] {
        &self.delays
    }

    /// Runs `attempt` until it returns `Ok` or the retries are used up, waiting before each retry.
    /// `attempt` returns `Err(value)` for "in use, try again"; the last result is returned with the number
    /// of attempts made.
    fn run<T, E>(&self, mut attempt: impl FnMut() -> Result<T, E>) -> (Result<T, E>, u32) {
        let mut tries = 1u32;
        let mut result = attempt();
        for delay in &self.delays {
            if result.is_ok() {
                break;
            }
            (self.sleep)(*delay);
            tries += 1;
            result = attempt();
        }
        (result, tries)
    }
}

impl Default for Retry {
    fn default() -> Retry {
        Retry::standard()
    }
}

impl fmt::Debug for Retry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Retry")
            .field("delays", &self.delays)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------------------------------

/// How a file action ended for one item, with a line for the report. The executor journals `outcome`;
/// `detail` says why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsResult {
    /// The outcome to journal.
    pub outcome: ItemOutcome,
    /// Why, for the report; may be empty for a plain success.
    pub detail: String,
}

impl FsResult {
    fn new(outcome: ItemOutcome, detail: impl Into<String>) -> FsResult {
        FsResult {
            outcome,
            detail: detail.into(),
        }
    }

    fn skipped(reason: SkipReason, detail: impl Into<String>) -> FsResult {
        FsResult::new(ItemOutcome::Skipped { reason }, detail)
    }

    fn blocked(blocker: Blocker, detail: impl Into<String>) -> FsResult {
        FsResult::skipped(SkipReason::GateBlocked { blocker }, detail)
    }

    fn failed(code: FailCode, os_error: Option<u32>, detail: impl Into<String>) -> FsResult {
        let detail = detail.into();
        FsResult {
            outcome: ItemOutcome::Failed {
                code,
                os_error,
                detail: detail.clone(),
            },
            detail,
        }
    }

    fn internal(detail: impl Into<String>) -> FsResult {
        FsResult::failed(FailCode::Internal, None, detail)
    }
}

/// A refusal raised by this module, as the gate spells refusals without a dedicated blocker.
fn rule(code: &str) -> Blocker {
    Blocker::DenyListed {
        rule: code.to_owned(),
    }
}

/// The failure code of a Win32 error: access denied, in use, or another OS error.
fn fail_code(code: u32) -> FailCode {
    match FsError::from(Win32Error(code)) {
        FsError::AccessDenied => FailCode::AccessDenied,
        FsError::SharingViolation => FailCode::InUse,
        _ => FailCode::Os,
    }
}

/// Act-time refusals that say the item is no longer what was validated: another object, a reparse
/// point now, another kind, a final path elsewhere. Validation passed the item, so these mean it changed.
const CHANGED_REASONS: &[&str] = &[
    live_reason::IDENTITY_CHANGED,
    live_reason::ITEM_IS_REPARSE_POINT,
    live_reason::FINAL_DIFFERS,
    live_reason::HANDLE_FACTS_CONTRADICT,
    live_reason::NOT_A_DIRECTORY,
    live_reason::NO_LINKS,
];

/// The result of a gate refusal: a soft refusal is `Skipped{ChangedSinceScan}`, a hard one
/// `Skipped{GateBlocked{blocker}}`. With `act_time`, the refusals that describe a changed identity,
/// reparse state or kind ([`CHANGED_REASONS`]) are `ChangedSinceScan` too.
fn refusal_to_result(refusal: &Refusal, act_time: bool) -> FsResult {
    let detail = format!("refused by the gate: {refusal}");
    if !refusal.is_hard() || (act_time && CHANGED_REASONS.contains(&refusal.reason)) {
        FsResult::skipped(SkipReason::ChangedSinceScan, detail)
    } else {
        FsResult::blocked(refusal.blocker.clone(), detail)
    }
}

/// The result of a gate outcome that is not a pass, for an item the executor journals without an intent
/// (`done_without_intent`): `Vanished`, a refusal (`Skipped{ChangedSinceScan}` for a soft refusal,
/// `Skipped{GateBlocked{blocker}}` otherwise) or `Failed`. `None` for `Pass` and `Locked` (a locked item
/// goes to the ladder). Use it for the validate pass; [`prepare_fs`] maps the act-time gate itself.
pub fn gate_result<T>(outcome: &GateOutcome<T>) -> Option<FsResult> {
    match outcome {
        GateOutcome::Pass(_) | GateOutcome::Locked(_) => None,
        GateOutcome::Vanished => Some(FsResult::new(ItemOutcome::Vanished, "the item is gone")),
        GateOutcome::Refused(refusal) => Some(refusal_to_result(refusal, false)),
        GateOutcome::Failed(e) => Some(FsResult::failed(
            fail_code(e.code()),
            Some(e.code()),
            format!("the item could not be opened: Win32 error {}", e.code()),
        )),
    }
}

/// Where a locked item was found locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockedStage {
    /// The acting handle could not be opened ([`prepare_fs`]). No intent is written for the op.
    Open,
    /// The handle was open and the intent written, but the rename or delete was refused as in use
    /// ([`act_fs`]): a directory with something open below it. The op's intent is durable; the ladder's
    /// outcome is journalled with the executor's token.
    Act,
}

/// An item still in use after the retries, with what the locked-file ladder (§7.6, `locked.rs`) needs. The
/// handle is closed; the ladder re-opens the item and gates it again when it acts.
#[derive(Debug, Clone)]
pub struct LockedItem {
    /// The op.
    pub op: OpId,
    /// The plan item.
    pub item: CandidateId,
    /// The executor op.
    pub exec_op: ExecOp,
    /// The item's path, as the plan names it.
    pub path: String,
    /// The facts a handle on the item gave (they passed the gate against the stamp), the stamp, and the
    /// last error (sharing or lock violation, or access denied on a directory).
    pub locked: LockedPath,
    /// How many attempts were made (1 + the retries).
    pub attempts: u32,
    /// Where it was locked.
    pub stage: LockedStage,
    /// For [`LockedStage::Act`] of a quarantine move: the quarantine path the intent's `MoveBack`
    /// records (its op directory exists and is empty). A boot-time move must go to exactly this path.
    pub quarantine_path: Option<String>,
}

impl LockedItem {
    /// Whether the op's intent is already in the journal.
    pub fn intent_written(&self) -> bool {
        self.stage == LockedStage::Act
    }
}

// ---------------------------------------------------------------------------------------------------
// Prepare
// ---------------------------------------------------------------------------------------------------

/// A file action that passed the act-time gate, holding the gate's handle on the item and, for a move, the
/// checked destination. Only [`prepare_fs`] makes one; [`act_fs`] consumes it.
#[derive(Debug)]
pub struct FsAction {
    intent: Intent,
    checked: CheckedPath,
    kind: ActKind,
}

#[derive(Debug)]
enum ActKind {
    Move { dest: CheckedDest },
    RemoveDir,
}

impl FsAction {
    /// The intent to journal before the act: the op, the inverse with the facts read from the acting
    /// handle ([`Inverse::MoveBack`] or [`Inverse::RecreateDir`]) and those facts as `pre`. It passes
    /// `Intent::is_consistent`.
    pub fn intent(&self) -> &Intent {
        &self.intent
    }

    /// For a quarantine move: the path the item will have in quarantine.
    pub fn quarantine_path(&self) -> Option<&str> {
        match &self.kind {
            ActKind::Move { dest } => Some(dest.path()),
            ActKind::RemoveDir => None,
        }
    }
}

/// What [`prepare_fs`] decided.
#[derive(Debug)]
pub enum FsPrepared {
    /// Decided without changing anything: journal with `done_without_intent`.
    Decided(FsResult),
    /// In use after the retries ([`LockedStage::Open`]): hand it to the locked-file ladder.
    Locked(Box<LockedItem>),
    /// Ready to act: journal [`FsAction::intent`], then call [`act_fs`] with its token.
    Ready(Box<FsAction>),
}

/// Whether two volume serials prove one volume: both known (0 means unknown) and equal.
fn same_volume(source: u64, destination: u64) -> Result<(), FsResult> {
    if source == 0 || destination == 0 {
        return Err(FsResult::blocked(
            Blocker::CannotBackUp,
            format!(
                "the volume serial is unknown (source {source:#x}, quarantine {destination:#x}); \
                 same volume cannot be proven ({})",
                reason::SERIAL_UNKNOWN
            ),
        ));
    }
    if source != destination {
        return Err(FsResult::blocked(
            Blocker::CannotBackUp,
            format!(
                "the item is on volume {source:#x}, its quarantine on {destination:#x}; items are never \
                 copied across volumes"
            ),
        ));
    }
    Ok(())
}

/// The plain form of a `\\?\C:\...` path; anything else unchanged.
fn strip_verbatim(path: &str) -> &str {
    match path.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest,
        _ => path,
    }
}

/// Runs the act-time gate for op `op` until it is not locked or the retries are used up.
fn gate_with_retry(ctx: &GateCtx, op: OpId, retry: &Retry) -> (GateOutcome<CheckedPath>, u32) {
    let (result, attempts) = retry.run(|| match gate::open_and_check_path(ctx, op) {
        GateOutcome::Locked(locked) => Err(Box::new(locked)),
        other => Ok(other),
    });
    match result {
        Ok(outcome) => (outcome, attempts),
        Err(locked) => (GateOutcome::Locked(*locked), attempts),
    }
}

/// Decides whether op `op` may act on its file-system item, and gets everything ready that must exist
/// before its intent: the gate's acting handle, the op's quarantine directory (for a move) and the inverse
/// with the facts recorded from that handle. Changes nothing outside Purge's store.
///
/// The op, its plan item, its stamp, its exemptions, its blast-radius limit and its recorded facts are
/// those of its journal `validated` record, handed to `GateCtx::record` before
/// ([`GateCtx::journalled`]); an op id without a record is `Failed{Internal}`. A sharing violation on the
/// acting handle is retried per `retry`.
///
/// Returns `Err` only for a store failure that concerns the whole run (integrity, I/O on the data root,
/// an op directory that already exists); a volume the store cannot quarantine on is a decided skip.
pub fn prepare_fs(
    ctx: &GateCtx,
    session: &SessionDir,
    op: OpId,
    retry: &Retry,
) -> Result<FsPrepared, StorageError> {
    let decided = |r: FsResult| Ok(FsPrepared::Decided(r));
    let Some((exec_op, record)) = ctx.journalled(op) else {
        return decided(FsResult::internal(format!(
            "op {op} has no journalled validated record in this run; nothing done"
        )));
    };
    let item = &record.item;
    let (path, is_move) = match exec_op {
        ExecOp::QuarantineMove { path } => (path.as_str(), true),
        ExecOp::RemoveDirIfEmpty { path } => (path.as_str(), false),
        other => {
            return decided(FsResult::internal(format!(
                "{} is not a file action; nothing done",
                other.name()
            )));
        }
    };
    let Some(Stamp::Path(stamp)) = ctx.stamp(op) else {
        return decided(FsResult::internal(format!(
            "the validation of {path} is not a file-system stamp; nothing done"
        )));
    };
    // A directory moves whole only when the validation counted the tree below it.
    if is_move && stamp.is_dir {
        let counted = matches!(
            &record.facts,
            ItemFacts::File(FileFacts {
                is_dir: true,
                reparse_tag: 0,
                tree_entries: Some(_),
                ..
            })
        );
        if !counted {
            return decided(FsResult::blocked(
                Blocker::HardLinkOutsidePlan,
                format!("the tree below {path} was not counted at validation; not moved whole"),
            ));
        }
    }

    let (outcome, attempts) = gate_with_retry(ctx, op, retry);
    let checked = match outcome {
        GateOutcome::Pass(checked) => checked,
        GateOutcome::Vanished => {
            return decided(FsResult::new(
                ItemOutcome::Vanished,
                format!("{path} is gone"),
            ));
        }
        GateOutcome::Locked(locked) => {
            return Ok(FsPrepared::Locked(Box::new(LockedItem {
                op,
                item: item.clone(),
                exec_op: exec_op.clone(),
                path: path.to_owned(),
                locked,
                attempts,
                stage: LockedStage::Open,
                quarantine_path: None,
            })));
        }
        GateOutcome::Refused(refusal) => return decided(refusal_to_result(&refusal, true)),
        GateOutcome::Failed(e) => {
            return decided(FsResult::failed(
                fail_code(e.code()),
                Some(e.code()),
                format!(
                    "{path} could not be opened to act on: Win32 error {}",
                    e.code()
                ),
            ));
        }
    };

    let serial = checked.stamp().identity.volume_serial;
    if serial == 0 {
        return decided(FsResult::blocked(
            Blocker::CannotBackUp,
            format!(
                "the handle on {path} reports volume serial 0 (unknown) ({})",
                reason::SERIAL_UNKNOWN
            ),
        ));
    }
    if is_move
        && checked.stamp().is_dir
        && !checked.facts().tree.as_ref().is_some_and(|t| t.complete)
    {
        return decided(FsResult::blocked(
            Blocker::HardLinkOutsidePlan,
            format!("the tree below {path} was not walked completely; not moved whole"),
        ));
    }

    let (inverse, kind) = if is_move {
        match quarantine_destination(ctx, session, op, path, &checked)? {
            Ok(found) => found,
            Err(result) => return decided(result),
        }
    } else {
        let meta = checked.meta();
        let Some(security) = checked.security() else {
            return decided(FsResult::blocked(
                Blocker::CannotBackUp,
                format!(
                    "the security descriptor of {path} cannot be read, so it cannot be recreated"
                ),
            ));
        };
        (
            Inverse::RecreateDir {
                path: path.to_owned(),
                attributes: meta.attributes,
                sddl: security.sddl.clone(),
                creation_time: Some(FileTime(meta.creation_time)),
                last_write_time: Some(FileTime(meta.last_write_time)),
            },
            ActKind::RemoveDir,
        )
    };
    let intent = Intent {
        op,
        item: item.clone(),
        exec_op: exec_op.clone(),
        inverse,
        definition: None,
        pre: ItemFacts::File(checked.file_facts().clone()),
    };
    if !intent.is_consistent() {
        return decided(FsResult::internal(format!(
            "the intent built for {path} does not hang together; nothing done"
        )));
    }
    Ok(FsPrepared::Ready(Box::new(FsAction {
        intent,
        checked,
        kind,
    })))
}

/// Creates the op's quarantine directory on the item's volume and checks the destination in it. The
/// outer `Err` is a store failure for the run, the inner one a decided skip.
#[allow(clippy::type_complexity)]
fn quarantine_destination(
    ctx: &GateCtx,
    session: &SessionDir,
    op: OpId,
    path: &str,
    checked: &CheckedPath,
) -> Result<Result<(Inverse, ActKind), FsResult>, StorageError> {
    let stamp = checked.stamp();
    let Some(leaf) = Path::new(path).file_name().and_then(|l| l.to_str()) else {
        return Ok(Err(FsResult::internal(format!(
            "{path} has no leaf name to quarantine under; nothing done"
        ))));
    };
    let quarantine = match session.create_op_dir(Path::new(path), stamp.identity.volume_serial, op)
    {
        Ok(dir) => dir,
        Err(StorageError::CannotBackUp { reason, .. }) => {
            return Ok(Err(FsResult::blocked(
                Blocker::CannotBackUp,
                format!("{path} cannot be quarantined on its volume: {reason}"),
            )));
        }
        Err(e) => return Err(e),
    };
    if let Err(result) = same_volume(stamp.identity.volume_serial, quarantine.volume_serial()) {
        return Ok(Err(result));
    }
    let dest = match gate::check_quarantine_destination(ctx, checked, &quarantine, leaf) {
        Ok(dest) => dest,
        Err(refusal) => return Ok(Err(refusal_to_result(&refusal, false))),
    };
    let inverse = Inverse::MoveBack {
        quarantine_path: dest.path().to_owned(),
        original_path: path.to_owned(),
        file_id: FileIdHex(stamp.identity.file_id),
        volume_serial: stamp.identity.volume_serial,
    };
    Ok(Ok((inverse, ActKind::Move { dest })))
}

// ---------------------------------------------------------------------------------------------------
// Act and verify
// ---------------------------------------------------------------------------------------------------

/// How [`act_fs`] ended.
#[derive(Debug)]
pub enum FsActed {
    /// The act ran (or was refused without a change) and was verified: journal `done` with the token.
    Finished(FsResult),
    /// In use after the retries ([`LockedStage::Act`]): the ladder decides; journal its outcome with the
    /// token.
    Locked(Box<LockedItem>),
}

/// Whether an error of the rename or delete may mean "in use" (retried, then the ladder).
fn in_use(error: FsError, is_dir: bool) -> bool {
    gate::may_be_in_use(error, is_dir)
}

/// The result of a rename into quarantine that the system refused; nothing was changed.
fn rename_failure(error: FsError, path: &str) -> FsResult {
    match error {
        FsError::NotSameDevice => FsResult::blocked(
            Blocker::CannotBackUp,
            format!("{path} is on another volume than its quarantine; never copied"),
        ),
        FsError::AlreadyExists => FsResult::blocked(
            Blocker::CannotBackUp,
            format!("the quarantine name for {path} was taken after the check; nothing replaced"),
        ),
        FsError::WrongKind => FsResult::internal(format!(
            "the quarantine directory of {path} is not a plain directory; nothing done"
        )),
        e => FsResult::failed(
            fail_code(e.code()),
            Some(e.code()),
            format!("moving {path} into quarantine failed: {e}"),
        ),
    }
}

/// Performs the action of `action`, whose intent `token` proves durable, then hits `act.after` and
/// verifies. The executor hits `act.before` before the call. A token of another op is
/// `Failed{Internal}` and nothing is done.
///
/// A move renames the gate's handle into the checked quarantine directory; a sharing violation, or for a
/// directory an access denial (something open below it), is retried per `retry` on the same handle and
/// then returned as [`FsActed::Locked`]. A remove deletes the directory through the gate's handle,
/// non-recursively.
///
/// Verify: after a move the handle (which follows the object) must be at the quarantine path with the
/// recorded file id, and the original path must not hold the item; after a remove the handle is closed
/// first and the path must not hold the directory. Otherwise `Failed{VerifyFailed}`.
pub fn act_fs(action: Box<FsAction>, token: &IntentToken, retry: &Retry) -> FsActed {
    let FsAction {
        intent,
        checked,
        kind,
    } = *action;
    let path = checked.path().to_owned();
    if token.op() != intent.op || token.item() != &intent.item {
        return FsActed::Finished(FsResult::internal(format!(
            "the intent token is for op {}, not op {}; {path} left untouched",
            token.op(),
            intent.op
        )));
    }
    let stamp = checked.stamp();
    let is_dir = stamp.is_dir;
    match kind {
        ActKind::Move { dest } => {
            let (result, attempts) =
                retry.run(
                    || match checked.handle().rename_into(dest.dir(), dest.leaf()) {
                        Err(e) if in_use(e, is_dir) => Err(e),
                        other => Ok(other),
                    },
                );
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return FsActed::Finished(rename_failure(e, &path)),
                Err(e) => {
                    return FsActed::Locked(Box::new(LockedItem {
                        op: intent.op,
                        item: intent.item.clone(),
                        exec_op: intent.exec_op.clone(),
                        path,
                        locked: LockedPath {
                            facts: checked.facts().clone(),
                            stamp,
                            error: Win32Error(e.code()),
                        },
                        attempts,
                        stage: LockedStage::Act,
                        quarantine_path: Some(dest.path().to_owned()),
                    }));
                }
            }
            fault::point(fault::ACT_AFTER);
            FsActed::Finished(verify_moved(&checked, &dest, &path))
        }
        ActKind::RemoveDir => {
            let (result, attempts) = retry.run(|| match checked.handle().remove_dir_if_empty() {
                Err(e) if in_use(e, false) => Err(e),
                other => Ok(other),
            });
            match result {
                Ok(Ok(())) => {}
                Ok(Err(FsError::DirNotEmpty)) => {
                    return FsActed::Finished(FsResult::skipped(
                        SkipReason::NoLongerEmpty,
                        format!("{path} has entries now; left in place"),
                    ));
                }
                Ok(Err(FsError::WrongKind)) => {
                    return FsActed::Finished(FsResult::skipped(
                        SkipReason::ChangedSinceScan,
                        format!("{path} is no longer a plain directory; left in place"),
                    ));
                }
                Ok(Err(e)) => {
                    return FsActed::Finished(FsResult::failed(
                        fail_code(e.code()),
                        Some(e.code()),
                        format!("removing {path} failed: {e}"),
                    ));
                }
                Err(e) => {
                    return FsActed::Locked(Box::new(LockedItem {
                        op: intent.op,
                        item: intent.item.clone(),
                        exec_op: intent.exec_op.clone(),
                        path,
                        locked: LockedPath {
                            facts: checked.facts().clone(),
                            stamp,
                            error: Win32Error(e.code()),
                        },
                        attempts,
                        stage: LockedStage::Act,
                        quarantine_path: None,
                    }));
                }
            }
            fault::point(fault::ACT_AFTER);
            // Without POSIX delete semantics the name goes only when the last handle closes.
            drop(checked);
            FsActed::Finished(verify_gone(&path, stamp.identity, "removed"))
        }
    }
}

/// Verify after a move: the handle is at the destination with the recorded identity, and the source path
/// does not hold the item.
fn verify_moved(checked: &CheckedPath, dest: &CheckedDest, path: &str) -> FsResult {
    let stamp = checked.stamp();
    let at = checked.handle().final_path();
    let id = checked.handle().file_id();
    let at_destination = at
        .as_deref()
        .is_ok_and(|p| prefix::is_same(strip_verbatim(p), dest.path()));
    let same_id = id.is_ok_and(|id| {
        id.volume_serial == stamp.identity.volume_serial && id.id == stamp.identity.file_id
    });
    if !(at_destination && same_id) {
        return FsResult::failed(
            FailCode::VerifyFailed,
            None,
            format!(
                "after the move, the item of {path} is not at {} with its recorded file id (it is at \
                 {at:?})",
                dest.path()
            ),
        );
    }
    verify_gone(path, stamp.identity, "moved")
}

/// Verify that `path` no longer holds the object `identity`: not found, or another object.
fn verify_gone(path: &str, identity: FileIdentity, what: &str) -> FsResult {
    let Ok(p) = extended_path(Path::new(path)) else {
        return FsResult::internal(format!("{path} has no \\\\?\\ form; cannot verify"));
    };
    match FileHandle::open(&p) {
        Err(e) if e.is_not_found() => FsResult::new(ItemOutcome::Done, ""),
        Ok(handle) => match handle.file_id() {
            Ok(id) if id.volume_serial == identity.volume_serial && id.id == identity.file_id => {
                FsResult::failed(
                    FailCode::VerifyFailed,
                    None,
                    format!("{path} was {what}, but the same object is still there"),
                )
            }
            Ok(_) => FsResult::new(
                ItemOutcome::Done,
                format!("{path} was {what}; another object has that name now"),
            ),
            Err(e) => FsResult::failed(
                FailCode::VerifyFailed,
                Some(e.code()),
                format!("{path} was {what}, but what is there now cannot be identified"),
            ),
        },
        Err(e) => FsResult::failed(
            FailCode::VerifyFailed,
            Some(e.code()),
            format!("{path} was {what}, but whether it is gone cannot be checked"),
        ),
    }
}

// ---------------------------------------------------------------------------------------------------
// Undo
// ---------------------------------------------------------------------------------------------------

/// How the undo of a file op ended, as a record, never an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsUndo {
    /// An outcome: `undo_done` (with the token when [`undo_fs`] ran, `undo_done_without_intent` from
    /// [`plan_undo_fs`], which only decides `NothingToUndo` or `AlreadyRestored`).
    Done {
        /// The outcome to journal.
        outcome: UndoOutcome,
        /// Why, for the report; may be empty.
        detail: String,
    },
    /// The inverse was not applied: `undo_conflict` (with the token when [`undo_fs`] ran,
    /// `undo_conflict_without_intent` from [`plan_undo_fs`]). Nothing was changed.
    Conflict {
        /// What stood in the way.
        conflict: UndoConflict,
        /// Text for the report.
        detail: String,
    },
}

impl FsUndo {
    fn done(outcome: UndoOutcome, detail: impl Into<String>) -> FsUndo {
        FsUndo::Done {
            outcome,
            detail: detail.into(),
        }
    }

    fn conflict(conflict: UndoConflict, detail: impl Into<String>) -> FsUndo {
        FsUndo::Conflict {
            conflict,
            detail: detail.into(),
        }
    }

    fn blocked(blocker: Blocker, detail: impl Into<String>) -> FsUndo {
        FsUndo::conflict(UndoConflict::GateBlocked { blocker }, detail)
    }

    fn failed(code: FailCode, os_error: Option<u32>, detail: impl Into<String>) -> FsUndo {
        let detail = detail.into();
        FsUndo::done(
            UndoOutcome::Failed {
                code,
                os_error,
                detail: detail.clone(),
            },
            detail,
        )
    }
}

/// One inverse to run, decided from the journal by [`plan_undo_fs`]. Only [`undo_fs`] consumes it.
#[derive(Debug, Clone)]
pub struct FsUndoJob {
    op: OpId,
    kind: UndoKind,
}

#[derive(Debug, Clone)]
enum UndoKind {
    MoveBack {
        quarantine_path: String,
        original_path: String,
        stamp: PathStamp,
    },
    RecreateDir {
        path: String,
        attributes: u32,
        sddl: String,
        volume_serial: u64,
    },
}

impl FsUndoJob {
    /// The op being undone.
    pub fn op(&self) -> OpId {
        self.op
    }

    /// Whether the job recreates a directory (the undo driver runs those first, in reverse op order).
    pub fn is_recreate_dir(&self) -> bool {
        matches!(self.kind, UndoKind::RecreateDir { .. })
    }
}

/// What [`plan_undo_fs`] decided.
#[derive(Debug, Clone)]
pub enum FsUndoPlan {
    /// Decided from the journal: journal without an undo intent.
    Decided(FsUndo),
    /// Write `undo_intent`, then call [`undo_fs`] with the token.
    Run(FsUndoJob),
}

/// The undo of a file op, decided from its journal records alone. `intent` is the op's intent, `done` its
/// `done` outcome or `None` when the journal holds only the intent (the run stopped during the act).
/// `None` for an op that is not a file op. The exemptions the inverse is gated with are not taken here:
/// [`undo_fs`] takes those of the op's journalled `validated` record from its `GateCtx`.
///
/// - An outcome that left the system unchanged (`Vanished`, `Skipped`, `HeldRetry`, `Failed` with any
///   code but `VerifyFailed`) is `NothingToUndo`.
/// - An intent that does not hang together, or a recorded volume serial of 0, is a conflict.
/// - Everything else (`Done`, `VerifyFailed`, `PendingReboot`, intent only) runs the inverse. For
///   `PendingReboot` the driver first has the locked-file ladder take back the registered pair; if the
///   boot-time move already happened the item is in quarantine and is moved back, if not the original
///   still holds it and the undo ends `AlreadyRestored`.
pub fn plan_undo_fs(intent: &Intent, done: Option<&ItemOutcome>) -> Option<FsUndoPlan> {
    let is_move = match &intent.exec_op {
        ExecOp::QuarantineMove { .. } => true,
        ExecOp::RemoveDirIfEmpty { .. } => false,
        _ => return None,
    };
    let unchanged = match done {
        Some(ItemOutcome::Failed { code, .. }) => *code != FailCode::VerifyFailed,
        Some(ItemOutcome::PendingReboot { .. }) => false,
        Some(outcome) => !outcome.changed_system(),
        None => false,
    };
    if unchanged {
        return Some(FsUndoPlan::Decided(FsUndo::done(
            UndoOutcome::NothingToUndo,
            "the op changed nothing",
        )));
    }
    let inconsistent = || {
        Some(FsUndoPlan::Decided(FsUndo::blocked(
            rule(reason::INTENT_INCONSISTENT),
            format!(
                "the intent of op {} does not hang together; nothing done",
                intent.op
            ),
        )))
    };
    let (ItemFacts::File(pre), true) = (&intent.pre, intent.is_consistent()) else {
        return inconsistent();
    };
    let serial_unknown = || {
        Some(FsUndoPlan::Decided(FsUndo::blocked(
            Blocker::CannotBackUp,
            format!(
                "the journal records volume serial 0 (unknown) for op {}; same volume cannot be proven \
                 ({})",
                intent.op,
                reason::SERIAL_UNKNOWN
            ),
        )))
    };
    let kind = match (&intent.inverse, is_move) {
        (
            Inverse::MoveBack {
                quarantine_path,
                original_path,
                file_id,
                volume_serial,
            },
            true,
        ) => {
            if *volume_serial == 0 {
                return serial_unknown();
            }
            UndoKind::MoveBack {
                quarantine_path: quarantine_path.clone(),
                original_path: original_path.clone(),
                stamp: PathStamp {
                    identity: FileIdentity {
                        volume_serial: *volume_serial,
                        file_id: file_id.0,
                    },
                    is_dir: pre.is_dir,
                },
            }
        }
        (
            Inverse::RecreateDir {
                path,
                attributes,
                sddl,
                ..
            },
            false,
        ) => {
            if pre.volume_serial == 0 {
                return serial_unknown();
            }
            UndoKind::RecreateDir {
                path: path.clone(),
                attributes: *attributes,
                sddl: sddl.clone(),
                volume_serial: pre.volume_serial,
            }
        }
        _ => return inconsistent(),
    };
    Some(FsUndoPlan::Run(FsUndoJob {
        op: intent.op,
        kind,
    }))
}

/// Runs the inverse of `job`, whose `undo_intent` `token` proves durable, and hits `undo.act.after` after
/// the inverse changed something. Returns `Err` only for a store integrity failure, which concerns the
/// whole undo run; every outcome of the item is an [`FsUndo`]. A token of another op is
/// `Failed{Internal}` and nothing is done.
///
/// The original path is checked ([`gate::check_undo_path`]) with the exemptions of the op's journalled
/// `validated` record, which the undo driver handed to `ctx` (`GateCtx::record`); an op without one is a
/// conflict ([`gate::reason::NOT_VALIDATED`]) and nothing is done.
pub fn undo_fs(
    ctx: &GateCtx,
    session: &SessionDir,
    job: FsUndoJob,
    retry: &Retry,
    token: &UndoToken,
) -> Result<FsUndo, StorageError> {
    if token.op() != job.op {
        return Ok(FsUndo::failed(
            FailCode::Internal,
            None,
            format!(
                "the undo token is for op {}, not op {}; nothing done",
                token.op(),
                job.op
            ),
        ));
    }
    let FsUndoJob { op, kind } = job;
    let Some(exemptions) = ctx.exemptions(op) else {
        return Ok(FsUndo::blocked(
            rule(gate::reason::NOT_VALIDATED),
            format!("op {op} has no journalled validated record in this undo run; nothing done"),
        ));
    };
    match kind {
        UndoKind::MoveBack {
            quarantine_path,
            original_path,
            stamp,
        } => move_back(
            ctx,
            session,
            op,
            &quarantine_path,
            &original_path,
            stamp,
            exemptions,
            retry,
        ),
        UndoKind::RecreateDir {
            path,
            attributes,
            sddl,
            volume_serial,
        } => Ok(recreate_dir(
            ctx,
            &path,
            attributes,
            &sddl,
            volume_serial,
            exemptions,
        )),
    }
}

/// What a path holds now, opened without following a final reparse point.
enum PathNow {
    Missing,
    Object {
        identity: Option<FileIdentity>,
        plain_dir: bool,
    },
    Unknown(Win32Error),
}

fn look_at(path: &str) -> PathNow {
    let Ok(p) = extended_path(Path::new(path)) else {
        return PathNow::Unknown(Win32Error::INVALID_PARAMETER);
    };
    match FileHandle::open(&p) {
        Err(e) if e.is_not_found() => PathNow::Missing,
        Err(e) => PathNow::Unknown(e),
        Ok(handle) => {
            let meta = handle.metadata().ok();
            PathNow::Object {
                identity: meta.as_ref().map(|m| FileIdentity {
                    volume_serial: m.file_id.volume_serial,
                    file_id: m.file_id.id,
                }),
                plain_dir: meta.is_some_and(|m| m.is_dir && m.reparse_tag == 0),
            }
        }
    }
}

/// The conflict for a missing parent of `path`, if it is missing.
fn parent_missing(path: &str) -> Option<FsUndo> {
    let parent = prefix::parent(path)?;
    matches!(look_at(parent), PathNow::Missing).then(|| {
        FsUndo::blocked(
            rule(reason::UNDO_PARENT_MISSING),
            format!(
                "the parent directory {parent} of {path} does not exist; it is recreated only by a \
                 RecreateDir inverse of this session, which must run first"
            ),
        )
    })
}

/// The undo conflict for a refusal of the gate's undo-destination check.
fn undo_refusal(refusal: &Refusal, path: &str) -> FsUndo {
    let detail = format!("restoring {path} was refused: {refusal}");
    match refusal.reason {
        live_reason::UNDO_OCCUPIED => FsUndo::conflict(UndoConflict::DestinationExists, detail),
        live_reason::UNDO_OTHER_VOLUME => FsUndo::blocked(Blocker::CannotBackUp, detail),
        _ => FsUndo::blocked(refusal.blocker.clone(), detail),
    }
}

/// The quarantined item is missing: already back at the original path, or a conflict.
fn quarantine_missing(original: &str, stamp: PathStamp, detail: &str) -> FsUndo {
    match look_at(original) {
        PathNow::Object {
            identity: Some(id), ..
        } if id == stamp.identity => FsUndo::done(
            UndoOutcome::AlreadyRestored,
            format!("{original} already holds the recorded item"),
        ),
        _ => FsUndo::conflict(UndoConflict::QuarantineMissing, detail.to_owned()),
    }
}

/// Moves a quarantined item back to its original path (the inverse of a quarantine move).
#[allow(clippy::too_many_arguments)]
fn move_back(
    ctx: &GateCtx,
    session: &SessionDir,
    op: OpId,
    quarantine_path: &str,
    original: &str,
    stamp: PathStamp,
    exemptions: Exemptions,
    retry: &Retry,
) -> Result<FsUndo, StorageError> {
    let serial = stamp.identity.volume_serial;
    // The op directory, through the store's checks; it is held open until the rename is done.
    let _op_dir = match session.open_op_dir(Path::new(quarantine_path), op, serial) {
        Ok(found) => found,
        Err(StorageError::VolumeMismatch {
            expected, actual, ..
        }) => {
            return Ok(FsUndo::conflict(
                UndoConflict::FileIdMismatch,
                format!(
                    "the quarantine of op {op} is on volume {actual:#x}, the journal recorded \
                     {expected:#x}"
                ),
            ));
        }
        Err(StorageError::Io {
            source: FsError::NotFound,
            ..
        }) => {
            return Ok(quarantine_missing(
                original,
                stamp,
                &format!("the quarantine directory of op {op} is missing"),
            ));
        }
        Err(e @ StorageError::Integrity { .. }) => return Err(e),
        Err(e) => {
            return Ok(FsUndo::failed(
                FailCode::Os,
                None,
                format!("the quarantine directory of op {op} cannot be opened: {e}"),
            ));
        }
    };

    // The quarantined item, by handle, bound to the recorded identity and kind.
    let (opened, _) = retry.run(|| {
        match gate::open_store_item(
            ctx,
            quarantine_path,
            StoreOp::MoveBack,
            Binding::Recheck(&stamp),
            serial,
            false,
        ) {
            GateOutcome::Failed(e) if fail_code(e.code()) == FailCode::InUse => Err(e),
            other => Ok(other),
        }
    });
    let item = match opened.unwrap_or_else(GateOutcome::Failed) {
        GateOutcome::Pass(item) => item,
        GateOutcome::Vanished => {
            return Ok(quarantine_missing(
                original,
                stamp,
                &format!("{quarantine_path} is missing"),
            ));
        }
        GateOutcome::Refused(refusal) if !refusal.is_hard() => {
            return Ok(FsUndo::conflict(
                UndoConflict::FileIdMismatch,
                format!("{quarantine_path} is not the recorded item: {refusal}"),
            ));
        }
        GateOutcome::Refused(refusal) => {
            return Ok(FsUndo::blocked(
                refusal.blocker.clone(),
                format!("{quarantine_path} was refused: {refusal}"),
            ));
        }
        GateOutcome::Failed(e) => {
            return Ok(FsUndo::failed(
                fail_code(e.code()),
                Some(e.code()),
                format!(
                    "{quarantine_path} could not be opened: Win32 error {}",
                    e.code()
                ),
            ));
        }
        GateOutcome::Locked(_) => {
            return Ok(FsUndo::failed(
                FailCode::InUse,
                None,
                format!("{quarantine_path} is in use"),
            ));
        }
    };

    if let Some(conflict) = parent_missing(original) {
        return Ok(conflict);
    }
    let dest = match gate::check_undo_path(ctx, original, serial, exemptions) {
        Ok(dest) => dest,
        Err(refusal) => return Ok(undo_refusal(&refusal, original)),
    };
    let (result, _) = retry.run(
        || match item.handle().rename_into(dest.dir(), dest.leaf()) {
            Err(e) if in_use(e, stamp.is_dir) => Err(e),
            other => Ok(other),
        },
    );
    match result.unwrap_or_else(Err) {
        Ok(()) => {}
        Err(FsError::AlreadyExists) => {
            return Ok(FsUndo::conflict(
                UndoConflict::DestinationExists,
                format!("{original} was taken before the item could go back; nothing overwritten"),
            ));
        }
        Err(FsError::NotSameDevice) => {
            return Ok(FsUndo::blocked(
                Blocker::CannotBackUp,
                format!("{original} is on another volume than the quarantined item"),
            ));
        }
        Err(e) if in_use(e, stamp.is_dir) => {
            return Ok(FsUndo::failed(
                FailCode::InUse,
                Some(e.code()),
                format!("{quarantine_path} stayed in use; not moved back"),
            ));
        }
        Err(e) => {
            return Ok(FsUndo::failed(
                fail_code(e.code()),
                Some(e.code()),
                format!("moving {quarantine_path} back to {original} failed: {e}"),
            ));
        }
    }
    fault::point(fault::UNDO_ACT_AFTER);

    // Verify: the handle follows the item; it must be at the original path with the recorded id.
    let at = item.handle().final_path();
    let back = at
        .as_deref()
        .is_ok_and(|p| prefix::is_same(strip_verbatim(p), original));
    let same = item.handle().file_id().is_ok_and(|id| {
        id.volume_serial == stamp.identity.volume_serial && id.id == stamp.identity.file_id
    });
    Ok(if back && same {
        FsUndo::done(UndoOutcome::Restored, "")
    } else {
        FsUndo::failed(
            FailCode::VerifyFailed,
            None,
            format!("after the move back the item is at {at:?}, not at {original}"),
        )
    })
}

/// `sddl` without its owner (`O:`) and group (`G:`) parts, for a token that cannot assign them.
fn without_owner_and_group(sddl: &str) -> String {
    let mut out = String::with_capacity(sddl.len());
    let mut depth = 0u32;
    let mut skipping = false;
    let bytes = sddl.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if depth == 0 && bytes.get(i + 1) == Some(&b':') && matches!(c, b'O' | b'G' | b'D' | b'S') {
            skipping = matches!(c, b'O' | b'G');
        }
        match c {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if !skipping {
            out.push(c as char);
        }
        i += 1;
    }
    out
}

/// Recreates a removed directory (the inverse of remove-dir-if-empty).
fn recreate_dir(
    ctx: &GateCtx,
    path: &str,
    attributes: u32,
    sddl: &str,
    volume_serial: u64,
    exemptions: Exemptions,
) -> FsUndo {
    match look_at(path) {
        PathNow::Missing => {}
        PathNow::Object {
            plain_dir: true, ..
        } => {
            return FsUndo::done(
                UndoOutcome::AlreadyRestored,
                format!("{path} exists as a directory"),
            );
        }
        PathNow::Object { .. } => {
            return FsUndo::conflict(
                UndoConflict::DestinationExists,
                format!("{path} exists and is not a plain directory; nothing changed"),
            );
        }
        PathNow::Unknown(e) => {
            return FsUndo::failed(
                fail_code(e.code()),
                Some(e.code()),
                format!("what {path} holds now cannot be read"),
            );
        }
    }
    if let Some(conflict) = parent_missing(path) {
        return conflict;
    }
    let dest = match gate::check_undo_path(ctx, path, volume_serial, exemptions) {
        Ok(dest) => dest,
        Err(refusal) => return undo_refusal(&refusal, path),
    };
    let Ok(p) = extended_path(Path::new(path)) else {
        return FsUndo::failed(
            FailCode::Internal,
            None,
            format!("{path} has no \\\\?\\ form"),
        );
    };
    let mut note = String::new();
    let created = match create_dir_secure(&p, sddl) {
        Err(FsError::Other(code @ (ERROR_INVALID_OWNER | ERROR_INVALID_PRIMARY_GROUP))) => {
            // The token cannot assign the recorded owner or group, and Purge never raises its access:
            // the directory gets the token's defaults and the recorded DACL.
            note = format!(
                "the recorded owner or group cannot be assigned (Win32 error {code}); the directory has \
                 the default owner and group"
            );
            create_dir_secure(&p, &without_owner_and_group(sddl))
        }
        other => other,
    };
    match created {
        Ok(()) => {}
        Err(FsError::AlreadyExists) => {
            return FsUndo::conflict(
                UndoConflict::DestinationExists,
                format!("{path} was taken before it could be recreated; nothing changed"),
            );
        }
        Err(e) => {
            return FsUndo::failed(
                fail_code(e.code()),
                Some(e.code()),
                format!("recreating {path} failed: {e}"),
            );
        }
    }
    fault::point(fault::UNDO_ACT_AFTER);

    // The creation went by path: check that it landed in the directory the gate checked.
    let handle = match MoveHandle::open_with_attribute_write(&p) {
        Ok(handle) => handle,
        Err(e) => {
            return FsUndo::failed(
                FailCode::VerifyFailed,
                Some(e.code()),
                format!("{path} was created but cannot be opened again: {e}"),
            );
        }
    };
    let parent_now = dest.dir().as_file().final_path().ok();
    let expected = parent_now.as_deref().map(|parent| {
        format!(
            r"{}\{}",
            strip_verbatim(parent).trim_end_matches('\\'),
            dest.leaf()
        )
    });
    let landed = handle.final_path().ok();
    let plain = handle
        .metadata()
        .is_ok_and(|m| m.is_dir && m.reparse_tag == 0);
    let in_place = matches!(
        (&landed, &expected),
        (Some(landed), Some(expected)) if prefix::is_same(strip_verbatim(landed), expected)
            && prefix::is_same(expected, path)
    );
    if !(plain && in_place) {
        // Purge's own new, empty directory in the wrong place: take it away again.
        let removed = handle.remove_dir_if_empty().is_ok();
        return FsUndo::blocked(
            Blocker::ReparseMismatch,
            format!(
                "{path} was created at {landed:?}, not in the checked parent directory; {}",
                if removed {
                    "it was removed again"
                } else {
                    "it could not be removed again"
                }
            ),
        );
    }
    let wanted = attributes & CHANGEABLE_ATTRIBUTES;
    if wanted != 0 {
        if let Err(e) = handle.set_attributes(wanted, 0) {
            return FsUndo::failed(
                fail_code(e.code()),
                Some(e.code()),
                format!("{path} was recreated, but its attributes could not be set: {e}"),
            );
        }
    }
    FsUndo::done(UndoOutcome::Restored, note)
}
