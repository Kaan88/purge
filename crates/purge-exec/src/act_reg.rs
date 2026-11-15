//! Registry actions and their inverses (M2-X-REG; ENGINE_PLAN.md §5.10, §7.4, §7.5, §7.8).
//!
//! This module is the glue between an [`ExecOp`] on the registry and the primitives of
//! [`crate::regbackup`]: it gates the item on the handle it acts on, backs it up, hands the executor the
//! intent to journal, acts on that same handle once the intent is durable, verifies, and later undoes.
//!
//! # Rules
//!
//! - **Execute-time refusal.** Before anything is opened, the deny-list and
//!   [`purge_guard::containers::check`] are asked about the target again, whatever the plan says: a
//!   structural container passed as a `DeleteKey`, or a deny-listed key, is skipped with its blocker.
//!   The act-time gate ([`gate::open_and_check_key`]) then runs every rule again (G1, G2, G3, G11, G13
//!   and the value binding) on the handle it opens, and that handle is the one acted on.
//! - **Only journalled facts.** The op, its plan item, its stamp and its exemptions are those of its
//!   journal `validated` record, which the executor handed to `GateCtx::record` after writing it (or
//!   reading it back): [`prepare_reg`] and [`prepare_undo_reg`] take only the op id. An op without a
//!   record is `Failed{Internal}` (undo: a conflict) and nothing is opened.
//! - **One route to a key.** The gate opens the key at the guard's `KeyProbe::open` address (root, view
//!   flag, logical path; both WOW64 views explicit, never through a `WOW6432Node` segment); undo acts on
//!   the key or parent handle [`gate::check_undo_key`] opened and checked at the same address, never on
//!   a second open. Every component is opened with `REG_OPTION_OPEN_LINK`, so no registry link is ever
//!   followed.
//! - **Links.** A link as the key, on its path or anywhere in a tree is a skip with
//!   `GateBlocked{RegLink}`; the link's target is never opened, read or changed. Keys are deleted only
//!   with `NtDeleteKey` on the inspected handle (`WKey::delete` / `WKey::delete_if_empty` inside
//!   [`regbackup::delete_tree`]), never by name: `RegDeleteKeyExW` on a link name deletes its target.
//! - **No verified backup, no delete.** Every op writes a `purge.regbackup/1` file below the session
//!   (`reg\<op>.regbackup.json`) with [`regbackup::write_verified`], through the store's handles only
//!   (`SessionDir::create_file`, then `SessionDir::open_file` with the same file id): flushed with its
//!   directory through those handles, read back through the checked handle, verified against the hash
//!   of the bytes meant to be written, and compared with the document. Only then is the intent built.
//!   Undo reads it with [`regbackup::read_verified`]. No path inside the store is opened, removed or
//!   flushed by name.
//! - **Exact data.** Values are read and written as raw type and raw bytes through `WKey` only (never the
//!   Win32 string reads, which zero the last byte of odd-length strings).
//!
//! # Outcomes of an action
//!
//! | Situation | Outcome |
//! |---|---|
//! | op is not a registry op, op was not validated, token of another op | `Failed{Internal}` |
//! | deny-list or structural container at execute time | `Skipped{GateBlocked{<blocker>}}` |
//! | key (or value, or segment) missing at open | `Vanished` |
//! | registry link: the key (also the key holding a value), an ancestor, anything in the tree, or one swapped in before the delete | `Skipped{GateBlocked{RegLink}}` |
//! | other gate refusal (TrustedInstaller, ...) | `Skipped{GateBlocked{<blocker>}}` |
//! | key or value changed since validation (gate: the journalled facts), or before the delete (compare on the way down) | `Skipped{ChangedSinceScan}` |
//! | delete-if-empty key with a value or subkey (at the gate, before the backup or at the delete) | `Skipped{NoLongerEmpty}` |
//! | tree larger than the key limit | `Skipped{GateBlocked{TooLarge}}` |
//! | what a backup cannot hold (bad name, `REG_LINK` value) | `Skipped{GateBlocked{CannotBackUp}}` |
//! | segment edit: value content changed since validation, segment still at the plan's index | acted on: `Done` (the backup and the inverse's hashes are of the value as read at the act) |
//! | segment edit: value type changed since validation | `Skipped{ChangedSinceScan}` (gate: the segment binding) |
//! | segment edit: segment no longer in the value | `Vanished` |
//! | segment edit: segment no longer at the plan's recorded index | `Skipped{ChangedSinceScan}` (the model's `Inverse::undoes` requires the recorded index) |
//! | segment edit: value no longer a list | `Skipped{ChangedSinceScan}` |
//! | open or call refused by the system | `Failed{AccessDenied}` / `Failed{Os}` |
//! | backup not written or not verified | [`BackupWriteError`]: `Skipped{NoVerifiedBackup}` |
//! | done and verified on the handle (key deleted, value gone, value holds the written data) | `Done` |
//! | the action ran but the verify does not see its result | `Failed{VerifyFailed}` |
//! | a tree delete stopped and putting back the deleted keys failed | `Failed{VerifyFailed}` (mixed state) |
//!
//! A tree delete that stops on a change puts the keys it already deleted back from the backup (per
//! subtree, all or nothing) before it reports the skip.
//!
//! # Journal contract
//!
//! This module never writes the journal. The executor, per item, in this order:
//!
//! 1. [`prepare_reg`] gates the item, captures it and writes the verified backup (hitting
//!    `backup.written` and `backup.verified`). It returns [`RegPrepared::Decided`] (journal it with
//!    `JournalWriter::done_without_intent`: every decided outcome passes
//!    `ItemOutcome::allowed_without_intent`), [`RegPrepared::Ready`], or a [`BackupWriteError`] (no backup,
//!    nothing changed: journal [`BackupWriteError::outcome`] without an intent, or abort the run with
//!    `BackupWriteFailed` / `StorageIntegrity` as [`BackupWriteError::is_storage_integrity`] says).
//! 2. The executor journals [`RegAction::intent`] with `JournalWriter::intent` (the token comes back once
//!    it is flushed) and hits `act.before`.
//! 3. [`act_reg`] takes the token, acts on the gated handle, hits `act.after` (and `regdelete.mid`
//!    inside a tree delete), verifies and returns the [`RegResult`] whose outcome goes to
//!    `JournalWriter::done` with the token.
//!
//! Undo, per op, from the journal's intent and done records:
//!
//! 1. [`prepare_undo_reg`] returns [`RegUndoPrepared::Decided`] (no inverse runs: `NothingToUndo` with
//!    `undo_done_without_intent`, a conflict with `undo_conflict_without_intent`) or
//!    [`RegUndoPrepared::Ready`].
//! 2. The executor writes `undo_intent` (the journal hits `undo.intent`).
//! 3. [`run_undo_reg`] takes the undo token, runs the inverse, hits `undo.act.after` and returns the
//!    [`RegUndoResult`] for `undo_done` or `undo_conflict` with the token.
//!
//! # Undo conflicts (§7.8)
//!
//! | Inverse | Live state | Result |
//! |---|---|---|
//! | any | the op changed nothing (`Vanished`, `Skipped`, `Failed` but `VerifyFailed`) | `NothingToUndo` |
//! | any | no journalled `validated` record for the op in the undo's gate context | conflict `GateBlocked{DenyListed{gate.not-validated}}` |
//! | any | the gate refuses the destination (deny-list, container, link on the chain) | conflict `GateBlocked{<blocker>}` |
//! | any | the parent (key target) or the key holding the value is missing | conflict `GateBlocked{ChangedSinceScan}` (`gate.undo-key-missing`) |
//! | any | backup file missing | conflict `BackupMissing` |
//! | any | backup file unreadable, size or SHA-256 differs, or not the op's backup | conflict `BackupTampered` |
//! | `RestoreKeyTree`, `RecreateKey` | key absent | `Restored` (all or nothing) |
//! | | key present and equal to the backup (owners aside) | `AlreadyRestored` |
//! | | key present below `Installer`, `Services` or a COM root | conflict `KeyExists` |
//! | | key present elsewhere, empty | merged into it: `Restored` (its own class and security kept, reported) |
//! | | key present elsewhere with content | conflict `KeyExists` |
//! | | key or parent is a link | conflict `GateBlocked{RegLink}` |
//! | | intent without done, or `VerifyFailed`: the tree is partly there | the missing keys put back, existing keys left as they are (one changed since is reported as a difference): `Restored`; a link in the tree: conflict `GateBlocked{RegLink}` |
//! | `RestoreValue` | value absent | `Restored` |
//! | | same type and data | `AlreadyRestored` |
//! | | other type or data | conflict `ValueDiffers` |
//! | `ReinsertSegment` | value holds its original data | `AlreadyRestored` |
//! | | value holds what Purge wrote | original data written back exactly: `Restored` |
//! | | value changed, segment present | `AlreadyRestored` |
//! | | value changed, segment missing | segment inserted at the recorded index (clamped): `Restored` |
//! | | value missing or no longer a list | conflict `ValueChanged` |
//! | | key is a link | conflict `GateBlocked{RegLink}` |
//!
//! Nothing that exists is ever overwritten: a conflict changes nothing.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use purge_guard::containers;
use purge_guard::deny::Exemptions;
use purge_guard::live::{self, Refusal};
use purge_model::exec::journal::{Intent, UndoConflict, UndoOutcome};
use purge_model::exec::op::{BackupRef, ExecOp, FailCode, Inverse, ItemOutcome, OpId, SkipReason};
use purge_model::exec::regbackup::{RegBackup, RegBackupBody, RegBackupSchema};
use purge_model::{Blocker, FileTime, Target};
use purge_win::os::Win32Error;
use purge_win::reg_write::WKey;

use crate::fault;
use crate::gate::{self, CheckedKey, CheckedUndoKey, GateCtx, GateOutcome};
use crate::journal::{IntentToken, UndoToken};
use crate::regbackup::{
    self, BackupFileError, CaptureError, Change, DeleteError, DeleteFailure, Difference,
    DifferenceKind, ReinsertOutcome, RestoreError, RestoreOutcome, RestoreReport, Rollback,
    SegmentError, SegmentRemoval, SegmentUndo, ValueDelete, VerifiedBackup,
};
use crate::storage::{BackupKind, SessionDir, StorageError, backup_rel};

#[cfg(test)]
mod tests;

/// `ERROR_KEY_DELETED`: the key behind a handle was deleted.
const KEY_DELETED: Win32Error = Win32Error(1018);

/// FILETIME of 1970-01-01 (100 ns ticks since 1601-01-01).
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

// ---------------------------------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------------------------------

/// How a registry action ended for one item, with a line for the report. The executor journals
/// `outcome`; `detail` says why (an [`ItemOutcome::Skipped`] has no text of its own).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegResult {
    /// The outcome to journal.
    pub outcome: ItemOutcome,
    /// Why, for the report; may be empty for a plain success.
    pub detail: String,
}

impl RegResult {
    fn new(outcome: ItemOutcome, detail: impl Into<String>) -> RegResult {
        RegResult {
            outcome,
            detail: detail.into(),
        }
    }

    fn skipped(reason: SkipReason, detail: impl Into<String>) -> RegResult {
        RegResult::new(ItemOutcome::Skipped { reason }, detail)
    }

    fn blocked(blocker: Blocker, detail: impl Into<String>) -> RegResult {
        RegResult::skipped(SkipReason::GateBlocked { blocker }, detail)
    }

    fn failed(code: FailCode, os_error: Option<u32>, detail: impl Into<String>) -> RegResult {
        let detail = detail.into();
        RegResult {
            outcome: ItemOutcome::Failed {
                code,
                os_error,
                detail: detail.clone(),
            },
            detail,
        }
    }

    /// A failure of the system call `error`: access denied or another OS error.
    fn os(error: Win32Error, detail: impl Into<String>) -> RegResult {
        RegResult::failed(fail_code(error), Some(error.code()), detail)
    }
}

/// The failure code of a Win32 error.
fn fail_code(error: Win32Error) -> FailCode {
    if error == Win32Error::ACCESS_DENIED {
        FailCode::AccessDenied
    } else {
        FailCode::Os
    }
}

// ---------------------------------------------------------------------------------------------------
// Backup file
// ---------------------------------------------------------------------------------------------------

/// The registry backup could not be written and verified. Nothing was changed and no intent is needed.
#[derive(Debug, thiserror::Error)]
pub enum BackupWriteError {
    /// The store refused (integrity check, existing file, I/O on the layout).
    #[error("registry backup: {0}")]
    Storage(#[from] StorageError),
    /// Writing or flushing the file failed.
    #[error("registry backup {}: {op} failed: {detail}", .path.display())]
    File {
        /// What was being done.
        op: &'static str,
        /// The file.
        path: PathBuf,
        /// The error.
        detail: String,
    },
    /// The file did not read back as written (other bytes, or a document that does not parse to the one
    /// written or fails the document checks).
    #[error("registry backup {} did not read back as written: {detail}", .path.display())]
    ReadBack {
        /// The file.
        path: PathBuf,
        /// What differed.
        detail: String,
    },
    /// The document could not be encoded.
    #[error("the registry backup could not be encoded: {0}")]
    Encode(String),
}

impl BackupWriteError {
    /// The outcome to journal for the item (without an intent): `Skipped{NoVerifiedBackup}`.
    pub fn outcome(&self) -> ItemOutcome {
        ItemOutcome::Skipped {
            reason: SkipReason::NoVerifiedBackup,
        }
    }

    /// Whether a storage directory failed its integrity check, which concerns the whole run
    /// (`AbortReason::StorageIntegrity`) rather than this item.
    pub fn is_storage_integrity(&self) -> bool {
        matches!(
            self,
            BackupWriteError::Storage(StorageError::Integrity { .. })
        )
    }
}

/// The current time as a FILETIME.
fn now() -> FileTime {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ticks = u64::try_from(since.as_nanos() / 100).unwrap_or(u64::MAX);
    FileTime(FILETIME_UNIX_EPOCH.saturating_add(ticks))
}

/// Writes `doc` to op `op`'s backup file `reg\<op>.regbackup.json` with [`regbackup::write_verified`],
/// the one writer of registry backups: through the store's handles only, create-new, flushed with its
/// directory, closed (`backup.written`), re-opened through the store's checks as the same file, read
/// and verified against the hash of the bytes meant to be written, and compared (`backup.verified`).
fn write_backup(
    session: &SessionDir,
    op: OpId,
    doc: &RegBackup,
) -> Result<VerifiedBackup, BackupWriteError> {
    let rel = backup_rel(BackupKind::Registry, op);
    regbackup::write_verified(session, &rel, doc).map_err(|e| match e {
        BackupFileError::Store(e) => BackupWriteError::Storage(*e),
        BackupFileError::Fs { op, error } => BackupWriteError::File {
            op,
            path: session.path().join(&rel),
            detail: error.to_string(),
        },
        BackupFileError::NotSessionRelative(_)
        | BackupFileError::Invalid(_)
        | BackupFileError::TooBig => BackupWriteError::Encode(e.to_string()),
        BackupFileError::Missing
        | BackupFileError::Tampered
        | BackupFileError::ReadBackMismatch => BackupWriteError::ReadBack {
            path: session.path().join(&rel),
            detail: e.to_string(),
        },
    })
}

// ---------------------------------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------------------------------

/// The key path of a registry op (its wire spelling, also the backup's `key`).
fn key_of(exec_op: &ExecOp) -> &str {
    match exec_op {
        ExecOp::DeleteKeyTree { key }
        | ExecOp::DeleteKeyIfEmpty { key }
        | ExecOp::DeleteValue { key, .. }
        | ExecOp::EditSegment { key, .. } => key,
        ExecOp::QuarantineMove { path } | ExecOp::RemoveDirIfEmpty { path } => path,
        ExecOp::RemovePackage { full_name } => full_name,
    }
}

/// What the op addresses, for messages: the key, or `key` value `name`.
fn what(exec_op: &ExecOp) -> String {
    match exec_op {
        ExecOp::DeleteValue { key, name } | ExecOp::EditSegment { key, name, .. } => {
            format!("{key} value {name:?}")
        }
        other => key_of(other).to_owned(),
    }
}

/// The execute-time refusal of §5.10 on the target itself, before anything is opened: the deny-list,
/// then the structural containers. The act-time gate applies both again on the handle.
fn execute_time_refusal(
    ctx: &GateCtx,
    target: &Target,
    exemptions: &Exemptions,
) -> Option<(Blocker, &'static str)> {
    if let Some(blocker) = ctx.deny().check(target, exemptions) {
        return Some((blocker, "deny-listed"));
    }
    containers::check(target, ctx.deny().env()).map(|blocker| (blocker, "a structural container"))
}

/// The result of a gate refusal.
fn refused(refusal: &Refusal, exec_op: &ExecOp) -> RegResult {
    let detail = format!(
        "{}: refused at execute time: {refusal}; left untouched",
        what(exec_op)
    );
    match &refusal.blocker {
        Blocker::ChangedSinceScan
            if refusal.reason == live::reason::NOT_EMPTY
                && matches!(exec_op, ExecOp::DeleteKeyIfEmpty { .. }) =>
        {
            RegResult::skipped(SkipReason::NoLongerEmpty, detail)
        }
        Blocker::ChangedSinceScan => RegResult::skipped(SkipReason::ChangedSinceScan, detail),
        blocker => RegResult::blocked(blocker.clone(), detail),
    }
}

/// The act-time gate for op `op`: the key opened with the access the action needs, every fact read from
/// that handle, every rule applied, against the facts of the op's journal `validated` record (a key's
/// counts, link state, owner and last write time; a value's type, length and hash; for a segment edit
/// the value's type only, see `gate::open_and_check_key`). A key or value that changed since validation
/// is `Skipped{ChangedSinceScan}`; a key replaced by a registry link is `GateBlocked{RegLink}`, also for
/// a value or segment op (the gate reports it so, not as a vanished value).
fn open_checked(ctx: &GateCtx, op: OpId, exec_op: &ExecOp) -> Result<CheckedKey, RegResult> {
    match gate::open_and_check_key(ctx, op) {
        GateOutcome::Pass(checked) => Ok(checked),
        GateOutcome::Vanished => Err(RegResult::new(
            ItemOutcome::Vanished,
            format!("{} no longer exists", what(exec_op)),
        )),
        GateOutcome::Refused(refusal) => Err(refused(&refusal, exec_op)),
        GateOutcome::Failed(e) => Err(RegResult::os(
            e,
            format!("opening {} failed: {e}; left untouched", what(exec_op)),
        )),
        GateOutcome::Locked(_) => Err(RegResult::failed(
            FailCode::Internal,
            None,
            format!(
                "the registry gate reported {} as a locked file; left untouched",
                what(exec_op)
            ),
        )),
    }
}

/// The result of a capture that was refused.
fn capture_refused(error: &CaptureError, exec_op: &ExecOp) -> RegResult {
    let detail = format!(
        "{}: the backup was not taken: {error}; left untouched",
        what(exec_op)
    );
    match (error, error.blocker()) {
        (CaptureError::Vanished, _) => RegResult::new(
            ItemOutcome::Vanished,
            format!("{} no longer exists", what(exec_op)),
        ),
        (_, Some(blocker)) => RegResult::blocked(blocker, detail),
        (CaptureError::Os(e), None) => RegResult::os(e.error, detail),
        (_, None) => RegResult::failed(FailCode::Internal, None, detail),
    }
}

// ---------------------------------------------------------------------------------------------------
// Prepare and act
// ---------------------------------------------------------------------------------------------------

/// What [`prepare_reg`] decided.
#[derive(Debug)]
pub enum RegPrepared {
    /// Decided without changing anything: journal the outcome with `done_without_intent`.
    Decided(RegResult),
    /// Gated, captured and backed up: journal [`RegAction::intent`], then call [`act_reg`] with its
    /// token.
    Ready(Box<RegAction>),
}

/// The action-specific part of a prepared op.
#[derive(Debug)]
enum Act {
    /// Delete the key tree of the backup.
    Tree,
    /// Delete the key if it is still empty.
    Empty,
    /// Delete the value.
    Value {
        /// Value name.
        name: String,
    },
    /// Write the planned segment removal.
    Segment {
        /// The planned read-modify-write.
        plan: SegmentRemoval,
    },
}

/// A registry action that passed the gate and whose backup is on disk, holding the gated key handle the
/// action runs on. Only [`prepare_reg`] makes one, and [`act_reg`] consumes it.
#[derive(Debug)]
pub struct RegAction {
    intent: Intent,
    key: CheckedKey,
    backup: VerifiedBackup,
    act: Act,
}

impl RegAction {
    /// The intent to journal before the action: the op, its inverse (with the verified backup), and the
    /// facts read from the gated handle. It passes `Intent::is_consistent`.
    pub fn intent(&self) -> &Intent {
        &self.intent
    }

    /// The backup file the inverse reads.
    pub fn backup(&self) -> &BackupRef {
        self.backup.reference()
    }
}

/// Decides whether registry op `op` may run, and if so writes its backup into `session` and builds the
/// intent. Never changes the registry.
///
/// The op, its plan item, its stamp and its exemptions are those of the op's journal `validated` record
/// that the executor handed to `GateCtx::record` ([`GateCtx::journalled`]). `key_limit` is the most keys
/// a tree may hold ([`regbackup::DEFAULT_KEY_LIMIT`], or the counted size of an absorbing Safe parent); a
/// larger tree is `Skipped{GateBlocked{TooLarge}}`.
///
/// Order: the op must have a journalled record in `ctx` and be a registry op; the deny-list and the
/// structural containers on the target; the act-time gate on the handle the action will use; then per op:
///
/// - `DeleteKeyTree`: the subtree is captured through the gated handle ([`regbackup::capture_tree`] with
///   `key_limit`); inverse `RestoreKeyTree`.
/// - `DeleteKeyIfEmpty`: zero values and zero subkeys are read again on the handle (else
///   `Skipped{NoLongerEmpty}`); the key is captured as a one-key tree with its class, security and
///   volatility; inverse `RecreateKey`.
/// - `DeleteValue`: type and raw bytes are captured ([`regbackup::capture_value`]); an absent value is
///   `Vanished`; inverse `RestoreValue`.
/// - `EditSegment`: the removal is planned on the handle ([`regbackup::plan_segment_removal`]): the value
///   as it is (type kept), the segment at the plan's index or (without one) its first occurrence; an
///   absent value or segment is `Vanished`. The whole value before the edit is backed up; inverse
///   `ReinsertSegment` with the hashes of the data before and after.
pub fn prepare_reg(
    ctx: &GateCtx,
    session: &SessionDir,
    op: OpId,
    key_limit: usize,
) -> Result<RegPrepared, BackupWriteError> {
    let decided = |result: RegResult| Ok(RegPrepared::Decided(result));
    let (Some((exec_op, record)), Some(exemptions)) = (ctx.journalled(op), ctx.exemptions(op))
    else {
        return decided(RegResult::failed(
            FailCode::Internal,
            None,
            format!("op {op} has no journalled validated record in this run; nothing done"),
        ));
    };
    if !exec_op.is_registry() {
        return decided(RegResult::failed(
            FailCode::Internal,
            None,
            format!("{} is not a registry op; nothing done", exec_op.name()),
        ));
    }
    if let Some((blocker, why)) = execute_time_refusal(ctx, &exec_op.target(), &exemptions) {
        return decided(RegResult::blocked(
            blocker.clone(),
            format!(
                "{} is {why} ({}): never acted on, whatever the plan says; left untouched",
                what(exec_op),
                blocker.name()
            ),
        ));
    }
    let checked = match open_checked(ctx, op, exec_op) {
        Ok(checked) => checked,
        Err(result) => return decided(result),
    };
    let key = key_of(exec_op).to_owned();
    let (doc, act) = match exec_op {
        ExecOp::DeleteKeyTree { .. } => {
            match regbackup::capture_tree(checked.key(), &key, key_limit) {
                Ok(doc) => (doc, Act::Tree),
                Err(e) => return decided(capture_refused(&e, exec_op)),
            }
        }
        ExecOp::DeleteKeyIfEmpty { .. } => match prepare_empty(&checked, &key, exec_op) {
            Ok(doc) => (doc, Act::Empty),
            Err(result) => return decided(result),
        },
        ExecOp::DeleteValue { name, .. } => {
            match regbackup::capture_value(checked.key(), &key, name) {
                Ok(Some(doc)) => (doc, Act::Value { name: name.clone() }),
                Ok(None) => {
                    return decided(RegResult::new(
                        ItemOutcome::Vanished,
                        format!("{} no longer exists", what(exec_op)),
                    ));
                }
                Err(e) => return decided(capture_refused(&e, exec_op)),
            }
        }
        ExecOp::EditSegment {
            name,
            segment,
            index,
            ..
        } => match prepare_segment(&checked, name, segment, *index, exec_op) {
            Ok(plan) => (
                RegBackup {
                    schema: RegBackupSchema,
                    key: key.clone(),
                    captured: now(),
                    body: RegBackupBody::Value(plan.original.clone()),
                },
                Act::Segment { plan },
            ),
            Err(result) => return decided(result),
        },
        ExecOp::QuarantineMove { .. }
        | ExecOp::RemoveDirIfEmpty { .. }
        | ExecOp::RemovePackage { .. } => unreachable!("checked by is_registry above"),
    };
    let backup = write_backup(session, op, &doc)?;
    let reference = backup.reference().clone();
    let inverse = match &act {
        Act::Tree => Inverse::RestoreKeyTree { backup: reference },
        Act::Empty => Inverse::RecreateKey { backup: reference },
        Act::Value { .. } => Inverse::RestoreValue { backup: reference },
        Act::Segment { plan } => Inverse::ReinsertSegment {
            key,
            name: plan.name.clone(),
            index: plan.index,
            segment: plan.segment.clone(),
            original_value_hash: plan.original_value_hash,
            written_value_hash: plan.written_value_hash,
            backup: Some(reference),
        },
    };
    let intent = Intent {
        op,
        item: record.item.clone(),
        exec_op: exec_op.clone(),
        inverse,
        definition: None,
        pre: checked.item_facts().clone(),
    };
    Ok(RegPrepared::Ready(Box::new(RegAction {
        intent,
        key: checked,
        backup,
        act,
    })))
}

/// Delete-if-empty: the counts read again on the gated handle, then the one-key capture.
fn prepare_empty(
    checked: &CheckedKey,
    key: &str,
    exec_op: &ExecOp,
) -> Result<RegBackup, RegResult> {
    let not_empty = |n_subkeys: u32, n_values: u32| {
        RegResult::skipped(
            SkipReason::NoLongerEmpty,
            format!("{key} has {n_subkeys} subkey(s) and {n_values} value(s) now; left untouched"),
        )
    };
    match checked.key().info() {
        Ok(info) if info.n_subkeys == 0 && info.n_values == 0 => {}
        Ok(info) => return Err(not_empty(info.n_subkeys, info.n_values)),
        Err(e) if e == KEY_DELETED || e.is_not_found() => {
            return Err(RegResult::new(
                ItemOutcome::Vanished,
                format!("{key} no longer exists"),
            ));
        }
        Err(e) => {
            return Err(RegResult::os(
                e,
                format!("{key}: reading its counts failed: {e}; left untouched"),
            ));
        }
    }
    let doc = match regbackup::capture_tree(checked.key(), key, 1) {
        Ok(doc) => doc,
        // A subkey appeared between the count and the capture.
        Err(CaptureError::TooLarge { .. }) => return Err(not_empty(1, 0)),
        Err(e) => return Err(capture_refused(&e, exec_op)),
    };
    match doc.tree().map(|tree| tree.keys[0].values.len()) {
        Some(0) => Ok(doc),
        Some(n) => Err(not_empty(0, u32::try_from(n).unwrap_or(u32::MAX))),
        None => Err(RegResult::failed(
            FailCode::Internal,
            None,
            format!("{key}: the capture of an empty key is not a tree; left untouched"),
        )),
    }
}

/// Segment edit: the plan on the gated handle.
fn prepare_segment(
    checked: &CheckedKey,
    name: &str,
    segment: &str,
    index: Option<u32>,
    exec_op: &ExecOp,
) -> Result<SegmentRemoval, RegResult> {
    let at = what(exec_op);
    let plan = match regbackup::plan_segment_removal(checked.key(), name, segment, index) {
        Ok(plan) => plan,
        Err(SegmentError::ValueAbsent) => {
            return Err(RegResult::new(
                ItemOutcome::Vanished,
                format!("{at} no longer exists"),
            ));
        }
        Err(SegmentError::SegmentAbsent) => {
            return Err(RegResult::new(
                ItemOutcome::Vanished,
                format!("{at} no longer holds the segment {segment:?}"),
            ));
        }
        Err(SegmentError::KeyIsLink) => {
            return Err(RegResult::blocked(
                Blocker::RegLink,
                format!("{at}: the key is a registry link; left untouched"),
            ));
        }
        Err(SegmentError::Os(e)) => {
            return Err(RegResult::os(e.error, format!("{at}: {e}; left untouched")));
        }
        Err(SegmentError::BadSegment) => {
            return Err(RegResult::failed(
                FailCode::Internal,
                None,
                format!(
                    "the plan's segment {segment:?} cannot be an element of {at}; left untouched"
                ),
            ));
        }
        Err(e @ (SegmentError::NotAList | SegmentError::Changed | SegmentError::VerifyFailed)) => {
            return Err(RegResult::skipped(
                SkipReason::ChangedSinceScan,
                format!("{at}: {e}; left untouched"),
            ));
        }
    };
    if let Some(recorded) = index
        && plan.index != recorded
    {
        return Err(RegResult::skipped(
            SkipReason::ChangedSinceScan,
            format!(
                "{at}: the segment {segment:?} is no longer at position {recorded} (found at {}); left \
                 untouched",
                plan.index
            ),
        ));
    }
    Ok(plan)
}

/// Runs the action of `action`, whose intent `token` proves durable, on the handle the gate inspected,
/// then verifies it on that handle. The executor hits `act.before` before the call and passes the result
/// to `JournalWriter::done` with the token. Hits `act.after` after the action ran, before the verify
/// (and `regdelete.mid` between the deletes of a tree).
///
/// - Tree and delete-if-empty: [`regbackup::delete_tree`], which compares every key with the backup on
///   the way down and right before its delete, deletes deepest first through each key's own handle, and
///   puts deleted keys back if it stops. Verified when the gated handle reports the key deleted.
/// - Value: [`regbackup::delete_value`] (deleted only while type and bytes are the backed-up ones).
///   Verified when the value no longer reads.
/// - Segment: [`regbackup::apply_segment_removal`] (written only while the value is still exactly what
///   was planned from, on the handle it was read through). Verified when the value reads as written.
///
/// A token of another op is `Failed{Internal}` and nothing is done.
pub fn act_reg(action: Box<RegAction>, token: &IntentToken) -> RegResult {
    let RegAction {
        intent,
        key,
        backup,
        act,
    } = *action;
    let at = what(&intent.exec_op);
    if token.op() != intent.op || token.item() != &intent.item {
        return RegResult::failed(
            FailCode::Internal,
            None,
            format!(
                "the intent token is for op {}, not op {}; {at} left untouched",
                token.op(),
                intent.op
            ),
        );
    }
    let handle = key.key();
    match act {
        Act::Tree | Act::Empty => {
            let empty = matches!(act, Act::Empty);
            match regbackup::delete_tree(handle, &backup) {
                Ok(report) => {
                    fault::point(fault::ACT_AFTER);
                    verify_key_deleted(handle, &at, report.keys_deleted)
                }
                Err(e) => delete_stopped(&e, &at, empty),
            }
        }
        Act::Value { name } => match regbackup::delete_value(handle, &backup) {
            Ok(ValueDelete::Deleted) => {
                fault::point(fault::ACT_AFTER);
                match handle.value(&name) {
                    Ok(None) => RegResult::new(ItemOutcome::Done, ""),
                    Err(e) if e == KEY_DELETED || e.is_not_found() => {
                        RegResult::new(ItemOutcome::Done, "")
                    }
                    Ok(Some(_)) => RegResult::failed(
                        FailCode::VerifyFailed,
                        None,
                        format!("{at} was deleted but reads again"),
                    ),
                    Err(e) => RegResult::failed(
                        FailCode::VerifyFailed,
                        Some(e.code()),
                        format!("{at} was deleted, but reading it again failed: {e}"),
                    ),
                }
            }
            Ok(ValueDelete::Vanished) => RegResult::new(
                ItemOutcome::Vanished,
                format!("{at} was gone before Purge deleted it"),
            ),
            Err(failure) => value_delete_stopped(&failure, &at),
        },
        Act::Segment { plan } => match regbackup::apply_segment_removal(handle, &plan) {
            Ok(()) => {
                fault::point(fault::ACT_AFTER);
                match handle.value(&plan.name) {
                    Ok(Some(back))
                        if back.ty == plan.original.value_type && back.data == plan.written =>
                    {
                        RegResult::new(ItemOutcome::Done, "")
                    }
                    Ok(_) => RegResult::failed(
                        FailCode::VerifyFailed,
                        None,
                        format!("{at} does not hold the data Purge wrote"),
                    ),
                    Err(e) => RegResult::failed(
                        FailCode::VerifyFailed,
                        Some(e.code()),
                        format!("{at} was written, but reading it again failed: {e}"),
                    ),
                }
            }
            Err(e) => segment_stopped(&e, &at, &plan.segment),
        },
    }
}

/// Verify of a key delete: the gated handle reports the key deleted.
fn verify_key_deleted(handle: &WKey, at: &str, keys: usize) -> RegResult {
    match handle.info() {
        Err(e) if e == KEY_DELETED => RegResult::new(
            ItemOutcome::Done,
            if keys > 1 {
                format!("{keys} keys deleted")
            } else {
                String::new()
            },
        ),
        Ok(_) => RegResult::failed(
            FailCode::VerifyFailed,
            None,
            format!("{at} was deleted but its handle still reports the key"),
        ),
        Err(e) => RegResult::failed(
            FailCode::VerifyFailed,
            Some(e.code()),
            format!("{at} was deleted, but the check on its handle failed: {e}"),
        ),
    }
}

/// Text on what a rollback after a stopped delete did.
fn rollback_text(rollback: &Rollback) -> String {
    match rollback {
        Rollback::NotNeeded => "nothing had been deleted".into(),
        Rollback::Done { keys, differences } if differences.is_empty() => {
            format!("the {keys} key(s) already deleted were put back")
        }
        Rollback::Done { keys, differences } => format!(
            "the {keys} key(s) already deleted were put back, with differences: {}",
            differences_text(differences)
        ),
        Rollback::Incomplete { failure, keys } => format!(
            "putting the deleted keys back stopped after {keys} key(s): {failure}; the tree is partly \
             deleted and needs recovery or undo"
        ),
        Rollback::PartialBefore {
            missing,
            keys,
            differences,
        } => {
            let differences = if differences.is_empty() {
                String::new()
            } else {
                format!(" (with differences: {})", differences_text(differences))
            };
            format!(
                "the {keys} key(s) this run deleted were put back{differences}, but {missing} key(s) \
                 deleted by the interrupted run are still missing; the tree is partly deleted and needs \
                 recovery or undo"
            )
        }
    }
}

/// Text on restore differences.
fn differences_text(differences: &[Difference]) -> String {
    differences
        .iter()
        .map(|d| {
            let at = if d.at.is_empty() { "(root)" } else { &d.at };
            match &d.kind {
                DifferenceKind::OwnerNotRestored { recorded_owner } => {
                    format!("{at}: owner {recorded_owner} not restored")
                }
                DifferenceKind::SecurityDiffers => format!("{at}: security differs"),
                DifferenceKind::RootClassKept => format!("{at}: existing class kept"),
                DifferenceKind::RootSecurityKept => format!("{at}: existing security kept"),
                DifferenceKind::ExistingKeyDiffers { change } => {
                    format!("{at}: left as it is, it differs from the backup: {change}")
                }
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The result of a tree delete that stopped.
fn delete_stopped(error: &DeleteError, at: &str, empty: bool) -> RegResult {
    let place = if error.at.is_empty() {
        at.to_owned()
    } else {
        format!("{at}\\{}", error.at)
    };
    let detail = format!(
        "the delete stopped at {place}: {}; {}",
        error.failure,
        rollback_text(&error.rollback)
    );
    if !error.rollback.is_complete() {
        let os_error = match &error.rollback {
            Rollback::Incomplete { failure, .. } => Some(failure.error.code()),
            _ => None,
        };
        return RegResult::failed(FailCode::VerifyFailed, os_error, detail);
    }
    match &error.failure {
        DeleteFailure::Changed(Change::Missing) if error.at.is_empty() => {
            RegResult::new(ItemOutcome::Vanished, format!("{at} no longer exists"))
        }
        DeleteFailure::Changed(Change::BecameLink) => RegResult::blocked(Blocker::RegLink, detail),
        DeleteFailure::Changed(Change::ExtraSubkey | Change::ValuesDiffer) if empty => {
            RegResult::skipped(SkipReason::NoLongerEmpty, detail)
        }
        DeleteFailure::Changed(_) => RegResult::skipped(SkipReason::ChangedSinceScan, detail),
        DeleteFailure::WrongBackupKind | DeleteFailure::NotThisKey => {
            RegResult::failed(FailCode::Internal, None, detail)
        }
        DeleteFailure::Os { error, .. } => RegResult::os(*error, detail),
    }
}

/// The result of a value delete that did not happen.
fn value_delete_stopped(failure: &DeleteFailure, at: &str) -> RegResult {
    let detail = format!("{at}: {failure}; left untouched");
    match failure {
        DeleteFailure::Changed(Change::BecameLink) => RegResult::blocked(Blocker::RegLink, detail),
        DeleteFailure::Changed(Change::Missing) => {
            RegResult::new(ItemOutcome::Vanished, format!("{at} no longer exists"))
        }
        DeleteFailure::Changed(Change::NameNotRepresentable) => {
            RegResult::blocked(Blocker::CannotBackUp, detail)
        }
        DeleteFailure::Changed(_) => RegResult::skipped(SkipReason::ChangedSinceScan, detail),
        DeleteFailure::WrongBackupKind | DeleteFailure::NotThisKey => {
            RegResult::failed(FailCode::Internal, None, detail)
        }
        DeleteFailure::Os { error, .. } if *error == KEY_DELETED || error.is_not_found() => {
            RegResult::new(ItemOutcome::Vanished, format!("{at} no longer exists"))
        }
        DeleteFailure::Os { error, .. } => RegResult::os(*error, detail),
    }
}

/// The result of a segment write that did not happen (or did not verify).
fn segment_stopped(error: &SegmentError, at: &str, segment: &str) -> RegResult {
    let detail = format!("{at}: {error}; left untouched");
    match error {
        SegmentError::ValueAbsent | SegmentError::SegmentAbsent => RegResult::new(
            ItemOutcome::Vanished,
            format!("{at} no longer holds the segment {segment:?}"),
        ),
        SegmentError::KeyIsLink => RegResult::blocked(Blocker::RegLink, detail),
        SegmentError::Changed | SegmentError::NotAList => {
            RegResult::skipped(SkipReason::ChangedSinceScan, detail)
        }
        SegmentError::BadSegment => RegResult::failed(FailCode::Internal, None, detail),
        SegmentError::VerifyFailed => RegResult::failed(
            FailCode::VerifyFailed,
            None,
            format!("{at}: the value did not read back as written"),
        ),
        SegmentError::Os(e) if e.error == KEY_DELETED => {
            RegResult::new(ItemOutcome::Vanished, format!("{at} no longer exists"))
        }
        SegmentError::Os(e) => RegResult::os(e.error, detail),
    }
}

// ---------------------------------------------------------------------------------------------------
// Undo
// ---------------------------------------------------------------------------------------------------

/// How the undo of a registry op ended, as the journal records it. Never an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegUndoResult {
    /// `undo_done` with this outcome (without an `undo_intent` only for `NothingToUndo`).
    Done {
        /// The outcome.
        outcome: UndoOutcome,
        /// For the report: what could not be put back exactly, or why it failed; may be empty.
        detail: String,
    },
    /// `undo_conflict`: the inverse was not applied, nothing was changed.
    Conflict {
        /// What stood in the way.
        conflict: UndoConflict,
        /// For the report.
        detail: String,
    },
}

impl RegUndoResult {
    fn done(outcome: UndoOutcome, detail: impl Into<String>) -> RegUndoResult {
        RegUndoResult::Done {
            outcome,
            detail: detail.into(),
        }
    }

    fn conflict(conflict: UndoConflict, detail: impl Into<String>) -> RegUndoResult {
        RegUndoResult::Conflict {
            conflict,
            detail: detail.into(),
        }
    }

    fn failed(code: FailCode, os_error: Option<u32>, detail: impl Into<String>) -> RegUndoResult {
        let detail = detail.into();
        RegUndoResult::Done {
            outcome: UndoOutcome::Failed {
                code,
                os_error,
                detail: detail.clone(),
            },
            detail,
        }
    }

    fn os(error: Win32Error, detail: impl Into<String>) -> RegUndoResult {
        RegUndoResult::failed(fail_code(error), Some(error.code()), detail)
    }
}

/// What [`prepare_undo_reg`] decided.
#[derive(Debug)]
pub enum RegUndoPrepared {
    /// No inverse runs: [`RegUndoResult::Done`] (always `NothingToUndo`) with
    /// `undo_done_without_intent`, [`RegUndoResult::Conflict`] with `undo_conflict_without_intent`.
    Decided(RegUndoResult),
    /// The inverse may run: write `undo_intent`, then call [`run_undo_reg`] with its token.
    Ready(Box<RegInverse>),
}

/// The inverse-specific part of a prepared undo.
#[derive(Debug)]
enum Undo {
    /// Restore a tree (also the one-key tree of a delete-if-empty).
    Tree {
        /// The intent had no `Done` (crash, or `VerifyFailed`): the missing part of a partly deleted
        /// tree is completed instead of the whole tree restored.
        complete: bool,
    },
    /// Restore a value.
    Value,
    /// Put a segment back.
    Segment(SegmentUndo),
}

/// A registry inverse whose destination passed the undo gate and whose backup verified, holding the key
/// handle the gate checked ([`CheckedUndoKey`]: the parent of a key to re-create, or the key holding a
/// value), which is the one the inverse acts on. Only [`prepare_undo_reg`] makes one, and
/// [`run_undo_reg`] consumes it.
#[derive(Debug)]
pub struct RegInverse {
    op: OpId,
    at: String,
    checked: CheckedUndoKey,
    backup: Option<VerifiedBackup>,
    undo: Undo,
}

impl RegInverse {
    /// The op being undone.
    pub fn op(&self) -> OpId {
        self.op
    }
}

/// Reads and checks the backup an inverse needs with [`regbackup::read_verified`] (opened through the
/// store's checks and read through that checked handle, checked against the journal's size and
/// SHA-256), and as the backup of `exec_op` (`RegBackup::validate_for`).
fn read_backup(
    session: &SessionDir,
    reference: &BackupRef,
    exec_op: &ExecOp,
) -> Result<VerifiedBackup, RegUndoResult> {
    let tampered = |detail: String| RegUndoResult::conflict(UndoConflict::BackupTampered, detail);
    let backup = regbackup::read_verified(session, reference).map_err(|e| match e {
        BackupFileError::Missing => RegUndoResult::conflict(
            UndoConflict::BackupMissing,
            format!("the backup {} is missing", reference.path),
        ),
        other => tampered(format!(
            "the backup {} cannot be used: {other}",
            reference.path
        )),
    })?;
    backup.doc().validate_for(exec_op).map_err(|e| {
        tampered(format!(
            "the backup {} is not the backup of this op: {e}",
            reference.path
        ))
    })?;
    Ok(backup)
}

/// Decides how the registry op of `intent` is undone. `done` is the op's `done` outcome, or `None` when
/// the journal holds only its intent (the run stopped during the action). `None` for an op that is not a
/// registry op. Changes nothing.
///
/// The destination is checked with the exemptions of the op's journal `validated` record, which the undo
/// driver handed to `ctx` (`GateCtx::record`, read with `GateCtx::exemptions`); an op without one is a
/// conflict and nothing is opened.
///
/// In order: the inverse must undo the op ([`Inverse::undoes`]); an op that changed nothing is
/// `NothingToUndo`; the op must have a journalled record in `ctx`; the destination must pass
/// [`gate::check_undo_key`] (deny-list, structural containers, no link on the key or its ancestors at
/// the probe addresses), which opens the key the restore acts on; the backup must exist, match the
/// journal and belong to the op.
pub fn prepare_undo_reg(
    ctx: &GateCtx,
    session: &SessionDir,
    intent: &Intent,
    done: Option<&ItemOutcome>,
) -> Option<RegUndoPrepared> {
    let exec_op = &intent.exec_op;
    if !exec_op.is_registry() {
        return None;
    }
    let at = what(exec_op);
    let decided = |result: RegUndoResult| Some(RegUndoPrepared::Decided(result));
    if !intent.inverse.undoes(exec_op) {
        return decided(RegUndoResult::conflict(
            UndoConflict::BackupTampered,
            format!(
                "the journal's inverse {} does not undo the op on {at}",
                intent.inverse.name()
            ),
        ));
    }
    let unchanged = match done {
        Some(ItemOutcome::Failed { code, .. }) => *code != FailCode::VerifyFailed,
        Some(outcome) => !outcome.changed_system(),
        None => false,
    };
    if unchanged {
        return decided(RegUndoResult::done(UndoOutcome::NothingToUndo, ""));
    }
    let Some(exemptions) = ctx.exemptions(intent.op) else {
        return decided(RegUndoResult::conflict(
            UndoConflict::GateBlocked {
                blocker: Blocker::DenyListed {
                    rule: gate::reason::NOT_VALIDATED.to_owned(),
                },
            },
            format!(
                "{at}: op {} has no journalled validated record in this undo run; nothing restored",
                intent.op
            ),
        ));
    };
    let checked = match gate::check_undo_key(ctx, &exec_op.target(), &exemptions) {
        Ok(checked) => checked,
        Err(refusal) => {
            return decided(RegUndoResult::conflict(
                UndoConflict::GateBlocked {
                    blocker: refusal.blocker.clone(),
                },
                format!("{at}: the restore is refused: {refusal}"),
            ));
        }
    };
    let backup = match intent.inverse.backup() {
        Some(reference) => match read_backup(session, reference, exec_op) {
            Ok(backup) => Some(backup),
            Err(result) => return decided(result),
        },
        None => None,
    };
    let undo = match &intent.inverse {
        Inverse::RestoreKeyTree { .. } | Inverse::RecreateKey { .. } => Undo::Tree {
            complete: !matches!(done, Some(ItemOutcome::Done)),
        },
        Inverse::RestoreValue { .. } => Undo::Value,
        Inverse::ReinsertSegment {
            name,
            index,
            segment,
            original_value_hash,
            written_value_hash,
            ..
        } => Undo::Segment(SegmentUndo {
            name: name.clone(),
            segment: segment.clone(),
            index: *index,
            original_value_hash: *original_value_hash,
            written_value_hash: *written_value_hash,
            original: backup.as_ref().and_then(|b| b.value().cloned()),
        }),
        Inverse::MoveBack { .. } | Inverse::RecreateDir { .. } | Inverse::None => {
            unreachable!("Inverse::undoes accepts only the registry inverses for a registry op")
        }
    };
    if backup.is_none() && !matches!(undo, Undo::Segment(_)) {
        return decided(RegUndoResult::conflict(
            UndoConflict::BackupMissing,
            format!("{at}: the journal names no backup for the restore"),
        ));
    }
    // The gate hands out the parent for a key target and the key itself for a value or segment target;
    // the inverse must act on the one it needs.
    let fits = matches!(
        (&undo, &checked),
        (Undo::Tree { .. }, CheckedUndoKey::Recreate(_))
            | (Undo::Value | Undo::Segment(_), CheckedUndoKey::Restore(_))
    );
    if !fits {
        return decided(RegUndoResult::conflict(
            UndoConflict::BackupTampered,
            format!(
                "{at}: the journal's inverse {} does not fit the op's target; nothing done",
                intent.inverse.name()
            ),
        ));
    }
    Some(RegUndoPrepared::Ready(Box::new(RegInverse {
        op: intent.op,
        at,
        checked,
        backup,
        undo,
    })))
}

/// Runs the inverse of `inverse`, whose `undo_intent` `token` proves durable, then hits
/// `undo.act.after`. The result goes to `JournalWriter::undo_done` or `JournalWriter::undo_conflict`
/// with the token. See the module's conflict table; a token of another op is `Failed{Internal}`.
///
/// Every inverse acts on the key handle [`gate::check_undo_key`] opened and checked in
/// [`prepare_undo_reg`]; nothing is opened again here.
///
/// - Tree: [`regbackup::restore_tree`] below the checked parent, or [`regbackup::restore_missing`] when
///   the op has no `Done` (intent only, or `VerifyFailed`): the keys of the backup that are missing are
///   put back and no existing key is changed, also when one was changed since (the tree is then the
///   backup plus that change, reported as a difference).
/// - Value: [`regbackup::restore_value`] into the checked key.
/// - Segment: [`regbackup::reinsert_segment`] into the value of the checked key, with the value backup
///   when there is one.
pub fn run_undo_reg(inverse: Box<RegInverse>, token: &UndoToken) -> RegUndoResult {
    let RegInverse {
        op,
        at,
        checked,
        backup,
        undo,
    } = *inverse;
    if token.op() != op {
        return RegUndoResult::failed(
            FailCode::Internal,
            None,
            format!(
                "the undo token is for op {}, not op {op}; {at} left as it is",
                token.op()
            ),
        );
    }
    let wrong_key = || {
        RegUndoResult::failed(
            FailCode::Internal,
            None,
            format!("{at}: the checked undo key is not the kind the inverse acts on; nothing done"),
        )
    };
    match undo {
        Undo::Tree { complete } => {
            let Some(backup) = backup else {
                return RegUndoResult::conflict(UndoConflict::BackupMissing, "no backup");
            };
            let CheckedUndoKey::Recreate(parent) = &checked else {
                return wrong_key();
            };
            let restored = if complete {
                regbackup::restore_missing(parent, &backup)
            } else {
                regbackup::restore_tree(parent, &backup)
            };
            fault::point(fault::UNDO_ACT_AFTER);
            restore_result(restored, &at)
        }
        Undo::Value => {
            let Some(backup) = backup else {
                return RegUndoResult::conflict(UndoConflict::BackupMissing, "no backup");
            };
            let CheckedUndoKey::Restore(key) = &checked else {
                return wrong_key();
            };
            let restored = regbackup::restore_value(key, &backup);
            fault::point(fault::UNDO_ACT_AFTER);
            restore_result(restored, &at)
        }
        Undo::Segment(segment) => {
            let CheckedUndoKey::Restore(key) = &checked else {
                return wrong_key();
            };
            let reinserted = regbackup::reinsert_segment(key, &segment);
            fault::point(fault::UNDO_ACT_AFTER);
            reinsert_result(reinserted, &at, &segment)
        }
    }
}

/// The undo result of a tree or value restore.
fn restore_result(result: Result<RestoreReport, RestoreError>, at: &str) -> RegUndoResult {
    match result {
        Ok(report) => {
            let detail = if report.differences.is_empty() {
                String::new()
            } else {
                format!(
                    "{at}: put back with differences: {}",
                    differences_text(&report.differences)
                )
            };
            let outcome = match report.outcome {
                RestoreOutcome::Restored => UndoOutcome::Restored,
                RestoreOutcome::AlreadyRestored => UndoOutcome::AlreadyRestored,
            };
            RegUndoResult::done(outcome, detail)
        }
        Err(RestoreError::Conflict(conflict)) => {
            RegUndoResult::conflict(conflict.undo_conflict(), format!("{at}: {conflict}"))
        }
        Err(RestoreError::WrongBackupKind) => RegUndoResult::failed(
            FailCode::Internal,
            None,
            format!("{at}: the backup is of the wrong kind"),
        ),
        Err(RestoreError::NotThisKey) => RegUndoResult::conflict(
            UndoConflict::BackupTampered,
            format!("{at}: the backup is not of the key the undo gate checked; nothing restored"),
        ),
        Err(RestoreError::Failed { failure, rollback }) => {
            let undone = match &rollback {
                Rollback::NotNeeded => "nothing had been created".to_owned(),
                Rollback::Done { keys, .. } => format!("the {keys} key(s) created were removed"),
                Rollback::Incomplete { failure, keys } => format!(
                    "removing what was created stopped after {keys} key(s): {failure}; the key is \
                     partly restored"
                ),
                // Only a resumed delete reports keys missing from before it.
                Rollback::PartialBefore { missing, .. } => {
                    format!("{missing} key(s) of the backup are missing")
                }
            };
            RegUndoResult::failed(
                fail_code(failure.error),
                Some(failure.error.code()),
                format!("{at}: the restore failed: {failure}; {undone}"),
            )
        }
    }
}

/// The undo result of a segment re-insert.
fn reinsert_result(
    result: Result<ReinsertOutcome, SegmentError>,
    at: &str,
    undo: &SegmentUndo,
) -> RegUndoResult {
    match result {
        Ok(ReinsertOutcome::AlreadyRestored) => {
            RegUndoResult::done(UndoOutcome::AlreadyRestored, "")
        }
        Ok(ReinsertOutcome::AlreadyPresent) => RegUndoResult::done(
            UndoOutcome::AlreadyRestored,
            format!(
                "{at} was changed since the edit and holds the segment {:?} again",
                undo.segment
            ),
        ),
        Ok(ReinsertOutcome::Reinserted { exact: true }) => {
            RegUndoResult::done(UndoOutcome::Restored, "")
        }
        Ok(ReinsertOutcome::Reinserted { exact: false }) => RegUndoResult::done(
            UndoOutcome::Restored,
            format!(
                "{at} was changed since the edit; the segment {:?} went back in at position {} of \
                 the changed value",
                undo.segment, undo.index
            ),
        ),
        Err(e) => {
            let detail = format!("{at}: {e}");
            match (e.undo_conflict(), &e) {
                (Some(conflict), _) => RegUndoResult::conflict(conflict, detail),
                (None, SegmentError::VerifyFailed) => {
                    RegUndoResult::failed(FailCode::VerifyFailed, None, detail)
                }
                (None, SegmentError::Os(os)) => RegUndoResult::os(os.error, detail),
                (None, _) => RegUndoResult::failed(FailCode::Internal, None, detail),
            }
        }
    }
}
