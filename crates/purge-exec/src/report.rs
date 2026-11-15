//! The execution report document, `purge.exec/1` (M2-X-EXEC).
//!
//! The report of a run is a reading of its journal, not a second set of books: [`build`] takes the
//! session's [`JournalState`] and its copy of the scan document and derives every item, outcome, count
//! and byte figure from them. The only things the journal does not hold are handed in as [`RunNotes`]:
//! who held a locked file, the texts that explain an outcome, and what became of the restore point.
//!
//! | Journal says about an op | Report says |
//! |---|---|
//! | a `done` record | its outcome |
//! | an `intent` without a `done` (the run stopped in the middle of the action) | `Failed{Internal}`, with a warning: recovery decides what happened |
//! | neither (the run was aborted before the item) | `Skipped{NotAttempted}` |
//!
//! Every journalled op is an item of the report. One whose target has no executor in this version (a
//! service, scheduled task or firewall rule) is listed with no `exec_op` and its journalled outcome
//! (skipped), so the report's `counts` equal both its items ([`ExecReport::tally`]) and, for a run
//! that ended, the journal's `done` records (the index entry's counts).
//!
//! # Bytes
//!
//! The bytes kept for an op ([`op_backup_bytes`]) are the sizes of its backup and definition files (they
//! exist once its intent is written) plus, for a quarantine move that happened or is registered for the
//! next restart, the size of what was moved as the acting handle reported it (for a directory, the bytes
//! of the tree below it).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use purge_model::exec::journal::{ItemFacts, UndoOutcome};
use purge_model::exec::op::{
    ExecOp, FailCode, Inverse, ItemOutcome, OpId, OutcomeCounts, SkipReason, resolve,
};
use purge_model::exec::session::{
    ExecReport, ExecReportSchema, Expiry, ItemReport, Locker, RestorePointOutcome, RetentionClass,
    SessionState, SessionSummary, VolumeUsage,
};
use purge_model::{AppRef, Candidate, FileTime};
use purge_plan::emit::ScanDoc;
use purge_win::fs_write::FsError;

use crate::journal::{JournalState, OpState, OpStatus, UndoState};
use crate::storage::{REPORT_FILE, SessionDir, StorageError, StorageRoots};
use crate::undo::{effective_outcome, standing, stands_changed};

#[cfg(test)]
mod tests;

/// What a run knows that its journal does not record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunNotes {
    /// Who held an item's file, per op (from Restart Manager; query only).
    pub lockers: BTreeMap<OpId, Vec<Locker>>,
    /// The text that explains an op's outcome, for the outcomes that are not plain successes.
    pub details: BTreeMap<OpId, String>,
    /// Messages about the run as a whole, in order.
    pub warnings: Vec<String>,
    /// What became of the restore point.
    pub restore_point: RestorePointOutcome,
}

impl Default for RunNotes {
    fn default() -> RunNotes {
        RunNotes {
            lockers: BTreeMap::new(),
            details: BTreeMap::new(),
            warnings: Vec::new(),
            restore_point: RestorePointOutcome::NotRequested,
        }
    }
}

/// A volume as the summary accounts for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataVolume {
    /// The 64-bit serial of the volume holding the data root.
    pub serial: u64,
    /// Its root, e.g. `C:\`.
    pub root: String,
}

/// The 64-bit serial of the volume holding `path`, read from a handle on it.
pub(crate) fn volume_serial(path: &Path) -> Option<u64> {
    let extended = purge_win::secure::extended_path(path).ok()?;
    purge_win::fs::metadata(&extended)
        .ok()
        .map(|meta| meta.file_id.volume_serial)
}

/// The volume holding the store's data root, where backup and definition files are kept: the one
/// [`summary`] and [`usage`] count them on. `None` when it cannot be read.
pub fn data_volume(roots: &StorageRoots) -> Option<DataVolume> {
    let root = roots.volume(roots.data_root()).ok()?.root;
    Some(DataVolume {
        serial: volume_serial(roots.data_root())?,
        root: root.to_string_lossy().into_owned(),
    })
}

/// Writes `report` as the session's `report.json` through the store: create-new (an existing report
/// is never overwritten), flushed with its directory. A failed write discards the file through its own
/// handle.
pub fn write_report(session: &SessionDir, report: &ExecReport) -> Result<(), String> {
    let text = serde_json::to_vec_pretty(report).map_err(|e| e.to_string())?;
    let mut file = session
        .create_file(REPORT_FILE)
        .map_err(|e| e.to_string())?;
    let written = file
        .write_all(&text)
        .map_err(|e| e.to_string())
        .and_then(|()| file.sync().map_err(|e| e.to_string()))
        .and_then(|()| file.sync_dir().map_err(|e| e.to_string()));
    if written.is_err() {
        // The file is Purge's own, created a moment ago.
        let _ = file.discard();
    }
    written
}

/// Whether the session holds its `report.json`; `Err` when the store cannot tell.
pub fn has_report(session: &SessionDir) -> Result<bool, StorageError> {
    match session.open_file(REPORT_FILE) {
        Ok(_) => Ok(true),
        Err(StorageError::Io {
            source: FsError::NotFound,
            ..
        }) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Where the session stands according to its journal.
pub fn session_state(state: &JournalState) -> SessionState {
    if state.commit().is_some() {
        SessionState::Committed
    } else if state.aborted().is_some() {
        SessionState::Aborted
    } else {
        SessionState::Open
    }
}

/// When the run ended according to its journal.
fn finished(state: &JournalState) -> Option<FileTime> {
    state
        .commit()
        .map(|commit| commit.at)
        .or_else(|| state.aborted().map(|aborted| aborted.at))
}

/// The bytes of what an op moved into quarantine: for a move that happened or is registered for the next
/// restart, the size the acting handle reported, with the volume it is on.
///
/// The outcome is the one the op stands at after its `reconcile` records (a retried move that
/// succeeded counts, a boot-time move that was cancelled does not); for a run that has not been
/// reconciled that is its `done` outcome.
fn quarantined(op: &OpState) -> Option<(u64, u64)> {
    let intent = op.intent.as_ref()?;
    let moved = stands_changed(op) && effective_outcome(op).is_some_and(|o| o.changed_system());
    match (&intent.inverse, &intent.pre) {
        (Inverse::MoveBack { volume_serial, .. }, ItemFacts::File(facts)) if moved => {
            Some((*volume_serial, facts.tree_bytes.unwrap_or(facts.size)))
        }
        _ => None,
    }
}

/// The bytes of an op's backup and definition files.
fn backup_file_bytes(op: &OpState) -> u64 {
    op.intent.as_ref().map_or(0, |intent| {
        intent
            .backups()
            .fold(0u64, |sum, backup| sum.saturating_add(backup.bytes))
    })
}

/// The bytes of quarantine and backup data kept for one op (see the module docs).
pub fn op_backup_bytes(op: &OpState) -> u64 {
    backup_file_bytes(op).saturating_add(quarantined(op).map_or(0, |(_, bytes)| bytes))
}

/// The bytes of quarantine and backup data the session holds: the sum over its ops. This is the figure
/// of the journal's `commit` record.
pub fn backup_bytes(state: &JournalState) -> u64 {
    state
        .ops()
        .fold(0u64, |sum, op| sum.saturating_add(op_backup_bytes(op)))
}

/// What an op moved into quarantine and that is still there: [`quarantined`], unless its undo put
/// it back (or found nothing to put back) or expiry deleted it.
fn held_quarantine(op: &OpState) -> Option<(u64, u64)> {
    let restored = matches!(
        op.undo,
        UndoState::Finished(
            UndoOutcome::Restored | UndoOutcome::AlreadyRestored | UndoOutcome::NothingToUndo
        )
    );
    if restored || op.expired.contains(&RetentionClass::Quarantine) {
        return None;
    }
    quarantined(op)
}

/// The bytes of an op's backup and definition files that are still kept: all of them until expiry
/// deleted them. An undo leaves them where they are.
fn held_backup_file_bytes(op: &OpState) -> u64 {
    if op.expired.contains(&RetentionClass::Backup) {
        0
    } else {
        backup_file_bytes(op)
    }
}

/// The bytes of quarantine and backup data still kept for one op: what [`op_backup_bytes`] counts,
/// less what its undo moved back out of quarantine and what expiry deleted.
pub fn op_held_bytes(op: &OpState) -> u64 {
    held_backup_file_bytes(op).saturating_add(held_quarantine(op).map_or(0, |(_, bytes)| bytes))
}

/// The bytes of quarantine and backup data the session still keeps: the sum of [`op_held_bytes`]
/// over its ops. Equal to [`backup_bytes`] until an undo or expiry ran; the index entry's figure.
pub fn held_bytes(state: &JournalState) -> u64 {
    state
        .ops()
        .fold(0u64, |sum, op| sum.saturating_add(op_held_bytes(op)))
}

/// The bytes the session still keeps ([`held_bytes`]) per volume: quarantined items on the volume
/// they were moved on, backup and definition files on the data root's volume (when it is known). A
/// volume left with nothing is not listed.
pub fn usage(state: &JournalState, data: Option<&DataVolume>) -> Vec<VolumeUsage> {
    let mut by_serial: BTreeMap<u64, u64> = BTreeMap::new();
    let mut add = |serial: u64, bytes: u64| {
        if bytes > 0 {
            let slot = by_serial.entry(serial).or_insert(0);
            *slot = slot.saturating_add(bytes);
        }
    };
    for op in state.ops() {
        if let Some((serial, bytes)) = held_quarantine(op) {
            add(serial, bytes);
        }
        if let Some(data) = data {
            add(data.serial, held_backup_file_bytes(op));
        }
    }
    let root_of = |serial: u64| {
        state
            .header()
            .volumes
            .iter()
            .find(|volume| volume.serial == serial)
            .map(|volume| volume.root.clone())
            .or_else(|| {
                data.filter(|data| data.serial == serial)
                    .map(|data| data.root.clone())
            })
            .unwrap_or_default()
    };
    by_serial
        .into_iter()
        .map(|(serial, bytes)| VolumeUsage {
            serial,
            root: root_of(serial),
            bytes,
        })
        .collect()
}

/// The outcome the report states for an op (see the table in the module docs).
fn reported_outcome(op: &OpState) -> ItemOutcome {
    match op.status() {
        OpStatus::Done(outcome) => outcome.clone(),
        OpStatus::IntentOnly => ItemOutcome::Failed {
            code: FailCode::Internal,
            os_error: None,
            detail: "the run stopped while the item was acted on; recovery decides what happened"
                .into(),
        },
        OpStatus::Validated => ItemOutcome::Skipped {
            reason: SkipReason::NotAttempted,
        },
    }
}

/// The executor op of a journalled op: the one of its intent, else the one its plan item resolves to.
fn exec_op_of(op: &OpState, candidate: Option<&Candidate>) -> Option<ExecOp> {
    if let Some(intent) = &op.intent {
        return Some(intent.exec_op.clone());
    }
    let resolved = resolve(&op.target, candidate?.action).ok()?;
    (resolved.target() == op.target).then_some(resolved)
}

/// The report of the session `state` describes, whose copy of the scan document is `scan`. `at` is the
/// time to state as the end of a run whose journal has neither `commit` nor `aborted` (a journal that
/// could not be written to the end).
pub fn build(state: &JournalState, scan: &ScanDoc, notes: &RunNotes, at: FileTime) -> ExecReport {
    let header = state.header();
    let mut warnings = notes.warnings.clone();
    let mut items = Vec::new();
    for op in state.ops() {
        let candidate = scan.items.iter().find(|c| c.id == op.item);
        let outcome = reported_outcome(op);
        let detail = notes.details.get(&op.op);
        let exec_op = exec_op_of(op, candidate);
        if exec_op.is_none() && detail.is_none() {
            warnings.push(format!(
                "item {} (op {}) was not acted on: it has no executor in this version",
                op.item.0, op.op
            ));
        }
        if let Some(detail) = detail.filter(|_| !outcome.is_success()) {
            warnings.push(format!("item {} (op {}): {detail}", op.item.0, op.op));
        }
        if matches!(op.status(), OpStatus::IntentOnly) {
            warnings.push(format!(
                "item {} (op {}) has an intent and no outcome in the journal",
                op.item.0, op.op
            ));
        }
        items.push(ItemReport {
            item: op.item.clone(),
            op: op.op,
            target: op.target.clone(),
            exec_op,
            outcome,
            backup_bytes: op_backup_bytes(op),
            lockers: notes.lockers.get(&op.op).cloned().unwrap_or_default(),
        });
    }
    if let Some(aborted) = state.aborted() {
        warnings.push(format!(
            "the run was aborted ({:?}){}{}; items after the stop are untouched",
            aborted.reason,
            if aborted.detail.is_empty() { "" } else { ": " },
            aborted.detail
        ));
    }
    let mut counts = OutcomeCounts::default();
    for item in &items {
        counts.record(&item.outcome);
    }
    ExecReport {
        schema: ExecReportSchema,
        session: header.session.clone(),
        app: header.app.clone(),
        plan_hash: header.plan_hash,
        selection_hash: header.selection_hash,
        state: session_state(state),
        started: header.created,
        finished: finished(state).unwrap_or(at),
        backup_bytes: items
            .iter()
            .fold(0u64, |sum, item| sum.saturating_add(item.backup_bytes)),
        pending_reboot: state.pending_reboot().next().is_some(),
        items,
        counts,
        restore_point: notes.restore_point.clone(),
        warnings,
    }
}

/// The owner the plan's items share, when they all name the same app.
fn common_owner(state: &JournalState, scan: &ScanDoc) -> Option<AppRef> {
    let mut owners = state
        .ops()
        .filter_map(|op| scan.items.iter().find(|c| c.id == op.item))
        .map(|candidate| &candidate.owner);
    let first = owners.next()?;
    owners.all(|owner| owner == first).then(|| first.clone())
}

/// The index entry of the session `state` describes: every figure is the journal's (the counts of its
/// `done` records), and `journal` records how far the journal reaches ([`JournalState::mark`], review
/// M7), which a later read checks ([`crate::journal::check_mark`]).
///
/// The undo records count too: `state` is `Undone` or `PartiallyUndone` once any op has one
/// ([`crate::undo`]'s standing), `undone` is the number of ops put back (`Restored` or
/// `AlreadyRestored`), and `backup_bytes` and `usage` are what the session still keeps
/// ([`held_bytes`], [`usage`]): what an undo moved back out of quarantine, or expiry deleted, is no
/// longer counted. `purged` is left empty: expiry marks the classes it purged in the entry itself.
pub fn summary(state: &JournalState, scan: &ScanDoc, data: Option<&DataVolume>) -> SessionSummary {
    summary_with_owner(state, common_owner(state, scan), data)
}

/// [`summary`] with the owner given (an existing entry's) instead of read from the scan document.
pub(crate) fn summary_with_owner(
    state: &JournalState,
    owner: Option<AppRef>,
    data: Option<&DataVolume>,
) -> SessionSummary {
    let header = state.header();
    let standing = standing(state.ops());
    SessionSummary {
        id: header.session.clone(),
        app: header.app.clone(),
        owner,
        plan_hash: header.plan_hash,
        state: standing.state.unwrap_or_else(|| session_state(state)),
        started: header.created,
        finished: finished(state),
        counts: state.counts(),
        undone: standing.undone,
        backup_bytes: held_bytes(state),
        usage: usage(state, data),
        expires: Expiry::from_start(header.created),
        purged: Vec::new(),
        pending_reboot: state.pending_reboot().next().is_some(),
        journal: Some(state.mark()),
    }
}
