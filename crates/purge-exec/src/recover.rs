//! Crash recovery: resume or roll back an interrupted session (M2-X-UNDO; ENGINE_PLAN.md §7.6, §10.3).
//!
//! A run that died leaves a journal with neither `commit` nor `aborted`. [`pending`] lists such
//! sessions (and those a crash left with an interrupted undo, an interrupted retry of a held item, or
//! without their index entry or report). [`probe`] says what really happened to an op whose intent has
//! no `done`. [`resume`] carries the session to the end the run would have reached; [`rollback`] brings
//! it back to where the run started. Both are idempotent: a second call finds nothing to do and
//! writes nothing. [`retry_held`] tries the held items of a finished session again; recovery never
//! does.
//!
//! # The probe
//!
//! An op with an intent and no `done` may have run in full, in part or not at all. The probe reads
//! the system and changes nothing. Each action module probes its own ops ([`act_fs::probe_fs`],
//! [`act_reg::probe_reg`], [`act_typed::probe_package`]) and completes them forward
//! ([`act_fs::complete_fs`], [`act_reg::complete_reg`], [`act_typed::complete_package`]); the verdicts
//! are this module's table.
//!
//! | Op | Found | Probe |
//! |---|---|---|
//! | quarantine move | its boot-time move pair is registered, once | `Done(PendingReboot)` |
//! | quarantine move | the source holds the recorded file id, the quarantine does not | `NotDone` |
//! | quarantine move | the quarantine holds the recorded file id, the source does not | `Done(Done)` |
//! | quarantine move | both, neither, or one cannot be read | `Attention` |
//! | remove directory | the recorded directory is at the path | `NotDone` |
//! | remove directory | nothing is at the path | `Done(Done)` |
//! | remove directory | something else is there, or it cannot be read | `Attention` |
//! | key tree, empty key | no root key ([`TreeState::Absent`]) | `Done(Done)` |
//! | key tree, empty key | the tree as backed up ([`TreeState::Intact`]) | `NotDone` |
//! | key tree, empty key | whole subtrees missing, the rest as backed up | `Partial` |
//! | key tree, empty key | differs from the backup; gate refusal; backup unusable | `Attention` |
//! | value | absent | `Done(Done)` |
//! | value | type and bytes of the backup | `NotDone` |
//! | value | anything else | `Attention` |
//! | segment edit | the value hashes to what the edit writes | `Done(Done)` |
//! | segment edit | the value hashes to what it was before | `NotDone` |
//! | segment edit | anything else | `Attention` |
//! | package | not listed | `Done(Done)` |
//! | package | listed | `NotDone` |
//! | package | the listing failed | `Attention` |
//!
//! # Resume
//!
//! | The session | What resume does |
//! |---|---|
//! | no journal, one without a complete header, or an empty one | removes the directory by handle when it holds nothing but the scan copy and that journal ([`SessionDir::remove_unstarted`]; [`RecoverError::Unstarted`] otherwise) |
//! | a journal without a `settings` record (written before the record existed) and validation incomplete | nothing was acted on: writes `aborted` (`Cancelled`) |
//! | the run stopped before every item was validated | continued as if never interrupted ([`Run::resume`]): the items without a `validated` record are validated now, a journalled record is never validated again |
//! | an open intent, probe `Done` | writes the missing `done` |
//! | an open intent, probe `NotDone` | runs the action now, bound to the journalled intent, and writes its `done`; a file in use goes to the locked-file ladder ([`Run::settle_open`]) |
//! | an open intent, probe `Partial` | finishes the key delete from the backup ([`act_reg::complete_reg`]) |
//! | an open intent, probe `Attention` | writes `done` `Failed{VerifyFailed}`; the item is left as it is |
//! | items with no intent yet | run through [`Run::run_item`]; a backup file a crash left is adopted when it verifies and equals a fresh capture, else deleted and written anew |
//! | held items | stay held: only [`retry_held`] tries them again |
//! | the end | `commit`, index entry and report through [`Run::finish`] |
//! | finished session, undo interrupted | finishes the undo: the ops in progress, and the ops the undo's `undo_plan` names that it had not reached |
//! | finished session, retry of a held item interrupted | probes the move and ends the retry (`Done`, `HeldRetry` or `Failed{VerifyFailed}`) |
//! | finished session without its report | writes `report.json` from the journal and the scan copy |
//! | finished session without a current index entry | writes the entry |
//!
//! # Rollback
//!
//! | The session | What rollback does |
//! |---|---|
//! | no journal; validation incomplete | nothing was acted on: removes the directory, or writes `aborted` (`RolledBack`); nothing to undo |
//! | an open intent, probe `Done` | writes the missing `done` |
//! | an open intent, probe `NotDone` | writes `done` `Skipped{NotAttempted}`: the action did not run and will not |
//! | an open intent, probe `Partial` or `Attention` | writes `done` `Failed{VerifyFailed}`; its undo then runs in the completing form (a key tree is completed from its backup, a move back looks where the item is) |
//! | every op with an intent | undone in reverse order by the undo driver ([`crate::undo`]) |
//! | the end | `aborted` (`RolledBack`), index entry and report through [`Run::abort`] |
//! | finished session | as resume: an interrupted undo or retry is finished, a missing report written, the index entry brought up to date |
//!
//! A journal record that cannot be written stops recovery at once with [`RecoverError::Journal`];
//! everything else is the result of its op.

// The store's and the journal's errors carry paths and are over clippy's size threshold wherever
// they are returned in this crate.
#![allow(clippy::result_large_err)]

use std::collections::BTreeSet;

use purge_guard::deny::DenyList;
use purge_model::FileTime;
use purge_model::exec::journal::{AbortReason, Intent};
use purge_model::exec::op::{ExecOp, FailCode, ItemOutcome, OpId, SkipReason};
use purge_model::exec::session::{ExecReport, SessionId, SessionState, UndoItemReport};
use purge_win::fs_write::FsError;

use crate::act_fs::{self, Retry};
use crate::act_reg;
use crate::act_typed::{self, PackageBackend};
use crate::execute::{self, Abort, ExecEnv, ExecError, ItemStep, Run};
use crate::gate::{GateCtx, GateSetupError};
use crate::journal::{
    self, JournalError, JournalRead, JournalState, JournalWriter, OpState, OpStatus, sha256_bytes,
};
use crate::locked::{self, PendingRenames};
use crate::prepare::LockerQuery;
use crate::regbackup::TreeState;
use crate::report::{self, RunNotes};
use crate::storage::{SessionDir, StorageError, StorageRoots, now};
use crate::undo::{self, CtxError, Driver, standing, undo_order};

#[cfg(test)]
mod tests;

/// What recovery works with: everything a run needs, because resume continues one.
pub struct RecoverEnv<'a> {
    /// Purge's store.
    pub roots: &'a StorageRoots,
    /// The deny-list compiled from the live `GuardEnv`.
    pub deny: &'a DenyList,
    /// The package calls.
    pub packages: &'a dyn PackageBackend,
    /// The Restart Manager, for the locked-file ladder of the items resume still runs.
    pub lockers: &'a dyn LockerQuery,
    /// The boot-time move list.
    pub pending_renames: &'a mut dyn PendingRenames,
    /// How an item in use is retried.
    pub retry: Retry,
}

impl<'a> RecoverEnv<'a> {
    /// An environment with the standard retries.
    pub fn new(
        roots: &'a StorageRoots,
        deny: &'a DenyList,
        packages: &'a dyn PackageBackend,
        lockers: &'a dyn LockerQuery,
        pending_renames: &'a mut dyn PendingRenames,
    ) -> RecoverEnv<'a> {
        RecoverEnv {
            roots,
            deny,
            packages,
            lockers,
            pending_renames,
            retry: Retry::standard(),
        }
    }
}

impl std::fmt::Debug for RecoverEnv<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoverEnv")
            .field("roots", &self.roots)
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

/// Why recovery did not run, or stopped.
#[derive(Debug, thiserror::Error)]
pub enum RecoverError {
    /// The store refused (integrity, a missing session, I/O).
    #[error(transparent)]
    Store(#[from] StorageError),
    /// The journal is damaged or cut, cannot be opened, or a record could not be written. Recovery
    /// stopped at once; what it had journalled before stays.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The gate could not be set up.
    #[error(transparent)]
    Gate(#[from] GateSetupError),
    /// The run could not be taken up again.
    #[error(transparent)]
    Exec(#[from] ExecError),
    /// The session has no journal (or one without a complete header) and its directory holds more
    /// than the scan copy, so it was not removed.
    #[error("the session never started and its directory was not removed: {0}")]
    Unstarted(String),
    /// The op is not part of the session.
    #[error("op {0} is not part of the session")]
    UnknownOp(OpId),
}

impl From<CtxError> for RecoverError {
    fn from(error: CtxError) -> RecoverError {
        match error {
            CtxError::Store(e) => RecoverError::Store(e),
            CtxError::Gate(e) => RecoverError::Gate(e),
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// The list
// ---------------------------------------------------------------------------------------------------

/// Why a session is on the recovery list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingKind {
    /// Its journal ends with neither `commit` nor `aborted`: the run was interrupted.
    Run,
    /// Its run ended, and an undo was interrupted: an op's undo is in progress, or the undo's
    /// `undo_plan` names ops it had not reached.
    Undo,
    /// Its run ended, and a retry of a held item was interrupted.
    Retry,
    /// Its run ended, and the index has no entry for it or its `report.json` was never written (the
    /// crash came before the index or the report was written).
    Unindexed,
    /// It has no journal, or one without a complete header, or an empty one: no run started.
    Unstarted,
    /// Its journal cannot be read, or does not fit the mark of its index entry.
    Damaged,
}

/// One session that needs recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSession {
    /// The session.
    pub session: SessionId,
    /// Why it is listed.
    pub kind: PendingKind,
    /// The app id of its plan, when the journal header can be read.
    pub app: Option<String>,
    /// When its run started, when the journal header can be read.
    pub started: Option<FileTime>,
    /// Ops with an intent and no `done`.
    pub open_intents: Vec<OpId>,
    /// Ops whose undo was interrupted: those in progress, then those the interrupted undo's
    /// `undo_plan` names and had not reached.
    pub undo_in_progress: Vec<OpId>,
    /// Ops whose retry was interrupted.
    pub retries_in_flight: Vec<OpId>,
    /// Text for the user; the error for [`PendingKind::Damaged`].
    pub detail: String,
}

/// What [`pending`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingList {
    /// The sessions that need recovery, in id order.
    pub sessions: Vec<PendingSession>,
    /// Session directories that failed their integrity check (each was renamed aside where possible).
    pub rejected: Vec<String>,
    /// Anything else the user should know.
    pub warnings: Vec<String>,
}

/// Whether the error says the journal file does not exist.
fn journal_missing(error: &JournalError) -> bool {
    matches!(
        error,
        JournalError::Empty { .. }
            | JournalError::Store(StorageError::Io {
                source: FsError::NotFound,
                ..
            })
    )
}

/// Lists the sessions that need recovery (`journal recover`). Read-only apart from what the store's
/// integrity check renames aside.
pub fn pending(roots: &StorageRoots) -> Result<PendingList, StorageError> {
    let mut list = PendingList::default();
    let listing = roots.list_sessions()?;
    list.rejected = listing.rejected.iter().map(ToString::to_string).collect();
    let index = undo::read_index(roots, &mut list.warnings)?;
    for id in listing.sessions {
        let found = |kind, detail: String| PendingSession {
            session: id.clone(),
            kind,
            app: None,
            started: None,
            open_intents: Vec::new(),
            undo_in_progress: Vec::new(),
            retries_in_flight: Vec::new(),
            detail,
        };
        let session = match roots.open_session(&id) {
            Ok(session) => session,
            Err(e @ StorageError::Integrity { .. }) => {
                list.rejected.push(e.to_string());
                continue;
            }
            Err(StorageError::SessionNotFound(_)) => continue,
            Err(e) => return Err(e),
        };
        let entry = index.as_ref().and_then(|index| index.get(&id));
        let mark = entry.and_then(|entry| entry.journal.as_ref());
        let read = match journal::read_indexed(&session, mark) {
            Ok(read) => read,
            Err(e) if journal_missing(&e) => {
                list.sessions
                    .push(found(PendingKind::Unstarted, "no run started".to_owned()));
                continue;
            }
            Err(e) => {
                list.sessions
                    .push(found(PendingKind::Damaged, e.to_string()));
                continue;
            }
        };
        let state = &read.state;
        let ids = |ops: &mut dyn Iterator<Item = &OpState>| ops.map(|op| op.op).collect::<Vec<_>>();
        let undo_in_progress = ids(&mut state.undo_in_progress());
        let undo_unreached = state.undo_unfinished();
        let retries_in_flight = ids(&mut state.retries_in_flight());
        let mut report_missing = || {
            report::has_report(&session).map_or_else(
                |e| {
                    list.warnings.push(format!(
                        "session {id}: whether its report exists cannot be told: {e}"
                    ));
                    false
                },
                |found| !found,
            )
        };
        let (kind, detail) = if !state.is_finished() {
            (
                PendingKind::Run,
                "the run ended with neither commit nor aborted".to_owned(),
            )
        } else if !undo_in_progress.is_empty() || !undo_unreached.is_empty() {
            (
                PendingKind::Undo,
                format!(
                    "an undo was interrupted; {} op(s) in progress, {} op(s) not reached",
                    undo_in_progress.len(),
                    undo_unreached.len()
                ),
            )
        } else if !retries_in_flight.is_empty() {
            (
                PendingKind::Retry,
                "a retry of a held item was interrupted".to_owned(),
            )
        } else if index.is_some() && entry.is_none() {
            (
                PendingKind::Unindexed,
                "the run ended and the session index has no entry for it".to_owned(),
            )
        } else if report_missing() {
            (
                PendingKind::Unindexed,
                "the run ended and its report was never written".to_owned(),
            )
        } else {
            continue;
        };
        let unreached: Vec<OpId> = undo_unreached
            .into_iter()
            .filter(|op| !undo_in_progress.contains(op))
            .collect();
        let mut undoing = undo_in_progress;
        undoing.extend(unreached);
        list.sessions.push(PendingSession {
            app: Some(state.header().app.clone()),
            started: Some(state.header().created),
            open_intents: ids(&mut state.open_intents()),
            undo_in_progress: undoing,
            retries_in_flight,
            ..found(kind, detail)
        });
    }
    Ok(list)
}

// ---------------------------------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------------------------------

/// What really happened to an op whose intent has no `done` (see the module's table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// The action did not run: the item is as the intent recorded it.
    NotDone,
    /// The action ran to its end; this is the outcome its `done` would have carried.
    Done(ItemOutcome),
    /// A key-tree delete stopped half way: the keys that exist are as backed up, and this many keys of
    /// the backup are missing.
    Partial {
        /// Keys of the backup that are missing.
        missing_keys: usize,
    },
    /// The state cannot be told, or is neither the one before nor the one after the action.
    Attention {
        /// What was found.
        detail: String,
    },
}

impl Probe {
    fn attention(detail: impl Into<String>) -> Probe {
        Probe::Attention {
            detail: detail.into(),
        }
    }
}

/// What a place holds, next to the identity the intent recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Seen {
    /// Nothing.
    Missing,
    /// The recorded object.
    Recorded,
    /// Another object.
    Other,
    /// It cannot be read.
    Unknown,
}

/// The probe of a quarantine move from what its source path and its quarantine path hold.
pub(crate) fn probe_move(source: Seen, quarantine: Seen) -> Probe {
    match (source, quarantine) {
        (Seen::Recorded, Seen::Missing | Seen::Other) => Probe::NotDone,
        (Seen::Missing | Seen::Other, Seen::Recorded) => Probe::Done(ItemOutcome::Done),
        (Seen::Recorded, Seen::Recorded) => {
            Probe::attention("the recorded item is at its path and in quarantine")
        }
        (Seen::Unknown, _) | (_, Seen::Unknown) => {
            Probe::attention("the item's path or its quarantine cannot be read")
        }
        (Seen::Missing | Seen::Other, Seen::Missing | Seen::Other) => {
            Probe::attention("the recorded item is neither at its path nor in quarantine")
        }
    }
}

/// The probe of a remove-directory from what its path holds.
pub(crate) fn probe_remove_dir(path: Seen) -> Probe {
    match path {
        Seen::Recorded => Probe::NotDone,
        Seen::Missing => Probe::Done(ItemOutcome::Done),
        Seen::Other => {
            Probe::attention("another object than the recorded directory is at the path")
        }
        Seen::Unknown => Probe::attention("the path cannot be read"),
    }
}

/// The probe of a key delete from the live tree next to its backup.
pub(crate) fn probe_key(tree: &TreeState) -> Probe {
    match tree {
        TreeState::Absent => Probe::Done(ItemOutcome::Done),
        TreeState::Intact => Probe::NotDone,
        TreeState::Partial { missing_keys } => Probe::Partial {
            missing_keys: *missing_keys,
        },
        TreeState::Diverged { at, change } => Probe::attention(format!(
            "the key differs from its backup at {at:?}: {change}"
        )),
    }
}

/// The probe of a value delete: `live` is the value's type and bytes now, `backup` what was backed up.
pub(crate) fn probe_value(live: Option<(u32, &[u8])>, backup: (u32, &[u8])) -> Probe {
    match live {
        None => Probe::Done(ItemOutcome::Done),
        Some(live) if live == backup => Probe::NotDone,
        Some(_) => Probe::attention("the value is not the one backed up"),
    }
}

/// The probe of a segment edit: `live` is the value's bytes now (`None`: no value), `original` and
/// `written` the bytes' hashes before and after the edit as the intent recorded them.
pub(crate) fn probe_segment(
    live: Option<&[u8]>,
    original: purge_model::exec::op::Sha256Hex,
    written: purge_model::exec::op::Sha256Hex,
) -> Probe {
    match live.map(sha256_bytes) {
        Some(hash) if hash == written => Probe::Done(ItemOutcome::Done),
        Some(hash) if hash == original => Probe::NotDone,
        Some(_) => Probe::attention("the value is neither what it was nor what the edit writes"),
        None => Probe::attention("the value no longer exists"),
    }
}

/// The probe of a package removal: whether the package is still listed (`None`: the listing failed).
pub(crate) fn probe_package(listed: Option<bool>) -> Probe {
    match listed {
        Some(false) => Probe::Done(ItemOutcome::Done),
        Some(true) => Probe::NotDone,
        None => Probe::attention("the packages cannot be listed"),
    }
}

/// Probes the op of `intent`, which has no `done`, through its action module: [`act_fs::probe_fs`],
/// [`act_reg::probe_reg`] (the key checked by the undo gate in `ctx`) or [`act_typed::probe_package`].
pub(crate) fn probe_intent(
    ctx: &GateCtx,
    session: &SessionDir,
    intent: &Intent,
    pending: &dyn PendingRenames,
    packages: &dyn PackageBackend,
) -> Probe {
    match &intent.exec_op {
        ExecOp::QuarantineMove { .. } | ExecOp::RemoveDirIfEmpty { .. } => {
            act_fs::probe_fs(session, intent, pending)
        }
        ExecOp::RemovePackage { .. } => act_typed::probe_package(packages, intent),
        _ => act_reg::probe_reg(ctx, session, intent),
    }
}

/// Probes op `op` of `session` (see the module's table). An op with a `done` is `Done` with that
/// outcome; one with neither intent nor `done` is `NotDone`. Changes nothing.
pub fn probe(session: &SessionId, op: OpId, env: &RecoverEnv<'_>) -> Result<Probe, RecoverError> {
    env.roots.check()?;
    let dir = env.roots.open_session(session)?;
    let read = journal::read(&dir)?;
    let state = read.state.op(op).ok_or(RecoverError::UnknownOp(op))?;
    match (state.status(), &state.intent) {
        (OpStatus::Done(outcome), _) => Ok(Probe::Done(outcome.clone())),
        (OpStatus::IntentOnly, Some(intent)) => {
            let mut warnings = Vec::new();
            let ctx = undo::gate_ctx(env.roots, env.deny, &dir, &read.state, &mut warnings)?;
            Ok(probe_intent(
                &ctx,
                &dir,
                intent,
                &*env.pending_renames,
                env.packages,
            ))
        }
        _ => Ok(Probe::NotDone),
    }
}

// ---------------------------------------------------------------------------------------------------
// Resume and rollback
// ---------------------------------------------------------------------------------------------------

/// Which way recovery went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoverMode {
    /// [`resume`].
    Resume,
    /// [`rollback`].
    Rollback,
}

/// An op whose intent had no `done`, and what recovery found and journalled for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledOp {
    /// The op.
    pub op: OpId,
    /// What the probe found.
    pub probe: Probe,
    /// The `done` outcome recovery wrote for it.
    pub outcome: ItemOutcome,
}

/// What a recovery did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverOutput {
    /// The session.
    pub session: SessionId,
    /// Resume or rollback.
    pub mode: RecoverMode,
    /// Where the session stands now; `None` when its directory was removed.
    pub state: Option<SessionState>,
    /// Whether the directory of a session that never started was removed.
    pub removed: bool,
    /// The ops whose intent had no `done`.
    pub settled: Vec<SettledOp>,
    /// The report of the run recovery ended (`commit` after a resume, `aborted` after a rollback).
    pub report: Option<ExecReport>,
    /// Whether that report was written as the session's `report.json`.
    pub report_written: bool,
    /// The ops recovery undid (a rollback, or an interrupted undo it finished), in order.
    pub undone: Vec<UndoItemReport>,
    /// The interrupted retries of held items recovery ended, with the outcome it journalled.
    pub retries: Vec<(OpId, ItemOutcome)>,
    /// Whether the session's index entry is current.
    pub index_updated: bool,
    /// Anything else the user should know.
    pub warnings: Vec<String>,
}

/// Continues an interrupted session to the end its run would have reached (`journal resume`; see the
/// module's table). A second call changes nothing.
pub fn resume(session: &SessionId, env: RecoverEnv<'_>) -> Result<RecoverOutput, RecoverError> {
    recover(session, env, RecoverMode::Resume)
}

/// Brings an interrupted session back to where its run started (`journal rollback`; see the module's
/// table). A second call changes nothing.
pub fn rollback(session: &SessionId, env: RecoverEnv<'_>) -> Result<RecoverOutput, RecoverError> {
    recover(session, env, RecoverMode::Rollback)
}

/// The executor's environment for the part of recovery that goes through [`Run`]: the same store,
/// deny-list, backends and retry waits.
fn exec_env<'e>(env: &'e mut RecoverEnv<'_>) -> ExecEnv<'e> {
    let mut exec = ExecEnv::new(
        env.roots,
        env.deny,
        env.packages,
        env.lockers,
        &mut *env.pending_renames,
    );
    exec.retry = Retry::with(env.retry.delays().to_vec(), std::thread::sleep);
    exec
}

fn recover(
    id: &SessionId,
    mut env: RecoverEnv<'_>,
    mode: RecoverMode,
) -> Result<RecoverOutput, RecoverError> {
    let mut out = RecoverOutput {
        session: id.clone(),
        mode,
        state: None,
        removed: false,
        settled: Vec::new(),
        report: None,
        report_written: false,
        undone: Vec::new(),
        retries: Vec::new(),
        index_updated: false,
        warnings: Vec::new(),
    };
    env.roots.check()?;
    let session = env.roots.open_session(id)?;
    let index = undo::read_index(env.roots, &mut out.warnings)?;
    let mark = index
        .as_ref()
        .and_then(|index| index.get(id))
        .and_then(|entry| entry.journal.as_ref());
    let read = match journal::read_indexed(&session, mark) {
        Ok(read) => read,
        Err(e) if journal_missing(&e) => {
            session
                .remove_unstarted()
                .map_err(|e| RecoverError::Unstarted(e.to_string()))?;
            out.removed = true;
            return Ok(out);
        }
        Err(e) => return Err(e.into()),
    };
    if !read.state.is_finished() {
        let state = &read.state;
        let validated = state.validated_count() == state.header().items;
        match mode {
            // A journal from before the `settings` record cannot be resumed; one that stopped in its
            // validation acted on nothing and ends here.
            RecoverMode::Resume if state.settings().is_none() && !validated => {
                end_unvalidated(&session, mode)?;
            }
            RecoverMode::Resume => resume_run(&mut env, session, &mut out)?,
            RecoverMode::Rollback if !validated => end_unvalidated(&session, mode)?,
            RecoverMode::Rollback => rollback_run(&mut env, session, &read, &mut out)?,
        }
    }
    finish_tail(&mut env, id, index.is_some(), &mut out)?;
    Ok(out)
}

/// Ends a run that stopped before every item was validated and is not continued: nothing was acted
/// on, so the journal only gets its `aborted` and there is nothing to undo.
fn end_unvalidated(session: &SessionDir, mode: RecoverMode) -> Result<(), RecoverError> {
    let reason = match mode {
        RecoverMode::Resume => AbortReason::Cancelled,
        RecoverMode::Rollback => AbortReason::RolledBack,
    };
    let mut journal = JournalWriter::open_append(session)?;
    journal.abort(
        now(),
        reason,
        "the run stopped before every item was validated; nothing was acted on".to_owned(),
    )?;
    Ok(())
}

/// Resume: the run is taken up again ([`Run::resume`], which validates what the interrupted pass had
/// not reached), every open intent is settled by its probe and forward completion
/// ([`Run::settle_open`]), the items without an intent run, and the run ends.
fn resume_run(
    env: &mut RecoverEnv<'_>,
    session: SessionDir,
    out: &mut RecoverOutput,
) -> Result<(), RecoverError> {
    let scan = execute::read_scan_copy(&session)?;
    let mut run = Run::resume(exec_env(env), session, &scan)?;
    let open: Vec<OpId> = run.state().open_intents().map(|op| op.op).collect();
    let mut aborted = None;
    for op in open {
        match run.settle_open(op) {
            Ok(Some(settled)) => out.settled.push(settled),
            Ok(None) => {}
            Err(abort) => {
                aborted = Some(abort);
                break;
            }
        }
    }
    if aborted.is_none() {
        let ops: Vec<OpId> = run.plan().items().iter().map(|item| item.op).collect();
        for op in ops {
            match run.run_item(op) {
                Ok(ItemStep::OpenIntent) => out.warnings.push(format!(
                    "op {op} still has an intent without a done; the run cannot be committed"
                )),
                Ok(_) => {}
                Err(abort) => {
                    aborted = Some(abort);
                    break;
                }
            }
        }
    }
    let output = match aborted {
        Some(abort) => run.abort(abort),
        None => run.finish(),
    };
    out.report_written = output.report_written;
    out.report = Some(output.report);
    Ok(())
}

fn failed(code: FailCode, os_error: Option<u32>, detail: impl Into<String>) -> ItemOutcome {
    ItemOutcome::Failed {
        code,
        os_error,
        detail: detail.into(),
    }
}

fn rollback_run(
    env: &mut RecoverEnv<'_>,
    session: SessionDir,
    read: &JournalRead,
    out: &mut RecoverOutput,
) -> Result<(), RecoverError> {
    let open: Vec<OpState> = read.state.open_intents().cloned().collect();
    let mut journal = JournalWriter::open_append(&session)?;
    let ctx = undo::gate_ctx(
        env.roots,
        env.deny,
        &session,
        &read.state,
        &mut out.warnings,
    )?;
    for op in &open {
        let Some(intent) = &op.intent else {
            continue;
        };
        let probe = probe_intent(&ctx, &session, intent, &*env.pending_renames, env.packages);
        let Some(token) = journal.resume_intent(op.op) else {
            continue;
        };
        let outcome = match &probe {
            Probe::Done(outcome) => outcome.clone(),
            Probe::NotDone => ItemOutcome::Skipped {
                reason: SkipReason::NotAttempted,
            },
            Probe::Partial { missing_keys } => failed(
                FailCode::VerifyFailed,
                None,
                format!("the key delete stopped half way; {missing_keys} key(s) are missing"),
            ),
            Probe::Attention { detail } => failed(FailCode::VerifyFailed, None, detail.clone()),
        };
        journal.done(token, outcome.clone())?;
        out.settled.push(SettledOp {
            op: op.op,
            probe,
            outcome,
        });
    }
    journal.sync()?;

    let all: BTreeSet<OpId> = journal
        .state()
        .ops()
        .filter(|op| op.intent.is_some())
        .map(|op| op.op)
        .collect();
    let covered = {
        let mut driver = Driver {
            session: &session,
            journal: &mut journal,
            ctx: &ctx,
            pending: &mut *env.pending_renames,
            retry: &env.retry,
        };
        driver.reconcile(&mut out.warnings)?;
        driver.run(&undo_order(&read.records, &all))
    };
    out.undone.extend(covered.items);
    if let Some(e) = covered.stopped {
        return Err(e.into());
    }
    drop(journal);

    // The run's end: `aborted`, the index entry and the report, through the executor's own close when
    // the run can be bound again, else the `aborted` record alone (the index entry and the report
    // follow in the tail).
    let abort = Abort {
        reason: AbortReason::RolledBack,
        detail: "rolled back after an interrupted run".to_owned(),
    };
    let id = session.id().clone();
    let bound = execute::read_scan_copy(&session)
        .and_then(|scan| Run::resume(exec_env(env), session, &scan));
    match bound {
        Ok(run) => {
            let output = run.abort(abort);
            out.report_written = output.report_written;
            out.report = Some(output.report);
        }
        Err(e) => {
            out.warnings.push(format!(
                "the run could not be bound to its plan again ({e}); its report is written from the \
                 journal"
            ));
            let session = env.roots.open_session(&id)?;
            let mut journal = JournalWriter::open_append(&session)?;
            journal.abort(now(), abort.reason, abort.detail)?;
        }
    }
    Ok(())
}

/// What the journal gets for an interrupted retry of a held item, from where the item is now.
pub(crate) fn retry_outcome(probe: &Probe) -> ItemOutcome {
    match probe {
        Probe::Done(outcome) => outcome.clone(),
        Probe::NotDone => ItemOutcome::HeldRetry,
        Probe::Partial { .. } => failed(FailCode::Internal, None, "a move cannot be half done"),
        Probe::Attention { detail } => failed(FailCode::VerifyFailed, None, detail.clone()),
    }
}

/// Writes `report.json` for a finished session that has none (a crash after `commit` or `aborted` and
/// before the report): built from the journal and the scan copy ([`report::build`]). The run's
/// per-item notes were not journalled and are not in it. Whether it was written.
fn write_missing_report(
    session: &SessionDir,
    state: &JournalState,
    out: &mut RecoverOutput,
) -> bool {
    match report::has_report(session) {
        Ok(true) => return false,
        Ok(false) => {}
        Err(e) => {
            out.warnings
                .push(format!("whether the report exists cannot be told: {e}"));
            return false;
        }
    }
    let scan = match execute::read_scan_copy(session) {
        Ok(scan) => scan,
        Err(e) => {
            out.warnings.push(format!(
                "the report is missing and cannot be built: the scan copy cannot be read ({e})"
            ));
            return false;
        }
    };
    let notes = RunNotes {
        warnings: vec![
            "written by recovery after the run ended: the run's notes on single items were not kept"
                .to_owned(),
        ],
        ..RunNotes::default()
    };
    let mut built = report::build(state, &scan, &notes, now());
    built.state = report::session_state(state);
    match report::write_report(session, &built) {
        Ok(()) => {
            out.report = Some(built);
            true
        }
        Err(e) => {
            out.warnings
                .push(format!("the missing report could not be written: {e}"));
            false
        }
    }
}

/// The part of recovery every finished session gets: a missing report is written, interrupted retries
/// are ended (never retried), an interrupted undo is finished (the ops in progress and those its
/// `undo_plan` names and had not reached), and the index entry is brought up to the journal. Writes
/// nothing when there is nothing to do.
fn finish_tail(
    env: &mut RecoverEnv<'_>,
    id: &SessionId,
    index_available: bool,
    out: &mut RecoverOutput,
) -> Result<(), RecoverError> {
    let session = env.roots.open_session(id)?;
    let read = journal::read(&session)?;
    let mut state = read.state.clone();
    if !state.is_finished() {
        out.state = Some(report::session_state(&state));
        out.warnings
            .push("the session's run could not be ended; it still needs recovery".to_owned());
        return Ok(());
    }
    if write_missing_report(&session, &state, out) {
        out.report_written = true;
    }
    let retries: Vec<OpState> = state.retries_in_flight().cloned().collect();
    let mut undoing: BTreeSet<OpId> = state.undo_in_progress().map(|op| op.op).collect();
    undoing.extend(state.undo_unfinished());
    if !retries.is_empty() || !undoing.is_empty() {
        let mut journal = JournalWriter::open_append(&session)?;
        let ctx = undo::gate_ctx(env.roots, env.deny, &session, &state, &mut out.warnings)?;
        for op in &retries {
            let (Some(intent), Some(token)) = (&op.intent, journal.resume_retry(op.op)) else {
                continue;
            };
            // A retry never registers a boot-time move, so the list is not asked.
            let outcome = retry_outcome(&act_fs::probe_move_back(&session, intent));
            journal.retried(token, now(), outcome.clone())?;
            out.retries.push((op.op, outcome));
        }
        if !undoing.is_empty() {
            let covered = {
                let mut driver = Driver {
                    session: &session,
                    journal: &mut journal,
                    ctx: &ctx,
                    pending: &mut *env.pending_renames,
                    retry: &env.retry,
                };
                driver.reconcile(&mut out.warnings)?;
                driver.run(&undo_order(&read.records, &undoing))
            };
            out.undone.extend(covered.items);
            if let Some(e) = covered.stopped {
                return Err(e.into());
            }
        }
        state = journal.state().clone();
    }
    if index_available {
        out.index_updated = undo::update_index(&session, &state, &mut out.warnings);
    }
    out.state = Some(
        standing(state.ops())
            .state
            .unwrap_or_else(|| report::session_state(&state)),
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------------
// Held items
// ---------------------------------------------------------------------------------------------------

/// What [`retry_held`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryOutput {
    /// The session.
    pub session: SessionId,
    /// Each held op tried again, with the outcome its `reconcile` `Retried` record carries.
    pub retried: Vec<locked::Retried>,
    /// Whether the session's index entry is current.
    pub index_updated: bool,
    /// Anything else the user should know (why nothing was tried, for one).
    pub warnings: Vec<String>,
}

/// Tries the held items of a finished session again (`HeldRetry`; [`locked::retry_held`] with the file
/// action's mover, [`act_fs::StoreRetryMove`]): each is validated again through the handle-based gate
/// with its journalled `validated` record and moved by handle to the quarantine path its intent
/// records, write-ahead (`retry_intent`, the move, `reconcile` `Retried`). An item still in use stays
/// held; a retry never registers a boot-time move. The index entry is brought up to the journal.
///
/// Recovery never retries: a session whose run is unfinished, or that holds an interrupted retry, is
/// left as it is (with a warning) until [`resume`] or [`rollback`] has run.
pub fn retry_held(session: &SessionId, env: RecoverEnv<'_>) -> Result<RetryOutput, RecoverError> {
    let mut out = RetryOutput {
        session: session.clone(),
        retried: Vec::new(),
        index_updated: false,
        warnings: Vec::new(),
    };
    env.roots.check()?;
    let dir = env.roots.open_session(session)?;
    let index = undo::read_index(env.roots, &mut out.warnings)?;
    let mark = index
        .as_ref()
        .and_then(|index| index.get(session))
        .and_then(|entry| entry.journal.as_ref());
    let read = journal::read_indexed(&dir, mark)?;
    if !read.state.is_finished() {
        out.warnings
            .push("the session's run is unfinished; recover it first (journal resume)".to_owned());
        return Ok(out);
    }
    if read.state.retries_in_flight().next().is_some() {
        out.warnings.push(
            "a retry of a held item was interrupted; recover it first (journal resume)".to_owned(),
        );
        return Ok(out);
    }
    if read.state.held_retry().next().is_none() {
        return Ok(out);
    }
    let ctx = undo::gate_ctx(env.roots, env.deny, &dir, &read.state, &mut out.warnings)?;
    let mut journal = JournalWriter::open_append(&dir)?;
    let state = {
        let mut mover = act_fs::StoreRetryMove::new(&ctx, &dir, &env.retry);
        out.retried = locked::retry_held(&mut journal, &mut mover, now())?;
        journal.state().clone()
    };
    drop(journal);
    if index.is_some() {
        out.index_updated = undo::update_index(&dir, &state, &mut out.warnings);
    }
    Ok(out)
}
