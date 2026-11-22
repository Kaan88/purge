//! The real [`Backend`] of history, undo and recovery: `purge-exec` over the broker's own store and the
//! live machine (M3-UNDO). Everything the rules need (what the dialog shows, that the run is the one
//! shown) is decided by [`crate::undo`] and [`crate::recover`] from what this returns; this file reads
//! and runs, and maps what the library says to what the client is told. It is not exercised by the
//! library tests (a real store needs the executor's `test-support` feature, which the broker has not):
//! `purge-exec`'s own tests cover the previews and the guarded runs on real journals, the handlers'
//! tests script this trait, and the elevated end-to-end run is VM work.

use purge_engine::pipeline::Sources;
use purge_exec::act_typed::WinPackages;
use purge_exec::execute;
use purge_exec::journal::{self, JournalError, UndoState};
use purge_exec::locked::{ReconcileAlert, SystemPendingRenames};
use purge_exec::plan_in::BoundPlan;
use purge_exec::prepare::RestartManager;
use purge_exec::recover::{
    self, PendingKind, RecoverEnv, RecoverError, RecoverMode, RecoverOutput, RecoverPreview,
    RetryOutput, Want,
};
use purge_exec::report;
use purge_exec::storage::{StorageError, StorageRoots};
use purge_exec::undo::{self, UndoEnv, UndoError, UndoOutput, UndoPreview};
use purge_guard::deny::DenyList;
use purge_model::exec::journal::ItemFacts;
use purge_model::exec::journal::{ReconcileResult, UndoOutcome};
use purge_model::exec::op::{ExecOp, ItemOutcome, OpId, SkipReason};
use purge_model::exec::session::{
    SessionId, SessionState, UndoCounts, UndoResult as ModelUndoResult,
};
use purge_model::{FileTime, ProgramId};
use purge_rpc::error::Outcome;
use purge_rpc::methods::{
    Alert, ConflictRow, HistoryDetail, HistoryItem, OutcomeResult, PendingSession, UndoResult,
};
use purge_source::filesystem::FileSystemSource;
use purge_source::live::Live;
use purge_source::registry::RegistrySource;
use purge_source::types::{ExistsState, SourceError};

use crate::backend::{Backend, BackendError, PendingReport};
use crate::history::{display_name, kind_of, outcome_of};
use crate::live_host::{LiveObjects, live_deny_list};

/// The backend over the store at `roots`. `purge_dirs` are Purge's own directories (the broker's
/// engine settings): the guard protects them and the data root.
pub struct LiveBackend {
    roots: StorageRoots,
    purge_dirs: Vec<String>,
}

/// What an executor call needs from the machine.
struct Machine {
    deny: DenyList,
    objects: LiveObjects,
    packages: WinPackages,
    lockers: RestartManager,
}

impl LiveBackend {
    /// The backend over `roots`.
    pub fn new(roots: StorageRoots, purge_dirs: Vec<String>) -> Self {
        Self { roots, purge_dirs }
    }

    /// The owners the index records for `session`: left out of the other apps' roots, as the CLI does.
    fn owners(&self, session: &SessionId) -> Vec<ProgramId> {
        self.roots
            .read_index()
            .ok()
            .and_then(|index| {
                index
                    .get(session)
                    .and_then(|entry| entry.owner.as_ref())
                    .map(|owner| owner.program_id.clone())
            })
            .into_iter()
            .collect()
    }

    fn machine(&self, session: &SessionId) -> Result<Machine, BackendError> {
        let live = Live::new();
        let sources = Sources {
            reg: &live.registry,
            fs: &live.fs,
            sys: &live.system,
        };
        let (deny, _warnings) = live_deny_list(
            sources,
            self.roots.data_root(),
            &self.purge_dirs,
            &self.owners(session),
        )
        .map_err(|why| BackendError::Failed(format!("{why}; nothing was done")))?;
        Ok(Machine {
            deny,
            objects: LiveObjects::new(sources),
            packages: WinPackages::new(),
            lockers: RestartManager,
        })
    }

    fn report_present(&self, session: &SessionId) -> bool {
        self.roots
            .open_session(session)
            .ok()
            .and_then(|dir| report::has_report(&dir).ok())
            .unwrap_or(false)
    }
}

fn store_error(e: StorageError) -> BackendError {
    match e {
        StorageError::SessionNotFound(_) => BackendError::Gone,
        StorageError::WriterBusy { .. } => BackendError::Busy,
        StorageError::Integrity { .. }
        | StorageError::IndexMalformed { .. }
        | StorageError::IndexLost { .. } => BackendError::Integrity(e.to_string()),
        other => BackendError::Failed(other.to_string()),
    }
}

fn journal_error(e: JournalError) -> BackendError {
    match e {
        JournalError::Store(store) => store_error(store),
        JournalError::Corrupt { .. }
        | JournalError::IndexMismatch { .. }
        | JournalError::WrongSession { .. }
        | JournalError::Empty { .. }
        | JournalError::Refused(_)
        | JournalError::Encoding(_) => BackendError::Integrity(e.to_string()),
        other => BackendError::Failed(other.to_string()),
    }
}

fn undo_error(session: &SessionId, e: UndoError) -> BackendError {
    match e {
        UndoError::Store(s) => store_error(s),
        UndoError::Journal(j) => journal_error(j),
        UndoError::UnknownItem(item) => BackendError::UnknownOp(item),
        UndoError::NeedsRecovery(_) => BackendError::NeedsRecovery(vec![session.clone()]),
        UndoError::JournalChanged | UndoError::NotAsShown => BackendError::NotAsShown,
        UndoError::PlanUnbound(why) => BackendError::Integrity(why),
        other @ (UndoError::Gate(_) | UndoError::PlanMismatch { .. }) => {
            BackendError::Failed(other.to_string())
        }
    }
}

fn recover_error(session: &SessionId, e: RecoverError) -> BackendError {
    match e {
        RecoverError::Store(s) => store_error(s),
        RecoverError::Journal(j) => journal_error(j),
        RecoverError::NotAsShown => BackendError::NotAsShown,
        RecoverError::NeedsRecovery(_) => BackendError::NeedsRecovery(vec![session.clone()]),
        RecoverError::Refused(why) => BackendError::Refused(why),
        RecoverError::PlanUnbound(why) => BackendError::Integrity(why),
        RecoverError::UnknownOp(op) => BackendError::UnknownOp(format!("op {op}")),
        other @ (RecoverError::Gate(_) | RecoverError::Exec(_) | RecoverError::Unstarted(_)) => {
            BackendError::Failed(other.to_string())
        }
    }
}

/// The worse of two outcomes, by the CLI exit code each mirrors.
fn worse(a: Outcome, b: Outcome) -> Outcome {
    if b.cli_exit() > a.cli_exit() { b } else { a }
}

/// Whether an item ended as asked: done, gone already, or a remove-if-empty whose object holds something.
fn complete(outcome: &ItemOutcome) -> bool {
    matches!(
        outcome,
        ItemOutcome::Done
            | ItemOutcome::Vanished
            | ItemOutcome::Skipped {
                reason: SkipReason::NoLongerEmpty
            }
    )
}

fn undo_outcome(counts: &UndoCounts) -> Outcome {
    if counts.conflicts > 0 || counts.failed > 0 {
        Outcome::UndoConflicts
    } else {
        Outcome::Complete
    }
}

fn undo_result(out: &UndoOutput, plan: &BoundPlan) -> UndoResult {
    let mut outcome = undo_outcome(&out.report.counts);
    if out.stopped.is_some() || !out.index_updated {
        outcome = worse(outcome, Outcome::NotClosed);
    }
    let conflicts = out
        .report
        .items
        .iter()
        .filter_map(|item| match &item.result {
            ModelUndoResult::Conflict { conflict, .. } => Some(ConflictRow {
                op: item.op,
                display_name: display_name(
                    &item.target,
                    plan.item(item.op).and_then(|i| plan.candidate(i)),
                ),
                conflict: conflict.clone(),
            }),
            ModelUndoResult::Finished { .. } => None,
        })
        .collect();
    UndoResult {
        outcome,
        conflicts,
        alerts: out.alerts.iter().map(alert_of).collect(),
    }
}

/// The RPC form of a reconcile alert (review M3-R2 S5).
fn alert_of(alert: &ReconcileAlert) -> Alert {
    Alert {
        op: alert.op,
        original_path: alert.original_path.clone(),
        moved_back: alert.moved_back,
    }
}

/// The source path of a quarantine move, for a history row's alert; other targets have none.
fn original_path_of(target: &purge_model::Target) -> String {
    match target {
        purge_model::Target::Path { path } => path.clone(),
        _ => String::new(),
    }
}

/// What one recovery did to the items, and whether the session ended recorded (closed, with its report
/// and a current index entry), as the CLI's exit code says.
fn recovered_outcome(out: &RecoverOutput, report_present: bool) -> Outcome {
    let mut counts = UndoCounts::default();
    for item in &out.undone {
        counts.record(&item.result);
    }
    let mut outcome = undo_outcome(&counts);
    if out.mode == RecoverMode::Resume {
        if let Some(report) = &out.report
            && !(report.state == SessionState::Committed
                && report.items.iter().all(|item| complete(&item.outcome)))
        {
            outcome = worse(outcome, Outcome::Partial);
        }
        if out.reprobed.iter().any(|r| !r.matches_journal()) {
            outcome = worse(outcome, Outcome::Partial);
        }
    }
    if out.retries.iter().any(|(_, o)| !complete(o)) {
        outcome = worse(outcome, Outcome::Partial);
    }
    let recorded = out.removed
        || (!matches!(out.state, None | Some(SessionState::Open))
            && report_present
            && out.index_updated);
    if recorded {
        outcome
    } else {
        worse(outcome, Outcome::NotClosed)
    }
}

fn retried_outcome(out: &RetryOutput) -> Outcome {
    let mut outcome = if out.retried.iter().all(|r| complete(&r.outcome)) {
        Outcome::Complete
    } else {
        Outcome::Partial
    };
    if !out.retried.is_empty() && !out.index_updated {
        outcome = worse(outcome, Outcome::NotClosed);
    }
    outcome
}

/// Whether the registry or the file system has something where an op would put an item back. What
/// cannot be looked at counts as taken.
fn taken(live: &Live, op: &ExecOp) -> bool {
    match op {
        ExecOp::QuarantineMove { path } | ExecOp::RemoveDirIfEmpty { path } => {
            live.fs.exists(path) != ExistsState::Absent
        }
        ExecOp::DeleteKeyTree { key } | ExecOp::DeleteKeyIfEmpty { key } => {
            live.registry.key_exists(key) != ExistsState::Absent
        }
        ExecOp::DeleteValue { key, name } => {
            !matches!(live.registry.value(key, name), Err(SourceError::NotFound))
        }
        _ => false,
    }
}

impl Backend for LiveBackend {
    fn writer_busy(&self) -> bool {
        // A lock file the store refuses is not a busy writer: the run's own lock reports it.
        self.roots.writer_busy().unwrap_or(false)
    }

    fn pending(&self) -> Result<PendingReport, BackendError> {
        let list = recover::pending(&self.roots).map_err(store_error)?;
        let index = self.roots.read_index().ok();
        let mut report = PendingReport::default();
        for s in list.sessions {
            match s.kind {
                PendingKind::Damaged => report.damaged.push((s.session, s.detail)),
                PendingKind::Run | PendingKind::Undo | PendingKind::Retry => {
                    let entry = index.as_ref().and_then(|index| index.get(&s.session));
                    let total = self
                        .roots
                        .open_session(&s.session)
                        .ok()
                        .and_then(|dir| {
                            journal::read_indexed(&dir, entry.and_then(|e| e.journal.as_ref())).ok()
                        })
                        .map_or((0, 0), |read| {
                            let done = read.state.ops().filter(|op| op.outcome.is_some()).count();
                            (
                                u32::try_from(done).unwrap_or(u32::MAX),
                                read.state.header().items,
                            )
                        });
                    report.open.push(PendingSession {
                        app: entry
                            .and_then(|e| e.owner.as_ref())
                            .map(|owner| owner.display_name.clone())
                            .or(s.app)
                            .unwrap_or_default(),
                        started: s.started.unwrap_or(FileTime(0)),
                        done: total.0,
                        total: total.1,
                        session: s.session,
                    });
                }
                PendingKind::Unindexed | PendingKind::Unstarted => {}
            }
        }
        Ok(report)
    }

    fn history(&self, session: &SessionId) -> Result<HistoryDetail, BackendError> {
        self.roots.check().map_err(store_error)?;
        let dir = self.roots.open_session(session).map_err(store_error)?;
        let index = self.roots.read_index().ok();
        let entry = index.as_ref().and_then(|index| index.get(session));
        let read = journal::read_indexed(&dir, entry.and_then(|e| e.journal.as_ref()))
            .map_err(journal_error)?;
        let scan = execute::read_scan_copy(&dir).ok();
        let items = read
            .state
            .ops()
            .map(|op| {
                let candidate = scan.as_ref().and_then(|scan| {
                    scan.items
                        .iter()
                        .chain(scan.absorbed.iter())
                        .find(|c| c.id == op.item)
                });
                let mut done = op.outcome.clone();
                for result in &op.reconciles {
                    match result {
                        ReconcileResult::Retried { outcome } => done = Some(outcome.clone()),
                        ReconcileResult::Completed => done = Some(ItemOutcome::Done),
                        _ => {}
                    }
                }
                let is_dir = match &op.facts {
                    ItemFacts::File(facts) => Some(facts.is_dir),
                    _ => None,
                };
                let alert = op.reconciles.iter().rev().find_map(|result| match result {
                    ReconcileResult::MismatchMovedBack => Some(Alert {
                        op: op.op,
                        original_path: original_path_of(&op.target),
                        moved_back: true,
                    }),
                    ReconcileResult::MismatchKept { .. } => Some(Alert {
                        op: op.op,
                        original_path: original_path_of(&op.target),
                        moved_back: false,
                    }),
                    _ => None,
                });
                HistoryItem {
                    op: op.op,
                    display_name: display_name(&op.target, candidate),
                    kind: kind_of(&op.target, is_dir),
                    outcome: outcome_of(done, op.intent.is_some()),
                    undone: matches!(
                        op.undo,
                        UndoState::Finished(UndoOutcome::Restored | UndoOutcome::AlreadyRestored)
                    ),
                    alert,
                }
            })
            .collect();
        Ok(HistoryDetail {
            session: session.clone(),
            state: entry
                .map(|e| e.state)
                .unwrap_or_else(|| report::session_state(&read.state)),
            items,
        })
    }

    fn undo_preview(
        &self,
        session: &SessionId,
        ops: Option<&[OpId]>,
    ) -> Result<UndoPreview, BackendError> {
        undo::preview(&self.roots, session, ops).map_err(|e| undo_error(session, e))
    }

    fn places_taken(&self, plan: &BoundPlan, ops: &[OpId]) -> Vec<OpId> {
        let live = Live::new();
        ops.iter()
            .filter(|op| {
                plan.item(**op)
                    .and_then(|item| item.exec_op.as_ref())
                    .is_some_and(|exec_op| taken(&live, exec_op))
            })
            .copied()
            .collect()
    }

    fn undo(&self, preview: &UndoPreview) -> Result<UndoResult, BackendError> {
        let session = &preview.request.session;
        let machine = self.machine(session)?;
        let mut pending = SystemPendingRenames;
        let env = UndoEnv {
            objects: Some(machine.objects.backends()),
            ..UndoEnv::new(&self.roots, &machine.deny, &mut pending)
        };
        let out = undo::undo_expecting(&preview.request, env, &preview.expect)
            .map_err(|e| undo_error(session, e))?;
        Ok(undo_result(&out, &preview.plan))
    }

    fn recover_preview(
        &self,
        session: &SessionId,
        want: Want,
    ) -> Result<RecoverPreview, BackendError> {
        recover::preview(&self.roots, session, want).map_err(|e| recover_error(session, e))
    }

    fn recover(&self, preview: &RecoverPreview, want: Want) -> Result<OutcomeResult, BackendError> {
        let session = &preview.session;
        let machine = self.machine(session)?;
        let mut pending = SystemPendingRenames;
        let env = RecoverEnv {
            objects: Some(machine.objects.backends()),
            ..RecoverEnv::new(
                &self.roots,
                &machine.deny,
                &machine.packages,
                &machine.lockers,
                &mut pending,
            )
        };
        let (outcome, alerts) = match want {
            Want::RetryHeld => {
                let out = recover::retry_held_expecting(session, env, &preview.mark)
                    .map_err(|e| recover_error(session, e))?;
                (retried_outcome(&out), Vec::new())
            }
            Want::Resume | Want::Rollback => {
                let out = if want == Want::Resume {
                    recover::resume_expecting(session, env, &preview.mark)
                } else {
                    recover::rollback_expecting(session, env, &preview.mark)
                }
                .map_err(|e| recover_error(session, e))?;
                let outcome = recovered_outcome(&out, self.report_present(session));
                (outcome, out.alerts.iter().map(alert_of).collect())
            }
        };
        Ok(OutcomeResult { outcome, alerts })
    }
}
