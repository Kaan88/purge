//! `history.get` and `journal.pending`, and the rule that an interrupted session blocks execute (M3
//! design 6.3, 6.4; package M3-UNDO).
//!
//! Both methods only read. `history.get` names a session by its executor id; the backend answers from
//! its own store, so an id that is not there is `gone` (`session`) and no client text is ever turned
//! into a path. [`check_nothing_pending`] is what `plan.execute` asks before it shows its dialog:
//! an interrupted session comes first (`needs_recovery`), a session whose journal cannot be read is
//! `store_integrity`.

use purge_model::exec::op::{ItemOutcome, SkipReason};
use purge_model::exec::session::SessionId;
use purge_model::{Candidate, Target};
use purge_rpc::error::ErrorObject;
use purge_rpc::methods::{HistoryDetail, ItemKind, PendingList};

use crate::backend::{Backend, BackendError};

/// `history.get`: the items of a session with how each ended and whether it was undone.
pub fn get(backend: &dyn Backend, session: &SessionId) -> Result<HistoryDetail, ErrorObject> {
    backend.history(session).map_err(BackendError::into_error)
}

/// `journal.pending`: the interrupted sessions. A session whose journal cannot be read is not listed
/// (it cannot be recovered); it is `store_integrity` wherever an interrupted session would stop a
/// request ([`check_nothing_pending`]).
pub fn pending(backend: &dyn Backend) -> Result<PendingList, ErrorObject> {
    let report = backend.pending().map_err(BackendError::into_error)?;
    Ok(PendingList {
        sessions: report.open,
    })
}

/// Refuses a request that needs the store at rest while a session is interrupted or damaged. A damaged
/// journal is named first: it cannot be recovered, so `needs_recovery` would send the user nowhere.
///
/// Another writer of the store comes before both: while another broker runs, its session reads as
/// interrupted, so the answer is `busy`, not `needs_recovery` (review R3, single writer).
pub fn check_nothing_pending(backend: &dyn Backend) -> Result<(), ErrorObject> {
    if backend.writer_busy() {
        return Err(BackendError::Busy.into_error());
    }
    let report = backend.pending().map_err(BackendError::into_error)?;
    if !report.damaged.is_empty() {
        let sessions: Vec<String> = report
            .damaged
            .iter()
            .map(|(session, why)| format!("{session} ({why})"))
            .collect();
        return Err(BackendError::Integrity(format!(
            "the journal of session(s) {} is damaged",
            sessions.join(", ")
        ))
        .into_error());
    }
    if !report.open.is_empty() {
        return Err(BackendError::NeedsRecovery(
            report.open.into_iter().map(|s| s.session).collect(),
        )
        .into_error());
    }
    Ok(())
}

/// What kind of thing an op acted on, for display.
pub fn kind_of(target: &Target, is_dir: Option<bool>) -> ItemKind {
    match target {
        Target::Path { .. } => {
            if is_dir == Some(true) {
                ItemKind::Folder
            } else {
                ItemKind::File
            }
        }
        Target::RegKey { .. } => ItemKind::RegistryKey,
        Target::RegValue { .. } => ItemKind::RegistryValue,
        Target::RegValueChanged { .. } | Target::RegMultiSzSegment { .. } => ItemKind::RegistryData,
        Target::Service { .. } => ItemKind::Service,
        Target::Task { .. } => ItemKind::Task,
        Target::FirewallRule { .. } => ItemKind::FirewallRule,
        Target::AppxPackage { .. } => ItemKind::Package,
    }
}

/// The name an item is listed under: the scan's display name, else what it acted on.
pub fn display_name(target: &Target, candidate: Option<&Candidate>) -> String {
    if let Some(name) = candidate.and_then(|c| c.display_name.as_deref())
        && !name.is_empty()
    {
        return name.to_owned();
    }
    match target {
        Target::Path { path } | Target::RegKey { path } | Target::Task { path } => path.clone(),
        Target::RegValue { path, name }
        | Target::RegValueChanged { path, name, .. }
        | Target::RegMultiSzSegment { path, name, .. } => {
            let name = if name.is_empty() { "(Default)" } else { name };
            format!("{path}\\{name}")
        }
        Target::Service { name } => name.clone(),
        Target::FirewallRule { id } => id.clone(),
        Target::AppxPackage { full_name } => full_name.clone(),
    }
}

/// How an op ended as the report states it: its `done` outcome, `Failed{Internal}` when its action
/// started and nothing says how it ended, `Skipped{NotAttempted}` when it never started.
pub fn outcome_of(done: Option<ItemOutcome>, started: bool) -> ItemOutcome {
    match (done, started) {
        (Some(outcome), _) => outcome,
        (None, true) => ItemOutcome::Failed {
            code: purge_model::exec::op::FailCode::Internal,
            os_error: None,
            detail: "the run stopped in the middle of this item; recovery decides what happened"
                .to_owned(),
        },
        (None, false) => ItemOutcome::Skipped {
            reason: SkipReason::NotAttempted,
        },
    }
}
