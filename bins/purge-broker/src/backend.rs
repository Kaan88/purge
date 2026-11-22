//! The store side of `history.get`, `undo.run` and the `journal.*` methods, as their handlers see it
//! (M3 design 6.3, package M3-UNDO).
//!
//! The handlers ([`crate::history`], [`crate::undo`], [`crate::recover`]) hold the rules: what is shown
//! in the dialog, that the run is the one shown, and what every refusal answers. The backend is the
//! journal and the machine: it reads a session and says what a request would do (a preview, drawn from
//! the session's own scan copy and journal), and it runs a request only against the preview the dialog
//! was drawn from. [`crate::live::LiveBackend`] is the real one over `purge-exec`; the tests script it.

use purge_exec::plan_in::BoundPlan;
use purge_exec::recover::{RecoverPreview, Want};
use purge_exec::undo::UndoPreview;
use purge_model::FileTime;
use purge_model::exec::op::OpId;
use purge_model::exec::session::SessionId;
use purge_rpc::error::{ErrorData, ErrorObject, IdKind};
use purge_rpc::methods::{HistoryDetail, OutcomeResult, PendingSession, UndoResult};

use crate::consent::text::Stamp;

/// The sessions that need recovery, and those that cannot be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingReport {
    /// Sessions a run, an undo or a retry was interrupted in: recovery has to go first.
    pub open: Vec<PendingSession>,
    /// Sessions whose journal failed its check, with what failed.
    pub damaged: Vec<(SessionId, String)>,
}

/// Why a backend call did not give its result. Each is an error of the method, never a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    /// The session is not in the store.
    Gone,
    /// An op the request names is not an op of the session.
    UnknownOp(String),
    /// The store or a journal failed its check.
    Integrity(String),
    /// These sessions were interrupted and come first.
    NeedsRecovery(Vec<SessionId>),
    /// The session is not as it was when the dialog was drawn: nothing was done.
    NotAsShown,
    /// Another operation writes the store now (a run, undo, recovery or purge of another broker):
    /// nothing was done (the store's single-writer lock, DECISIONS 2026-11-22).
    Busy,
    /// The request cannot be given to this session, with the reason.
    Refused(String),
    /// Anything else, with the reason.
    Failed(String),
}

impl BackendError {
    /// The error the client gets.
    pub fn into_error(self) -> ErrorObject {
        match self {
            BackendError::Gone => ErrorObject::server(ErrorData::Gone {
                id: IdKind::Session,
            }),
            BackendError::UnknownOp(_) => ErrorObject::server(ErrorData::Gone {
                id: IdKind::Candidate,
            }),
            BackendError::Integrity(message) => {
                ErrorObject::server(ErrorData::StoreIntegrity { message })
            }
            BackendError::NeedsRecovery(sessions) => {
                ErrorObject::server(ErrorData::NeedsRecovery { sessions })
            }
            BackendError::Busy => ErrorObject::server(ErrorData::Busy),
            BackendError::NotAsShown => ErrorObject::runtime(
                "the session is not as it was when the dialog was shown; nothing was done",
            ),
            BackendError::Refused(why) | BackendError::Failed(why) => ErrorObject::runtime(why),
        }
    }
}

/// The journal and the machine behind history, undo and recovery. Every method that reads or runs
/// takes ids from the broker's own store; nothing a client sends is a path or a document.
pub trait Backend: Send + Sync + 'static {
    /// The sessions that need recovery (`journal.pending`).
    fn pending(&self) -> Result<PendingReport, BackendError>;

    /// Whether another operation holds the store's writer lock now (another broker's run, undo,
    /// recovery or purge). A hint taken before a dialog, so that the user is not asked to approve a
    /// change that would be refused, and a run of another broker is not mistaken for an interrupted
    /// session; the run itself takes the lock. The fakes of the tests have no other writer.
    fn writer_busy(&self) -> bool {
        false
    }

    /// What a session holds (`history.get`).
    fn history(&self, session: &SessionId) -> Result<HistoryDetail, BackendError>;

    /// What an undo of `ops` of `session` (all of them for `None`) would put back, as the run will
    /// go through it. Changes nothing.
    fn undo_preview(
        &self,
        session: &SessionId,
        ops: Option<&[OpId]>,
    ) -> Result<UndoPreview, BackendError>;

    /// Which of `ops` of `plan` have something in their place now (read-only). An op that cannot be
    /// looked at counts as taken.
    fn places_taken(&self, plan: &BoundPlan, ops: &[OpId]) -> Vec<OpId>;

    /// Runs the undo `preview` describes, only if the session is as the preview read it
    /// ([`BackendError::NotAsShown`] otherwise, before anything is changed).
    fn undo(&self, preview: &UndoPreview) -> Result<UndoResult, BackendError>;

    /// What a recovery of `session` would change, as it will go through it. Changes nothing.
    fn recover_preview(
        &self,
        session: &SessionId,
        want: Want,
    ) -> Result<RecoverPreview, BackendError>;

    /// Runs the recovery `want` that `preview` describes, only if the session is as the preview read
    /// it ([`BackendError::NotAsShown`] otherwise).
    fn recover(&self, preview: &RecoverPreview, want: Want) -> Result<OutcomeResult, BackendError>;
}

/// A FILETIME as the dialog states it (UTC, to the minute); `None` for a time before 1970 or one the
/// calendar cannot hold.
pub fn stamp_of(time: FileTime) -> Option<Stamp> {
    const TICKS_PER_SECOND: u64 = 10_000_000;
    const UNIX_EPOCH_SECONDS: u64 = 11_644_473_600;
    let seconds = (time.0 / TICKS_PER_SECOND).checked_sub(UNIX_EPOCH_SECONDS)?;
    let days = i64::try_from(seconds / 86_400).ok()?;
    let rest = seconds % 86_400;
    // Days since 1970-01-01 to a civil date (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u8::try_from(doy - (153 * mp + 2) / 5 + 1).ok()?;
    let month = u8::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).ok()?;
    let year = u16::try_from(yoe + era * 400 + i64::from(month <= 2)).ok()?;
    Some(Stamp {
        year,
        month,
        day,
        hour: u8::try_from(rest / 3600).ok()?,
        minute: u8::try_from(rest % 3600 / 60).ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(unix_seconds: u64) -> FileTime {
        FileTime((unix_seconds + 11_644_473_600) * 10_000_000)
    }

    #[test]
    fn a_filetime_is_a_utc_date_and_minute() {
        assert_eq!(
            stamp_of(at(0)),
            Some(Stamp {
                year: 1970,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0
            })
        );
        assert_eq!(
            stamp_of(at(1_795_291_560)).map(|s| s.date_time()),
            Some("2026-11-21 20:06 UTC".to_owned())
        );
        // A leap day.
        assert_eq!(
            stamp_of(at(1_709_251_170)).map(|s| s.date_time()),
            Some("2024-02-29 23:59 UTC".to_owned())
        );
        assert_eq!(stamp_of(FileTime(0)), None, "before 1970");
    }

    #[test]
    fn every_backend_error_is_the_error_the_client_is_told() {
        let kind = |e: BackendError| e.into_error().data.map(|d| d.kind());
        assert_eq!(kind(BackendError::Gone), Some("gone"));
        assert_eq!(kind(BackendError::UnknownOp("op 9".into())), Some("gone"));
        assert_eq!(
            kind(BackendError::Integrity("x".into())),
            Some("store_integrity")
        );
        assert_eq!(
            kind(BackendError::NeedsRecovery(vec![])),
            Some("needs_recovery")
        );
        assert_eq!(kind(BackendError::Busy), Some("busy"));
        assert_eq!(kind(BackendError::NotAsShown), Some("runtime"));
        assert_eq!(kind(BackendError::Refused("x".into())), Some("runtime"));
        assert_eq!(kind(BackendError::Failed("x".into())), Some("runtime"));
    }
}
