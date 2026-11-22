//! `journal.resume`, `journal.rollback` and `journal.retry_held` (M3 design 6.3, 8.2; package M3-UNDO).
//!
//! Each names a session of the broker's own store. The backend reads it as the recovery will
//! ([`purge_exec::recover::preview`]) and says which ops the recovery can change; the recovery dialog
//! is drawn from those ops of the session's own plan, and only an approval runs it, started only when
//! the journal is the one the preview read ([`purge_exec::recover::resume_expecting`] and its
//! siblings). What the recovery does is the library's decision about the session, so the dialog states
//! that, not what the request's name suggests: a resume of a run that was being rolled back, or of a
//! finished session whose undo was interrupted, is a put-back and says so.
//!
//! A recovery that changes nothing on the machine (every op is done, only Purge's own records are
//! missing) has no dialog to show; it runs without one, and the preview's empty op list is what says it
//! changes nothing. Every other recovery ends in a dialog, and a session that never started, one that
//! needs none, and one whose journal is damaged are refused.

use purge_exec::recover::Want;
use purge_model::exec::session::SessionId;
use purge_rpc::error::{ErrorData, ErrorObject};
use purge_win::taskdialog::Outcome;
use serde_json::Value;

use crate::backend::{Backend, BackendError, stamp_of};
use crate::consent::dialog;
use crate::consent::view::{RecoverFacts, RecoverKind, ViewError, view_recover};
use crate::serve::{Ctx, Handler};
use crate::undo::value;

/// `journal.resume`.
pub fn resume<H: Handler>(
    ctx: &Ctx<'_, H>,
    backend: &dyn Backend,
    session: &SessionId,
) -> Result<Value, ErrorObject> {
    run(ctx, backend, session, Want::Resume)
}

/// `journal.rollback`.
pub fn rollback<H: Handler>(
    ctx: &Ctx<'_, H>,
    backend: &dyn Backend,
    session: &SessionId,
) -> Result<Value, ErrorObject> {
    run(ctx, backend, session, Want::Rollback)
}

/// `journal.retry_held`.
pub fn retry_held<H: Handler>(
    ctx: &Ctx<'_, H>,
    backend: &dyn Backend,
    session: &SessionId,
) -> Result<Value, ErrorObject> {
    run(ctx, backend, session, Want::RetryHeld)
}

fn kind_of(effective: Want) -> RecoverKind {
    match effective {
        Want::Resume => RecoverKind::Resume,
        Want::Rollback => RecoverKind::Rollback,
        Want::RetryHeld => RecoverKind::RetryHeld,
    }
}

fn run<H: Handler>(
    ctx: &Ctx<'_, H>,
    backend: &dyn Backend,
    session: &SessionId,
    want: Want,
) -> Result<Value, ErrorObject> {
    let preview = backend
        .recover_preview(session, want)
        .map_err(BackendError::into_error)?;
    if !preview.ops.is_empty() {
        let plan = preview.plan.as_ref().ok_or_else(|| {
            ErrorObject::runtime("the session's plan is not available to show what would change")
        })?;
        let facts = RecoverFacts {
            kind: kind_of(preview.effective),
            app_name: preview
                .owner
                .as_ref()
                .map_or_else(|| preview.app.clone(), |owner| owner.display_name.clone()),
            session: preview.session.to_string(),
            started: stamp_of(preview.started),
            done: preview.done,
            total: preview.total,
            ops: preview.ops.clone(),
        };
        // No selected op that would act (each is one the run leaves alone) changes nothing either.
        match view_recover(plan, &facts) {
            Ok(view) => {
                // Every op of the preview is a line of the dialog: one that will act, or one it says
                // it leaves alone.
                if usize::try_from(view.counts.items + view.counts.skipped).ok()
                    != Some(preview.ops.len())
                {
                    return Err(ErrorObject::runtime(
                        "the dialog does not describe the ops the recovery can change",
                    ));
                }
                // Not asked while another broker writes the store (its live run reads as
                // interrupted here); the recovery itself would be refused after the approval.
                if backend.writer_busy() {
                    return Err(BackendError::Busy.into_error());
                }
                if dialog::ask(ctx, &view) != Outcome::Approved {
                    return Err(ErrorObject::server(ErrorData::ConsentDeclined));
                }
            }
            Err(ViewError::NothingToRun) => {}
            Err(e) => {
                return Err(ErrorObject::runtime(format!(
                    "the dialog cannot be built: {e}"
                )));
            }
        }
    }
    let done = backend
        .recover(&preview, want)
        .map_err(BackendError::into_error)?;
    value!(&done)
}
