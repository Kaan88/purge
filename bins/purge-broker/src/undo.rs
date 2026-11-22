//! `undo.run` (M3 design 6.3, 8.2; package M3-UNDO), and [`UndoMethods`], the one entry the broker's
//! handler calls for `history.get`, `undo.run` and the `journal.*` methods.
//!
//! # What the dialog shows is what runs
//!
//! `undo.run` takes a session of the broker's own store and, optionally, ops of it. The backend reads
//! the session as the run will ([`purge_exec::undo::preview`]) and says which ops it puts back: not
//! settled, standing changed, with an inverse, with the ones the selection's restores depend on. The
//! restore dialog is drawn from exactly those ops of the session's own plan, with the ops whose place is
//! taken now as attention entries ([`ConflictKind::PlaceTaken`]: the run never overwrites, it skips
//! the item and reports a conflict). Only an approval runs, and it runs that same preview: the backend
//! starts it only when the journal is the one the preview read and the run goes through the preview's
//! ops ([`purge_exec::undo::undo_expecting`]). Cancel, a dialog that could not be shown and a broker
//! that is ending all answer `consent_declined` with nothing done.
//!
//! Nothing to put back (everything settled, or only items without an inverse) is a `runtime` error,
//! not a dialog over nothing.

use purge_rpc::error::{ErrorData, ErrorObject};
use purge_rpc::methods::{NonEmpty, PipeCall, Progress, ServerNotification, UndoParams};
use purge_win::taskdialog::Outcome;
use serde_json::Value;

use crate::backend::{Backend, BackendError};
use crate::consent::dialog;
use crate::consent::view::{ConflictKind, RestoreFacts, view_restore};
use crate::serve::{Ctx, Handler};
use crate::{history, recover};

/// `undo.run`: the dialog, then the run the dialog described.
pub fn run<H: Handler>(
    ctx: &Ctx<'_, H>,
    backend: &dyn Backend,
    params: UndoParams,
) -> Result<Value, ErrorObject> {
    let ops = params.item_ids.map(NonEmpty::into_vec);
    let preview = backend
        .undo_preview(&params.session, ops.as_deref())
        .map_err(BackendError::into_error)?;
    if preview.put_back.is_empty() {
        return Err(ErrorObject::runtime(
            "nothing in the selection can be put back",
        ));
    }
    let taken = backend.places_taken(&preview.plan, &preview.put_back);
    let facts = RestoreFacts {
        app_name: preview
            .owner
            .as_ref()
            .map_or_else(|| preview.app.clone(), |owner| owner.display_name.clone()),
        ops: preview.put_back.clone(),
        conflicts: preview
            .put_back
            .iter()
            .filter(|op| taken.contains(op))
            .map(|op| (*op, ConflictKind::PlaceTaken))
            .collect(),
    };
    let view = view_restore(&preview.plan, &facts)
        .map_err(|e| ErrorObject::runtime(format!("the dialog cannot be built: {e}")))?;
    // What the button says is what the run covers: every op of the preview is a line of the dialog.
    if usize::try_from(view.counts.items).ok() != Some(preview.put_back.len()) {
        return Err(ErrorObject::runtime(
            "the dialog does not describe the ops the undo would put back",
        ));
    }
    // Not asked while another broker writes the store: the run would be refused after the approval.
    if backend.writer_busy() {
        return Err(BackendError::Busy.into_error());
    }
    if dialog::ask(ctx, &view) != Outcome::Approved {
        return Err(ErrorObject::server(ErrorData::ConsentDeclined));
    }
    let _ = ctx.notify(&ServerNotification::UndoProgress(Progress {
        request: ctx.request(),
        program_id: None,
        phase: "restore".to_owned(),
        done: 0,
        total: Some(preview.put_back.len() as u64),
    }));
    let result = backend.undo(&preview).map_err(BackendError::into_error)?;
    value!(&result)
}

/// A result as the JSON value the answer carries.
macro_rules! value {
    ($result:expr) => {
        serde_json::to_value($result).map_err(|e| ErrorObject::runtime(e.to_string()))
    };
}
pub(crate) use value;

/// The methods of this package over one [`Backend`]. The broker's handler hands every call for which
/// [`UndoMethods::handles`] is true to [`UndoMethods::call`], and asks [`UndoMethods::check_nothing_pending`]
/// before it shows the dialog of `plan.execute`.
pub struct UndoMethods<B: Backend> {
    backend: B,
}

impl<B: Backend> UndoMethods<B> {
    /// The methods over `backend`.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// The backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Whether `call` is one of this package's methods.
    pub fn handles(call: &PipeCall) -> bool {
        matches!(
            call,
            PipeCall::HistoryGet(_)
                | PipeCall::UndoRun(_)
                | PipeCall::JournalPending(_)
                | PipeCall::JournalResume(_)
                | PipeCall::JournalRollback(_)
                | PipeCall::JournalRetryHeld(_)
        )
    }

    /// `needs_recovery` while a session is interrupted, `store_integrity` while a journal is damaged:
    /// the check `plan.execute` makes before its dialog.
    pub fn check_nothing_pending(&self) -> Result<(), ErrorObject> {
        history::check_nothing_pending(&self.backend)
    }

    /// Runs one of this package's methods; any other call is a `runtime` error.
    pub fn call<H: Handler>(&self, ctx: &Ctx<'_, H>, call: PipeCall) -> Result<Value, ErrorObject> {
        let backend = &self.backend;
        match call {
            PipeCall::HistoryGet(p) => value!(&history::get(backend, &p.session)?),
            PipeCall::JournalPending(_) => value!(&history::pending(backend)?),
            PipeCall::UndoRun(p) => run(ctx, backend, p),
            PipeCall::JournalResume(p) => recover::resume(ctx, backend, &p.session),
            PipeCall::JournalRollback(p) => recover::rollback(ctx, backend, &p.session),
            PipeCall::JournalRetryHeld(p) => recover::retry_held(ctx, backend, &p.session),
            other => Err(ErrorObject::runtime(format!(
                "{other:?} is not a history or undo method"
            ))),
        }
    }
}
