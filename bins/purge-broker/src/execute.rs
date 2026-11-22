//! `plan.execute` (M3 design 3.6, 6.3, 6.4, 8.1; package M3-EXEC).
//!
//! # One plan object (B3) and one dialog (B4)
//!
//! `plan.create` froze a [`BoundPlan`] behind an `Arc` in the plan table. `plan.execute` takes the plan
//! out of the table (a plan id works once: a second request, or one for a plan of another broker, is
//! `gone`), draws the dialog from **that** object ([`view::view`], then [`ConsentView::describes_plan`]),
//! and only on an approval hands **that same `Arc`** to the executor
//! ([`purge_exec::execute::execute_bound`]). Nothing is bound or derived a second time: the items the
//! dialog listed are the items that run, and the dialog's code is the one `plan.create` gave the UI.
//!
//! The client sends a plan id and the restore-point setting (an enum). It sends no path, no item and
//! no fingerprint. The session's fingerprint travels with the plan (frozen at `plan.create`) and the
//! executor checks every selected service, task or firewall rule against it before it creates a
//! session ([`purge_exec::plan_in::unbound_objects`]).
//!
//! # What ends the request
//!
//! | Situation | Answer | Changed |
//! |---|---|---|
//! | plan id unknown, used, or another broker's | `gone` (`plan`) | nothing |
//! | an interrupted session exists | `needs_recovery`, or `store_integrity` for a damaged journal | nothing |
//! | the dialog cannot be drawn (nothing selected can run, a name cannot be shown) | `runtime` | nothing |
//! | Cancel, a dialog that could not be shown, a broker that is ending | `consent_declined` | nothing |
//! | the executor refused before it started (not elevated, cap, store, objects not vouched for) | the error | nothing |
//! | the run ended | `{outcome, session, counts, held[], restore_point}` | the run, recorded |
//!
//! A scan is claimed by its live plan. The claim is given back whenever **nothing ran**, so a declined
//! dialog (or a refusal) can be followed by a new `plan.create` of the same scan. Once the executor
//! started the claim stays: the scan describes a machine that has changed, and a second plan from it
//! would be a second run of the same items. The user scans again.
//!
//! # After the approval
//!
//! The run is finished and recorded even when the client or its parent is gone (the answer is dropped,
//! `exec.progress` stops): the handler never looks at [`Ctx::cancelled`] after the approval. Before the
//! approval a lost pipe or parent closes the dialog as Cancel (the core's `Closer`), and nothing runs.
//!
//! # Outcomes (design 6.4)
//!
//! `not_closed` when the session was not recorded completely (journal not ended, report or index entry
//! missing); it wins. Else `partial` when the session did not commit or any item did not end done
//! (done, already gone, or a remove-if-empty whose object holds something). Else `complete`.
//!
//! # Irreversible removals
//!
//! A removal without an undo (a package) is run only when `plan.create` froze the plan with
//! `allow_irreversible` (a boolean of that request). The dialog then names every such item as an
//! attention entry, warns that it cannot be put back and gates its button behind the verification box;
//! without the flag the dialog lists them as "Leave alone" and the executor skips them.

use std::cell::Cell;
use std::sync::Arc;

use purge_exec::execute::{ExecError, ExecOutput, Progress as ExecProgress};
use purge_exec::plan_in::{BoundPlan, ExecSettings};
use purge_exec::prepare::{RestorePointSetting, RiskItem, risk_reasons};
use purge_exec::storage::StorageError;
use purge_model::exec::op::ItemOutcome;
use purge_model::exec::session::{RETAIN_QUARANTINE_DAYS, SessionState};
use purge_model::{FileTime, Fingerprint};
use purge_rpc::error::{ErrorData, ErrorObject, Outcome, Refusal};
use purge_rpc::methods::{
    CandidateRef, ExecResult, HeldItem, PlanExecuteParams, Progress, RestorePoint,
    ServerNotification,
};
use purge_win::taskdialog::Outcome as Answer;
use serde_json::Value;

use crate::backend::stamp_of;
use crate::consent::dialog;
use crate::consent::view::{self, Facts};
use crate::history::display_name;
use crate::plan::Plan;
use crate::uninstall::FlowHandler;

/// FILETIME ticks (100 ns) per day.
const TICKS_PER_DAY: u64 = 864_000_000_000;

/// What the executor is given: the frozen plan, the run's settings and the plan's fingerprint.
pub struct ExecJob {
    /// The very object the dialog was drawn from.
    pub plan: Arc<BoundPlan>,
    /// The settings of the run: the account and the program roots the broker decided when the plan was
    /// made, and the restore-point setting of this request. The machine's M1b lists are the backend's
    /// to add (they are judged now, never taken from the plan).
    pub settings: ExecSettings,
    /// The fingerprint of the scan the plan came from: the object binding.
    pub fingerprint: Arc<Fingerprint>,
}

/// The executor and the clock behind `plan.execute`. [`crate::exec_live::LiveExec`] is the real one;
/// the tests script it.
pub trait ExecBackend: Send + Sync + 'static {
    /// The time the dialog's "restorable until" is counted from.
    fn now(&self) -> FileTime;

    /// Runs `job` ([`purge_exec::execute::execute_bound`]), telling `progress` what it does.
    ///
    /// # Errors
    ///
    /// The run did not start and nothing outside Purge's store was changed. `Err` does not mean that no
    /// executor session exists: `purge_exec`'s `Run::start_bound` can fail after `create_session` and
    /// then removes the session only when that is safe, so a session directory may stay in the store
    /// for `check_nothing_pending` and recovery to judge. The handler gives the scan's claim back on
    /// `Err` because nothing on the machine changed (review M3-R2 N8).
    fn execute(
        &self,
        job: ExecJob,
        progress: &dyn Fn(&ExecProgress<'_>),
    ) -> Result<ExecOutput, ExecFailure>;
}

/// Why a run did not start.
#[derive(Debug)]
pub enum ExecFailure {
    /// The executor refused.
    Exec(Box<ExecError>),
    /// The machine could not be read well enough to guard the run (the deny-list); nothing was done.
    Machine(String),
}

fn setting_of(restore_point: RestorePoint) -> RestorePointSetting {
    match restore_point {
        RestorePoint::Off => RestorePointSetting::Off,
        RestorePoint::HighRisk => RestorePointSetting::HighRiskOnly,
        RestorePoint::Always => RestorePointSetting::Always,
    }
}

/// Whether the run will ask for a restore point, as far as the plan alone tells: `always`, or
/// `high_risk` and the selected items (with their absorbed children) are high-risk. The executor may
/// find more risk when it reads the items (a registry tree's size); it then asks without the dialog
/// having said so, which only ever adds a restore point.
fn restore_point_requested(plan: &BoundPlan, setting: RestorePointSetting) -> bool {
    let mut items = Vec::new();
    for item in plan.items() {
        if let Some(candidate) = plan.candidate(item) {
            items.push(RiskItem::from_candidate(candidate));
            items.extend(plan.children(candidate).map(RiskItem::from_candidate));
        }
    }
    setting.requests(&risk_reasons(&items, plan.scan().mode))
}

/// `plan.execute`: the dialog, then the run the dialog described.
///
/// `check_nothing_pending` is the check that an interrupted session comes first
/// ([`crate::undo::UndoMethods::check_nothing_pending`]).
pub fn run<H: FlowHandler>(
    ctx: &crate::serve::Ctx<'_, H>,
    backend: &dyn ExecBackend,
    check_nothing_pending: &dyn Fn() -> Result<(), ErrorObject>,
    params: PlanExecuteParams,
) -> Result<Value, ErrorObject> {
    // A plan id works once, whatever happens next.
    let plan = ctx.tables().plans.take(params.plan_id)?;
    // A sibling scan of the same program may have been planned before that program's run started; its
    // document describes the machine before the run (review M3-R2 S2), so it is refused as well.
    if ctx
        .tables()
        .scans
        .get(plan.scan_id)
        .is_ok_and(|slot| slot.scan.spent())
    {
        plan.release(ctx.tables(), params.plan_id);
        return Err(ErrorObject::server(ErrorData::PlanRefused {
            refusals: vec![Refusal {
                candidate_id: None,
                reason: "the program of this plan was already uninstalled; scan again".into(),
            }],
        }));
    }
    let ran = Cell::new(false);
    let result = execute_plan(ctx, backend, check_nothing_pending, &plan, &params, &ran);
    if !ran.get() {
        // Nothing was changed: the scan can have its next plan.
        plan.release(ctx.tables(), params.plan_id);
    } else {
        // The run spends every scan of this program, not only the plan's: a scan made before the run
        // describes the machine before it, and a second plan from one would be a second run of the
        // same items (review M3-R2 S2).
        let tables = ctx.tables();
        for id in tables.scans.ids() {
            if let Ok(slot) = tables.scans.get(id)
                && slot.scan.program == plan.program
            {
                slot.scan.spend();
            }
        }
        if let Some(session) = plan.session {
            // The uninstall session is spent (design 3.6: a completed change with no session left
            // ends the broker).
            tables.sessions.remove(session);
        }
    }
    result
}

fn execute_plan<H: FlowHandler>(
    ctx: &crate::serve::Ctx<'_, H>,
    backend: &dyn ExecBackend,
    check_nothing_pending: &dyn Fn() -> Result<(), ErrorObject>,
    plan: &Plan,
    params: &PlanExecuteParams,
    ran: &Cell<bool>,
) -> Result<Value, ErrorObject> {
    check_nothing_pending()?;

    let bound = Arc::clone(&plan.bound);
    let setting = setting_of(params.restore_point);
    let facts = Facts {
        app_name: plan.app_name.clone(),
        restorable_until: backend
            .now()
            .0
            .checked_add(u64::from(RETAIN_QUARANTINE_DAYS) * TICKS_PER_DAY)
            .and_then(|until| stamp_of(FileTime(until))),
        restore_point: restore_point_requested(&bound, setting),
    };
    let consent = view::view(&bound, &facts)
        .map_err(|e| ErrorObject::runtime(format!("the dialog cannot be built: {e}")))?;
    if !consent.describes_plan(&bound) || consent.code != plan.code {
        return Err(ErrorObject::runtime(
            "the consent dialog does not describe this plan",
        ));
    }
    if dialog::ask(ctx, &consent) != Answer::Approved {
        return Err(ErrorObject::server(ErrorData::ConsentDeclined));
    }

    // Approved: from here the run finishes, whatever happens to the client.
    let total = u64::try_from(bound.items().len()).unwrap_or(u64::MAX);
    let finished = Cell::new(0u64);
    let notify = |phase: &str, done: u64| {
        let _ = ctx.notify(&ServerNotification::ExecProgress(Progress {
            request: ctx.request(),
            program_id: None,
            phase: phase.to_owned(),
            done,
            total: Some(total),
        }));
    };
    let progress = |event: &ExecProgress<'_>| match event {
        ExecProgress::SessionCreated { .. } => notify("session", 0),
        ExecProgress::ItemStarting { .. } => notify("item", finished.get()),
        ExecProgress::ItemFinished { .. } => {
            finished.set(finished.get() + 1);
            notify("item", finished.get());
        }
        ExecProgress::Aborting { .. } => notify("aborting", finished.get()),
    };
    let job = ExecJob {
        plan: bound,
        settings: ExecSettings {
            restore_point: setting,
            ..plan.settings.clone()
        },
        fingerprint: Arc::clone(&plan.fingerprint),
    };
    let output = backend.execute(job, &progress).map_err(failure_error)?;
    ran.set(true);
    let result = result_of(&output, plan.bound());
    serde_json::to_value(result).map_err(|e| ErrorObject::runtime(e.to_string()))
}

/// Whether an item ended as asked: done, gone already, or a remove-if-empty whose object holds
/// something (as the CLI counts it).
fn complete(outcome: &ItemOutcome) -> bool {
    matches!(
        outcome,
        ItemOutcome::Done
            | ItemOutcome::Vanished
            | ItemOutcome::Skipped {
                reason: purge_model::exec::op::SkipReason::NoLongerEmpty
            }
    )
}

/// The outcome of a finished run (design 6.4).
pub fn outcome_of(output: &ExecOutput) -> Outcome {
    if !output.closed || !output.report_written || !output.index_updated {
        return Outcome::NotClosed;
    }
    let report = &output.report;
    if report.state != SessionState::Committed
        || !report.items.iter().all(|item| complete(&item.outcome))
    {
        return Outcome::Partial;
    }
    Outcome::Complete
}

fn result_of(output: &ExecOutput, plan: &BoundPlan) -> ExecResult {
    let report = &output.report;
    let held = report
        .items
        .iter()
        .filter(|item| matches!(item.outcome, ItemOutcome::HeldRetry))
        .map(|item| HeldItem {
            op: item.op,
            display_name: display_name(
                &item.target,
                plan.item(item.op).and_then(|i| plan.candidate(i)),
            ),
            lockers: item.lockers.clone(),
        })
        .collect();
    ExecResult {
        outcome: outcome_of(output),
        session: output.session.clone(),
        counts: report.counts,
        held,
        restore_point: report.restore_point.clone(),
    }
}

fn failure_error(failure: ExecFailure) -> ErrorObject {
    match failure {
        ExecFailure::Exec(error) => exec_error(*error),
        ExecFailure::Machine(why) => ErrorObject::runtime(why),
    }
}

/// The error a run that did not start answers (design 6.4); nothing was changed.
pub fn exec_error(error: ExecError) -> ErrorObject {
    match error {
        ExecError::Plan(refusal) => ErrorObject::server(ErrorData::PlanRefused {
            refusals: vec![Refusal {
                candidate_id: None,
                reason: refusal.to_string(),
            }],
        }),
        ExecError::ObjectsUnbound(ids) => ErrorObject::server(ErrorData::PlanRefused {
            refusals: ids
                .into_iter()
                .map(|id| Refusal {
                    candidate_id: CandidateRef::try_from(&purge_model::CandidateId(id)).ok(),
                    reason: "the fingerprint does not record this system object as the program's, \
                             with the digest the scan saw"
                        .into(),
                })
                .collect(),
        }),
        ExecError::NeedsElevation(_) => ErrorObject::server(ErrorData::NotElevated),
        // Found once the run held the store's writer lock, after the dialog: nothing was done.
        ExecError::NeedsRecovery(sessions) => {
            ErrorObject::server(ErrorData::NeedsRecovery { sessions })
        }
        e @ ExecError::Damaged(_) => ErrorObject::server(ErrorData::StoreIntegrity {
            message: e.to_string(),
        }),
        // Another writer of the store (another broker's run, undo, recovery or purge) holds it.
        ExecError::Store(StorageError::WriterBusy { .. }) => ErrorObject::server(ErrorData::Busy),
        ExecError::Store(StorageError::Cap(cap)) => ErrorObject::server(ErrorData::CapExceeded {
            volume: cap.root.clone(),
            used: cap.held,
            needed: cap.planned,
            cap: cap.cap,
        }),
        ExecError::Store(
            e @ (StorageError::Integrity { .. }
            | StorageError::VolumeRoot { .. }
            | StorageError::VolumeMismatch { .. }
            | StorageError::IndexMalformed { .. }
            | StorageError::IndexLost { .. }),
        ) => ErrorObject::server(ErrorData::StoreIntegrity {
            message: e.to_string(),
        }),
        other => ErrorObject::runtime(other.to_string()),
    }
}
