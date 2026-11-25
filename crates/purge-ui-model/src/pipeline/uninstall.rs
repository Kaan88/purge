//! The Uninstall pipeline's view model (the port of `UninstallController` in
//! `ui/Purge.Client/Pipeline/UninstallPipeline.cs`, M3-UI-S2): launch the broker on the click, prepare,
//! confirm, run the program's own uninstaller on its route, check it is gone, scan, then hand the scan to
//! the leftovers page.
//!
//! The WinUI controller was one `async` method per action; here each `await` is a state, each call a
//! [`PipelineRequest`], and each answer an `on_*` method. The UI holds the broker link the launch made
//! and the medium engine; the model only knows whether it has a broker ([`UninstallController::has_broker`]).

use std::collections::HashMap;

use purge_model::{RunOutcome, ScanMode};
use purge_rpc::error::ErrorData;
use purge_rpc::methods::{
    ObservedResult, PrepareResult, Prepared, Progress, RestorePoint, Route, RouteInfo, RunResult,
    RunUserResult, RunningProcess, ScanResult, UninstallSessionId,
};

use super::strings;
use super::{CallError, LaunchResult, LaunchState, NoticeKind, UninstallTarget};

/// The five steps of the Uninstall pipeline page (M3_DESIGN.md §10, "Uninstall pipeline").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UninstallStep {
    /// `uninstall.prepare`: the broker records what the program registered.
    Record,
    /// The program's own uninstaller, in the broker or at the user's level.
    Run,
    /// Verify-gone: the broker's own check that the program left.
    CheckGone,
    /// `leftovers.scan` over the session.
    FindLeftovers,
    /// The scan is in; the leftovers page takes over.
    Ready,
}

impl UninstallStep {
    /// The five steps in the order the page lists them.
    pub const ALL: [UninstallStep; 5] = [
        UninstallStep::Record,
        UninstallStep::Run,
        UninstallStep::CheckGone,
        UninstallStep::FindLeftovers,
        UninstallStep::Ready,
    ];
}

/// How one step of the stepper stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum StepState {
    /// Not reached.
    #[default]
    Pending,
    /// Running now.
    Active,
    /// Done.
    Done,
    /// Done with a caveat, or a choice that stopped it.
    Warning,
    /// Failed.
    Failed,
}

/// One bar the page shows: the cancelled prompt, an exit code with the forced cleanup and Retry, still
/// installed, a restart, or a link that ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallNotice {
    /// Its severity; an [`NoticeKind::Error`] one blocks the run.
    pub kind: NoticeKind,
    /// The title.
    pub title: String,
    /// The message.
    pub message: String,
    /// The uninstaller's exit code, when it gave one.
    pub exit_code: Option<u32>,
    /// The bar offers Retry ("Try again" on an informational bar).
    pub can_retry: bool,
    /// The bar offers "Run forced cleanup".
    pub can_force: bool,
    /// The bar offers "Start over".
    pub can_start_over: bool,
}

impl UninstallNotice {
    /// A bar without actions.
    pub fn new(kind: NoticeKind, title: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind,
            title: title.into(),
            message: message.into(),
            exit_code: None,
            can_retry: false,
            can_force: false,
            can_start_over: false,
        }
    }

    fn retry(mut self) -> Self {
        self.can_retry = true;
        self
    }

    fn start_over(mut self) -> Self {
        self.can_start_over = true;
        self
    }

    fn code(mut self, exit_code: Option<u32>) -> Self {
        self.exit_code = exit_code;
        self
    }
}

/// The answer the leftovers page needs after the pipeline ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallOutcome {
    /// The program.
    pub target: UninstallTarget,
    /// The uninstall session.
    pub session_id: UninstallSessionId,
    /// The scan.
    pub scan_id: purge_rpc::methods::ScanId,
    /// The mode the broker scanned in.
    pub mode: ScanMode,
    /// Whether the uninstaller ran quietly.
    pub quiet: bool,
    /// The restore-point choice carried to the leftovers page's `plan.execute`.
    pub restore_point: RestorePoint,
    /// Counts each outcome of a controller, so a page can tell a new scan from the one it holds (the
    /// WinUI page compared object references).
    pub serial: u64,
}

impl UninstallOutcome {
    /// True for the forced scan after a failed or unverified uninstall: nothing starts ticked.
    pub fn forced(&self) -> bool {
        self.mode == ScanMode::Forced
    }
}

/// The confirm dialog's content: the steps, the exact command and its signer, the quiet choice and the
/// restore-point choice. The command is the one that will run, taken from the process that runs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallConfirmation {
    /// The program.
    pub target: UninstallTarget,
    /// "Purge will:" and these, numbered.
    pub steps: Vec<String>,
    /// The command for the current quiet choice.
    pub command: String,
    /// The quiet command, when there is one.
    pub quiet_command: Option<String>,
    /// The uninstaller's signer.
    pub signer: Option<String>,
    /// Whether a quiet command exists.
    pub quiet_available: bool,
    /// The quiet choice.
    pub quiet: bool,
    /// The restore-point choice.
    pub restore_point: RestorePoint,
    /// Processes of the program that run now.
    pub running: Vec<RunningProcess>,
}

/// How the confirm dialog was answered: go on, stop, or check the running processes again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UninstallAnswer {
    /// Uninstall.
    pub proceed: bool,
    /// The quiet choice in the dialog.
    pub quiet: bool,
    /// The restore-point choice in the dialog.
    pub restore_point: RestorePoint,
    /// "Check again".
    pub recheck: bool,
}

impl UninstallAnswer {
    /// "Uninstall" or "Not now".
    pub fn new(proceed: bool, quiet: bool, restore_point: RestorePoint) -> Self {
        Self {
            proceed,
            quiet,
            restore_point,
            recheck: false,
        }
    }

    /// "Check again".
    pub fn recheck(quiet: bool, restore_point: RestorePoint) -> Self {
        Self {
            proceed: false,
            quiet,
            restore_point,
            recheck: true,
        }
    }
}

/// What the pipeline asks the UI to do. Each call request gets exactly one answer through its `on_*`
/// method; the others are told and need none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineRequest {
    /// Start the elevated broker (the first-elevation explanation and the UAC prompt happen there); answer
    /// with [`UninstallController::on_launch`].
    Launch,
    /// `uninstall.prepare {program_ids: [program_id]}` over the broker; `prepare.progress` goes to
    /// [`UninstallController::on_progress`]; answer with [`UninstallController::on_prepare`].
    Prepare {
        /// The program.
        program_id: purge_model::ProgramId,
    },
    /// `uninstall.route {program_id}` on the medium engine; answer with [`UninstallController::on_route`].
    Route {
        /// The program.
        program_id: purge_model::ProgramId,
    },
    /// Show the confirm dialog; answer with [`UninstallController::answer`].
    Confirm(UninstallConfirmation),
    /// `uninstall.run` over the broker (let the broker's window come to the front first); `consent.shown`
    /// goes to [`UninstallController::on_consent_shown`], `uninstall.progress` to
    /// [`UninstallController::on_progress`]; answer with [`UninstallController::on_run`].
    Run {
        /// The session of the prepare.
        session_id: UninstallSessionId,
        /// Run the quiet command.
        quiet: bool,
        /// Shown in the broker's dialog and carried to the cleanup.
        restore_point: RestorePoint,
    },
    /// `uninstall.run_user {program_id, quiet}` on the medium engine; answer with
    /// [`UninstallController::on_run_user`].
    RunUser {
        /// The program.
        program_id: purge_model::ProgramId,
        /// Run the quiet command.
        quiet: bool,
    },
    /// `uninstall.observed {session_id, outcome}` over the broker; answer with
    /// [`UninstallController::on_observed`].
    Observed {
        /// The session.
        session_id: UninstallSessionId,
        /// The engine's report of the run.
        outcome: Option<RunOutcome>,
    },
    /// `leftovers.scan {session_id, forced}` over the broker; `scan.progress` goes to
    /// [`UninstallController::on_progress`]; answer with [`UninstallController::on_scan`].
    Scan {
        /// The session.
        session_id: UninstallSessionId,
        /// The forced mode: nothing pre-selected.
        forced: bool,
    },
    /// End the broker link the UI holds.
    CloseBroker,
    /// The user said No at the Windows prompt, or "Not now" at Purge's explanation (`declined`).
    AdminPromptCancelled {
        /// "Not now" at Purge's explanation.
        declined: bool,
    },
    /// The uninstaller ran and the broker checked the program, before the leftover scan. `removed` is
    /// true when the uninstaller succeeded and the broker confirmed the program gone: Purge removed it, so
    /// the Programs page drops it and the engine forgets it. Either way the list is read again.
    RunEnded {
        /// The program.
        target: UninstallTarget,
        /// Purge removed it.
        removed: bool,
    },
    /// The scan is in ([`UninstallController::completed_outcome`]); the page hands it to the leftovers page.
    Completed(UninstallOutcome),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryStage {
    None,
    Run,
    Scan,
}

/// The call the pipeline waits for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Waiting {
    Launch,
    Prepare,
    Route,
    Confirm,
    Run,
    RunUser,
    Observed { run: RunUserResult },
    Scan,
}

/// Which side a failed call was on: the bars name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Broker,
    Engine,
}

/// The Uninstall pipeline of one program at a time.
#[derive(Debug, Clone)]
pub struct UninstallController {
    steps: HashMap<UninstallStep, (StepState, Option<String>)>,
    notices: Vec<UninstallNotice>,
    target: Option<UninstallTarget>,
    current_step: UninstallStep,
    active_step: Option<UninstallStep>,
    launch_state: Option<LaunchState>,
    route_text: Option<&'static str>,
    command: Option<String>,
    quiet_command: Option<String>,
    signer: Option<String>,
    running: Vec<RunningProcess>,
    quiet_available: bool,
    quiet: bool,
    restore_point: RestorePoint,
    completed: Option<UninstallOutcome>,
    serial: u64,
    prepared: Option<Prepared>,
    retry: RetryStage,
    force: bool,
    busy: bool,
    has_broker: bool,
    detached: bool,
    waiting: Option<Waiting>,
}

impl Default for UninstallController {
    fn default() -> Self {
        Self::new()
    }
}

impl UninstallController {
    /// A controller with nothing started.
    pub fn new() -> Self {
        Self {
            steps: UninstallStep::ALL
                .iter()
                .map(|&s| (s, (StepState::Pending, None)))
                .collect(),
            notices: vec![],
            target: None,
            current_step: UninstallStep::Record,
            active_step: None,
            launch_state: None,
            route_text: None,
            command: None,
            quiet_command: None,
            signer: None,
            running: vec![],
            quiet_available: false,
            quiet: false,
            restore_point: RestorePoint::HighRisk,
            completed: None,
            serial: 0,
            prepared: None,
            retry: RetryStage::None,
            force: false,
            busy: false,
            has_broker: false,
            detached: false,
            waiting: None,
        }
    }

    // ---- state ------------------------------------------------------------------------------------

    /// The program; `None` before the first [`Self::begin`].
    pub fn target(&self) -> Option<&UninstallTarget> {
        self.target.as_ref()
    }

    /// The step the stepper marks as current (the active or the last finished one).
    pub fn current_step(&self) -> UninstallStep {
        self.current_step
    }

    /// How the broker's start went, once it was asked.
    pub fn launch_state(&self) -> Option<LaunchState> {
        self.launch_state
    }

    /// "Administrator" or "This user's level", once the route is known.
    pub fn route_text(&self) -> Option<&'static str> {
        self.route_text
    }

    /// The command for the current quiet choice: the one the run will use.
    pub fn selected_command(&self) -> Option<&str> {
        if self.quiet && self.quiet_available {
            self.quiet_command.as_deref()
        } else {
            self.command.as_deref()
        }
    }

    /// The interactive command, once recorded.
    pub fn command(&self) -> Option<&str> {
        self.command.as_deref()
    }

    /// The quiet command.
    pub fn quiet_command(&self) -> Option<&str> {
        self.quiet_command.as_deref()
    }

    /// The uninstaller's signer.
    pub fn signer(&self) -> Option<&str> {
        self.signer.as_deref()
    }

    /// Processes of the program that run now.
    pub fn running(&self) -> &[RunningProcess] {
        &self.running
    }

    /// Whether a quiet command exists.
    pub fn quiet_available(&self) -> bool {
        self.quiet_available
    }

    /// The quiet choice.
    pub fn quiet(&self) -> bool {
        self.quiet
    }

    /// The restore-point choice carried to the leftovers page's `plan.execute`.
    pub fn restore_point(&self) -> RestorePoint {
        self.restore_point
    }

    /// Every bar of this run, newest last; an [`NoticeKind::Error`] one blocks the run.
    pub fn notices(&self) -> &[UninstallNotice] {
        &self.notices
    }

    /// The scan and its ids once the pipeline ended; `None` before.
    pub fn completed_outcome(&self) -> Option<&UninstallOutcome> {
        self.completed.as_ref()
    }

    /// Whether the controller holds a broker link (the UI holds the link itself).
    pub fn has_broker(&self) -> bool {
        self.has_broker
    }

    /// True while a step runs (from an action until its last answer is in).
    pub fn is_busy(&self) -> bool {
        self.busy
    }

    /// True while the confirm dialog is open.
    pub fn is_confirming(&self) -> bool {
        self.waiting == Some(Waiting::Confirm)
    }

    /// The page's guide line before anything ran.
    pub fn guide_text(&self) -> &'static str {
        strings::GUIDE
    }

    /// The state of `step`.
    pub fn state_of(&self, step: UninstallStep) -> StepState {
        self.steps[&step].0
    }

    /// The detail line of `step`.
    pub fn detail_of(&self, step: UninstallStep) -> Option<&str> {
        self.steps[&step].1.as_deref()
    }

    // ---- actions ----------------------------------------------------------------------------------

    /// Starts the pipeline for one program. A second call while one runs is ignored.
    pub fn begin(&mut self, target: UninstallTarget) -> Vec<PipelineRequest> {
        if self.busy {
            return vec![];
        }
        self.busy = true;
        self.reset(target);
        let mut out = vec![];
        self.gather(&mut out);
        out
    }

    /// The confirm dialog's answer. A "check again" re-reads the commands and the running processes and
    /// asks again; "not now" stops with nothing changed.
    pub fn answer(&mut self, answer: UninstallAnswer) -> Vec<PipelineRequest> {
        if self.waiting != Some(Waiting::Confirm) {
            return vec![];
        }
        self.waiting = None;
        let mut out = vec![];
        if answer.recheck {
            // Re-read both sides: a process may have closed and the command may differ now.
            self.prepared = None;
            self.clear_steps();
            self.set_step(UninstallStep::Record, StepState::Pending, None);
            self.gather(&mut out);
            return out;
        }
        if !answer.proceed {
            self.add_notice(UninstallNotice::new(
                NoticeKind::Info,
                strings::CANCELLED_TITLE,
                strings::CANCELLED_MESSAGE,
            ));
            self.current_step = UninstallStep::Run;
            self.end();
            return out;
        }
        self.quiet = answer.quiet && self.quiet_available;
        self.restore_point = answer.restore_point;
        self.run_stage(&mut out);
        out
    }

    /// The Retry of a bar: the run again, the scan again, or the whole preparation again.
    pub fn retry(&mut self) -> Vec<PipelineRequest> {
        if self.busy {
            return vec![];
        }
        self.busy = true;
        self.clear_errors();
        self.stage_rerun();
        let mut out = vec![];
        match self.retry {
            RetryStage::Run => {
                self.retry = RetryStage::None;
                self.run_stage(&mut out);
            }
            RetryStage::Scan => {
                self.retry = RetryStage::None;
                let force = self.force;
                self.find_leftovers(force, &mut out);
            }
            RetryStage::None => self.restart(&mut out),
        }
        out
    }

    /// The safety-net choices of the page before the confirmation is answered.
    pub fn set_choice(&mut self, quiet: bool, restore_point: RestorePoint) {
        if self.quiet_available {
            self.quiet = quiet;
        }
        self.restore_point = restore_point;
    }

    /// The running-process line's Retry: re-reads the commands and the processes that hold the program,
    /// then asks again. At the confirm dialog it answers it with a recheck; later it records the program
    /// again.
    pub fn recheck(&mut self) -> Vec<PipelineRequest> {
        if self.waiting == Some(Waiting::Confirm) {
            return self.answer(UninstallAnswer::recheck(self.quiet, self.restore_point));
        }
        if self.target.is_none() || self.prepared.is_none() || self.busy {
            return vec![];
        }
        self.busy = true;
        self.stage_rerun();
        self.prepared = None;
        self.clear_steps();
        self.set_step(UninstallStep::Record, StepState::Pending, None);
        let mut out = vec![];
        self.gather(&mut out);
        out
    }

    /// "Run forced cleanup": scan this session in the forced mode with nothing pre-selected.
    pub fn force(&mut self) -> Vec<PipelineRequest> {
        if self.busy {
            return vec![];
        }
        self.busy = true;
        self.clear_errors();
        self.stage_rerun();
        self.force = true;
        self.retry = RetryStage::None;
        if matches!(
            self.state_of(UninstallStep::CheckGone),
            StepState::Pending | StepState::Active
        ) {
            // A broker-route run that failed never carried a verify-gone. The scan is forced either way.
            self.set_step(
                UninstallStep::CheckGone,
                StepState::Warning,
                Some(strings::NOT_CHECKED_FAILED.into()),
            );
        }
        let mut out = vec![];
        self.find_leftovers(true, &mut out);
        out
    }

    /// Starts again from the broker: a dead link is closed and a fresh one is launched (UAC again).
    pub fn start_over(&mut self) -> Vec<PipelineRequest> {
        if self.busy {
            return vec![];
        }
        self.busy = true;
        self.clear_errors();
        let mut out = vec![];
        self.restart(&mut out);
        out
    }

    /// Hands the live broker to the leftovers page: true when there was one. The controller no longer
    /// closes it.
    pub fn take_broker(&mut self) -> bool {
        self.detached = true;
        std::mem::take(&mut self.has_broker)
    }

    /// The page goes away: ends the broker unless it was handed over.
    pub fn close(&mut self) -> Vec<PipelineRequest> {
        if self.detached {
            return vec![];
        }
        self.drop_broker()
    }

    // ---- answers ----------------------------------------------------------------------------------

    /// The broker's start. With [`LaunchState::Started`] the UI holds the live link.
    pub fn on_launch(&mut self, launch: LaunchResult) -> Vec<PipelineRequest> {
        if self.waiting != Some(Waiting::Launch) {
            return vec![];
        }
        self.waiting = None;
        self.launch_state = Some(launch.state);
        let mut out = vec![];
        match launch.state {
            LaunchState::Started => {
                self.has_broker = true;
                self.gather(&mut out);
                return out;
            }
            LaunchState::Cancelled => {
                // "Not now" at the explanation and No at the Windows prompt both end here: the words fit
                // either. It is a choice, not a failure: the step stays "not started" (no red cross), and
                // the bar offers to try again.
                self.set_step(
                    UninstallStep::Record,
                    StepState::Pending,
                    Some(strings::NOT_STARTED_NO_PERMISSION.into()),
                );
                self.add_notice(
                    UninstallNotice::new(
                        NoticeKind::Info,
                        strings::NOT_GIVEN_TITLE,
                        if launch.declined_explanation {
                            strings::NOT_GIVEN_NOT_NOW
                        } else {
                            strings::NOT_GIVEN_PROMPT_CANCELLED
                        },
                    )
                    .retry(),
                );
                out.push(PipelineRequest::AdminPromptCancelled {
                    declined: launch.declined_explanation,
                });
            }
            LaunchState::NotAdministrator => {
                self.set_step(
                    UninstallStep::Record,
                    StepState::Failed,
                    Some(strings::ADMIN_ACCOUNT_NEEDED.into()),
                );
                self.add_notice(UninstallNotice::new(
                    NoticeKind::Error,
                    strings::NOT_ADMIN_TITLE,
                    launch.message,
                ));
            }
            LaunchState::CannotStart | LaunchState::Failed => {
                self.set_step(
                    UninstallStep::Record,
                    StepState::Failed,
                    Some(strings::BROKER_DID_NOT_START.into()),
                );
                self.add_notice(
                    UninstallNotice::new(
                        NoticeKind::Error,
                        strings::CANNOT_START_TITLE,
                        exit_text(&launch.message, launch.exit_code),
                    )
                    .code(launch.exit_code)
                    .start_over(),
                );
            }
        }
        self.end();
        out
    }

    /// A `*.progress` notification of the call in flight: the active step's line.
    pub fn on_progress(&mut self, progress: &Progress) {
        let step = match self.waiting {
            Some(Waiting::Prepare) => {
                self.set_step(
                    UninstallStep::Record,
                    StepState::Active,
                    Some(record_phase_text(Some(&progress.phase)).into()),
                );
                return;
            }
            Some(Waiting::Run | Waiting::RunUser) => UninstallStep::Run,
            Some(Waiting::Scan) => UninstallStep::FindLeftovers,
            _ => return,
        };
        self.set_step(step, StepState::Active, Some(progress.phase.clone()));
    }

    /// `consent.shown`: the broker's dialog is up; `code` is the one in its footer.
    pub fn on_consent_shown(&mut self, code: &str) {
        if self.waiting == Some(Waiting::Run) {
            self.set_step(
                UninstallStep::Run,
                StepState::Active,
                Some(strings::consent_shown(code)),
            );
        }
    }

    /// The answer of `uninstall.prepare`.
    pub fn on_prepare(&mut self, result: Result<PrepareResult, CallError>) -> Vec<PipelineRequest> {
        if self.waiting != Some(Waiting::Prepare) {
            return vec![];
        }
        self.waiting = None;
        let mut out = vec![];
        let program = match result {
            Err(e) => return self.fail(e, Side::Broker),
            Ok(r) => match r.programs.into_iter().next() {
                Some(p) => p,
                None => {
                    return self.fail(
                        CallError::Other(strings::NO_PROGRAM_RECORDED.into()),
                        Side::Broker,
                    );
                }
            },
        };
        self.command = Some(program.command.clone());
        self.quiet_command = program.quiet_command.clone();
        self.signer = program.signer.clone();
        self.running = program.running.clone();
        self.route_text = Some(if program.route == Route::Broker {
            strings::ROUTE_ADMIN
        } else {
            strings::ROUTE_USER
        });
        let medium = program.route == Route::Medium;
        let program_id = program.program_id.clone();
        self.prepared = Some(program);
        if medium {
            // The command shown must be the one the medium engine will run: its own inventory, its own rules.
            self.waiting = Some(Waiting::Route);
            out.push(PipelineRequest::Route { program_id });
            return out;
        }
        self.finish_prepare(&mut out);
        out
    }

    /// The answer of `uninstall.route` (medium route only).
    pub fn on_route(&mut self, result: Result<RouteInfo, CallError>) -> Vec<PipelineRequest> {
        if self.waiting != Some(Waiting::Route) {
            return vec![];
        }
        self.waiting = None;
        let info = match result {
            Ok(info) => info,
            Err(e) => return self.fail(e, Side::Engine),
        };
        let mut out = vec![];
        if info.route != Route::Medium {
            self.set_step(
                UninstallStep::Record,
                StepState::Failed,
                Some(strings::ROUTES_DISAGREE.into()),
            );
            self.fail_wrong_route(info.route);
            self.prepared = None;
            self.end();
            return out;
        }
        self.command = Some(info.command);
        self.quiet_command = info.quiet_command;
        self.signer = info.signer;
        self.running = info.running;
        self.route_text = Some(strings::ROUTE_USER);
        self.finish_prepare(&mut out);
        out
    }

    /// The answer of `uninstall.run` (broker route).
    pub fn on_run(&mut self, result: Result<RunResult, CallError>) -> Vec<PipelineRequest> {
        if self.waiting != Some(Waiting::Run) {
            return vec![];
        }
        self.waiting = None;
        let mut out = vec![];
        let result = match result {
            Ok(r) => r,
            Err(e) => {
                match (e.kind(), e.data()) {
                    (Some("consent_declined"), _) => {
                        self.set_step(
                            UninstallStep::Run,
                            StepState::Warning,
                            Some(strings::DECLINED_STEP.into()),
                        );
                        self.retry = RetryStage::Run;
                        self.add_notice(
                            UninstallNotice::new(
                                NoticeKind::Info,
                                strings::DECLINED_TITLE,
                                strings::DECLINED_MESSAGE,
                            )
                            .retry(),
                        );
                    }
                    (Some("uninstall_failed"), data) => {
                        let code = match data {
                            Some(ErrorData::UninstallFailed { exit_code, .. }) => *exit_code,
                            _ => None,
                        };
                        let detail = exit_detail(code, self.quiet);
                        self.set_step(UninstallStep::Run, StepState::Failed, Some(detail));
                        self.on_uninstall_failed(code);
                    }
                    (Some("wrong_route"), data) => {
                        let route = match data {
                            Some(ErrorData::WrongRoute { route }) => *route,
                            _ => Route::Medium,
                        };
                        self.set_step(
                            UninstallStep::Run,
                            StepState::Failed,
                            Some(strings::WRONG_PART_STEP.into()),
                        );
                        self.fail_wrong_route(route);
                    }
                    _ => return self.fail(e, Side::Broker),
                }
                self.end();
                return out;
            }
        };
        let detail = exit_detail(result.exit_code, self.quiet);
        self.set_step(UninstallStep::Run, StepState::Done, Some(detail));
        let gone = result.verify_gone.is_passed();
        self.check_gone(gone, &mut out);
        if result.outcome == RunOutcome::SuccessReboot || result.exit_code == Some(3010) {
            self.add_notice(restart_notice());
        }
        self.find_leftovers(!gone, &mut out);
        out
    }

    /// The answer of `uninstall.run_user` (medium route).
    pub fn on_run_user(
        &mut self,
        result: Result<RunUserResult, CallError>,
    ) -> Vec<PipelineRequest> {
        if self.waiting != Some(Waiting::RunUser) {
            return vec![];
        }
        self.waiting = None;
        let result = match result {
            Ok(r) => r,
            Err(e) if e.kind() == Some("wrong_route") => {
                self.fail_wrong_route(Route::Broker);
                self.end();
                return vec![];
            }
            Err(e) => return self.fail(e, Side::Engine),
        };
        let failed = is_failed(result.outcome);
        let detail = exit_detail(result.exit_code, self.quiet);
        self.set_step(
            UninstallStep::Run,
            if failed {
                StepState::Failed
            } else {
                StepState::Done
            },
            Some(detail),
        );
        // The order of design 3.2: run_user, then the broker's own observation. It is the broker that
        // decides. The engine's report travels with it, so a failed or cancelled run is forced even if it
        // left nothing.
        let Some(session_id) = self.prepared.as_ref().map(|p| p.session_id) else {
            self.end();
            return vec![];
        };
        let outcome = Some(result.outcome);
        self.waiting = Some(Waiting::Observed { run: result });
        vec![PipelineRequest::Observed {
            session_id,
            outcome,
        }]
    }

    /// The answer of `uninstall.observed` (medium route).
    pub fn on_observed(
        &mut self,
        result: Result<ObservedResult, CallError>,
    ) -> Vec<PipelineRequest> {
        let Some(Waiting::Observed { run }) = self.waiting.clone() else {
            return vec![];
        };
        self.waiting = None;
        let observed = match result {
            Ok(o) => o,
            Err(e) => return self.fail(e, Side::Broker),
        };
        let mut out = vec![];
        let failed = is_failed(run.outcome);
        let gone = observed.verify_gone.is_passed();
        if let Some(target) = self.target.clone() {
            out.push(PipelineRequest::RunEnded {
                target,
                removed: gone && !failed,
            });
        }
        self.mark_gone(gone);
        if failed {
            self.on_uninstall_failed(run.exit_code);
            self.end();
            return out;
        }
        if run.outcome == RunOutcome::SuccessReboot {
            self.add_notice(restart_notice());
        }
        self.find_leftovers(!gone, &mut out);
        out
    }

    /// The answer of `leftovers.scan`.
    pub fn on_scan(&mut self, result: Result<ScanResult, CallError>) -> Vec<PipelineRequest> {
        if self.waiting != Some(Waiting::Scan) {
            return vec![];
        }
        self.waiting = None;
        let scan = match result {
            Ok(s) => s,
            Err(e) => {
                self.retry = RetryStage::Scan;
                return self.fail(e, Side::Broker);
            }
        };
        let (Some(target), Some(session_id)) = (
            self.target.clone(),
            self.prepared.as_ref().map(|p| p.session_id),
        ) else {
            self.end();
            return vec![];
        };
        self.set_step(
            UninstallStep::FindLeftovers,
            StepState::Done,
            Some(counts_text(&scan)),
        );
        self.set_step(
            UninstallStep::Ready,
            StepState::Done,
            Some(strings::READY_FOR_REVIEW.into()),
        );
        self.current_step = UninstallStep::Ready;
        self.serial += 1;
        let outcome = UninstallOutcome {
            target,
            session_id,
            scan_id: scan.scan_id,
            mode: scan.mode,
            quiet: self.quiet,
            restore_point: self.restore_point,
            serial: self.serial,
        };
        self.completed = Some(outcome.clone());
        self.retry = RetryStage::None;
        self.end();
        vec![PipelineRequest::Completed(outcome)]
    }

    // ---- the flow ---------------------------------------------------------------------------------

    /// `GatherAndConfirmAsync` up to its next wait: the broker, the record, then the confirm dialog.
    fn gather(&mut self, out: &mut Vec<PipelineRequest>) {
        if !self.has_broker {
            self.set_step(
                UninstallStep::Record,
                StepState::Active,
                Some(strings::STARTING_BROKER.into()),
            );
            self.waiting = Some(Waiting::Launch);
            out.push(PipelineRequest::Launch);
            return;
        }
        if self.prepared.is_none() || self.state_of(UninstallStep::Record) != StepState::Done {
            let Some(target) = &self.target else {
                self.end();
                return;
            };
            let program_id = target.program_id.clone();
            self.set_step(
                UninstallStep::Record,
                StepState::Active,
                Some(record_phase_text(None).into()),
            );
            self.waiting = Some(Waiting::Prepare);
            out.push(PipelineRequest::Prepare { program_id });
            return;
        }
        let Some(target) = self.target.clone() else {
            self.end();
            return;
        };
        self.waiting = Some(Waiting::Confirm);
        out.push(PipelineRequest::Confirm(self.build_confirmation(target)));
    }

    fn finish_prepare(&mut self, out: &mut Vec<PipelineRequest>) {
        self.quiet_available = self.quiet_command.as_deref().is_some_and(|q| !q.is_empty());
        self.quiet = self.quiet_available;
        let medium = self
            .prepared
            .as_ref()
            .is_some_and(|p| p.route == Route::Medium);
        self.set_step(
            UninstallStep::Record,
            StepState::Done,
            Some(if medium {
                strings::RECORDED_MEDIUM.into()
            } else {
                strings::RECORDED_BROKER.into()
            }),
        );
        self.set_step(UninstallStep::Run, StepState::Pending, None);
        self.current_step = UninstallStep::Run;
        self.gather(out);
    }

    fn build_confirmation(&self, target: UninstallTarget) -> UninstallConfirmation {
        let medium = self
            .prepared
            .as_ref()
            .is_some_and(|p| p.route == Route::Medium);
        UninstallConfirmation {
            target,
            steps: strings::confirm_steps(medium),
            command: self.selected_command().unwrap_or_default().to_owned(),
            quiet_command: self.quiet_command.clone(),
            signer: self.signer.clone(),
            quiet_available: self.quiet_available,
            quiet: self.quiet && self.quiet_available,
            restore_point: self.restore_point,
            running: self.running.clone(),
        }
    }

    fn run_stage(&mut self, out: &mut Vec<PipelineRequest>) {
        let Some(prepared) = &self.prepared else {
            self.end();
            return;
        };
        let session_id = prepared.session_id;
        let medium = prepared.route == Route::Medium;
        self.current_step = UninstallStep::Run;
        if medium {
            let Some(target) = &self.target else {
                self.end();
                return;
            };
            let program_id = target.program_id.clone();
            self.set_step(
                UninstallStep::Run,
                StepState::Active,
                Some(if self.quiet {
                    strings::RUNNING_QUIET.into()
                } else {
                    strings::RUNNING.into()
                }),
            );
            self.waiting = Some(Waiting::RunUser);
            out.push(PipelineRequest::RunUser {
                program_id,
                quiet: self.quiet,
            });
        } else {
            // The broker asks its own dialog before it starts anything: wait for it, and say nothing has run.
            self.set_step(
                UninstallStep::Run,
                StepState::Active,
                Some(strings::WAITING_FOR_PROMPT.into()),
            );
            self.waiting = Some(Waiting::Run);
            out.push(PipelineRequest::Run {
                session_id,
                quiet: self.quiet,
                restore_point: self.restore_point,
            });
        }
    }

    fn check_gone(&mut self, gone: bool, out: &mut Vec<PipelineRequest>) {
        if let Some(target) = self.target.clone() {
            out.push(PipelineRequest::RunEnded {
                target,
                removed: gone,
            });
        }
        self.mark_gone(gone);
    }

    fn mark_gone(&mut self, gone: bool) {
        self.set_step(
            UninstallStep::CheckGone,
            if gone {
                StepState::Done
            } else {
                StepState::Warning
            },
            Some(if gone {
                strings::CONFIRMED_GONE.into()
            } else {
                strings::PARTS_REMAIN.into()
            }),
        );
        if !gone {
            self.add_notice(UninstallNotice::new(
                NoticeKind::Warning,
                strings::STILL_INSTALLED_TITLE,
                strings::STILL_INSTALLED_MESSAGE,
            ));
        }
    }

    fn find_leftovers(&mut self, forced: bool, out: &mut Vec<PipelineRequest>) {
        let Some(prepared) = &self.prepared else {
            self.end();
            return;
        };
        let session_id = prepared.session_id;
        self.force = forced;
        self.set_step(
            UninstallStep::FindLeftovers,
            StepState::Active,
            Some(strings::LOOKING_FOR_LEFTOVERS.into()),
        );
        self.current_step = UninstallStep::FindLeftovers;
        self.waiting = Some(Waiting::Scan);
        out.push(PipelineRequest::Scan { session_id, forced });
    }

    fn on_uninstall_failed(&mut self, exit_code: Option<u32>) {
        self.retry = RetryStage::Run;
        let mut notice = UninstallNotice::new(
            NoticeKind::Error,
            strings::UNINSTALLER_FAILED_TITLE,
            strings::uninstaller_failed(exit_code),
        )
        .code(exit_code)
        .retry();
        notice.can_force = true;
        self.add_notice(notice);
    }

    fn fail_wrong_route(&mut self, route: Route) {
        self.retry = RetryStage::None;
        self.fail_running_step();
        self.add_notice(UninstallNotice::new(
            NoticeKind::Error,
            strings::WRONG_PART_TITLE,
            strings::wrong_part(route == Route::Broker),
        ));
    }

    /// The `catch` blocks of the WinUI `GuardAsync`: a bar for the error, then the run ends.
    fn fail(&mut self, error: CallError, side: Side) -> Vec<PipelineRequest> {
        match error {
            CallError::Cancelled => {
                self.add_notice(UninstallNotice::new(
                    NoticeKind::Info,
                    strings::STOPPED_TITLE,
                    strings::STOPPED_MESSAGE,
                ));
            }
            CallError::Link(message) => {
                self.fail_running_step();
                let notice = match side {
                    Side::Broker => UninstallNotice::new(
                        NoticeKind::Error,
                        strings::BROKER_ENDED_TITLE,
                        format!("{message}{}", strings::BROKER_ENDED_TAIL),
                    ),
                    Side::Engine => UninstallNotice::new(
                        NoticeKind::Error,
                        strings::ENGINE_ENDED_TITLE,
                        format!("{message}{}", strings::ENGINE_ENDED_TAIL),
                    ),
                };
                self.add_notice(notice.start_over());
                self.retry = RetryStage::None;
            }
            CallError::Rpc(e) => {
                self.fail_running_step();
                let notice = match side {
                    Side::Broker => {
                        let code = match &e.data {
                            Some(ErrorData::UninstallFailed { exit_code, .. }) => *exit_code,
                            _ => None,
                        };
                        UninstallNotice::new(NoticeKind::Error, strings::REFUSED_TITLE, e.message)
                            .code(code)
                    }
                    Side::Engine => UninstallNotice::new(
                        NoticeKind::Error,
                        strings::ENGINE_REFUSED_TITLE,
                        e.message,
                    ),
                };
                self.add_notice(notice.start_over());
                self.retry = RetryStage::None;
            }
            CallError::Other(message) => {
                self.fail_running_step();
                self.add_notice(
                    UninstallNotice::new(NoticeKind::Error, strings::WENT_WRONG_TITLE, message)
                        .start_over(),
                );
                self.retry = RetryStage::None;
            }
        }
        self.end();
        vec![]
    }

    fn restart(&mut self, out: &mut Vec<PipelineRequest>) {
        out.extend(self.drop_broker());
        let Some(target) = self.target.clone() else {
            self.end();
            return;
        };
        self.reset(target);
        self.gather(out);
    }

    /// A stage runs again (Retry, Check again, Run forced cleanup): the scan from before is no longer this
    /// run's, so [`Self::completed_outcome`] is cleared until the new scan is in. A page that holds the old
    /// scan for the leftovers page must not hand it over (with the broker this run is using) meanwhile.
    fn stage_rerun(&mut self) {
        self.completed = None;
    }

    fn end(&mut self) {
        self.busy = false;
        self.waiting = None;
    }

    fn fail_running_step(&mut self) {
        if let Some(step) = self.active_step {
            self.set_step(step, StepState::Failed, None);
        }
    }

    fn reset(&mut self, target: UninstallTarget) {
        self.target = Some(target);
        self.prepared = None;
        self.force = false;
        self.retry = RetryStage::None;
        self.waiting = None;
        self.active_step = None;
        self.notices.clear();
        self.command = None;
        self.quiet_command = None;
        self.signer = None;
        self.running.clear();
        self.quiet_available = false;
        self.quiet = false;
        self.route_text = None;
        self.launch_state = None;
        self.completed = None;
        self.current_step = UninstallStep::Record;
        self.clear_steps();
        self.set_step(UninstallStep::Record, StepState::Pending, None);
    }

    fn clear_steps(&mut self) {
        for step in UninstallStep::ALL {
            self.steps.insert(step, (StepState::Pending, None));
        }
    }

    fn set_step(&mut self, step: UninstallStep, state: StepState, detail: Option<String>) {
        self.steps.insert(step, (state, detail));
        if state == StepState::Active {
            self.active_step = Some(step);
        } else if self.active_step == Some(step) {
            self.active_step = None;
        }
        if matches!(state, StepState::Active | StepState::Done) {
            self.current_step = step;
        }
    }

    fn add_notice(&mut self, notice: UninstallNotice) {
        if self
            .notices
            .iter()
            .any(|n| n.kind == notice.kind && n.title == notice.title)
        {
            return;
        }
        self.notices.push(notice);
    }

    fn clear_errors(&mut self) {
        self.notices.retain(|n| n.kind != NoticeKind::Error);
    }

    fn drop_broker(&mut self) -> Vec<PipelineRequest> {
        self.detached = false;
        if std::mem::take(&mut self.has_broker) {
            vec![PipelineRequest::CloseBroker]
        } else {
            vec![]
        }
    }
}

fn is_failed(outcome: RunOutcome) -> bool {
    matches!(
        outcome,
        RunOutcome::Failed | RunOutcome::TimedOut | RunOutcome::Cancelled
    )
}

/// The Record step's line for one broker harvest phase. The phases are the engine's own log lines; the
/// longest is the snapshot of the PC taken before the uninstaller runs (about 10 to 20 seconds on a full
/// PC, the same for any program), so it says what it is for and how long it takes instead of sitting on a
/// technical line (user feedback: the first step "takes too long").
pub fn record_phase_text(phase: Option<&str>) -> &'static str {
    let Some(phase) = phase else {
        return strings::PHASE_RECORDING;
    };
    if phase.starts_with("harvest: reading roots") {
        strings::PHASE_SNAPSHOT
    } else if phase.starts_with("loading the baseline") || phase.starts_with("baseline view") {
        strings::PHASE_BASELINE
    } else if phase.starts_with("harvest: reading the inventory")
        || phase.contains(" entries; target ")
    {
        strings::PHASE_FINDING
    } else {
        strings::PHASE_RECORDING
    }
}

fn restart_notice() -> UninstallNotice {
    UninstallNotice::new(
        NoticeKind::Info,
        strings::RESTART_TITLE,
        strings::RESTART_MESSAGE,
    )
}

fn exit_detail(exit_code: Option<u32>, quiet: bool) -> String {
    let code = exit_code.map_or_else(|| "unknown".to_owned(), |c| c.to_string());
    format!(
        "Finished, exit code {code}{}",
        if quiet { " · quiet mode" } else { "" }
    )
}

fn counts_text(scan: &ScanResult) -> String {
    let c = &scan.counts;
    format!(
        "{} leftovers ({}) · {} pre-selected",
        c.safe + c.likely + c.weak + c.blocked,
        if scan.mode == ScanMode::Forced {
            "forced"
        } else {
            "post"
        },
        c.preselected
    )
}

fn exit_text(message: &str, exit_code: Option<u32>) -> String {
    match exit_code {
        Some(code) => format!("{message} (exit code {code})"),
        None => message.to_owned(),
    }
}

#[cfg(test)]
mod tests;
