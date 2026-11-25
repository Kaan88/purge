//! The Uninstall page (S2; the state logic of `ui/Purge.App/Views/Uninstall/UninstallView.xaml.cs`):
//! the queue of an "Uninstall N" click, the pipeline of the current program, the scan that waits for
//! the Leftovers page, and everything the page shows, as [`UninstallPageView`].
//!
//! The page starts the elevated broker on the Uninstall click (never at app start), asks the confirm
//! dialog ([`ConfirmDialog`]), walks the five-step stepper, and hands the scan to the Leftovers page.

use purge_rpc::methods::{
    ObservedResult, PrepareResult, Progress, RestorePoint, RouteInfo, RunResult, RunUserResult,
    ScanResult,
};

use super::queue::UninstallQueue;
use super::strings;
use super::uninstall::{
    PipelineRequest, StepState, UninstallAnswer, UninstallConfirmation, UninstallController,
    UninstallNotice, UninstallOutcome, UninstallStep,
};
use super::{CallError, LaunchResult, LaunchState, NoticeKind, UninstallTarget};
use crate::casefold::{fold, to_upper_invariant};
use crate::programs::row::tile_for;

/// What the rest of the window tells the page: the other broker users and where the user is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PageEnv {
    /// A removed program's leftovers check runs on the Programs page (one broker at a time).
    pub check_running: bool,
    /// The Leftovers page applies a change: its broker link must not be replaced.
    pub leftovers_changing: bool,
    /// The Leftovers page is on screen.
    pub leftovers_on_screen: bool,
}

/// What the page asks the UI to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageRequest {
    /// A pipeline request: send it (calls) or act on it (`RunEnded`, `AdminPromptCancelled`,
    /// `CloseBroker`). `Completed` never comes through here: the page hands the scan over itself.
    Pipeline(PipelineRequest),
    /// Show `outcome` on the Leftovers page with the pipeline's broker link (the page has let go of it;
    /// `with_broker` is false when it had none), and bring that page on screen when `navigate`.
    ShowLeftovers {
        /// The scan and its ids.
        outcome: UninstallOutcome,
        /// Bring the Leftovers page on screen.
        navigate: bool,
        /// The pipeline had a broker link to hand over.
        with_broker: bool,
    },
    /// The held scan or the queue changed: the Leftovers page's lines follow ([`UninstallPage::held_program`],
    /// [`UninstallPage::queued_next`]).
    HeldScanChanged,
    /// The pipeline started or ended a step: the Programs page's removed-program buttons and the rail's
    /// badges follow ([`UninstallPage::is_busy`]).
    BrokerUsersChanged,
    /// Go to the Leftovers page.
    NavigateLeftovers,
    /// Go to the Programs page.
    NavigatePrograms,
}

/// An action button of a bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarAction {
    /// "Run forced cleanup": [`UninstallPage::force`].
    Force,
    /// "Retry" / "Try again": [`UninstallPage::retry`].
    Retry,
    /// "Start over": [`UninstallPage::start_over`].
    StartOver,
    /// "Show leftovers" on the held scan's bar: [`UninstallPage::show_held`].
    ShowHeld,
    /// "Show leftovers" on the handed scan's bar: [`UninstallPage::show_handed`].
    ShowHanded,
}

/// One button of a bar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarButton {
    /// What it does.
    pub action: BarAction,
    /// Its text (and accessible name).
    pub label: &'static str,
    /// Whether it can be clicked.
    pub enabled: bool,
    /// Why not, when disabled.
    pub tooltip: Option<&'static str>,
}

/// What closing a bar does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarClose {
    /// The bar cannot be closed.
    No,
    /// Closing hides it until the page is drawn again (a pipeline notice).
    Hide,
    /// Closing forgets the handed-scan bar: [`UninstallPage::dismiss_handed`].
    Handed,
    /// Closing forgets the dropped-scan bar: [`UninstallPage::dismiss_dropped`].
    Dropped,
}

/// One bar of the page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bar {
    /// Its severity.
    pub kind: NoticeKind,
    /// The title.
    pub title: String,
    /// The message.
    pub message: String,
    /// Its buttons, in order.
    pub buttons: Vec<BarButton>,
    /// What its close button does.
    pub close: BarClose,
}

/// One row of the stepper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRow {
    /// The step.
    pub step: UninstallStep,
    /// Its title.
    pub title: &'static str,
    /// Its state: the glyph's and (for Warning and Failed) the title's colour.
    pub state: StepState,
    /// The glyph.
    pub glyph: &'static str,
    /// The detail line; `None` hides it.
    pub detail: Option<String>,
}

/// The card of processes that hold the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningCard {
    /// The line.
    pub text: String,
    /// Whether "Retry" ("Check again") can be clicked.
    pub retry_enabled: bool,
    /// Why not.
    pub retry_tooltip: Option<&'static str>,
}

/// The card of the next queued program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextCard {
    /// "Next: Beta (2 of 3)."
    pub text: String,
    /// The detail line.
    pub detail: &'static str,
    /// "Uninstall Beta" (also its accessible name).
    pub button: String,
    /// Whether it can be clicked.
    pub enabled: bool,
    /// Why not.
    pub tooltip: Option<&'static str>,
    /// The Skip button's accessible name: "Skip Beta".
    pub skip_name: String,
}

/// Everything the Uninstall page shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallPageView {
    /// No program was started: the empty card instead of the run grid.
    pub empty: bool,
    /// The subtitle: the program and "2 of 3".
    pub subtitle: String,
    /// The program card's name.
    pub program_name: String,
    /// The program tile's letter.
    pub initial: String,
    /// The program tile's colour: an index into [`crate::programs::row::TILE_COLORS`].
    pub tile: usize,
    /// The route chip's text; [`Self::route_chip`] says whether it shows.
    pub route_text: &'static str,
    /// Whether the route chip shows.
    pub route_chip: bool,
    /// The line under the route.
    pub route_detail: String,
    /// The command that will run; `None` hides it and the signer.
    pub command: Option<String>,
    /// The signer line.
    pub signer: String,
    /// The stepper.
    pub steps: Vec<StepRow>,
    /// The running card.
    pub running: Option<RunningCard>,
    /// Whether the quiet row shows (only for a program with a quiet uninstaller).
    pub quiet_row: bool,
    /// Whether the quiet switch can be toggled.
    pub quiet_enabled: bool,
    /// The quiet switch.
    pub quiet_on: bool,
    /// The note under the quiet row.
    pub quiet_note: &'static str,
    /// The restore-point box's choice.
    pub restore_point: RestorePoint,
    /// Whether the restore-point box can be changed.
    pub restore_enabled: bool,
    /// The tooltip of both choices while a check runs.
    pub choices_tooltip: Option<&'static str>,
    /// The bars, in order.
    pub bars: Vec<Bar>,
    /// The next queued program.
    pub next: Option<NextCard>,
    /// The footer line.
    pub footer: &'static str,
}

/// The confirm dialog's content, from an [`UninstallConfirmation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmDialog {
    /// The request it answers.
    pub confirmation: UninstallConfirmation,
    /// "Uninstall App?"
    pub title: String,
    /// "1. Record what the program registered", ...
    pub steps: Vec<String>,
    /// The signer line.
    pub signer: String,
    /// The running processes line, when some run (then "Check again" shows).
    pub still_running: Option<String>,
    /// The quiet row's text.
    pub quiet_label: &'static str,
    /// The quiet switch's start position.
    pub quiet_on: bool,
    /// Whether the quiet switch can be toggled.
    pub quiet_enabled: bool,
    /// The line under the quiet row.
    pub quiet_line: String,
    /// The restore-point box's start choice.
    pub restore_point: RestorePoint,
    /// Whether the dialog has the "Check again" button.
    pub check_again: bool,
}

/// The button the confirm dialog was closed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmButton {
    /// "Uninstall".
    Uninstall,
    /// "Check again".
    CheckAgain,
    /// "Not now", Esc, or a dialog that could not be shown.
    NotNow,
}

impl ConfirmDialog {
    /// The dialog for `confirmation`.
    pub fn new(confirmation: UninstallConfirmation) -> Self {
        let names = distinct_names(confirmation.running.iter().map(|p| p.name.as_str()));
        Self {
            title: strings::confirm_title(&confirmation.target.program_name),
            steps: confirmation
                .steps
                .iter()
                .enumerate()
                .map(|(i, s)| format!("{}. {s}", i + 1))
                .collect(),
            signer: strings::signer_text(confirmation.signer.as_deref()),
            still_running: (!confirmation.running.is_empty())
                .then(|| strings::confirm::still_running(&names)),
            quiet_label: if confirmation.quiet_available {
                strings::confirm::USE_QUIET
            } else {
                strings::confirm::NO_QUIET
            },
            quiet_on: confirmation.quiet_available && confirmation.quiet,
            quiet_enabled: confirmation.quiet_available,
            quiet_line: match &confirmation.quiet_command {
                None => strings::confirm::OWN_DIALOGS.into(),
                Some(q) => strings::confirm::quiet_command(q),
            },
            restore_point: confirmation.restore_point,
            check_again: !confirmation.running.is_empty(),
            confirmation,
        }
    }

    /// The command line for the quiet switch's position: the quiet command when on, the
    /// interactive one when off (the WinUI dialog showed the quiet one in both positions). It
    /// never shows the quiet command with the switch off: when the interactive command is not
    /// known, it says so ([`strings::confirm::COMMAND_NOT_KNOWN`]).
    pub fn command_for(&self, quiet_on: bool) -> &str {
        let c = &self.confirmation;
        match &c.quiet_command {
            Some(q) if quiet_on && c.quiet_available && !q.is_empty() => q,
            _ if !c.interactive_command.is_empty() => &c.interactive_command,
            // `command` is the selected one, which is the quiet one when the quiet switch was on
            // at the record step: only a program without a quiet command may show it here.
            _ if !c.command.is_empty() && c.quiet_command.as_deref() != Some(c.command.as_str()) => {
                &c.command
            }
            _ => strings::confirm::COMMAND_NOT_KNOWN,
        }
    }

    /// The answer for the button the dialog closed with and its controls' last positions.
    pub fn answer(
        &self,
        button: ConfirmButton,
        quiet_on: bool,
        restore_point: RestorePoint,
    ) -> UninstallAnswer {
        match button {
            ConfirmButton::CheckAgain => UninstallAnswer::recheck(quiet_on, restore_point),
            ConfirmButton::Uninstall => UninstallAnswer::new(
                true,
                quiet_on && self.confirmation.quiet_available,
                restore_point,
            ),
            ConfirmButton::NotNow => UninstallAnswer::new(
                false,
                quiet_on && self.confirmation.quiet_available,
                restore_point,
            ),
        }
    }
}

/// The Uninstall page's model.
#[derive(Debug, Clone, Default)]
pub struct UninstallPage {
    controller: UninstallController,
    queue: UninstallQueue,
    // A scan that could not go to the Leftovers page because that page was applying another change. The
    // controller keeps its broker meanwhile; the hand-off is tried again when that change ends, when the
    // user leaves the Leftovers page, and by "Show leftovers".
    held: Option<UninstallOutcome>,
    // The program whose held scan a new run closed, for a bar that says so; `dropped_rerun`: the same
    // program's uninstall ran again, not a new one.
    dropped_held: Option<String>,
    dropped_rerun: bool,
    // A held scan handed to the Leftovers page while the user was on another page: the bar says where it
    // went. `None` once that scan is no longer the pipeline's.
    handed_quietly: Option<UninstallOutcome>,
    was_busy: bool,
}

impl UninstallPage {
    /// A page with nothing started.
    pub fn new() -> Self {
        Self::default()
    }

    /// The pipeline.
    pub fn controller(&self) -> &UninstallController {
        &self.controller
    }

    /// The queue.
    pub fn queue(&self) -> &UninstallQueue {
        &self.queue
    }

    /// True while the pipeline runs a step (the Programs page's removed-program check waits meanwhile).
    pub fn is_busy(&self) -> bool {
        self.controller.is_busy()
    }

    /// The program whose scan waits for the Leftovers page, for that page's line; `None` when none waits.
    pub fn held_program(&self) -> Option<String> {
        self.held.as_ref().map(name_of)
    }

    /// The program the queue names after the current one, for the Leftovers page's line; `None` when none.
    pub fn queued_next(&self) -> Option<String> {
        let next = self.queue.next()?;
        if self.controller.is_busy() {
            return None;
        }
        let name = if next.program_name.is_empty() {
            strings::THE_NEXT_PROGRAM_CAP
        } else {
            &next.program_name
        };
        Some(format!(
            "{name} ({} of {})",
            self.queue.position() + 1,
            self.queue.count()
        ))
    }

    // ---- actions ----------------------------------------------------------------------------------

    /// Starts the pipeline for the programs ticked on the Programs page, one after another: the first
    /// now, each next one when the user asks for it ("Uninstall next" or "Skip"). Ignored while a step runs.
    pub fn begin(
        &mut self,
        targets: impl IntoIterator<Item = UninstallTarget>,
        env: PageEnv,
    ) -> Vec<PageRequest> {
        if self.controller.is_busy() {
            return vec![];
        }
        let Some(first) = self.queue.start(targets).cloned() else {
            return vec![];
        };
        self.start_queued(first, env)
    }

    fn start_queued(&mut self, target: UninstallTarget, env: PageEnv) -> Vec<PageRequest> {
        let requests = self.controller.begin(target);
        let mut out = self.pipeline(requests, env);
        out.push(PageRequest::HeldScanChanged);
        self.sync(&mut out);
        out
    }

    /// "Uninstall next".
    pub fn uninstall_next(&mut self, env: PageEnv) -> Vec<PageRequest> {
        if self.why_not_next(env).is_some() {
            return vec![];
        }
        match self.queue.advance().cloned() {
            Some(next) => self.start_queued(next, env),
            None => vec![],
        }
    }

    /// "Skip" of the Next card.
    pub fn skip_next(&mut self) -> Vec<PageRequest> {
        self.queue.skip_next();
        vec![PageRequest::HeldScanChanged]
    }

    /// A bar's "Retry" / "Try again". Waits while a removed program's check has the broker.
    pub fn retry(&mut self, env: PageEnv) -> Vec<PageRequest> {
        if env.check_running {
            return vec![];
        }
        let requests = self.controller.retry();
        self.after(requests, env)
    }

    /// A bar's "Run forced cleanup".
    pub fn force(&mut self, env: PageEnv) -> Vec<PageRequest> {
        if env.check_running {
            return vec![];
        }
        let requests = self.controller.force();
        self.after(requests, env)
    }

    /// A bar's "Start over".
    pub fn start_over(&mut self, env: PageEnv) -> Vec<PageRequest> {
        if env.check_running {
            return vec![];
        }
        let requests = self.controller.start_over();
        self.after(requests, env)
    }

    /// The running card's "Check again".
    pub fn recheck(&mut self, env: PageEnv) -> Vec<PageRequest> {
        if env.check_running {
            return vec![];
        }
        let requests = self.controller.recheck();
        self.after(requests, env)
    }

    /// The quiet switch.
    pub fn set_quiet(&mut self, quiet: bool) {
        let restore = self.controller.restore_point();
        self.controller.set_choice(quiet, restore);
    }

    /// The restore-point box.
    pub fn set_restore_point(&mut self, restore_point: RestorePoint) {
        let quiet = self.controller.quiet();
        self.controller.set_choice(quiet, restore_point);
    }

    /// The confirm dialog closed ([`ConfirmDialog::answer`]).
    pub fn answer(&mut self, answer: UninstallAnswer, env: PageEnv) -> Vec<PageRequest> {
        let requests = self.controller.answer(answer);
        self.after(requests, env)
    }

    /// "Show leftovers" on the held scan's bar, or "Show the scan" on the Leftovers page: the held scan
    /// replaces what that page shows.
    pub fn show_held(&mut self, env: PageEnv) -> Vec<PageRequest> {
        let mut out = vec![];
        if let Some(held) = self.held.clone()
            && !self.controller.is_busy()
        {
            self.hand_off(held, true, env, &mut out);
        }
        self.sync(&mut out);
        out
    }

    /// "Show leftovers" on the handed scan's bar.
    pub fn show_handed(&mut self) -> Vec<PageRequest> {
        self.handed_quietly = None;
        vec![PageRequest::NavigateLeftovers]
    }

    /// The handed scan's bar was closed.
    pub fn dismiss_handed(&mut self) {
        self.handed_quietly = None;
    }

    /// The dropped scan's bar was closed.
    pub fn dismiss_dropped(&mut self) {
        self.dropped_held = None;
    }

    /// "Open Programs" on the empty card.
    pub fn open_programs(&self) -> Vec<PageRequest> {
        vec![PageRequest::NavigatePrograms]
    }

    /// The Leftovers page started or finished a change. A held scan goes there once it has finished,
    /// unless that page is on screen: then its outcome is being read, and the scan waits until the user
    /// leaves the page ([`Self::on_leftovers_left`]) or asks for it.
    pub fn on_leftovers_changing_changed(&mut self, env: PageEnv) -> Vec<PageRequest> {
        self.try_hand_off_held(true, env)
    }

    /// The user left the Leftovers page: a held scan goes there now, without taking the user back; the
    /// bar on this page says where it went.
    pub fn on_leftovers_left(&mut self, env: PageEnv) -> Vec<PageRequest> {
        self.try_hand_off_held(false, env)
    }

    /// The page goes away: ends the broker unless it was handed over.
    pub fn close(&mut self) -> Vec<PageRequest> {
        self.controller
            .close()
            .into_iter()
            .map(PageRequest::Pipeline)
            .collect()
    }

    // ---- answers ----------------------------------------------------------------------------------

    /// See [`UninstallController::on_launch`].
    pub fn on_launch(&mut self, launch: LaunchResult, env: PageEnv) -> Vec<PageRequest> {
        let requests = self.controller.on_launch(launch);
        self.after(requests, env)
    }

    /// The window ended this page's broker session: see [`UninstallController::on_broker_ended`].
    pub fn on_broker_ended(&mut self) {
        self.controller.on_broker_ended();
    }

    /// See [`UninstallController::on_run_user_without_broker`].
    pub fn on_run_user_without_broker(&mut self, env: PageEnv) -> Vec<PageRequest> {
        let requests = self.controller.on_run_user_without_broker();
        self.after(requests, env)
    }

    /// The run still needs its broker session although no step runs: a prepared record waits
    /// for the confirmation's answer, a failed run can still be cleaned up by force, or a scan
    /// waits for the Leftovers page. Ending the session for another page loses that work.
    pub fn holds_broker_work(&self) -> bool {
        self.controller.has_broker()
    }

    /// See [`UninstallController::on_progress`].
    pub fn on_progress(&mut self, progress: &Progress) {
        self.controller.on_progress(progress);
    }

    /// See [`UninstallController::on_consent_shown`].
    pub fn on_consent_shown(&mut self, code: &str) {
        self.controller.on_consent_shown(code);
    }

    /// See [`UninstallController::on_prepare`].
    pub fn on_prepare(
        &mut self,
        result: Result<PrepareResult, CallError>,
        env: PageEnv,
    ) -> Vec<PageRequest> {
        let requests = self.controller.on_prepare(result);
        self.after(requests, env)
    }

    /// See [`UninstallController::on_route`].
    pub fn on_route(
        &mut self,
        result: Result<RouteInfo, CallError>,
        env: PageEnv,
    ) -> Vec<PageRequest> {
        let requests = self.controller.on_route(result);
        self.after(requests, env)
    }

    /// See [`UninstallController::on_run`].
    pub fn on_run(
        &mut self,
        result: Result<RunResult, CallError>,
        env: PageEnv,
    ) -> Vec<PageRequest> {
        let requests = self.controller.on_run(result);
        self.after(requests, env)
    }

    /// See [`UninstallController::on_run_user`].
    pub fn on_run_user(
        &mut self,
        result: Result<RunUserResult, CallError>,
        env: PageEnv,
    ) -> Vec<PageRequest> {
        let requests = self.controller.on_run_user(result);
        self.after(requests, env)
    }

    /// See [`UninstallController::on_observed`].
    pub fn on_observed(
        &mut self,
        result: Result<ObservedResult, CallError>,
        env: PageEnv,
    ) -> Vec<PageRequest> {
        let requests = self.controller.on_observed(result);
        self.after(requests, env)
    }

    /// See [`UninstallController::on_scan`].
    pub fn on_scan(
        &mut self,
        result: Result<ScanResult, CallError>,
        env: PageEnv,
    ) -> Vec<PageRequest> {
        let requests = self.controller.on_scan(result);
        self.after(requests, env)
    }

    // ---- the hand-off -----------------------------------------------------------------------------

    fn after(&mut self, requests: Vec<PipelineRequest>, env: PageEnv) -> Vec<PageRequest> {
        let mut out = self.pipeline(requests, env);
        self.sync(&mut out);
        out
    }

    /// Passes the pipeline's requests on; a completed scan is handed off here.
    fn pipeline(&mut self, requests: Vec<PipelineRequest>, env: PageEnv) -> Vec<PageRequest> {
        let mut out = vec![];
        for request in requests {
            match request {
                PipelineRequest::Completed(outcome) => self.hand_off(outcome, true, env, &mut out),
                other => out.push(PageRequest::Pipeline(other)),
            }
        }
        out
    }

    fn try_hand_off_held(&mut self, navigate: bool, env: PageEnv) -> Vec<PageRequest> {
        let mut out = vec![];
        // Never while the pipeline runs a step: it may be using the broker the held scan would take with it.
        if let Some(held) = self.held.clone()
            && !self.controller.is_busy()
            && !env.leftovers_changing
            && !env.leftovers_on_screen
        {
            self.hand_off(held, navigate, env, &mut out);
        }
        self.sync(&mut out);
        out
    }

    /// Hands the scan and the live broker to the Leftovers page (and shows that page when `navigate`).
    /// While that page applies another change its link must not be replaced, so the scan waits here (the
    /// controller keeps the broker) behind a "Show leftovers" bar.
    fn hand_off(
        &mut self,
        outcome: UninstallOutcome,
        navigate: bool,
        env: PageEnv,
        out: &mut Vec<PageRequest>,
    ) {
        if self.controller.completed_outcome() != Some(&outcome) {
            // The pipeline started again meanwhile: this scan is no longer the one on the page.
            if let Some(held) = self.held.clone() {
                self.drop_held(&held, out);
            }
            return;
        }
        // A newer scan is in: the bar about an older one that was closed has said what it had to.
        self.dropped_held = None;
        self.handed_quietly = None;
        if env.leftovers_changing {
            self.set_held(Some(outcome), out);
            return;
        }
        self.set_held(None, out);
        let with_broker = self.controller.take_broker();
        if !navigate {
            self.handed_quietly = Some(outcome.clone());
        }
        out.push(PageRequest::ShowLeftovers {
            outcome,
            navigate,
            with_broker,
        });
    }

    fn set_held(&mut self, outcome: Option<UninstallOutcome>, out: &mut Vec<PageRequest>) {
        if self.held == outcome {
            return;
        }
        self.held = outcome;
        out.push(PageRequest::HeldScanChanged);
    }

    /// Forgets a held scan the pipeline no longer has and keeps a bar that says so.
    fn drop_held(&mut self, held: &UninstallOutcome, out: &mut Vec<PageRequest>) {
        self.set_held(None, out);
        self.dropped_held = Some(name_of(held));
        self.dropped_rerun = self
            .controller
            .target()
            .is_some_and(|t| t.program_id == held.target.program_id);
    }

    /// What the WinUI page did on every draw: a held or handed scan the pipeline no longer has is gone,
    /// and a change of "busy" is told to the window.
    fn sync(&mut self, out: &mut Vec<PageRequest>) {
        // The pipeline ran again or started anew while a scan waited (it cleared or replaced its
        // outcome): that scan is gone, so say so.
        if let Some(held) = self.held.clone()
            && self.controller.completed_outcome() != Some(&held)
        {
            self.drop_held(&held, out);
        }
        if self
            .handed_quietly
            .as_ref()
            .is_some_and(|h| self.controller.completed_outcome() != Some(h))
        {
            self.handed_quietly = None;
        }
        let busy = self.controller.is_busy();
        if busy != self.was_busy {
            self.was_busy = busy;
            out.push(PageRequest::HeldScanChanged);
            out.push(PageRequest::BrokerUsersChanged);
        }
    }

    /// Why the next queued program may not start yet; `None` when it may.
    pub fn why_not_next(&self, env: PageEnv) -> Option<&'static str> {
        if self.controller.is_busy() {
            Some(strings::NEXT_WAITS_STEP)
        } else if env.check_running {
            Some(strings::CHECK_RUNNING_HINT)
        } else if env.leftovers_changing {
            Some(strings::NEXT_WAITS_LEFTOVERS)
        } else if self.held.is_some() {
            Some(strings::NEXT_WAITS_HELD)
        } else {
            None
        }
    }

    // ---- the view ---------------------------------------------------------------------------------

    /// Everything the page shows now.
    pub fn view(&self, env: PageEnv) -> UninstallPageView {
        let c = &self.controller;
        let name = c.target().map(|t| t.program_name.as_str()).unwrap_or("");
        let has_target = c.target().is_some();
        let mut subtitle = if name.is_empty() {
            strings::NOTHING_RUNNING.to_owned()
        } else {
            name.to_owned()
        };
        if has_target && let Some(position) = self.queue.position_text() {
            subtitle.push_str(" · ");
            subtitle.push_str(&position);
        }
        let route_detail = if !has_target {
            strings::ROUTE_PICK.to_owned()
        } else if let Some(route) = c.route_text() {
            strings::route_detail(route, c.state_of(UninstallStep::Run) != StepState::Pending)
        } else if c.launch_state() == Some(LaunchState::Cancelled) {
            strings::ROUTE_NOT_GIVEN.to_owned()
        } else if c.is_busy() {
            if c.launch_state().is_none() {
                strings::ROUTE_ASKING.to_owned()
            } else {
                strings::ROUTE_RECORDING.to_owned()
            }
        } else {
            strings::ROUTE_NOT_STARTED.to_owned()
        };
        let hint = env.check_running.then_some(strings::CHECK_RUNNING_HINT);
        UninstallPageView {
            empty: !has_target,
            subtitle,
            program_name: if name.is_empty() {
                strings::NO_PROGRAM_SELECTED.to_owned()
            } else {
                name.to_owned()
            },
            initial: name
                .chars()
                .next()
                .map_or_else(|| "?".to_owned(), |ch| fold(ch).to_string()),
            tile: tile_for(name),
            route_text: c.route_text().unwrap_or(strings::ROUTE_WAITING),
            route_chip: c.route_text().is_some(),
            route_detail,
            command: c.selected_command().map(str::to_owned),
            signer: strings::signer_text(c.signer()),
            steps: self.steps(),
            running: self.running_card(env),
            quiet_row: c.quiet_available(),
            quiet_enabled: c.quiet_available() && !c.is_busy() && !env.check_running,
            quiet_on: c.quiet(),
            quiet_note: if c.command().is_none() {
                strings::QUIET_NOTE_UNKNOWN
            } else if c.quiet_available() {
                strings::QUIET_NOTE_AVAILABLE
            } else {
                strings::QUIET_NOTE_NONE
            },
            restore_point: c.restore_point(),
            restore_enabled: !c.is_busy() && !env.check_running,
            choices_tooltip: hint,
            bars: self.bars(env),
            next: self.next_card(env),
            footer: if !has_target {
                c.guide_text()
            } else if c.current_step() == UninstallStep::Ready {
                strings::FOOTER_READY
            } else {
                strings::FOOTER_RUNNING
            },
        }
    }

    fn steps(&self) -> Vec<StepRow> {
        UninstallStep::ALL
            .iter()
            .zip(strings::STEP_TITLES)
            .map(|(&step, title)| {
                let state = self.controller.state_of(step);
                StepRow {
                    step,
                    title,
                    state,
                    glyph: match state {
                        StepState::Done => strings::GLYPH_DONE,
                        StepState::Active => strings::GLYPH_ACTIVE,
                        StepState::Warning => strings::GLYPH_WARNING,
                        StepState::Failed => strings::GLYPH_FAILED,
                        StepState::Pending => strings::GLYPH_PENDING,
                    },
                    detail: self
                        .controller
                        .detail_of(step)
                        .filter(|d| !d.is_empty())
                        .map(str::to_owned),
                }
            })
            .collect()
    }

    fn running_card(&self, env: PageEnv) -> Option<RunningCard> {
        let running = self.controller.running();
        if running.is_empty() {
            return None;
        }
        let names = distinct_names(running.iter().map(|p| p.name.as_str()));
        Some(RunningCard {
            text: strings::running_text(&names, running.len()),
            retry_enabled: !self.controller.is_busy() && !env.check_running,
            retry_tooltip: env.check_running.then_some(strings::CHECK_RUNNING_HINT),
        })
    }

    fn bars(&self, env: PageEnv) -> Vec<Bar> {
        let mut bars: Vec<Bar> = self
            .controller
            .notices()
            .iter()
            .map(|n| notice_bar(n, env))
            .collect();
        // The disabled actions' tooltips do not show (a disabled control gets no pointer events), so say it
        // in a line.
        if env.check_running && self.controller.target().is_some() {
            bars.push(Bar {
                kind: NoticeKind::Info,
                title: strings::WAITING_FOR_CHECK_TITLE.into(),
                message: strings::CHECK_RUNNING_HINT.into(),
                buttons: vec![],
                close: BarClose::No,
            });
        }
        if self.held.is_some() {
            // The broker ends after ten minutes without a request (bins/purge-broker/src/lifetime.rs,
            // IDLE_LIMIT), and the held scan with it.
            bars.push(Bar {
                kind: NoticeKind::Warning,
                title: strings::HELD_TITLE.into(),
                message: strings::held_message(env.leftovers_changing),
                buttons: vec![BarButton {
                    action: BarAction::ShowHeld,
                    label: strings::ACTION_SHOW_LEFTOVERS,
                    enabled: !env.leftovers_changing && !self.controller.is_busy(),
                    tooltip: None,
                }],
                close: BarClose::No,
            });
        }
        if let Some(handed) = &self.handed_quietly {
            bars.push(Bar {
                kind: NoticeKind::Info,
                title: strings::HANDED_TITLE.into(),
                message: strings::handed_message(&name_of(handed)),
                buttons: vec![BarButton {
                    action: BarAction::ShowHanded,
                    label: strings::ACTION_SHOW_LEFTOVERS,
                    enabled: true,
                    tooltip: None,
                }],
                close: BarClose::Handed,
            });
        }
        if let Some(dropped) = &self.dropped_held {
            bars.push(Bar {
                kind: NoticeKind::Info,
                title: strings::DROPPED_TITLE.into(),
                message: strings::dropped_message(dropped, self.dropped_rerun),
                buttons: vec![],
                close: BarClose::Dropped,
            });
        }
        bars
    }

    fn next_card(&self, env: PageEnv) -> Option<NextCard> {
        let next = self.queue.next()?;
        if self.controller.is_busy() {
            return None;
        }
        let name = if next.program_name.is_empty() {
            strings::THE_NEXT_PROGRAM
        } else {
            &next.program_name
        };
        let why = self.why_not_next(env);
        Some(NextCard {
            text: strings::next_text(name, self.queue.position() + 1, self.queue.count()),
            detail: strings::NEXT_DETAIL,
            button: format!("Uninstall {name}"),
            enabled: why.is_none(),
            tooltip: why,
            skip_name: format!("Skip {name}"),
        })
    }
}

/// A pipeline notice as a bar: its actions can start the broker, so they wait while a removed program's
/// check has one.
fn notice_bar(notice: &UninstallNotice, env: PageEnv) -> Bar {
    let button = |action, label| BarButton {
        action,
        label,
        enabled: !env.check_running,
        tooltip: env.check_running.then_some(strings::CHECK_RUNNING_HINT),
    };
    let mut buttons = vec![];
    if notice.can_force {
        buttons.push(button(BarAction::Force, strings::ACTION_FORCE));
    }
    if notice.can_retry {
        // An informational bar's retry is a declined or cancelled admin prompt: nothing failed.
        buttons.push(button(
            BarAction::Retry,
            if notice.kind == NoticeKind::Info {
                strings::ACTION_TRY_AGAIN
            } else {
                strings::ACTION_RETRY
            },
        ));
    }
    if notice.can_start_over {
        buttons.push(button(BarAction::StartOver, strings::ACTION_START_OVER));
    }
    Bar {
        kind: notice.kind,
        title: notice.title.clone(),
        message: notice.message.clone(),
        buttons,
        close: BarClose::Hide,
    }
}

fn name_of(outcome: &UninstallOutcome) -> String {
    if outcome.target.program_name.is_empty() {
        strings::THE_LAST_PROGRAM.into()
    } else {
        outcome.target.program_name.clone()
    }
}

/// The non-empty names, each once (not case sensitive), in order.
fn distinct_names<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    names
        .filter(|n| !n.is_empty())
        .filter(|n| seen.insert(to_upper_invariant(n)))
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests;
