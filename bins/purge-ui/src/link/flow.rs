//! The uninstall flow's half of the link (UI-FLOW): the Uninstall page's pipeline requests, the
//! Leftovers page's calls, the broker launches behind the first-elevation explanation, and the
//! hand-overs of the one broker session between the pages.
//!
//! - **Launches.** Every page that needs the broker asks [`Link::launch_for`]. Before the first
//!   Windows prompt of the run the explanation shows ([`crate::flow::Elevation`]); its "Not now"
//!   answers the page as a declined launch, so its bar does not claim a cancelled prompt. A session
//!   another page holds is ended first when that page is idle (the WinUI app replaced an idle
//!   link too); while that page uses it, the launch is refused with a sentence. With sample data
//!   the session is the [`SampleBroker`], with no prompt at all.
//! - **Hand-overs.** The pipeline's session goes to the Leftovers page with its scan
//!   (`PageRequest::ShowLeftovers { with_broker }`), as the removed-program check's does
//!   (`ProgramsRequest::OpenLeftovers`).

use std::collections::HashMap;
use std::sync::Arc;

use purge_client::{Answer, Broker, ClientError};
use purge_model::ProgramId;
use purge_rpc::methods::{
    CandidateRef, ConsentShown, LeftoversScanParams, NonEmpty, ObservedParams, PipeCall,
    ProgramParams, ProgramsParams, Progress, RestorePoint, RunParams, RunUserParams,
    ScanSessionParams, StdioCall,
};
use purge_ui_model::CallError;
use purge_ui_model::broker_link::BrokerLaunch;
use purge_ui_model::leftovers::{LeftoversCall, LeftoversRequest};
use purge_ui_model::pipeline::{
    LaunchResult, LaunchState, PageRequest, PipelineRequest, StoredScanOutcome,
};
use purge_ui_model::programs::page::BrokerUsers;

use super::{Link, Owner, Pending, failure, no_session};
use crate::flow::Confirm;
use crate::model::{Model, Page};
use crate::sample_broker::{Pace, SampleBroker, SampleProgram};

/// What a flow call in flight is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Call {
    Prepare,
    Route,
    Run,
    RunUser,
    Observed,
    /// The pipeline's own scan.
    Scan,
    /// A scan the Leftovers page asked for (a re-scan).
    LeftoversScan,
    Candidates,
    Explain(CandidateRef),
    Plan,
    Execute,
    Undo,
    RetryHeld,
}

/// What the flow last told the other pages, so each change is told once.
#[derive(Debug, Default)]
pub struct Seen {
    users: BrokerUsers,
    changing: bool,
    /// The page shown when the pump last ran: leaving the Uninstall or the Leftovers page tells
    /// the flow.
    page: Option<Page>,
    /// How fast the sample broker answers (the tests take a quicker one).
    pace: Option<Pace>,
}

impl Link {
    /// Sends what the Uninstall and Leftovers pages asked for and acts on the explanation's
    /// answers. True when anything was done.
    pub(super) fn flow_pump(&mut self, model: &mut Model) -> bool {
        let mut busy = false;
        if let Some(from) = self.flow.page.replace(model.page)
            && from != model.page
        {
            model.flow_left(from);
        }
        for (owner, go) in std::mem::take(&mut model.flow.elevation.answers) {
            busy = true;
            if go {
                self.launch_now(model, owner);
            } else {
                // "Not now": no Windows prompt was shown.
                let declined = LaunchResult {
                    declined_explanation: true,
                    ..LaunchResult::of(LaunchState::Cancelled, "")
                };
                self.on_launched(model, owner, Ok(declined));
            }
        }
        for r in std::mem::take(&mut model.flow.out) {
            busy = true;
            self.page_request(model, r);
        }
        for c in std::mem::take(&mut model.flow.lout) {
            busy = true;
            self.leftovers_call(model, c);
        }
        // The Leftovers page started or ended a change: a held scan may go there now.
        let changing = model.flow.leftovers.is_changing();
        if changing != self.flow.changing {
            self.flow.changing = changing;
            let env = model.flow_env();
            let r = model.flow.page.on_leftovers_changing_changed(env);
            model.flow.take(r);
            busy = true;
        }
        // The Programs page's removed-program check waits while the broker is in use.
        let users = BrokerUsers {
            uninstall_busy: model.flow.page.is_busy(),
            leftovers_changing: changing,
        };
        if users != self.flow.users {
            self.flow.users = users;
            let r = model.programs.page.set_broker_users(users);
            model.programs.take(r);
            busy = true;
        }
        busy
    }

    // ---- launches ----------------------------------------------------------------------------

    /// `owner` needs the broker: the explanation first (once a run), then the launch.
    pub(super) fn launch_for(&mut self, model: &mut Model, owner: Owner) {
        if self.broker.session(owner).is_some() {
            return self.on_launched(model, owner, Ok(LaunchResult::started()));
        }
        if model.flow.elevation.ask(owner) {
            self.launch_now(model, owner);
        }
    }

    /// Whether `owner`'s session may be ended for another page: it runs nothing.
    fn idle(model: &Model, owner: Owner) -> bool {
        match owner {
            Owner::Removed => !model.programs.page.check_running(),
            Owner::Pipeline => !model.flow.page.is_busy(),
            Owner::Leftovers => !model.flow.leftovers.is_changing(),
            // UI-PAGES2: a restore, recovery or purge in flight keeps the session.
            Owner::History => !model.history.page.busy(),
            Owner::Vault => !model.quarantine.page.busy(),
        }
    }

    fn launch_now(&mut self, model: &mut Model, owner: Owner) {
        if let Some(other) = self.broker.holder().filter(|o| *o != owner) {
            if !Self::idle(model, other) {
                let message = format!("The administrator part is in use ({other:?}).");
                return self.on_launched(
                    model,
                    owner,
                    Ok(LaunchResult::of(LaunchState::CannotStart, message)),
                );
            }
            self.broker.close(other);
            self.flow_broker_closed(model, other);
        }
        if !self.live {
            // Sample data: the made-up administrator part, no Windows prompt.
            let programs: HashMap<ProgramId, SampleProgram> = model
                .programs
                .all
                .iter()
                .map(|p| {
                    let program = SampleProgram {
                        name: p.name.clone(),
                        location: p.location.clone(),
                        uninstall: p.uninstall.clone(),
                        quiet: p.quiet,
                    };
                    (p.id.clone(), program)
                })
                .collect();
            let session: Arc<dyn Broker> = Arc::new(SampleBroker::new(
                self.sink.clone(),
                programs,
                self.flow.pace.unwrap_or_default(),
            ));
            self.broker.adopt(owner, session);
            return self.on_launched(model, owner, Ok(LaunchResult::started()));
        }
        if let Err(message) = self.broker.launch(owner, self.sink.clone()) {
            self.on_launched(
                model,
                owner,
                Ok(LaunchResult::of(LaunchState::CannotStart, message)),
            );
        }
    }

    /// How `owner`'s launch ended (`Err(Cancelled)`: Purge stopped it).
    pub(super) fn on_launched(
        &mut self,
        model: &mut Model,
        owner: Owner,
        answer: Result<LaunchResult, CallError>,
    ) {
        match owner {
            Owner::Removed => {
                let pr = &mut model.programs;
                let r = pr.page.on_check_launch(answer);
                pr.take(r);
            }
            Owner::Pipeline => {
                let launch =
                    answer.unwrap_or_else(|_| LaunchResult::of(LaunchState::Cancelled, ""));
                let env = model.flow_env();
                let r = model.flow.page.on_launch(launch, env);
                model.flow.take(r);
            }
            Owner::Leftovers => {
                let launch = match answer {
                    Ok(l) => match l.state {
                        LaunchState::Started => BrokerLaunch::started(),
                        LaunchState::Cancelled if l.declined_explanation => {
                            BrokerLaunch::declined()
                        }
                        LaunchState::Cancelled => BrokerLaunch::cancelled(l.message),
                        _ => BrokerLaunch::failed(l.message),
                    },
                    Err(_) => BrokerLaunch::cancelled(""),
                };
                let r = model.flow.leftovers.on_relaunch(launch);
                model.flow.ltake(r);
            }
            // UI-PAGES2: the History and Quarantine pages (link/pages2.rs).
            Owner::History | Owner::Vault => self.pages_launched(model, owner, answer),
        }
    }

    /// `owner`'s broker link ended.
    pub(super) fn flow_broker_closed(&mut self, model: &mut Model, owner: Owner) {
        if owner == Owner::Leftovers {
            model.flow.leftovers.set_broker_live(false);
        }
        // UI-PAGES2.
        self.pages_broker_closed(model, owner);
    }

    // ---- the Uninstall page -------------------------------------------------------------------

    fn page_request(&mut self, model: &mut Model, request: PageRequest) {
        match request {
            PageRequest::Pipeline(p) => self.pipeline_request(model, p),
            PageRequest::ShowLeftovers {
                outcome,
                navigate,
                with_broker,
            } => {
                let request = LeftoversRequest {
                    program_id: outcome.target.program_id.clone(),
                    program_name: outcome.target.program_name.clone(),
                    session_id: Some(outcome.session_id),
                    scan_id: outcome.scan_id,
                    mode: outcome.mode,
                    restore_point: outcome.restore_point,
                    quiet: outcome.quiet,
                    broker: (with_broker && self.broker.session(Owner::Pipeline).is_some())
                        .then_some(()),
                };
                self.show(model, request, Owner::Pipeline, navigate);
            }
            // The rail and the Leftovers page's lines read the page each time they are drawn.
            PageRequest::HeldScanChanged | PageRequest::BrokerUsersChanged => {}
            PageRequest::NavigateLeftovers => model.page = leftovers_page(model),
            PageRequest::NavigatePrograms => model.page = Page::Programs,
        }
    }

    /// Shows `request` on the Leftovers page with `from`'s session, which that page holds from
    /// then on. A page that applies a change refuses it: the session ends.
    fn show(&mut self, model: &mut Model, request: LeftoversRequest, from: Owner, navigate: bool) {
        let with = request.broker.is_some();
        match model.flow.leftovers.try_show(request) {
            Ok(shown) => {
                if with {
                    if self.broker.holder() == Some(Owner::Leftovers) {
                        // The page's older link is replaced by the scan's.
                        self.broker.close(Owner::Leftovers);
                    }
                    self.broker.hand_over(from, Owner::Leftovers);
                }
                model.flow.closed_bars.clear();
                model.flow.ltake(shown.calls);
                if navigate {
                    model.page = leftovers_page(model);
                }
            }
            Err(_) => self.broker.close(from),
        }
    }

    /// The removed-program check's scan, with its session.
    pub(super) fn show_stored(&mut self, model: &mut Model, outcome: StoredScanOutcome) {
        let request = LeftoversRequest {
            program_id: outcome.program_id,
            program_name: outcome.program_name,
            session_id: None,
            scan_id: outcome.scan.scan_id,
            mode: outcome.scan.mode,
            restore_point: RestorePoint::HighRisk,
            quiet: false,
            broker: self.broker.session(Owner::Removed).is_some().then_some(()),
        };
        self.show(model, request, Owner::Removed, true);
    }

    fn broker_call(&mut self, owner: Owner, call: PipeCall, what: Call) -> bool {
        let Some(session) = self.broker.session(owner).cloned() else {
            return false;
        };
        let id = session.request(call);
        self.pending.insert(id, Pending::Flow(what));
        true
    }

    fn pipeline_request(&mut self, model: &mut Model, request: PipelineRequest) {
        let env = model.flow_env();
        let page = &mut model.flow.page;
        let r = match request {
            PipelineRequest::Launch => return self.launch_for(model, Owner::Pipeline),
            PipelineRequest::Prepare { program_id } => {
                let Some(program_ids) = NonEmpty::new(vec![program_id]) else {
                    return;
                };
                let call = PipeCall::UninstallPrepare(ProgramsParams { program_ids });
                if self.broker_call(Owner::Pipeline, call, Call::Prepare) {
                    return;
                }
                page.on_prepare(Err(no_session()), env)
            }
            PipelineRequest::Route { program_id } => {
                let call = StdioCall::UninstallRoute(ProgramParams { program_id });
                if self.engine_call(call, Pending::Flow(Call::Route)).is_some() {
                    return;
                }
                page.on_route(Err(no_engine()), env)
            }
            PipelineRequest::Confirm(c) => {
                model.flow.confirm = Some(Confirm::new(c));
                return;
            }
            PipelineRequest::Run {
                session_id,
                quiet,
                restore_point,
            } => {
                let call = PipeCall::UninstallRun(RunParams {
                    session_id,
                    quiet,
                    restore_point: Some(restore_point),
                });
                if self.broker_call(Owner::Pipeline, call, Call::Run) {
                    return;
                }
                page.on_run(Err(no_session()), env)
            }
            PipelineRequest::RunUser { program_id, quiet } => {
                let call = StdioCall::UninstallRunUser(RunUserParams { program_id, quiet });
                if self
                    .engine_call(call, Pending::Flow(Call::RunUser))
                    .is_some()
                {
                    return;
                }
                page.on_run_user(Err(no_engine()), env)
            }
            PipelineRequest::Observed {
                session_id,
                outcome,
            } => {
                let call = PipeCall::UninstallObserved(ObservedParams {
                    session_id,
                    outcome,
                });
                if self.broker_call(Owner::Pipeline, call, Call::Observed) {
                    return;
                }
                page.on_observed(Err(no_session()), env)
            }
            PipelineRequest::Scan { session_id, forced } => {
                let call =
                    PipeCall::LeftoversScan(LeftoversScanParams::Session(ScanSessionParams {
                        session_id,
                        forced,
                    }));
                if self.broker_call(Owner::Pipeline, call, Call::Scan) {
                    return;
                }
                page.on_scan(Err(no_session()), env)
            }
            PipelineRequest::CloseBroker => {
                self.broker.close(Owner::Pipeline);
                return;
            }
            // The page shows the bar; the window has nothing to undo.
            PipelineRequest::AdminPromptCancelled { .. } => return,
            PipelineRequest::RunEnded { target, removed } => {
                let pr = &mut model.programs;
                if self.live {
                    let r = pr.page.on_uninstall_run_ended(&target.program_id, removed);
                    pr.take(r);
                } else if removed && let Some(at) = pr.index_of(&target.program_id) {
                    // The sample engine keeps its list: the row is marked removed as the real
                    // list would drop it.
                    pr.pretend_removed(at);
                }
                return;
            }
            // The page hands a completed scan over itself (`ShowLeftovers`).
            PipelineRequest::Completed(_) => return,
        };
        model.flow.take(r);
    }

    // ---- the Leftovers page -------------------------------------------------------------------

    fn leftovers_call(&mut self, model: &mut Model, call: LeftoversCall) {
        let l = &mut model.flow.leftovers;
        let (pipe, what) = match call {
            LeftoversCall::Scan(p) => (PipeCall::LeftoversScan(p), Call::LeftoversScan),
            LeftoversCall::Candidates(p) => (PipeCall::ScanCandidates(p), Call::Candidates),
            LeftoversCall::Explain(p) => {
                let id = p.candidate_id;
                (PipeCall::CandidateExplain(p), Call::Explain(id))
            }
            LeftoversCall::CreatePlan(p) => (PipeCall::PlanCreate(p), Call::Plan),
            LeftoversCall::Execute(p) => (PipeCall::PlanExecute(p), Call::Execute),
            LeftoversCall::Undo(p) => (PipeCall::UndoRun(p), Call::Undo),
            LeftoversCall::RetryHeld(p) => (PipeCall::JournalRetryHeld(p), Call::RetryHeld),
            LeftoversCall::AllowForeground => {
                if let Some(s) = self.broker.session(Owner::Leftovers) {
                    s.allow_foreground();
                }
                return;
            }
            LeftoversCall::Relaunch => {
                l.set_broker_live(false);
                return self.launch_for(model, Owner::Leftovers);
            }
            LeftoversCall::OpenHistory => {
                model.page = Page::History;
                return;
            }
        };
        if !self.broker_call(Owner::Leftovers, pipe, what) {
            // Never sent: the page says the link has ended, never "moved".
            self.flow_reply(
                model,
                what,
                Err(ClientError::Link {
                    reason: "The administrator part is not running.".into(),
                    not_sent: true,
                }),
            );
        }
    }

    // ---- answers ------------------------------------------------------------------------------

    pub(super) fn flow_reply(
        &mut self,
        model: &mut Model,
        what: Call,
        result: Result<Answer, ClientError>,
    ) {
        let env = model.flow_env();
        let page = &mut model.flow.page;
        let l = &mut model.flow.leftovers;
        match (what, result) {
            (Call::Prepare, Ok(Answer::Prepare(p))) => {
                let r = page.on_prepare(Ok(p), env);
                model.flow.take(r);
            }
            (Call::Prepare, r) => {
                let r = page.on_prepare(Err(failure(r)), env);
                model.flow.take(r);
            }
            (Call::Route, Ok(Answer::Route(p))) => {
                let r = page.on_route(Ok(p), env);
                model.flow.take(r);
            }
            (Call::Route, r) => {
                let r = page.on_route(Err(failure(r)), env);
                model.flow.take(r);
            }
            (Call::Run, Ok(Answer::Run(p))) => {
                let r = page.on_run(Ok(p), env);
                model.flow.take(r);
            }
            (Call::Run, r) => {
                let r = page.on_run(Err(failure(r)), env);
                model.flow.take(r);
            }
            (Call::RunUser, Ok(Answer::RunUser(p))) => {
                let r = page.on_run_user(Ok(p), env);
                model.flow.take(r);
            }
            (Call::RunUser, r) => {
                let r = page.on_run_user(Err(failure(r)), env);
                model.flow.take(r);
            }
            (Call::Observed, Ok(Answer::Observed(p))) => {
                let r = page.on_observed(Ok(p), env);
                model.flow.take(r);
            }
            (Call::Observed, r) => {
                let r = page.on_observed(Err(failure(r)), env);
                model.flow.take(r);
            }
            (Call::Scan, Ok(Answer::Scan(p))) => {
                let r = page.on_scan(Ok(p), env);
                model.flow.take(r);
            }
            (Call::Scan, r) => {
                let r = page.on_scan(Err(failure(r)), env);
                model.flow.take(r);
            }
            (Call::LeftoversScan, r) => {
                let r = l.on_scan(match r {
                    Ok(Answer::Scan(s)) => Ok(s),
                    r => Err(failure(r)),
                });
                model.flow.ltake(r);
            }
            (Call::Candidates, r) => {
                let r = l.on_candidates(match r {
                    Ok(Answer::Candidates(c)) => Ok(c),
                    r => Err(failure(r)),
                });
                model.flow.ltake(r);
            }
            (Call::Explain(id), r) => l.on_explain(
                &id,
                match r {
                    Ok(Answer::Explanation(e)) => Ok(e),
                    r => Err(failure(r)),
                },
            ),
            (Call::Plan, r) => {
                let r = l.on_plan_created(match r {
                    Ok(Answer::Plan(p)) => Ok(p),
                    r => Err(failure(r)),
                });
                model.flow.ltake(r);
            }
            (Call::Execute, r) => l.on_executed(match r {
                Ok(Answer::Exec(e)) => Ok(e),
                r => Err(failure(r)),
            }),
            (Call::Undo, r) => {
                let r = l.on_undone(match r {
                    Ok(Answer::Undo(u)) => Ok(u),
                    r => Err(failure(r)),
                });
                model.flow.ltake(r);
            }
            (Call::RetryHeld, r) => l.on_retried(match r {
                Ok(Answer::Outcome(o)) => Ok(o),
                r => Err(failure(r)),
            }),
        }
    }

    pub(super) fn flow_progress(&mut self, model: &mut Model, what: Call, progress: &Progress) {
        match what {
            Call::Prepare | Call::Run | Call::RunUser | Call::Scan => {
                model.flow.page.on_progress(progress)
            }
            Call::LeftoversScan | Call::Execute | Call::Undo => {
                let r = model.flow.leftovers.on_progress(progress);
                model.flow.ltake(r);
            }
            _ => {}
        }
    }

    pub(super) fn flow_consent(&mut self, model: &mut Model, what: Call, shown: &ConsentShown) {
        match what {
            Call::Run => model.flow.page.on_consent_shown(&shown.code.to_string()),
            Call::Execute | Call::Undo | Call::RetryHeld => {
                model.flow.leftovers.on_consent_shown(shown)
            }
            _ => {}
        }
    }
}

/// Where the Leftovers page is drawn: its own page, or inside the flow look's Uninstall page.
fn leftovers_page(model: &Model) -> Page {
    if crate::ui::Look::of(model.prefs.design).flow {
        Page::Pipeline
    } else {
        Page::Leftovers
    }
}

fn no_engine() -> CallError {
    CallError::link("Purge's engine is not running.", true)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use mdshared_ui::keys::Mods;
    use purge_ui_model::leftovers::LeftoversPhase;
    use purge_ui_model::pipeline::page::ConfirmButton;

    use super::*;
    use crate::link::Source;
    use crate::model::tests::sample_programs;
    use crate::prefs::Prefs;

    /// Pumps until `done`, for at most 10 s.
    fn until(link: &mut Link, model: &mut Model, what: &str, done: impl Fn(&Model) -> bool) {
        let t0 = Instant::now();
        while !done(model) {
            assert!(t0.elapsed() < Duration::from_secs(10), "waited for {what}");
            link.pump(model);
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// The sample started, with the made-up broker answering at once, and `name` selected.
    fn started(name: &str) -> (Link, Model) {
        let mut link = Link::new(|| {});
        link.flow.pace = Some(Pace {
            step: Duration::from_millis(5),
            prompt: Duration::from_millis(10),
        });
        let mut model = Model::new(Prefs::default(), sample_programs(), true);
        model.programs = crate::model::Programs::new(crate::model::tests::clock(), |_| false);
        link.start(&Source::Sample { bench_rows: 0 });
        until(&mut link, &mut model, "the sample list", |m| {
            m.programs.loaded
        });
        model.programs.set_query(name);
        model.programs.click(0, Mods::default());
        (link, model)
    }

    #[test]
    fn the_sample_walks_from_the_explanation_to_put_back_all() {
        let (mut link, mut model) = started("firefox");
        assert!(model.ask_uninstall());
        until(&mut link, &mut model, "the explanation", |m| {
            m.flow.elevation.showing() == Some(Owner::Pipeline)
        });
        assert!(
            model.flow.confirm.is_none(),
            "nothing is read before Continue"
        );
        model.flow_elevation(true);
        until(&mut link, &mut model, "the confirmation", |m| {
            m.flow.confirm.is_some()
        });

        // The dialog's command follows its quiet switch (the WinUI dialog kept the quiet one).
        let c = model.flow.confirm.as_ref().unwrap();
        assert!(c.dialog.quiet_enabled && c.quiet_on);
        let quiet = c.command().to_owned();
        assert!(quiet.ends_with(" /S"), "{quiet}");
        model.flow_quiet();
        let c = model.flow.confirm.as_ref().unwrap();
        assert!(!c.quiet_on);
        assert_eq!(format!("{} /S", c.command()), quiet);
        model.flow_quiet();

        model.flow_confirm(ConfirmButton::Uninstall);
        until(&mut link, &mut model, "the review", |m| {
            m.flow.leftovers.phase() == LeftoversPhase::Review
        });
        assert!(!model.flow.page.is_busy());
        let ticked = model.flow.leftovers.selected_count();
        assert!(ticked > 0);
        let r = model.flow.leftovers.click_move();
        model.flow.ltake(r);
        until(&mut link, &mut model, "the result", |m| {
            m.flow.leftovers.phase() == LeftoversPhase::Result
        });
        assert!(
            model
                .flow
                .leftovers
                .result_title_text()
                .contains(&ticked.to_string()),
            "{}",
            model.flow.leftovers.result_title_text()
        );
        let r = model.flow.leftovers.click_undo_all();
        model.flow.ltake(r);
        until(&mut link, &mut model, "put back", |m| {
            m.flow.leftovers.phase() == LeftoversPhase::Undone
        });
        assert!(
            model.flow.elevation.showing().is_none(),
            "explained once: the undo's launch asks nothing"
        );
    }

    #[test]
    fn not_now_on_the_explanation_starts_nothing_and_says_so() {
        let (mut link, mut model) = started("7-zip");
        assert!(model.ask_uninstall());
        until(&mut link, &mut model, "the explanation", |m| {
            m.flow.elevation.showing().is_some()
        });
        model.flow_elevation(false);
        until(&mut link, &mut model, "the bar", |m| {
            !m.flow_bars().is_empty()
        });
        assert!(link.broker.holder().is_none(), "no broker was started");
        assert!(model.flow.confirm.is_none() && !model.flow.page.is_busy());
        assert!(!model.flow.elevation.explained);
    }
}
