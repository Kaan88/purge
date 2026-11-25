//! A scripted broker, medium engine and launcher for the pipeline tests: the Rust form of the
//! `ScriptedBroker`/`ScriptedMedium` of `UninstallPageTests.cs`. It answers each request the models send,
//! as the UI would, and counts what was asked.

use std::collections::VecDeque;

use purge_model::{ProgramId, RunOutcome};
use purge_rpc::error::ErrorObject;
use purge_rpc::methods::{
    ObservedResult, PrepareResult, Prepared, RestorePoint, Route, RouteInfo, RunResult,
    RunUserResult, ScanResult,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::page::{PageEnv, PageRequest, UninstallPage};
use super::uninstall::{
    PipelineRequest, UninstallConfirmation, UninstallController, UninstallOutcome,
};
use super::{CallError, LaunchResult, UninstallTarget};

pub const PROGRAM: &str = "HKLM|64|App_is1";
pub const COMMAND: &str = r#""C:\Program Files\App\unins000.exe""#;
pub const QUIET: &str = r#""C:\Program Files\App\unins000.exe" /S"#;

pub fn id(s: &str) -> ProgramId {
    s.parse().expect("a program id")
}

pub fn target() -> UninstallTarget {
    UninstallTarget::new(id(PROGRAM), "App")
}

pub fn wire<T: DeserializeOwned>(v: Value) -> T {
    serde_json::from_value(v).expect("a wire value")
}

/// A fixture of `crates/purge-rpc/fixtures`.
pub fn fixture<T: DeserializeOwned>(stem: &str) -> T {
    let path = format!(
        "{}/../purge-rpc/fixtures/{stem}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).expect("the fixture");
    serde_json::from_str(&text).expect("the fixture's shape")
}

/// A server error with `error.data`.
pub fn rpc_error(data: Value) -> CallError {
    let kind = data["kind"].as_str().unwrap_or_default().to_owned();
    CallError::Rpc(wire::<ErrorObject>(
        json!({ "code": -32000, "message": kind, "data": data }),
    ))
}

pub fn route_name(route: Route) -> &'static str {
    match route {
        Route::Broker => "broker",
        Route::Medium => "medium",
    }
}

pub fn prepared_for(route: Route, quiet: Option<&str>) -> Prepared {
    wire(json!({
        "program_id": PROGRAM,
        "session_id": "u-1122334455667788",
        "route": route_name(route),
        "command": COMMAND,
        "quiet_command": quiet,
        "signer": "App Signer",
        "running": [],
        "fingerprint_summary": { "roots": 1, "files": 2, "registry": 3, "objects": 0 },
        "warnings": [],
        "co_products": [],
    }))
}

pub fn route_of(route: Route, command: &str, quiet: Option<&str>) -> RouteInfo {
    wire(json!({
        "route": route_name(route),
        "command": command,
        "quiet_command": quiet,
        "signer": "App Signer",
        "running": [],
    }))
}

pub fn run_result(exit_code: u32, outcome: &str, gone: bool, arp_gone: bool) -> RunResult {
    wire(json!({
        "exit_code": exit_code,
        "outcome": outcome,
        "verify_gone": {
            "arp_gone": arp_gone,
            "main_exes_gone": gone,
            "msi_unknown_all_ctx": true,
            "passed": gone,
        },
    }))
}

pub fn run_user(exit_code: u32, outcome: &str) -> RunUserResult {
    wire(json!({ "exit_code": exit_code, "outcome": outcome }))
}

fn scan(forced: bool) -> ScanResult {
    wire(json!({
        "scan_id": "s-0123456789abcdef",
        "mode": if forced { "forced" } else { "post" },
        "baseline_trust": "Exact",
        "counts": { "safe": 3, "likely": 1, "weak": 0, "blocked": 0, "preselected": 3 },
        "warnings": [],
    }))
}

/// The scripted broker.
pub struct Broker {
    pub prepared: Prepared,
    pub run: RunResult,
    pub run_error: Option<CallError>,
    pub first_run_error: Option<CallError>,
    /// `uninstall.run` does not answer until [`Rig::release_run`]: the broker's dialog is open.
    pub hold_run: bool,
    pub prepare_calls: usize,
    pub run_calls: usize,
    pub run_quiet: bool,
    pub run_restore_point: Option<RestorePoint>,
    pub observed_calls: usize,
    pub observed_outcome: Option<RunOutcome>,
    pub scan_calls: usize,
    pub scan_forced: bool,
    pub observed_before_scan: bool,
    pub closed: usize,
}

impl Broker {
    pub fn new(prepared: Prepared) -> Self {
        Self {
            prepared,
            run: run_result(0, "Success", true, true),
            run_error: None,
            first_run_error: None,
            hold_run: false,
            prepare_calls: 0,
            run_calls: 0,
            run_quiet: false,
            run_restore_point: None,
            observed_calls: 0,
            observed_outcome: None,
            scan_calls: 0,
            scan_forced: false,
            observed_before_scan: false,
            closed: 0,
        }
    }

    pub fn command_for(&self, quiet: bool) -> &str {
        match (&self.prepared.quiet_command, quiet) {
            (Some(q), true) => q,
            _ => &self.prepared.command,
        }
    }
}

/// The scripted medium engine.
pub struct Medium {
    pub route: RouteInfo,
    pub run: RunUserResult,
    pub run_error: Option<CallError>,
    pub route_calls: usize,
    pub run_calls: usize,
    pub run_quiet: bool,
}

impl Medium {
    pub fn new() -> Self {
        Self::with(route_of(Route::Medium, COMMAND, Some(QUIET)))
    }

    pub fn with(route: RouteInfo) -> Self {
        Self {
            route,
            run: run_user(0, "Success"),
            run_error: None,
            route_calls: 0,
            run_calls: 0,
            run_quiet: false,
        }
    }

    pub fn command_for(&self, quiet: bool) -> &str {
        match (&self.route.quiet_command, quiet) {
            (Some(q), true) => q,
            _ => &self.route.command,
        }
    }
}

/// The UI around a controller or a page: it answers each request from the scripts.
pub struct Rig {
    pub broker: Broker,
    pub medium: Medium,
    pub launch: LaunchResult,
    pub launches: usize,
    pub confirmations: VecDeque<UninstallConfirmation>,
    pub completed: Vec<UninstallOutcome>,
    pub ended: Vec<(UninstallTarget, bool)>,
    pub declined: Option<bool>,
    pub shown: Vec<(UninstallOutcome, bool, bool)>,
    pub page_requests: Vec<PageRequest>,
    held_run: bool,
}

/// What the scripts answer to one request.
enum Answer {
    Launch(LaunchResult),
    Prepare(Result<PrepareResult, CallError>),
    Route(Result<RouteInfo, CallError>),
    Run(Result<RunResult, CallError>),
    RunUser(Result<RunUserResult, CallError>),
    Observed(Result<ObservedResult, CallError>),
    Scan(Result<ScanResult, CallError>),
}

impl Rig {
    pub fn new(broker: Broker, medium: Medium) -> Self {
        Self::launching(LaunchResult::started(), broker, medium)
    }

    pub fn launching(launch: LaunchResult, broker: Broker, medium: Medium) -> Self {
        Self {
            broker,
            medium,
            launch,
            launches: 0,
            confirmations: VecDeque::new(),
            completed: vec![],
            ended: vec![],
            declined: None,
            shown: vec![],
            page_requests: vec![],
            held_run: false,
        }
    }

    /// The scripts' answer, or `None` for a request the UI acts on itself (recorded here).
    fn answer(&mut self, request: &PipelineRequest) -> Option<Answer> {
        Some(match request {
            PipelineRequest::Launch => {
                self.launches += 1;
                Answer::Launch(self.launch.clone())
            }
            PipelineRequest::Prepare { .. } => {
                self.broker.prepare_calls += 1;
                Answer::Prepare(Ok(PrepareResult {
                    programs: vec![self.broker.prepared.clone()],
                    timings: None,
                }))
            }
            PipelineRequest::Route { .. } => {
                self.medium.route_calls += 1;
                Answer::Route(Ok(self.medium.route.clone()))
            }
            PipelineRequest::Run {
                quiet,
                restore_point,
                ..
            } => {
                self.broker.run_calls += 1;
                self.broker.run_quiet = *quiet;
                self.broker.run_restore_point = Some(*restore_point);
                if self.broker.hold_run && !self.held_run {
                    self.held_run = true;
                    return None;
                }
                Answer::Run(self.run_answer())
            }
            PipelineRequest::RunUser { quiet, .. } => {
                self.medium.run_calls += 1;
                self.medium.run_quiet = *quiet;
                Answer::RunUser(match &self.medium.run_error {
                    Some(e) => Err(e.clone()),
                    None => Ok(self.medium.run.clone()),
                })
            }
            PipelineRequest::Observed { outcome, .. } => {
                self.broker.observed_calls += 1;
                self.broker.observed_outcome = *outcome;
                Answer::Observed(Ok(wire(json!({
                    "verify_gone": {
                        "arp_gone": true, "main_exes_gone": true,
                        "msi_unknown_all_ctx": true, "passed": true,
                    }
                }))))
            }
            PipelineRequest::Scan { forced, .. } => {
                self.broker.scan_calls += 1;
                self.broker.scan_forced = *forced;
                self.broker.observed_before_scan = self.broker.observed_calls > 0;
                Answer::Scan(Ok(scan(*forced)))
            }
            PipelineRequest::Confirm(c) => {
                self.confirmations.push_back(c.clone());
                return None;
            }
            PipelineRequest::CloseBroker => {
                self.broker.closed += 1;
                return None;
            }
            PipelineRequest::AdminPromptCancelled { declined } => {
                self.declined = Some(*declined);
                return None;
            }
            PipelineRequest::RunEnded { target, removed } => {
                self.ended.push((target.clone(), *removed));
                return None;
            }
            PipelineRequest::Completed(outcome) => {
                self.completed.push(outcome.clone());
                return None;
            }
        })
    }

    fn run_answer(&mut self) -> Result<RunResult, CallError> {
        if self.broker.run_calls == 1
            && let Some(e) = self.broker.first_run_error.clone()
        {
            return Err(e);
        }
        match &self.broker.run_error {
            Some(e) => Err(e.clone()),
            None => Ok(self.broker.run.clone()),
        }
    }

    /// Answers the controller's requests until it waits for the user (or a held run).
    pub fn pump(&mut self, c: &mut UninstallController, requests: Vec<PipelineRequest>) {
        let mut queue: VecDeque<PipelineRequest> = requests.into();
        while let Some(request) = queue.pop_front() {
            let more = match self.answer(&request) {
                None => vec![],
                Some(Answer::Launch(l)) => c.on_launch(l),
                Some(Answer::Prepare(r)) => c.on_prepare(r),
                Some(Answer::Route(r)) => c.on_route(r),
                Some(Answer::Run(r)) => c.on_run(r),
                Some(Answer::RunUser(r)) => c.on_run_user(r),
                Some(Answer::Observed(r)) => c.on_observed(r),
                Some(Answer::Scan(r)) => c.on_scan(r),
            };
            queue.extend(more);
        }
    }

    /// The held `uninstall.run` answers now.
    pub fn release_run(&mut self, c: &mut UninstallController) {
        let answer = self.run_answer();
        let requests = c.on_run(answer);
        self.pump(c, requests);
    }

    /// The next confirm dialog.
    pub fn next_confirmation(&mut self) -> UninstallConfirmation {
        self.confirmations
            .pop_front()
            .expect("the pipeline asked for a confirmation")
    }

    /// Answers the page's requests, as the window would.
    pub fn pump_page(&mut self, p: &mut UninstallPage, requests: Vec<PageRequest>, env: PageEnv) {
        let mut queue: VecDeque<PageRequest> = requests.into();
        while let Some(request) = queue.pop_front() {
            let PageRequest::Pipeline(request) = request else {
                if let PageRequest::ShowLeftovers {
                    outcome,
                    navigate,
                    with_broker,
                } = &request
                {
                    self.shown.push((outcome.clone(), *navigate, *with_broker));
                }
                self.page_requests.push(request);
                continue;
            };
            let more = match self.answer(&request) {
                None => vec![],
                Some(Answer::Launch(l)) => p.on_launch(l, env),
                Some(Answer::Prepare(r)) => p.on_prepare(r, env),
                Some(Answer::Route(r)) => p.on_route(r, env),
                Some(Answer::Run(r)) => p.on_run(r, env),
                Some(Answer::RunUser(r)) => p.on_run_user(r, env),
                Some(Answer::Observed(r)) => p.on_observed(r, env),
                Some(Answer::Scan(r)) => p.on_scan(r, env),
            };
            queue.extend(more);
        }
    }
}
