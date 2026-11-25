//! The port of `UninstallPageTests.cs` (the pipeline against a scripted broker, medium engine and
//! launcher) and the model part of `UninstallClientTests.cs` (the record step's phase lines).

use purge_model::{RunOutcome, ScanMode};
use purge_rpc::methods::{PrepareResult, RestorePoint, Route, RunResult, ScanResult};
use serde_json::json;

use super::*;
use crate::pipeline::rig::*;
use crate::pipeline::{CallError, LaunchResult, LaunchState, NoticeKind};

fn begin(rig: &mut Rig, c: &mut UninstallController) {
    let requests = c.begin(target());
    rig.pump(c, requests);
}

fn answer(rig: &mut Rig, c: &mut UninstallController, proceed: bool, restore: RestorePoint) {
    let requests = c.answer(UninstallAnswer::new(proceed, true, restore));
    rig.pump(c, requests);
}

fn single(c: &UninstallController) -> &UninstallNotice {
    assert_eq!(c.notices().len(), 1, "{:?}", c.notices());
    &c.notices()[0]
}

/// Begin, confirm with quiet and HighRisk, and run to the end.
fn run_through(rig: &mut Rig, c: &mut UninstallController) {
    begin(rig, c);
    rig.next_confirmation();
    answer(rig, c, true, RestorePoint::HighRisk);
}

fn fixture_error(stem: &str) -> CallError {
    CallError::Rpc(fixture(stem))
}

// ---- route selection --------------------------------------------------------------------------------

#[test]
fn a_broker_route_shows_the_brokers_command_and_runs_with_the_same_quiet_choice() {
    let mut rig = Rig::new(
        Broker::new(prepared_for(Route::Broker, Some(QUIET))),
        Medium::new(),
    );
    let mut c = UninstallController::new();
    begin(&mut rig, &mut c);
    let confirmation = rig.next_confirmation();

    assert_eq!(confirmation.command, QUIET);
    assert_eq!(confirmation.signer.as_deref(), Some("App Signer"));
    assert!(confirmation.quiet_available);
    assert!(
        confirmation
            .steps
            .iter()
            .any(|s| s.contains("as administrator"))
    );
    assert_eq!(rig.medium.route_calls, 0);
    assert_eq!(c.state_of(UninstallStep::Record), StepState::Done);
    assert_eq!(c.state_of(UninstallStep::Run), StepState::Pending);
    assert_eq!(c.state_of(UninstallStep::Ready), StepState::Pending);

    answer(&mut rig, &mut c, true, RestorePoint::HighRisk);

    assert_eq!(rig.broker.run_calls, 1);
    assert!(rig.broker.run_quiet);
    assert_eq!(rig.broker.command_for(rig.broker.run_quiet), QUIET);
    assert_eq!(rig.medium.run_calls, 0);
    let outcome = c.completed_outcome().expect("an outcome");
    assert_eq!(outcome.mode, ScanMode::Post);
    assert_eq!(outcome.restore_point, RestorePoint::HighRisk);
    assert_eq!(c.state_of(UninstallStep::CheckGone), StepState::Done);
    assert_eq!(c.state_of(UninstallStep::FindLeftovers), StepState::Done);
    assert_eq!(c.state_of(UninstallStep::Ready), StepState::Done);
    assert_eq!(rig.completed.len(), 1);
}

#[test]
fn a_medium_route_shows_the_engines_command_runs_it_and_then_the_broker_observes() {
    let local = r#""C:\Users\u\AppData\Local\App\unins000.exe""#;
    let interactive = format!("{local} /interactive");
    let quiet = format!("{local} /S");
    let mut rig = Rig::new(
        Broker::new(prepared_for(Route::Medium, Some(QUIET))),
        Medium::with(route_of(Route::Medium, &interactive, Some(&quiet))),
    );
    let mut c = UninstallController::new();
    begin(&mut rig, &mut c);
    let confirmation = rig.next_confirmation();

    // The command shown is the medium engine's, because it is the process that runs it.
    assert_eq!(confirmation.command, quiet);
    assert_eq!(rig.medium.route_calls, 1);
    assert!(
        confirmation
            .steps
            .iter()
            .any(|s| s.contains("at your level"))
    );

    answer(&mut rig, &mut c, true, RestorePoint::Always);

    assert_eq!(rig.medium.run_calls, 1);
    assert!(rig.medium.run_quiet);
    assert_eq!(rig.medium.command_for(true), confirmation.command);
    assert_eq!(rig.broker.run_calls, 0);
    assert_eq!(rig.broker.observed_calls, 1);
    assert_eq!(rig.broker.observed_outcome, Some(RunOutcome::Success));
    assert!(
        rig.broker.observed_before_scan,
        "the order is prepare, run_user, observed"
    );
    assert_eq!(
        c.completed_outcome().map(|o| o.restore_point),
        Some(RestorePoint::Always)
    );
}

#[test]
fn a_quietless_program_offers_only_its_interactive_command() {
    let mut rig = Rig::new(
        Broker::new(prepared_for(Route::Broker, None)),
        Medium::new(),
    );
    let mut c = UninstallController::new();
    begin(&mut rig, &mut c);
    let confirmation = rig.next_confirmation();
    assert!(!confirmation.quiet_available);
    assert!(!confirmation.quiet);
    assert_eq!(confirmation.command, COMMAND);

    answer(&mut rig, &mut c, true, RestorePoint::HighRisk);
    assert!(
        !rig.broker.run_quiet,
        "a program with no quiet command runs interactively"
    );
}

// ---- a cancelled UAC --------------------------------------------------------------------------------

#[test]
fn a_cancelled_uac_changes_nothing_and_shows_the_cancelled_bar() {
    let mut rig = Rig::launching(
        LaunchResult::of(
            LaunchState::Cancelled,
            "You cancelled the Windows prompt. Nothing was changed.",
        ),
        Broker::new(prepared_for(Route::Broker, Some(QUIET))),
        Medium::new(),
    );
    let mut c = UninstallController::new();
    begin(&mut rig, &mut c);

    assert_eq!(rig.declined, Some(false)); // raised, and it was the Windows prompt
    assert_eq!(c.launch_state(), Some(LaunchState::Cancelled));
    let notice = single(&c);
    assert_eq!(notice.kind, NoticeKind::Info);
    // "Not now" at the explanation ends here too, so the words do not claim a cancelled Windows prompt.
    assert_eq!(notice.title, "Administrator permission was not given.");
    assert!(notice.can_retry);
    assert!(c.command().is_none());
    assert!(c.completed_outcome().is_none());
    assert!(!c.is_busy());
    assert_eq!(c.state_of(UninstallStep::Record), StepState::Pending);
}

#[test]
fn not_now_at_the_explanation_reaches_the_bar_as_declined() {
    let mut launch = LaunchResult::of(LaunchState::Cancelled, "");
    launch.declined_explanation = true;
    let mut rig = Rig::launching(
        launch,
        Broker::new(prepared_for(Route::Broker, Some(QUIET))),
        Medium::new(),
    );
    let mut c = UninstallController::new();
    begin(&mut rig, &mut c);

    assert_eq!(rig.declined, Some(true));
    assert_eq!(single(&c).title, "Administrator permission was not given.");
    assert!(single(&c).message.contains("you chose Not now"));
}

#[test]
fn a_standard_user_is_told_an_administrator_account_is_needed() {
    let mut rig = Rig::launching(
        LaunchResult::of(
            LaunchState::NotAdministrator,
            "Uninstalling needs an administrator account. Sign in with one, or ask its owner.",
        ),
        Broker::new(prepared_for(Route::Broker, Some(QUIET))),
        Medium::new(),
    );
    let mut c = UninstallController::new();
    begin(&mut rig, &mut c);

    let notice = single(&c);
    assert_eq!(notice.kind, NoticeKind::Error);
    assert!(
        notice
            .message
            .to_lowercase()
            .contains("administrator account")
    );
    // The title and the launcher's sentence are read together; the title does not say it a second time.
    assert!(
        !notice
            .title
            .to_lowercase()
            .contains("administrator account")
    );
    assert!(!notice.can_start_over);
    assert_eq!(c.state_of(UninstallStep::Record), StepState::Failed);
}

#[test]
fn a_broker_that_exits_before_its_pipe_shows_its_exit_code() {
    let mut launch = LaunchResult::of(
        LaunchState::CannotStart,
        "The administrator part could not start",
    );
    launch.exit_code = Some(5);
    let mut rig = Rig::launching(
        launch,
        Broker::new(prepared_for(Route::Broker, Some(QUIET))),
        Medium::new(),
    );
    let mut c = UninstallController::new();
    begin(&mut rig, &mut c);

    let notice = single(&c);
    assert_eq!(notice.kind, NoticeKind::Error);
    assert_eq!(notice.exit_code, Some(5));
    assert!(notice.can_start_over);
}

// ---- wrong route ------------------------------------------------------------------------------------

#[test]
fn a_medium_prepare_whose_engine_says_broker_is_a_wrong_route_refusal() {
    let mut rig = Rig::new(
        Broker::new(prepared_for(Route::Medium, Some(QUIET))),
        Medium::with(route_of(Route::Broker, COMMAND, Some(QUIET))),
    );
    let mut c = UninstallController::new();
    begin(&mut rig, &mut c);

    assert!(rig.confirmations.is_empty());
    let notice = single(&c);
    assert_eq!(notice.kind, NoticeKind::Error);
    assert!(notice.title.to_lowercase().contains("wrong part"));
    assert_eq!(rig.medium.run_calls, 0);
    assert_eq!(rig.broker.run_calls, 0);
    assert!(c.completed_outcome().is_none());
    assert_eq!(c.state_of(UninstallStep::Record), StepState::Failed);
    assert_eq!(c.state_of(UninstallStep::Run), StepState::Pending);
}

#[test]
fn a_broker_run_refused_with_wrong_route_is_shown_as_that() {
    let mut broker = Broker::new(prepared_for(Route::Broker, Some(QUIET)));
    broker.run_error = Some(fixture_error("error.wrong_route"));
    let mut rig = Rig::new(broker, Medium::new());
    let mut c = UninstallController::new();
    run_through(&mut rig, &mut c);

    let notice = single(&c);
    assert_eq!(notice.kind, NoticeKind::Error);
    assert!(notice.title.to_lowercase().contains("wrong part"));
    assert!(notice.message.contains("the user's level"));
    assert_eq!(c.state_of(UninstallStep::Run), StepState::Failed);
    assert!(c.completed_outcome().is_none());
}

// ---- the broker's own dialog ------------------------------------------------------------------------

#[test]
fn while_the_brokers_dialog_is_open_the_run_step_waits_and_says_nothing_has_run() {
    let mut broker = Broker::new(prepared_for(Route::Broker, Some(QUIET)));
    broker.hold_run = true;
    let mut rig = Rig::new(broker, Medium::new());
    let mut c = UninstallController::new();
    begin(&mut rig, &mut c);
    rig.next_confirmation();
    answer(&mut rig, &mut c, true, RestorePoint::Always);
    assert_eq!(rig.broker.run_calls, 1);

    assert_eq!(c.state_of(UninstallStep::Run), StepState::Active);
    let detail = c
        .detail_of(UninstallStep::Run)
        .unwrap_or_default()
        .to_owned();
    assert!(detail.contains("Waiting for the Purge security prompt"));
    assert!(detail.contains("Nothing has run yet"));
    assert_eq!(rig.broker.run_restore_point, Some(RestorePoint::Always));

    c.on_consent_shown("A1B2-C3D4");
    let detail = c.detail_of(UninstallStep::Run).unwrap_or_default();
    assert!(detail.contains("A1B2-C3D4"));
    assert!(detail.contains("Nothing has run yet"));
    assert!(c.completed_outcome().is_none());

    rig.release_run(&mut c);
    assert_eq!(c.state_of(UninstallStep::Run), StepState::Done);
    assert!(c.completed_outcome().is_some());
}

#[test]
fn a_declined_broker_dialog_runs_nothing_and_retry_asks_again() {
    let mut broker = Broker::new(prepared_for(Route::Broker, Some(QUIET)));
    broker.first_run_error = Some(fixture_error("error.consent_declined"));
    let mut rig = Rig::new(broker, Medium::new());
    let mut c = UninstallController::new();
    run_through(&mut rig, &mut c);

    let notice = single(&c);
    assert_eq!(notice.kind, NoticeKind::Info);
    assert!(notice.title.to_lowercase().contains("declined"));
    assert!(notice.message.contains("Nothing was run"));
    assert!(notice.can_retry);
    assert!(
        !notice.can_force,
        "nothing ran, so there is nothing to force"
    );
    assert_eq!(c.state_of(UninstallStep::Run), StepState::Warning);
    assert_eq!(rig.broker.observed_calls, 0);
    assert_eq!(rig.broker.scan_calls, 0);
    assert!(c.completed_outcome().is_none());

    let requests = c.retry();
    rig.pump(&mut c, requests);
    assert_eq!(rig.broker.run_calls, 2);
    assert!(c.completed_outcome().is_some());
}

// ---- a failed uninstaller, with forced offered ------------------------------------------------------

#[test]
fn a_failed_broker_uninstaller_offers_the_forced_cleanup_and_scans_forced() {
    let mut broker = Broker::new(prepared_for(Route::Broker, Some(QUIET)));
    broker.run_error = Some(fixture_error("error.uninstall_failed"));
    let mut rig = Rig::new(broker, Medium::new());
    let mut c = UninstallController::new();
    run_through(&mut rig, &mut c);

    let notice = single(&c);
    assert_eq!(notice.kind, NoticeKind::Error);
    assert_eq!(notice.exit_code, Some(1603));
    assert!(notice.can_force, "forced_offered from error.data");
    assert!(notice.can_retry);
    assert!(
        notice
            .message
            .starts_with("The uninstaller ended with exit code 1603. ")
    );
    assert_eq!(c.state_of(UninstallStep::Run), StepState::Failed);
    assert_eq!(rig.broker.scan_calls, 0);

    let requests = c.force();
    rig.pump(&mut c, requests);
    let outcome = rig.completed.last().expect("the forced scan");

    assert!(rig.broker.scan_forced);
    assert_eq!(rig.broker.scan_calls, 1);
    assert_eq!(outcome.mode, ScanMode::Forced);
    assert!(!c.notices().iter().any(|n| n.kind == NoticeKind::Error));
    assert_eq!(c.state_of(UninstallStep::CheckGone), StepState::Warning);
    assert_eq!(
        c.detail_of(UninstallStep::CheckGone),
        Some("Not checked: the uninstaller failed")
    );
}

#[test]
fn a_failed_medium_uninstaller_observes_then_offers_the_forced_cleanup() {
    let mut medium = Medium::new();
    medium.run = run_user(1603, "Failed");
    let mut rig = Rig::new(
        Broker::new(prepared_for(Route::Medium, Some(QUIET))),
        medium,
    );
    let mut c = UninstallController::new();
    run_through(&mut rig, &mut c);

    assert_eq!(rig.broker.observed_calls, 1);
    assert_eq!(rig.broker.observed_outcome, Some(RunOutcome::Failed));
    let notice = single(&c);
    assert_eq!(notice.kind, NoticeKind::Error);
    assert_eq!(notice.exit_code, Some(1603));
    assert!(notice.can_force);

    let requests = c.force();
    rig.pump(&mut c, requests);
    let outcome = rig.completed.last().expect("the forced scan");
    assert!(rig.broker.scan_forced);
    assert_eq!(outcome.mode, ScanMode::Forced);
    assert_eq!(rig.broker.observed_calls, 1);
}

// ---- a stage that runs again clears the scan from before --------------------------------------------

#[test]
fn check_again_after_a_completed_scan_leaves_no_outcome_until_the_new_scan_is_in() {
    // The Uninstall page may hold the completed scan for the Leftovers page; while the pipeline runs again
    // it must not hand that scan over with the broker this run is using.
    let mut rig = Rig::new(
        Broker::new(prepared_for(Route::Broker, Some(QUIET))),
        Medium::new(),
    );
    let mut c = UninstallController::new();
    run_through(&mut rig, &mut c);
    let first = c.completed_outcome().cloned().expect("an outcome");

    let requests = c.recheck();
    rig.pump(&mut c, requests);
    rig.next_confirmation();

    assert!(c.is_busy());
    assert!(c.completed_outcome().is_none());
    assert!(c.has_broker());
    assert_eq!(rig.broker.closed, 0);

    answer(&mut rig, &mut c, true, RestorePoint::HighRisk);

    let second = c.completed_outcome().expect("a new outcome");
    assert_ne!(&first, second);
    assert_eq!(rig.broker.scan_calls, 2);
}

#[test]
fn a_forced_cleanup_after_a_completed_scan_clears_the_old_outcome_before_it_scans() {
    let mut rig = Rig::new(
        Broker::new(prepared_for(Route::Broker, Some(QUIET))),
        Medium::new(),
    );
    let mut c = UninstallController::new();
    run_through(&mut rig, &mut c);
    let first = c.completed_outcome().cloned().expect("an outcome");

    let requests = c.force();
    assert!(
        c.is_busy() && c.completed_outcome().is_none(),
        "the scan from before stayed while the forced scan ran"
    );
    rig.pump(&mut c, requests);

    let second = c.completed_outcome().expect("a new outcome");
    assert_ne!(&first, second);
    assert!(second.forced());
}

// ---- the Programs page learns what the run did ------------------------------------------------------

#[test]
fn the_run_tells_the_page_once_whether_purge_removed_the_program() {
    for (how, removed) in [
        ("broker-gone", true),
        ("broker-still-installed", false),
        ("medium-gone", true),
        ("medium-failed", false),
    ] {
        let route = if how.starts_with("medium") {
            Route::Medium
        } else {
            Route::Broker
        };
        let mut broker = Broker::new(prepared_for(route, Some(QUIET)));
        if how == "broker-still-installed" {
            broker.run = run_result(0, "Success", false, false);
        }
        let mut medium = Medium::with(route_of(route, COMMAND, Some(QUIET)));
        if how == "medium-failed" {
            medium.run = run_user(1603, "Failed");
        }
        let mut rig = Rig::new(broker, medium);
        let mut c = UninstallController::new();
        run_through(&mut rig, &mut c);

        assert_eq!(rig.ended, vec![(target(), removed)], "{how}");
    }
}

#[test]
fn a_declined_prompt_runs_nothing_and_tells_the_page_nothing() {
    let mut broker = Broker::new(prepared_for(Route::Broker, Some(QUIET)));
    broker.run_error = Some(rpc_error(json!({ "kind": "consent_declined" })));
    let mut rig = Rig::new(broker, Medium::new());
    let mut c = UninstallController::new();
    run_through(&mut rig, &mut c);

    assert!(rig.ended.is_empty());
}

// ---- still installed and restart ----------------------------------------------------------------------

#[test]
fn a_still_installed_program_scans_forced_and_says_so() {
    let mut broker = Broker::new(prepared_for(Route::Broker, Some(QUIET)));
    broker.run = run_result(0, "Success", false, true);
    let mut rig = Rig::new(broker, Medium::new());
    let mut c = UninstallController::new();
    run_through(&mut rig, &mut c);

    assert!(rig.broker.scan_forced);
    assert_eq!(c.state_of(UninstallStep::CheckGone), StepState::Warning);
    assert!(c.notices().iter().any(
        |n| n.kind == NoticeKind::Warning && n.title.to_lowercase().contains("still installed")
    ));
    assert!(c.completed_outcome().is_some_and(UninstallOutcome::forced));
}

#[test]
fn a_restart_request_is_text_only() {
    let mut broker = Broker::new(prepared_for(Route::Broker, Some(QUIET)));
    broker.run = run_result(3010, "SuccessReboot", true, true);
    let mut rig = Rig::new(broker, Medium::new());
    let mut c = UninstallController::new();
    run_through(&mut rig, &mut c);

    assert!(
        c.notices()
            .iter()
            .any(|n| n.kind == NoticeKind::Info && n.title.to_lowercase().contains("restart"))
    );
    assert!(c.completed_outcome().is_some());
}

// ---- links that die mid-run -------------------------------------------------------------------------

#[test]
fn a_broker_that_dies_mid_run_keeps_the_page_and_offers_a_start_over() {
    let mut broker = Broker::new(prepared_for(Route::Broker, Some(QUIET)));
    broker.run_error = Some(CallError::Link("The administrator part ended.".into()));
    let mut rig = Rig::new(broker, Medium::new());
    let mut c = UninstallController::new();
    run_through(&mut rig, &mut c);

    let notice = single(&c);
    assert_eq!(notice.kind, NoticeKind::Error);
    assert!(
        notice
            .title
            .to_lowercase()
            .contains("administrator part ended")
    );
    assert!(notice.can_start_over);
    assert_eq!(c.state_of(UninstallStep::Run), StepState::Failed);

    // Start over closes the dead link and starts a fresh broker: the UAC prompt appears again.
    let requests = c.start_over();
    rig.pump(&mut c, requests);
    rig.next_confirmation();
    answer(&mut rig, &mut c, false, RestorePoint::HighRisk);

    assert_eq!(rig.launches, 2);
    assert_eq!(rig.broker.closed, 1);
    assert!(
        c.notices()
            .iter()
            .any(|n| n.kind == NoticeKind::Info && n.title.to_lowercase().contains("cancelled"))
    );
}

#[test]
fn an_engine_that_dies_mid_run_asks_for_a_restart_of_purge() {
    let mut medium = Medium::new();
    medium.run_error = Some(CallError::Link("The engine ended (exit code 3).".into()));
    let mut rig = Rig::new(
        Broker::new(prepared_for(Route::Medium, Some(QUIET))),
        medium,
    );
    let mut c = UninstallController::new();
    run_through(&mut rig, &mut c);

    let notice = single(&c);
    assert_eq!(notice.kind, NoticeKind::Error);
    assert!(notice.title.to_lowercase().contains("engine ended"));
    assert!(notice.can_start_over);
    assert_eq!(rig.broker.observed_calls, 0);
}

// ---- beyond the C# tests: answers out of turn, the guard, the fixtures ------------------------------

#[test]
fn an_answer_the_pipeline_is_not_waiting_for_is_ignored_and_a_second_begin_while_busy_too() {
    let mut c = UninstallController::new();
    assert!(
        c.on_scan(Ok(fixture("pipe.leftovers.scan.result")))
            .is_empty()
    );
    assert!(c.completed_outcome().is_none());

    let requests = c.begin(target());
    assert_eq!(requests, vec![PipelineRequest::Launch]);
    assert!(c.is_busy());
    assert!(c.begin(target()).is_empty(), "a second begin is ignored");
    assert!(
        c.on_prepare(Ok(PrepareResult {
            programs: vec![],
            timings: None,
        }))
        .is_empty(),
        "the launch is awaited, not the prepare"
    );
    assert_eq!(c.state_of(UninstallStep::Record), StepState::Active);
    assert_eq!(
        c.detail_of(UninstallStep::Record),
        Some("Starting the administrator part")
    );
}

#[test]
fn the_wire_fixtures_carry_a_broker_run_to_the_end() {
    let mut c = UninstallController::new();
    c.begin(UninstallTarget::new(id("HKLM|64|Git_is1"), "Git"));
    c.on_launch(LaunchResult::started());
    let confirm = c.on_prepare(Ok(fixture("pipe.uninstall.prepare.result")));
    let [PipelineRequest::Confirm(confirmation)] = confirm.as_slice() else {
        panic!("a confirmation: {confirm:?}");
    };
    assert_eq!(
        confirmation.command,
        r#""C:\Program Files\Git\unins000.exe" /SILENT"#
    );
    assert_eq!(confirmation.signer.as_deref(), Some("Johannes Schindelin"));
    assert_eq!(c.route_text(), Some("Administrator"));

    let run = c.answer(UninstallAnswer::new(true, true, RestorePoint::HighRisk));
    assert!(matches!(
        run.as_slice(),
        [PipelineRequest::Run { quiet: true, .. }]
    ));
    let after: RunResult = fixture("pipe.uninstall.run.result");
    let scan = c.on_run(Ok(after));
    assert!(matches!(
        scan.as_slice(),
        [
            PipelineRequest::RunEnded { removed: true, .. },
            PipelineRequest::Scan { forced: false, .. }
        ]
    ));
    assert_eq!(
        c.detail_of(UninstallStep::Run),
        Some("Finished, exit code 0 · quiet mode")
    );
    let result: ScanResult = fixture("pipe.leftovers.scan.result");
    let done = c.on_scan(Ok(result));
    assert!(matches!(done.as_slice(), [PipelineRequest::Completed(_)]));
    assert_eq!(
        c.detail_of(UninstallStep::FindLeftovers),
        Some("29 leftovers (post) · 20 pre-selected")
    );
    assert_eq!(c.current_step(), UninstallStep::Ready);
    assert!(!c.is_busy());
}

#[test]
fn the_medium_fixtures_show_the_running_process_and_observe_a_partial_removal() {
    let mut c = UninstallController::new();
    c.begin(UninstallTarget::new(
        id("HKU:S-1-5-21-1-2-3-1001|64|VSCode"),
        "VS Code",
    ));
    c.on_launch(LaunchResult::started());
    let mut prepared = prepared_for(Route::Medium, Some(QUIET));
    prepared.program_id = id("HKU:S-1-5-21-1-2-3-1001|64|VSCode");
    let route = c.on_prepare(Ok(PrepareResult {
        programs: vec![prepared],
        timings: None,
    }));
    assert!(matches!(route.as_slice(), [PipelineRequest::Route { .. }]));
    let confirm = c.on_route(Ok(fixture("stdio.uninstall.route.result")));
    let [PipelineRequest::Confirm(confirmation)] = confirm.as_slice() else {
        panic!("a confirmation: {confirm:?}");
    };
    assert_eq!(confirmation.running.len(), 1);
    assert_eq!(confirmation.running[0].name, "Code.exe");
    assert_eq!(c.route_text(), Some("This user's level"));

    c.answer(UninstallAnswer::new(true, false, RestorePoint::Off));
    let observed = c.on_run_user(Ok(fixture("stdio.uninstall.run_user.result")));
    assert!(matches!(
        observed.as_slice(),
        [PipelineRequest::Observed {
            outcome: Some(RunOutcome::Success),
            ..
        }]
    ));
    let scan = c.on_observed(Ok(fixture("pipe.uninstall.observed.result")));
    assert!(matches!(
        scan.as_slice(),
        [
            PipelineRequest::RunEnded { removed: false, .. },
            PipelineRequest::Scan { forced: true, .. }
        ]
    ));
    assert_eq!(c.state_of(UninstallStep::CheckGone), StepState::Warning);
}

#[test]
fn not_now_at_the_confirm_dialog_records_only_and_keeps_the_broker() {
    let mut rig = Rig::new(
        Broker::new(prepared_for(Route::Broker, Some(QUIET))),
        Medium::new(),
    );
    let mut c = UninstallController::new();
    begin(&mut rig, &mut c);
    rig.next_confirmation();
    answer(&mut rig, &mut c, false, RestorePoint::HighRisk);

    let notice = single(&c);
    assert_eq!(notice.title, "Uninstall cancelled.");
    assert_eq!(
        notice.message,
        "Nothing was changed. The program was only recorded."
    );
    assert!(!c.is_busy());
    assert!(c.has_broker());
    assert_eq!(rig.broker.run_calls, 0);

    // The page goes away: the broker ends with it, unless it was handed over.
    assert_eq!(c.close(), vec![PipelineRequest::CloseBroker]);
}

#[test]
fn a_broker_handed_over_is_not_closed_with_the_page() {
    let mut rig = Rig::new(
        Broker::new(prepared_for(Route::Broker, Some(QUIET))),
        Medium::new(),
    );
    let mut c = UninstallController::new();
    run_through(&mut rig, &mut c);
    assert!(c.take_broker());
    assert!(!c.take_broker());
    assert!(c.close().is_empty());
}

#[test]
fn progress_lines_go_to_the_step_that_waits() {
    let mut c = UninstallController::new();
    c.begin(target());
    c.on_launch(LaunchResult::started());
    c.on_progress(&wire(
        json!({ "request": 5, "phase": "harvest: reading roots, Inno log", "done": 0, "total": 0 }),
    ));
    assert_eq!(
        c.detail_of(UninstallStep::Record),
        Some(
            "Taking a snapshot of this PC to compare with after the uninstall. This usually takes 10 to 20 seconds."
        )
    );
}

#[test]
fn record_phases_read_plainly() {
    for (phase, text) in [
        (None, "Recording what the program registered"),
        (
            Some("harvest: reading the inventory"),
            "Finding the program",
        ),
        (
            Some("harvest: 586 entries; target HKLM|64|Git_is1 (Git) (173 ms)"),
            "Finding the program",
        ),
        (
            Some("loading the baseline Professional-26300.9974"),
            "Loading what a clean Windows looks like",
        ),
        (
            Some("baseline view local-Professional-26300.9974+2 loaded: trust merged (171 ms)"),
            "Loading what a clean Windows looks like",
        ),
        (
            Some("harvest: reading roots, Inno log, anchors and the reference snapshot"),
            "Taking a snapshot of this PC to compare with after the uninstall. This usually takes 10 to 20 seconds.",
        ),
        (
            Some(
                "harvest: 1 roots, 10 exes, 0 Inno records, 40 reference-snapshot entries (8739 ms)",
            ),
            "Recording what the program registered",
        ),
        (
            Some("something new"),
            "Recording what the program registered",
        ),
    ] {
        assert_eq!(record_phase_text(phase), text, "{phase:?}");
    }
}
