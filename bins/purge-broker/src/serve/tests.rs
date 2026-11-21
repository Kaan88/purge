//! Tests of the serving loop over the in-memory transport. Each refusal row of design 3.3 and 3.6 has
//! one; `tests/pipe.rs` runs the client checks over a real pipe.

use std::sync::atomic::Ordering;
use std::time::Duration;

use purge_rpc::BaselineBuild;
use purge_win::taskdialog::Outcome;
use serde_json::json;

use crate::lifetime::ExitReason;
use crate::link::Refusal;
use crate::testkit::{HELLO, Harness, SECS, id_text, kind, request};

fn run_params() -> serde_json::Value {
    json!({ "session_id": id_text("u", 1), "quiet": false })
}

fn prepare_params() -> serde_json::Value {
    json!({ "program_ids": ["HKLM|64|Git_is1"] })
}

fn execute_params(plan: &str) -> serde_json::Value {
    json!({ "plan_id": plan, "restore_point": "off" })
}

/// A scan and a plan in the broker's tables, over the wire.
fn make_plan(c: &crate::testkit::Client, first_id: u64) -> String {
    c.send_line(&request(
        first_id,
        "plan.create",
        &json!({ "scan_id": id_text("s", 1), "preselected": true }),
    ));
    c.reply()["result"]["plan_id"].as_str().unwrap().to_owned()
}

// ---------------------------------------------------------------------------------------------------
// Design 3.3: the client check, three refusals, engine.hello first.

/// Row: a client that fails the identity check (each reason) is disconnected and nothing is answered
/// to it; three of them end the broker with code 25.
#[test]
fn three_refused_clients_end_the_broker() {
    let mut h = Harness::start();
    let reasons = [
        Refusal::Pid,
        Refusal::CreationTime,
        Refusal::Exited,
        Refusal::Image,
        Refusal::Account,
        Refusal::Token,
        Refusal::Unidentified("before its first write".into()),
    ];
    // Two refused clients: the broker still serves.
    for reason in &reasons[..2] {
        let c = h.net.connect(Err(reason.clone()));
        c.send_line(HELLO);
        assert!(c.disconnected(SECS), "{reason}");
        c.silent();
    }
    assert!(h.still_running());
    let third = h.net.connect(Err(reasons[2].clone()));
    third.send_line(HELLO);
    let exit = h.exit(SECS);
    assert_eq!(exit.reason, ExitReason::RefusedClients);
    assert_eq!(exit.code(), 25);
    assert_eq!(exit.refusals, reasons[..3]);
    third.silent();
}

#[test]
fn every_refusal_reason_is_one_refused_client() {
    for reason in [
        Refusal::Pid,
        Refusal::CreationTime,
        Refusal::Exited,
        Refusal::Image,
        Refusal::Account,
        Refusal::Token,
        Refusal::Unidentified("x".into()),
    ] {
        let mut h = Harness::start();
        let clients: Vec<_> = (0..3).map(|_| h.net.connect(Err(reason.clone()))).collect();
        let exit = h.exit(SECS);
        assert_eq!(exit.refusals, vec![reason.clone(); 3], "{reason}");
        for c in clients {
            assert!(c.disconnected(SECS));
            c.silent();
        }
    }
}

#[test]
fn a_good_client_after_refused_ones_is_served() {
    let mut h = Harness::start();
    h.net.connect(Err(Refusal::Pid));
    h.net.connect(Err(Refusal::Image));
    let c = h.client();
    c.close();
    let exit = h.exit(SECS);
    assert_eq!(exit.reason, ExitReason::PipeLost);
    assert_eq!(exit.refusals, [Refusal::Pid, Refusal::Image]);
}

/// Row: engine.hello must come first; anything else, answered with nothing, is a refused client.
#[test]
fn hello_comes_first() {
    let mut h = Harness::start();
    let lines = [
        request(1, "journal.pending", &json!({})),
        request(1, "programs.list", &json!({})),
        "not json at all".to_owned(),
        // A notification with the hello's name carries no id: it asks for nothing.
        r#"{"jsonrpc":"2.0","method":"engine.hello"}"#.to_owned(),
        // The first line is over the first-line cap.
        format!("{}{}", " ".repeat(5000), HELLO),
    ];
    let clients: Vec<_> = lines[..3]
        .iter()
        .map(|line| {
            let c = h.net.connect(Ok(()));
            c.send_line(line);
            c
        })
        .collect();
    let exit = h.exit(SECS);
    assert_eq!(exit.reason, ExitReason::RefusedClients);
    assert_eq!(exit.refusals, vec![Refusal::NotHello; 3]);
    for c in clients {
        assert!(c.disconnected(SECS));
        c.silent();
    }

    for line in &lines[3..] {
        let mut h = Harness::start();
        let bad = h.net.connect(Ok(()));
        bad.send_line(line);
        assert!(bad.disconnected(SECS), "{line:.40}");
        bad.silent();
        // The broker goes on and serves the next, correct, client.
        let good = h.client();
        good.close();
        assert_eq!(h.exit(SECS).refusals, [Refusal::NotHello]);
    }
}

#[test]
fn a_first_line_that_never_ends_is_refused_at_the_cap() {
    let mut h = Harness::start();
    let bad = h.net.connect(Ok(()));
    bad.send_bytes(&vec![b'x'; 5000]);
    assert!(bad.disconnected(SECS));
    let good = h.client();
    good.close();
    assert_eq!(h.exit(SECS).refusals, [Refusal::NotHello]);
}

#[test]
fn a_hello_that_does_not_come_is_refused_and_one_that_comes_with_more_is_served() {
    let mut h = Harness::start();
    let silent = h.net.connect(Ok(()));
    std::thread::sleep(Duration::from_millis(60));
    h.advance(Duration::from_secs(31));
    assert!(silent.disconnected(SECS));
    silent.silent();

    // Hello and the next request in one write: both are answered.
    let c = h.net.connect(Ok(()));
    c.send(&format!(
        "{HELLO}\n{}\n",
        request(2, "journal.pending", &json!({}))
    ));
    assert_eq!(c.reply()["id"], 1);
    h.probe.stubborn_gate.open();
    assert_eq!(c.reply()["id"], 2);
    c.close();
    assert_eq!(h.exit(SECS).refusals, [Refusal::HelloTimeout]);
}

#[test]
fn a_client_that_closes_before_hello_is_refused() {
    let mut h = Harness::start();
    let gone = h.net.connect(Ok(()));
    gone.close();
    let also = h.net.connect(Ok(()));
    also.close();
    let c = h.client();
    c.close();
    assert_eq!(h.exit(SECS).refusals, [Refusal::Gone, Refusal::Gone]);
}

#[test]
fn hello_carries_the_baseline_build_and_a_repeat_is_answered() {
    let mut h = Harness::start();
    h.build.set(BaselineBuild::Building {
        parts: vec!["S1".into()],
        scan_waiting: false,
    });
    let c = h.net.connect(Ok(()));
    c.send_line(HELLO);
    let hello = c.reply();
    assert_eq!(hello["result"]["baseline_build"]["state"], "building");
    assert_eq!(hello["result"]["user_sid"], crate::testkit::ME);
    c.send_line(&request(2, "engine.hello", &json!({})));
    assert_eq!(c.reply()["id"], 2);
    c.close();
    h.exit(SECS);
}

/// An unknown method, a stdio-only method and malformed params answer the protocol errors; the broker
/// stays.
#[test]
fn routing_errors_are_answered_and_change_nothing() {
    let mut h = Harness::start();
    let c = h.client();
    c.send_line(&request(2, "programs.list", &json!({})));
    assert_eq!(c.reply()["error"]["code"], -32601);
    c.send_line(&request(3, "nonsense", &json!({})));
    assert_eq!(c.reply()["error"]["code"], -32601);
    c.send_line(&request(4, "scan.candidates", &json!({ "scan_id": "x" })));
    assert_eq!(c.reply()["error"]["code"], -32602);
    c.send_line("{broken");
    assert_eq!(c.reply()["error"]["code"], -32700);
    assert!(h.still_running());
    c.close();
    h.exit(SECS);
}

// ---------------------------------------------------------------------------------------------------
// Design 3.6: the tables, busy, gone.

#[test]
fn one_mutating_request_at_a_time() {
    let mut h = Harness::start();
    let c = h.client();
    c.send_line(&request(2, "uninstall.run", &run_params()));
    assert!(h.probe.run_started.wait(SECS));
    // A second mutating request is busy, of any method; a read goes through.
    c.send_line(&request(3, "uninstall.run", &run_params()));
    let busy = c.reply();
    assert_eq!((busy["id"].as_u64(), kind(&busy)), (Some(3), "busy"));
    c.send_line(&request(4, "uninstall.prepare", &prepare_params()));
    assert_eq!(kind(&c.reply()), "busy");
    c.send_line(&request(
        5,
        "scan.candidates",
        &json!({"scan_id": id_text("s", 9), "offset": 0, "limit": 5}),
    ));
    assert_eq!(kind(&c.reply()), "gone");
    // The request id of the one that runs cannot be reused.
    c.send_line(&request(2, "uninstall.run", &run_params()));
    assert_eq!(c.reply()["error"]["code"], -32600);

    h.probe.run_gate.open();
    let got = [c.reply(), c.reply()];
    let note = got
        .iter()
        .find(|m| m.get("method").is_some())
        .expect("progress");
    assert_eq!(note["method"], "uninstall.progress");
    assert_eq!(note["params"]["request"], 2);
    let done = got.iter().find(|m| m["id"] == 2).expect("result");
    assert_eq!(done["result"]["outcome"], "complete");
    // After the answer the next mutating request is not busy: the end of a job is seen first.
    for n in 0..100u64 {
        c.send_line(&request(
            10 + n,
            "uninstall.observed",
            &json!({ "session_id": id_text("u", 1) }),
        ));
        let reply = c.reply();
        assert!(reply.get("result").is_some(), "round {n}: {reply}");
    }
    c.close();
    h.exit(SECS);
}

#[test]
fn unknown_removed_and_reused_ids_are_gone() {
    let mut h = Harness::start();
    let c = h.client();
    // A scan, then its candidates; an id of another kind of table is not looked up in this one.
    c.send_line(&request(
        2,
        "leftovers.scan",
        &json!({ "session_id": id_text("u", 1) }),
    ));
    h.probe.scan_started.wait(SECS);
    c.send_line(r#"{"jsonrpc":"2.0","method":"$/cancel","params":{"request":2}}"#);
    let scan = c.reply();
    let scan_id = scan["result"]["scan_id"].as_str().unwrap().to_owned();
    c.send_line(&request(
        3,
        "scan.candidates",
        &json!({ "scan_id": scan_id, "offset": 0, "limit": 5 }),
    ));
    assert_eq!(c.reply()["result"]["scan"], "scan");
    c.send_line(&request(
        4,
        "scan.candidates",
        &json!({ "scan_id": id_text("s", 5), "offset": 0, "limit": 5 }),
    ));
    let g = c.reply();
    assert_eq!(
        (kind(&g), g["error"]["data"]["id"].as_str()),
        ("gone", Some("scan"))
    );
    // A plan id that never existed, then one that was used once.
    c.send_line(&request(
        5,
        "plan.execute",
        &execute_params(&id_text("p", 5)),
    ));
    let g = c.reply();
    assert_eq!(
        (kind(&g), g["error"]["data"]["id"].as_str()),
        ("gone", Some("plan"))
    );
    let plan = make_plan(&c, 6);
    h.consent.answer(Outcome::Declined);
    c.send_line(&request(7, "plan.execute", &execute_params(&plan)));
    assert!(h.consent.wait_open(SECS));
    h.consent.answer(Outcome::Declined);
    assert_eq!(kind(&c.reply()), "consent_declined");
    c.send_line(&request(8, "plan.execute", &execute_params(&plan)));
    let g = c.reply();
    assert_eq!(
        (kind(&g), g["error"]["data"]["id"].as_str()),
        ("gone", Some("plan"))
    );
    c.close();
    h.exit(SECS);
}

#[test]
fn a_program_id_of_another_account_is_gone_before_the_handler() {
    let mut h = Harness::start();
    let c = h.client();
    let other = "HKU:S-1-5-21-1-2-3-1002|64|x";
    let system = "HKU:S-1-5-18|64|x";
    for (n, id) in [other, system].into_iter().enumerate() {
        c.send_line(&request(
            2 + n as u64,
            "leftovers.stored",
            &json!({ "program_ids": [id] }),
        ));
        let g = c.reply();
        assert_eq!(
            (kind(&g), g["error"]["data"]["id"].as_str()),
            ("gone", Some("program"))
        );
        c.send_line(&request(
            5 + n as u64,
            "leftovers.scan",
            &json!({ "program_id": id }),
        ));
        assert_eq!(kind(&c.reply()), "gone");
        c.send_line(&request(
            8 + n as u64,
            "uninstall.prepare",
            &json!({ "program_ids": ["HKLM|64|a", id] }),
        ));
        assert_eq!(kind(&c.reply()), "gone");
    }
    assert_eq!(h.probe.stored_calls.load(Ordering::SeqCst), 0);
    for (n, id) in ["HKLM|64|Git_is1", "HKU:S-1-5-21-1-2-3-1001|64|x"]
        .into_iter()
        .enumerate()
    {
        c.send_line(&request(
            20 + n as u64,
            "leftovers.stored",
            &json!({ "program_ids": [id] }),
        ));
        assert!(c.reply().get("result").is_some());
    }
    assert_eq!(h.probe.stored_calls.load(Ordering::SeqCst), 2);
    c.close();
    h.exit(SECS);
}

#[test]
fn cancel_stops_a_cancellable_request_and_is_ignored_for_the_others() {
    let mut h = Harness::start();
    let c = h.client();
    c.send_line(&request(
        2,
        "leftovers.scan",
        &json!({ "session_id": id_text("u", 1) }),
    ));
    assert!(h.probe.scan_started.wait(SECS));
    c.send_line(r#"{"jsonrpc":"2.0","method":"$/cancel","params":{"request":2}}"#);
    assert!(h.probe.scan_saw_cancel.wait(SECS));
    assert!(c.reply()["result"]["scan_id"].is_string());

    c.send_line(&request(3, "uninstall.run", &run_params()));
    assert!(h.probe.run_started.wait(SECS));
    c.send_line(r#"{"jsonrpc":"2.0","method":"$/cancel","params":{"request":3}}"#);
    // Not cancellable: it runs on; a cancel of an id that is not running does nothing.
    c.send_line(r#"{"jsonrpc":"2.0","method":"$/cancel","params":{"request":99}}"#);
    std::thread::sleep(Duration::from_millis(60));
    assert!(!h.probe.run_finished.is_open());
    h.probe.run_gate.open();
    let mut seen = 0;
    while seen < 2 {
        let m = c.reply();
        if m["id"] == 3 {
            assert_eq!(m["result"]["outcome"], "complete");
        }
        seen += 1;
    }
    c.close();
    h.exit(SECS);
}

// ---------------------------------------------------------------------------------------------------
// Design 3.6: when the broker ends.

#[test]
fn idle_for_ten_minutes_ends_the_broker_and_a_request_restarts_the_count() {
    let mut h = Harness::start();
    let c = h.client();
    let min = Duration::from_secs(60);
    h.advance(9 * min + Duration::from_secs(59));
    assert!(h.still_running());
    c.send_line(&request(2, "journal.pending", &json!({})));
    h.probe.stubborn_gate.open();
    assert_eq!(c.reply()["id"], 2);
    h.advance(9 * min + Duration::from_secs(59));
    assert!(h.still_running());
    h.advance(Duration::from_secs(1));
    let exit = h.exit(SECS);
    assert_eq!(exit.reason, ExitReason::Idle);
    assert_eq!(exit.code(), 0);
}

#[test]
fn idle_never_ends_a_running_request_and_counts_from_its_end() {
    let mut h = Harness::start();
    let c = h.client();
    c.send_line(&request(2, "uninstall.run", &run_params()));
    assert!(h.probe.run_started.wait(SECS));
    h.advance(Duration::from_secs(3600));
    assert!(h.still_running());
    h.probe.run_gate.open();
    c.reply();
    c.reply();
    assert!(
        h.still_running(),
        "the count restarts when the request ends"
    );
    h.advance(Duration::from_secs(600));
    assert_eq!(h.exit(SECS).reason, ExitReason::Idle);
}

#[test]
fn a_broker_nobody_connects_to_ends_when_idle() {
    let mut h = Harness::start();
    h.advance(Duration::from_secs(600));
    assert_eq!(h.exit(SECS).reason, ExitReason::Idle);
}

/// Row: a completed change with no other session open sends its result, waits for the client to
/// close, and ends.
/// Design 8.1: the broker sends `consent.shown` with the code when the dialog is up, before the client
/// can have an answer; a dialog that is declined still ends in `consent_declined`.
#[test]
fn consent_shown_is_sent_when_the_dialog_is_up() {
    let mut h = Harness::start();
    h.consent.announce_shown();
    let c = h.client();
    let plan = make_plan(&c, 2);
    c.send_line(&request(3, "plan.execute", &execute_params(&plan)));
    let shown = c.reply();
    assert_eq!(shown["method"], "consent.shown");
    assert_eq!(shown["params"]["request"], 3);
    assert_eq!(shown["params"]["code"], "A1B2-C3D4");
    assert!(h.consent.wait_open(SECS));
    assert_eq!(h.consent.primary(), 100);
    h.consent.answer(Outcome::Declined);
    assert_eq!(kind(&c.reply()), "consent_declined");
    c.close();
    h.exit(SECS);
}

#[test]
fn a_completed_change_ends_the_broker_after_the_client_closes() {
    let mut h = Harness::start();
    let c = h.client();
    let plan = make_plan(&c, 2);
    c.send_line(&request(3, "plan.execute", &execute_params(&plan)));
    assert!(h.consent.wait_open(SECS));
    h.consent.answer(Outcome::Approved);
    let done = c.reply();
    assert_eq!(done["result"]["outcome"], "complete");
    assert!(h.still_running(), "it waits for the client to close");
    c.close();
    assert_eq!(h.exit(SECS).reason, ExitReason::CompletedChange);
}

#[test]
fn a_completed_change_waits_five_seconds_for_a_client_that_does_not_close() {
    let mut h = Harness::start();
    let c = h.client();
    let plan = make_plan(&c, 2);
    c.send_line(&request(3, "plan.execute", &execute_params(&plan)));
    assert!(h.consent.wait_open(SECS));
    h.consent.answer(Outcome::Approved);
    c.reply();
    h.advance(Duration::from_millis(4900));
    assert!(h.still_running());
    // A request in that time is answered with an error, not run.
    c.send_line(&request(4, "journal.pending", &json!({})));
    let closing = c.reply();
    assert_eq!(kind(&closing), "runtime");
    h.advance(Duration::from_millis(200));
    assert_eq!(h.exit(SECS).reason, ExitReason::CompletedChange);
}

#[test]
fn a_completed_change_with_another_session_open_does_not_end_the_broker() {
    let mut h = Harness::start();
    let c = h.client();
    // Two sessions: the plan's change completes and removes one; the other keeps the broker.
    for id in [2, 3] {
        c.send_line(&request(id, "uninstall.prepare", &prepare_params()));
        c.reply();
    }
    let plan = make_plan(&c, 4);
    c.send_line(&request(5, "plan.execute", &execute_params(&plan)));
    assert!(h.consent.wait_open(SECS));
    h.consent.answer(Outcome::Approved);
    assert_eq!(c.reply()["result"]["outcome"], "complete");
    h.advance(Duration::from_secs(10));
    assert!(h.still_running());
    // The next request is served; a declined or failed change never ends the broker either.
    c.send_line(&request(
        6,
        "plan.execute",
        &execute_params(&id_text("p", 3)),
    ));
    assert_eq!(kind(&c.reply()), "gone");
    c.close();
    assert_eq!(h.exit(SECS).reason, ExitReason::PipeLost);
}

#[test]
fn a_declined_change_does_not_end_the_broker() {
    let mut h = Harness::start();
    let c = h.client();
    let plan = make_plan(&c, 2);
    c.send_line(&request(3, "plan.execute", &execute_params(&plan)));
    assert!(h.consent.wait_open(SECS));
    h.consent.answer(Outcome::Declined);
    assert_eq!(kind(&c.reply()), "consent_declined");
    h.advance(Duration::from_secs(10));
    assert!(h.still_running());
    c.close();
    h.exit(SECS);
}

#[test]
fn shutdown_exits_when_nothing_runs_and_says_no_while_something_does() {
    let mut h = Harness::start();
    let c = h.client();
    c.send_line(&request(2, "uninstall.run", &run_params()));
    assert!(h.probe.run_started.wait(SECS));
    c.send_line(&request(3, "broker.shutdown", &json!({})));
    assert_eq!(c.reply()["result"]["exiting"], false);
    assert!(h.still_running());
    h.probe.run_gate.open();
    c.reply();
    c.reply();
    c.send_line(&request(4, "broker.shutdown", &json!({})));
    assert_eq!(c.reply()["result"]["exiting"], true);
    c.close();
    assert_eq!(h.exit(SECS).reason, ExitReason::Shutdown);
}

#[test]
fn baseline_changed_is_sent_with_the_scans_made_during_the_build() {
    let mut h = Harness::start();
    h.build.set(BaselineBuild::Building {
        parts: vec!["S1".into()],
        scan_waiting: false,
    });
    let c = h.client();
    // A scan made while the build runs.
    c.send_line(&request(
        2,
        "leftovers.scan",
        &json!({ "session_id": id_text("u", 1) }),
    ));
    h.probe.scan_started.wait(SECS);
    c.send_line(r#"{"jsonrpc":"2.0","method":"$/cancel","params":{"request":2}}"#);
    let scan_id = c.reply()["result"]["scan_id"].as_str().unwrap().to_owned();

    h.build.set(BaselineBuild::Building {
        parts: vec!["S2".into()],
        scan_waiting: true,
    });
    let m = c.reply();
    assert_eq!(m["method"], "baseline.changed");
    assert_eq!(m["params"]["state"], "building");
    assert_eq!(m["params"]["rescan_offered"], json!([]));
    h.build.set(BaselineBuild::Done { rescan: true });
    let m = c.reply();
    assert_eq!(m["params"]["state"], "done");
    assert_eq!(m["params"]["rescan_offered"], json!([scan_id]));
    c.close();
    h.exit(SECS);
}

// ---------------------------------------------------------------------------------------------------
// Design 3.6: parent and pipe loss, in every state.

#[test]
fn pipe_loss_with_nothing_running_ends_the_broker_at_once() {
    let mut h = Harness::start();
    let c = h.client();
    c.close();
    let exit = h.exit(SECS);
    assert_eq!((exit.code(), exit.reason), (0, ExitReason::PipeLost));
    assert!(
        h.build.stopped.load(Ordering::SeqCst),
        "the build was asked to stop"
    );
}

#[test]
fn parent_loss_with_nothing_running_ends_the_broker_at_once() {
    let mut h = Harness::start();
    let _c = h.client();
    h.parent.exit();
    assert_eq!(h.exit(SECS).reason, ExitReason::ParentLost);
    assert!(h.build.stopped.load(Ordering::SeqCst));
}

#[test]
fn parent_loss_before_any_client_ends_the_broker() {
    let mut h = Harness::start();
    h.parent.exit();
    assert_eq!(h.exit(SECS).reason, ExitReason::ParentLost);
}

#[test]
fn parent_loss_while_waiting_for_the_hello_ends_the_broker() {
    let mut h = Harness::start();
    let silent = h.net.connect(Ok(()));
    std::thread::sleep(Duration::from_millis(60));
    h.parent.exit();
    assert_eq!(h.exit(SECS).reason, ExitReason::ParentLost);
    silent.silent();
}

/// Row: pipe lost while a change runs: it is finished first (and its answer is not sent).
#[test]
fn pipe_loss_while_a_change_runs_finishes_it_first() {
    let mut h = Harness::start();
    let c = h.client();
    c.send_line(&request(2, "uninstall.run", &run_params()));
    assert!(h.probe.run_started.wait(SECS));
    c.close();
    assert!(h.still_running(), "a running change is not abandoned");
    h.advance(Duration::from_secs(3600));
    assert!(h.still_running(), "and no grace applies to it");
    assert!(!h.probe.run_finished.is_open());
    h.probe.run_gate.open();
    assert_eq!(h.exit(SECS).reason, ExitReason::PipeLost);
    assert!(
        h.probe.run_finished.is_open(),
        "it was finished before the end"
    );
    assert!(
        h.probe.notify_failed.load(Ordering::SeqCst),
        "nothing was sent to the lost client"
    );
}

#[test]
fn parent_loss_while_a_change_runs_finishes_it_first() {
    let mut h = Harness::start();
    let c = h.client();
    c.send_line(&request(2, "uninstall.run", &run_params()));
    assert!(h.probe.run_started.wait(SECS));
    h.parent.exit();
    assert!(h.still_running());
    h.probe.run_gate.open();
    assert_eq!(h.exit(SECS).reason, ExitReason::ParentLost);
    assert!(h.probe.run_finished.is_open());
    c.silent();
}

#[test]
fn a_write_that_fails_while_a_change_runs_is_a_lost_pipe() {
    let mut h = Harness::start();
    let c = h.client();
    c.send_line(&request(2, "uninstall.run", &run_params()));
    assert!(h.probe.run_started.wait(SECS));
    c.break_writes();
    h.probe.run_gate.open();
    assert_eq!(h.exit(SECS).reason, ExitReason::PipeLost);
    assert!(h.probe.run_finished.is_open());
}

/// Row: pipe or parent lost while the consent dialog is open: closed as Cancel, then the end.
#[test]
fn pipe_loss_with_the_consent_dialog_open_closes_it_as_cancel() {
    let mut h = Harness::start();
    let c = h.client();
    let plan = make_plan(&c, 2);
    c.send_line(&request(3, "plan.execute", &execute_params(&plan)));
    assert!(h.consent.wait_open(SECS));
    c.close();
    let exit = h.exit(SECS);
    assert_eq!(exit.reason, ExitReason::PipeLost);
    assert!(h.consent.closed_by_broker());
    assert_eq!(
        *h.probe.consent_outcome.lock().unwrap(),
        Some(Outcome::Declined)
    );
}

#[test]
fn parent_loss_with_the_consent_dialog_open_closes_it_as_cancel() {
    let mut h = Harness::start();
    let c = h.client();
    let plan = make_plan(&c, 2);
    c.send_line(&request(3, "plan.execute", &execute_params(&plan)));
    assert!(h.consent.wait_open(SECS));
    h.parent.exit();
    assert_eq!(h.exit(SECS).reason, ExitReason::ParentLost);
    assert!(h.consent.closed_by_broker());
    assert_eq!(
        *h.probe.consent_outcome.lock().unwrap(),
        Some(Outcome::Declined)
    );
}

#[test]
fn no_dialog_opens_after_the_broker_decided_to_end() {
    let mut h = Harness::start();
    let c = h.client();
    let plan = make_plan(&c, 2);
    // The client is gone before the request is read: the request is not run at all.
    c.close();
    c.send_line(&request(3, "plan.execute", &execute_params(&plan)));
    h.exit(SECS);
    assert!(!h.consent.wait_open(Duration::from_millis(100)));
}

#[test]
fn pipe_loss_cancels_a_running_scan() {
    let mut h = Harness::start();
    let c = h.client();
    c.send_line(&request(
        2,
        "leftovers.scan",
        &json!({ "session_id": id_text("u", 1) }),
    ));
    assert!(h.probe.scan_started.wait(SECS));
    c.close();
    assert_eq!(h.exit(SECS).reason, ExitReason::PipeLost);
    assert!(h.probe.scan_saw_cancel.is_open());
}

/// A read-only request that does not stop is waited for only for the grace.
#[test]
fn a_read_that_ignores_the_loss_is_waited_for_ten_seconds_only() {
    let mut h = Harness::start();
    let c = h.client();
    c.send_line(&request(2, "journal.pending", &json!({})));
    assert!(h.probe.stubborn_started.wait(SECS));
    c.close();
    assert!(h.still_running());
    h.advance(Duration::from_secs(9));
    assert!(h.still_running());
    h.advance(Duration::from_secs(2));
    assert_eq!(h.exit(SECS).reason, ExitReason::PipeLost);
    h.probe.stubborn_gate.open();
}

/// T13: a line over 4 MiB closes the pipe, and with nothing running that ends the broker.
#[test]
fn an_oversize_line_closes_the_pipe() {
    let mut h = Harness::start();
    let c = h.client();
    c.send_bytes(&vec![b'a'; (4 << 20) + 10]);
    assert_eq!(h.exit(SECS).reason, ExitReason::PipeLost);
    drop(c);
}

#[test]
fn the_build_is_asked_to_stop_at_every_end() {
    let mut h = Harness::start();
    h.build.set(BaselineBuild::Building {
        parts: vec!["S1".into()],
        scan_waiting: false,
    });
    h.parent.exit();
    h.exit(SECS);
    assert!(h.build.stopped.load(Ordering::SeqCst));
}

/// M3-R2 S1: `mark_broken` is reached from `respond`, on the supervisor thread, which is the only
/// receiver of the event channel. A full channel must not make it block: the flag it sets is read by
/// the supervisor every tick.
#[test]
fn a_full_event_channel_does_not_block_the_pipe_broken_signal() {
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc::sync_channel;

    use purge_engine::pipeline::Settings;

    use crate::lifetime::Closer;
    use crate::serve::{Consent, Event, Out, Shared, Unwired};

    struct NullOut;
    impl Out for NullOut {
        fn write_line(&self, _: &[u8]) -> io::Result<()> {
            Ok(())
        }
    }

    struct NoConsent;
    impl Consent for NoConsent {
        fn ask(
            &self,
            _: &[purge_win::taskdialog::Page],
            _: i32,
            _: &Closer,
            _: &(dyn Fn() + Sync),
        ) -> io::Result<Outcome> {
            Ok(Outcome::Declined)
        }
    }

    let (events, _rx) = sync_channel(1);
    events
        .send(Event::ReaderEnded)
        .expect("the channel takes one");
    let shared = Arc::new(Shared::<Unwired> {
        tables: crate::session::Tables::new(),
        out: Box::new(NullOut),
        consent: Arc::new(NoConsent),
        closer: Closer::new(),
        build: None,
        settings: Settings::default(),
        user_sid: "S-1-5-21-1-2-3-1001".into(),
        lost: AtomicBool::new(false),
        stop: AtomicBool::new(false),
        broken: AtomicBool::new(false),
        events,
    });

    let worker = shared.clone();
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        worker.mark_broken();
        let _ = finished_tx.send(());
    });
    finished_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("mark_broken must not block on a full event channel");
    assert!(
        shared.broken.load(Ordering::SeqCst),
        "the supervisor reads this flag every tick"
    );
}
