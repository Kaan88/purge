//! The port of the controller and group parts of `RemovedLeftoversTests.cs`. The fingerprint-file probe
//! and the wire client are `purge-client`'s (they touch the file system and a pipe).

use purge_model::ScanMode;
use purge_rpc::methods::{ProgramRef, ScanResult};
use serde_json::json;

use super::*;
use crate::pipeline::rig::{fixture, id, rpc_error, wire};

const PROGRAM: &str = "HKLM|64|Git_is1";

fn git() -> ProgramId {
    id(PROGRAM)
}

fn scan_result(mode: &str) -> ScanResult {
    wire(json!({
        "scan_id": "s-0000000000000001",
        "mode": mode,
        "baseline_trust": "Exact",
        "counts": { "safe": 0, "likely": 0, "weak": 0, "blocked": 0, "preselected": 0 },
        "warnings": [],
    }))
}

/// A broker that answers `leftovers.stored` and the stored scan from a script, as the UI would.
struct Script {
    launch: LaunchResult,
    stored: Vec<ProgramId>,
    mode: &'static str,
    gone_at: Option<&'static str>,
    link_dies_at_scan: bool,
    hold_scan: bool,
    calls: Vec<&'static str>,
    stored_asked: Vec<ProgramId>,
    scanned: Option<ProgramId>,
    closed: usize,
    launches: usize,
    completed: Vec<StoredScanOutcome>,
    declined: Option<bool>,
    states: Vec<RemovedCheckState>,
}

impl Script {
    fn new(stored: Vec<ProgramId>) -> Self {
        Self {
            launch: LaunchResult::started(),
            stored,
            mode: "external",
            gone_at: None,
            link_dies_at_scan: false,
            hold_scan: false,
            calls: vec![],
            stored_asked: vec![],
            scanned: None,
            closed: 0,
            launches: 0,
            completed: vec![],
            declined: None,
            states: vec![],
        }
    }

    fn launching(launch: LaunchResult) -> Self {
        Self {
            launch,
            ..Self::new(vec![git()])
        }
    }

    fn pump(&mut self, c: &mut RemovedLeftovers, requests: Vec<RemovedRequest>) {
        let mut queue: std::collections::VecDeque<_> = requests.into();
        while let Some(request) = queue.pop_front() {
            let more = match request {
                RemovedRequest::Launch => {
                    self.launches += 1;
                    c.on_launch(Ok(self.launch.clone()))
                }
                RemovedRequest::Stored { program_ids } => {
                    self.calls.push("stored");
                    self.stored_asked.extend(program_ids.iter().cloned());
                    if self.gone_at == Some("stored") {
                        c.on_stored(Err(rpc_error(json!({ "kind": "gone", "id": "program" }))))
                    } else {
                        let stored = program_ids
                            .into_iter()
                            .filter(|p| self.stored.contains(p))
                            .collect();
                        c.on_stored(Ok(stored))
                    }
                }
                RemovedRequest::ScanStored { program_id } => {
                    self.calls.push("scan");
                    self.scanned = Some(program_id);
                    if self.gone_at == Some("scan") {
                        c.on_scan(Err(rpc_error(json!({ "kind": "gone", "id": "program" }))))
                    } else if self.link_dies_at_scan {
                        c.on_scan(Err(CallError::link(
                            "The administrator part closed the link.",
                            false,
                        )))
                    } else {
                        c.on_scan_progress("scan");
                        if self.hold_scan {
                            vec![]
                        } else {
                            c.on_scan(Ok(scan_result(self.mode)))
                        }
                    }
                }
                RemovedRequest::Cancel => c.on_scan(Err(CallError::Cancelled)),
                RemovedRequest::CloseBroker => {
                    self.closed += 1;
                    vec![]
                }
                RemovedRequest::AdminPromptCancelled { declined } => {
                    self.declined = Some(declined);
                    vec![]
                }
                RemovedRequest::Completed(outcome) => {
                    self.completed.push(outcome);
                    vec![]
                }
            };
            if let Some(active) = c.active_program().cloned() {
                self.states.push(c.state_of(&active));
            }
            queue.extend(more);
        }
    }

    fn check(&mut self, c: &mut RemovedLeftovers, program: &ProgramId, name: &str) {
        let requests = c.check(program, name);
        if !requests.is_empty() {
            self.states.push(c.state_of(program));
        }
        self.pump(c, requests);
    }
}

fn controller(record: bool) -> RemovedLeftovers {
    RemovedLeftovers::new(move |_| record)
}

// ---- the controller ---------------------------------------------------------------------------------

#[test]
fn a_program_with_no_record_never_starts_the_broker() {
    let mut c = controller(false);
    c.classify([&git()]);
    assert_eq!(c.state_of(&git()), RemovedCheckState::NoRecord);

    let mut s = Script::new(vec![git()]);
    s.check(&mut c, &git(), "Git");

    assert_eq!(s.launches, 0);
    assert_eq!(c.state_of(&git()), RemovedCheckState::NoRecord);
    assert!(c.notice().is_none());
}

#[test]
fn a_record_asks_stored_then_scans_the_stored_fingerprint_and_hands_the_scan_over() {
    let mut c = controller(true);
    let mut s = Script::new(vec![git()]);
    s.check(&mut c, &git(), "Git");

    assert_eq!(s.calls, vec!["stored", "scan"]);
    assert_eq!(s.stored_asked, vec![git()]);
    assert_eq!(s.scanned, Some(git()));
    let done = s.completed.first().expect("the scan was handed over");
    assert_eq!(done.scan.scan_id.to_string(), "s-0000000000000001");
    assert_eq!(done.scan.mode, ScanMode::External);
    assert_eq!(done.program_name, "Git");
    for state in [
        RemovedCheckState::Starting,
        RemovedCheckState::Checking,
        RemovedCheckState::Scanning,
    ] {
        assert!(s.states.contains(&state), "{state:?} in {:?}", s.states);
    }
    assert_eq!(c.state_of(&git()), RemovedCheckState::Record);
    assert_eq!(s.closed, 0, "the session goes to the Leftovers page");
    assert!(!c.is_busy());
    assert!(c.notice().is_none());
}

#[test]
fn defensive_a_scan_mode_other_than_external_is_passed_on_unchanged() {
    let mut c = controller(true);
    let mut s = Script::new(vec![git()]);
    s.mode = "forced";
    s.check(&mut c, &git(), "Git");
    assert_eq!(s.completed[0].scan.mode, ScanMode::Forced);
}

#[test]
fn no_stored_record_after_the_prompt_turns_the_row_to_no_record_without_a_scan() {
    let mut c = controller(true);
    let mut s = Script::new(vec![]);
    s.check(&mut c, &git(), "Git");

    assert_eq!(s.calls, vec!["stored"]);
    assert!(s.completed.is_empty());
    assert_eq!(s.closed, 1);
    assert_eq!(c.state_of(&git()), RemovedCheckState::NoRecord);
    // The user approved a prompt, so a bar says why nothing followed.
    let notice = c.notice().expect("a bar");
    assert_eq!(notice.kind, NoticeKind::Info);
    assert_eq!(notice.title, "Purge has no record of Git.");
    assert_eq!(notice.message, "Nothing was scanned or changed.");

    // A second click on it does nothing: no prompt for a program without a record.
    let mut again = controller(false);
    s.check(&mut again, &git(), "Git");
    s.check(&mut c, &git(), "Git");
    assert_eq!(s.launches, 1);
    assert_eq!(s.calls, vec!["stored"]);
}

#[test]
fn a_cancelled_prompt_shows_the_cancelled_bar_and_keeps_the_button() {
    let mut c = controller(true);
    let mut s = Script::launching(LaunchResult::of(
        LaunchState::Cancelled,
        "You cancelled the Windows prompt. Nothing was changed.",
    ));
    s.check(&mut c, &git(), "Git");

    assert_eq!(s.declined, Some(false));
    assert!(s.completed.is_empty());
    assert_eq!(c.state_of(&git()), RemovedCheckState::Record);
    assert!(!c.is_busy());
    // The page's own bar says it (the window has no bar for it any more).
    assert_eq!(
        c.notice().map(|n| n.title.as_str()),
        Some("Not checked: administrator permission was not given.")
    );
}

#[test]
fn not_now_at_the_explanation_reaches_the_bar_as_declined() {
    let mut launch = LaunchResult::of(LaunchState::Cancelled, "");
    launch.declined_explanation = true;
    let mut c = controller(true);
    let mut s = Script::launching(launch);
    s.check(&mut c, &git(), "Git");

    assert_eq!(s.declined, Some(true));
    assert!(
        c.notice()
            .is_some_and(|n| n.message.starts_with("You chose Not now"))
    );
}

#[test]
fn a_standard_user_gets_one_sentence_about_the_account() {
    let mut c = controller(true);
    let mut s = Script::launching(LaunchResult::of(
        LaunchState::NotAdministrator,
        "Uninstalling needs an administrator account. Sign in with one, or ask its owner.",
    ));
    s.check(&mut c, &git(), "Git");

    let notice = c.notice().expect("a bar");
    assert_eq!(notice.kind, NoticeKind::Error);
    assert!(
        notice
            .message
            .to_lowercase()
            .contains("administrator account")
    );
    assert!(
        !notice
            .title
            .to_lowercase()
            .contains("administrator account")
    );
    assert_eq!(c.state_of(&git()), RemovedCheckState::Record);
}

#[test]
fn a_launch_that_fails_says_why_and_keeps_the_button() {
    let mut launch = LaunchResult::of(
        LaunchState::CannotStart,
        "The administrator part could not start.",
    );
    launch.exit_code = Some(22);
    let mut c = controller(true);
    let mut s = Script::launching(launch);
    s.check(&mut c, &git(), "Git");

    let notice = c.notice().expect("a bar");
    assert_eq!(notice.kind, NoticeKind::Error);
    assert!(notice.message.contains("exit code 22"));
    assert_eq!(c.state_of(&git()), RemovedCheckState::Record);
}

#[test]
fn gone_from_the_broker_means_no_record() {
    for at in ["stored", "scan"] {
        let mut c = controller(true);
        let mut s = Script::new(vec![git()]);
        s.gone_at = Some(at);
        s.check(&mut c, &git(), "Git");

        assert!(s.completed.is_empty(), "{at}");
        assert_eq!(c.state_of(&git()), RemovedCheckState::NoRecord, "{at}");
        let notice = c.notice().expect("a bar");
        assert_eq!(notice.kind, NoticeKind::Info);
        assert_eq!(notice.title, "Purge has no record of Git.");
        assert_eq!(notice.message, "Nothing was scanned or changed.");
        assert_eq!(s.closed, 1, "{at}");
    }
}

#[test]
fn stop_during_the_scan_cancels_it_and_ends_the_broker() {
    let mut c = controller(true);
    let mut s = Script::new(vec![git()]);
    s.hold_scan = true;
    s.check(&mut c, &git(), "Git");

    assert!(c.is_busy());
    assert_eq!(c.active_program(), Some(&git()));
    assert_eq!(c.state_of(&git()), RemovedCheckState::Scanning);
    assert_eq!(c.progress_text(), Some("scan"));
    let requests = c.cancel();
    assert_eq!(requests, vec![RemovedRequest::Cancel]);
    s.pump(&mut c, requests);

    assert!(s.completed.is_empty());
    assert_eq!(s.closed, 1);
    assert_eq!(c.state_of(&git()), RemovedCheckState::Record);
    assert_eq!(c.notice().map(|n| n.kind), Some(NoticeKind::Info));
    assert!(!c.is_busy());
}

#[test]
fn a_broker_that_ends_mid_scan_is_an_error_and_keeps_the_button() {
    let mut c = controller(true);
    let mut s = Script::new(vec![git()]);
    s.link_dies_at_scan = true;
    s.check(&mut c, &git(), "Git");

    let notice = c.notice().expect("a bar");
    assert_eq!(notice.kind, NoticeKind::Error);
    assert!(notice.title.contains("ended"));
    assert_eq!(
        notice.message,
        "The administrator part closed the link. Nothing was changed; you can check again."
    );
    assert_eq!(c.state_of(&git()), RemovedCheckState::Record);
}

#[test]
fn a_cancel_while_the_prompt_is_up_ends_the_check_once_the_launch_answers() {
    let mut c = controller(true);
    let requests = c.check(&git(), "Git");
    assert_eq!(requests, vec![RemovedRequest::Launch]);
    assert_eq!(c.cancel(), vec![RemovedRequest::Cancel]);
    // The launch answered Started anyway: the check stops there and ends that broker.
    let out = c.on_launch(Ok(LaunchResult::started()));
    assert_eq!(out, vec![RemovedRequest::CloseBroker]);
    assert!(!c.is_busy());
    assert_eq!(c.notice().map(|n| n.title.as_str()), Some("Check stopped."));
}

#[test]
fn the_stored_fixture_lists_what_the_broker_has() {
    let stored: purge_rpc::methods::StoredResult = fixture("pipe.leftovers.stored.result");
    let mut c = controller(true);
    let first = stored.stored.first().cloned().expect("a stored program");
    c.check(&first, "Stored");
    c.on_launch(Ok(LaunchResult::started()));
    let out = c.on_stored(Ok(stored.stored.clone()));
    assert_eq!(
        out,
        vec![RemovedRequest::ScanStored {
            program_id: first.clone()
        }]
    );
    let out = c.on_scan(Ok(fixture("pipe.leftovers.scan.result")));
    assert!(matches!(out.as_slice(), [RemovedRequest::Completed(o)] if o.program_id == first));
}

// ---- the group: rows leave it once dealt with -------------------------------------------------------

fn refs(names: &[&str]) -> Vec<ProgramRef> {
    names
        .iter()
        .map(|n| ProgramRef {
            program_id: id(&format!("HKLM|64|{n}")),
            name: (*n).to_owned(),
        })
        .collect()
}

#[test]
fn the_header_counts_every_program_and_says_how_many_are_shown() {
    let group = RemovedGroup::new(refs(&["A", "B", "C", "D", "E", "F", "G"]));
    assert_eq!(group.count(), 7);
    assert_eq!(group.shown().len(), RemovedGroup::MAX_SHOWN);
    assert_eq!(group.header(true), "REMOVED OUTSIDE PURGE · 7 (showing 5)");
    assert!(group.header(false).ends_with("SAMPLE DATA"));
}

#[test]
fn an_acknowledged_program_leaves_the_group_the_next_moves_up_and_the_engine_forgets_it() {
    let mut group = RemovedGroup::new(refs(&["A", "B", "C", "D", "E", "F"]));
    assert!(group.acknowledge(&id("HKLM|64|B")));
    assert_eq!(group.count(), 5);
    assert!(!group.contains(&id("HKLM|64|B")));
    let names: Vec<&str> = group.shown().iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["A", "C", "D", "E", "F"]);
    assert_eq!(group.header(true), "REMOVED OUTSIDE PURGE · 5");
    // Not in the group (any more): nothing changes, so the caller does not tell the engine again.
    assert!(!group.acknowledge(&id("HKLM|64|B")));
}

#[test]
fn the_group_is_empty_once_every_program_is_dealt_with() {
    let mut group = RemovedGroup::new(refs(&["A", "A", "B"]));
    assert_eq!(group.count(), 2); // a repeated id is one row
    assert!(group.acknowledge(&id("HKLM|64|A")));
    assert!(group.acknowledge(&id("HKLM|64|B")));
    assert!(group.is_empty());
    assert!(group.shown().is_empty());
}

#[test]
fn a_finished_check_acknowledges_the_row_and_a_stopped_one_keeps_it() {
    let other = id("HKLM|64|Other");
    let mut group = RemovedGroup::new(refs(&["Git_is1", "Other"]));
    let mut c = controller(true);

    // Stopped mid-scan: the row stays, and while its check runs it cannot be dismissed.
    let mut held = Script::new(vec![other.clone()]);
    held.hold_scan = true;
    held.check(&mut c, &other, "Other");
    assert!(!c.can_dismiss(&other));
    assert!(c.can_dismiss(&git()));
    let requests = c.cancel();
    held.pump(&mut c, requests);
    assert!(group.contains(&other));
    assert!(c.can_dismiss(&other));

    // Finished: the page acknowledges the row when the scan reached the Leftovers page.
    let mut done = Script::new(vec![git()]);
    done.check(&mut c, &git(), "Git");
    for outcome in &done.completed {
        assert!(group.acknowledge(&outcome.program_id));
    }
    assert!(!group.contains(&git()));
    assert_eq!(group.count(), 1);
}

#[test]
fn a_failed_check_keeps_the_row() {
    let group = RemovedGroup::new(refs(&["Git_is1"]));
    let mut c = controller(true);
    let mut s = Script::new(vec![git()]);
    s.link_dies_at_scan = true;
    s.check(&mut c, &git(), "Git");
    assert!(s.completed.is_empty());
    assert!(group.contains(&git()));
    assert!(c.notice().is_some());
}
