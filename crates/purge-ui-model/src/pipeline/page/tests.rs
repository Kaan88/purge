//! The Uninstall page's state logic (`UninstallView.xaml.cs` had no tests of its own; these pin what it
//! did): the hand-off of the scan, the held scan and its bars, the queue's Next card, the confirm dialog's
//! content, and the view's texts.

use purge_rpc::methods::{RestorePoint, Route, RunningProcess};

use super::*;
use crate::pipeline::rig::*;

const IDLE: PageEnv = PageEnv {
    check_running: false,
    leftovers_changing: false,
    leftovers_on_screen: false,
};
const CHANGING: PageEnv = PageEnv {
    check_running: false,
    leftovers_changing: true,
    leftovers_on_screen: false,
};

fn rig() -> Rig {
    Rig::new(
        Broker::new(prepared_for(Route::Broker, Some(QUIET))),
        Medium::new(),
    )
}

fn two() -> Vec<UninstallTarget> {
    vec![
        target(),
        UninstallTarget::new(id("HKLM|64|Beta_is1"), "Beta"),
    ]
}

/// Begins `targets` and answers the confirm dialog with Uninstall; `env` is the window's state throughout.
fn run(rig: &mut Rig, p: &mut UninstallPage, targets: Vec<UninstallTarget>, env: PageEnv) {
    let requests = p.begin(targets, env);
    rig.pump_page(p, requests, env);
    let dialog = ConfirmDialog::new(rig.next_confirmation());
    let answer = dialog.answer(ConfirmButton::Uninstall, true, RestorePoint::HighRisk);
    let requests = p.answer(answer, env);
    rig.pump_page(p, requests, env);
}

fn bar(p: &UninstallPage, env: PageEnv, title: &str) -> Option<Bar> {
    p.view(env).bars.into_iter().find(|b| b.title == title)
}

#[test]
fn an_empty_page_points_to_programs() {
    let p = UninstallPage::new();
    let v = p.view(IDLE);
    assert!(v.empty);
    assert_eq!(v.subtitle, "Nothing is running");
    assert_eq!(v.program_name, "No program selected");
    assert_eq!(v.route_text, "Waiting");
    assert!(!v.route_chip);
    assert_eq!(
        v.route_detail,
        "Pick a program in Programs and choose Uninstall."
    );
    assert_eq!(v.footer, strings::GUIDE);
    assert_eq!(v.steps.len(), 5);
    assert_eq!(v.steps[0].title, "Record what it registered");
    assert!(v.steps.iter().all(|s| s.glyph == strings::GLYPH_PENDING));
    assert_eq!(v.quiet_note, strings::QUIET_NOTE_UNKNOWN);
    assert_eq!(p.open_programs(), vec![PageRequest::NavigatePrograms]);
}

#[test]
fn a_finished_scan_goes_to_the_leftovers_page_with_the_broker() {
    let mut rig = rig();
    let mut p = UninstallPage::new();
    run(&mut rig, &mut p, vec![target()], IDLE);

    assert_eq!(rig.shown.len(), 1);
    let (outcome, navigate, with_broker) = &rig.shown[0];
    assert_eq!(outcome.target, target());
    assert!(*navigate);
    assert!(*with_broker);
    assert!(
        !p.controller().has_broker(),
        "the Leftovers page holds it now"
    );
    assert!(p.close().is_empty(), "a handed broker is not closed");
    assert!(rig.page_requests.contains(&PageRequest::BrokerUsersChanged));

    let v = p.view(IDLE);
    assert_eq!(v.subtitle, "App");
    assert!(v.route_chip);
    assert_eq!(v.route_text, "Administrator");
    assert_eq!(v.route_detail, "Its uninstaller ran at administrator.");
    assert_eq!(v.footer, strings::FOOTER_READY);
    assert_eq!(v.signer, "Signed by App Signer");
    assert_eq!(v.command.as_deref(), Some(QUIET));
    assert!(v.steps.iter().all(|s| s.glyph == strings::GLYPH_DONE));
    assert_eq!(v.initial, "A");
}

#[test]
fn while_the_leftovers_page_changes_the_scan_waits_and_goes_there_when_it_has_finished() {
    let mut rig = rig();
    let mut p = UninstallPage::new();
    run(&mut rig, &mut p, vec![target()], CHANGING);

    assert!(rig.shown.is_empty());
    assert_eq!(p.held_program().as_deref(), Some("App"));
    assert!(
        p.controller().has_broker(),
        "the controller keeps the broker meanwhile"
    );
    let held = bar(&p, CHANGING, "The scan is ready.").expect("the held bar");
    assert!(
        held.message
            .starts_with("The Leftovers page is still applying another change")
    );
    assert!(held.message.ends_with(
        "It is kept for about 10 minutes; after that, start the uninstall again. Nothing was moved."
    ));
    assert!(!held.buttons[0].enabled);

    // The user is on the Leftovers page when the change ends: its outcome is being read, so the scan waits.
    let on_screen = PageEnv {
        leftovers_on_screen: true,
        ..IDLE
    };
    let requests = p.on_leftovers_changing_changed(on_screen);
    rig.pump_page(&mut p, requests, on_screen);
    assert!(rig.shown.is_empty());
    let held = bar(&p, on_screen, "The scan is ready.").expect("the held bar");
    assert!(
        held.message
            .starts_with("The Leftovers page has finished its change")
    );
    assert!(held.buttons[0].enabled);

    // The user leaves it: the scan goes there without taking them back, and a bar says where it went.
    let requests = p.on_leftovers_left(IDLE);
    rig.pump_page(&mut p, requests, IDLE);
    assert_eq!(rig.shown.len(), 1);
    assert!(!rig.shown[0].1, "not navigated");
    assert!(p.held_program().is_none());
    let handed = bar(&p, IDLE, "The scan is on the Leftovers page.").expect("the handed bar");
    assert_eq!(
        handed.message,
        "The Leftovers page finished its change, so the scan of App went there. Nothing was moved."
    );
    assert_eq!(handed.close, BarClose::Handed);
    assert_eq!(p.show_handed(), vec![PageRequest::NavigateLeftovers]);
    assert!(bar(&p, IDLE, "The scan is on the Leftovers page.").is_none());
}

#[test]
fn show_leftovers_on_the_held_bar_hands_the_scan_over_and_navigates() {
    let mut rig = rig();
    let mut p = UninstallPage::new();
    run(&mut rig, &mut p, vec![target()], CHANGING);

    let requests = p.show_held(CHANGING);
    rig.pump_page(&mut p, requests, CHANGING);
    assert!(rig.shown.is_empty(), "the change still runs");

    let requests = p.show_held(IDLE);
    rig.pump_page(&mut p, requests, IDLE);
    assert_eq!(rig.shown.len(), 1);
    assert!(rig.shown[0].1);
}

#[test]
fn a_rerun_closes_the_held_scan_and_says_so() {
    let mut rig = rig();
    let mut p = UninstallPage::new();
    run(&mut rig, &mut p, vec![target()], CHANGING);
    assert!(p.held_program().is_some());

    // "Check again" on the same program while its scan waits: the waiting scan is closed.
    let requests = p.recheck(CHANGING);
    rig.pump_page(&mut p, requests, CHANGING);
    assert!(p.held_program().is_none());
    let dropped = bar(&p, CHANGING, "The waiting scan was closed.").expect("the dropped bar");
    assert_eq!(
        dropped.message,
        "The uninstall of App ran again, so its scan that waited for the Leftovers page was closed. Nothing was moved."
    );
    assert_eq!(dropped.close, BarClose::Dropped);
    p.dismiss_dropped();
    assert!(bar(&p, CHANGING, "The waiting scan was closed.").is_none());
}

#[test]
fn a_new_uninstall_closes_a_waiting_scan_of_another_program() {
    let mut rig = rig();
    let mut p = UninstallPage::new();
    run(&mut rig, &mut p, vec![target()], CHANGING);
    let other = vec![UninstallTarget::new(id("HKLM|64|Gamma_is1"), "Gamma")];
    let requests = p.begin(other, CHANGING);
    rig.pump_page(&mut p, requests, CHANGING);
    let dropped = bar(&p, CHANGING, "The waiting scan was closed.").expect("the dropped bar");
    assert_eq!(
        dropped.message,
        "A new uninstall started, so the scan of App that waited for the Leftovers page was closed. Nothing was moved."
    );
}

#[test]
fn the_queue_shows_the_next_program_and_waits_for_the_users_choice() {
    let mut rig = rig();
    let mut p = UninstallPage::new();
    run(&mut rig, &mut p, two(), IDLE);

    let v = p.view(IDLE);
    assert_eq!(v.subtitle, "App · 1 of 2");
    let next = v.next.expect("the Next card");
    assert_eq!(next.text, "Next: Beta (2 of 2).");
    assert_eq!(next.button, "Uninstall Beta");
    assert_eq!(next.skip_name, "Skip Beta");
    assert!(next.enabled);
    assert_eq!(p.queued_next().as_deref(), Some("Beta (2 of 2)"));

    // A running check or a changing Leftovers page holds it back, each with its reason.
    let checking = PageEnv {
        check_running: true,
        ..IDLE
    };
    assert_eq!(
        p.view(checking).next.and_then(|n| n.tooltip),
        Some(strings::CHECK_RUNNING_HINT)
    );
    assert_eq!(
        p.view(CHANGING).next.and_then(|n| n.tooltip),
        Some("Waits until the Leftovers page has finished its change.")
    );
    assert!(p.uninstall_next(CHANGING).is_empty());

    let requests = p.uninstall_next(IDLE);
    rig.pump_page(&mut p, requests, IDLE);
    let confirmation = rig.next_confirmation();
    assert_eq!(confirmation.target.program_name, "Beta");
    assert_eq!(p.view(IDLE).subtitle, "Beta · 2 of 2");
    assert!(p.view(IDLE).next.is_none());
}

#[test]
fn skip_drops_the_next_program() {
    let mut rig = rig();
    let mut p = UninstallPage::new();
    run(&mut rig, &mut p, two(), IDLE);
    assert_eq!(p.skip_next(), vec![PageRequest::HeldScanChanged]);
    assert!(p.view(IDLE).next.is_none());
    assert!(p.queued_next().is_none());
}

#[test]
fn a_held_scan_holds_the_next_program_back() {
    let mut rig = rig();
    let mut p = UninstallPage::new();
    run(&mut rig, &mut p, two(), CHANGING);
    let on_screen = PageEnv {
        leftovers_on_screen: true,
        ..IDLE
    };
    assert_eq!(
        p.view(on_screen).next.and_then(|n| n.tooltip),
        Some("Waits until this program's scan has gone to the Leftovers page.")
    );
}

#[test]
fn a_running_check_disables_the_choices_and_says_why_in_a_bar() {
    let mut rig = rig();
    let mut p = UninstallPage::new();
    let requests = p.begin(vec![target()], IDLE);
    rig.pump_page(&mut p, requests, IDLE);
    let dialog = ConfirmDialog::new(rig.next_confirmation());
    let requests = p.answer(
        dialog.answer(ConfirmButton::NotNow, true, RestorePoint::HighRisk),
        IDLE,
    );
    rig.pump_page(&mut p, requests, IDLE);

    let checking = PageEnv {
        check_running: true,
        ..IDLE
    };
    let v = p.view(checking);
    assert!(!v.restore_enabled);
    assert!(!v.quiet_enabled);
    assert_eq!(v.choices_tooltip, Some(strings::CHECK_RUNNING_HINT));
    assert!(
        v.bars
            .iter()
            .any(|b| b.title == "Waiting for a leftovers check."
                && b.message == strings::CHECK_RUNNING_HINT)
    );
    assert!(p.retry(checking).is_empty());
    assert!(p.start_over(checking).is_empty());
    assert_eq!(v.quiet_note, strings::QUIET_NOTE_AVAILABLE);
    assert!(v.quiet_row);
    assert!(p.view(IDLE).restore_enabled);
}

#[test]
fn the_notice_bars_name_their_buttons() {
    let mut broker = Broker::new(prepared_for(Route::Broker, Some(QUIET)));
    broker.run_error = Some(CallError::Rpc(fixture("error.uninstall_failed")));
    let mut rig = Rig::new(broker, Medium::new());
    let mut p = UninstallPage::new();
    run(&mut rig, &mut p, vec![target()], IDLE);

    let bars = p.view(IDLE).bars;
    assert_eq!(bars[0].title, "The uninstaller failed.");
    let labels: Vec<&str> = bars[0].buttons.iter().map(|b| b.label).collect();
    assert_eq!(labels, vec!["Run forced cleanup", "Retry"]);

    let mut rig = Rig::launching(
        LaunchResult::of(LaunchState::Cancelled, ""),
        Broker::new(prepared_for(Route::Broker, Some(QUIET))),
        Medium::new(),
    );
    let mut p = UninstallPage::new();
    let requests = p.begin(vec![target()], IDLE);
    rig.pump_page(&mut p, requests, IDLE);
    let v = p.view(IDLE);
    assert_eq!(v.bars[0].buttons[0].label, "Try again");
    assert_eq!(
        v.route_detail,
        "Not started: administrator permission was not given."
    );
}

#[test]
fn the_confirm_dialog_says_what_will_run() {
    let mut rig = rig();
    let mut p = UninstallPage::new();
    let requests = p.begin(vec![target()], IDLE);
    rig.pump_page(&mut p, requests, IDLE);
    let mut confirmation = rig.next_confirmation();
    confirmation.running = vec![
        RunningProcess {
            pid: 1,
            name: "app.exe".into(),
        },
        RunningProcess {
            pid: 2,
            name: "APP.EXE".into(),
        },
        RunningProcess {
            pid: 3,
            name: String::new(),
        },
    ];
    let d = ConfirmDialog::new(confirmation);
    assert_eq!(d.title, "Uninstall App?");
    assert_eq!(d.steps[0], "1. Record what the program registered");
    assert_eq!(d.steps[1], "2. Run its uninstaller as administrator");
    assert_eq!(d.steps.len(), 5);
    assert_eq!(d.signer, "Signed by App Signer");
    assert_eq!(
        d.still_running.as_deref(),
        Some(
            "Still running: app.exe. Close it yourself; Purge never closes a program for you. Check again once it is closed."
        )
    );
    assert!(d.check_again);
    assert_eq!(d.quiet_label, "Use quiet mode");
    assert!(d.quiet_on && d.quiet_enabled);
    assert_eq!(d.quiet_line, format!("Quiet command: {QUIET}"));
    assert_eq!(d.command_for(true), QUIET);
    // Fixed (coordinator's decision): the WinUI dialog kept only the selected command, so switching
    // quiet off still showed the quiet one; switched off, the dialog now shows the interactive one.
    assert_eq!(d.command_for(false), COMMAND);
    assert!(
        d.answer(ConfirmButton::CheckAgain, true, RestorePoint::Off)
            .recheck
    );
}

#[test]
fn the_switched_off_dialog_never_shows_the_quiet_command() {
    let mut rig = rig();
    let mut p = UninstallPage::new();
    let requests = p.begin(vec![target()], IDLE);
    rig.pump_page(&mut p, requests, IDLE);
    let mut confirmation = rig.next_confirmation();
    // The record knew only the quiet command: the selected one is that.
    confirmation.interactive_command = String::new();
    confirmation.command = QUIET.into();
    let d = ConfirmDialog::new(confirmation);
    assert_eq!(d.command_for(true), QUIET);
    assert_eq!(d.command_for(false), strings::confirm::COMMAND_NOT_KNOWN);
    // Nothing runs a command the dialog does not show.
    assert!(d.can_uninstall(true));
    assert!(!d.can_uninstall(false));
}

#[test]
fn the_running_card_names_each_process_once() {
    assert_eq!(
        strings::running_text(&["Code.exe".into()], 1),
        "Code.exe is still running from the program's folder. Its files are in use."
    );
    assert_eq!(
        strings::running_text(&[], 3),
        "A program (3 processes) is still running from the program's folder. Its files are in use."
    );
}
