//! Every user-visible text of the pipeline models, word for word as the WinUI app had them (they were
//! reviewed): `UninstallPipeline.cs`, `RemovedLeftovers.cs` and `UninstallView.xaml.cs`.

// ---- shared bars ----------------------------------------------------------------------------------

/// Bar title: the launch reported a standard account.
pub const NOT_ADMIN_TITLE: &str = "Administrator permission is not available.";
/// Bar title: the broker did not start.
pub const CANNOT_START_TITLE: &str = "The administrator part could not start.";
/// Bar title: the broker answered an error.
pub const REFUSED_TITLE: &str = "The administrator part refused the request.";
/// Bar title: the broker's link ended.
pub const BROKER_ENDED_TITLE: &str = "The administrator part ended.";
/// Bar title: anything else.
pub const WENT_WRONG_TITLE: &str = "Something went wrong.";

// ---- the pipeline ---------------------------------------------------------------------------------

/// The page's guide line before anything ran.
pub const GUIDE: &str = "Purge records the program, runs the program's own uninstaller, checks that it is gone, then scans for what it left.";

/// Record step: the broker is starting.
pub const STARTING_BROKER: &str = "Starting the administrator part";
/// Record step: the launch was cancelled or declined.
pub const NOT_STARTED_NO_PERMISSION: &str = "Not started: administrator permission was not given";
/// Record step: a standard account.
pub const ADMIN_ACCOUNT_NEEDED: &str = "An administrator account is needed";
/// Record step: the broker did not start.
pub const BROKER_DID_NOT_START: &str = "The administrator part did not start";
/// Record step: the medium route's engine named the broker route.
pub const ROUTES_DISAGREE: &str = "The two parts disagree about the route";
/// Record step done, medium route.
pub const RECORDED_MEDIUM: &str = "Recorded; its uninstaller runs at your level";
/// Record step done, broker route.
pub const RECORDED_BROKER: &str = "Recorded by the administrator part";

/// Record step phase: the default line.
pub const PHASE_RECORDING: &str = "Recording what the program registered";
/// Record step phase: the snapshot before the uninstall.
pub const PHASE_SNAPSHOT: &str = "Taking a snapshot of this PC to compare with after the uninstall. This usually takes 10 to 20 seconds.";
/// Record step phase: the baseline.
pub const PHASE_BASELINE: &str = "Loading what a clean Windows looks like";
/// Record step phase: the inventory.
pub const PHASE_FINDING: &str = "Finding the program";

/// The route chip: broker.
pub const ROUTE_ADMIN: &str = "Administrator";
/// The route chip: medium.
pub const ROUTE_USER: &str = "This user's level";

/// Run step: waiting for the broker's dialog.
pub const WAITING_FOR_PROMPT: &str = "Waiting for the Purge security prompt. Nothing has run yet.";
/// Run step: medium route, quiet.
pub const RUNNING_QUIET: &str = "Running its quiet uninstaller";
/// Run step: medium route.
pub const RUNNING: &str = "Running its uninstaller";
/// Run step: the broker's dialog was declined.
pub const DECLINED_STEP: &str = "Not started: the security prompt was declined";
/// Run step: wrong route.
pub const WRONG_PART_STEP: &str = "The wrong part was asked";

/// Run step while the broker's dialog is up.
pub fn consent_shown(code: &str) -> String {
    format!("Confirm in the Purge security prompt (code {code}). Nothing has run yet.")
}

/// Check step: gone.
pub const CONFIRMED_GONE: &str = "Confirmed gone";
/// Check step: not gone.
pub const PARTS_REMAIN: &str = "Some parts remain";
/// Check step after a failed broker run, when the cleanup is forced.
pub const NOT_CHECKED_FAILED: &str = "Not checked: the uninstaller failed";
/// Find step running.
pub const LOOKING_FOR_LEFTOVERS: &str = "Looking for what it left";
/// Ready step.
pub const READY_FOR_REVIEW: &str = "Ready for review";

/// The confirm dialog's steps.
pub fn confirm_steps(medium: bool) -> Vec<String> {
    vec![
        "Record what the program registered".into(),
        if medium {
            "Run its uninstaller at your level".into()
        } else {
            "Run its uninstaller as administrator".into()
        },
        "Check that it is gone".into(),
        "Find its leftovers".into(),
        "Review the list before anything moves".into(),
    ]
}

/// Bar: the confirm dialog said Not now.
pub const CANCELLED_TITLE: &str = "Uninstall cancelled.";
/// Bar: the confirm dialog said Not now.
pub const CANCELLED_MESSAGE: &str = "Nothing was changed. The program was only recorded.";
/// Bar: the launch was cancelled or declined.
pub const NOT_GIVEN_TITLE: &str = "Administrator permission was not given.";
/// Bar: "Not now" at Purge's explanation.
pub const NOT_GIVEN_NOT_NOW: &str =
    "Not started: you chose Not now, so Purge did not ask Windows. Nothing was changed.";
/// Bar: No at the Windows prompt.
pub const NOT_GIVEN_PROMPT_CANCELLED: &str =
    "Not started: the Windows prompt was cancelled. Nothing was changed.";
/// Bar: the broker's dialog was declined.
pub const DECLINED_TITLE: &str = "You declined in the Purge security prompt.";
/// Bar: the broker's dialog was declined.
pub const DECLINED_MESSAGE: &str =
    "Nothing was run. The program was only recorded. You can ask again.";
/// Bar: still installed.
pub const STILL_INSTALLED_TITLE: &str = "The program is still installed.";
/// Bar: still installed.
pub const STILL_INSTALLED_MESSAGE: &str = "The broker's own check found parts of it. The leftover scan runs in the forced mode until you say so.";
/// Bar: the uninstaller failed.
pub const UNINSTALLER_FAILED_TITLE: &str = "The uninstaller failed.";
/// Bar: wrong route.
pub const WRONG_PART_TITLE: &str = "The wrong part was asked to run this.";
/// Bar: a restart.
pub const RESTART_TITLE: &str = "A restart is needed.";
/// Bar: a restart.
pub const RESTART_MESSAGE: &str = "The uninstaller asked Windows to finish after the next restart. Purge does not restart the PC.";
/// Bar: cancelled.
pub const STOPPED_TITLE: &str = "Uninstall stopped.";
/// Bar: cancelled.
pub const STOPPED_MESSAGE: &str = "Nothing more will run until you retry.";
/// The bar's message when an idle run's broker session was ended (another page took it).
pub const BROKER_ENDED_IDLE: &str = "It was closed while this uninstall waited.";
/// The link error of a step that needs the broker after its session ended.
pub const BROKER_NOT_RUNNING: &str = "The administrator part is not running.";
/// After the broker link's sentence.
pub const BROKER_ENDED_TAIL: &str = " Purge can start it again and record the program again.";
/// Bar title: the engine's link ended.
pub const ENGINE_ENDED_TITLE: &str = "Purge's engine ended.";
/// After the engine link's sentence.
pub const ENGINE_ENDED_TAIL: &str =
    " Restart Purge; the program's own uninstaller may already have run.";
/// Bar title: the engine answered an error.
pub const ENGINE_REFUSED_TITLE: &str = "The engine refused the request.";
/// The prepare answered no program.
pub const NO_PROGRAM_RECORDED: &str = "The administrator part recorded no program.";

/// Bar: the uninstaller failed, with the forced cleanup offered.
pub fn uninstaller_failed(exit_code: Option<u32>) -> String {
    let code = exit_code
        .map(|c| format!("The uninstaller ended with exit code {c}. "))
        .unwrap_or_default();
    format!(
        "{code}You can run the forced cleanup: Purge scans for what the program left and leaves the list for you to review, with nothing pre-selected. Or run the uninstaller again."
    )
}

/// Bar: wrong route; `broker` is the route the program belongs to.
pub fn wrong_part(broker: bool) -> String {
    let place = if broker {
        "the administrator part"
    } else {
        "the user's level"
    };
    format!(
        "The program's uninstaller belongs to {place}. Nothing ran; Purge refuses a program of the other route."
    )
}

// ---- the "removed outside Purge" check --------------------------------------------------------------

/// The group's header.
pub fn removed_header(count: usize, max_shown: usize, live: bool) -> String {
    let more = if count > max_shown {
        format!(" (showing {max_shown})")
    } else {
        String::new()
    };
    format!(
        "REMOVED OUTSIDE PURGE · {count}{more}{}",
        if live { "" } else { "   SAMPLE DATA" }
    )
}

/// Progress before the scan's first phase.
pub const REMOVED_SCAN_STARTING: &str = "Starting the scan";
/// Bar: the check was stopped.
pub const REMOVED_STOPPED_TITLE: &str = "Check stopped.";
/// Bar: the check was stopped.
pub const REMOVED_STOPPED_MESSAGE: &str = "Nothing was changed.";
/// After the broker link's sentence.
pub const REMOVED_LINK_TAIL: &str = " Nothing was changed; you can check again.";
/// Bar: the launch was cancelled or declined.
pub const REMOVED_NOT_GIVEN_TITLE: &str = "Not checked: administrator permission was not given.";
/// Bar: "Not now" at Purge's explanation.
pub const REMOVED_NOT_NOW_MESSAGE: &str =
    "You chose Not now, so Purge did not ask Windows. Nothing was changed.";
/// Bar: No at the Windows prompt.
pub const REMOVED_PROMPT_CANCELLED_MESSAGE: &str =
    "The Windows prompt was cancelled. Nothing was changed.";
/// Bar: no record after an approved prompt.
pub const NO_RECORD_MESSAGE: &str = "Nothing was scanned or changed.";

/// Bar title: no record after an approved prompt.
pub fn no_record_title(program_name: &str) -> String {
    format!(
        "Purge has no record of {}.",
        if program_name.is_empty() {
            "this program"
        } else {
            program_name
        }
    )
}

// ---- the Uninstall page -----------------------------------------------------------------------------

/// The stepper's titles, in step order.
pub const STEP_TITLES: [&str; 5] = [
    "Record what it registered",
    "Run its own uninstaller",
    "Check that it is gone",
    "Find its leftovers",
    "Ready for review",
];

/// The glyph of a done step.
pub const GLYPH_DONE: &str = "\u{2713}";
/// The glyph of the active step.
pub const GLYPH_ACTIVE: &str = "\u{25CF}";
/// The glyph of a warning step.
pub const GLYPH_WARNING: &str = "\u{0021}";
/// The glyph of a failed step.
pub const GLYPH_FAILED: &str = "\u{00D7}";
/// The glyph of a pending step.
pub const GLYPH_PENDING: &str = "\u{25CB}";

/// The tooltip (and bar) of an action that waits for a removed program's leftovers check.
pub const CHECK_RUNNING_HINT: &str =
    "A leftovers check is running on the Programs page. Try again when it has finished.";
/// The bar while that check runs.
pub const WAITING_FOR_CHECK_TITLE: &str = "Waiting for a leftovers check.";

/// The subtitle with nothing started.
pub const NOTHING_RUNNING: &str = "Nothing is running";
/// The program card with nothing started.
pub const NO_PROGRAM_SELECTED: &str = "No program selected";
/// The route chip before the route is known.
pub const ROUTE_WAITING: &str = "Waiting";
/// Route detail: nothing started.
pub const ROUTE_PICK: &str = "Pick a program in Programs and choose Uninstall.";
/// Route detail: the launch was cancelled or declined.
pub const ROUTE_NOT_GIVEN: &str = "Not started: administrator permission was not given.";
/// Route detail: the launch runs.
pub const ROUTE_ASKING: &str = "Purge is asking for administrator permission.";
/// Route detail: the record runs.
pub const ROUTE_RECORDING: &str = "Purge is recording the program.";
/// Route detail: not started.
pub const ROUTE_NOT_STARTED: &str = "Not started.";

/// Route detail once the route is known.
pub fn route_detail(route: &str, ran: bool) -> String {
    let route = route.to_lowercase();
    if ran {
        format!("Its uninstaller ran at {route}.")
    } else {
        format!("Its uninstaller will run at {route}.")
    }
}

/// The signer line.
pub fn signer_text(signer: Option<&str>) -> String {
    match signer {
        Some(s) if !s.is_empty() => format!("Signed by {s}"),
        _ => "No signature Purge can name.".into(),
    }
}

/// The quiet note before the program is recorded.
pub const QUIET_NOTE_UNKNOWN: &str = "Purge reads whether this program has a quiet uninstaller when it records it. Quiet mode is used when it has one.";
/// The quiet note with a quiet uninstaller.
pub const QUIET_NOTE_AVAILABLE: &str = "Quiet mode skips the program's own dialogs. Purge never answers \"Keep my settings?\" for you.";
/// The quiet note without one.
pub const QUIET_NOTE_NONE: &str =
    "This program names no quiet uninstaller, so its own dialogs will appear.";

/// The restore-point choices, in [`purge_rpc::methods::RestorePoint`] order (Off, HighRisk, Always).
pub const RESTORE_POINT_CHOICES: [&str; 3] = ["Off", "High-risk changes only (default)", "Always"];

/// The running card.
pub fn running_text(names: &[String], processes: usize) -> String {
    let what = if names.is_empty() {
        "A program".to_owned()
    } else {
        names.join(", ")
    };
    let running = if processes == 1 {
        " is still running".to_owned()
    } else {
        format!(" ({processes} processes) is still running")
    };
    format!("{what}{running} from the program's folder. Its files are in use.")
}

/// The footer with nothing started is [`GUIDE`]; this is the footer once the scan is in.
pub const FOOTER_READY: &str = "The scan is in. The leftovers page shows what Purge found; nothing moves until you confirm there.";
/// The footer while the pipeline runs.
pub const FOOTER_RUNNING: &str =
    "Nothing is moved or removed by Purge until you confirm the list on the leftovers page.";

/// Bar action: forced cleanup.
pub const ACTION_FORCE: &str = "Run forced cleanup";
/// Bar action: retry after a cancelled or declined prompt.
pub const ACTION_TRY_AGAIN: &str = "Try again";
/// Bar action: retry after a failure.
pub const ACTION_RETRY: &str = "Retry";
/// Bar action: start over.
pub const ACTION_START_OVER: &str = "Start over";
/// Bar action: show the held or handed scan.
pub const ACTION_SHOW_LEFTOVERS: &str = "Show leftovers";

/// Bar title: a scan waits for the Leftovers page.
pub const HELD_TITLE: &str = "The scan is ready.";

/// Bar message: a scan waits for the Leftovers page.
pub fn held_message(changing: bool) -> String {
    let why = if changing {
        "The Leftovers page is still applying another change, so this scan waits here and opens there when that change has finished. "
    } else {
        "The Leftovers page has finished its change and shows its outcome, so this scan waits until you show it there. "
    };
    format!(
        "{why}It is kept for about 10 minutes; after that, start the uninstall again. Nothing was moved."
    )
}

/// Bar title: the held scan went to the Leftovers page while the user was elsewhere.
pub const HANDED_TITLE: &str = "The scan is on the Leftovers page.";

/// Bar message: the held scan went to the Leftovers page.
pub fn handed_message(name: &str) -> String {
    format!(
        "The Leftovers page finished its change, so the scan of {name} went there. Nothing was moved."
    )
}

/// Bar title: a held scan was closed.
pub const DROPPED_TITLE: &str = "The waiting scan was closed.";

/// Bar message: a held scan was closed.
pub fn dropped_message(name: &str, rerun: bool) -> String {
    if rerun {
        format!(
            "The uninstall of {name} ran again, so its scan that waited for the Leftovers page was closed. Nothing was moved."
        )
    } else {
        format!(
            "A new uninstall started, so the scan of {name} that waited for the Leftovers page was closed. Nothing was moved."
        )
    }
}

/// A held scan's program when it has no name.
pub const THE_LAST_PROGRAM: &str = "the last program";

/// Why "Uninstall next" waits: a step runs.
pub const NEXT_WAITS_STEP: &str = "Waits until this program's step has finished.";
/// Why "Uninstall next" waits: the Leftovers page changes.
pub const NEXT_WAITS_LEFTOVERS: &str = "Waits until the Leftovers page has finished its change.";
/// Why "Uninstall next" waits: a scan is held.
pub const NEXT_WAITS_HELD: &str = "Waits until this program's scan has gone to the Leftovers page.";

/// The Next card's line.
pub fn next_text(name: &str, position: usize, count: usize) -> String {
    format!("Next: {name} ({position} of {count}).")
}

/// The Next card's detail.
pub const NEXT_DETAIL: &str = "It gets its own confirmation, prompts and leftover scan. Review this program's leftovers first if you like; the next one starts only when you choose.";

/// The next program without a name, in a sentence.
pub const THE_NEXT_PROGRAM: &str = "the next program";
/// The next program without a name, at the start of a line.
pub const THE_NEXT_PROGRAM_CAP: &str = "The next program";

/// The confirm dialog: its title.
pub fn confirm_title(name: &str) -> String {
    format!("Uninstall {name}?")
}

/// The confirm dialog's texts.
pub mod confirm {
    /// Above the steps.
    pub const PURGE_WILL: &str = "Purge will:";
    /// The command's label.
    pub const COMMAND: &str = "Command";
    /// The command shown with the quiet switch off when the program's own (interactive) command
    /// is not known.
    pub const COMMAND_NOT_KNOWN: &str =
        "The program's own uninstall command is not known; only its quiet command is.";
    /// The quiet switch's accessible name.
    pub const QUIET_SWITCH_NAME: &str = "Use quiet mode when available";
    /// The quiet row with a quiet uninstaller.
    pub const USE_QUIET: &str = "Use quiet mode";
    /// The quiet row without one.
    pub const NO_QUIET: &str = "This program has no quiet uninstaller";
    /// Below the quiet row without a quiet command.
    pub const OWN_DIALOGS: &str = "Its own dialogs will appear.";
    /// The restore-point box's accessible name.
    pub const RESTORE_NAME: &str = "Restore point at the cleanup step";
    /// The restore-point box's label.
    pub const RESTORE_LABEL: &str = "Restore point for the cleanup step";
    /// The dialog's last line.
    pub const NOTHING_MOVES: &str =
        "Nothing is moved or removed by Purge until you confirm the list on the next page.";
    /// The primary button.
    pub const UNINSTALL: &str = "Uninstall";
    /// The close button (the default).
    pub const NOT_NOW: &str = "Not now";
    /// The secondary button, with running processes.
    pub const CHECK_AGAIN: &str = "Check again";

    /// The quiet command line.
    pub fn quiet_command(command: &str) -> String {
        format!("Quiet command: {command}")
    }

    /// The running processes line.
    pub fn still_running(names: &[String]) -> String {
        format!(
            "Still running: {}. Close it yourself; Purge never closes a program for you. Check again once it is closed.",
            names.join(", ")
        )
    }
}
