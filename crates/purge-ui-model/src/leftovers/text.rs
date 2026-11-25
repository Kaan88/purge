//! Every user-visible string of the Leftovers page, word for word the WinUI app's
//! (`LeftoversModel.cs`, `LeftoversRow.cs`, `LeftoversView.xaml.cs`), in one place.

#![allow(missing_docs)]

use purge_rpc::methods::{DeleteAfter, DeleteAfterOutcome};

// ---- The move -------------------------------------------------------------------------------

/// The tick box of "delete after".
pub const DELETE_AFTER_TEXT: &str = "Delete instead of keeping in quarantine";

/// What the tick box means, for its tooltip.
pub const DELETE_AFTER_HELP: &str = "Purge still moves the items to quarantine first, so the move is checked and recorded as always. \
     Then a second security prompt names the quarantined files and asks whether to delete them for good. \
     Deleted files cannot be put back. Registry changes keep their backups and can still be undone.";

/// The footer line instead of its one-prompt hint while "delete after" is ticked.
pub const TWO_PROMPTS_HINT: &str =
    "You'll confirm twice in the Purge security prompt: the move, then the delete";
pub const ONE_PROMPT_HINT: &str = "You'll confirm in the Purge security prompt";
pub const SAMPLE_HINT: &str = "Sample data: nothing can be moved";
pub const SAMPLE_MOVE_TIP: &str = "Sample data: nothing can be moved.";

pub fn move_text(delete_after: bool, selected: usize) -> String {
    match (delete_after, selected) {
        (true, 1) => "Move 1 item, then delete it…".into(),
        (true, n) => format!("Move {n} items, then delete them…"),
        (false, 1) => "Move 1 item to quarantine…".into(),
        (false, n) => format!("Move {n} items to quarantine…"),
    }
}

pub const NOTHING_MOVED_YET: &str = "Nothing has been moved yet.";
pub const PREPARING_PLAN: &str = "Preparing the plan…";
pub const CONFIRM_MOVE: &str = "Confirm in the Purge security prompt.";
pub const CONFIRM_MOVE_DETAIL: &str =
    "Nothing has been moved yet. The prompt names the items and shows the same code.";
pub const CONFIRM_MOVE_DETAIL_DELETE: &str = "Nothing has been moved yet. The prompt names the items and shows the same code. \
     It approves the move only; a second prompt then asks about deleting.";
pub const CONFIRM_DELETE: &str = "Confirm the delete in the second Purge security prompt.";
pub const CONFIRM_DELETE_DETAIL: &str =
    "The items are in quarantine. Nothing has been deleted yet.";
pub const MOVE_DECLINED: &str = "Nothing was moved: the prompt was cancelled.";
pub const MOVE_NOT_STARTED: &str = "The move was not started.";
pub const MOVE_NEVER_SENT: &str =
    "Nothing was moved: the administrator part had already ended, so the move never started.";
pub const MOVE_INTERRUPTED: &str = "The administrator part ended during the move. Purge cannot tell which items were moved. \
     Check History & undo before trying again; nothing is claimed here.";
pub const PLAN_REFUSED: &str = "The plan was refused.";

pub fn refused_some(refused: usize, chosen: usize) -> String {
    format!(
        "{refused} of {chosen} selected items cannot be quarantined; they are shown unticked. Nothing has been moved."
    )
}

// ---- The scan -------------------------------------------------------------------------------

pub const READING_SCAN: &str = "Reading the scan";
pub const STARTING_SCAN: &str = "Starting the scan";
pub const SCAN_NOT_LOADED: &str = "The scan was not loaded.";
pub const SCAN_CANCELLED: &str = "The scan was cancelled.";
pub const SHOW_LINK_ENDED: &str = "The administrator part ended before the scan could be shown. ";
pub const SCAN_LINK_ENDED: &str = "The administrator part ended before the scan finished. ";
pub const RESCAN_UNCHANGED: &str = "Scanned again. The list is unchanged; your ticks were kept.";

pub fn rescan_changed(new_items: usize, gone: usize, gone_ticked: usize) -> String {
    format!(
        "Scanned again. {new_items} new {}, {gone} gone ({gone_ticked} of them ticked); your ticks were kept by item id.",
        if new_items == 1 { "item" } else { "items" }
    )
}

// ---- Groups ---------------------------------------------------------------------------------

pub const GROUP_FILES: &str = "Files & folders";
pub const GROUP_REGISTRY: &str = "Registry";
pub const GROUP_ASSOCIATIONS: &str = "File associations & protocols";
pub const GROUP_SHELL: &str = "Shell & COM";
pub const GROUP_SERVICES: &str = "Services, tasks & other";
pub const GROUP_FIREWALL: &str = "Firewall rules";
pub const GROUP_PACKAGES: &str = "Packages";
pub const GROUP_PRIVACY: &str = "Privacy traces";
pub const GROUP_PROTECTED: &str = "Protected — never removed";
pub const GROUP_REPORT_ONLY: &str = "Report only — shown, never removed";

/// The eight list groups, in the order the list shows them.
pub const GROUP_ORDER: [&str; 8] = [
    GROUP_FILES,
    GROUP_REGISTRY,
    GROUP_ASSOCIATIONS,
    GROUP_SHELL,
    GROUP_SERVICES,
    GROUP_FIREWALL,
    GROUP_PACKAGES,
    GROUP_PRIVACY,
];

pub const GROUP_TICK_TIP: &str =
    "This group has no Safe items. A group box ticks Safe items only; tick these one at a time.";

pub fn group_count(shown: usize, hidden: usize) -> String {
    if hidden > 0 {
        format!("{shown} ({hidden} hidden)")
    } else {
        shown.to_string()
    }
}

pub fn of_selected(checked: usize, all: usize) -> String {
    format!("{checked} of {all} selected")
}

pub fn of(checked: usize, all: usize) -> String {
    format!("{checked} of {all}")
}

pub const EXPAND_ALL: &str = "Expand all";
pub const COLLAPSE_ALL: &str = "Collapse all";

pub fn weak_button(showing: bool, weak: usize) -> String {
    if showing {
        format!("Hide weak matches ({weak})")
    } else {
        format!("Show weak matches ({weak})")
    }
}

// ---- Items ----------------------------------------------------------------------------------

pub const WHY_SAFE: &str = "Safe: nothing points to another installed app";
pub const WHY_LIKELY: &str = "Likely: matched by the app's own records";
pub const WHY_WEAK: &str = "Weak: the name matches only";
pub const WHY_PROTECTED: &str = "Protected: kept for information";
pub const WEAK_NOTE: &str = "Name matches only; never ticked for you.";
pub const CANNOT_QUARANTINE: &str = "Cannot be quarantined: ";
pub const SHARED_WITH: &str = "Shared with ";

pub const NEVER_REMOVED: &str = "Never removed";
pub const CANNOT_BE_QUARANTINED: &str = "Cannot be quarantined";
pub const TICKED: &str = "Ticked";
pub const NOT_TICKED: &str = "Not ticked";
pub const NEVER_REMOVES_IT: &str = "Purge never removes it";
pub const MOVED_RESTORABLE: &str = "Moved to quarantine, restorable from History & undo";
pub const NO_CONTENTS: &str = "—";

pub const BAND_PROTECTED: &str = "Protected";
pub const CANNOT_BE_TICKED: &str = "cannot be ticked";
pub const A11Y_TICKED: &str = "ticked";
pub const A11Y_NOT_TICKED: &str = "not ticked";
pub const A11Y_USER_DATA: &str = ", user data";

// ---- Footer and band chips ------------------------------------------------------------------

pub fn verdict(selected: usize, size: &str) -> String {
    format!(
        "{selected} {} · {size}",
        if selected == 1 { "item" } else { "items" }
    )
}

pub fn part(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

pub const FILE_ITEM: (&str, &str) = ("file item", "file items");
pub const REGISTRY_ITEM: (&str, &str) = ("registry item", "registry items");
pub const TASK_ITEM: (&str, &str) = ("task or service", "tasks and services");

// ---- Result ---------------------------------------------------------------------------------

pub const STILL_IN_USE: &str = "still in use";
pub const NOT_CLOSED: &str = "The session was not recorded completely";
pub const NOT_CLOSED_DETAIL: &str = ". History & undo offers recovery.";
pub const MOVE_FINISHED: &str = "The move finished";

pub fn held_line(name: &str, lockers: &str) -> String {
    format!("{name} — held by {lockers}")
}

pub fn failed_line(n: u32) -> String {
    format!("{n} could not be moved. They are listed in History & undo.")
}

pub fn reboot_line(n: u32) -> String {
    format!("{n} will go at the next restart.")
}

pub fn skipped_line(n: u32) -> String {
    format!("{n} were left alone.")
}

pub fn moved_title(moved: u32) -> String {
    if moved == 1 {
        "Moved 1 item to quarantine".into()
    } else {
        format!("Moved {moved} items to quarantine")
    }
}

pub fn moved_of_title(moved: u32, asked: usize) -> String {
    format!("Moved {moved} of {asked} items to quarantine")
}

pub fn restore_point(sequence: i64) -> String {
    format!("Restore point {sequence} made before the move.")
}

/// The undo button after a delete step that deleted something, or the usual one.
pub const UNDO_KEPT: &str = "Put back what is still in quarantine…";
pub const UNDO_REGISTRY: &str = "Undo registry changes…";
pub const UNDO_ALL: &str = "Put back all";

const KEPT: &str = "can be put back for 30 days from the Quarantine page or History & undo";

/// The result line of the delete step. Whatever is not counted as deleted is in quarantine, and the
/// line says so: a cancelled or failed second step never loses an item and never claims a delete.
pub fn describe_delete_after(step: Option<&DeleteAfter>) -> String {
    let Some(step) = step else {
        // An answer without the step (a broker that does not know the request): nothing was deleted.
        return format!("The delete step did not run. What was moved is in quarantine and {KEPT}.");
    };
    let (n, k) = (step.purged, step.kept);
    match step.outcome {
        DeleteAfterOutcome::Deleted => format!(
            "Then deleted for good, as you asked: {n} quarantined {}. \
             That cannot be undone. Registry and other changes of this cleanup can still be undone.",
            if n == 1 { "item" } else { "items" }
        ),
        DeleteAfterOutcome::Partial => format!(
            "Then deleted for good: {n}. Still in quarantine: {k} (declined, or not deletable now); {} {KEPT}.",
            if k == 1 { "it" } else { "they" }
        ),
        DeleteAfterOutcome::Declined => format!(
            "Nothing was deleted: the delete prompt was cancelled. What was moved is in quarantine and {KEPT}."
        ),
        DeleteAfterOutcome::Nothing => {
            "Nothing was deleted: this cleanup left nothing in quarantine that can be deleted now."
                .into()
        }
        DeleteAfterOutcome::Failed => format!(
            "The delete did not go through. What was moved is safe in quarantine and {KEPT}; \
             you can delete it from the Quarantine page."
        ),
    }
}

// ---- Undo and retry -------------------------------------------------------------------------

/// The waiting title of "Put back all" while the broker's restore prompt is the next thing to answer.
pub const UNDO_WAITING_TITLE: &str = "Confirm putting it back in the Purge security prompt.";
/// The waiting title of "Put back all" while a new broker is being started (admin explanation, UAC).
pub const UNDO_STARTING_TITLE: &str = "Starting the administrator part to put it back…";
/// The page's answer when the admin explanation or UAC was declined for "Put back all".
pub const UNDO_NOT_PERMITTED: &str = "Not put back: administrator permission was not given.";
pub const NOTHING_PUT_BACK_YET: &str = "Nothing has been put back yet.";
pub const ASKS_PERMISSION_FIRST: &str =
    "Nothing has been put back yet. Purge asks for administrator permission first.";
pub const OPEN_HISTORY: &str = "Open History & undo to put back what this cleanup still holds.";
pub const UNDO_DECLINED: &str = "Nothing was put back: the prompt was cancelled.";
pub const UNDO_NEVER_SENT: &str = "Nothing was put back: the administrator part had already ended. Open History & undo to put it back.";
pub const UNDO_INTERRUPTED: &str = "The administrator part ended while putting things back. Purge cannot tell what was put back; \
     check History & undo.";
pub const UNDO_NOT_STARTED: &str = "Not put back: the administrator part could not be started. ";
pub const PUT_BACK_CONFLICTS: &str = "Put back, with conflicts";
pub const PUT_BACK: &str = "Put back";
pub const ALL_BACK: &str = "Everything this session moved is back where it was.";

pub fn conflicts_detail(n: usize) -> String {
    format!("{n} items could not be put back; they are listed below.")
}

pub const CONFIRM_RETRY: &str = "Confirm the retry in the Purge security prompt.";
pub const RETRY_MOVED: &str = "The held items were tried again and moved.";
pub const RETRY_STILL_HELD: &str =
    "The held items were tried again; some are still in use. See History & undo.";
pub const RETRY_DECLINED: &str = "Nothing was tried: the prompt was cancelled.";
/// The waiting title of the retry while a new broker is being started (admin explanation, UAC).
pub const RETRY_STARTING_TITLE: &str = "Starting the administrator part to try the held items again…";
pub const RETRY_ASKS_PERMISSION_FIRST: &str =
    "Nothing has been tried yet. Purge asks for administrator permission first.";
pub const RETRY_NOT_PERMITTED: &str = "Nothing was tried: administrator permission was not given.";
pub const RETRY_NOT_STARTED: &str =
    "Nothing was tried: the administrator part could not be started. ";
pub const RETRY_NEVER_SENT: &str = "Nothing was tried: the administrator part had already ended. \
     History & undo shows what this cleanup still holds.";
pub const RETRY_INTERRUPTED: &str = "The administrator part ended during the retry. Purge cannot tell what was moved; \
     check History & undo.";

// ---- Broker errors --------------------------------------------------------------------------

pub fn cap_exceeded(volume: &str, needed: u64, used: u64, cap: u64) -> String {
    format!(
        "The quarantine would pass its cap on {volume}: {needed} bytes are needed, {used} of {cap} are in use."
    )
}

pub const NEEDS_RECOVERY: &str =
    "An interrupted cleanup comes first. Finish or roll it back from History & undo.";
pub const GONE: &str = "This scan has expired. Scan again to get a current list.";
pub const BUSY: &str = "The administrator part is running another change. Wait for it to finish.";
pub const STORE_INTEGRITY: &str = "The quarantine store failed its check. ";
pub const PLAN_REFUSED_PREFIX: &str = "The plan was refused. ";

// ---- The page -------------------------------------------------------------------------------

/// The empty page's words: where an uninstall starts, and where a program removed without Purge is checked.
pub const NO_SCAN_TITLE: &str = "No scan yet";
pub const NO_SCAN_TEXT: &str = "Start an uninstall on the Programs page; Purge shows this page after the uninstaller has run. A program removed \
     without Purge can be checked from Programs, under \"Removed outside Purge\".";
pub const LINK_GONE_TITLE: &str = "The administrator part ended";
pub const LINK_GONE_TEXT: &str = "The scan cannot be shown because its broker link is gone. Start the uninstall again from the Uninstall pipeline page.";
/// The empty panel after the link ended during a review or a scan (review SF2): what WinUI's page
/// offered when its broker went away, with the program named.
pub fn review_ended(name: &str, stored: bool) -> String {
    let name = if name.is_empty() { "the program" } else { name };
    let again = if stored {
        format!("Check {name} again from Programs, under \"Removed outside Purge\".")
    } else {
        "Start the uninstall again from the Uninstall pipeline page, or check the program from \
         Programs, under \"Removed outside Purge\"."
            .to_owned()
    };
    format!(
        "The leftovers review of {name} cannot go on because its broker link is gone. \
         Nothing was moved. {again}"
    )
}
pub const INTERRUPTED_TITLE: &str = "A change was interrupted";
pub const INTERRUPTED_FALLBACK: &str = "The administrator part ended.";

pub const TITLE: &str = "Leftovers";

pub fn title_of(name: &str) -> String {
    format!("Leftovers of {name}")
}

pub const SUB_SCANNING: &str = "Scanning…";
pub const SUB_SCANNING_PREFIX: &str = "Scanning: ";
pub const SUB_WAITING: &str = "Waiting for the security prompt";
pub const SUB_RESULT: &str = "The result is in · restorable from History & undo";
pub const SUB_UNDONE: &str = "Put back";
pub const SUB_INTERRUPTED: &str = "Interrupted · check History & undo";
pub const SUB_REVIEW: &str = "Review the list";
pub const SUB_EMPTY: &str = "No scan yet";
pub const MODE_POST: &str = "Post-uninstall scan";
pub const MODE_FORCED: &str = "Forced scan";
pub const MODE_STORED: &str = "Stored-fingerprint scan";

pub fn review_subtitle(mode: &str, items: usize) -> String {
    format!("{mode} · {items} items")
}

pub const NO_CODE: &str = "—";

pub fn attention_header(n: usize) -> String {
    format!("Items that need attention ({n})")
}

// ---- Bars -----------------------------------------------------------------------------------

pub const BAR_REFUSED_OR_FAILED: &str = "The administrator part refused or failed.";
pub const BAR_SOME_REFUSED: &str = "Some selected items cannot be quarantined.";

pub fn and_more(n: usize) -> String {
    format!(" · and {n} more")
}

pub const BAR_BASELINE_TITLE: &str = "The local baseline finished building.";
pub const BAR_BASELINE_TEXT: &str =
    "Scan again to apply what the new baseline learned. Your ticks are kept by item id.";
pub const BAR_SCAN_AGAIN: &str = "Scan again";
pub const BAR_RESCANNED: &str = "Scanned again.";
pub const BAR_SAMPLE_TITLE: &str = "Sample data.";
pub const BAR_SAMPLE_TEXT: &str =
    "This list is an example, not a scan of this PC. Nothing can be moved from it.";
pub const BAR_FORCED_TITLE: &str = "Nothing is ticked for you.";
pub const BAR_FORCED_TEXT: &str = "The uninstaller failed or Purge could not check that the program is gone, so this is a forced scan: \
     Purge ticks nothing, not even Safe items. Tick what you want moved.";

pub fn bar_held_title(name: &str) -> String {
    format!("A scan of {name} is waiting for this page.")
}

pub const BAR_HELD_CHANGING: &str = "It opens here when this change has finished, but not over its outcome: while you are on this page it \
     waits until you go to another page or choose Show the scan.";
pub const BAR_HELD_IDLE: &str = "It takes this page's place when you go to another page, or now with Show the scan, so you can read \
     this page first.";
pub const BAR_SHOW_SCAN: &str = "Show the scan";

pub fn bar_next_title(next: &str) -> String {
    format!("Next to uninstall: {next}.")
}

pub const BAR_NEXT_TEXT: &str =
    "Finish here first if you like. It starts from the Uninstall page when you choose.";
pub const BAR_GO_UNINSTALL: &str = "Go to Uninstall";
