//! Every sentence the History page shows, verbatim from the WinUI app (`HistoryModel.cs`,
//! `HistoryView.xaml.cs`), in one place: they were reviewed, so a change here is a change of the
//! reviewed text.

/// The busy answer of `undo.run` and `journal.resume`/`journal.rollback`.
pub const BUSY: &str =
    "Another Purge window is changing the quarantine. Wait for it to finish, then try again.";
/// The busy answer of `journal.pending`.
pub const PENDING_BUSY: &str = "Another Purge window is working on the quarantine. Try again when it has finished; nothing is listed until then.";

/// Waiting line of "Show items".
pub const READING_ITEMS: &str = "Reading the items of this cleanup…";
/// Waiting line of a restore.
pub const CONFIRM_RESTORE: &str = "Confirm putting it back in the Purge security prompt.";
/// Its second line.
pub const NOTHING_PUT_BACK_YET: &str = "Nothing has been put back yet.";
/// Waiting line of a roll back.
pub const CONFIRM_ROLLBACK: &str = "Confirm the roll back in the Purge security prompt.";
/// Waiting line of a resume.
pub const CONFIRM_RESUME: &str = "Confirm the resume in the Purge security prompt.";
/// Their second line.
pub const NOTHING_CHANGED_YET: &str = "Nothing has been changed yet.";
/// Waiting line of the check for interrupted cleanups.
pub const LOOKING: &str = "Looking for interrupted cleanups…";

/// `history.get` answered `gone`.
pub const GONE: &str = "This cleanup is no longer in Purge's store.";
/// The link ended before an answer to a read.
pub const ENDED_BEFORE_ANSWER: &str = "The administrator part ended before it answered. Try again.";
/// Prefix of any other failure of "Show items".
pub const COULD_NOT_READ_ITEMS: &str = "Couldn't read the items: ";

/// The undo's outcome titles.
pub const PUT_BACK_WITH_CONFLICTS: &str = "Put back, with conflicts";
/// A run that was not closed.
pub const NOT_RECORDED: &str = "The session was not recorded completely";
/// A partial undo.
pub const PARTLY_PUT_BACK: &str = "Partly put back";
/// A complete undo.
pub const PUT_BACK: &str = "Put back";
/// A complete undo's note.
pub const WHAT_YOU_CHOSE_IS_BACK: &str = "What you chose is back where it was.";
/// The undo's note when some items could not be put back.
pub fn could_not_put_back(n: usize) -> String {
    format!("{n} items could not be put back; they are listed below.")
}
/// The restore prompt was cancelled.
pub const RESTORE_DECLINED: &str = "Nothing was put back: the prompt was cancelled.";
/// `undo.run` answered `needs_recovery`.
pub const NEEDS_RECOVERY: &str =
    "An interrupted cleanup comes first. Finish or roll it back, then put back.";
/// The link ended during an undo.
pub const ENDED_WHILE_PUTTING_BACK: &str = "The administrator part ended while putting things back. Purge cannot tell what was put back; the list below is read again.";
/// Prefix of any other failure of a restore.
pub const COULD_NOT_PUT_BACK: &str = "Couldn't put it back: ";

/// The recovery's outcome titles.
pub const ROLLED_BACK: &str = "Rolled back";
/// A complete resume.
pub const FINISHED: &str = "Finished";
/// A partial roll back.
pub const PARTLY_ROLLED_BACK: &str = "Partly rolled back";
/// A partial resume.
pub const PARTLY_FINISHED: &str = "Partly finished";
/// A partial recovery's note.
pub const SOME_STILL_HELD: &str = "Some items are still held or failed; the list below says which.";
/// The recovery prompt was cancelled.
pub const RECOVER_DECLINED: &str = "Nothing was changed: the prompt was cancelled.";
/// The link ended during a recovery.
pub const ENDED_DURING_RECOVERY: &str =
    "The administrator part ended during the recovery. The list below is read again.";
/// Prefix of any other failure of a recovery.
pub const COULD_NOT_RECOVER: &str = "Couldn't recover the session: ";

/// The check could not start the broker.
pub const NOT_CHECKED: &str = "Not checked: administrator permission was not given.";
/// The check found nothing.
pub const NOTHING_INTERRUPTED: &str = "No cleanup was interrupted.";
/// Prefix of any other failure of the check.
pub const COULD_NOT_LOOK: &str = "Couldn't look for interrupted cleanups: ";
/// A broker launch was declined or cancelled.
pub const NOT_STARTED: &str = "Not started: administrator permission was not given.";

/// The session states and the timeline's lines.
pub const INTERRUPTED: &str = "Interrupted";
/// A session part of which was put back.
pub const STATE_PARTLY_PUT_BACK: &str = "Partly put back";
/// A session that was rolled back.
pub const STATE_ROLLED_BACK: &str = "Rolled back";
/// A session with nothing left to put back.
pub const NOTHING_TO_PUT_BACK: &str = "Nothing to put back";
/// A session that can be put back.
pub const UNDOABLE: &str = "Undoable";
/// The timeline marker of a session with nothing kept.
pub const NOTHING_TO_RESTORE: &str = "Nothing to restore";
/// The detail pane's expiry line of an interrupted session.
pub const NOT_RECORDED_COMPLETELY: &str = "The session was not recorded completely.";
/// Detail line of a session listed from `journal.pending`.
pub fn from_journal(done: u32, total: u32) -> String {
    format!("{done} of {total} items done · found in the journals")
}

/// The page's state panel.
pub const READING_HISTORY: &str = "Reading the history…";
/// The empty state's title.
pub const NO_CLEANUPS: &str = "No cleanups yet.";
/// The empty state's text.
pub const NO_CLEANUPS_TEXT: &str =
    "Cleanups you run from Leftovers appear here, and you can put them back from here.";
/// The error state's title.
pub const COULD_NOT_READ_HISTORY: &str = "Couldn't read the history.";
/// The title of an error bar.
pub const COULD_NOT_FINISH: &str = "Couldn't finish that.";
/// The recovery banner.
pub const RECOVERY_TITLE: &str = "The session was not recorded completely.";
/// Its text.
pub const RECOVERY_TEXT: &str = "Resume finishes what it started; Roll back puts back what it changed. Both ask in the Purge security prompt first.";
/// The recovery banner's buttons.
pub const RESUME: &str = "Resume";
/// The second one.
pub const ROLL_BACK: &str = "Roll back";
/// The alert mark's tooltip on a session row.
pub const ALERT_TIP: &str = "Purge found another object in quarantine in place of one of these items. Show items to see it.";
/// The day headers.
pub const TODAY: &str = "Today";
/// Yesterday's header.
pub const YESTERDAY: &str = "Yesterday";

/// The item outcomes.
pub const OUTCOME_DELETED_EARLY: &str =
    "Deleted from quarantine at your request · cannot be put back";
/// An item deleted after its retention.
pub const OUTCOME_DELETED_EXPIRED: &str = "Deleted after its retention ended · cannot be put back";

/// The restore button with the ticked count.
pub fn put_back_selected(n: usize) -> String {
    format!("Put back {n} selected")
}
