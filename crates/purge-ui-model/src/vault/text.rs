//! Every sentence the Quarantine (vault) page shows, verbatim from the WinUI app (`VaultModel.cs`,
//! `VaultRows.cs`, `VaultView.xaml.cs`), in one place: they were reviewed, so a change here is a
//! change of the reviewed text.

/// A busy answer of `undo.run` (and any other call without its own busy line).
pub const BUSY: &str =
    "Another Purge window is changing the quarantine. Wait for it to finish, then try again.";
/// A busy answer of a delete.
pub const DELETE_BUSY: &str = "Another Purge window is changing the quarantine; nothing was deleted. Try again when it has finished.";
/// `needs_recovery`.
pub const NEEDS_RECOVERY: &str =
    "An interrupted cleanup comes first. Finish or roll it back from History & undo.";
/// Prefix of `store_integrity`.
pub const STORE_INTEGRITY: &str = "The quarantine store failed its check. ";
/// A broker launch was declined or cancelled.
pub const NOT_STARTED: &str = "Not started: administrator permission was not given.";

/// Waiting line of "Put back…".
pub const CONFIRM_RESTORE: &str = "Confirm putting it back in the Purge security prompt.";
/// Waiting line of "Review and delete…".
pub const READING_EXPIRED: &str = "Reading what has expired…";
/// Waiting line of "Choose items…" and a whole cleanup's "Delete now".
pub const READING_HELD: &str = "Reading what this cleanup holds…";
/// Waiting line of every purge.
pub const CONFIRM_DELETE: &str = "Confirm the delete in the Purge security prompt.";
/// The waiting bar's second line.
pub const NOTHING_CHANGED_YET: &str = "Nothing has changed yet.";

/// The restore prompt was cancelled.
pub const RESTORE_DECLINED: &str = "Nothing was put back: the prompt was cancelled.";
/// The link ended during an undo.
pub const ENDED_WHILE_PUTTING_BACK: &str = "The administrator part ended while putting things back. Purge cannot tell what was put back; the list is read again.";
/// Prefix of any other failure of a restore.
pub const COULD_NOT_PUT_BACK: &str = "Couldn't put it back: ";
/// An undo that was not closed.
pub const NOT_RECORDED: &str = "The session was not recorded completely";

/// "Review and delete…" found nothing.
pub const NOTHING_EXPIRED: &str = "Nothing has passed its retention yet; nothing was deleted.";
/// A purge prompt was cancelled.
pub const DELETE_DECLINED: &str = "Nothing was deleted: the prompt was cancelled.";
/// The link ended during a purge.
pub const ENDED_DURING_DELETE: &str =
    "The administrator part ended during the delete. The list is read again.";
/// Prefix of any other failure of "Review and delete…".
pub const COULD_NOT_DELETE_EXPIRED: &str = "Couldn't delete the expired items: ";
/// A purge that deleted nothing.
pub const NOTHING_DELETED: &str = "Nothing was deleted";

/// The link ended while "Choose items…" read.
pub const ENDED_WHILE_READING: &str =
    "The administrator part ended while it read the quarantine. Nothing was changed.";
/// Prefix of any other failure of "Choose items…".
pub const COULD_NOT_READ_ITEMS: &str = "Couldn't read the quarantined items: ";

/// `gone` from a "Delete now".
pub const NO_LONGER_LISTED: &str =
    "That is no longer in quarantine as listed; nothing was deleted. The list is read again.";
/// Prefix of any other failure of a "Delete now".
pub const COULD_NOT_DELETE: &str = "Couldn't delete from quarantine: ";
/// The note of a delete that took registry backups.
pub const BACKUPS_GIVEN_UP: &str = "Its registry changes can no longer be undone.";
/// "Delete now" with the tick found nothing.
pub const NOTHING_TO_DELETE_AT_ALL: &str = "This cleanup has nothing to delete now: no quarantined files and no registry backups. A cleanup that is being put back or recovered is left alone.";
/// "Delete now" without the tick found no files.
pub const NOTHING_TO_DELETE: &str = "This cleanup has no quarantined files to delete now. Registry and task backups keep their own retention, and a cleanup that is being put back or recovered is left alone.";

/// The opt-in of a whole cleanup's "Delete now" (DECISIONS 2026-11-24), off each time it is
/// offered. It is a request: the broker asks for the backups in a prompt of their own.
pub const ALSO_BACKUPS_TEXT: &str =
    "Also delete its registry backups (its registry changes can then no longer be undone)";
/// The "Delete now" choice's intro once the files are gone.
pub const DELETE_NOW_INTRO_BACKUPS: &str = "This cleanup's files are already deleted. Its registry backups are what is left; tick the box to delete them too.";
/// The "Delete now" choice's intro.
pub const DELETE_NOW_INTRO: &str = "Deletes this cleanup's quarantined files for good, before their retention ends. Purge names every file in its security prompt first; nothing is deleted without it.";
/// The "Delete now" choice's button.
pub const CONTINUE_TO_PROMPT: &str = "Continue to the security prompt…";

/// Batch states.
pub const EXPIRED: &str = "Expired";
/// Within [`super::WARN_DAYS`] of the file retention's end.
pub const EXPIRING: &str = "Expiring";
/// Files deleted, registry backups kept.
pub const REGISTRY_ONLY: &str = "Registry undo only";
/// Partly undone.
pub const PARTLY_RESTORED: &str = "Partly restored";
/// Everything can be put back.
pub const RESTORABLE: &str = "Restorable";
/// The batch's restore button.
pub const PUT_BACK: &str = "Put back…";
/// It once the files are gone.
pub const UNDO_REGISTRY: &str = "Undo registry changes…";

/// The page's bars.
pub const READING_QUARANTINE: &str = "Reading the quarantine…";
/// The error bar's title.
pub const COULD_NOT_READ_QUARANTINE: &str = "Couldn't read the quarantine.";
/// The interrupted bar.
pub const INTERRUPTED_TITLE: &str = "An earlier cleanup was interrupted.";
/// Its text.
pub const INTERRUPTED_TEXT: &str =
    "Resume or roll it back from History & undo before the next change.";
/// Its button.
pub const OPEN_HISTORY: &str = "Open History & undo";
/// The expired bar's text.
pub const EXPIRED_TEXT: &str = "Purge offers to delete expired items and asks first in its security prompt; nothing is deleted on its own. User data is asked for one item at a time.";
/// Its button.
pub const REVIEW_AND_DELETE: &str = "Review and delete…";
/// The title of an error bar.
pub const COULD_NOT_FINISH: &str = "Couldn't finish that.";
/// Why "Review and delete…" is off while an action runs.
pub const REVIEW_WAIT: &str = "Wait until the current action has finished.";
/// Why it is off when nothing expired.
pub const REVIEW_NOTHING: &str =
    "Nothing has passed its retention yet. \"Delete now\" on a cleanup deletes it sooner.";

/// The expired bar's title.
pub fn expired_title(n: usize) -> String {
    if n == 1 {
        "One cleanup is past its retention.".into()
    } else {
        format!("{n} cleanups are past their retention.")
    }
}

/// The kept note of a purge.
pub fn kept(n: u32) -> String {
    format!("{n} kept: you declined them, or they could not be deleted.")
}

/// "N item(s)".
pub fn items(n: u32) -> String {
    format!("{n} {}", if n == 1 { "item" } else { "items" })
}
