//! Quarantine expiry: propose-only listing and the non-traversing purge walk (M2-X-EXPIRY).
//!
//! ENGINE_PLAN.md §7.8 (retention), §3.1 (irreversible verbs need a prompt naming every item).
//!
//! # Two calls, nothing automatic
//!
//! - [`expiring`] lists what is due at a given time and **proposes** only: quarantined items of an op
//!   after [`RETAIN_QUARANTINE_DAYS`](purge_model::exec::session::RETAIN_QUARANTINE_DAYS), a session's
//!   registry backups and definitions after `RETAIN_BACKUP_DAYS`, its journal after
//!   `RETAIN_JOURNAL_DAYS`, all counted from the journal header's `created`. It reads the store and the
//!   journals and changes nothing. The time is a parameter; this module reads no clock and no
//!   environment variable.
//! - [`purge`] permanently deletes quarantined items, and the registry backup and definition files of an
//!   op ([`ExpiringBackup`]). It is irreversible, so it takes a [`PurgeConsent`] that names every item,
//!   and every backup file by its session-relative path ([`PurgeConsent::name_files`]); an item whose
//!   plan candidate is user data (or whose category cannot be read back from the session's scan copy) is
//!   excluded unless the consent confirms it individually. Nothing else in Purge calls it; nothing is
//!   ever deleted on a schedule.
//!
//! Journals are listed as due ([`DueClass`]) but not purged: the store has no call to delete a session
//! directory. The backup class is listed as due as a whole too, and per op in
//! [`ExpiryListing::backups`].
//!
//! # Every session is read against its index entry
//!
//! A session's journal is read with [`journal::read_indexed`] and the [`JournalMark`] of the session's
//! index entry. A journal cut at a line boundary or replaced since the index last recorded it is never
//! taken as it reads: [`expiring`] reports the session in [`ExpiryListing::problems`] and lists nothing
//! of it, and [`purge`] refuses every item of it ([`Refused::JournalMismatch`], with an [`Alert`]). A
//! session without an entry or without a mark, and every session while the index cannot be read (it is
//! then rebuilt from the journals, not guessed), is read as it is.
//!
//! # Backup files
//!
//! An op whose intent names backup files (a registry backup, a package definition) is purged, once its
//! class is due ([`RETAIN_BACKUP_DAYS`](purge_model::exec::session::RETAIN_BACKUP_DAYS) after the
//! journal's `created`), by deleting each file through the store ([`SessionDir::delete_backup_file`]:
//! `reg\` and `def\` only, by handle, after the store's file check). Before that, never: an op that can
//! still be undone needs its backup, and the class is due for every op of the session at once. The
//! holds are those of quarantined items (an open run, an undo in progress, an op waiting for recovery
//! or with a retry in flight). The `expire` record of the backup class is written first, as for the
//! quarantine; a file left behind (a reader holding it, an I/O error) is listed as
//! [`ExpiringBackup::unfinished`] and a later [`purge`] continues without a second record.
//!
//! # The delete walk never leaves the quarantine
//!
//! This is the one recursive delete in Purge. Per item:
//!
//! 1. The op directory is reached through the store ([`SessionDir::open_op_dir`]): the whole chain from
//!    the data root is checked (owner, protected DACL, no reparse point, final path) and the directory
//!    must be on the volume the journal recorded.
//! 2. The item is opened **relative to that checked directory handle**, by its single leaf name, with
//!    `FILE_OPEN_REPARSE_POINT`. Its volume serial and file id must equal the journal's `MoveBack`
//!    record, else the item is refused with an alert and nothing is written or deleted.
//! 3. Every entry below is opened the same way: relative to the handle of its parent, which was itself
//!    verified and is held open, by the one name the directory listing of that handle returned, with
//!    `FILE_OPEN_REPARSE_POINT`. No path string is ever resolved, so no junction on any path is
//!    followed, whatever is swapped in between the listing and the open.
//! 4. Each opened entry is judged on its own handle by the guard ([`check_store_item`]): it must lie
//!    strictly inside this session's quarantine directory (lexically and by its final path), be on the
//!    item's volume, and be a plain directory to be descended into. A reparse point of **any** tag
//!    (junction, symbolic link, mount point, cloud placeholder, unknown) is only ever deleted as the link
//!    itself, through the handle that is on the link, and never listed or entered.
//! 5. The delete is a disposition on that same handle, so it removes exactly the name that was opened:
//!    for a file with hard links, the name inside the quarantine; the other names and the data stay.
//!    Read-only files are deleted with `FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE`, which changes
//!    no attribute; only where that flag is unknown is read-only cleared, through the entry's own handle
//!    and only for a file with a single name.
//! 6. Handles on the directories being emptied are opened without delete sharing, so nobody can rename
//!    them out of the quarantine while the walk works below them (NTFS also refuses to rename a directory
//!    while a handle below it is open).
//!
//! The walk is post-order with an explicit stack of directory handles (no recursion), keeps one listing
//! buffer and one batch of names at a time (never a whole tree), and stops the item at the first entry
//! it cannot open, judge or delete: the item is [`PurgeOutcome::Failed`], everything not yet deleted
//! stays in place, and a later [`purge`] continues it.
//!
//! # Journal and index
//!
//! The journal has one `expire` record per op and class and no completion record. It is written **before**
//! the walk (write-ahead): from then on the state machine refuses an undo of the op
//! (`Violation::UndoAfterExpire`), which is the safe side of a crash half way through a delete. Completion
//! is the item being gone from disk: [`expiring`] probes the store for every op with an expire record and
//! lists one whose item is still there as [`ExpiringItem::unfinished`]; [`purge`] then continues it
//! without writing a second record. A session with an undo in progress, an unfinished run, a boot-time
//! move that has not happened, or an op whose undo restored it, is not expired. After the walks, the
//! session index is updated through [`StorageRoots::update_index`] (bytes, and the quarantine or backup
//! class marked purged once every op of the session with data of that class is expired and its data
//! gone); an unavailable index is reported, never guessed ([`IndexUpdate`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;
use std::str::FromStr;

use purge_guard::live::{
    Binding, FileIdentity, PathFacts, PathStamp, Refusal, StoreCheck, StoreOp, StoreScope,
    check_store_item,
};
use purge_model::exec::journal::{Expire, Intent, ItemFacts, ReconcileResult, UndoOutcome};
use purge_model::exec::op::{ExecOp, FailCode, Inverse, ItemOutcome, OpId};
use purge_model::exec::session::{Expiry, JournalMark, RetentionClass, SessionId, SessionIndex};
use purge_model::{Blocker, CandidateId, Category, FileTime};
use purge_win::fs::FileId;
use purge_win::fs_write::FsError;
use purge_win::os::Win32Error;

use crate::fault;
use crate::journal::{
    self, JournalError, JournalState, JournalWriter, OpState, OpStatus, UndoState,
};
use crate::storage::{QuarantineDir, SCAN_FILE, SessionDir, StorageError, StorageRoots};

#[cfg(test)]
mod tests;

/// The largest session scan copy (`plan.scan.json`) read to find the category of an item. A larger or
/// unreadable copy makes every item of the session count as user data.
pub const MAX_SCAN_DOC_BYTES: u64 = 64 << 20;

/// The deepest directory nesting the walk enters below an item. Deeper trees stop the item with
/// [`WalkError::TooDeep`]; nothing below that depth is touched.
pub const MAX_WALK_DEPTH: usize = 16_384;

/// Size of the one listing buffer the walk reuses (64 KiB).
const LIST_BUFFER_BYTES: usize = 64 << 10;

// ---------------------------------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------------------------------

/// One purgeable unit: the quarantined item, or the backup files, of one op of one session (an op has
/// one or the other, never both). Spelled `<session>/<op>`
/// (`20261115T101502Z-9f3a6c1d2b7e4a50/3`) by [`fmt::Display`] and [`FromStr`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExpiryId {
    /// The session.
    pub session: SessionId,
    /// The op within the session.
    pub op: OpId,
}

impl fmt::Display for ExpiryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.session, self.op)
    }
}

/// Why a string is not an [`ExpiryId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("an expiry id needs the form <session id>/<op number>")]
pub struct ExpiryIdError;

impl FromStr for ExpiryId {
    type Err = ExpiryIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (session, op) = s.split_once('/').ok_or(ExpiryIdError)?;
        let session = session.parse::<SessionId>().map_err(|_| ExpiryIdError)?;
        let op = op.parse::<u32>().map_err(|_| ExpiryIdError)?;
        if op == 0 || op.to_string().len() != s.len() - session.as_str().len() - 1 {
            return Err(ExpiryIdError);
        }
        Ok(ExpiryId {
            session,
            op: OpId(op),
        })
    }
}

/// A quarantined item that is due: expired at the time [`expiring`] was asked about, or left
/// unfinished by an earlier [`purge`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiringItem {
    /// Which item.
    pub id: ExpiryId,
    /// The plan candidate it came from.
    pub item: CandidateId,
    /// Where the item was before it was quarantined.
    pub original_path: String,
    /// Where it is in the quarantine.
    pub quarantine_path: String,
    /// When its retention ended.
    pub expires: FileTime,
    /// The bytes the run recorded for it (its size, or its tree size when the run counted one).
    pub bytes: u64,
    /// Whether it is a directory.
    pub is_dir: bool,
    /// The plan candidate is user data, or its category could not be read back. Such an item is
    /// purged only when the consent confirms it individually ([`PurgeConsent::confirm_user_data`]).
    pub user_data: bool,
    /// An earlier purge recorded the expiry and stopped before the item was gone; [`purge`] continues.
    pub unfinished: bool,
}

/// The backup files of one op (its registry backup, its package definition) whose class is due:
/// expired at the time [`expiring`] was asked about, or left unfinished by an earlier [`purge`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiringBackup {
    /// Which op.
    pub id: ExpiryId,
    /// The plan candidate of the op.
    pub item: CandidateId,
    /// The files, by the session-relative paths the op's intent records (`reg\000042.regbackup.json`),
    /// in the intent's order. A consent must name each one ([`PurgeConsent::name_files`]).
    pub files: Vec<String>,
    /// When the backup class's retention ended.
    pub expires: FileTime,
    /// The bytes the intent recorded for the files.
    pub bytes: u64,
    /// The plan candidate is user data, or its category could not be read back; purged only when the
    /// consent confirms it individually ([`PurgeConsent::confirm_user_data`]).
    pub user_data: bool,
    /// An earlier purge recorded the expiry and stopped before every file was gone; [`purge`]
    /// continues.
    pub unfinished: bool,
}

/// Why an expired item is not offered for purging now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldReason {
    /// The session's run has neither `commit` nor `aborted`: it runs, or waits for recovery.
    SessionOpen,
    /// An undo of some op of the session is in progress: the session is being undone.
    SessionUndoInProgress,
    /// The op's boot-time move into quarantine is registered and has not happened (or was not
    /// reconciled yet): the item may still arrive.
    PendingReboot,
    /// The op has an intent and no outcome: recovery must decide it first.
    Unresolved,
}

impl fmt::Display for HoldReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HoldReason::SessionOpen => "the session's run has not ended",
            HoldReason::SessionUndoInProgress => "an undo of the session is in progress",
            HoldReason::PendingReboot => "the boot-time move has not been reconciled",
            HoldReason::Unresolved => "the op waits for recovery",
        })
    }
}

/// A whole class of a session's data that is past its retention but is not purged by this module
/// (registry backups and definitions, or the journal). Proposed only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueClass {
    /// The session.
    pub session: SessionId,
    /// [`RetentionClass::Backup`] or [`RetentionClass::Journal`].
    pub class: RetentionClass,
    /// When its retention ended.
    pub expires: FileTime,
}

/// A session [`expiring`] could not read; its items are not listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionProblem {
    /// The session, when known (a rejected directory may not have one).
    pub session: Option<SessionId>,
    /// What went wrong.
    pub detail: String,
}

/// What [`expiring`] found. Nothing was changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpiryListing {
    /// Quarantined items that may be purged now, in session and op order.
    pub items: Vec<ExpiringItem>,
    /// Quarantined items and backup files past retention that are held, with the reason.
    pub held: Vec<(ExpiryId, HoldReason)>,
    /// Backup and journal classes past retention, per session (journals are not purged by [`purge`];
    /// the backups are, per op, from [`ExpiryListing::backups`]).
    pub due: Vec<DueClass>,
    /// Sessions that could not be read, or whose journal does not match their index entry.
    pub problems: Vec<SessionProblem>,
    /// Backup files that may be purged now, per op, in session and op order.
    pub backups: Vec<ExpiringBackup>,
}

/// The consent for one irreversible [`purge`]: the items the user saw and confirmed, by id, among them
/// the user-data items confirmed one by one, and for backup files every file by name. Built by the
/// broker from its own prompt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgeConsent {
    items: BTreeSet<ExpiryId>,
    user_data: BTreeSet<ExpiryId>,
    files: BTreeMap<ExpiryId, BTreeSet<String>>,
}

impl PurgeConsent {
    /// A consent naming exactly `items`.
    pub fn naming(items: impl IntoIterator<Item = ExpiryId>) -> PurgeConsent {
        PurgeConsent {
            items: items.into_iter().collect(),
            ..PurgeConsent::default()
        }
    }

    /// Names backup files of op `id` (the session-relative paths [`ExpiringBackup::files`] lists). They
    /// count only if the consent also names `id`; [`purge`] deletes an op's backup files only when every
    /// one of them is named.
    pub fn name_files(&mut self, id: ExpiryId, files: impl IntoIterator<Item = String>) {
        self.files.entry(id).or_default().extend(files);
    }

    /// Whether `id` is named and its backup file `file` named with it (exactly as listed).
    pub fn names_file(&self, id: &ExpiryId, file: &str) -> bool {
        self.names(id) && self.files.get(id).is_some_and(|files| files.contains(file))
    }

    /// Confirms one user-data item individually. It counts only if the consent also names it.
    pub fn confirm_user_data(&mut self, id: ExpiryId) {
        self.user_data.insert(id);
    }

    /// Whether the consent names `id`.
    pub fn names(&self, id: &ExpiryId) -> bool {
        self.items.contains(id)
    }

    /// Whether `id` is named and confirmed individually as user data.
    pub fn confirms_user_data(&self, id: &ExpiryId) -> bool {
        self.names(id) && self.user_data.contains(id)
    }
}

/// Why [`purge`] refused the whole request; nothing was opened for delete and nothing was written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PurgeError {
    /// The consent does not name these requested items.
    #[error("the consent does not name {} of the requested items", .0.len())]
    NotConsented(Vec<ExpiryId>),
}

/// Why an item was left untouched on purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exclusion {
    /// The item is user data (or its category is unknown) and the consent does not confirm it
    /// individually.
    UserDataNotConfirmed,
    /// Its retention has not ended.
    NotExpired {
        /// When it ends.
        expires: FileTime,
    },
    /// The op has nothing in the quarantine (not a quarantine move, not moved, undone, or already
    /// purged) and no backup files.
    NotInQuarantine,
    /// It is held.
    Held(HoldReason),
    /// Backup files of the op the consent does not name ([`PurgeConsent::name_files`]); none of the
    /// op's files was deleted.
    FilesNotNamed {
        /// The files not named, as the intent records them.
        files: Vec<String>,
    },
}

/// Why an item was refused: something is not what the journal recorded. Nothing of it was deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The item in the quarantine has another volume serial or file id than the journal recorded.
    IdentityMismatch {
        /// What the journal recorded.
        expected: FileIdentity,
        /// What the handle showed.
        found: FileIdentity,
    },
    /// The store refused the session, the op directory or a backup file (integrity, volume, path).
    Store(StorageError),
    /// The guard refused the item itself.
    Gate(Refusal),
    /// The session's journal does not match the mark of its index entry: it was cut or replaced since
    /// the index recorded it ([`JournalError::IndexMismatch`]). Nothing of the session is touched.
    JournalMismatch(String),
}

/// Why the walk stopped at an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkError {
    /// Opening, reading or deleting the entry failed.
    Fs(FsError),
    /// The guard refused the entry ([`check_store_item`]).
    Gate(Refusal),
    /// A reopened handle was not on the object the probe handle was on.
    IdentityChanged,
    /// The nesting is deeper than [`MAX_WALK_DEPTH`].
    TooDeep,
    /// An entry name is not valid UTF-16, so its path cannot be checked.
    NameNotRepresentable,
}

/// Where and why the walk stopped. Everything not yet deleted is still in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkFailure {
    /// The entry (its path inside the quarantine).
    pub at: String,
    /// What went wrong.
    pub error: WalkError,
}

/// Why an item failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The journal could not be opened or the expire record could not be written; nothing was deleted.
    Journal(String),
    /// The store failed in a way that is not a refusal (I/O).
    Store(StorageError),
    /// The walk stopped; the expire record is written and the rest of the item stays for a later run.
    Walk(WalkFailure),
}

/// How one requested item ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurgeOutcome {
    /// The item was deleted completely.
    Purged,
    /// Nothing of the item was on disk any more; the expiry is recorded.
    AlreadyGone,
    /// Left untouched on purpose.
    Excluded(Exclusion),
    /// Refused: not what the journal recorded. Comes with an [`Alert`] when identity or volume differ.
    Refused(Refused),
    /// Failed; see [`Failure`].
    Failed(Failure),
}

/// The result for one requested item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeResult {
    /// Which item.
    pub id: ExpiryId,
    /// How it ended.
    pub outcome: PurgeOutcome,
    /// Whether this call wrote the op's `expire` record.
    pub expire_recorded: bool,
    /// Entries (files, links, directories) this call deleted.
    pub entries_deleted: u64,
    /// Bytes of single-name files this call deleted.
    pub bytes_deleted: u64,
    /// Whether the emptied op directory was removed too.
    pub op_dir_removed: bool,
}

/// Something that must be shown to the user: the quarantine does not hold what the journal says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// The item.
    pub id: ExpiryId,
    /// The path concerned.
    pub path: String,
    /// What was found.
    pub detail: String,
}

/// What became of the session index after a [`purge`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexUpdate {
    /// No expire record was written, so nothing to update.
    NotNeeded,
    /// The index was updated.
    Updated,
    /// The index is busy, lost or unreadable ([`StorageError::is_index_unavailable`]); it was not
    /// changed and must be rebuilt from the journals.
    Unavailable(StorageError),
    /// Writing the index failed otherwise; it was not changed.
    Failed(StorageError),
}

/// What [`purge`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeReport {
    /// One result per distinct requested item, in request order.
    pub items: Vec<PurgeResult>,
    /// Identity and volume mismatches found.
    pub alerts: Vec<Alert>,
    /// The session index.
    pub index: IndexUpdate,
}

// ---------------------------------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------------------------------

/// Lists what is due at `now` and changes nothing (see the module documentation). Fails only when the
/// store's layout itself is refused; a session that cannot be read is reported in
/// [`ExpiryListing::problems`].
pub fn expiring(roots: &StorageRoots, now: FileTime) -> Result<ExpiryListing, StorageError> {
    let listing_of_sessions = roots.list_sessions()?;
    let marks = index_marks(roots);
    let mut listing = ExpiryListing::default();
    for rejected in listing_of_sessions.rejected {
        listing.problems.push(SessionProblem {
            session: None,
            detail: rejected.to_string(),
        });
    }
    for id in listing_of_sessions.sessions {
        let problem = |detail: String| SessionProblem {
            session: Some(id.clone()),
            detail,
        };
        let session = match roots.open_session(&id) {
            Ok(s) => s,
            Err(e) => {
                listing.problems.push(problem(e.to_string()));
                continue;
            }
        };
        // A journal cut or replaced since its index entry was written is a problem, not a session.
        let state = match journal::read_indexed(&session, marks.get(&id)) {
            Ok(read) => read.state,
            Err(e) => {
                listing.problems.push(problem(e.to_string()));
                continue;
            }
        };
        list_session(&session, &state, now, &mut listing);
    }
    Ok(listing)
}

/// The journal mark of every session the index has one for. An index that cannot be read gives none:
/// it is rebuilt from the journals, and there is nothing in it to compare them with.
fn index_marks(roots: &StorageRoots) -> BTreeMap<SessionId, JournalMark> {
    roots
        .read_index()
        .map(|index| {
            index
                .sessions
                .into_iter()
                .filter_map(|summary| Some((summary.id, summary.journal?)))
                .collect()
        })
        .unwrap_or_default()
}

/// The backup and definition files op `op`'s intent names, by their session-relative paths, each once
/// in the intent's order; `None` when it names none.
fn backup_files(op: &OpState) -> Option<Vec<String>> {
    let intent = op.intent.as_ref()?;
    let mut files: Vec<String> = Vec::new();
    for backup in intent.backups() {
        if !files.contains(&backup.path) {
            files.push(backup.path.clone());
        }
    }
    (!files.is_empty()).then_some(files)
}

/// The bytes the intent of `op` recorded for its backup files.
fn backup_bytes_of(op: &OpState) -> u64 {
    op.intent.as_ref().map_or(0, |intent| {
        intent
            .backups()
            .fold(0u64, |sum, backup| sum.saturating_add(backup.bytes))
    })
}

/// Why the backup files of `op` are held, apart from the session's holds.
fn backup_hold(op: &OpState) -> Option<HoldReason> {
    if op.retry_in_flight || matches!(op.status(), OpStatus::IntentOnly) {
        Some(HoldReason::Unresolved)
    } else if op.undo == UndoState::InProgress {
        Some(HoldReason::SessionUndoInProgress)
    } else {
        None
    }
}

/// Whether any of the backup files `files` is still in the session, probed through the store.
fn backup_presence(session: &SessionDir, files: &[String]) -> Presence {
    let mut presence = Presence::Gone;
    for rel in files {
        match session.open_file(rel) {
            Ok(_) => return Presence::Present,
            Err(StorageError::Io {
                source: FsError::NotFound,
                ..
            }) => {}
            Err(_) => presence = Presence::Unknown,
        }
    }
    presence
}

/// Adds one session's due items and classes to `listing`.
fn list_session(
    session: &SessionDir,
    state: &JournalState,
    now: FileTime,
    listing: &mut ExpiryListing,
) {
    let expiry = Expiry::from_start(state.header().created);
    let session_hold = session_hold(state);
    let categories = Categories::read(session);
    for op in state.ops() {
        let id = ExpiryId {
            session: session.id().clone(),
            op: op.op,
        };
        let Some(record) = QuarantineRecord::of(op) else {
            continue;
        };
        if op.expired.contains(&RetentionClass::Quarantine) {
            // Expiry was recorded; the item is due until it is gone from disk.
            if presence(session, &record) == Presence::Present {
                listing
                    .items
                    .push(record.item(id, op, expiry.quarantine, &categories, true));
            }
            continue;
        }
        if expiry.quarantine > now {
            continue;
        }
        // The session's hold comes first, as in `purge`.
        match (quarantine_state(op), &session_hold) {
            (InQuarantine::No, _) => {}
            (_, Some(reason)) => listing.held.push((id, reason.clone())),
            (InQuarantine::Held(reason), None) => listing.held.push((id, reason)),
            (InQuarantine::Yes, None) => {
                listing
                    .items
                    .push(record.item(id, op, expiry.quarantine, &categories, false))
            }
        }
    }
    for op in state.ops() {
        let Some(files) = backup_files(op) else {
            continue;
        };
        let id = ExpiryId {
            session: session.id().clone(),
            op: op.op,
        };
        let entry = |unfinished: bool| ExpiringBackup {
            id: id.clone(),
            item: op.item.clone(),
            files: files.clone(),
            expires: expiry.backups,
            bytes: backup_bytes_of(op),
            user_data: categories.is_user_data(&op.item),
            unfinished,
        };
        if op.expired.contains(&RetentionClass::Backup) {
            // Expiry was recorded; the files are due until they are gone.
            if backup_presence(session, &files) == Presence::Present {
                listing.backups.push(entry(true));
            }
            continue;
        }
        if expiry.backups > now {
            continue;
        }
        match (&session_hold, backup_hold(op)) {
            (Some(reason), _) => listing.held.push((id, reason.clone())),
            (None, Some(reason)) => listing.held.push((id, reason)),
            (None, None) => listing.backups.push(entry(false)),
        }
    }
    let has_backups = state.ops().any(|op| {
        op.intent
            .as_ref()
            .is_some_and(|i| i.backups().next().is_some())
            && !op.expired.contains(&RetentionClass::Backup)
    });
    if has_backups && expiry.backups <= now {
        listing.due.push(DueClass {
            session: session.id().clone(),
            class: RetentionClass::Backup,
            expires: expiry.backups,
        });
    }
    if expiry.journal <= now {
        listing.due.push(DueClass {
            session: session.id().clone(),
            class: RetentionClass::Journal,
            expires: expiry.journal,
        });
    }
}

/// Why the whole session is held, if it is.
fn session_hold(state: &JournalState) -> Option<HoldReason> {
    if !state.is_finished() {
        Some(HoldReason::SessionOpen)
    } else if state.undo_in_progress().next().is_some() {
        Some(HoldReason::SessionUndoInProgress)
    } else {
        None
    }
}

/// What the journal says about an op's item in the quarantine.
#[derive(Debug, Clone, PartialEq, Eq)]
enum InQuarantine {
    /// The item was moved in and not moved back.
    Yes,
    /// Nothing of the op is in the quarantine.
    No,
    /// It may be, or may arrive; not decidable now.
    Held(HoldReason),
}

/// Whether the op's item sits in the quarantine, from its outcome, reconcile records and undo state.
fn quarantine_state(op: &OpState) -> InQuarantine {
    match &op.undo {
        UndoState::InProgress => return InQuarantine::Held(HoldReason::SessionUndoInProgress),
        UndoState::Finished(
            UndoOutcome::Restored | UndoOutcome::AlreadyRestored | UndoOutcome::NothingToUndo,
        ) => return InQuarantine::No,
        UndoState::NotStarted | UndoState::Finished(UndoOutcome::Failed { .. }) => {}
        UndoState::Conflict(_) => {}
    }
    let outcome = match op.status() {
        OpStatus::Validated => return InQuarantine::No,
        OpStatus::IntentOnly => return InQuarantine::Held(HoldReason::Unresolved),
        OpStatus::Done(outcome) => outcome,
    };
    match outcome {
        ItemOutcome::Done
        | ItemOutcome::Failed {
            code: FailCode::VerifyFailed,
            ..
        } => InQuarantine::Yes,
        ItemOutcome::PendingReboot { .. } => {
            match op
                .reconciles
                .iter()
                .rev()
                .find(|r| !matches!(r, ReconcileResult::StillPending))
            {
                Some(ReconcileResult::Completed) => InQuarantine::Yes,
                Some(_) => InQuarantine::No,
                None => InQuarantine::Held(HoldReason::PendingReboot),
            }
        }
        ItemOutcome::HeldRetry => match op.reconciles.iter().rev().find_map(|r| match r {
            ReconcileResult::Retried { outcome } => Some(outcome),
            _ => None,
        }) {
            Some(ItemOutcome::Done) => InQuarantine::Yes,
            Some(ItemOutcome::PendingReboot { .. }) => {
                InQuarantine::Held(HoldReason::PendingReboot)
            }
            _ => InQuarantine::No,
        },
        _ => InQuarantine::No,
    }
}

/// What the intent of a quarantine move recorded about its item.
#[derive(Debug, Clone)]
struct QuarantineRecord {
    quarantine_path: String,
    original_path: String,
    stamp: PathStamp,
    bytes: u64,
}

impl QuarantineRecord {
    /// The record of an op whose intent is a quarantine move with a `MoveBack` inverse.
    fn of(op: &OpState) -> Option<QuarantineRecord> {
        Self::of_intent(op.intent.as_ref()?)
    }

    fn of_intent(intent: &Intent) -> Option<QuarantineRecord> {
        let ExecOp::QuarantineMove { .. } = &intent.exec_op else {
            return None;
        };
        let Inverse::MoveBack {
            quarantine_path,
            original_path,
            file_id,
            volume_serial,
        } = &intent.inverse
        else {
            return None;
        };
        let ItemFacts::File(pre) = &intent.pre else {
            return None;
        };
        let bytes = if pre.is_dir {
            pre.tree_bytes.unwrap_or(0)
        } else {
            pre.size
        };
        Some(QuarantineRecord {
            quarantine_path: quarantine_path.clone(),
            original_path: original_path.clone(),
            stamp: PathStamp {
                identity: FileIdentity {
                    volume_serial: *volume_serial,
                    file_id: file_id.0,
                },
                is_dir: pre.is_dir,
            },
            bytes,
        })
    }

    fn item(
        &self,
        id: ExpiryId,
        op: &OpState,
        expires: FileTime,
        categories: &Categories,
        unfinished: bool,
    ) -> ExpiringItem {
        ExpiringItem {
            user_data: categories.is_user_data(&op.item),
            id,
            item: op.item.clone(),
            original_path: self.original_path.clone(),
            quarantine_path: self.quarantine_path.clone(),
            expires,
            bytes: self.bytes,
            is_dir: self.stamp.is_dir,
            unfinished,
        }
    }
}

/// Whether anything of an item is on disk, probed through the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    /// The item (or its op directory with it) is there.
    Present,
    /// Neither the op directory nor the item exists.
    Gone,
    /// The store could not tell (refusal or I/O).
    Unknown,
}

/// Probes the item of `record` through the checked op directory, read-only.
fn presence(session: &SessionDir, record: &QuarantineRecord) -> Presence {
    let op_dir = match open_op_dir(session, record) {
        Ok(Some(found)) => found,
        Ok(None) => return Presence::Gone,
        Err(_) => return Presence::Unknown,
    };
    match probe(&op_dir.0, &wide(&op_dir.1), true) {
        Ok(_) => Presence::Present,
        Err(FsError::NotFound) => Presence::Gone,
        Err(_) => Presence::Unknown,
    }
}

/// The op directory of `record` and the item's leaf name; `Ok(None)` when the op directory is missing.
fn open_op_dir(
    session: &SessionDir,
    record: &QuarantineRecord,
) -> Result<Option<(QuarantineDir, String)>, StorageError> {
    let op = op_of(&record.quarantine_path)
        .ok_or_else(|| StorageError::InvalidPath(record.quarantine_path.clone()))?;
    match session.open_op_dir(
        Path::new(&record.quarantine_path),
        op,
        record.stamp.identity.volume_serial,
    ) {
        Ok(found) => Ok(Some(found)),
        Err(StorageError::Io {
            source: FsError::NotFound,
            ..
        }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The op id a quarantine path names in its op directory component (`...\<session>\000042\<leaf>`).
fn op_of(quarantine_path: &str) -> Option<OpId> {
    let parent = Path::new(quarantine_path).parent()?.file_name()?.to_str()?;
    if parent.len() != 6 || !parent.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = parent.parse::<u32>().ok().filter(|n| *n != 0)?;
    Some(OpId(n))
}

/// The categories of a session's plan candidates, from its scan copy. Unknown counts as user data.
#[derive(Debug, Default)]
struct Categories {
    user_data: BTreeSet<CandidateId>,
    known: BTreeSet<CandidateId>,
}

impl Categories {
    /// Reads `plan.scan.json` through the store. An absent, oversized or unparsable copy leaves every
    /// candidate unknown.
    fn read(session: &SessionDir) -> Categories {
        let Ok(mut file) = session.open_file(SCAN_FILE) else {
            return Categories::default();
        };
        let Ok(bytes) = file.read_all(MAX_SCAN_DOC_BYTES) else {
            return Categories::default();
        };
        let Ok(doc) = serde_json::from_slice::<purge_plan::emit::ScanDoc>(&bytes) else {
            return Categories::default();
        };
        let all: BTreeMap<&CandidateId, &purge_model::Candidate> = doc
            .items
            .iter()
            .chain(&doc.absorbed)
            .map(|c| (&c.id, c))
            .collect();
        let personal = |c: &purge_model::Candidate| {
            c.category == Category::UserData || c.blockers.contains(&Blocker::UserData)
        };
        let mut categories = Categories::default();
        for candidate in &doc.items {
            categories.known.insert(candidate.id.clone());
            // A directory is user data when it or anything nested below it is.
            let nested_personal = candidate
                .children
                .iter()
                .any(|child| all.get(child).is_none_or(|c| personal(c)));
            if personal(candidate) || nested_personal {
                categories.user_data.insert(candidate.id.clone());
            }
        }
        categories
    }

    /// Whether the candidate is user data, or not found in the scan copy.
    fn is_user_data(&self, item: &CandidateId) -> bool {
        !self.known.contains(item) || self.user_data.contains(item)
    }
}

// ---------------------------------------------------------------------------------------------------
// Purge
// ---------------------------------------------------------------------------------------------------

/// Permanently deletes the quarantined items `ids` (see the module documentation). `now` is the time
/// the retention is judged at and the time the expire records carry.
///
/// Refuses the whole request when `consent` does not name every requested item. Otherwise every item
/// gets a result, and one item's refusal or failure never stops the others. Duplicate ids count once.
pub fn purge(
    roots: &StorageRoots,
    ids: &[ExpiryId],
    consent: &PurgeConsent,
    now: FileTime,
) -> Result<PurgeReport, PurgeError> {
    let mut seen = BTreeSet::new();
    let ids: Vec<&ExpiryId> = ids.iter().filter(|id| seen.insert(*id)).collect();
    let missing: Vec<ExpiryId> = ids
        .iter()
        .filter(|id| !consent.names(id))
        .map(|id| (*id).clone())
        .collect();
    if !missing.is_empty() {
        return Err(PurgeError::NotConsented(missing));
    }

    let mut by_session: BTreeMap<&SessionId, Vec<&ExpiryId>> = BTreeMap::new();
    for id in &ids {
        by_session.entry(&id.session).or_default().push(id);
    }
    let mut results: BTreeMap<ExpiryId, PurgeResult> = BTreeMap::new();
    let mut alerts = Vec::new();
    let mut changes: Vec<SessionChange> = Vec::new();
    let marks = index_marks(roots);
    for (session_id, wanted) in by_session {
        let change = purge_session(
            roots,
            session_id,
            marks.get(session_id),
            &wanted,
            consent,
            now,
            &mut results,
            &mut alerts,
        );
        if let Some(change) = change {
            changes.push(change);
        }
    }
    let index = update_index(roots, &changes);
    let items = ids.iter().filter_map(|id| results.remove(*id)).collect();
    Ok(PurgeReport {
        items,
        alerts,
        index,
    })
}

/// What the index must learn about one session.
#[derive(Debug, Clone)]
struct SessionChange {
    session: SessionId,
    /// Bytes per volume serial whose expiry this call recorded.
    freed: BTreeMap<u64, u64>,
    /// Every quarantined op of the session is expired and gone.
    quarantine_purged: bool,
    /// Every op of the session with backup files is expired and its files are gone.
    backup_purged: bool,
}

/// A result that touched nothing.
fn untouched(id: &ExpiryId, outcome: PurgeOutcome) -> PurgeResult {
    PurgeResult {
        id: id.clone(),
        outcome,
        expire_recorded: false,
        entries_deleted: 0,
        bytes_deleted: 0,
        op_dir_removed: false,
    }
}

/// Purges the requested items of one session, under one journal writer (which keeps any other writer,
/// an undo included, out until it is dropped). `mark` is the journal mark of the session's index entry.
#[allow(clippy::too_many_arguments)]
fn purge_session(
    roots: &StorageRoots,
    session_id: &SessionId,
    mark: Option<&JournalMark>,
    wanted: &[&ExpiryId],
    consent: &PurgeConsent,
    now: FileTime,
    results: &mut BTreeMap<ExpiryId, PurgeResult>,
    alerts: &mut Vec<Alert>,
) -> Option<SessionChange> {
    let mut fail_all = |outcome: PurgeOutcome| {
        for id in wanted {
            results.insert((*id).clone(), untouched(id, outcome.clone()));
        }
    };
    let session = match roots.open_session(session_id) {
        Ok(s) => s,
        Err(e @ StorageError::Integrity { .. }) => {
            fail_all(PurgeOutcome::Refused(Refused::Store(e)));
            return None;
        }
        Err(e) => {
            fail_all(PurgeOutcome::Failed(Failure::Store(e)));
            return None;
        }
    };
    // The journal as its index entry knows it, then the writer on that same journal: a writer excludes
    // other writers but also the reader, so the check comes first and the writer must find the very
    // journal that was checked (the chain value of its last line).
    let checked = match journal::read_indexed(&session, mark) {
        Ok(read) => read.head,
        Err(e @ JournalError::IndexMismatch { .. }) => {
            for id in wanted {
                alerts.push(Alert {
                    id: (*id).clone(),
                    path: session.path().display().to_string(),
                    detail: format!(
                        "the session's journal is not the one its index entry records: {e}"
                    ),
                });
            }
            fail_all(PurgeOutcome::Refused(Refused::JournalMismatch(
                e.to_string(),
            )));
            return None;
        }
        Err(e) => {
            fail_all(PurgeOutcome::Failed(Failure::Journal(e.to_string())));
            return None;
        }
    };
    let mut writer = match JournalWriter::open_append(&session) {
        Ok(w) => w,
        Err(e) => {
            fail_all(PurgeOutcome::Failed(Failure::Journal(e.to_string())));
            return None;
        }
    };
    if writer.head() != checked {
        fail_all(PurgeOutcome::Failed(Failure::Journal(
            "the journal changed between its check against the index and its opening; nothing was \
             done, try again"
                .to_owned(),
        )));
        return None;
    }
    let volume_roots: Vec<String> = writer
        .state()
        .header()
        .volumes
        .iter()
        .map(|v| v.root.clone())
        .collect();
    let scope = match roots.store_scope(session_id, &volume_roots) {
        Ok(scope) => scope,
        Err(e) => {
            fail_all(PurgeOutcome::Refused(Refused::Store(e)));
            return None;
        }
    };
    let expiry = Expiry::from_start(writer.state().header().created);
    let session_hold = session_hold(writer.state());
    let categories = Categories::read(&session);

    let mut change = SessionChange {
        session: session_id.clone(),
        freed: BTreeMap::new(),
        quarantine_purged: false,
        backup_purged: false,
    };
    let mut wrote_any = false;
    for id in wanted {
        let result = purge_one(
            &session,
            &mut writer,
            &scope,
            id,
            ItemContext {
                consent,
                categories: &categories,
                expires: expiry.quarantine,
                backups_expire: expiry.backups,
                session_hold: session_hold.as_ref(),
                now,
            },
            alerts,
        );
        if result.expire_recorded {
            wrote_any = true;
            // Quarantined bytes on the item's volume; backup files on the data root's, where the
            // session directory is.
            let freed = writer.state().op(id.op).and_then(|op| {
                QuarantineRecord::of(op)
                    .map(|record| (record.stamp.identity.volume_serial, record.bytes))
                    .or_else(|| {
                        backup_files(op)
                            .map(|_| (session.dir().volume_serial(), backup_bytes_of(op)))
                    })
            });
            if let Some((serial, bytes)) = freed {
                let slot = change.freed.entry(serial).or_insert(0);
                *slot = slot.saturating_add(bytes);
            }
        }
        results.insert((*id).clone(), result);
    }
    if !wrote_any {
        return None;
    }
    // The quarantine class of the session is purged once every quarantined op (there must be one) has
    // its expire record and nothing of it is left on disk.
    let mut quarantined = writer
        .state()
        .ops()
        .filter_map(|op| QuarantineRecord::of(op).map(|record| (op, record)))
        .peekable();
    change.quarantine_purged = quarantined.peek().is_some()
        && quarantined.all(|(op, record)| {
            if op.expired.contains(&RetentionClass::Quarantine) {
                presence(&session, &record) == Presence::Gone
            } else {
                quarantine_state(op) == InQuarantine::No
            }
        });
    // The backup class likewise, once every op with backup files (there must be one) has its expire
    // record and none of its files is left.
    let mut with_backups = writer
        .state()
        .ops()
        .filter_map(|op| backup_files(op).map(|files| (op, files)))
        .peekable();
    change.backup_purged = with_backups.peek().is_some()
        && with_backups.all(|(op, files)| {
            op.expired.contains(&RetentionClass::Backup)
                && backup_presence(&session, &files) == Presence::Gone
        });
    Some(change)
}

/// What one item is judged with besides its op.
#[derive(Clone, Copy)]
struct ItemContext<'a> {
    consent: &'a PurgeConsent,
    categories: &'a Categories,
    /// When the session's quarantine retention ends.
    expires: FileTime,
    /// When the session's backup retention ends.
    backups_expire: FileTime,
    session_hold: Option<&'a HoldReason>,
    now: FileTime,
}

/// Decides and purges one item.
fn purge_one(
    session: &SessionDir,
    writer: &mut JournalWriter,
    scope: &StoreScope,
    id: &ExpiryId,
    cx: ItemContext<'_>,
    alerts: &mut Vec<Alert>,
) -> PurgeResult {
    let excluded = |e: Exclusion| untouched(id, PurgeOutcome::Excluded(e));
    let Some(op) = writer.state().op(id.op) else {
        return excluded(Exclusion::NotInQuarantine);
    };
    let Some(record) = QuarantineRecord::of(op) else {
        return purge_backup(session, writer, id, cx, alerts);
    };
    let resume = op.expired.contains(&RetentionClass::Quarantine);
    if !resume {
        if let Some(reason) = cx.session_hold {
            return excluded(Exclusion::Held(reason.clone()));
        }
        match quarantine_state(op) {
            InQuarantine::Yes => {}
            InQuarantine::No => return excluded(Exclusion::NotInQuarantine),
            InQuarantine::Held(reason) => return excluded(Exclusion::Held(reason)),
        }
        if cx.expires > cx.now {
            return excluded(Exclusion::NotExpired {
                expires: cx.expires,
            });
        }
    }
    if cx.categories.is_user_data(&op.item) && !cx.consent.confirms_user_data(id) {
        return excluded(Exclusion::UserDataNotConfirmed);
    }

    let mut result = untouched(id, PurgeOutcome::AlreadyGone);
    let alert = |detail: String| Alert {
        id: id.clone(),
        path: record.quarantine_path.clone(),
        detail,
    };

    // 1. The op directory, checked by the store from the data root down, on the recorded volume.
    let found = match open_op_dir(session, &record) {
        Ok(found) => found,
        Err(e) => {
            if matches!(
                e,
                StorageError::VolumeMismatch { .. } | StorageError::Integrity { .. }
            ) {
                alerts.push(alert(e.to_string()));
            }
            let outcome = match e {
                StorageError::Io { .. } => PurgeOutcome::Failed(Failure::Store(e)),
                e => PurgeOutcome::Refused(Refused::Store(e)),
            };
            return untouched(id, outcome);
        }
    };
    let Some((op_dir, leaf)) = found else {
        // Nothing left of the item: record the expiry (if not yet) and report it gone.
        if !resume {
            if let Err(e) = write_expire(writer, id.op, &record, cx.now) {
                return untouched(id, PurgeOutcome::Failed(Failure::Journal(e)));
            }
            result.expire_recorded = true;
        }
        return result;
    };
    let Some(op_dir_path) = op_dir.path().to_str().map(str::to_owned) else {
        return untouched(
            id,
            PurgeOutcome::Refused(Refused::Store(StorageError::InvalidPath(
                op_dir.path().display().to_string(),
            ))),
        );
    };
    let item_path = format!(r"{}\{leaf}", op_dir_path.trim_end_matches('\\'));

    // 2. The item, opened relative to the checked op directory, by its leaf, never followed.
    let root = match probe(&op_dir, &wide(&leaf), true) {
        Ok(p) => Some(p),
        Err(FsError::NotFound) => None,
        Err(e) => {
            return untouched(
                id,
                PurgeOutcome::Failed(Failure::Walk(WalkFailure {
                    at: item_path,
                    error: WalkError::Fs(e),
                })),
            );
        }
    };
    if let Some(root) = &root {
        let found = root.identity();
        if found != record.stamp.identity {
            alerts.push(alert(format!(
                "the item in quarantine is not the recorded one: volume {:#x} id {}, recorded volume \
                 {:#x} id {}",
                found.volume_serial,
                hex(&found.file_id),
                record.stamp.identity.volume_serial,
                hex(&record.stamp.identity.file_id)
            )));
            return untouched(
                id,
                PurgeOutcome::Refused(Refused::IdentityMismatch {
                    expected: record.stamp.identity,
                    found,
                }),
            );
        }
        // The guard judges the item before anything is written: a refusal leaves it undoable.
        let op = if root.facts.is_dir && root.facts.reparse_tag == 0 {
            StoreOp::Descend
        } else {
            StoreOp::Remove
        };
        if let Err(refusal) = gate(
            scope,
            &item_path,
            op,
            Binding::Recheck(&record.stamp),
            record.stamp.identity.volume_serial,
            &root.facts,
            &root.final_path,
        ) {
            return untouched(id, PurgeOutcome::Refused(Refused::Gate(refusal)));
        }
    }

    // 3. Write-ahead: the expire record is durable before anything is deleted.
    if !resume {
        if let Err(e) = write_expire(writer, id.op, &record, cx.now) {
            return untouched(id, PurgeOutcome::Failed(Failure::Journal(e)));
        }
        result.expire_recorded = true;
    }

    // 4. The walk, from the very handle whose identity was compared.
    if let Some(root) = root {
        let mut walk = Walk::new(scope, record.stamp.identity.volume_serial);
        let done = walk.delete_item(root, item_path, record.stamp);
        result.entries_deleted = walk.entries;
        result.bytes_deleted = walk.bytes;
        match done {
            Ok(()) => result.outcome = PurgeOutcome::Purged,
            Err(failure) => {
                result.outcome = PurgeOutcome::Failed(Failure::Walk(failure));
                return result;
            }
        }
    }

    // 5. The emptied op directory goes too (it is Purge's own, inside the session's quarantine).
    result.op_dir_removed = remove_op_dir(&op_dir, &op_dir_path, scope).is_ok();
    result
}

/// Decides and deletes the backup files of one op (see "Backup files" in the module docs): holds, the
/// backup class's retention, the user-data confirmation, every file named by the consent; then the
/// `expire` record of the backup class (write-ahead, once), then each file through the store. A file
/// already gone is skipped; the first file the store refuses or fails to delete stops the op, and a
/// later purge continues it.
fn purge_backup(
    session: &SessionDir,
    writer: &mut JournalWriter,
    id: &ExpiryId,
    cx: ItemContext<'_>,
    alerts: &mut Vec<Alert>,
) -> PurgeResult {
    let excluded = |e: Exclusion| untouched(id, PurgeOutcome::Excluded(e));
    let Some(op) = writer.state().op(id.op) else {
        return excluded(Exclusion::NotInQuarantine);
    };
    let Some(files) = backup_files(op) else {
        return excluded(Exclusion::NotInQuarantine);
    };
    let bytes = backup_bytes_of(op);
    let resume = op.expired.contains(&RetentionClass::Backup);
    if !resume {
        if let Some(reason) = cx.session_hold {
            return excluded(Exclusion::Held(reason.clone()));
        }
        if let Some(reason) = backup_hold(op) {
            return excluded(Exclusion::Held(reason));
        }
        // Never before the class is due: until then the op may be undone from these files.
        if cx.backups_expire > cx.now {
            return excluded(Exclusion::NotExpired {
                expires: cx.backups_expire,
            });
        }
    }
    if cx.categories.is_user_data(&op.item) && !cx.consent.confirms_user_data(id) {
        return excluded(Exclusion::UserDataNotConfirmed);
    }
    let not_named: Vec<String> = files
        .iter()
        .filter(|file| !cx.consent.names_file(id, file))
        .cloned()
        .collect();
    if !not_named.is_empty() {
        return excluded(Exclusion::FilesNotNamed { files: not_named });
    }

    let mut result = untouched(id, PurgeOutcome::AlreadyGone);
    // Write-ahead: from here on the op is not undone (`Violation::UndoAfterExpire`).
    if !resume {
        let expire = Expire {
            at: cx.now,
            op: id.op,
            class: RetentionClass::Backup,
            bytes,
        };
        if let Err(e) = writer.expire(expire) {
            return untouched(id, PurgeOutcome::Failed(Failure::Journal(e.to_string())));
        }
        result.expire_recorded = true;
    }
    for rel in &files {
        match session.delete_backup_file(rel) {
            Ok(Some(size)) => {
                result.entries_deleted += 1;
                result.bytes_deleted = result.bytes_deleted.saturating_add(size);
            }
            Ok(None) => {}
            Err(e) => {
                if matches!(e, StorageError::Integrity { .. }) {
                    alerts.push(Alert {
                        id: id.clone(),
                        path: session.path().join(rel).display().to_string(),
                        detail: e.to_string(),
                    });
                }
                result.outcome = match e {
                    StorageError::Io { .. } => PurgeOutcome::Failed(Failure::Store(e)),
                    e => PurgeOutcome::Refused(Refused::Store(e)),
                };
                return result;
            }
        }
    }
    if result.entries_deleted > 0 {
        result.outcome = PurgeOutcome::Purged;
    }
    result
}

/// Writes and flushes the op's `expire` record of the quarantine class.
fn write_expire(
    writer: &mut JournalWriter,
    op: OpId,
    record: &QuarantineRecord,
    now: FileTime,
) -> Result<(), String> {
    writer
        .expire(Expire {
            at: now,
            op,
            class: RetentionClass::Quarantine,
            bytes: record.bytes,
        })
        .map_err(|e| e.to_string())
}

/// Removes the op directory if it is empty, through a handle reopened on the checked one.
fn remove_op_dir(
    op_dir: &QuarantineDir,
    path: &str,
    scope: &StoreScope,
) -> Result<(), WalkFailure> {
    let fail = |error| WalkFailure {
        at: path.to_owned(),
        error,
    };
    let checked = op_dir.dir().file_id();
    let stamp = PathStamp {
        identity: FileIdentity {
            volume_serial: checked.volume_serial,
            file_id: checked.id,
        },
        is_dir: true,
    };
    let handle = reopen(op_dir, ACCESS_DELETE, SHARE_READ_WRITE, FILE_DIRECTORY_FILE)
        .map_err(|e| fail(WalkError::Fs(e)))?;
    let facts = read_facts(&handle).map_err(|e| fail(WalkError::Fs(e)))?;
    let final_path = final_path(&handle).map_err(|e| fail(WalkError::Fs(e)))?;
    gate(
        scope,
        path,
        StoreOp::Remove,
        Binding::Recheck(&stamp),
        checked.volume_serial,
        &facts,
        &final_path,
    )
    .map_err(|r| fail(WalkError::Gate(r)))?;
    log_delete_open(&final_path);
    dispose(&handle, &facts).map_err(|e| fail(WalkError::Fs(e)))
}

// ---------------------------------------------------------------------------------------------------
// Index
// ---------------------------------------------------------------------------------------------------

/// Applies the sessions' changes to the index through the store.
fn update_index(roots: &StorageRoots, changes: &[SessionChange]) -> IndexUpdate {
    if changes.is_empty() {
        return IndexUpdate::NotNeeded;
    }
    match roots.update_index(|index| apply_changes(index, changes)) {
        Ok(_) => IndexUpdate::Updated,
        Err(e) if e.is_index_unavailable() => IndexUpdate::Unavailable(e),
        Err(e) => IndexUpdate::Failed(e),
    }
}

/// Subtracts the freed bytes and marks the quarantine class purged where it is.
fn apply_changes(index: &mut SessionIndex, changes: &[SessionChange]) {
    for change in changes {
        let Some(summary) = index.sessions.iter_mut().find(|s| s.id == change.session) else {
            continue;
        };
        for (serial, bytes) in &change.freed {
            summary.backup_bytes = summary.backup_bytes.saturating_sub(*bytes);
            for usage in summary.usage.iter_mut().filter(|u| u.serial == *serial) {
                usage.bytes = usage.bytes.saturating_sub(*bytes);
            }
        }
        if change.quarantine_purged && !summary.purged.contains(&RetentionClass::Quarantine) {
            summary.purged.push(RetentionClass::Quarantine);
        }
        if change.backup_purged && !summary.purged.contains(&RetentionClass::Backup) {
            summary.purged.push(RetentionClass::Backup);
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------------------------------

/// One directory on the walk's stack: the handle it is emptied through (list and delete access, no
/// delete sharing) and the identity it was judged with.
struct Frame {
    handle: OwnedHandle,
    stamp: PathStamp,
    /// Length of the walk's path before this directory's name was appended.
    parent_len: usize,
}

/// The post-order delete of one item.
struct Walk<'a> {
    scope: &'a StoreScope,
    volume_serial: u64,
    /// The path of the entry being worked on (the top frame, or a child of it).
    path: String,
    buffer: Vec<u64>,
    entries: u64,
    bytes: u64,
}

/// What [`Walk::act`] made of an entry.
enum Step {
    /// The entry is deleted (or was already gone).
    Removed,
    /// The entry is a plain directory, opened to be emptied.
    Descend(Frame),
}

impl<'a> Walk<'a> {
    fn new(scope: &'a StoreScope, volume_serial: u64) -> Walk<'a> {
        Walk {
            scope,
            volume_serial,
            path: String::new(),
            buffer: vec![0u64; LIST_BUFFER_BYTES / 8],
            entries: 0,
            bytes: 0,
        }
    }

    fn fail(&self, error: WalkError) -> WalkFailure {
        WalkFailure {
            at: self.path.clone(),
            error,
        }
    }

    /// Deletes the item behind `root` (probed at `root_path`) and everything below it.
    fn delete_item(
        &mut self,
        root: Probe,
        root_path: String,
        recorded: PathStamp,
    ) -> Result<(), WalkFailure> {
        self.path = root_path;
        let mut stack: Vec<Frame> = Vec::new();
        match self.act(root, Binding::Recheck(&recorded))? {
            Step::Removed => return Ok(()),
            Step::Descend(frame) => stack.push(frame),
        }
        while let Some(top) = stack.last() {
            let listed = read_batch(&top.handle, &mut self.buffer);
            let names = listed.map_err(|e| self.fail(WalkError::Fs(e)))?;
            after_listing(&self.path);
            fault::point(fault::EXPIRY_MID);
            if names.is_empty() {
                let Some(frame) = stack.pop() else { break };
                self.remove_dir(&frame)?;
                self.path.truncate(frame.parent_len);
                continue;
            }
            let depth = stack.len() - 1;
            // An entry listed and then not found is skipped; a batch of nothing but such entries
            // stops the item, so that a name that lists but never opens cannot loop.
            let mut progress = false;
            let mut vanished = None;
            for name in names {
                let parent_len = self.path.len();
                let text = String::from_utf16(&name)
                    .map_err(|_| self.fail(WalkError::NameNotRepresentable))?;
                self.path.push('\\');
                self.path.push_str(&text);
                let step = match probe(&stack[depth].handle, &name, false) {
                    Ok(p) => self.act(p, Binding::Capture)?,
                    Err(FsError::NotFound) => {
                        vanished = Some(self.path.clone());
                        self.path.truncate(parent_len);
                        continue;
                    }
                    Err(e) => return Err(self.fail(WalkError::Fs(e))),
                };
                progress = true;
                match step {
                    Step::Removed => self.path.truncate(parent_len),
                    Step::Descend(mut frame) => {
                        if stack.len() >= MAX_WALK_DEPTH {
                            return Err(self.fail(WalkError::TooDeep));
                        }
                        frame.parent_len = parent_len;
                        stack.push(frame);
                        // The new directory is listed first; this batch is read again afterwards.
                        break;
                    }
                }
            }
            if let (false, Some(at)) = (progress, vanished) {
                return Err(WalkFailure {
                    at,
                    error: WalkError::Fs(FsError::NotFound),
                });
            }
        }
        Ok(())
    }

    /// Judges the probed entry at `self.path` on its handle and deletes it, or opens it for descent.
    fn act(&mut self, probe: Probe, binding: Binding<'_, PathStamp>) -> Result<Step, WalkFailure> {
        let Probe {
            handle: probe_handle,
            facts,
            final_path,
        } = probe;
        let plain_dir = facts.is_dir && facts.reparse_tag == 0;
        let op = if plain_dir {
            StoreOp::Descend
        } else {
            StoreOp::Remove
        };
        gate(
            self.scope,
            &self.path,
            op,
            binding,
            self.volume_serial,
            &facts,
            &final_path,
        )
        .map_err(|r| self.fail(WalkError::Gate(r)))?;
        if plain_dir {
            let handle = reopen(
                &probe_handle,
                ACCESS_DELETE | FILE_LIST_DIRECTORY,
                SHARE_READ_WRITE,
                FILE_DIRECTORY_FILE,
            )
            .map_err(|e| self.fail(WalkError::Fs(e)))?;
            let again = read_facts(&handle).map_err(|e| self.fail(WalkError::Fs(e)))?;
            if again.file_id != facts.file_id || again.reparse_tag != 0 || !again.is_dir {
                return Err(self.fail(WalkError::IdentityChanged));
            }
            log_delete_open(&final_path);
            return Ok(Step::Descend(Frame {
                handle,
                stamp: stamp_of(&facts),
                parent_len: 0,
            }));
        }
        // A file, or a reparse point of any tag: the handle is on the object itself (the link, never
        // its target), and the disposition removes exactly the name it was opened by.
        let handle = reopen(&probe_handle, ACCESS_DELETE, SHARE_READ_WRITE, 0)
            .map_err(|e| self.fail(WalkError::Fs(e)))?;
        let again = read_facts(&handle).map_err(|e| self.fail(WalkError::Fs(e)))?;
        if again.file_id != facts.file_id || again.reparse_tag != facts.reparse_tag {
            return Err(self.fail(WalkError::IdentityChanged));
        }
        log_delete_open(&final_path);
        dispose(&handle, &again).map_err(|e| self.fail(WalkError::Fs(e)))?;
        drop(handle);
        drop(probe_handle);
        self.entries += 1;
        if facts.reparse_tag == 0 && facts.n_links == 1 {
            self.bytes = self.bytes.saturating_add(facts.size);
        }
        Ok(Step::Removed)
    }

    /// Removes an emptied directory through its own handle, after judging it again.
    fn remove_dir(&mut self, frame: &Frame) -> Result<(), WalkFailure> {
        let facts = read_facts(&frame.handle).map_err(|e| self.fail(WalkError::Fs(e)))?;
        let final_path = final_path(&frame.handle).map_err(|e| self.fail(WalkError::Fs(e)))?;
        gate(
            self.scope,
            &self.path,
            StoreOp::Remove,
            Binding::Recheck(&frame.stamp),
            self.volume_serial,
            &facts,
            &final_path,
        )
        .map_err(|r| self.fail(WalkError::Gate(r)))?;
        dispose(&frame.handle, &facts).map_err(|e| self.fail(WalkError::Fs(e)))?;
        self.entries += 1;
        Ok(())
    }
}

/// The guard's verdict for an entry from the facts of its handle.
fn gate(
    scope: &StoreScope,
    path: &str,
    op: StoreOp,
    binding: Binding<'_, PathStamp>,
    volume_serial: u64,
    facts: &Facts,
    final_path: &str,
) -> Result<(), Refusal> {
    let path_facts = PathFacts {
        final_path: Some(final_path.to_owned()),
        reparse_tag: Some(facts.reparse_tag),
        attributes: Some(facts.attributes),
        identity: Some(identity_of(&facts.file_id)),
        n_links: Some(facts.n_links),
        is_dir: Some(facts.is_dir),
        ..PathFacts::default()
    };
    check_store_item(
        &StoreCheck {
            path,
            op,
            binding,
            volume_serial,
        },
        &path_facts,
        scope,
    )
}

fn identity_of(id: &FileId) -> FileIdentity {
    FileIdentity {
        volume_serial: id.volume_serial,
        file_id: id.id,
    }
}

fn stamp_of(facts: &Facts) -> PathStamp {
    PathStamp {
        identity: identity_of(&facts.file_id),
        is_dir: facts.is_dir,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

// ---------------------------------------------------------------------------------------------------
// Test hooks
// ---------------------------------------------------------------------------------------------------

/// A test hook called with a directory's path.
#[cfg(test)]
type ListingHook = Box<dyn FnMut(&str)>;

#[cfg(test)]
thread_local! {
    /// Called with the directory's path after each listing, before any listed entry is opened.
    static AFTER_LISTING: std::cell::RefCell<Option<ListingHook>> =
        const { std::cell::RefCell::new(None) };
    /// The final path of every object opened with delete access, in order.
    static DELETE_OPENS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn after_listing(path: &str) {
    let hook = AFTER_LISTING.with(|h| h.borrow_mut().take());
    if let Some(mut hook) = hook {
        hook(path);
        AFTER_LISTING.with(|h| *h.borrow_mut() = Some(hook));
    }
}

#[cfg(not(test))]
#[inline(always)]
fn after_listing(_path: &str) {}

#[cfg(test)]
fn log_delete_open(final_path: &str) {
    DELETE_OPENS.with(|log| log.borrow_mut().push(final_path.to_owned()));
}

#[cfg(not(test))]
#[inline(always)]
fn log_delete_open(_final_path: &str) {}

// ---------------------------------------------------------------------------------------------------
// Handle-relative file calls (purge-exec has no windows-sys dependency; purge-win opens by path only)
// ---------------------------------------------------------------------------------------------------

type Handle = *mut core::ffi::c_void;

/// `DELETE | FILE_READ_ATTRIBUTES`.
const ACCESS_DELETE: u32 = 0x0001_0000 | FILE_READ_ATTRIBUTES;
/// `FILE_READ_ATTRIBUTES`.
const FILE_READ_ATTRIBUTES: u32 = 0x80;
/// `FILE_WRITE_ATTRIBUTES`.
const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
/// `FILE_LIST_DIRECTORY`.
const FILE_LIST_DIRECTORY: u32 = 0x1;
/// `SYNCHRONIZE`.
const SYNCHRONIZE: u32 = 0x0010_0000;
/// `FILE_SHARE_READ | FILE_SHARE_WRITE`: no delete sharing, so nobody renames or deletes the object
/// while the walk holds it.
const SHARE_READ_WRITE: u32 = 0x3;
/// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`.
const SHARE_ALL: u32 = 0x7;
/// `FILE_OPEN`.
const FILE_OPEN: u32 = 1;
/// `FILE_DIRECTORY_FILE`.
const FILE_DIRECTORY_FILE: u32 = 0x1;
/// `FILE_SYNCHRONOUS_IO_NONALERT`.
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
/// `FILE_OPEN_REPARSE_POINT`: a reparse point is opened itself, never followed.
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// `OBJ_CASE_INSENSITIVE`.
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
/// `FILE_ATTRIBUTE_READONLY`.
const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
/// `FILE_ATTRIBUTE_DIRECTORY`.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
/// `FILE_ATTRIBUTE_NORMAL`.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// `FileBasicInfo`.
const CLASS_BASIC: i32 = 0;
/// `FileStandardInfo`.
const CLASS_STANDARD: i32 = 1;
/// `FileDispositionInfo`.
const CLASS_DISPOSITION: i32 = 4;
/// `FileAttributeTagInfo`.
const CLASS_ATTRIBUTE_TAG: i32 = 9;
/// `FileFullDirectoryRestartInfo`: the first batch of a listing, from the start.
const CLASS_FULL_DIRECTORY_RESTART: i32 = 15;
/// `FileIdInfo`.
const CLASS_ID: i32 = 18;
/// `FileDispositionInfoEx`.
const CLASS_DISPOSITION_EX: i32 = 21;

/// `FILE_DISPOSITION_FLAG_DELETE`.
const DISPOSITION_DELETE: u32 = 0x1;
/// `FILE_DISPOSITION_FLAG_POSIX_SEMANTICS`: the name goes when this handle closes.
const DISPOSITION_POSIX: u32 = 0x2;
/// `FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE`: delete a read-only file without changing it.
const DISPOSITION_IGNORE_READONLY: u32 = 0x10;

/// `ERROR_NO_MORE_FILES`.
const ERROR_NO_MORE_FILES: u32 = 18;
/// Offset of `FileNameLength` in `FILE_FULL_DIR_INFO`.
const DIR_NAME_LENGTH_OFFSET: usize = 60;
/// Offset of `FileName` in `FILE_FULL_DIR_INFO`.
const DIR_NAME_OFFSET: usize = 68;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: Handle,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: *const core::ffi::c_void,
    security_quality_of_service: *const core::ffi::c_void,
}

#[repr(C)]
#[derive(Default)]
struct IoStatusBlock {
    status: usize,
    information: usize,
}

#[repr(C)]
#[derive(Default)]
struct BasicInfo {
    creation: i64,
    last_access: i64,
    last_write: i64,
    change: i64,
    attributes: u32,
}

#[repr(C)]
#[derive(Default)]
struct StandardInfo {
    allocation_size: i64,
    end_of_file: i64,
    number_of_links: u32,
    delete_pending: u8,
    directory: u8,
}

#[repr(C)]
#[derive(Default)]
struct AttributeTagInfo {
    attributes: u32,
    reparse_tag: u32,
}

#[repr(C)]
#[derive(Default)]
struct IdInfo {
    volume_serial: u64,
    file_id: [u8; 16],
}

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    /// `NtCreateFile`: the only call that opens a name relative to a directory handle.
    fn NtCreateFile(
        file: *mut Handle,
        access: u32,
        attributes: *const ObjectAttributes,
        io_status: *mut IoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
        ea: *const core::ffi::c_void,
        ea_length: u32,
    ) -> i32;
    /// `RtlNtStatusToDosError`.
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn GetFileInformationByHandleEx(
        file: Handle,
        class: i32,
        info: *mut core::ffi::c_void,
        size: u32,
    ) -> i32;
    fn SetFileInformationByHandle(
        file: Handle,
        class: i32,
        info: *const core::ffi::c_void,
        size: u32,
    ) -> i32;
    fn GetFinalPathNameByHandleW(file: Handle, path: *mut u16, len: u32, flags: u32) -> u32;
    fn GetLastError() -> u32;
}

fn last_error() -> FsError {
    // SAFETY: reads the calling thread's last-error value; no preconditions.
    FsError::from(Win32Error(unsafe { GetLastError() }))
}

/// Whether an information class was refused as unknown, so that an older one may be tried.
fn class_unsupported(e: FsError) -> bool {
    matches!(e, FsError::Other(1 | 50 | 87))
}

/// `NtCreateFile(FILE_OPEN)` of `name` relative to the directory (or, for an empty name, the object)
/// behind `root`, always with `FILE_OPEN_REPARSE_POINT` and synchronous I/O. Names are matched
/// exactly unless `case_insensitive`.
fn open_rel(
    root: &impl AsHandle,
    name: &[u16],
    access: u32,
    share: u32,
    options: u32,
    case_insensitive: bool,
) -> Result<OwnedHandle, FsError> {
    if name
        .iter()
        .any(|&u| u == 0 || u == u16::from(b'\\') || u == u16::from(b'/'))
        || name == [u16::from(b'.')]
        || name == [u16::from(b'.'), u16::from(b'.')]
    {
        return Err(FsError::Other(87));
    }
    let Ok(bytes) = u16::try_from(name.len() * 2) else {
        return Err(FsError::Other(206));
    };
    let unicode = UnicodeString {
        length: bytes,
        maximum_length: bytes,
        buffer: if name.is_empty() {
            ptr::null()
        } else {
            name.as_ptr()
        },
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: root.as_handle().as_raw_handle(),
        object_name: &unicode,
        attributes: if case_insensitive {
            OBJ_CASE_INSENSITIVE
        } else {
            0
        },
        security_descriptor: ptr::null(),
        security_quality_of_service: ptr::null(),
    };
    let mut handle: Handle = ptr::null_mut();
    let mut io = IoStatusBlock::default();
    // SAFETY: `attributes` points to live locals (`unicode`, whose buffer `name` outlives the call);
    // the root handle is borrowed for the call; `handle` and `io` are writable; no allocation size, no
    // extended attributes, no security descriptor (FILE_OPEN never creates).
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes,
            &mut io,
            ptr::null(),
            0,
            share,
            FILE_OPEN,
            options | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: a pure status-to-code mapping.
        return Err(FsError::from(Win32Error(unsafe {
            RtlNtStatusToDosError(status)
        })));
    }
    // SAFETY: a successful NtCreateFile returned a fresh handle that nobody else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// A second handle on the very object behind `h` (an empty name relative to it), with other access.
fn reopen(
    h: &impl AsHandle,
    access: u32,
    share: u32,
    options: u32,
) -> Result<OwnedHandle, FsError> {
    open_rel(h, &[], access, share, options, false)
}

/// An entry opened only to look at it: attribute read, full sharing, never followed.
struct Probe {
    handle: OwnedHandle,
    facts: Facts,
    final_path: String,
}

impl Probe {
    fn identity(&self) -> FileIdentity {
        identity_of(&self.facts.file_id)
    }
}

/// Opens `name` in the directory behind `dir` without following it and reads its facts.
fn probe(dir: &impl AsHandle, name: &[u16], case_insensitive: bool) -> Result<Probe, FsError> {
    if name.is_empty() {
        return Err(FsError::Other(87));
    }
    let handle = open_rel(
        dir,
        name,
        FILE_READ_ATTRIBUTES,
        SHARE_ALL,
        0,
        case_insensitive,
    )?;
    let facts = read_facts(&handle)?;
    let final_path = final_path(&handle)?;
    Ok(Probe {
        handle,
        facts,
        final_path,
    })
}

fn info<T: Default>(h: &impl AsHandle, class: i32) -> Result<T, FsError> {
    let mut out = T::default();
    // SAFETY: the handle is live for the call; `out` is a writable, aligned value of exactly the size
    // passed, of the layout the class documents.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            h.as_handle().as_raw_handle(),
            class,
            (&mut out as *mut T).cast(),
            size_of::<T>() as u32,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(out)
}

/// What the walk reads from a handle.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Facts {
    attributes: u32,
    reparse_tag: u32,
    is_dir: bool,
    n_links: u32,
    size: u64,
    file_id: FileId,
}

fn read_facts(h: &impl AsHandle) -> Result<Facts, FsError> {
    let basic: BasicInfo = info(h, CLASS_BASIC)?;
    let standard: StandardInfo = info(h, CLASS_STANDARD)?;
    let tag: AttributeTagInfo = info(h, CLASS_ATTRIBUTE_TAG)?;
    let id: IdInfo = info(h, CLASS_ID)?;
    Ok(Facts {
        attributes: basic.attributes,
        reparse_tag: if tag.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            tag.reparse_tag
        } else {
            0
        },
        is_dir: standard.directory != 0 || basic.attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        n_links: standard.number_of_links,
        size: u64::try_from(standard.end_of_file).unwrap_or(0),
        file_id: FileId {
            volume_serial: id.volume_serial,
            id: id.file_id,
        },
    })
}

/// `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)`, in `\\?\C:\...` form.
fn final_path(h: &impl AsHandle) -> Result<String, FsError> {
    let mut buf = vec![0u16; 512];
    loop {
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: the handle is live; `buf` has `len` writable units.
        let n = unsafe {
            GetFinalPathNameByHandleW(h.as_handle().as_raw_handle(), buf.as_mut_ptr(), len, 0)
        };
        if n == 0 {
            return Err(last_error());
        }
        let n = n as usize;
        if n < buf.len() {
            return Ok(String::from_utf16_lossy(&buf[..n]));
        }
        if buf.len() > 1 << 16 {
            return Err(FsError::Other(206));
        }
        buf.resize(n + 1, 0);
    }
}

fn set_info<T>(h: &impl AsHandle, class: i32, value: &T) -> Result<(), FsError> {
    // SAFETY: `value` points to `size_of::<T>()` readable bytes; callers pair each class with its
    // documented struct; the handle is live for the call.
    let ok = unsafe {
        SetFileInformationByHandle(
            h.as_handle().as_raw_handle(),
            class,
            ptr::from_ref(value).cast(),
            size_of::<T>() as u32,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Marks the object behind `h` (opened with `DELETE`) for deletion; its name goes when the handle
/// closes. A read-only object is deleted without changing its attributes where the system supports
/// that; elsewhere read-only is cleared through this handle's object only when it has a single name.
fn dispose(h: &impl AsHandle, facts: &Facts) -> Result<(), FsError> {
    let flags = DISPOSITION_DELETE | DISPOSITION_POSIX | DISPOSITION_IGNORE_READONLY;
    match set_info(h, CLASS_DISPOSITION_EX, &flags) {
        Ok(()) => return Ok(()),
        Err(e) if class_unsupported(e) => {}
        Err(e) => return Err(e),
    }
    let flags = DISPOSITION_DELETE | DISPOSITION_POSIX;
    match set_info(h, CLASS_DISPOSITION_EX, &flags) {
        Ok(()) => return Ok(()),
        Err(e) if class_unsupported(e) || e == FsError::AccessDenied => {}
        Err(e) => return Err(e),
    }
    if facts.attributes & FILE_ATTRIBUTE_READONLY != 0 {
        if facts.n_links != 1 {
            // Attributes belong to the file, not the name: clearing them would change the other
            // names, which may lie outside the quarantine.
            return Err(FsError::AccessDenied);
        }
        clear_readonly(h, facts.attributes)?;
    }
    let delete: u8 = 1;
    set_info(h, CLASS_DISPOSITION, &delete)
}

/// Clears read-only on the object behind `h`, through a handle reopened on it.
fn clear_readonly(h: &impl AsHandle, attributes: u32) -> Result<(), FsError> {
    let writer = reopen(
        h,
        FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES,
        SHARE_ALL,
        0,
    )?;
    let wanted = attributes & !FILE_ATTRIBUTE_READONLY & !FILE_ATTRIBUTE_DIRECTORY;
    let basic = BasicInfo {
        // Zero times mean "leave unchanged"; zero attributes too, so NORMAL clears them.
        attributes: if wanted == 0 {
            FILE_ATTRIBUTE_NORMAL
        } else {
            wanted
        },
        ..BasicInfo::default()
    };
    set_info(&writer, CLASS_BASIC, &basic)
}

/// The first batch of entry names of the directory behind `dir`, listed from the start
/// (`FileFullDirectoryRestartInfo`), without `.` and `..`. Empty when the directory is empty. One
/// buffer is reused; a batch holds what fits in it.
fn read_batch(dir: &impl AsHandle, buffer: &mut [u64]) -> Result<Vec<Vec<u16>>, FsError> {
    let size = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
    // SAFETY: the handle is live; `buffer` has `size` writable bytes, 8-byte aligned, which
    // FILE_FULL_DIR_INFO records need.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            dir.as_handle().as_raw_handle(),
            CLASS_FULL_DIRECTORY_RESTART,
            buffer.as_mut_ptr().cast(),
            size,
        )
    };
    if ok == 0 {
        return match last_error() {
            FsError::Other(ERROR_NO_MORE_FILES) => Ok(Vec::new()),
            e => Err(e),
        };
    }
    let bytes: &[u8] =
        // SAFETY: `buffer` is `buffer.len() * 8` initialised bytes; u8 has no alignment needs.
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buffer.len() * 8) };
    parse_names(bytes).ok_or(FsError::Other(13))
}

/// Decodes a chain of `FILE_FULL_DIR_INFO` records into names, without `.` and `..`.
fn parse_names(bytes: &[u8]) -> Option<Vec<Vec<u16>>> {
    let u32_at = |o: usize| Some(u32::from_le_bytes(bytes.get(o..o + 4)?.try_into().ok()?));
    let mut names = Vec::new();
    let mut off = 0usize;
    loop {
        let next = u32_at(off)? as usize;
        let len = u32_at(off + DIR_NAME_LENGTH_OFFSET)? as usize;
        let start = off.checked_add(DIR_NAME_OFFSET)?;
        let name: Vec<u16> = bytes
            .get(start..start.checked_add(len)?)?
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let dot = u16::from(b'.');
        if name != [dot] && name != [dot, dot] {
            names.push(name);
        }
        if next == 0 {
            return Some(names);
        }
        off = off.checked_add(next)?;
    }
}
