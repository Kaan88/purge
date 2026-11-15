//! Registry backup `regbackup/1`: link-refusing walk, verified write, restore (M2-X-REGBACKUP).
//!
//! ENGINE_PLAN.md §7.4, §7.5, §7.8. This module turns live keys into `purge.regbackup/1` documents and back,
//! and it is the only place that deletes a key tree. Its rules:
//!
//! - **Capture refuses what it cannot put back.** [`capture_tree`] walks the subtree itself, one handle
//!   per key, every open with `REG_OPTION_OPEN_LINK` (through [`WKey`]). Any registry link anywhere in the
//!   subtree, a name that is not valid UTF-16 or holds a NUL, a volatile key, a `REG_LINK` value, or more
//!   keys than the caller's blast-radius limit ends the capture with a typed [`CaptureError`]; the item is
//!   then skipped and nothing is deleted.
//! - **No verified backup, no delete.** [`write_verified`] writes the document, flushes it, closes it,
//!   reads it back, parses it, compares it with what was meant to be written and hashes the bytes read.
//!   Only that path and [`read_verified`] (which checks size and SHA-256 against the journal's
//!   [`BackupRef`] before parsing) produce a [`VerifiedBackup`], and every function that deletes or
//!   restores takes one. Both go through the store's checked handles only ([`SessionDir::create_file`],
//!   [`SessionDir::open_file`], [`StoreFile`](crate::storage::StoreFile)); no file inside the store is
//!   opened, created, flushed or removed here by path.
//! - **One route to a key.** Nothing here maps a key path to a key: restores act below the parent the
//!   gate opened and checked ([`CheckedKeyParent`], [`CheckedValueKey`] from `gate::check_undo_key`), and
//!   a tree restore refuses a parent whose leaf is not the backup's root key
//!   ([`RestoreError::NotThisKey`]). The backup
//!   document records the plan's spelling of the key (`RegBackup::key`); the `purge.regbackup/1` schema
//!   has no field for the canonical address the gate opened, so undo derives that address again from the
//!   journalled target through the gate's probe, the route the delete took.
//! - **Deletes act on inspected handles.** [`delete_tree`] reopens every key of the backup below the
//!   caller's root handle, compares it with its backup node, and deletes that same handle, deepest first.
//!   A key that became a link, gained a subkey or a value, or changed its data, class or security stops the
//!   walk ([`Change`]); the keys already deleted are then put back from the backup, so a subtree goes
//!   whole or not at all. A key that is not in the backup is never opened. A resumed delete
//!   ([`finish_delete_tree`]) that stops says how many keys an earlier, interrupted run had deleted and
//!   are still missing ([`Rollback::PartialBefore`]); [`restore_missing`] puts exactly those back.
//! - **Restore never forces.** [`restore_tree`] recreates keys with their recorded class and security
//!   descriptor (applied atomically at creation), and follows the conflict rules of §7.8: an existing key
//!   under `Installer`, `Services` or a COM root is a conflict, elsewhere an existing key is merged into only
//!   when it is empty. A failure rolls back the keys created so far. An owner the token may not assign is
//!   left to the token and reported ([`DifferenceKind::OwnerNotRestored`]); no privilege is enabled.
//! - **Segments** of `;` lists and `REG_MULTI_SZ` values are removed in one read-modify-write that keeps
//!   type and terminators ([`plan_segment_removal`], [`apply_segment_removal`]) and put back only while the
//!   value is what Purge wrote or merely lacks the segment ([`reinsert_segment`]).
//!
//! The last write time of a key cannot be set and is not compared. Every value is read through [`WKey`],
//! whose reads are exact; the Win32 reads of `reg::Key` may change the last byte of odd-length strings.

use std::collections::{HashMap, HashSet};
use std::io::Write;

use purge_guard::live::KeyAddress;
use purge_model::Blocker;
use purge_model::FileTime;
use purge_model::exec::journal::UndoConflict;
use purge_model::exec::op::{BackupRef, Sha256Hex};
use purge_model::exec::regbackup::{
    BytesB64, KeyNode, RegBackup, RegBackupBody, RegBackupSchema, RegTree, ValueBackup, WideB64,
};
use purge_win::fs_write::FsError;
use purge_win::os::Win32Error;
use purge_win::reg::{REG_EXPAND_SZ, REG_LINK, REG_MULTI_SZ, REG_SZ, RegValue};
use purge_win::reg_write::{
    CreatedKey, HAS_SUBKEYS, HAS_VALUES, KeyAccess, NAME_NOT_REPRESENTABLE, WKey,
};
use sha2::{Digest, Sha256};

use crate::fault;
use crate::gate::{CheckedKeyParent, CheckedValueKey};
use crate::storage::{SessionDir, StorageError, now};

/// The blast-radius limit for one key tree (ENGINE_PLAN.md §5.10): a tree with more keys is refused
/// ([`CaptureError::TooLarge`]) unless the plan item is an absorbing Safe parent whose children were
/// counted, in which case the caller passes that count to [`capture_tree`] instead.
pub const DEFAULT_KEY_LIMIT: usize = 50;

/// The largest backup file [`read_verified`] reads. Anything larger is refused before it is read, and
/// [`write_verified`] refuses to write a larger one.
pub const MAX_BACKUP_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// The most raw bytes (names, classes, security descriptors and value data) [`capture_tree`] holds in
/// memory before it refuses the tree ([`CaptureError::TooManyBytes`]). Base64 grows data by a third,
/// so a capture within this budget makes a file well below [`MAX_BACKUP_FILE_BYTES`]: what is captured
/// can be read back at undo time.
pub const MAX_CAPTURE_BYTES: u64 = MAX_BACKUP_FILE_BYTES / 2;

/// `ERROR_KEY_DELETED`: the key behind a handle was deleted.
const KEY_DELETED: Win32Error = Win32Error(1018);
/// `ERROR_INVALID_OWNER`: the token may not assign the owner of a security descriptor.
const INVALID_OWNER: Win32Error = Win32Error(1307);
/// `ERROR_REQUEST_ABORTED`: a walk was stopped from inside (test hook only).
const REQUEST_ABORTED: Win32Error = Win32Error(1235);

// ---------------------------------------------------------------------------------------------------
// Errors and reports
// ---------------------------------------------------------------------------------------------------

/// An operating-system call on a key failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{op} failed at {at:?}: {error}")]
pub struct KeyOpError {
    /// The key, as names from the backup root down joined by `\` (empty for the root). For messages only.
    pub at: String,
    /// What was being done.
    pub op: &'static str,
    /// The error.
    pub error: Win32Error,
}

/// Why a key tree or a value could not be captured. Nothing is written and nothing may be deleted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaptureError {
    /// A registry link sits at `at` (or `at` became one). Links are never captured or followed.
    #[error("registry link at {at:?}")]
    RegLink {
        /// The link key, relative to the backup root.
        at: String,
    },
    /// A key name, value name or class at `at` is not valid UTF-16 or holds a NUL, so it cannot be
    /// addressed exactly and could not be put back.
    #[error("a name at {at:?} is not valid UTF-16 or holds a NUL")]
    NameNotRepresentable {
        /// The key, relative to the backup root.
        at: String,
    },
    /// The key at `at` is volatile; the backup format cannot record that, so it could not be put back
    /// as it was.
    #[error("volatile key at {at:?}")]
    Volatile {
        /// The key, relative to the backup root.
        at: String,
    },
    /// The key at `at` holds a value of type `REG_LINK`, which Purge never writes.
    #[error("value of type REG_LINK at {at:?}")]
    LinkValue {
        /// The key, relative to the backup root.
        at: String,
    },
    /// The tree has more keys than the limit the caller passed.
    #[error("the tree has more than {limit} keys")]
    TooLarge {
        /// The limit.
        limit: usize,
    },
    /// The tree holds more bytes than a backup file can carry ([`MAX_CAPTURE_BYTES`]).
    #[error("the tree holds more than {budget} bytes")]
    TooManyBytes {
        /// The budget.
        budget: u64,
    },
    /// The key no longer exists.
    #[error("the key no longer exists")]
    Vanished,
    /// A call failed.
    #[error(transparent)]
    Os(#[from] KeyOpError),
}

impl CaptureError {
    /// The blocker to report for a skipped item, when the refusal is one: [`Blocker::RegLink`],
    /// [`Blocker::TooLarge`], or [`Blocker::CannotBackUp`] for what the backup cannot hold. `None` for
    /// [`CaptureError::Vanished`] and [`CaptureError::Os`].
    pub fn blocker(&self) -> Option<Blocker> {
        match self {
            Self::RegLink { .. } => Some(Blocker::RegLink),
            Self::TooLarge { .. } | Self::TooManyBytes { .. } => Some(Blocker::TooLarge),
            Self::NameNotRepresentable { .. } | Self::Volatile { .. } | Self::LinkValue { .. } => {
                Some(Blocker::CannotBackUp)
            }
            Self::Vanished | Self::Os(_) => None,
        }
    }
}

/// Why a backup file could not be written or read as verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackupFileError {
    /// The relative path would leave the session directory ([`BackupRef::is_session_relative`]).
    #[error("backup path {0:?} does not stay inside the session directory")]
    NotSessionRelative(String),
    /// The document is not one Purge writes or acts on: bad shape, a link flag, a root name that is not
    /// the leaf of the key path, duplicate sibling names, an unrepresentable name, or a `REG_LINK` value.
    #[error("the backup document is not usable: {0}")]
    Invalid(String),
    /// The file does not exist.
    #[error("the backup file is missing")]
    Missing,
    /// The file's size or SHA-256 differs from the reference: it was changed after it was written.
    #[error("the backup file's size or SHA-256 does not match the journal")]
    Tampered,
    /// The file is larger than [`MAX_BACKUP_FILE_BYTES`].
    #[error("the backup file is too large to read")]
    TooBig,
    /// The bytes read back after the write differ from the bytes written, or do not parse to the same
    /// document.
    #[error("the backup file read back differs from what was written")]
    ReadBackMismatch,
    /// A file-system call failed.
    #[error("{op} failed: {error}")]
    Fs {
        /// What was being done.
        op: &'static str,
        /// The error.
        error: FsError,
    },
    /// The store refused to create or open the file, or a call on its checked handle failed (an
    /// integrity failure, an existing file of that name, I/O). [`BackupFileError::Missing`] is used
    /// for a file that does not exist.
    #[error("the store: {0}")]
    Store(Box<StorageError>),
}

impl BackupFileError {
    /// The store's error, with a missing file as [`BackupFileError::Missing`].
    fn from_store(error: StorageError) -> BackupFileError {
        match error {
            StorageError::Io {
                source: FsError::NotFound,
                ..
            } => BackupFileError::Missing,
            other => BackupFileError::store(other),
        }
    }

    /// A store error, boxed.
    fn store(error: StorageError) -> BackupFileError {
        BackupFileError::Store(Box::new(error))
    }
}

/// How a live key differs from its backup node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum Change {
    /// A key of the backup no longer exists.
    #[error("the key is gone")]
    Missing,
    /// The key is a registry link now (or the key on the way to it is).
    #[error("the key is a registry link now")]
    BecameLink,
    /// The key has a subkey that is not in the backup.
    #[error("the key has a subkey that is not in the backup")]
    ExtraSubkey,
    /// The key's values are not the backed-up ones (another set, type or data).
    #[error("the key's values differ from the backup")]
    ValuesDiffer,
    /// The key's class differs.
    #[error("the key's class differs from the backup")]
    ClassDiffers,
    /// The key's owner, group or DACL differs.
    #[error("the key's security differs from the backup")]
    SecurityDiffers,
    /// The key is volatile where the backup recorded a stable key, or the other way round.
    #[error("the key's volatility differs from the backup")]
    VolatilityDiffers,
    /// A name in the key is not valid UTF-16 or holds a NUL, so it is not one the backup holds.
    #[error("the key holds a name that is not representable")]
    NameNotRepresentable,
}

impl Change {
    /// The blocker to report for an item skipped because of this change: [`Blocker::RegLink`] for
    /// [`Change::BecameLink`], otherwise [`Blocker::ChangedSinceScan`].
    pub fn blocker(self) -> Blocker {
        match self {
            Change::BecameLink => Blocker::RegLink,
            _ => Blocker::ChangedSinceScan,
        }
    }
}

/// Why a delete stopped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeleteFailure {
    /// The live key is not what the backup holds (ChangedSinceScan, or RegLink for
    /// [`Change::BecameLink`]). [`Change::Missing`] at the root (`at` empty) means the item vanished.
    #[error("{0}")]
    Changed(Change),
    /// The backup is not of the kind the call needs (a value backup given to a tree delete, or the
    /// reverse).
    #[error("the backup is of the wrong kind")]
    WrongBackupKind,
    /// The checked parent's leaf is not the backup's root key ([`finish_delete_tree`]); nothing was
    /// opened below it.
    #[error("the checked key is not the key of the backup")]
    NotThisKey,
    /// A call failed.
    #[error("{op} failed: {error}")]
    Os {
        /// What was being done.
        op: &'static str,
        /// The error.
        error: Win32Error,
    },
}

/// What was done to undo the part of an operation that had already happened, and so what is on the
/// machine afterwards. Only [`Rollback::NotNeeded`] and [`Rollback::Done`] mean that every key Purge
/// deleted (in this call, or for [`finish_delete_tree`] in the interrupted run before it) is back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rollback {
    /// Nothing had been changed, so nothing was undone. After a resumed delete
    /// ([`finish_delete_tree`]): no key of the backup is missing either.
    NotNeeded,
    /// Everything that had been changed was undone. `keys` counts the keys put back (after a delete)
    /// or removed again (after a restore).
    Done {
        /// Keys put back or removed again.
        keys: usize,
        /// What could not be put back exactly (after a delete only).
        differences: Vec<Difference>,
    },
    /// Undoing stopped at `failure`; `keys` were handled before it. The system is in a mixed state and
    /// needs recovery.
    Incomplete {
        /// The call that failed.
        failure: Box<KeyOpError>,
        /// Keys put back or removed again before the failure.
        keys: usize,
    },
    /// A resumed delete ([`finish_delete_tree`]) stopped: the keys it deleted itself were put back
    /// (`keys`), but `missing` keys of the backup, deleted before it by the interrupted run, are still
    /// missing. The tree is half deleted; [`restore_missing`] puts those keys back (and only those),
    /// from the same backup.
    PartialBefore {
        /// Keys of the backup still missing.
        missing: usize,
        /// Keys this call deleted and put back.
        keys: usize,
        /// What could not be put back exactly of those `keys`.
        differences: Vec<Difference>,
    },
}

impl Rollback {
    /// Whether the system is back where the operation started (nothing changed, or all undone):
    /// `false` for [`Rollback::Incomplete`] and [`Rollback::PartialBefore`].
    pub fn is_complete(&self) -> bool {
        !matches!(
            self,
            Rollback::Incomplete { .. } | Rollback::PartialBefore { .. }
        )
    }
}

/// A delete that stopped, and what was done about the keys it had already deleted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("delete stopped at {at:?}: {failure}; rollback: {rollback:?}")]
pub struct DeleteError {
    /// The key at which the delete stopped, relative to the backup root (empty for the root).
    pub at: String,
    /// Why.
    pub failure: DeleteFailure,
    /// The keys deleted before the stop were put back from the backup (per-subtree all-or-nothing).
    pub rollback: Rollback,
}

/// A completed tree delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteReport {
    /// Keys deleted by this call.
    pub keys_deleted: usize,
}

/// How a value delete ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueDelete {
    /// The value was deleted.
    Deleted,
    /// The value was already gone.
    Vanished,
}

/// Something a restore could not put back exactly. The restore still counts as done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Difference {
    /// The key, relative to the backup root (empty for the root).
    pub at: String,
    /// What differs.
    pub kind: DifferenceKind,
}

/// The kinds of [`Difference`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DifferenceKind {
    /// The recorded owner could not be assigned by this token (`ERROR_INVALID_OWNER`, for example
    /// TrustedInstaller); the key was created with the token's default owner and the recorded group and
    /// DACL.
    OwnerNotRestored {
        /// The owner part of the recorded SDDL (`S-1-5-80-…` or an alias such as `SY`).
        recorded_owner: String,
    },
    /// The key's security reads back other than recorded even after one correction.
    SecurityDiffers,
    /// The backup was merged into an existing empty root key, which keeps its own class.
    RootClassKept,
    /// The backup was merged into an existing empty root key, which keeps its own security.
    RootSecurityKept,
    /// A key that exists differs from its backup node ([`restore_missing`], which never changes an
    /// existing key): the first such key found, left as it is.
    ExistingKeyDiffers {
        /// How it differs.
        change: Change,
    },
}

/// How a restore ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// The keys or the value were put back.
    Restored,
    /// Everything was already in place; nothing was changed.
    AlreadyRestored,
}

/// A completed restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// Restored or already in place.
    pub outcome: RestoreOutcome,
    /// Keys created by this call.
    pub keys_created: usize,
    /// What could not be put back exactly.
    pub differences: Vec<Difference>,
}

/// Why a restore was not applied. A conflict is reported, never forced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RestoreConflict {
    /// The root key exists again under `Installer`, `Services` or a COM root ([`is_protected_root`]).
    #[error("the key exists again under a protected root")]
    KeyExistsProtected,
    /// The root key exists again with values or subkeys.
    #[error("the key exists again and is not empty")]
    KeyNotEmpty,
    /// The root key, or the parent it would be created in, is a registry link.
    #[error("the key or its parent is a registry link")]
    Link,
    /// A partly deleted tree no longer matches the backup ([`complete_tree`]).
    #[error("the remaining tree differs from the backup at {at:?}: {change}")]
    Diverged {
        /// The key that differs, relative to the backup root.
        at: String,
        /// How.
        change: Change,
    },
    /// The value exists with another type or other data.
    #[error("the value exists with other data")]
    ValueDiffers,
    /// The root key exists again, empty, with another volatility than the backup recorded: merging
    /// into it would leave the restored tree volatile (or stable) where it was not.
    #[error("the key exists again with another volatility")]
    VolatilityDiffers,
}

impl RestoreConflict {
    /// The journal's form of this conflict.
    pub fn undo_conflict(&self) -> UndoConflict {
        match self {
            Self::KeyExistsProtected
            | Self::KeyNotEmpty
            | Self::Diverged { .. }
            | Self::VolatilityDiffers => UndoConflict::KeyExists,
            Self::Link => UndoConflict::GateBlocked {
                blocker: Blocker::RegLink,
            },
            Self::ValueDiffers => UndoConflict::ValueDiffers,
        }
    }
}

/// Why a restore did not complete.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RestoreError {
    /// The restore was not applied; nothing was changed.
    #[error("conflict: {0}")]
    Conflict(RestoreConflict),
    /// The backup is not of the kind the call needs.
    #[error("the backup is of the wrong kind")]
    WrongBackupKind,
    /// The checked undo destination is not the backup's key: the leaf of [`CheckedKeyParent`] is not
    /// the backup's root key name. Nothing was opened below it or changed.
    #[error("the checked key is not the key of the backup")]
    NotThisKey,
    /// A call failed; what had been created was removed again as far as `rollback` says.
    #[error("{failure}; rollback: {rollback:?}")]
    Failed {
        /// The call that failed.
        failure: KeyOpError,
        /// What was undone.
        rollback: Rollback,
    },
}

/// What a live tree looks like next to its backup ([`probe_tree`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeState {
    /// The root key does not exist.
    Absent,
    /// Every key of the backup exists and matches, with nothing extra.
    Intact,
    /// The keys that exist match the backup and nothing extra exists, but whole subtrees are missing: the
    /// state an interrupted delete or restore leaves.
    Partial {
        /// Number of backup keys that are missing.
        missing_keys: usize,
    },
    /// Some key differs from the backup.
    Diverged {
        /// The key that differs, relative to the backup root.
        at: String,
        /// How.
        change: Change,
    },
}

// ---------------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------------

/// SHA-256 of `bytes`.
fn sha256(bytes: &[u8]) -> Sha256Hex {
    Sha256Hex(Sha256::digest(bytes).into())
}

/// A recorded name as the strict `&str` form [`WKey`] takes; `None` when it is not valid UTF-16 or holds
/// a NUL.
fn name_of(wide: &WideB64) -> Option<String> {
    if wide.0.contains(&0) {
        return None;
    }
    String::from_utf16(&wide.0).ok()
}

/// The last component of a key path; `None` when it is empty.
fn leaf_name(key_path: &str) -> Option<&str> {
    key_path
        .trim_end_matches('\\')
        .rsplit('\\')
        .next()
        .filter(|leaf| !leaf.is_empty())
}

/// `parent\name`, or `name` below the root.
fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}\\{name}")
    }
}

/// The path of key `index` below the backup root, for messages.
fn display_path(tree: &RegTree, index: usize) -> String {
    tree.rel_path(index)
        .map(|names| {
            names
                .iter()
                .map(|n| n.to_string_lossy())
                .collect::<Vec<_>>()
                .join("\\")
        })
        .unwrap_or_default()
}

/// Upper-cases one UTF-16 unit where it has a single-unit upper case; registry names compare without
/// case.
fn upcase_unit(unit: u16) -> u16 {
    match char::from_u32(u32::from(unit)) {
        Some(c) => {
            let mut upper = c.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(u), None) => u16::try_from(u32::from(u)).unwrap_or(unit),
                _ => unit,
            }
        }
        None => unit,
    }
}

/// A name folded for case-insensitive comparison.
fn fold(units: &[u16]) -> Vec<u16> {
    units.iter().map(|&u| upcase_unit(u)).collect()
}

/// The direct children of every key, in stored order.
fn child_lists(tree: &RegTree) -> Vec<Vec<usize>> {
    let mut children = vec![Vec::new(); tree.keys.len()];
    for (i, key) in tree.keys.iter().enumerate().skip(1) {
        if let Some(parent) = key.parent {
            children[parent as usize].push(i);
        }
    }
    children
}

/// Splits `O:<owner>` off the front of an SDDL string: `(owner, rest)`. `None` when there is no owner
/// part.
fn split_owner(sddl: &str) -> Option<(&str, &str)> {
    let rest = sddl.strip_prefix("O:")?;
    match rest.find(':') {
        // The letter before the next `:` starts the next part (`G:`, `D:` or `S:`).
        Some(colon) if colon >= 2 && rest.is_char_boundary(colon - 1) => {
            Some((&rest[..colon - 1], &rest[colon - 1..]))
        }
        Some(_) => None,
        None => Some((rest, "")),
    }
}

/// The SDDL string without its owner part.
fn without_owner(sddl: &str) -> &str {
    split_owner(sddl).map_or(sddl, |(_, rest)| rest)
}

/// Whether restoring a key at `key_path` that exists again is always a conflict (§7.8): the key lies
/// below an `Installer` key, below `Services` of a control set, or below a COM root (`CLSID`,
/// `Interface`, `TypeLib`, `AppID`). Only the ancestors count, not the key's own name. The match is
/// case-insensitive and deliberately broad: a false match only turns a merge into a reported conflict.
pub fn is_protected_root(key_path: &str) -> bool {
    let segments: Vec<&str> = key_path.split('\\').filter(|s| !s.is_empty()).collect();
    let ancestors = &segments[..segments.len().saturating_sub(1)];
    ancestors.iter().enumerate().any(|(i, segment)| {
        let is = |name: &str| segment.eq_ignore_ascii_case(name);
        let under_control_set = i > 0 && {
            let prev = ancestors[i - 1];
            prev.eq_ignore_ascii_case("CurrentControlSet")
                || prev
                    .get(..10)
                    .is_some_and(|p| p.eq_ignore_ascii_case("ControlSet"))
        };
        is("Installer")
            || (is("Services") && under_control_set)
            || is("CLSID")
            || is("Interface")
            || is("TypeLib")
            || is("AppID")
    })
}

/// Whether a key exists again in a place where that is always a conflict ([`is_protected_root`]), judged
/// on the plan's spelling the backup records and on the canonical address the gate opened (either is
/// enough).
fn is_protected(backup: &RegBackup, address: &KeyAddress) -> bool {
    is_protected_root(&backup.key) || is_protected_root(&address.path)
}

/// Whether two key names are the same name: registry names compare without case.
fn same_name(a: &[u16], b: &[u16]) -> bool {
    fold(a) == fold(b)
}

/// The tree of `backup`, when it is a tree backup of the key `parent` hands out: the parent's leaf is the
/// backup's root key name ([`RestoreError::NotThisKey`] otherwise).
fn tree_below<'a>(
    parent: &CheckedKeyParent,
    backup: &'a VerifiedBackup,
) -> Result<&'a RegTree, RestoreError> {
    let tree = backup.tree().ok_or(RestoreError::WrongBackupKind)?;
    let leaf: Vec<u16> = parent.leaf().encode_utf16().collect();
    if !same_name(&leaf, &tree.keys[0].name_b64.0) {
        return Err(RestoreError::NotThisKey);
    }
    Ok(tree)
}

// ---------------------------------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------------------------------

/// Maps an error of a capture call at `at` to its typed refusal.
fn capture_err(at: &str, op: &'static str, error: Win32Error) -> CaptureError {
    if error == Win32Error::LINK_ON_PATH {
        CaptureError::RegLink { at: at.to_owned() }
    } else if error == NAME_NOT_REPRESENTABLE {
        CaptureError::NameNotRepresentable { at: at.to_owned() }
    } else {
        CaptureError::Os(KeyOpError {
            at: at.to_owned(),
            op,
            error,
        })
    }
}

/// Reads one key into a node, and its subkey names.
fn read_node(
    key: &WKey,
    name: WideB64,
    parent: Option<u32>,
    at: &str,
) -> Result<(KeyNode, Vec<String>), CaptureError> {
    let err = |op| move |e| capture_err(at, op, e);
    let flags = key.flags().map_err(err("query key flags"))?;
    if flags.link || key.is_link().map_err(err("query link value"))? {
        return Err(CaptureError::RegLink { at: at.to_owned() });
    }
    let info = key.info().map_err(err("query key info"))?;
    let sddl = key.security_sddl().map_err(err("read security"))?;
    let live_values = key.values().map_err(err("read values"))?;
    let mut values = Vec::with_capacity(live_values.len());
    for value in live_values {
        if value.ty == REG_LINK {
            return Err(CaptureError::LinkValue { at: at.to_owned() });
        }
        values.push(ValueBackup {
            name_b64: WideB64::from(value.name.as_str()),
            value_type: value.ty,
            data_b64: BytesB64(value.data),
        });
    }
    let subkeys = key.subkey_names().map_err(err("list subkeys"))?;
    let node = key_node(
        parent,
        name,
        (!info.class.is_empty()).then(|| WideB64::from(info.class.as_str())),
        sddl,
        FileTime(info.last_write_time),
        values,
        flags.volatile,
    )
    .ok_or_else(|| CaptureError::Volatile { at: at.to_owned() })?;
    Ok((node, subkeys))
}

/// The one place a [`KeyNode`] is built. `None` when the node cannot record what the key is; no such
/// case is left since the model records volatility (a non-volatile key cannot be created below a
/// volatile one, error 1021, so restore needs the flag).
fn key_node(
    parent: Option<u32>,
    name_b64: WideB64,
    class_b64: Option<WideB64>,
    sddl: String,
    last_write_time: FileTime,
    values: Vec<ValueBackup>,
    volatile: bool,
) -> Option<KeyNode> {
    Some(KeyNode {
        parent,
        name_b64,
        class_b64,
        sddl,
        last_write_time,
        link: false,
        volatile,
        values,
    })
}

/// Whether a backed-up key is to be re-created volatile.
fn node_volatile(node: &KeyNode) -> bool {
    node.volatile
}

/// Captures the key behind `root` with its whole subtree as a `purge.regbackup/1` tree document.
///
/// `root` is the handle the gate inspected (any access that includes reading). `key_path` is the item's
/// canonical key path; its last component becomes the root key's name. Every subkey is opened from its
/// parent's handle with `REG_OPTION_OPEN_LINK`; a link anywhere ends the capture with
/// [`CaptureError::RegLink`]. More than `limit` keys end it with [`CaptureError::TooLarge`] (pass
/// [`DEFAULT_KEY_LIMIT`], or the counted size of an absorbing Safe parent). A subkey that disappears
/// between listing and opening is left out.
///
/// For a delete-if-empty key, call it with `limit` 1 after checking that the key has no subkeys: the
/// result is a one-key tree holding its class and security.
///
/// A tree whose names, classes, security descriptors and value data add up to more than
/// [`MAX_CAPTURE_BYTES`] is refused while it is captured ([`CaptureError::TooManyBytes`]), so that no
/// tree is deleted whose backup could not be read back at undo time.
pub fn capture_tree(root: &WKey, key_path: &str, limit: usize) -> Result<RegBackup, CaptureError> {
    capture_tree_within(root, key_path, limit, MAX_CAPTURE_BYTES)
}

/// What the JSON of a key node adds to its own bytes at most (field names, parent index, flags, last
/// write time), and of a value.
const NODE_OVERHEAD: u64 = 256;
const VALUE_OVERHEAD: u64 = 64;

/// The bytes a node holds, as [`MAX_CAPTURE_BYTES`] counts them: its raw names, class, security
/// descriptor and value data, plus the JSON around them.
fn node_bytes(node: &KeyNode) -> u64 {
    let units = |w: &WideB64| 2 * w.0.len() as u64;
    NODE_OVERHEAD
        + units(&node.name_b64)
        + node.class_b64.as_ref().map_or(0, units)
        + node.sddl.len() as u64
        + node
            .values
            .iter()
            .map(|v| VALUE_OVERHEAD + units(&v.name_b64) + v.data_b64.0.len() as u64)
            .sum::<u64>()
}

/// [`capture_tree`] with a byte budget.
fn capture_tree_within(
    root: &WKey,
    key_path: &str,
    limit: usize,
    budget: u64,
) -> Result<RegBackup, CaptureError> {
    let mut held = 0u64;
    let mut hold = |node: &KeyNode| {
        held = held.saturating_add(node_bytes(node));
        if held > budget {
            Err(CaptureError::TooManyBytes { budget })
        } else {
            Ok(())
        }
    };
    let leaf = leaf_name(key_path).ok_or_else(|| {
        CaptureError::Os(KeyOpError {
            at: String::new(),
            op: "read key path",
            error: Win32Error::INVALID_PARAMETER,
        })
    })?;
    if limit == 0 {
        return Err(CaptureError::TooLarge { limit });
    }
    let (root_node, root_subkeys) = match read_node(root, WideB64::from(leaf), None, "") {
        Err(CaptureError::Os(e)) if e.error == KEY_DELETED || e.error.is_not_found() => {
            return Err(CaptureError::Vanished);
        }
        other => other?,
    };
    hold(&root_node)?;

    struct Frame {
        index: usize,
        key: Option<WKey>,
        path: String,
        names: Vec<String>,
        next: usize,
    }

    let mut keys = vec![root_node];
    let mut stack = vec![Frame {
        index: 0,
        key: None,
        path: String::new(),
        names: root_subkeys,
        next: 0,
    }];
    while let Some(top) = stack.last_mut() {
        let Some(name) = top.names.get(top.next).cloned() else {
            stack.pop();
            continue;
        };
        top.next += 1;
        if keys.len() >= limit {
            return Err(CaptureError::TooLarge { limit });
        }
        let at = join(&top.path, &name);
        let handle = top.key.as_ref().unwrap_or(root);
        let child = match handle.open_subkey(&name, KeyAccess::READ) {
            Ok(child) => child,
            Err(e) if e.is_not_found() => continue,
            Err(e) if e == Win32Error::LINK_ON_PATH => {
                return Err(CaptureError::RegLink {
                    at: top.path.clone(),
                });
            }
            Err(e) => return Err(capture_err(&at, "open subkey", e)),
        };
        let parent = u32::try_from(top.index).map_err(|_| CaptureError::TooLarge { limit })?;
        let (node, names) = read_node(&child, WideB64::from(name.as_str()), Some(parent), &at)?;
        hold(&node)?;
        keys.push(node);
        stack.push(Frame {
            index: keys.len() - 1,
            key: Some(child),
            path: at,
            names,
            next: 0,
        });
    }
    Ok(RegBackup {
        schema: RegBackupSchema,
        key: key_path.to_owned(),
        captured: now(),
        body: RegBackupBody::Tree(RegTree { keys }),
    })
}

/// Captures value `name` (`""` for the default value) of `key` as a value document. `Ok(None)` when the
/// value does not exist. Refuses a link key, a `REG_LINK` value and a name with a NUL.
pub fn capture_value(
    key: &WKey,
    key_path: &str,
    name: &str,
) -> Result<Option<RegBackup>, CaptureError> {
    if name.contains('\0') {
        return Err(CaptureError::NameNotRepresentable { at: String::new() });
    }
    let gone = |e: Win32Error| e == KEY_DELETED || e.is_not_found();
    match key.is_link() {
        Ok(true) => return Err(CaptureError::RegLink { at: String::new() }),
        Ok(false) => {}
        Err(e) if gone(e) => return Err(CaptureError::Vanished),
        Err(e) => return Err(capture_err("", "query link value", e)),
    }
    let value = match key.value(name) {
        Ok(value) => value,
        Err(e) if e == KEY_DELETED => return Err(CaptureError::Vanished),
        Err(e) => return Err(capture_err("", "read value", e)),
    };
    let Some(value) = value else {
        return Ok(None);
    };
    if value.ty == REG_LINK {
        return Err(CaptureError::LinkValue { at: String::new() });
    }
    Ok(Some(RegBackup {
        schema: RegBackupSchema,
        key: key_path.to_owned(),
        captured: now(),
        body: RegBackupBody::Value(ValueBackup {
            name_b64: WideB64::from(value.name.as_str()),
            value_type: value.ty,
            data_b64: BytesB64(value.data),
        }),
    }))
}

// ---------------------------------------------------------------------------------------------------
// Verified backup files
// ---------------------------------------------------------------------------------------------------

/// A backup document whose file was written and read back ([`write_verified`]) or whose file matched the
/// journal's size and SHA-256 ([`read_verified`]), and which passed the document checks. Deleting and
/// restoring take only this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBackup {
    doc: RegBackup,
    reference: BackupRef,
}

impl VerifiedBackup {
    /// The document.
    pub fn doc(&self) -> &RegBackup {
        &self.doc
    }

    /// The file reference for the journal: session-relative path, SHA-256 of the bytes read back, size.
    pub fn reference(&self) -> &BackupRef {
        &self.reference
    }

    /// The tree, when the document holds one.
    pub fn tree(&self) -> Option<&RegTree> {
        self.doc.tree()
    }

    /// The value, when the document holds one.
    pub fn value(&self) -> Option<&ValueBackup> {
        self.doc.value()
    }
}

/// Checks one value of a document.
fn check_value(value: &ValueBackup) -> Result<(), String> {
    if name_of(&value.name_b64).is_none() {
        return Err("a value name is not representable".into());
    }
    if value.value_type == REG_LINK {
        return Err("a value has type REG_LINK".into());
    }
    Ok(())
}

/// The checks a document passes before it is written and after it is read: what the model does not
/// check itself.
fn check_doc(doc: &RegBackup) -> Result<(), String> {
    let tree = match &doc.body {
        RegBackupBody::Value(value) => return check_value(value),
        RegBackupBody::Tree(tree) => tree,
    };
    tree.validate().map_err(|e| e.to_string())?;
    if tree.has_link() {
        return Err("a key is flagged as a registry link".into());
    }
    let leaf = leaf_name(&doc.key).ok_or("the key path has no last component")?;
    if tree.keys[0].name_b64 != WideB64::from(leaf) {
        return Err("the root key's name is not the last component of the key path".into());
    }
    let mut siblings = HashSet::new();
    for (i, key) in tree.keys.iter().enumerate() {
        if name_of(&key.name_b64).is_none() {
            return Err(format!("key {i} has a name that is not representable"));
        }
        if key.class_b64.as_ref().is_some_and(|c| name_of(c).is_none()) {
            return Err(format!("key {i} has a class that is not representable"));
        }
        if key.sddl.is_empty() || key.sddl.contains('\0') {
            return Err(format!("key {i} has no usable security descriptor"));
        }
        let mut value_names = HashSet::new();
        for value in &key.values {
            check_value(value)?;
            if !value_names.insert(fold(&value.name_b64.0)) {
                return Err(format!("key {i} has two values of the same name"));
            }
        }
        if let Some(parent) = key.parent
            && !siblings.insert((parent, fold(&key.name_b64.0)))
        {
            return Err(format!("key {i} has the name of a sibling"));
        }
    }
    Ok(())
}

/// Writes `doc` as the new session file `rel` of `session` and returns it as a [`VerifiedBackup`] whose
/// reference carries the size and SHA-256 of the bytes written. The only writer of registry backups.
///
/// Through the store's handles only: the file is created new with the store's file descriptor
/// ([`SessionDir::create_file`], which re-checks the session directory chain and creates `reg` when
/// needed), written, flushed with its directory through the checked handles, and read back through the
/// same handle; then it is closed (fault point `backup.written`), opened again through the store's
/// checks ([`SessionDir::open_file`]), required to be the same file (volume serial and file id), read
/// through that handle, checked against the size and SHA-256 of the bytes meant to be written
/// ([`verify_bytes`]) and parsed back to `doc` (fault point `backup.verified`). Each fault point is hit
/// exactly once per call that gets that far.
///
/// `rel` must be session-relative (for example `reg\000042.regbackup.json`, see
/// `storage::backup_rel`); an existing file of that name is never replaced
/// ([`BackupFileError::Store`]). A failure while the created handle is open discards the file through
/// that handle; nothing is removed by name. Without an `Ok` from here the caller must not delete.
pub fn write_verified(
    session: &SessionDir,
    rel: &str,
    doc: &RegBackup,
) -> Result<VerifiedBackup, BackupFileError> {
    let reference = BackupRef {
        path: rel.to_owned(),
        sha256: Sha256Hex([0; 32]),
        bytes: 0,
    };
    if !reference.is_session_relative() {
        return Err(BackupFileError::NotSessionRelative(rel.to_owned()));
    }
    check_doc(doc).map_err(BackupFileError::Invalid)?;
    let text = serde_json::to_vec(doc).map_err(|e| BackupFileError::Invalid(e.to_string()))?;
    let bytes = u64::try_from(text.len()).map_err(|_| BackupFileError::TooBig)?;
    if bytes > MAX_BACKUP_FILE_BYTES {
        return Err(BackupFileError::TooBig);
    }
    let reference = BackupRef {
        sha256: sha256(&text),
        bytes,
        ..reference
    };

    let mut created = session.create_file(rel).map_err(BackupFileError::store)?;
    if let Err(e) = write_created(&mut created, &text) {
        // The file is Purge's own, created a moment ago, and holds no verified backup.
        let _ = created.discard();
        return Err(e);
    }
    let written_id = created.file_id();
    drop(created);
    fault::point(fault::BACKUP_WRITTEN);

    let mut opened = session
        .open_file(rel)
        .map_err(BackupFileError::from_store)?;
    if opened.file_id() != written_id {
        return Err(BackupFileError::ReadBackMismatch);
    }
    let back = opened
        .read_all(MAX_BACKUP_FILE_BYTES)
        .map_err(BackupFileError::from_store)?;
    drop(opened);
    let verified = verify_bytes(&reference, &back).map_err(|e| match e {
        BackupFileError::Tampered => BackupFileError::ReadBackMismatch,
        other => other,
    })?;
    if verified.doc() != doc {
        return Err(BackupFileError::ReadBackMismatch);
    }
    fault::point(fault::BACKUP_VERIFIED);
    Ok(verified)
}

/// Writes `text` through the created store file, flushes it and its directory (through the directory's
/// checked handle), and reads it back through the same handle.
fn write_created(file: &mut crate::storage::StoreFile, text: &[u8]) -> Result<(), BackupFileError> {
    file.write_all(text).map_err(|e| BackupFileError::Fs {
        op: "write backup file",
        error: FsError::from(Win32Error(
            e.raw_os_error()
                .and_then(|c| u32::try_from(c).ok())
                .unwrap_or(0),
        )),
    })?;
    file.sync().map_err(BackupFileError::store)?;
    file.sync_dir().map_err(BackupFileError::store)?;
    let back = file
        .read_all(MAX_BACKUP_FILE_BYTES)
        .map_err(BackupFileError::store)?;
    if back != text {
        return Err(BackupFileError::ReadBackMismatch);
    }
    Ok(())
}

/// Reads the backup file `reference` names in `session`: refuses a path that leaves the session
/// directory, opens the file through the store's checks ([`SessionDir::open_file`]: no reparse point,
/// one link, the store's owner and descriptor, inside its checked directory) and reads it through that
/// handle, refusing more than [`MAX_BACKUP_FILE_BYTES`]; then checks size and SHA-256 against the
/// reference before parsing ([`BackupFileError::Tampered`] on a mismatch), and parses and checks the
/// document ([`verify_bytes`]). A missing file is [`BackupFileError::Missing`].
pub fn read_verified(
    session: &SessionDir,
    reference: &BackupRef,
) -> Result<VerifiedBackup, BackupFileError> {
    if !reference.is_session_relative() {
        return Err(BackupFileError::NotSessionRelative(reference.path.clone()));
    }
    let mut file = session
        .open_file(&reference.path)
        .map_err(BackupFileError::from_store)?;
    if file.len_at_open() != reference.bytes {
        return Err(BackupFileError::Tampered);
    }
    let bytes = match file.read_all(MAX_BACKUP_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(StorageError::TooLarge { .. }) => return Err(BackupFileError::TooBig),
        Err(e) => return Err(BackupFileError::from_store(e)),
    };
    verify_bytes(reference, &bytes)
}

/// The checks of [`read_verified`] on the bytes of a backup file the caller read through a checked
/// handle (`SessionDir::open_file`): a session-relative reference, size and SHA-256 equal to the
/// reference ([`BackupFileError::Tampered`] otherwise), then the parse and the document checks.
pub fn verify_bytes(
    reference: &BackupRef,
    bytes: &[u8],
) -> Result<VerifiedBackup, BackupFileError> {
    if !reference.is_session_relative() {
        return Err(BackupFileError::NotSessionRelative(reference.path.clone()));
    }
    if u64::try_from(bytes.len()).map_or(true, |n| n > MAX_BACKUP_FILE_BYTES) {
        return Err(BackupFileError::TooBig);
    }
    if bytes.len() as u64 != reference.bytes || sha256(bytes) != reference.sha256 {
        return Err(BackupFileError::Tampered);
    }
    let doc: RegBackup =
        serde_json::from_slice(bytes).map_err(|e| BackupFileError::Invalid(e.to_string()))?;
    check_doc(&doc).map_err(BackupFileError::Invalid)?;
    Ok(VerifiedBackup {
        doc,
        reference: reference.clone(),
    })
}

// ---------------------------------------------------------------------------------------------------
// Comparing live keys with the backup
// ---------------------------------------------------------------------------------------------------

/// Whether the live values are exactly the backed-up ones (same names, types and bytes; order free).
fn values_equal(live: &[RegValue], backup: &[ValueBackup]) -> bool {
    if live.len() != backup.len() {
        return false;
    }
    let by_name: HashMap<Vec<u16>, &ValueBackup> =
        backup.iter().map(|v| (fold(&v.name_b64.0), v)).collect();
    live.iter().all(|value| {
        let units: Vec<u16> = value.name.encode_utf16().collect();
        by_name.get(&fold(&units)).is_some_and(|b| {
            b.name_b64.0 == units && b.value_type == value.ty && b.data_b64.0 == value.data
        })
    })
}

/// Maps an error of a comparing call: a vanished key or an unrepresentable name are changes.
fn as_change(error: Win32Error) -> Result<Change, Win32Error> {
    if error == KEY_DELETED || error.is_not_found() {
        Ok(Change::Missing)
    } else if error == NAME_NOT_REPRESENTABLE {
        Ok(Change::NameNotRepresentable)
    } else if error == Win32Error::LINK_ON_PATH {
        Ok(Change::BecameLink)
    } else {
        Err(error)
    }
}

/// Compares a live key with its node: link, volatility, class, values, security (the owner only when
/// `owner_strict`). Subkeys are not looked at. `Ok(None)` when it matches.
fn compare_node(
    key: &WKey,
    node: &KeyNode,
    owner_strict: bool,
) -> Result<Option<(Change, &'static str)>, (Win32Error, &'static str)> {
    let check = |r: Result<(), Win32Error>, op: &'static str| match r {
        Ok(()) => Ok(None),
        Err(e) => as_change(e).map(|c| Some((c, op))).map_err(|e| (e, op)),
    };
    match key.is_link() {
        Ok(true) => return Ok(Some((Change::BecameLink, "query link value"))),
        Ok(false) => {}
        Err(e) => return check(Err(e), "query link value"),
    }
    let flags = match key.flags() {
        Ok(flags) => flags,
        Err(e) => return check(Err(e), "query key flags"),
    };
    if flags.link {
        return Ok(Some((Change::BecameLink, "query key flags")));
    }
    if flags.volatile != node_volatile(node) {
        return Ok(Some((Change::VolatilityDiffers, "compare volatility")));
    }
    let info = match key.info() {
        Ok(info) => info,
        Err(e) => return check(Err(e), "query key info"),
    };
    let class = node
        .class_b64
        .as_ref()
        .map(|c| c.0.clone())
        .unwrap_or_default();
    if info.class.encode_utf16().collect::<Vec<_>>() != class {
        return Ok(Some((Change::ClassDiffers, "compare class")));
    }
    let values = match key.values() {
        Ok(values) => values,
        Err(e) => return check(Err(e), "read values"),
    };
    if !values_equal(&values, &node.values) {
        return Ok(Some((Change::ValuesDiffer, "compare values")));
    }
    let sddl = match key.security_sddl() {
        Ok(sddl) => sddl,
        Err(e) => return check(Err(e), "read security"),
    };
    let same = if owner_strict {
        sddl == node.sddl
    } else {
        without_owner(&sddl) == without_owner(&node.sddl)
    };
    if !same {
        return Ok(Some((Change::SecurityDiffers, "compare security")));
    }
    Ok(None)
}

/// Whether `key` has a subkey that is not among `expected` (folded names).
fn has_extra_subkey(key: &WKey, expected: &HashSet<Vec<u16>>) -> Result<bool, Win32Error> {
    Ok(key.subkey_names()?.iter().any(|name| {
        let units: Vec<u16> = name.encode_utf16().collect();
        !expected.contains(&fold(&units))
    }))
}

/// The folded names of the backup children of key `index`.
fn child_names(tree: &RegTree, children: &[Vec<usize>], index: usize) -> HashSet<Vec<u16>> {
    children[index]
        .iter()
        .map(|&c| fold(&tree.keys[c].name_b64.0))
        .collect()
}

/// Compares a live key with its node and its subkey names with the node's children.
fn compare_with_children(
    key: &WKey,
    tree: &RegTree,
    children: &[Vec<usize>],
    index: usize,
    owner_strict: bool,
) -> Result<Option<Change>, (Win32Error, &'static str)> {
    if let Some((change, _)) = compare_node(key, &tree.keys[index], owner_strict)? {
        return Ok(Some(change));
    }
    match has_extra_subkey(key, &child_names(tree, children, index)) {
        Ok(true) => Ok(Some(Change::ExtraSubkey)),
        Ok(false) => Ok(None),
        Err(e) => as_change(e).map(Some).map_err(|e| (e, "list subkeys")),
    }
}

// ---------------------------------------------------------------------------------------------------
// Restore engine
// ---------------------------------------------------------------------------------------------------

/// Creates keys from a tree and remembers them, so that they can be removed again.
struct Restorer<'a> {
    tree: &'a RegTree,
    /// Created keys in creation order (parent-first), with their tree index.
    created: Vec<(usize, CreatedKey)>,
    differences: Vec<Difference>,
    /// Whether fault point `regrestore.mid` is hit before each key after the first one created: for
    /// undo and recovery restores, not for the put-back of a stopped delete (which has its own point).
    fault_mid: bool,
}

impl<'a> Restorer<'a> {
    /// A restorer for the put-back of a stopped delete.
    fn new(tree: &'a RegTree) -> Self {
        Self {
            tree,
            created: Vec::new(),
            differences: Vec::new(),
            fault_mid: false,
        }
    }

    /// A restorer for undo and recovery.
    fn for_undo(tree: &'a RegTree) -> Self {
        Self {
            fault_mid: true,
            ..Self::new(tree)
        }
    }

    fn fail(&self, index: usize, op: &'static str, error: Win32Error) -> KeyOpError {
        KeyOpError {
            at: display_path(self.tree, index),
            op,
            error,
        }
    }

    /// Creates key `sub_root` below `parent` and every key below it in the backup, parent-first. Every
    /// key created is kept in `self.created`, also when a later step fails, so that it can be removed.
    fn restore_subtree(&mut self, parent: &WKey, sub_root: usize) -> Result<(), KeyOpError> {
        let n = self.tree.keys.len();
        // Position in `self.created` of every key of this subtree created so far.
        let mut slot: Vec<Option<usize>> = vec![None; n];
        let mut member = vec![false; n];
        member[sub_root] = true;
        for i in sub_root..n {
            let parent_key: &WKey = if i == sub_root {
                parent
            } else {
                match self.tree.keys[i].parent.map(|p| p as usize) {
                    Some(p) if member[p] => match slot[p] {
                        Some(pos) => &self.created[pos].1,
                        None => return Err(self.fail(i, "find parent", Win32Error::INVALID_DATA)),
                    },
                    _ => continue,
                }
            };
            member[i] = true;
            // Fault point for crash tests: between the creations of two keys, so the process dies
            // with part of the tree re-created.
            if self.fault_mid && !self.created.is_empty() {
                fault::point(fault::REGRESTORE_MID);
            }
            match create_key(self.tree, parent_key, i, &mut self.differences) {
                Ok(key) => {
                    self.created.push((i, key));
                    slot[i] = Some(self.created.len() - 1);
                }
                Err((failure, key)) => {
                    if let Some(key) = key {
                        self.created.push((i, key));
                    }
                    return Err(failure);
                }
            }
        }
        Ok(())
    }

    /// Removes every key created so far, deepest first, through the handles kept since creation.
    fn remove_created(&mut self) -> Rollback {
        let mut keys = 0;
        while let Some((index, key)) = self.created.pop() {
            if let Err(error) = key.delete() {
                let failure = Box::new(self.fail(index, "remove restored key", error));
                self.created.push((index, key));
                return Rollback::Incomplete { failure, keys };
            }
            keys += 1;
        }
        if keys == 0 {
            Rollback::NotNeeded
        } else {
            Rollback::Done {
                keys,
                differences: Vec::new(),
            }
        }
    }
}

/// Creates key `index` of `tree` below `parent` with its class, security descriptor and values. On a
/// failure after the key was created, the key is handed back with the error so it can be removed.
fn create_key(
    tree: &RegTree,
    parent: &WKey,
    index: usize,
    differences: &mut Vec<Difference>,
) -> Result<CreatedKey, (KeyOpError, Option<CreatedKey>)> {
    let node = &tree.keys[index];
    let fail = |op, error| KeyOpError {
        at: display_path(tree, index),
        op,
        error,
    };
    let name =
        name_of(&node.name_b64).ok_or_else(|| (fail("read name", NAME_NOT_REPRESENTABLE), None))?;
    let class = match &node.class_b64 {
        Some(class) => {
            name_of(class).ok_or_else(|| (fail("read class", NAME_NOT_REPRESENTABLE), None))?
        }
        None => String::new(),
    };
    let volatile = node_volatile(node);
    let (key, owner_dropped) = match parent.create_subkey(&name, &class, Some(&node.sddl), volatile)
    {
        Ok(key) => (key, false),
        Err(e) if e == INVALID_OWNER => {
            // The token may not assign the recorded owner; Purge enables no privilege to force it.
            let rest = without_owner(&node.sddl);
            let sddl = (!rest.is_empty()).then_some(rest);
            let key = parent
                .create_subkey(&name, &class, sddl, volatile)
                .map_err(|e| (fail("create key", e), None))?;
            (key, true)
        }
        Err(e) => return Err((fail("create key", e), None)),
    };
    match finish_key(tree, &key, index, owner_dropped, differences) {
        Ok(()) => Ok(key),
        Err(failure) => Err((failure, Some(key))),
    }
}

/// Security check and values of a key just created.
fn finish_key(
    tree: &RegTree,
    key: &CreatedKey,
    index: usize,
    owner_dropped: bool,
    differences: &mut Vec<Difference>,
) -> Result<(), KeyOpError> {
    let node = &tree.keys[index];
    let at = || display_path(tree, index);
    let fail = |op, error| KeyOpError {
        at: at(),
        op,
        error,
    };
    if owner_dropped {
        differences.push(Difference {
            at: at(),
            kind: DifferenceKind::OwnerNotRestored {
                recorded_owner: split_owner(&node.sddl)
                    .map(|(owner, _)| owner.to_owned())
                    .unwrap_or_default(),
            },
        });
    }
    let expected = if owner_dropped {
        without_owner(&node.sddl)
    } else {
        node.sddl.as_str()
    };
    let matches = |live: &str| {
        if owner_dropped {
            without_owner(live) == expected
        } else {
            live == expected
        }
    };
    let live = key.security_sddl().map_err(|e| fail("read security", e))?;
    if !matches(&live) {
        // One correction through the handle Purge created; a difference that remains is reported.
        let fixed = !expected.is_empty()
            && key.set_security(expected).is_ok()
            && key.security_sddl().is_ok_and(|live| matches(&live));
        if !fixed {
            differences.push(Difference {
                at: at(),
                kind: DifferenceKind::SecurityDiffers,
            });
        }
    }
    for value in &node.values {
        let name = name_of(&value.name_b64)
            .ok_or_else(|| fail("read value name", NAME_NOT_REPRESENTABLE))?;
        key.set_value_raw(&name, value.value_type, &value.data_b64.0)
            .map_err(|e| fail("set value", e))?;
    }
    Ok(())
}

/// Restores the whole tree below `parent`, where the root does not exist. All or nothing.
fn restore_fresh(parent: &WKey, tree: &RegTree) -> Result<RestoreReport, RestoreError> {
    let mut restorer = Restorer::for_undo(tree);
    match restorer.restore_subtree(parent, 0) {
        Ok(()) => Ok(RestoreReport {
            outcome: RestoreOutcome::Restored,
            keys_created: restorer.created.len(),
            differences: restorer.differences,
        }),
        Err(failure) => Err(RestoreError::Failed {
            failure,
            rollback: restorer.remove_created(),
        }),
    }
}

/// The root key's name, as [`WKey`] takes it.
fn root_name(tree: &RegTree) -> Result<String, RestoreError> {
    name_of(&tree.keys[0].name_b64).ok_or_else(|| RestoreError::Failed {
        failure: KeyOpError {
            at: String::new(),
            op: "read name",
            error: NAME_NOT_REPRESENTABLE,
        },
        rollback: Rollback::NotNeeded,
    })
}

/// A failure before anything was changed.
fn failed_early(at: &str, op: &'static str, error: Win32Error) -> RestoreError {
    RestoreError::Failed {
        failure: KeyOpError {
            at: at.to_owned(),
            op,
            error,
        },
        rollback: Rollback::NotNeeded,
    }
}

/// What a walk over the existing part of a tree found.
struct Walk {
    /// Handles of the keys below the root that exist (opened for reading), by tree index. The root's
    /// handle is the caller's ([`Walk::handle`]).
    handles: Vec<Option<WKey>>,
    /// The first key that differs, in walk order.
    diverged: Option<(usize, Change)>,
    /// The first key the walk could not look below: a link, or a backup name that cannot be opened.
    /// The backup keys below it are counted neither as existing nor as missing.
    blocked: Option<(usize, Change)>,
    /// Tree indexes of the missing keys whose parent exists.
    missing_roots: Vec<usize>,
    /// Number of missing keys.
    missing_keys: usize,
}

impl Walk {
    /// The open key at tree index `index`: `root` for 0, the handle the walk opened otherwise.
    fn handle<'k>(&'k self, root: &'k WKey, index: usize) -> Option<&'k WKey> {
        if index == 0 {
            Some(root)
        } else {
            self.handles.get(index).and_then(Option::as_ref)
        }
    }
}

/// Walks the existing part of `tree` below the open root key, parent-first, comparing each existing key
/// with its node and its subkey names with the node's children. With `stop`, the walk ends at the first
/// difference. Without, it goes on past keys that differ, so that every missing key is counted; it never
/// looks below a key that is a link (or whose backup name cannot be opened), see [`Walk::blocked`].
fn walk_existing(
    root: &WKey,
    tree: &RegTree,
    owner_strict: bool,
    stop: bool,
) -> Result<Walk, KeyOpError> {
    let n = tree.keys.len();
    let children = child_lists(tree);
    let mut walk = Walk {
        handles: Vec::with_capacity(n),
        diverged: None,
        blocked: None,
        missing_roots: Vec::new(),
        missing_keys: 0,
    };
    walk.handles.resize_with(n, || None);
    let mut missing = vec![false; n];
    // Keys the walk does not look at: below a link or below a name that cannot be opened.
    let mut hidden = vec![false; n];
    let os = |index: usize, (error, op): (Win32Error, &'static str)| KeyOpError {
        at: display_path(tree, index),
        op,
        error,
    };
    for i in 0..n {
        if let Some(p) = tree.keys[i].parent.map(|p| p as usize) {
            if missing[p] {
                missing[i] = true;
                walk.missing_keys += 1;
                continue;
            }
            if hidden[p] || hidden[i] {
                hidden[i] = true;
                continue;
            }
            let blocked = match name_of(&tree.keys[i].name_b64) {
                None => Some((i, Change::NameNotRepresentable)),
                Some(name) => {
                    let opened = match walk.handle(root, p) {
                        Some(parent) => parent.open_subkey(&name, KeyAccess::READ),
                        None => return Err(os(i, (Win32Error::INVALID_DATA, "find parent"))),
                    };
                    match opened {
                        Ok(key) => {
                            walk.handles[i] = Some(key);
                            None
                        }
                        Err(e) if e.is_not_found() => {
                            missing[i] = true;
                            walk.missing_keys += 1;
                            walk.missing_roots.push(i);
                            continue;
                        }
                        Err(e) if e == Win32Error::LINK_ON_PATH => Some((p, Change::BecameLink)),
                        Err(e) => return Err(os(i, (e, "open key"))),
                    }
                }
            };
            if let Some(found) = blocked {
                walk.diverged.get_or_insert(found);
                walk.blocked.get_or_insert(found);
                if stop {
                    return Ok(walk);
                }
                hidden[i] = true;
                continue;
            }
        }
        let Some(key) = walk.handle(root, i) else {
            return Err(os(i, (Win32Error::INVALID_DATA, "find key")));
        };
        let change =
            compare_with_children(key, tree, &children, i, owner_strict).map_err(|e| os(i, e))?;
        if let Some(change) = change {
            walk.diverged.get_or_insert((i, change));
            if stop {
                return Ok(walk);
            }
            if change == Change::BecameLink {
                walk.blocked.get_or_insert((i, change));
                // The key exists, but what is below a link is not the backup's.
                for &child in &children[i] {
                    hidden[child] = true;
                }
            }
        }
    }
    Ok(walk)
}

/// Opens the backup's root key below `parent` for reading. `Ok(None)` when it does not exist.
fn open_root(parent: &WKey, tree: &RegTree) -> Result<Option<WKey>, RestoreError> {
    let name = root_name(tree)?;
    match parent.open_subkey(&name, KeyAccess::READ) {
        Ok(key) => Ok(Some(key)),
        Err(e) if e.is_not_found() => Ok(None),
        Err(e) if e == Win32Error::LINK_ON_PATH => {
            Err(RestoreError::Conflict(RestoreConflict::Link))
        }
        Err(e) => Err(failed_early("", "open key", e)),
    }
}

/// Refuses a parent that is a registry link (the gate checked it; this reads it again on the handle).
fn parent_not_link(parent: &WKey) -> Result<(), RestoreError> {
    match parent.is_link() {
        Ok(false) => Ok(()),
        Ok(true) => Err(RestoreError::Conflict(RestoreConflict::Link)),
        Err(e) => Err(failed_early("", "query parent link", e)),
    }
}

/// A walk's failure, before anything was changed.
fn walk_failed(failure: KeyOpError) -> RestoreError {
    RestoreError::Failed {
        failure,
        rollback: Rollback::NotNeeded,
    }
}

/// Compares the live tree below `parent` (the parent the gate checked, [`gate::check_undo_key`]) with
/// the backup tree, changing nothing: the probe recovery uses to tell an interrupted delete or restore
/// ([`TreeState::Partial`]) from one that had not started ([`TreeState::Intact`]) or had finished
/// ([`TreeState::Absent`]). Owners are not compared (an owner the token could not assign is a reported
/// restore difference, not a change). [`RestoreError::NotThisKey`] when the parent's leaf is not the
/// backup's root key.
///
/// [`gate::check_undo_key`]: crate::gate::check_undo_key
pub fn probe_tree(
    parent: &CheckedKeyParent,
    backup: &VerifiedBackup,
) -> Result<TreeState, RestoreError> {
    let tree = tree_below(parent, backup)?;
    let root = match open_root(parent.parent(), tree) {
        Ok(Some(root)) => root,
        Ok(None) => return Ok(TreeState::Absent),
        Err(RestoreError::Conflict(RestoreConflict::Link)) => {
            return Ok(TreeState::Diverged {
                at: String::new(),
                change: Change::BecameLink,
            });
        }
        Err(e) => return Err(e),
    };
    let walk = walk_existing(&root, tree, false, true).map_err(walk_failed)?;
    Ok(match walk.diverged {
        Some((index, change)) => TreeState::Diverged {
            at: display_path(tree, index),
            change,
        },
        None if walk.missing_keys == 0 => TreeState::Intact,
        None => TreeState::Partial {
            missing_keys: walk.missing_keys,
        },
    })
}

/// Restores a deleted key tree below `parent` (the parent of [`RegBackup::key`] the gate opened and
/// checked, [`gate::check_undo_key`]) from a verified backup, following the conflict rules of §7.8:
///
/// - parent's leaf not the backup's root key name: [`RestoreError::NotThisKey`];
/// - root absent: the tree is created, parent-first, each key with its recorded class and security
///   descriptor; all or nothing (keys created so far are removed again on a failure);
/// - root present and equal to the backup (owners aside): [`RestoreOutcome::AlreadyRestored`];
/// - root present below a protected root ([`is_protected_root`], judged on the backup's key and on the
///   gate's canonical address): [`RestoreConflict::KeyExistsProtected`];
/// - root present and empty: the backup is merged into it (its values and subkeys are added; the existing
///   key keeps its class and security, reported as differences); another volatility than recorded is
///   [`RestoreConflict::VolatilityDiffers`];
/// - root present with content: [`RestoreConflict::KeyNotEmpty`].
///
/// A partly deleted tree (an interrupted delete) is a conflict here; recovery uses [`complete_tree`] or
/// [`restore_missing`].
///
/// [`gate::check_undo_key`]: crate::gate::check_undo_key
pub fn restore_tree(
    parent: &CheckedKeyParent,
    backup: &VerifiedBackup,
) -> Result<RestoreReport, RestoreError> {
    let tree = tree_below(parent, backup)?;
    let parent_key = parent.parent();
    parent_not_link(parent_key)?;
    let Some(root) = open_root(parent_key, tree)? else {
        return restore_fresh(parent_key, tree);
    };
    let walk = walk_existing(&root, tree, false, true).map_err(walk_failed)?;
    if walk.diverged.is_none() && walk.missing_keys == 0 {
        return Ok(RestoreReport {
            outcome: RestoreOutcome::AlreadyRestored,
            keys_created: 0,
            differences: Vec::new(),
        });
    }
    if matches!(walk.diverged, Some((0, Change::BecameLink))) {
        return Err(RestoreError::Conflict(RestoreConflict::Link));
    }
    drop(walk);
    drop(root);
    if is_protected(backup.doc(), parent.address()) {
        return Err(RestoreError::Conflict(RestoreConflict::KeyExistsProtected));
    }
    merge_into_empty(parent, tree)
}

/// Merges the backup into an existing, empty root key below the checked parent. The root must have
/// the recorded volatility ([`RestoreConflict::VolatilityDiffers`]): the keys created below a volatile
/// key would be volatile, below a stable key stable.
fn merge_into_empty(
    parent: &CheckedKeyParent,
    tree: &RegTree,
) -> Result<RestoreReport, RestoreError> {
    let name = root_name(tree)?;
    let access = KeyAccess::SET_VALUE | KeyAccess::CREATE_SUB_KEY;
    let root = match parent.parent().open_subkey(&name, access) {
        Ok(root) => root,
        Err(e) if e == Win32Error::LINK_ON_PATH => {
            return Err(RestoreError::Conflict(RestoreConflict::Link));
        }
        Err(e) => return Err(failed_early("", "open key", e)),
    };
    match root.is_link() {
        Ok(false) => {}
        Ok(true) => return Err(RestoreError::Conflict(RestoreConflict::Link)),
        Err(e) => return Err(failed_early("", "query link value", e)),
    }
    let info = root
        .info()
        .map_err(|e| failed_early("", "query key info", e))?;
    if info.n_subkeys != 0 || info.n_values != 0 {
        return Err(RestoreError::Conflict(RestoreConflict::KeyNotEmpty));
    }
    let node = &tree.keys[0];
    let flags = root
        .flags()
        .map_err(|e| failed_early("", "query key flags", e))?;
    if flags.link {
        return Err(RestoreError::Conflict(RestoreConflict::Link));
    }
    if flags.volatile != node_volatile(node) {
        return Err(RestoreError::Conflict(RestoreConflict::VolatilityDiffers));
    }
    let mut differences = Vec::new();
    let class = node
        .class_b64
        .as_ref()
        .map(|c| c.0.clone())
        .unwrap_or_default();
    if info.class.encode_utf16().collect::<Vec<_>>() != class {
        differences.push(Difference {
            at: String::new(),
            kind: DifferenceKind::RootClassKept,
        });
    }
    let live_sddl = root
        .security_sddl()
        .map_err(|e| failed_early("", "read security", e))?;
    if live_sddl != node.sddl {
        differences.push(Difference {
            at: String::new(),
            kind: DifferenceKind::RootSecurityKept,
        });
    }

    let mut restorer = Restorer::for_undo(tree);
    let mut set_values: Vec<String> = Vec::new();
    let mut result = Ok(());
    for value in &node.values {
        let Some(vname) = name_of(&value.name_b64) else {
            result = Err(restorer.fail(0, "read value name", NAME_NOT_REPRESENTABLE));
            break;
        };
        if let Err(e) = root.set_value_raw(&vname, value.value_type, &value.data_b64.0) {
            result = Err(restorer.fail(0, "set value", e));
            break;
        }
        set_values.push(vname);
    }
    if result.is_ok() {
        for child in child_lists(tree)[0].clone() {
            result = restorer.restore_subtree(&root, child);
            if result.is_err() {
                break;
            }
        }
    }
    match result {
        Ok(()) => {
            differences.append(&mut restorer.differences);
            Ok(RestoreReport {
                outcome: RestoreOutcome::Restored,
                keys_created: restorer.created.len(),
                differences,
            })
        }
        Err(failure) => {
            let mut rollback = restorer.remove_created();
            if rollback.is_complete() {
                let keys = match &rollback {
                    Rollback::Done { keys, .. } => *keys,
                    _ => 0,
                };
                for vname in set_values.iter().rev() {
                    if let Err(error) = root.delete_value(vname) {
                        rollback = Rollback::Incomplete {
                            failure: Box::new(KeyOpError {
                                at: String::new(),
                                op: "remove restored value",
                                error,
                            }),
                            keys,
                        };
                        break;
                    }
                }
                if rollback == Rollback::NotNeeded && !set_values.is_empty() {
                    rollback = Rollback::Done {
                        keys: 0,
                        differences: Vec::new(),
                    };
                }
            }
            Err(RestoreError::Failed { failure, rollback })
        }
    }
}

/// Completes a partly deleted (or partly restored) tree below `parent` from its backup: for recovery,
/// where the journal shows that the missing keys were Purge's own (an intent without its done record).
///
/// Every existing key must match its backup node (owners aside) and have no subkey outside the backup;
/// otherwise nothing is changed and [`RestoreConflict::Diverged`] is returned. The missing subtrees are
/// then created as in [`restore_tree`], all or nothing. An absent root is restored whole; an intact tree
/// is [`RestoreOutcome::AlreadyRestored`]. The protected-root rule does not apply: nothing that exists is
/// changed. `parent` and [`RestoreError::NotThisKey`] as for [`restore_tree`].
pub fn complete_tree(
    parent: &CheckedKeyParent,
    backup: &VerifiedBackup,
) -> Result<RestoreReport, RestoreError> {
    let tree = tree_below(parent, backup)?;
    let parent_key = parent.parent();
    parent_not_link(parent_key)?;
    let Some(root) = open_root(parent_key, tree)? else {
        return restore_fresh(parent_key, tree);
    };
    let walk = walk_existing(&root, tree, false, true).map_err(walk_failed)?;
    if let Some((index, change)) = walk.diverged {
        if (index, change) == (0, Change::BecameLink) {
            return Err(RestoreError::Conflict(RestoreConflict::Link));
        }
        return Err(RestoreError::Conflict(RestoreConflict::Diverged {
            at: display_path(tree, index),
            change,
        }));
    }
    create_missing(&root, &walk, tree, Vec::new())
}

/// Puts back the keys of the backup that are missing below `parent` (the gate's checked parent, as for
/// [`restore_tree`]), and nothing else: the repair after a resumed delete stopped with
/// [`Rollback::PartialBefore`], or after any interrupted delete or restore whose tree no longer matches
/// the backup ([`TreeState::Diverged`]).
///
/// Never changes a key that exists: a key that differs from its backup node (another value, an extra
/// subkey, ...) stays as it is and the first one found is reported as
/// [`DifferenceKind::ExistingKeyDiffers`]; the missing subtrees are created below the keys that exist,
/// parent-first, with their recorded class, security and values, all or nothing. The result is the
/// backup plus the changes made to it since. An absent root is restored whole. A link where a backup
/// key is ([`RestoreConflict::Link`]), or a backup name that cannot be opened
/// ([`RestoreConflict::Diverged`]), hides what is below it; then nothing is created. Nothing missing is
/// [`RestoreOutcome::AlreadyRestored`]. The protected-root rule does not apply: nothing that exists is
/// changed.
pub fn restore_missing(
    parent: &CheckedKeyParent,
    backup: &VerifiedBackup,
) -> Result<RestoreReport, RestoreError> {
    let tree = tree_below(parent, backup)?;
    let parent_key = parent.parent();
    parent_not_link(parent_key)?;
    let Some(root) = open_root(parent_key, tree)? else {
        return restore_fresh(parent_key, tree);
    };
    let walk = walk_existing(&root, tree, false, false).map_err(walk_failed)?;
    match walk.blocked {
        Some((_, Change::BecameLink)) => {
            return Err(RestoreError::Conflict(RestoreConflict::Link));
        }
        Some((index, change)) => {
            return Err(RestoreError::Conflict(RestoreConflict::Diverged {
                at: display_path(tree, index),
                change,
            }));
        }
        None => {}
    }
    let differences = walk
        .diverged
        .map(|(index, change)| Difference {
            at: display_path(tree, index),
            kind: DifferenceKind::ExistingKeyDiffers { change },
        })
        .into_iter()
        .collect();
    create_missing(&root, &walk, tree, differences)
}

/// Creates every missing subtree a walk found below the keys it opened, all or nothing.
/// `differences` go in front of the restorer's own.
fn create_missing(
    root: &WKey,
    walk: &Walk,
    tree: &RegTree,
    mut differences: Vec<Difference>,
) -> Result<RestoreReport, RestoreError> {
    if walk.missing_roots.is_empty() {
        return Ok(RestoreReport {
            outcome: RestoreOutcome::AlreadyRestored,
            keys_created: 0,
            differences,
        });
    }
    let mut restorer = Restorer::for_undo(tree);
    for &missing in &walk.missing_roots {
        let parent_index = tree.keys[missing].parent.map_or(0, |p| p as usize);
        let result = match walk.handle(root, parent_index) {
            Some(parent_key) => restorer.restore_subtree(parent_key, missing),
            None => Err(restorer.fail(missing, "find parent", Win32Error::INVALID_DATA)),
        };
        if let Err(failure) = result {
            return Err(RestoreError::Failed {
                failure,
                rollback: restorer.remove_created(),
            });
        }
    }
    differences.append(&mut restorer.differences);
    Ok(RestoreReport {
        outcome: RestoreOutcome::Restored,
        keys_created: restorer.created.len(),
        differences,
    })
}

// ---------------------------------------------------------------------------------------------------
// Tree delete
// ---------------------------------------------------------------------------------------------------

/// How a delete walk ended.
enum Walked {
    Finished(usize),
    /// The hook stopped the walk without any rollback (a simulated crash, tests only).
    Interrupted,
}

/// One open key on the way down.
struct Frame {
    index: usize,
    /// `None` for the root, whose handle is the caller's.
    key: Option<WKey>,
    next: usize,
}

/// What one step of the delete walk decided.
enum Step {
    Push(Frame),
    Skip,
    Deleted,
    Fail(usize, DeleteFailure),
}

/// Maps a comparing call's outcome to a step.
fn compare_step(
    index: usize,
    result: Result<Option<Change>, (Win32Error, &'static str)>,
) -> Option<Step> {
    match result {
        Ok(None) => None,
        Ok(Some(change)) => Some(Step::Fail(index, DeleteFailure::Changed(change))),
        Err((error, op)) => Some(Step::Fail(index, DeleteFailure::Os { op, error })),
    }
}

/// The delete walk: post-order over the backup tree, one handle per key on the way down (opened with
/// `KeyAccess::DELETE` from its parent's handle), each key compared on the way down and again right
/// before it is deleted through its own handle. `resume` skips backup keys that are already gone
/// (recovery after an interruption). `hook` runs before each key's final check and delete; returning
/// `false` stops the walk as a crash would.
fn delete_walk(
    root: &WKey,
    tree: &RegTree,
    resume: bool,
    hook: &mut dyn FnMut(usize) -> bool,
) -> Result<Walked, DeleteError> {
    let n = tree.keys.len();
    let children = child_lists(tree);
    let mut deleted = vec![false; n];
    let mut count = 0usize;
    let mut stack: Vec<Frame> = Vec::new();

    let first = match compare_step(0, compare_with_children(root, tree, &children, 0, true)) {
        Some(step) => step,
        None => Step::Push(Frame {
            index: 0,
            key: None,
            next: 0,
        }),
    };
    let mut step = first;
    loop {
        match step {
            Step::Push(frame) => stack.push(frame),
            Step::Skip => {}
            Step::Deleted => {
                if let Some(frame) = stack.pop() {
                    deleted[frame.index] = true;
                    count += 1;
                }
            }
            Step::Fail(index, failure) => {
                let mut rollback = put_back(root, tree, &children, &stack, &deleted);
                if resume {
                    rollback = missing_before(root, tree, rollback);
                }
                return Err(DeleteError {
                    at: display_path(tree, index),
                    failure,
                    rollback,
                });
            }
        }
        let Some(top) = stack.last_mut() else {
            return Ok(Walked::Finished(count));
        };
        let index = top.index;
        let handle = top.key.as_ref().unwrap_or(root);
        step = if let Some(&child) = children[index].get(top.next) {
            top.next += 1;
            match name_of(&tree.keys[child].name_b64) {
                None => Step::Fail(child, DeleteFailure::Changed(Change::NameNotRepresentable)),
                Some(name) => match handle.open_subkey(&name, KeyAccess::DELETE) {
                    Ok(key) => compare_step(
                        child,
                        compare_with_children(&key, tree, &children, child, true),
                    )
                    .unwrap_or(Step::Push(Frame {
                        index: child,
                        key: Some(key),
                        next: 0,
                    })),
                    Err(e) if e.is_not_found() && resume => Step::Skip,
                    Err(e) if e.is_not_found() => {
                        Step::Fail(child, DeleteFailure::Changed(Change::Missing))
                    }
                    Err(e) if e == Win32Error::LINK_ON_PATH => {
                        Step::Fail(index, DeleteFailure::Changed(Change::BecameLink))
                    }
                    Err(error) => Step::Fail(
                        child,
                        DeleteFailure::Os {
                            op: "open key",
                            error,
                        },
                    ),
                },
            }
        } else {
            // Fault point for crash tests: between the deletes of two keys. Hit only once a key is
            // gone, so the process dies with some keys of the tree deleted and this one still there.
            if count > 0 {
                fault::point(fault::REGDELETE_MID);
            }
            if !hook(index) {
                return Ok(Walked::Interrupted);
            }
            let node = &tree.keys[index];
            match compare_step(
                index,
                compare_node(handle, node, true).map(|c| c.map(|(c, _)| c)),
            ) {
                Some(step) => step,
                // A key backed up without values is deleted only while it is still empty: the
                // counts are read again on the handle right before the delete, so a value written
                // since the comparison is not lost with the key.
                None => match if node.values.is_empty() {
                    handle.delete_if_empty()
                } else {
                    handle.delete()
                } {
                    Ok(()) => Step::Deleted,
                    Err(e) if e == HAS_SUBKEYS => {
                        Step::Fail(index, DeleteFailure::Changed(Change::ExtraSubkey))
                    }
                    Err(e) if e == HAS_VALUES => {
                        Step::Fail(index, DeleteFailure::Changed(Change::ValuesDiffer))
                    }
                    Err(e) => match as_change(e) {
                        Ok(change) => Step::Fail(index, DeleteFailure::Changed(change)),
                        Err(error) => Step::Fail(
                            index,
                            DeleteFailure::Os {
                                op: "delete key",
                                error,
                            },
                        ),
                    },
                },
            }
        };
    }
}

/// After a stopped delete: puts every deleted subtree back below the key on the stack it hangs from. A
/// post-order walk only ever has whole subtrees deleted, each one the child of a key still on the stack.
fn put_back(
    root: &WKey,
    tree: &RegTree,
    children: &[Vec<usize>],
    stack: &[Frame],
    deleted: &[bool],
) -> Rollback {
    if !deleted.iter().any(|&d| d) {
        return Rollback::NotNeeded;
    }
    let mut keys = 0;
    let mut differences = Vec::new();
    for frame in stack {
        let handle = frame.key.as_ref().unwrap_or(root);
        for &child in &children[frame.index] {
            if !deleted[child] {
                continue;
            }
            let mut restorer = Restorer::new(tree);
            let result = restorer.restore_subtree(handle, child);
            keys += restorer.created.len();
            differences.append(&mut restorer.differences);
            if let Err(failure) = result {
                // Keep what was put back: it is part of the original tree.
                return Rollback::Incomplete {
                    failure: Box::new(failure),
                    keys,
                };
            }
        }
    }
    Rollback::Done { keys, differences }
}

/// After a resumed delete stopped and put back what it had deleted itself: whether keys of the backup
/// that the interrupted run before it deleted are still missing below `root`. If so the rollback is
/// [`Rollback::PartialBefore`], never "complete": the tree is half deleted. Keys below a link (which the
/// failure itself reports) are not looked at. If the tree cannot be read, the rollback is
/// [`Rollback::Incomplete`].
fn missing_before(root: &WKey, tree: &RegTree, rollback: Rollback) -> Rollback {
    let (keys, differences) = match rollback {
        Rollback::NotNeeded => (0, Vec::new()),
        Rollback::Done { keys, differences } => (keys, differences),
        unfinished => return unfinished,
    };
    match walk_existing(root, tree, false, false) {
        Ok(walk) if walk.missing_keys > 0 => Rollback::PartialBefore {
            missing: walk.missing_keys,
            keys,
            differences,
        },
        Ok(_) if keys == 0 && differences.is_empty() => Rollback::NotNeeded,
        Ok(_) => Rollback::Done { keys, differences },
        Err(failure) => Rollback::Incomplete {
            failure: Box::new(failure),
            keys,
        },
    }
}

/// Runs a delete walk with no hook.
fn run_delete(
    root: &WKey,
    backup: &VerifiedBackup,
    resume: bool,
) -> Result<DeleteReport, DeleteError> {
    let Some(tree) = backup.tree() else {
        return Err(DeleteError {
            at: String::new(),
            failure: DeleteFailure::WrongBackupKind,
            rollback: Rollback::NotNeeded,
        });
    };
    match delete_walk(root, tree, resume, &mut |_| true)? {
        Walked::Finished(keys_deleted) => Ok(DeleteReport { keys_deleted }),
        Walked::Interrupted => Err(DeleteError {
            at: String::new(),
            failure: DeleteFailure::Os {
                op: "delete walk",
                error: REQUEST_ABORTED,
            },
            rollback: Rollback::NotNeeded,
        }),
    }
}

/// Deletes the key tree behind `root` that `backup` holds, deepest first.
///
/// `root` must be the handle the gate inspected, opened with [`KeyAccess::DELETE`]. Every other key is
/// opened from its parent's handle by its backed-up name (with `REG_OPTION_OPEN_LINK`, never through a
/// link), compared with its backup node on the way down and again right before it is deleted through
/// that same handle ([`WKey::delete`], or [`WKey::delete_if_empty`] for a key backed up without values;
/// never by name). A key that is missing, became a link, has a subkey or a value not in the backup, or
/// another volatility, class or security descriptor stops the delete with
/// [`DeleteFailure::Changed`]; the keys already deleted are then put back from the backup and
/// [`DeleteError::rollback`] says how that went. Keys that are not in the backup are never opened.
pub fn delete_tree(root: &WKey, backup: &VerifiedBackup) -> Result<DeleteReport, DeleteError> {
    run_delete(root, backup, false)
}

/// As [`delete_tree`], for recovery after an interrupted delete: backup keys that are already gone are
/// taken as deleted by the interrupted run and skipped. Use it only when the journal shows the delete's
/// intent without its done record.
///
/// `parent` is the parent of the backup's key as the gate opened and checked it
/// ([`gate::check_undo_key`] on the journalled target): recovery cannot gate the half-deleted root
/// itself against facts recorded before the delete. The root is opened below it with
/// [`KeyAccess::DELETE`] and `REG_OPTION_OPEN_LINK` (a link root stops the delete as
/// [`Change::BecameLink`]); an absent root means the interrupted run had finished (`Ok` with no key
/// deleted); a parent whose leaf is not the backup's root key is [`DeleteFailure::NotThisKey`].
///
/// When the resumed delete stops, the keys it deleted are put back; keys the interrupted run had
/// deleted are not, and [`Rollback::PartialBefore`] says how many are still missing. The two ways out
/// both work from the backup alone: call this again once the change is gone (finish the delete), or
/// [`restore_missing`] (put the tree back as the backup holds it, plus the change).
///
/// [`gate::check_undo_key`]: crate::gate::check_undo_key
pub fn finish_delete_tree(
    parent: &CheckedKeyParent,
    backup: &VerifiedBackup,
) -> Result<DeleteReport, DeleteError> {
    let stop = |failure| DeleteError {
        at: String::new(),
        failure,
        rollback: Rollback::NotNeeded,
    };
    let tree = match tree_below(parent, backup) {
        Ok(tree) => tree,
        Err(RestoreError::NotThisKey) => return Err(stop(DeleteFailure::NotThisKey)),
        Err(_) => return Err(stop(DeleteFailure::WrongBackupKind)),
    };
    let Some(name) = name_of(&tree.keys[0].name_b64) else {
        return Err(stop(DeleteFailure::Changed(Change::NameNotRepresentable)));
    };
    let root = match parent.parent().open_subkey(&name, KeyAccess::DELETE) {
        Ok(root) => root,
        Err(e) if e.is_not_found() => return Ok(DeleteReport { keys_deleted: 0 }),
        Err(e) if e == Win32Error::LINK_ON_PATH => {
            return Err(stop(DeleteFailure::Changed(Change::BecameLink)));
        }
        Err(error) => {
            return Err(stop(DeleteFailure::Os {
                op: "open key",
                error,
            }));
        }
    };
    run_delete(&root, backup, true)
}

// ---------------------------------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------------------------------

/// Deletes the value that `backup` holds from `key` (opened with [`KeyAccess::SET_VALUE`]) after reading
/// it again: [`ValueDelete::Vanished`] when it is gone, [`Change::ValuesDiffer`] when its type or data
/// changed, [`Change::BecameLink`] when the key is a link.
pub fn delete_value(key: &WKey, backup: &VerifiedBackup) -> Result<ValueDelete, DeleteFailure> {
    let value = backup.value().ok_or(DeleteFailure::WrongBackupKind)?;
    let name =
        name_of(&value.name_b64).ok_or(DeleteFailure::Changed(Change::NameNotRepresentable))?;
    let os = |op| move |error| DeleteFailure::Os { op, error };
    if key.is_link().map_err(os("query link value"))? {
        return Err(DeleteFailure::Changed(Change::BecameLink));
    }
    match key.value(&name).map_err(os("read value"))? {
        None => Ok(ValueDelete::Vanished),
        Some(live) if live.ty == value.value_type && live.data == value.data_b64.0 => {
            match key.delete_value(&name) {
                Ok(()) => Ok(ValueDelete::Deleted),
                Err(e) if e.is_not_found() => Ok(ValueDelete::Vanished),
                Err(e) => Err(os("delete value")(e)),
            }
        }
        Some(_) => Err(DeleteFailure::Changed(Change::ValuesDiffer)),
    }
}

/// Restores the value that `backup` holds into `key` (the key the gate opened with
/// [`KeyAccess::SET_VALUE`] and checked, [`gate::check_undo_key`]): absent → written and read back;
/// present with the same type and data → [`RestoreOutcome::AlreadyRestored`]; present otherwise →
/// [`RestoreConflict::ValueDiffers`]. The key is the backup's because the caller validated the backup
/// for the operation (`RegBackup::validate_for`, the same key text) and the gate resolved that
/// operation's journalled target.
///
/// [`gate::check_undo_key`]: crate::gate::check_undo_key
pub fn restore_value(
    key: &CheckedValueKey,
    backup: &VerifiedBackup,
) -> Result<RestoreReport, RestoreError> {
    let key = key.key();
    let value = backup.value().ok_or(RestoreError::WrongBackupKind)?;
    let name = name_of(&value.name_b64)
        .ok_or_else(|| failed_early("", "read value name", NAME_NOT_REPRESENTABLE))?;
    match key.is_link() {
        Ok(false) => {}
        Ok(true) => return Err(RestoreError::Conflict(RestoreConflict::Link)),
        Err(e) => return Err(failed_early("", "query link value", e)),
    }
    let same = |live: &RegValue| live.ty == value.value_type && live.data == value.data_b64.0;
    match key.value(&name) {
        Ok(Some(live)) if same(&live) => Ok(RestoreReport {
            outcome: RestoreOutcome::AlreadyRestored,
            keys_created: 0,
            differences: Vec::new(),
        }),
        Ok(Some(_)) => Err(RestoreError::Conflict(RestoreConflict::ValueDiffers)),
        Ok(None) => {
            key.set_value_raw(&name, value.value_type, &value.data_b64.0)
                .map_err(|e| failed_early("", "set value", e))?;
            let back = key
                .value(&name)
                .map_err(|e| failed_early("", "read value", e))?;
            if back.as_ref().is_some_and(same) {
                Ok(RestoreReport {
                    outcome: RestoreOutcome::Restored,
                    keys_created: 0,
                    differences: Vec::new(),
                })
            } else {
                Err(RestoreError::Failed {
                    failure: KeyOpError {
                        at: String::new(),
                        op: "verify value",
                        error: Win32Error::INVALID_DATA,
                    },
                    rollback: Rollback::NotNeeded,
                })
            }
        }
        Err(e) => Err(failed_early("", "read value", e)),
    }
}

// ---------------------------------------------------------------------------------------------------
// Segments
// ---------------------------------------------------------------------------------------------------

/// Why a segment edit or its inverse was not done.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SegmentError {
    /// The value is not a list Purge edits: not `REG_SZ`, `REG_EXPAND_SZ` or `REG_MULTI_SZ`, an odd
    /// number of bytes, or a NUL or an unclosed double quote inside a `;` list.
    #[error("the value is not an editable list")]
    NotAList,
    /// The segment is empty, holds a NUL, or in a `;` list is not one element (a `;` outside quotes,
    /// or an unclosed quote).
    #[error("the segment cannot be a list element")]
    BadSegment,
    /// The value does not exist.
    #[error("the value does not exist")]
    ValueAbsent,
    /// The segment is not in the value (the edit's item vanished).
    #[error("the segment is not in the value")]
    SegmentAbsent,
    /// The value changed since the edit was planned, or (undo) it holds what Purge wrote but the segment
    /// cannot be put back so that the original data results.
    #[error("the value changed")]
    Changed,
    /// The key is a registry link.
    #[error("the key is a registry link")]
    KeyIsLink,
    /// The value read back after the write is not what was written.
    #[error("the value did not read back as written")]
    VerifyFailed,
    /// A call failed.
    #[error(transparent)]
    Os(#[from] KeyOpError),
}

impl SegmentError {
    /// The journal's form of this error when it stops an undo, if it is a conflict.
    pub fn undo_conflict(&self) -> Option<UndoConflict> {
        match self {
            Self::NotAList | Self::ValueAbsent | Self::Changed => Some(UndoConflict::ValueChanged),
            Self::KeyIsLink => Some(UndoConflict::GateBlocked {
                blocker: Blocker::RegLink,
            }),
            Self::BadSegment | Self::SegmentAbsent | Self::VerifyFailed | Self::Os(_) => None,
        }
    }
}

/// How a list value separates its elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListKind {
    /// `REG_SZ` / `REG_EXPAND_SZ` with `;` between elements.
    Semicolon,
    /// `REG_MULTI_SZ` with NUL between elements.
    MultiSz,
}

impl ListKind {
    fn of(ty: u32) -> Option<ListKind> {
        match ty {
            REG_SZ | REG_EXPAND_SZ => Some(ListKind::Semicolon),
            REG_MULTI_SZ => Some(ListKind::MultiSz),
            _ => None,
        }
    }

    fn separator(self) -> u16 {
        match self {
            ListKind::Semicolon => u16::from(b';'),
            ListKind::MultiSz => 0,
        }
    }
}

/// A list value taken apart: the elements, and the NUL units that end the data (kept as they were).
#[derive(Debug, Clone, PartialEq, Eq)]
struct List {
    kind: ListKind,
    segments: Vec<Vec<u16>>,
    terminators: usize,
}

impl List {
    fn parse(ty: u32, data: &[u8]) -> Result<List, SegmentError> {
        let kind = ListKind::of(ty).ok_or(SegmentError::NotAList)?;
        if data.len() % 2 != 0 {
            return Err(SegmentError::NotAList);
        }
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let body_len = units.iter().rposition(|&u| u != 0).map_or(0, |p| p + 1);
        let body = &units[..body_len];
        if kind == ListKind::Semicolon && body.contains(&0) {
            return Err(SegmentError::NotAList);
        }
        let segments = if body.is_empty() {
            Vec::new()
        } else if kind == ListKind::Semicolon {
            split_semicolons(body).ok_or(SegmentError::NotAList)?
        } else {
            body.split(|&u| u == kind.separator())
                .map(<[u16]>::to_vec)
                .collect()
        };
        Ok(List {
            kind,
            segments,
            terminators: units.len() - body_len,
        })
    }

    fn render(&self) -> Vec<u8> {
        let mut units: Vec<u16> = Vec::new();
        for (i, segment) in self.segments.iter().enumerate() {
            if i > 0 {
                units.push(self.kind.separator());
            }
            units.extend_from_slice(segment);
        }
        units.extend(std::iter::repeat_n(0u16, self.terminators));
        units.iter().flat_map(|u| u.to_le_bytes()).collect()
    }

    /// Every reading of the same data: an empty body may be no element or one empty element, and NULs at
    /// the end of a `REG_MULTI_SZ` may be terminators or separators of empty trailing elements.
    fn readings(&self) -> Vec<List> {
        let data = self.render();
        let mut out = vec![self.clone()];
        let mut push = |list: List| {
            if list.render() == data && !out.contains(&list) {
                out.push(list);
            }
        };
        if self.segments.is_empty() {
            push(List {
                segments: vec![Vec::new()],
                ..self.clone()
            });
        }
        if self.kind == ListKind::MultiSz {
            for k in 1..=self.terminators {
                let mut list = self.clone();
                if list.segments.is_empty() {
                    list.segments.push(Vec::new());
                }
                list.segments.extend(std::iter::repeat_n(Vec::new(), k));
                list.terminators -= k;
                push(list);
            }
        }
        out
    }

    fn insert(&self, index: u32, segment: &[u16]) -> List {
        let mut list = self.clone();
        let at = (index as usize).min(list.segments.len());
        list.segments.insert(at, segment.to_vec());
        list
    }
}

/// Splits the body of a `;` list at every `;` outside double quotes: Windows reads
/// `"C:\a;b";C:\c` as two entries, the first one quoted. `None` when a quote is left open, which no
/// reader agrees on.
fn split_semicolons(body: &[u16]) -> Option<Vec<Vec<u16>>> {
    let quote = u16::from(b'"');
    let separator = u16::from(b';');
    let mut segments = Vec::new();
    let mut current = Vec::new();
    let mut quoted = false;
    for &unit in body {
        if unit == quote {
            quoted = !quoted;
        }
        if unit == separator && !quoted {
            segments.push(std::mem::take(&mut current));
        } else {
            current.push(unit);
        }
    }
    if quoted {
        return None;
    }
    segments.push(current);
    Some(segments)
}

/// The segment as UTF-16, checked for the list kind: never empty or with a NUL, and in a `;` list one
/// element (a `;` only inside quotes, every quote closed).
fn segment_units(kind: ListKind, segment: &str) -> Result<Vec<u16>, SegmentError> {
    let units: Vec<u16> = segment.encode_utf16().collect();
    let one_element = match kind {
        ListKind::Semicolon => split_semicolons(&units).is_some_and(|parts| parts.len() == 1),
        ListKind::MultiSz => true,
    };
    if units.is_empty() || units.contains(&0) || !one_element {
        return Err(SegmentError::BadSegment);
    }
    Ok(units)
}

/// A planned segment removal: everything the journal's intent needs before the value is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentRemoval {
    /// The value name (`""` for the default value).
    pub name: String,
    /// The segment text.
    pub segment: String,
    /// Zero-based position of the removed element (empty elements count).
    pub index: u32,
    /// The whole value before the edit, for a value backup.
    pub original: ValueBackup,
    /// SHA-256 of the data before the edit.
    pub original_value_hash: Sha256Hex,
    /// The data the edit writes (same type, same terminators).
    pub written: Vec<u8>,
    /// SHA-256 of `written`.
    pub written_value_hash: Sha256Hex,
}

/// Reads value `name` of `key` and plans the removal of `segment`: the element at `index` when it is the
/// segment, else the first element equal to it (exact, case-sensitive match). Changes nothing.
///
/// `;` lists (`REG_SZ`, `REG_EXPAND_SZ`) and `REG_MULTI_SZ` keep their type, their empty elements and
/// their terminating NULs exactly; other types are refused ([`SegmentError::NotAList`]).
pub fn plan_segment_removal(
    key: &WKey,
    name: &str,
    segment: &str,
    index: Option<u32>,
) -> Result<SegmentRemoval, SegmentError> {
    let os = |op| {
        move |error| {
            SegmentError::Os(KeyOpError {
                at: String::new(),
                op,
                error,
            })
        }
    };
    if key.is_link().map_err(os("query link value"))? {
        return Err(SegmentError::KeyIsLink);
    }
    let value = key
        .value(name)
        .map_err(os("read value"))?
        .ok_or(SegmentError::ValueAbsent)?;
    let list = List::parse(value.ty, &value.data)?;
    let units = segment_units(list.kind, segment)?;
    let position = match index {
        Some(i) if list.segments.get(i as usize) == Some(&units) => i as usize,
        _ => list
            .segments
            .iter()
            .position(|s| *s == units)
            .ok_or(SegmentError::SegmentAbsent)?,
    };
    let mut edited = list.clone();
    edited.segments.remove(position);
    let written = edited.render();
    Ok(SegmentRemoval {
        name: name.to_owned(),
        segment: segment.to_owned(),
        index: u32::try_from(position).map_err(|_| SegmentError::NotAList)?,
        original_value_hash: sha256(&value.data),
        original: ValueBackup {
            name_b64: WideB64::from(name),
            value_type: value.ty,
            data_b64: BytesB64(value.data),
        },
        written_value_hash: sha256(&written),
        written,
    })
}

/// Writes a planned removal: reads the value again and writes the planned data only while the value is
/// still exactly what was planned from ([`SegmentError::Changed`] otherwise, so the caller can plan
/// again), then reads it back. `key` needs [`KeyAccess::SET_VALUE`].
pub fn apply_segment_removal(key: &WKey, plan: &SegmentRemoval) -> Result<(), SegmentError> {
    let os = |op| {
        move |error| {
            SegmentError::Os(KeyOpError {
                at: String::new(),
                op,
                error,
            })
        }
    };
    if key.is_link().map_err(os("query link value"))? {
        return Err(SegmentError::KeyIsLink);
    }
    let live = key
        .value(&plan.name)
        .map_err(os("read value"))?
        .ok_or(SegmentError::ValueAbsent)?;
    if live.ty != plan.original.value_type || sha256(&live.data) != plan.original_value_hash {
        return Err(SegmentError::Changed);
    }
    key.set_value_raw(&plan.name, live.ty, &plan.written)
        .map_err(os("set value"))?;
    match key.value(&plan.name).map_err(os("read value"))? {
        Some(back) if back.ty == live.ty && back.data == plan.written => Ok(()),
        _ => Err(SegmentError::VerifyFailed),
    }
}

/// What [`reinsert_segment`] needs: the journal's `ReinsertSegment` inverse, and the value backup when
/// one was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentUndo {
    /// The value name (`""` for the default value).
    pub name: String,
    /// The segment text.
    pub segment: String,
    /// The position it was removed from.
    pub index: u32,
    /// SHA-256 of the data before the edit.
    pub original_value_hash: Sha256Hex,
    /// SHA-256 of the data the edit wrote.
    pub written_value_hash: Sha256Hex,
    /// The whole value before the edit, from a verified backup, when there is one.
    pub original: Option<ValueBackup>,
}

/// How a segment re-insert ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReinsertOutcome {
    /// The value holds its original data already.
    AlreadyRestored,
    /// The segment is in the value already (put back by someone else); nothing was changed.
    AlreadyPresent,
    /// The segment was put back. `exact` when the value was what Purge wrote, so the original data is
    /// back byte for byte; otherwise the segment went in at the recorded index (clamped) of the changed
    /// value.
    Reinserted {
        /// Whether the original data was restored exactly.
        exact: bool,
    },
}

/// Puts a removed segment back into value `undo.name` of `key` (the key the gate opened with
/// [`KeyAccess::SET_VALUE`] and checked, [`gate::check_undo_key`](crate::gate::check_undo_key)):
///
/// - value data equal to the original: [`ReinsertOutcome::AlreadyRestored`];
/// - value equal to what Purge wrote: the original data is written back (from the backup when given,
///   otherwise rebuilt and accepted only when it hashes to the original), also when a duplicate of the
///   segment is still in the list;
/// - value changed otherwise and the segment present: [`ReinsertOutcome::AlreadyPresent`];
/// - value changed otherwise and the segment merely missing: the segment is inserted at the recorded
///   index, clamped to the list length, keeping the value's type and terminators;
/// - value gone or no longer a list: [`SegmentError::ValueAbsent`] / [`SegmentError::NotAList`].
pub fn reinsert_segment(
    key: &CheckedValueKey,
    undo: &SegmentUndo,
) -> Result<ReinsertOutcome, SegmentError> {
    let key = key.key();
    let os = |op| {
        move |error| {
            SegmentError::Os(KeyOpError {
                at: String::new(),
                op,
                error,
            })
        }
    };
    if key.is_link().map_err(os("query link value"))? {
        return Err(SegmentError::KeyIsLink);
    }
    let live = key
        .value(&undo.name)
        .map_err(os("read value"))?
        .ok_or(SegmentError::ValueAbsent)?;
    let live_hash = sha256(&live.data);
    if live_hash == undo.original_value_hash {
        return Ok(ReinsertOutcome::AlreadyRestored);
    }
    let list = List::parse(live.ty, &live.data)?;
    let units = segment_units(list.kind, &undo.segment)?;
    // A value that is exactly what Purge wrote may still hold the segment: a duplicate the edit left.
    if live_hash != undo.written_value_hash && list.segments.contains(&units) {
        return Ok(ReinsertOutcome::AlreadyPresent);
    }
    let (data, exact) = if live_hash == undo.written_value_hash {
        let from_backup = undo.original.as_ref().filter(|original| {
            original.value_type == live.ty
                && sha256(&original.data_b64.0) == undo.original_value_hash
        });
        let data = match from_backup {
            Some(original) => original.data_b64.0.clone(),
            None => list
                .readings()
                .iter()
                .map(|reading| reading.insert(undo.index, &units).render())
                .find(|data| sha256(data) == undo.original_value_hash)
                .ok_or(SegmentError::Changed)?,
        };
        (data, true)
    } else {
        (list.insert(undo.index, &units).render(), false)
    };
    key.set_value_raw(&undo.name, live.ty, &data)
        .map_err(os("set value"))?;
    match key.value(&undo.name).map_err(os("read value"))? {
        Some(back) if back.ty == live.ty && back.data == data => {
            Ok(ReinsertOutcome::Reinserted { exact })
        }
        _ => Err(SegmentError::VerifyFailed),
    }
}

#[cfg(test)]
mod tests {
    //! Live tests write only below a fresh `HKU\<current SID>\Software\PurgeTest-<random>` key, removed on
    //! drop (also on failure), and inside fresh temp directories. They run unelevated.

    use super::*;
    // Raw calls for what `WKey` deliberately cannot do: create and delete links, odd names.
    use crate::test_ffi::{
        DELETE_ACCESS, Hkey, KEY_ALL_ACCESS, KEY_SET_VALUE, KEY_WOW64_64KEY, NtDeleteKey,
        REG_OPTION_CREATE_LINK, REG_OPTION_OPEN_LINK, RegCloseKey, RegCreateKeyExW, RegOpenKeyExW,
        RegSetValueExW, hkey_users, wz,
    };
    use purge_guard::live::KeyRoot;
    use purge_model::View;
    use purge_win::reg::{
        REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_NONE, REG_QWORD, RegRoot, RegView,
    };
    use purge_win::sid::current_user_sid;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A raw key handle, closed on drop.
    struct RawKey(Hkey);

    impl Drop for RawKey {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful open or create and is closed once here.
            unsafe { RegCloseKey(self.0) };
        }
    }

    /// Opens `HKU\<path>` raw, as the key itself even when it is a link.
    fn raw_open(path: &str, access: u32) -> Result<RawKey, u32> {
        let w = wz(path);
        let mut out: Hkey = std::ptr::null_mut();
        // SAFETY: `w` is NUL-terminated and outlives the call; `out` is a valid out-pointer.
        let rc = unsafe {
            RegOpenKeyExW(
                hkey_users(),
                w.as_ptr(),
                REG_OPTION_OPEN_LINK,
                access | KEY_WOW64_64KEY,
                &mut out,
            )
        };
        if rc == 0 { Ok(RawKey(out)) } else { Err(rc) }
    }

    /// Creates the link `HKU\<parent>\<name>` pointing at NT path `target`.
    fn make_link(parent: &str, name: &str, target: &str) {
        let parent = raw_open(parent, KEY_ALL_ACCESS).expect("open link parent");
        let w = wz(name);
        let mut out: Hkey = std::ptr::null_mut();
        // SAFETY: `w` is NUL-terminated; class, security attributes and disposition are null; `out` is
        // a valid out-pointer.
        let rc = unsafe {
            RegCreateKeyExW(
                parent.0,
                w.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_CREATE_LINK,
                KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                std::ptr::null(),
                &mut out,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "create link {name}");
        let link = RawKey(out);
        let data: Vec<u8> = target.encode_utf16().flat_map(u16::to_le_bytes).collect();
        raw_set(&link, &wz("SymbolicLinkValue"), REG_LINK, &data);
    }

    /// Sets a value whose name is given as raw NUL-terminated units (it may be unrepresentable).
    fn raw_set(key: &RawKey, name_z: &[u16], ty: u32, data: &[u8]) {
        // SAFETY: `name_z` is NUL-terminated; `data` has the stated number of readable bytes.
        let rc = unsafe {
            RegSetValueExW(
                key.0,
                name_z.as_ptr(),
                0,
                ty,
                data.as_ptr(),
                data.len() as u32,
            )
        };
        assert_eq!(rc, 0, "raw set value");
    }

    /// Deletes the key `HKU\<path>` itself through its own handle (links included, never followed).
    fn raw_delete(path: &str) -> Result<(), u32> {
        let key = raw_open(path, DELETE_ACCESS)?;
        // SAFETY: the handle is live and was opened with DELETE.
        let status = unsafe { NtDeleteKey(key.0) };
        if status >= 0 {
            Ok(())
        } else {
            Err(status as u32)
        }
    }

    /// Deletes `name` below `parent` with everything in it. Links are deleted as keys, never followed.
    fn nuke(parent: &WKey, name: &str, parent_path: &str) -> Result<(), Win32Error> {
        let path = format!("{parent_path}\\{name}");
        let child = parent.open_subkey(name, KeyAccess::DELETE)?;
        let real_link = child.flags()?.link;
        let link_like = child.is_link()?;
        if !real_link && !link_like {
            for sub in child.subkey_names()? {
                nuke(&child, &sub, &path)?;
            }
        }
        if link_like {
            drop(child);
            return raw_delete(&path).map_err(Win32Error);
        }
        child.delete()
    }

    /// A fresh `HKU\<SID>\Software\PurgeTest-<random>` key, removed again on drop.
    struct TestRoot {
        software: WKey,
        software_path: String,
        name: String,
        /// Relative to `HKU`.
        path: String,
        key: WKey,
    }

    impl TestRoot {
        fn new() -> TestRoot {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let name = format!(
                "PurgeTest-{:x}-{:x}-{}",
                std::process::id(),
                nanos,
                COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            let software_path = format!(r"{}\Software", current_user_sid().unwrap());
            let software = WKey::open(
                RegRoot::Hku,
                &software_path,
                RegView::K64,
                KeyAccess::CREATE_SUB_KEY,
            )
            .unwrap();
            let key = software
                .create_subkey(&name, "", None, false)
                .unwrap()
                .into_key();
            TestRoot {
                path: format!(r"{software_path}\{name}"),
                software,
                software_path,
                name,
                key,
            }
        }

        fn rel(&self, rel: &str) -> String {
            if rel.is_empty() {
                self.path.clone()
            } else {
                format!(r"{}\{rel}", self.path)
            }
        }

        /// Canonical key path, as a backup records it.
        fn key_path(&self, rel: &str) -> String {
            format!(r"HKU\{}", self.rel(rel))
        }

        fn nt_path(&self, rel: &str) -> String {
            format!(r"\REGISTRY\USER\{}", self.rel(rel))
        }

        fn try_open(&self, rel: &str, access: KeyAccess) -> Result<WKey, Win32Error> {
            WKey::open(RegRoot::Hku, &self.rel(rel), RegView::K64, access)
        }

        fn open(&self, rel: &str, access: KeyAccess) -> WKey {
            self.try_open(rel, access).unwrap()
        }

        fn exists(&self, rel: &str) -> bool {
            match self.try_open(rel, KeyAccess::READ) {
                Ok(_) => true,
                Err(e) if e.is_not_found() => false,
                Err(e) => panic!("open {rel}: {e}"),
            }
        }

        fn raw(&self, rel: &str, access: u32) -> RawKey {
            raw_open(&self.rel(rel), access).unwrap()
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let r = nuke(&self.software, &self.name, &self.software_path);
            if !std::thread::panicking() {
                r.expect("test key removed");
            }
        }
    }

    /// A fresh temp directory, removed on drop (after everything holding a handle in it).
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Scratch {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "purge-regbackup-{:x}-{:x}-{}",
                std::process::id(),
                nanos,
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(purge_win::secure::extended_path(&self.0).unwrap());
        }
    }

    /// A relaxed test store in a fresh temp directory, with one session for the backup files.
    struct TempDir {
        session: SessionDir,
        /// Last: removed after the session's handles are closed.
        _scratch: Scratch,
    }

    impl TempDir {
        fn new() -> TempDir {
            let scratch = Scratch::new();
            let roots =
                crate::storage::StorageRoots::install_relaxed(&scratch.0.join("data")).unwrap();
            let session = roots.create_session().unwrap();
            TempDir {
                session,
                _scratch: scratch,
            }
        }

        /// Where backup file `n` is, for tests that change it behind the store's back.
        fn file(&self, n: u32) -> PathBuf {
            self.session.path().join(rel_file(n))
        }
    }

    fn rel_file(n: u32) -> String {
        format!(r"reg\{n:06}.regbackup.json")
    }

    fn save(dir: &TempDir, n: u32, doc: &RegBackup) -> VerifiedBackup {
        write_verified(&dir.session, &rel_file(n), doc).unwrap()
    }

    /// The canonical address of `HKU\<path>` in the 64-bit view, as the gate resolves a test key.
    fn hku(path: &str) -> KeyAddress {
        KeyAddress {
            root: KeyRoot::Hku,
            view: View::K64,
            path: path.to_owned(),
        }
    }

    /// The parent of the backup's key, as `gate::check_undo_key` would hand it out (opened here with
    /// `KEY_CREATE_SUB_KEY` at the 64-bit address the test key has).
    fn parent_of(backup: &VerifiedBackup) -> CheckedKeyParent {
        let path = backup.doc().key.strip_prefix(r"HKU\").unwrap();
        let (parent, leaf) = path.rsplit_once('\\').unwrap();
        let key = WKey::open(
            RegRoot::Hku,
            parent,
            RegView::K64,
            KeyAccess::CREATE_SUB_KEY,
        )
        .unwrap();
        CheckedKeyParent::unchecked_for_tests(key, leaf, hku(path))
    }

    /// The key of a value backup, as `gate::check_undo_key` would hand it out (`KEY_SET_VALUE`).
    fn value_key(backup: &VerifiedBackup) -> CheckedValueKey {
        let path = backup.doc().key.strip_prefix(r"HKU\").unwrap();
        let key = WKey::open(RegRoot::Hku, path, RegView::K64, KeyAccess::SET_VALUE).unwrap();
        CheckedValueKey::unchecked_for_tests(key, hku(path))
    }

    fn utf16z(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// The comparable content of a tree: per key its path, class, security and values (sorted by name).
    /// Last write times and the capture time are left out.
    type Shape = Vec<(String, Option<WideB64>, String, Vec<ValueBackup>)>;

    fn shape(doc: &RegBackup) -> Shape {
        let tree = doc.tree().unwrap();
        let mut out: Shape = tree
            .keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let mut values = key.values.clone();
                values.sort_by(|a, b| a.name_b64.0.cmp(&b.name_b64.0));
                (
                    display_path(tree, i),
                    key.class_b64.clone(),
                    key.sddl.clone(),
                    values,
                )
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    fn capture(root: &TestRoot, rel: &str) -> RegBackup {
        capture_tree(
            &root.open(rel, KeyAccess::READ),
            &root.key_path(rel),
            10_000,
        )
        .unwrap()
    }

    /// `T` with `T\A\A1`, `T\A\A2` and `T\B`: indexes 0 T, 1 A, 2 A1, 3 A2, 4 B.
    fn small_tree(root: &TestRoot) {
        let t = root.key.create_subkey("T", "", None, false).unwrap();
        t.set_value_raw("", REG_SZ, &utf16z("root")).unwrap();
        let a = t.create_subkey("A", "ClsA", None, false).unwrap();
        a.set_value_raw("x", REG_DWORD, &[1, 0, 0, 0]).unwrap();
        a.create_subkey("A1", "", None, false)
            .unwrap()
            .set_value_raw("y", REG_BINARY, &[7])
            .unwrap();
        a.create_subkey("A2", "", None, false).unwrap();
        t.create_subkey("B", "", None, false)
            .unwrap()
            .set_value_raw("v", REG_SZ, &utf16z("b"))
            .unwrap();
    }

    /// `Rich`: every value type including odd lengths, empty and default values, classes, a protected
    /// DACL, and a 10 000-byte value.
    fn rich_tree(root: &TestRoot) {
        let sid = current_user_sid().unwrap();
        let r = root
            .key
            .create_subkey("Rich", "RichClass", None, false)
            .unwrap();
        for (name, ty, data) in [
            ("", REG_SZ, utf16z("default")),
            ("sz", REG_SZ, utf16z("text")),
            ("sz-odd", REG_SZ, vec![0x41, 0x00, 0x42]),
            ("sz-unterminated", REG_SZ, utf16("ab")),
            ("sz-empty", REG_SZ, Vec::new()),
            ("expand", REG_EXPAND_SZ, utf16z("%SystemRoot%\\x")),
            ("expand-odd", REG_EXPAND_SZ, vec![0x25, 0x00, 0x41]),
            ("bin-empty", REG_BINARY, Vec::new()),
            ("bin", REG_BINARY, vec![0, 1, 2, 255]),
            ("none", REG_NONE, vec![9, 8]),
            ("dword", REG_DWORD, 0xdead_beefu32.to_le_bytes().to_vec()),
            ("dword-short", REG_DWORD, vec![1, 2, 3]),
            ("dword-be", REG_DWORD_BIG_ENDIAN, vec![0, 0, 1, 0]),
            ("multi", REG_MULTI_SZ, utf16z("a\0\0b\0")),
            ("multi-odd", REG_MULTI_SZ, vec![0x61, 0x00, 0x00]),
            ("qword", REG_QWORD, 42u64.to_le_bytes().to_vec()),
            ("custom", 0x4000_0001, vec![1]),
            (
                "big",
                REG_BINARY,
                (0..10_000u32).map(|i| (i * 7) as u8).collect(),
            ),
            ("name with \\ and \"", REG_SZ, utf16z("q")),
        ] {
            r.set_value_raw(name, ty, &data).unwrap();
        }
        let a = r.create_subkey("A", "", None, false).unwrap();
        a.set_value_raw("", REG_DWORD, &[5, 0, 0, 0]).unwrap();
        a.create_subkey("B", "Class B", None, false)
            .unwrap()
            .set_value_raw("deep", REG_SZ, &utf16z("deep"))
            .unwrap();
        let c = r
            .create_subkey(
                "C",
                "",
                Some(&format!("D:P(A;OICI;KA;;;{sid})(A;;KR;;;BU)")),
                false,
            )
            .unwrap();
        c.create_subkey("D", "", None, false).unwrap();
    }

    #[test]
    fn capture_delete_restore_round_trips_exactly() {
        let root = TestRoot::new();
        rich_tree(&root);
        let key = root.open("Rich", KeyAccess::DELETE);
        let doc = capture_tree(&key, &root.key_path("Rich"), DEFAULT_KEY_LIMIT).unwrap();
        let tree = doc.tree().unwrap();
        assert_eq!(tree.keys.len(), 5);
        assert_eq!(tree.keys[0].name_b64, WideB64::from("Rich"));
        assert_eq!(tree.keys[0].class_b64, Some(WideB64::from("RichClass")));
        let odd = tree.keys[0]
            .values
            .iter()
            .find(|v| v.name_b64 == WideB64::from("sz-odd"))
            .unwrap();
        assert_eq!(odd.data_b64.0, [0x41, 0x00, 0x42]);
        assert!(tree.keys[0].values.iter().any(|v| v.name_b64.0.is_empty()));

        let dir = TempDir::new();
        let written = save(&dir, 1, &doc);
        assert_eq!(written.reference().path, rel_file(1));
        let bytes = std::fs::read(dir.session.path().join(rel_file(1))).unwrap();
        assert_eq!(written.reference().bytes, bytes.len() as u64);
        assert_eq!(written.reference().sha256, sha256(&bytes));
        let backup = read_verified(&dir.session, written.reference()).unwrap();
        assert_eq!(backup.doc(), &doc);

        assert_eq!(
            probe_tree(&parent_of(&backup), &backup).unwrap(),
            TreeState::Intact
        );
        assert_eq!(delete_tree(&key, &backup).unwrap().keys_deleted, 5);
        assert!(!root.exists("Rich"));
        assert_eq!(
            probe_tree(&parent_of(&backup), &backup).unwrap(),
            TreeState::Absent
        );

        let report = restore_tree(&parent_of(&backup), &backup).unwrap();
        assert_eq!(report.outcome, RestoreOutcome::Restored);
        assert_eq!(report.keys_created, 5);
        assert_eq!(report.differences, []);
        assert_eq!(shape(&capture(&root, "Rich")), shape(&doc));
        assert_eq!(
            probe_tree(&parent_of(&backup), &backup).unwrap(),
            TreeState::Intact
        );

        // Restoring again changes nothing.
        let again = restore_tree(&parent_of(&backup), &backup).unwrap();
        assert_eq!(again.outcome, RestoreOutcome::AlreadyRestored);
        assert_eq!(shape(&capture(&root, "Rich")), shape(&doc));
    }

    #[test]
    fn a_deep_tree_round_trips() {
        let root = TestRoot::new();
        let depth = 300u32;
        let mut current = root.key.create_subkey("k0", "", None, false).unwrap();
        for i in 1..depth {
            current
                .set_value_raw("i", REG_DWORD, &i.to_le_bytes())
                .unwrap();
            current = current
                .create_subkey(&format!("k{i}"), "", None, false)
                .unwrap();
        }
        current
            .set_value_raw("leaf", REG_SZ, &[0x41, 0x00, 0x42])
            .unwrap();
        drop(current);

        let key = root.open("k0", KeyAccess::DELETE);
        assert_eq!(
            capture_tree(&key, &root.key_path("k0"), DEFAULT_KEY_LIMIT),
            Err(CaptureError::TooLarge {
                limit: DEFAULT_KEY_LIMIT
            })
        );
        let doc = capture_tree(&key, &root.key_path("k0"), 1000).unwrap();
        assert_eq!(doc.tree().unwrap().keys.len(), depth as usize);
        let dir = TempDir::new();
        let backup = read_verified(&dir.session, save(&dir, 7, &doc).reference()).unwrap();
        assert_eq!(
            delete_tree(&key, &backup).unwrap().keys_deleted,
            depth as usize
        );
        assert!(!root.exists("k0"));
        assert_eq!(
            restore_tree(&parent_of(&backup), &backup)
                .unwrap()
                .keys_created,
            depth as usize
        );
        assert_eq!(shape(&capture(&root, "k0")), shape(&doc));
    }

    #[test]
    fn a_link_anywhere_is_refused_and_nothing_changes() {
        let root = TestRoot::new();
        small_tree(&root);
        let target = root.key.create_subkey("Target", "", None, false).unwrap();
        target
            .set_value_raw("keep", REG_SZ, &utf16z("keep"))
            .unwrap();
        target.create_subkey("child", "", None, false).unwrap();
        let before = capture(&root, "T");
        let target_before = capture(&root, "Target");

        for (parent, link, at) in [("T\\A\\A1", "L", "A\\A1\\L"), ("T", "M", "M")] {
            make_link(&root.rel(parent), link, &root.nt_path("Target"));
            let key = root.open("T", KeyAccess::DELETE);
            let err = capture_tree(&key, &root.key_path("T"), 100).unwrap_err();
            assert_eq!(err, CaptureError::RegLink { at: at.into() });
            assert_eq!(err.blocker(), Some(Blocker::RegLink));
            raw_delete(&root.rel(&format!("{parent}\\{link}"))).unwrap();
        }
        // A link as the root itself.
        make_link(&root.path, "Link", &root.nt_path("Target"));
        let link = root.open("Link", KeyAccess::DELETE);
        assert_eq!(
            capture_tree(&link, &root.key_path("Link"), 100),
            Err(CaptureError::RegLink { at: String::new() })
        );
        assert_eq!(
            capture_value(&link, &root.key_path("Link"), "x"),
            Err(CaptureError::RegLink { at: String::new() })
        );
        assert_eq!(shape(&capture(&root, "T")), shape(&before));
        assert_eq!(shape(&capture(&root, "Target")), shape(&target_before));

        // A backup taken before a link appeared: an extra link subkey stops the delete before anything
        // goes.
        let dir = TempDir::new();
        let backup = save(&dir, 1, &before);
        make_link(&root.rel("T\\A"), "New", &root.nt_path("Target"));
        let err = delete_tree(&root.open("T", KeyAccess::DELETE), &backup).unwrap_err();
        assert_eq!(err.failure, DeleteFailure::Changed(Change::ExtraSubkey));
        assert_eq!(err.at, "A");
        assert_eq!(err.rollback, Rollback::NotNeeded);
        raw_delete(&root.rel("T\\A\\New")).unwrap();

        // A backed-up key replaced by a link of the same name: refused, link and target untouched.
        root.open("T\\A\\A2", KeyAccess::DELETE).delete().unwrap();
        make_link(&root.rel("T\\A"), "A2", &root.nt_path("Target"));
        let err = delete_tree(&root.open("T", KeyAccess::DELETE), &backup).unwrap_err();
        assert_eq!(err.failure, DeleteFailure::Changed(Change::BecameLink));
        assert_eq!(err.at, "A\\A2");
        assert_eq!(err.failure, DeleteFailure::Changed(Change::BecameLink));
        assert!(root.exists("T\\A\\A1"));
        assert!(root.open("T\\A\\A2", KeyAccess::READ).is_link().unwrap());
        assert_eq!(shape(&capture(&root, "Target")), shape(&target_before));
    }

    #[test]
    fn what_a_backup_cannot_hold_is_refused() {
        let root = TestRoot::new();
        small_tree(&root);
        // A value name with a lone surrogate.
        raw_set(
            &root.raw("T\\B", KEY_SET_VALUE),
            &[0x41, 0xd800, 0],
            REG_SZ,
            &utf16z("x"),
        );
        let err =
            capture_tree(&root.open("T", KeyAccess::READ), &root.key_path("T"), 100).unwrap_err();
        assert_eq!(err, CaptureError::NameNotRepresentable { at: "B".into() });
        assert_eq!(err.blocker(), Some(Blocker::CannotBackUp));
        assert_eq!(
            capture_value(&root.open("T", KeyAccess::READ), "x", "a\0b"),
            Err(CaptureError::NameNotRepresentable { at: String::new() })
        );

        // A REG_LINK value under another name than the link value.
        root.key.create_subkey("LV", "", None, false).unwrap();
        raw_set(
            &root.raw("LV", KEY_SET_VALUE),
            &wz("lv"),
            REG_LINK,
            &utf16("x"),
        );
        let lv = root.open("LV", KeyAccess::READ);
        assert_eq!(
            capture_tree(&lv, &root.key_path("LV"), 10),
            Err(CaptureError::LinkValue { at: String::new() })
        );
        assert_eq!(
            capture_value(&lv, &root.key_path("LV"), "lv"),
            Err(CaptureError::LinkValue { at: String::new() })
        );

        // A volatile key is recorded as volatile.
        let vol = root.key.create_subkey("Vol", "", None, false).unwrap();
        vol.create_subkey("v", "", None, true).unwrap();
        let doc = capture_tree(
            &root.open("Vol", KeyAccess::READ),
            &root.key_path("Vol"),
            10,
        )
        .unwrap();
        let keys = &doc.tree().unwrap().keys;
        assert_eq!(
            keys.iter().map(|k| k.volatile).collect::<Vec<_>>(),
            [false, true]
        );

        // The blast radius: 5 keys.
        root.key.create_subkey("L", "", None, false).unwrap();
        for i in 0..4 {
            root.open("L", KeyAccess::CREATE_SUB_KEY)
                .create_subkey(&format!("c{i}"), "", None, false)
                .unwrap();
        }
        let l = root.open("L", KeyAccess::READ);
        for limit in [0, 1, 4] {
            assert_eq!(
                capture_tree(&l, &root.key_path("L"), limit),
                Err(CaptureError::TooLarge { limit })
            );
        }
        assert_eq!(
            CaptureError::TooLarge { limit: 4 }.blocker(),
            Some(Blocker::TooLarge)
        );
        assert_eq!(
            capture_tree(&l, &root.key_path("L"), 5)
                .unwrap()
                .tree()
                .unwrap()
                .keys
                .len(),
            5
        );
    }

    /// Review M5: a tree is refused while it is captured once it holds more than the byte budget, so
    /// nothing is deleted whose backup file could not be read back at undo time.
    #[test]
    fn a_tree_over_the_byte_budget_is_refused() {
        let root = TestRoot::new();
        small_tree(&root);
        let key = root.open("T", KeyAccess::READ);
        let path = root.key_path("T");
        let doc = capture_tree(&key, &path, 10).unwrap();
        let total: u64 = doc.tree().unwrap().keys.iter().map(node_bytes).sum();
        let within = capture_tree_within(&key, &path, 10, total).unwrap();
        assert_eq!(shape(&within), shape(&doc));
        let err = capture_tree_within(&key, &path, 10, total - 1).unwrap_err();
        assert_eq!(err, CaptureError::TooManyBytes { budget: total - 1 });
        assert_eq!(err.blocker(), Some(Blocker::TooLarge));
        // The budget, base64 and all, stays below what `read_verified` reads.
        let json = serde_json::to_vec(&doc).unwrap().len() as u64;
        assert!(
            json <= total.div_ceil(3) * 4,
            "{json} bytes of JSON for {total}"
        );
        assert!(MAX_CAPTURE_BYTES.div_ceil(3) * 4 < MAX_BACKUP_FILE_BYTES);
    }

    #[test]
    fn concurrent_changes_stop_the_delete_and_put_deleted_keys_back() {
        // (index whose turn it is, change made at that moment, expected stop, expected path, keys put
        // back). Post-order: A1 (2), A2 (3), A (1), B (4), T (0).
        type Inject = fn(&TestRoot);
        let cases: [(usize, Inject, Change, &str, usize); 3] = [
            (
                0,
                |r: &TestRoot| {
                    r.open("T", KeyAccess::CREATE_SUB_KEY)
                        .create_subkey("X", "", None, false)
                        .unwrap();
                },
                Change::ExtraSubkey,
                "",
                4,
            ),
            (
                4,
                |r: &TestRoot| {
                    r.open("T\\B", KeyAccess::SET_VALUE)
                        .set_value_raw("v", REG_SZ, &utf16z("changed"))
                        .unwrap();
                },
                Change::ValuesDiffer,
                "B",
                3,
            ),
            (
                3,
                |r: &TestRoot| {
                    raw_set(
                        &r.raw("T\\A\\A2", KEY_SET_VALUE),
                        &wz("SymbolicLinkValue"),
                        REG_LINK,
                        &utf16("\\REGISTRY\\USER\\nowhere"),
                    );
                },
                Change::BecameLink,
                "A\\A2",
                1,
            ),
        ];
        for (turn, inject, change, at, put_back_keys) in cases {
            let root = TestRoot::new();
            small_tree(&root);
            let before = capture(&root, "T");
            let dir = TempDir::new();
            let backup = save(&dir, 1, &before);
            let key = root.open("T", KeyAccess::DELETE);
            let mut hook = |index: usize| {
                if index == turn {
                    inject(&root);
                }
                true
            };
            let err = match delete_walk(&key, backup.tree().unwrap(), false, &mut hook) {
                Err(err) => err,
                Ok(_) => panic!("delete went through a change at {at:?}"),
            };
            assert_eq!(err.failure, DeleteFailure::Changed(change), "{at}");
            assert_eq!(err.at, at);
            assert_eq!(
                err.rollback,
                Rollback::Done {
                    keys: put_back_keys,
                    differences: Vec::new()
                }
            );
            // Everything of the backup is back; only the injected change remains.
            let state = probe_tree(&parent_of(&backup), &backup).unwrap();
            assert!(
                matches!(state, TreeState::Diverged { .. }),
                "{state:?} after {at:?}"
            );
            for rel in ["T", "T\\A", "T\\A\\A1", "T\\A\\A2", "T\\B"] {
                assert!(root.exists(rel), "{rel}");
            }
            let after = capture_tree(
                &root.open("T\\A\\A1", KeyAccess::READ),
                &root.key_path("T\\A\\A1"),
                10,
            )
            .unwrap();
            assert_eq!(
                after.tree().unwrap().keys[0].values,
                before.tree().unwrap().keys[2].values
            );
        }

        // Changes found on the way down stop the walk before anything is deleted.
        let root = TestRoot::new();
        small_tree(&root);
        let dir = TempDir::new();
        let backup = save(&dir, 1, &capture(&root, "T"));
        root.open("T\\A", KeyAccess::CREATE_SUB_KEY)
            .create_subkey("extra", "", None, false)
            .unwrap();
        let err = delete_tree(&root.open("T", KeyAccess::DELETE), &backup).unwrap_err();
        assert_eq!(
            (err.at.as_str(), &err.failure, &err.rollback),
            (
                "A",
                &DeleteFailure::Changed(Change::ExtraSubkey),
                &Rollback::NotNeeded
            )
        );
        root.open("T\\A\\extra", KeyAccess::DELETE)
            .delete()
            .unwrap();
        root.open("T", KeyAccess::SET_VALUE)
            .set_value_raw("new", REG_DWORD, &[0; 4])
            .unwrap();
        let err = delete_tree(&root.open("T", KeyAccess::DELETE), &backup).unwrap_err();
        assert_eq!(err.failure, DeleteFailure::Changed(Change::ValuesDiffer));
        assert_eq!(err.at, "");
        assert_eq!(err.rollback, Rollback::NotNeeded);
        root.open("T", KeyAccess::SET_VALUE)
            .delete_value("new")
            .unwrap();

        // A root handle without DELETE: the children go, the root refuses, the children come back.
        let err = delete_tree(&root.open("T", KeyAccess::READ), &backup).unwrap_err();
        assert_eq!(
            err.failure,
            DeleteFailure::Os {
                op: "delete key",
                error: Win32Error::ACCESS_DENIED
            }
        );
        assert!(matches!(err.rollback, Rollback::Done { keys: 4, .. }));
        assert_eq!(
            probe_tree(&parent_of(&backup), &backup).unwrap(),
            TreeState::Intact
        );

        // A value backup is not a tree.
        let value = capture_value(&root.open("T", KeyAccess::READ), &root.key_path("T"), "")
            .unwrap()
            .unwrap();
        let value = save(&dir, 2, &value);
        assert_eq!(
            delete_tree(&root.open("T", KeyAccess::DELETE), &value)
                .unwrap_err()
                .failure,
            DeleteFailure::WrongBackupKind
        );
        assert_eq!(
            restore_tree(&parent_of(&value), &value),
            Err(RestoreError::WrongBackupKind)
        );
    }

    #[test]
    fn an_interrupted_delete_is_completed_or_finished() {
        let root = TestRoot::new();
        small_tree(&root);
        let before = capture(&root, "T");
        let dir = TempDir::new();
        let backup = save(&dir, 1, &before);
        let tree = backup.tree().unwrap();

        // Crash when A's turn comes: A1 and A2 are gone.
        let key = root.open("T", KeyAccess::DELETE);
        let walked = delete_walk(&key, tree, false, &mut |index| index != 1).unwrap();
        assert!(matches!(walked, Walked::Interrupted));
        drop(key);
        assert_eq!(
            probe_tree(&parent_of(&backup), &backup).unwrap(),
            TreeState::Partial { missing_keys: 2 }
        );
        // Undo's restore does not merge into a non-empty key; recovery completes the tree.
        assert_eq!(
            restore_tree(&parent_of(&backup), &backup),
            Err(RestoreError::Conflict(RestoreConflict::KeyNotEmpty))
        );
        let report = complete_tree(&parent_of(&backup), &backup).unwrap();
        assert_eq!(
            (report.outcome, report.keys_created),
            (RestoreOutcome::Restored, 2)
        );
        assert_eq!(shape(&capture(&root, "T")), shape(&before));
        assert_eq!(
            complete_tree(&parent_of(&backup), &backup).unwrap().outcome,
            RestoreOutcome::AlreadyRestored
        );

        // Crash again, then resume: the rest goes.
        let key = root.open("T", KeyAccess::DELETE);
        assert!(matches!(
            delete_walk(&key, tree, false, &mut |index| index != 1).unwrap(),
            Walked::Interrupted
        ));
        assert_eq!(
            finish_delete_tree(&parent_of(&backup), &backup)
                .unwrap()
                .keys_deleted,
            3
        );
        drop(key);
        // Run again on the finished delete: the root is absent, nothing to do.
        assert_eq!(
            finish_delete_tree(&parent_of(&backup), &backup)
                .unwrap()
                .keys_deleted,
            0
        );
        assert_eq!(
            probe_tree(&parent_of(&backup), &backup).unwrap(),
            TreeState::Absent
        );
        // Recovery after a finished delete restores everything.
        assert_eq!(
            complete_tree(&parent_of(&backup), &backup)
                .unwrap()
                .keys_created,
            5
        );
        assert_eq!(shape(&capture(&root, "T")), shape(&before));

        // A partial tree that changed meanwhile is not completed.
        let key = root.open("T", KeyAccess::DELETE);
        assert!(matches!(
            delete_walk(&key, tree, false, &mut |index| index != 1).unwrap(),
            Walked::Interrupted
        ));
        root.open("T\\B", KeyAccess::SET_VALUE)
            .set_value_raw("v", REG_SZ, &utf16z("other"))
            .unwrap();
        assert_eq!(
            complete_tree(&parent_of(&backup), &backup),
            Err(RestoreError::Conflict(RestoreConflict::Diverged {
                at: "B".into(),
                change: Change::ValuesDiffer
            }))
        );
        // The repair puts back what is missing and leaves the changed key as it is: the backup plus
        // the change, never a half-deleted tree (review S2).
        let report = restore_missing(&parent_of(&backup), &backup).unwrap();
        assert_eq!(
            (report.outcome, report.keys_created, report.differences),
            (
                RestoreOutcome::Restored,
                2,
                vec![Difference {
                    at: "B".into(),
                    kind: DifferenceKind::ExistingKeyDiffers {
                        change: Change::ValuesDiffer
                    }
                }]
            )
        );
        assert!(root.exists("T\\A\\A1") && root.exists("T\\A\\A2"));
        assert_eq!(
            root.open("T\\B", KeyAccess::READ)
                .value("v")
                .unwrap()
                .unwrap()
                .data,
            utf16z("other")
        );
        let mut want = shape(&before);
        let mut got = shape(&capture(&root, "T"));
        let b = |s: &mut Shape| s.iter_mut().find(|k| k.0 == "B").unwrap().3.clear();
        b(&mut want);
        b(&mut got);
        assert_eq!(got, want);
    }

    /// `T` with `T\A\A1` and `T\B`: indexes 0 T, 1 A, 2 A1, 3 B. Post-order: A1, A, B, T.
    fn s2_tree(root: &TestRoot) {
        let t = root.key.create_subkey("T", "", None, false).unwrap();
        let a = t.create_subkey("A", "", None, false).unwrap();
        a.create_subkey("A1", "", None, false)
            .unwrap()
            .set_value_raw("y", REG_BINARY, &[7])
            .unwrap();
        t.create_subkey("B", "", None, false)
            .unwrap()
            .set_value_raw("v", REG_SZ, &utf16z("b"))
            .unwrap();
    }

    /// The review's S2 experiment: an interrupted tree delete, then a foreign change, then the
    /// resumed delete. In either walk order the result says what is on the machine, and both ways out
    /// (finish the delete, put the tree back) work from the backup alone.
    #[test]
    fn a_resumed_delete_that_stops_never_reports_a_half_deleted_tree_as_complete() {
        let root = TestRoot::new();
        s2_tree(&root);
        let before = capture(&root, "T");
        let dir = TempDir::new();
        let backup = save(&dir, 1, &before);
        let tree = backup.tree().unwrap();
        let change_b = |text: &str| {
            root.open("T\\B", KeyAccess::SET_VALUE)
                .set_value_raw("v", REG_SZ, &utf16z(text))
                .unwrap();
        };

        // The first run deleted A1 and A, and crashed when B's turn came. B changes meanwhile.
        let key = root.open("T", KeyAccess::DELETE);
        assert!(matches!(
            delete_walk(&key, tree, false, &mut |index| index != 3).unwrap(),
            Walked::Interrupted
        ));
        drop(key);
        change_b("changed");
        let err = finish_delete_tree(&parent_of(&backup), &backup).unwrap_err();
        assert_eq!(
            (err.at.as_str(), &err.failure),
            ("B", &DeleteFailure::Changed(Change::ValuesDiffer))
        );
        assert_eq!(
            err.rollback,
            Rollback::PartialBefore {
                missing: 2,
                keys: 0,
                differences: Vec::new()
            }
        );
        assert!(!err.rollback.is_complete());
        assert!(!root.exists("T\\A"));
        assert_eq!(
            probe_tree(&parent_of(&backup), &backup).unwrap(),
            TreeState::Diverged {
                at: "B".into(),
                change: Change::ValuesDiffer
            }
        );
        // Way out 1: once the change is gone, the resumed delete finishes (B and T are left).
        change_b("b");
        assert_eq!(
            finish_delete_tree(&parent_of(&backup), &backup)
                .unwrap()
                .keys_deleted,
            2
        );
        assert!(!root.exists("T"));
        restore_tree(&parent_of(&backup), &backup).unwrap();
        assert_eq!(shape(&capture(&root, "T")), shape(&before));

        // Way out 2, from the same state: put the tree back as the backup holds it, plus the change.
        let key = root.open("T", KeyAccess::DELETE);
        assert!(matches!(
            delete_walk(&key, tree, false, &mut |index| index != 3).unwrap(),
            Walked::Interrupted
        ));
        drop(key);
        change_b("changed");
        assert!(matches!(
            finish_delete_tree(&parent_of(&backup), &backup)
                .unwrap_err()
                .rollback,
            Rollback::PartialBefore { missing: 2, .. }
        ));
        let report = restore_missing(&parent_of(&backup), &backup).unwrap();
        assert_eq!(
            (report.outcome, report.keys_created),
            (RestoreOutcome::Restored, 2)
        );
        assert!(root.exists("T\\A\\A1"));
        assert_eq!(
            restore_missing(&parent_of(&backup), &backup)
                .unwrap()
                .outcome,
            RestoreOutcome::AlreadyRestored
        );
        change_b("b");
        assert_eq!(shape(&capture(&root, "T")), shape(&before));

        // The other walk order: only A1 was deleted, so the resumed run deletes A itself before it
        // meets B. It puts A back with A1, and the tree is whole again.
        let key = root.open("T", KeyAccess::DELETE);
        assert!(matches!(
            delete_walk(&key, tree, false, &mut |index| index != 1).unwrap(),
            Walked::Interrupted
        ));
        drop(key);
        change_b("changed");
        let err = finish_delete_tree(&parent_of(&backup), &backup).unwrap_err();
        assert_eq!(err.failure, DeleteFailure::Changed(Change::ValuesDiffer));
        assert_eq!(
            err.rollback,
            Rollback::Done {
                keys: 2,
                differences: Vec::new()
            }
        );
        assert!(root.exists("T\\A\\A1"));

        // A parent whose leaf is not the backup's key is refused before anything is opened.
        let other = CheckedKeyParent::unchecked_for_tests(
            root.open("", KeyAccess::CREATE_SUB_KEY),
            "Other",
            hku(&root.rel("Other")),
        );
        assert_eq!(
            finish_delete_tree(&other, &backup).unwrap_err().failure,
            DeleteFailure::NotThisKey
        );
        assert!(root.exists("T\\A\\A1"));
    }

    #[test]
    fn backup_files_are_verified() {
        let root = TestRoot::new();
        small_tree(&root);
        let doc = capture(&root, "T");
        let dir = TempDir::new();
        let written = save(&dir, 1, &doc);
        let path = dir.file(1);
        let original = std::fs::read(&path).unwrap();

        // One byte changed: refused on the hash.
        let mut bytes = original.clone();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            read_verified(&dir.session, written.reference()),
            Err(BackupFileError::Tampered)
        );
        // Another length: refused before reading.
        bytes.push(b' ');
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            read_verified(&dir.session, written.reference()),
            Err(BackupFileError::Tampered)
        );
        std::fs::write(&path, &original).unwrap();
        assert!(read_verified(&dir.session, written.reference()).is_ok());

        // Missing, and references that leave the session directory.
        let mut other = written.reference().clone();
        other.path = rel_file(9);
        assert_eq!(
            read_verified(&dir.session, &other),
            Err(BackupFileError::Missing)
        );
        for bad in [r"..\x.json", r"C:\x.json", "reg/x.json", ""] {
            other.path = bad.into();
            assert_eq!(
                read_verified(&dir.session, &other),
                Err(BackupFileError::NotSessionRelative(bad.into()))
            );
            assert_eq!(
                write_verified(&dir.session, bad, &doc),
                Err(BackupFileError::NotSessionRelative(bad.into()))
            );
        }

        // An existing file is never replaced: the store refuses to create it.
        let existing = write_verified(&dir.session, &rel_file(1), &doc);
        assert!(
            matches!(
                &existing,
                Err(BackupFileError::Store(e)) if matches!(**e, StorageError::Io {
                    source: FsError::AlreadyExists,
                    ..
                })
            ),
            "{existing:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);

        // Documents Purge does not write are refused before any file exists.
        let edits: [fn(&mut RegTree); 5] = [
            |t| t.keys[1].link = true,
            |t| t.keys[0].name_b64 = WideB64::from("Other"),
            |t| t.keys[4].name_b64 = WideB64::from("a"),
            |t| t.keys[1].values[0].value_type = REG_LINK,
            |t| t.keys[2].name_b64 = WideB64(vec![0x41, 0, 0x42]),
        ];
        for (i, edit) in edits.into_iter().enumerate() {
            let mut bad = doc.clone();
            let RegBackupBody::Tree(tree) = &mut bad.body else {
                unreachable!("a tree capture")
            };
            edit(tree);
            let name = rel_file(100 + i as u32);
            assert!(
                matches!(
                    write_verified(&dir.session, &name, &bad),
                    Err(BackupFileError::Invalid(_))
                ),
                "edit {i}"
            );
            assert!(!dir.session.path().join(&name).exists());
        }
    }

    /// Set only in a child process of the test binary: the data root of the parent's store.
    const CHILD_ROOT: &str = "PURGE_TEST_REGBACKUP_CHILD_ROOT";
    /// Set only in a child process: the session id in that store.
    const CHILD_SESSION: &str = "PURGE_TEST_REGBACKUP_CHILD_SESSION";
    /// Set only in a child process: the parent's test key, relative to `HKU`.
    const CHILD_KEY: &str = "PURGE_TEST_REGBACKUP_CHILD_KEY";
    /// Set only in a child process: the JSON of the `BackupRef` to restore from; unset to write the
    /// backup of `T` as file 1 instead.
    const CHILD_RESTORE: &str = "PURGE_TEST_REGBACKUP_CHILD_RESTORE";

    /// The child half of the crash tests: writes the backup of `<key>\T` through [`write_verified`],
    /// or restores `T` from a backup with [`restore_tree`]. Does nothing when run as an ordinary test.
    /// The parent owns the store and the key and removes both.
    #[test]
    fn child_regbackup_scenario() {
        let (Some(data_root), Ok(id), Ok(key)) = (
            std::env::var_os(CHILD_ROOT),
            std::env::var(CHILD_SESSION),
            std::env::var(CHILD_KEY),
        ) else {
            return;
        };
        let roots =
            crate::storage::StorageRoots::relaxed(std::path::Path::new(&data_root)).unwrap();
        let session = roots.open_session(&id.parse().unwrap()).unwrap();
        match std::env::var(CHILD_RESTORE) {
            Ok(reference) => {
                let reference: BackupRef = serde_json::from_str(&reference).unwrap();
                let backup = read_verified(&session, &reference).unwrap();
                restore_tree(&parent_of(&backup), &backup).unwrap();
            }
            Err(_) => {
                let t = WKey::open(
                    RegRoot::Hku,
                    &format!(r"{key}\T"),
                    RegView::K64,
                    KeyAccess::READ,
                )
                .unwrap();
                let doc = capture_tree(&t, &format!(r"HKU\{key}\T"), 10).unwrap();
                write_verified(&session, &rel_file(1), &doc).unwrap();
            }
        }
    }

    #[cfg(feature = "fault-inject")]
    mod crash {
        use super::*;

        /// The exit code of a process ended by `std::process::abort` on Windows (`__fastfail`).
        const ABORT_CODE: i32 = 0xC000_0409_u32 as i32;

        /// Runs [`child_regbackup_scenario`] on `root`'s key and `dir`'s session, faulting at `at`.
        fn run(
            root: &TestRoot,
            dir: &TempDir,
            at: &str,
            restore: Option<&BackupRef>,
        ) -> Option<i32> {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "regbackup::tests::child_regbackup_scenario",
                    "--test-threads=1",
                ])
                .env(CHILD_ROOT, dir.session.roots().data_root())
                .env(CHILD_SESSION, dir.session.id().as_str())
                .env(CHILD_KEY, &root.path)
                .env(fault::ENV_AT, at)
                .env_remove(fault::ENV_PAUSE)
                .env_remove(CHILD_RESTORE)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            if let Some(reference) = restore {
                command.env(CHILD_RESTORE, serde_json::to_string(reference).unwrap());
            }
            command.status().unwrap().code()
        }

        /// Review S1: the one backup writer hits `backup.written` and `backup.verified` exactly once
        /// each: the first hit aborts, a second hit is never reached.
        #[test]
        fn the_backup_writer_hits_each_backup_point_once() {
            for point in [fault::BACKUP_WRITTEN, fault::BACKUP_VERIFIED] {
                let root = TestRoot::new();
                small_tree(&root);
                let dir = TempDir::new();
                assert_eq!(run(&root, &dir, point, None), Some(ABORT_CODE), "{point}");
                // The file was written (and flushed) before either point.
                let bytes = std::fs::read(dir.file(1)).unwrap();
                let doc: RegBackup = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(shape(&doc), shape(&capture(&root, "T")));

                let dir = TempDir::new();
                assert_eq!(
                    run(&root, &dir, &format!("{point}:2"), None),
                    Some(0),
                    "{point} hit twice"
                );
                assert!(dir.file(1).exists());
            }
        }

        /// Review M6: `regrestore.mid` is hit inside the restore walk once a key is re-created; the
        /// crash leaves a partly restored tree that recovery completes from the backup.
        #[test]
        fn a_crash_in_the_middle_of_a_restore_is_completed() {
            let root = TestRoot::new();
            small_tree(&root);
            let dir = TempDir::new();
            let before = capture(&root, "T");
            let backup = save(&dir, 1, &before);
            delete_tree(&root.open("T", KeyAccess::DELETE), &backup).unwrap();

            // Five keys: the point is hit before each of the last four.
            let reference = backup.reference();
            assert_eq!(
                run(&root, &dir, "regrestore.mid:5", Some(reference)),
                Some(0)
            );
            assert_eq!(shape(&capture(&root, "T")), shape(&before));
            delete_tree(&root.open("T", KeyAccess::DELETE), &backup).unwrap();

            assert_eq!(
                run(&root, &dir, "regrestore.mid:2", Some(reference)),
                Some(ABORT_CODE)
            );
            assert_eq!(
                probe_tree(&parent_of(&backup), &backup).unwrap(),
                TreeState::Partial { missing_keys: 3 }
            );
            assert_eq!(
                complete_tree(&parent_of(&backup), &backup)
                    .unwrap()
                    .keys_created,
                3
            );
            assert_eq!(shape(&capture(&root, "T")), shape(&before));
        }
    }

    #[test]
    fn restore_conflicts_follow_the_rules() {
        let root = TestRoot::new();
        small_tree(&root);
        let dir = TempDir::new();
        let doc = capture(&root, "T");
        let backup = save(&dir, 1, &doc);

        // Existing and equal: already restored. Existing with other content: conflict, nothing changed.
        assert_eq!(
            restore_tree(&parent_of(&backup), &backup).unwrap().outcome,
            RestoreOutcome::AlreadyRestored
        );
        root.open("T", KeyAccess::SET_VALUE)
            .set_value_raw("", REG_SZ, &utf16z("new"))
            .unwrap();
        let conflict = restore_tree(&parent_of(&backup), &backup).unwrap_err();
        assert_eq!(
            conflict,
            RestoreError::Conflict(RestoreConflict::KeyNotEmpty)
        );
        assert_eq!(
            RestoreConflict::KeyNotEmpty.undo_conflict(),
            UndoConflict::KeyExists
        );
        assert_eq!(
            root.open("T", KeyAccess::READ)
                .value("")
                .unwrap()
                .unwrap()
                .data,
            utf16z("new")
        );
        root.open("T", KeyAccess::SET_VALUE)
            .set_value_raw("", REG_SZ, &utf16z("root"))
            .unwrap();

        // Existing and empty elsewhere: merged; the existing key keeps its class.
        delete_tree(&root.open("T", KeyAccess::DELETE), &backup).unwrap();
        root.key.create_subkey("T", "Other", None, false).unwrap();
        let report = restore_tree(&parent_of(&backup), &backup).unwrap();
        assert_eq!(report.outcome, RestoreOutcome::Restored);
        assert_eq!(report.keys_created, 4);
        assert!(report.differences.contains(&Difference {
            at: String::new(),
            kind: DifferenceKind::RootClassKept
        }));
        let merged = capture(&root, "T");
        let (mut want, mut got) = (shape(&doc), shape(&merged));
        want[0].1 = None;
        got[0].1 = None;
        assert_eq!(got, want);

        // The checked parent must be the backup's parent: another leaf is refused before anything is
        // opened below it, by every restore and by the probe (review S3/S4).
        let wrong = || {
            CheckedKeyParent::unchecked_for_tests(
                root.open("", KeyAccess::CREATE_SUB_KEY),
                "U",
                hku(&root.rel("U")),
            )
        };
        assert_eq!(
            restore_tree(&wrong(), &backup),
            Err(RestoreError::NotThisKey)
        );
        assert_eq!(
            complete_tree(&wrong(), &backup),
            Err(RestoreError::NotThisKey)
        );
        assert_eq!(
            restore_missing(&wrong(), &backup),
            Err(RestoreError::NotThisKey)
        );
        assert_eq!(probe_tree(&wrong(), &backup), Err(RestoreError::NotThisKey));
        assert!(!root.exists("U"));
        // Case does not make another key.
        let lower = CheckedKeyParent::unchecked_for_tests(
            root.open("", KeyAccess::CREATE_SUB_KEY),
            "t",
            hku(&root.rel("t")),
        );
        assert!(matches!(
            probe_tree(&lower, &backup),
            Ok(TreeState::Diverged {
                change: Change::ClassDiffers,
                ..
            })
        ));

        // The protected-root rule also judges the canonical address the gate resolved, not only the
        // plan's spelling the backup records.
        nuke(&root.key, "T", &root.path).unwrap();
        root.key.create_subkey("T", "", None, false).unwrap();
        let aliased = CheckedKeyParent::unchecked_for_tests(
            root.open("", KeyAccess::CREATE_SUB_KEY),
            "T",
            hku(&root.rel(r"Installer\T")),
        );
        assert_eq!(
            restore_tree(&aliased, &backup),
            Err(RestoreError::Conflict(RestoreConflict::KeyExistsProtected))
        );
        // An empty key of another volatility is not merged into (review M9). The backup is made to
        // record the root as volatile: a key re-created volatile right after the stable one was
        // deleted came back stable on Windows 11 26300 (see the volatility test).
        root.open("T", KeyAccess::DELETE).delete().unwrap();
        root.key.create_subkey("T", "Other", None, false).unwrap();
        restore_tree(&parent_of(&backup), &backup).unwrap();
        let w = root.key.create_subkey("W", "", None, false).unwrap();
        w.set_value_raw("v", REG_DWORD, &[1, 0, 0, 0]).unwrap();
        let mut volatile = capture(&root, "W");
        let RegBackupBody::Tree(tree) = &mut volatile.body else {
            unreachable!("a tree capture")
        };
        tree.keys[0].volatile = true;
        let volatile = save(&dir, 3, &volatile);
        w.delete_value("v").unwrap();
        assert_eq!(
            restore_tree(&parent_of(&volatile), &volatile),
            Err(RestoreError::Conflict(RestoreConflict::VolatilityDiffers))
        );
        assert_eq!(
            RestoreConflict::VolatilityDiffers.undo_conflict(),
            UndoConflict::KeyExists
        );
        assert_eq!(root.open("W", KeyAccess::READ).info().unwrap().n_values, 0);
        drop(w);

        // Existing below a protected root: always a conflict, even when empty.
        let installer = root
            .key
            .create_subkey("Installer", "", None, false)
            .unwrap();
        installer
            .create_subkey("P", "", None, false)
            .unwrap()
            .set_value_raw("v", REG_DWORD, &[1, 0, 0, 0])
            .unwrap();
        let p_doc = capture(&root, "Installer\\P");
        let p_backup = save(&dir, 2, &p_doc);
        delete_tree(&root.open("Installer\\P", KeyAccess::DELETE), &p_backup).unwrap();
        installer.create_subkey("P", "", None, false).unwrap();
        assert_eq!(
            restore_tree(&parent_of(&p_backup), &p_backup),
            Err(RestoreError::Conflict(RestoreConflict::KeyExistsProtected))
        );
        assert_eq!(
            root.open("Installer\\P", KeyAccess::READ)
                .info()
                .unwrap()
                .n_values,
            0
        );
        // Absent below a protected root: restored.
        root.open("Installer\\P", KeyAccess::DELETE)
            .delete()
            .unwrap();
        assert_eq!(
            restore_tree(&parent_of(&p_backup), &p_backup)
                .unwrap()
                .outcome,
            RestoreOutcome::Restored
        );

        // A link at the root's name, or as the parent: refused.
        delete_tree(&root.open("T", KeyAccess::DELETE), &backup).unwrap_err();
        nuke(&root.key, "T", &root.path).unwrap();
        make_link(&root.path, "T", &root.nt_path("Installer"));
        let err = restore_tree(&parent_of(&backup), &backup).unwrap_err();
        assert_eq!(err, RestoreError::Conflict(RestoreConflict::Link));
        assert_eq!(
            RestoreConflict::Link.undo_conflict(),
            UndoConflict::GateBlocked {
                blocker: Blocker::RegLink
            }
        );
        let link = CheckedKeyParent::unchecked_for_tests(
            root.open("T", KeyAccess::READ),
            "T",
            hku(&root.rel("T\\T")),
        );
        assert_eq!(
            restore_tree(&link, &backup),
            Err(RestoreError::Conflict(RestoreConflict::Link))
        );
        assert_eq!(
            restore_missing(&parent_of(&backup), &backup),
            Err(RestoreError::Conflict(RestoreConflict::Link))
        );
        assert_eq!(
            complete_tree(&parent_of(&backup), &backup),
            Err(RestoreError::Conflict(RestoreConflict::Link))
        );
        assert!(!root.exists("Installer\\T"));
    }

    #[test]
    fn an_owner_the_token_cannot_assign_is_reported() {
        let root = TestRoot::new();
        let o = root.key.create_subkey("O", "", None, false).unwrap();
        o.create_subkey("c", "", None, false).unwrap();
        drop(o);
        let doc = capture(&root, "O");
        let dir = TempDir::new();
        let backup = save(&dir, 1, &doc);
        let mut system_owned = doc.clone();
        if let RegBackupBody::Tree(tree) = &mut system_owned.body {
            let rest = without_owner(&tree.keys[0].sddl).to_owned();
            tree.keys[0].sddl = format!("O:SY{rest}");
        }
        let system_backup = save(&dir, 2, &system_owned);
        delete_tree(&root.open("O", KeyAccess::DELETE), &backup).unwrap();

        let report = restore_tree(&parent_of(&system_backup), &system_backup).unwrap();
        assert_eq!(report.outcome, RestoreOutcome::Restored);
        assert_eq!(
            report.differences,
            [Difference {
                at: String::new(),
                kind: DifferenceKind::OwnerNotRestored {
                    recorded_owner: "SY".into()
                }
            }]
        );
        let live = capture(&root, "O");
        let live_root = &live.tree().unwrap().keys[0];
        assert_eq!(
            without_owner(&live_root.sddl),
            without_owner(&doc.tree().unwrap().keys[0].sddl)
        );
        assert!(!live_root.sddl.starts_with("O:SY"));
        assert!(root.exists("O\\c"));
        // Owners aside the tree is in place, so a second run changes nothing.
        assert_eq!(
            restore_tree(&parent_of(&system_backup), &system_backup)
                .unwrap()
                .outcome,
            RestoreOutcome::AlreadyRestored
        );
    }

    #[test]
    fn values_capture_delete_and_restore() {
        let root = TestRoot::new();
        let v = root.key.create_subkey("V", "", None, false).unwrap();
        v.set_value_raw("odd", REG_SZ, &[0x41, 0x00, 0x42]).unwrap();
        v.set_value_raw("", REG_EXPAND_SZ, &utf16z("%X%")).unwrap();
        drop(v);
        let key = root.open("V", KeyAccess::SET_VALUE);
        let path = root.key_path("V");
        assert_eq!(capture_value(&key, &path, "absent"), Ok(None));
        let dir = TempDir::new();
        for (n, name) in [(1, "odd"), (2, "")] {
            let doc = capture_value(&key, &path, name).unwrap().unwrap();
            let backup = read_verified(&dir.session, save(&dir, n, &doc).reference()).unwrap();
            let original = key.value(name).unwrap().unwrap();
            assert_eq!(delete_value(&key, &backup), Ok(ValueDelete::Deleted));
            assert_eq!(key.value(name).unwrap(), None);
            assert_eq!(delete_value(&key, &backup), Ok(ValueDelete::Vanished));
            assert_eq!(
                restore_value(&value_key(&backup), &backup).unwrap().outcome,
                RestoreOutcome::Restored
            );
            assert_eq!(key.value(name).unwrap(), Some(original));
            assert_eq!(
                restore_value(&value_key(&backup), &backup).unwrap().outcome,
                RestoreOutcome::AlreadyRestored
            );
            key.set_value_raw(name, REG_BINARY, &[1]).unwrap();
            assert_eq!(
                delete_value(&key, &backup),
                Err(DeleteFailure::Changed(Change::ValuesDiffer))
            );
            assert_eq!(
                restore_value(&value_key(&backup), &backup),
                Err(RestoreError::Conflict(RestoreConflict::ValueDiffers))
            );
            assert_eq!(key.value(name).unwrap().unwrap().data, [1]);
            let tree = save(&dir, 10 + n, &capture(&root, "V"));
            assert_eq!(
                restore_value(&value_key(&tree), &tree),
                Err(RestoreError::WrongBackupKind)
            );
        }
    }

    /// The volatility of every key of `rel` and below, by display path.
    fn volatility(root: &TestRoot, rel: &str) -> Vec<(String, bool)> {
        let doc = capture(root, rel);
        let tree = doc.tree().unwrap();
        let mut out: Vec<(String, bool)> = (0..tree.keys.len())
            .map(|i| (display_path(tree, i), tree.keys[i].volatile))
            .collect();
        out.sort();
        out
    }

    #[test]
    fn a_tree_with_volatile_keys_round_trips() {
        let root = TestRoot::new();
        // `VT` (stable) with `S` (stable, a value), `E` (stable, empty), `V` (volatile, a value) and
        // `V\W` (volatile, empty; nothing stable can live below a volatile key).
        let vt = root.key.create_subkey("VT", "", None, false).unwrap();
        vt.create_subkey("S", "", None, false)
            .unwrap()
            .set_value_raw("s", REG_DWORD, &[1, 0, 0, 0])
            .unwrap();
        vt.create_subkey("E", "", None, false).unwrap();
        let v = vt.create_subkey("V", "ClsV", None, true).unwrap();
        v.set_value_raw("v", REG_SZ, &utf16z("volatile")).unwrap();
        v.create_subkey("W", "", None, true).unwrap();
        drop((v, vt));

        let before = volatility(&root, "VT");
        assert_eq!(
            before,
            [
                (String::new(), false),
                ("E".to_owned(), false),
                ("S".to_owned(), false),
                ("V".to_owned(), true),
                (r"V\W".to_owned(), true),
            ]
        );
        let key = root.open("VT", KeyAccess::DELETE);
        let doc = capture_tree(&key, &root.key_path("VT"), DEFAULT_KEY_LIMIT).unwrap();
        let dir = TempDir::new();
        let written = save(&dir, 1, &doc);
        let backup = read_verified(&dir.session, written.reference()).unwrap();
        assert_eq!(backup.doc(), &doc);

        assert_eq!(delete_tree(&key, &backup).unwrap().keys_deleted, 5);
        drop(key);
        assert!(!root.exists("VT"));
        let report = restore_tree(&parent_of(&backup), &backup).unwrap();
        assert_eq!(
            (report.outcome, report.keys_created, report.differences),
            (RestoreOutcome::Restored, 5, Vec::new())
        );
        assert_eq!(shape(&capture(&root, "VT")), shape(&doc));
        assert_eq!(volatility(&root, "VT"), before);
        assert_eq!(
            probe_tree(&parent_of(&backup), &backup).unwrap(),
            TreeState::Intact
        );

        // A key whose volatility is not the recorded one stops the delete before anything goes. The
        // backup is made to record `E` as volatile: re-creating `E` volatile right after deleting the
        // stable one gave a stable key again on Windows 11 26300, so the live side is left as it is.
        let mut flipped = doc.clone();
        let RegBackupBody::Tree(tree) = &mut flipped.body else {
            panic!("a tree backup");
        };
        let e = (0..tree.keys.len())
            .find(|&i| display_path(tree, i) == "E")
            .unwrap();
        tree.keys[e].volatile = true;
        let flipped = save(&dir, 2, &flipped);
        let key = root.open("VT", KeyAccess::DELETE);
        let err = delete_tree(&key, &flipped).unwrap_err();
        assert_eq!(
            err.failure,
            DeleteFailure::Changed(Change::VolatilityDiffers)
        );
        assert_eq!(err.at, "E");
        assert_eq!(err.rollback, Rollback::NotNeeded);
        assert_eq!(
            probe_tree(&parent_of(&flipped), &flipped).unwrap(),
            TreeState::Diverged {
                at: "E".to_owned(),
                change: Change::VolatilityDiffers,
            }
        );
        assert_eq!(volatility(&root, "VT"), before);
        assert_eq!(
            probe_tree(&parent_of(&backup), &backup).unwrap(),
            TreeState::Intact
        );
    }

    #[test]
    fn the_32_bit_view_round_trips() {
        let root = TestRoot::new();
        small_tree(&root);
        let parent = WKey::open(RegRoot::Hku, &root.path, RegView::K32, KeyAccess::READ).unwrap();
        let key = parent.open_subkey("T", KeyAccess::DELETE).unwrap();
        assert_eq!(key.view(), RegView::K32);
        let doc = capture_tree(&key, &root.key_path("T"), 10).unwrap();
        let dir = TempDir::new();
        let backup = save(&dir, 1, &doc);
        assert_eq!(delete_tree(&key, &backup).unwrap().keys_deleted, 5);
        assert!(!root.exists("T"));
        let parent = CheckedKeyParent::unchecked_for_tests(
            WKey::open(
                RegRoot::Hku,
                &root.path,
                RegView::K32,
                KeyAccess::CREATE_SUB_KEY,
            )
            .unwrap(),
            "T",
            KeyAddress {
                root: KeyRoot::Hku,
                view: View::K32,
                path: root.rel("T"),
            },
        );
        assert_eq!(restore_tree(&parent, &backup).unwrap().keys_created, 5);
        // `HKCU\Software` is shared between the views: the 64-bit view sees the same tree.
        assert_eq!(shape(&capture(&root, "T")), shape(&doc));
    }

    #[test]
    fn key_paths_open_and_protected_roots() {
        // Keys are opened at the guard's probe address, by the gate only (this module opens no key by
        // path): the addresses it resolves.
        let probe = |key_path: &str| {
            purge_guard::live::key_probe(
                &purge_model::Target::RegKey {
                    path: key_path.to_owned(),
                },
                &purge_guard::canon::GuardEnv::sample(),
            )
            .unwrap()
        };
        let addr = |root: KeyRoot, view: View, path: &str| KeyAddress {
            root,
            view,
            path: path.to_owned(),
        };
        let root = TestRoot::new();
        small_tree(&root);
        assert_eq!(
            probe(&root.key_path("T\\A")).open,
            addr(KeyRoot::Hku, View::K64, &root.rel("T\\A"))
        );
        assert_eq!(
            probe(r"HKLM\SOFTWARE\WOW6432Node\Vendor").open,
            addr(KeyRoot::Hklm, View::K32, r"SOFTWARE\Vendor")
        );
        assert_eq!(
            probe(r"HKU\S-1-5-21-1_Classes\WOW6432Node\CLSID\x").open,
            addr(KeyRoot::Hku, View::K32, r"S-1-5-21-1_Classes\CLSID\x")
        );
        assert_eq!(
            probe(r"HKU\S-1-5-21-1\Software\x").open,
            addr(KeyRoot::Hku, View::K64, r"S-1-5-21-1\Software\x")
        );
        // `HKLM\SOFTWARE\WOW6432Node\Classes` is a registry link on Windows 11; the probe address of a
        // 32-bit machine class key avoids it (view flag, logical path), and so does its parent.
        let class = probe(r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{0}");
        assert_eq!(
            class.open,
            addr(KeyRoot::Hklm, View::K32, r"SOFTWARE\Classes\CLSID\{0}")
        );
        assert_eq!(
            class.ancestors.last(),
            Some(&addr(KeyRoot::Hklm, View::K32, r"SOFTWARE\Classes\CLSID"))
        );
        // The current control set is reached through `ControlSet00N`, never through the link.
        assert_eq!(
            probe(r"HKLM\SYSTEM\CurrentControlSet\Services\Svc").open,
            addr(
                KeyRoot::Hklm,
                View::K64,
                r"SYSTEM\ControlSet001\Services\Svc"
            )
        );

        for (path, protected) in [
            (r"HKLM\SOFTWARE\Classes\Installer\Products\ABC", true),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\X",
                true,
            ),
            (r"HKLM\SYSTEM\ControlSet001\Services\Svc", true),
            (
                r"HKLM\SYSTEM\CurrentControlSet\Services\Svc\Parameters",
                true,
            ),
            (r"HKLM\SOFTWARE\Classes\CLSID\{0}", true),
            (
                r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{0}\InprocServer32",
                true,
            ),
            (r"HKU\S-1-5-21-1_Classes\Interface\{0}", true),
            (r"HKLM\SOFTWARE\Classes\TypeLib\{0}", true),
            (r"HKLM\SOFTWARE\Classes\AppID\{0}", true),
            (r"hklm\software\classes\clsid\{0}", true),
            (r"HKLM\SOFTWARE\Vendor\App", false),
            (r"HKLM\SOFTWARE\Vendor\Installer", false),
            (r"HKLM\SOFTWARE\Classes\CLSID", false),
            (r"HKLM\SOFTWARE\Vendor\Services\X", false),
            (r"HKU\S-1-5-21-1\Software\Vendor", false),
        ] {
            assert_eq!(is_protected_root(path), protected, "{path}");
        }
    }

    #[test]
    fn sddl_owner_parts() {
        assert_eq!(split_owner("O:BAG:SYD:P"), Some(("BA", "G:SYD:P")));
        assert_eq!(
            split_owner("O:S-1-5-21-1-2-3G:BAD:(A;;KA;;;BA)"),
            Some(("S-1-5-21-1-2-3", "G:BAD:(A;;KA;;;BA)"))
        );
        assert_eq!(split_owner("O:SY"), Some(("SY", "")));
        assert_eq!(split_owner("G:SYD:"), None);
        assert_eq!(without_owner("O:BAD:(A;;KA;;;BA)"), "D:(A;;KA;;;BA)");
        assert_eq!(without_owner("D:"), "D:");
    }

    /// UTF-16LE bytes of `text`, exactly (NULs written into the text are kept, nothing is added).
    fn list(text: &str) -> Vec<u8> {
        utf16(text)
    }

    /// Removes `segment` purely and checks that the re-insert of the written data restores the original
    /// exactly through the readings. Returns (index, written data as text).
    fn remove_and_back(ty: u32, data: &[u8], segment: &str, index: Option<u32>) -> (u32, Vec<u8>) {
        let parsed = List::parse(ty, data).unwrap();
        let units = segment_units(parsed.kind, segment).unwrap();
        let pos = match index {
            Some(i) if parsed.segments.get(i as usize) == Some(&units) => i as usize,
            _ => parsed.segments.iter().position(|s| *s == units).unwrap(),
        };
        let mut edited = parsed.clone();
        edited.segments.remove(pos);
        let written = edited.render();
        let back = List::parse(ty, &written).unwrap();
        let restored = back
            .readings()
            .iter()
            .map(|r| r.insert(pos as u32, &units).render())
            .find(|d| sha256(d) == sha256(data));
        assert_eq!(restored.as_deref(), Some(data), "re-insert of {segment:?}");
        (pos as u32, written)
    }

    /// (type, data, segment, index asked for, index removed, data written).
    type SegmentCase = (
        u32,
        &'static str,
        &'static str,
        Option<u32>,
        u32,
        &'static str,
    );

    #[test]
    fn segment_lists_keep_type_and_terminators() {
        let cases: &[SegmentCase] = &[
            // ';' lists: duplicates, index, empty elements, trailing ';', no terminator.
            (REG_SZ, "a;b;a;\0", "a", Some(2), 2, "a;b;\0"),
            (REG_SZ, "a;b;a;\0", "a", None, 0, "b;a;\0"),
            (REG_SZ, "a;b;a;\0", "a", Some(1), 0, "b;a;\0"),
            (REG_SZ, "a;;b\0", "b", None, 2, "a;\0"),
            (REG_SZ, "x;\0", "x", None, 0, "\0"),
            (REG_SZ, "x\0", "x", None, 0, "\0"),
            (REG_SZ, "x", "x", None, 0, ""),
            (REG_SZ, ";x;\0\0", "x", None, 1, ";\0\0"),
            (REG_EXPAND_SZ, "%A%;C:\\x;D\0", "C:\\x", None, 1, "%A%;D\0"),
            // A `;` inside double quotes is part of the element (review M8).
            (
                REG_SZ,
                "\"C:\\a;b\";C:\\c\0",
                "C:\\c",
                Some(1),
                1,
                "\"C:\\a;b\"\0",
            ),
            (
                REG_EXPAND_SZ,
                "\"C:\\a;b\";C:\\c\0",
                "\"C:\\a;b\"",
                None,
                0,
                "C:\\c\0",
            ),
            (REG_SZ, "x;\"y\";z\0", "\"y\"", None, 1, "x;z\0"),
            // REG_MULTI_SZ: empty elements and terminators kept.
            (REG_MULTI_SZ, "a\0b\0\0", "b", None, 1, "a\0\0"),
            (REG_MULTI_SZ, "a\0b\0\0", "a", None, 0, "b\0\0"),
            (REG_MULTI_SZ, "a\0\0b\0\0", "b", None, 2, "a\0\0\0"),
            // The empty first element merges into the terminators; the re-insert still gets it back.
            (REG_MULTI_SZ, "\0a\0\0", "a", None, 1, "\0\0"),
            (REG_MULTI_SZ, "a\0b", "b", None, 1, "a"),
            (REG_MULTI_SZ, "a\0\0", "a", None, 0, "\0\0"),
            (REG_MULTI_SZ, "a;b\0c\0\0", "a;b", None, 0, "c\0\0"),
        ];
        for &(ty, data, segment, index, want_index, want) in cases {
            let data = list(data);
            let (pos, written) = remove_and_back(ty, &data, segment, index);
            assert_eq!(
                (pos, written),
                (want_index, list(want)),
                "{segment:?} from {data:?}"
            );
        }
        // Every element of a few awkward lists, at every index.
        for (ty, data) in [
            (REG_SZ, ";;a;;b;;\0"),
            (REG_MULTI_SZ, "\0\0a\0\0b\0\0\0"),
            (REG_MULTI_SZ, "a\0a\0a\0\0"),
        ] {
            let data = list(data);
            let parsed = List::parse(ty, &data).unwrap();
            for (i, segment) in parsed.segments.iter().enumerate() {
                if !segment.is_empty() {
                    let text = String::from_utf16(segment).unwrap();
                    remove_and_back(ty, &data, &text, Some(i as u32));
                }
            }
        }
        // Refusals.
        assert_eq!(List::parse(REG_DWORD, &[0; 4]), Err(SegmentError::NotAList));
        assert_eq!(List::parse(REG_SZ, &[0x41]), Err(SegmentError::NotAList));
        assert_eq!(
            List::parse(REG_SZ, &list("a\0b\0")),
            Err(SegmentError::NotAList)
        );
        for bad in ["", "a;b", "a\0", "b\"", "\"a;b"] {
            assert_eq!(
                segment_units(ListKind::Semicolon, bad),
                Err(SegmentError::BadSegment),
                "{bad:?}"
            );
        }
        assert!(segment_units(ListKind::MultiSz, "a;b").is_ok());
        assert!(segment_units(ListKind::Semicolon, "\"a;b\"").is_ok());
        // An unclosed quote: no reader agrees where the elements are, so the value is not edited.
        assert_eq!(
            List::parse(REG_SZ, &list("\"C:\\a;b;C:\\c\0")),
            Err(SegmentError::NotAList)
        );
        // Half of a quoted element is not an element: before M8 `b"` was one, and removing it broke
        // the quoted path.
        let quoted = List::parse(REG_SZ, &list("\"C:\\a;b\";C:\\c\0")).unwrap();
        assert_eq!(quoted.segments.len(), 2);
        assert!(
            !quoted
                .segments
                .contains(&"b\"".encode_utf16().collect::<Vec<u16>>())
        );
    }

    #[test]
    fn segment_edits_on_live_values() {
        let root = TestRoot::new();
        let s = root.key.create_subkey("S", "", None, false).unwrap();
        let cases = [
            (
                "path",
                REG_EXPAND_SZ,
                utf16z("%A%;C:\\x;;D:\\y;"),
                "C:\\x",
                Some(1),
            ),
            (
                "multi",
                REG_MULTI_SZ,
                utf16z("one\0two\0\0two\0"),
                "two",
                Some(3),
            ),
            ("only", REG_SZ, utf16z("only"), "only", None),
            ("unterminated", REG_SZ, utf16("a;b"), "b", None),
        ];
        for (name, ty, data, _, _) in &cases {
            s.set_value_raw(name, *ty, data).unwrap();
        }
        drop(s);
        let key = root.open("S", KeyAccess::SET_VALUE);
        // The same key as the gate hands it to undo.
        let checked = CheckedValueKey::unchecked_for_tests(
            root.open("S", KeyAccess::SET_VALUE),
            hku(&root.rel("S")),
        );
        for (name, ty, data, segment, index) in cases {
            let plan = plan_segment_removal(&key, name, segment, index).unwrap();
            assert_eq!(plan.original.data_b64.0, data);
            assert_eq!(plan.original_value_hash, sha256(&data));
            assert_eq!(plan.written_value_hash, sha256(&plan.written));
            apply_segment_removal(&key, &plan).unwrap();
            let live = key.value(name).unwrap().unwrap();
            assert_eq!((live.ty, &live.data), (ty, &plan.written));

            let mut undo = SegmentUndo {
                name: name.into(),
                segment: segment.into(),
                index: plan.index,
                original_value_hash: plan.original_value_hash,
                written_value_hash: plan.written_value_hash,
                original: None,
            };
            // Without the value backup: rebuilt, and exact.
            assert_eq!(
                reinsert_segment(&checked, &undo),
                Ok(ReinsertOutcome::Reinserted { exact: true })
            );
            assert_eq!(key.value(name).unwrap().unwrap().data, data);
            assert_eq!(
                reinsert_segment(&checked, &undo),
                Ok(ReinsertOutcome::AlreadyRestored)
            );

            // With the value backup.
            apply_segment_removal(&key, &plan).unwrap();
            undo.original = Some(plan.original.clone());
            assert_eq!(
                reinsert_segment(&checked, &undo),
                Ok(ReinsertOutcome::Reinserted { exact: true })
            );
            assert_eq!(key.value(name).unwrap().unwrap().data, data);

            // Applying a plan after the value changed is refused.
            key.set_value_raw(name, ty, &utf16z("zzz")).unwrap();
            assert_eq!(
                apply_segment_removal(&key, &plan),
                Err(SegmentError::Changed)
            );
            key.set_value_raw(name, ty, &data).unwrap();
        }

        // The value changed after the edit and merely lacks the segment: put back at the index, clamped.
        let plan = plan_segment_removal(&key, "path", "D:\\y", None).unwrap();
        assert_eq!(plan.index, 3);
        apply_segment_removal(&key, &plan).unwrap();
        key.set_value_raw("path", REG_EXPAND_SZ, &utf16z("E"))
            .unwrap();
        let undo = SegmentUndo {
            name: "path".into(),
            segment: "D:\\y".into(),
            index: plan.index,
            original_value_hash: plan.original_value_hash,
            written_value_hash: plan.written_value_hash,
            original: Some(plan.original.clone()),
        };
        assert_eq!(
            reinsert_segment(&checked, &undo),
            Ok(ReinsertOutcome::Reinserted { exact: false })
        );
        let live = key.value("path").unwrap().unwrap();
        assert_eq!((live.ty, live.data), (REG_EXPAND_SZ, utf16z("E;D:\\y")));
        // Present again: nothing to do.
        assert_eq!(
            reinsert_segment(&checked, &undo),
            Ok(ReinsertOutcome::AlreadyPresent)
        );
        // Gone, or no longer a list: conflicts.
        key.delete_value("path").unwrap();
        let err = reinsert_segment(&checked, &undo).unwrap_err();
        assert_eq!(err, SegmentError::ValueAbsent);
        assert_eq!(err.undo_conflict(), Some(UndoConflict::ValueChanged));
        key.set_value_raw("path", REG_DWORD, &[0; 4]).unwrap();
        assert_eq!(
            reinsert_segment(&checked, &undo),
            Err(SegmentError::NotAList)
        );

        // Planning refusals.
        assert_eq!(
            plan_segment_removal(&key, "absent", "x", None),
            Err(SegmentError::ValueAbsent)
        );
        assert_eq!(
            plan_segment_removal(&key, "only", "nothere", None),
            Err(SegmentError::SegmentAbsent)
        );
        assert_eq!(
            plan_segment_removal(&key, "path", "x", None),
            Err(SegmentError::NotAList)
        );
    }
}
