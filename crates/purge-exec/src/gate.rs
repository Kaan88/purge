//! Execute-time gate: live fact collection and the guard verdict on the acting handle (M2-X-GATE).
//!
//! ENGINE_PLAN.md §5.10, §7.2, §7.6. This is the only place in the executor where facts about the items
//! of a plan are read from the system. The verdicts themselves are pure and live in
//! [`purge_guard::live`]; this module opens the objects, fills the guard's fact structs from the open
//! handles, asks for the verdict and hands the **same** handle back for the action.
//!
//! # The two passes
//!
//! - **Validate** ([`validate`], [`validate_all`]) at the start of a run: each item is opened through a
//!   read-only handle, its facts are read, the guard decides with [`Binding::Capture`], and the result is a
//!   [`Stamp`] (what the act will be bound to) plus the [`ItemFacts`] for the journal's `validated`
//!   record. No handle that could change anything is opened. A file or directory whose candidate
//!   carries a scan-time identity ([`GateItem::scan_identity`]) passes only when the file id and volume
//!   serial read from that handle equal it (§5.10 "the file id must equal the scan"); otherwise it is
//!   refused with [`reason::SCAN_IDENTITY`] and nothing binds it.
//! - **Record**: the journal's `validated` record of each op is handed to [`GateCtx::record`] once it is
//!   written (and, for a resumed run, once it is read back). That record is the only source of the
//!   act's stamp and exemptions: the act-time functions take an op id and nothing else, so an act can
//!   be gated only with what was journalled.
//! - **Act** ([`open_and_check_path`], [`open_and_check_key`]) immediately before each action: the item is
//!   opened with the access the action needs, every fact is read from **that** handle, the guard decides
//!   with [`Binding::Recheck`] against the recorded stamp (for a key: the recorded counts, owner, link
//!   state and last write time), and on a pass the open handle is returned inside [`CheckedPath`] /
//!   [`CheckedKey`]. The action must be performed on it; nothing is reopened between check and act. On
//!   any other outcome the handle is closed before the function returns.
//!
//! # Same-run dependencies (registry)
//!
//! Items of one run can depend on each other: a key deleted if empty after its values and subkeys, a
//! key tree after separate items inside it, a value deleted after a segment edit of it. The plan puts
//! inner items first. The gate learns the run's ops ([`GateCtx::set_run_ops`], before the validate pass)
//! and, as the run goes, what its own completed ops did ([`GateCtx::note_done`] after each `done`;
//! [`GateCtx::note_journal`] for a resumed run). The validate pass does not refuse a delete-if-empty key
//! that earlier items empty; the act-time gate compares a key with its recorded facts as the run's own
//! ops changed them, and refuses every other difference as before. See [`GateCtx::note_done`].
//!
//! # Outcomes
//!
//! Every gate call ends in a [`GateOutcome`]: `Pass`, `Vanished` (the item is gone: success, nothing to
//! do; "not found" is mapped before the guard is asked), `Locked` (a sharing violation on the acting
//! handle, while a read-only look says the item would pass: for the locked-file ladder), `Refused` (a
//! guard or gate refusal; [`Refusal::is_hard`] tells skip from block) and `Failed` (the system refused
//! the open, e.g. access denied; Purge never raises its own access).
//!
//! # Failing closed
//!
//! A fact that cannot be read stays `None` in the guard's structs, and the guard refuses. The walk below a
//! directory that is moved whole reports `complete = false` on any error or skipped entry. The blast
//! radius (5,000 files by default, [`GateItem::max_files`]) is enforced here with
//! [`Blocker::TooLarge`]. [`GateCtx::new`] fails unless the process could be switched to
//! `PHCM_EXPOSE_PLACEHOLDERS`, without which cloud placeholders hide their attributes (G7).
//!
//! # Residual races
//!
//! The directory walk and the hard-link name listing are path based (`FindFirstFileExW`,
//! `FindFirstFileNameW`); each directory is opened and checked (plain directory, final path equal, the
//! root's identity equal to the acting handle's) before it is listed. Someone who can write inside the tree
//! can still add a link after the walk; the walk cannot stop a writer, it only refuses what it saw.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use purge_guard::deny::{DenyList, Exemptions};
use purge_guard::live::{
    self, AncestorWrite, Binding, BootMove, DestinationFacts, FileIdentity, KeyAddress,
    KeyAncestor, KeyCheck, KeyFacts, KeyNode, KeyOp, KeyProbe, KeyRoot, PLACEHOLDER_ATTRIBUTES,
    PathCheck, PathFacts, PathOp, PathStamp, QuarantineCheck, Refusal, StoreCheck, StoreOp,
    StoreScope, TreeFacts, UndoKeyFacts, UndoPathCheck, ValueStamp, ValueState, VolumeFacts,
    is_cloud_reparse_tag,
};
use purge_guard::prefix;
use purge_model::exec::journal::{
    FileFacts, GateExemptions, Intent, ItemFacts, RegFacts, Validated, ValueFacts,
};
use purge_model::exec::op::{ExecOp, FileIdHex, Inverse, ItemOutcome, OpId, Sha256Hex, SkipReason};
use purge_model::object::{ObjectFp, ObjectKind};
use purge_model::{Blocker, Candidate, CandidateId, FileTime, ItemFp, ScanMode, Target, View};
use purge_win::fs::{FileHandle, FileMeta, volume_info};
use purge_win::fs_write::{DestDir, FsError, MoveHandle, extended_path};
use purge_win::os::Win32Error;
use purge_win::reg::{RegRoot, RegValue, RegView};
use purge_win::reg_write::{KeyAccess, NAME_NOT_REPRESENTABLE, WKey, WKeyInfo};
use purge_win::secure::{Security, handle_security, open_for_security};
use purge_win::sid::{TRUSTED_INSTALLER_SID, is_admin_only_writable};
use sha2::{Digest, Sha256};

use crate::journal::{JournalState, OpState};
use crate::regbackup;
use crate::storage::QuarantineDir;

mod ffi;
#[cfg(test)]
mod tests;

/// Stable codes for refusals the gate raises itself (the guard's own codes are in
/// [`purge_guard::live::reason`]).
pub mod reason {
    /// The path cannot be put into `\\?\` form (relative, `.`/`..` segment, device path).
    pub const PATH_FORM: &str = "gate.path-form";
    /// The tree below a directory moved whole holds more files or directories than the item may.
    pub const BLAST_RADIUS: &str = "gate.blast-radius";
    /// A name on the key path cannot be addressed exactly (not valid UTF-16).
    pub const NAME_NOT_REPRESENTABLE: &str = "gate.name-not-representable";
    /// Facts the journal needs (counts, class, owner, value size) could not be read.
    pub const FACTS_UNREADABLE: &str = "gate.facts-unreadable";
    /// The validated facts do not fit the item's operation (a file stamp for a key action, ...).
    pub const STAMP_KIND: &str = "gate.stamp-kind";
    /// The executor op has no file-system or registry gate (wrong function for the op).
    pub const OP_KIND: &str = "gate.op-kind";
    /// The act-time gate was asked about an op id with no recorded validation ([`super::GateCtx::record`]).
    pub const NOT_VALIDATED: &str = "gate.not-validated";
    /// A `validated` record does not belong to the op it was recorded for (other target), or the op id
    /// already has one.
    pub const VALIDATION_MISMATCH: &str = "gate.validation-mismatch";
    /// A key to delete is not the one validated: subkey or value count, owner, link state or last write
    /// time differ from the `validated` record. Soft: changed since the scan.
    pub const KEY_CHANGED: &str = "gate.key-changed";
    /// The tree of a key to delete, as captured for its backup, is not the tree validated: somewhere
    /// below or in the key a value, a subkey, a class, a security descriptor or a volatility differs from
    /// the `validated` record's digest after what the run's own completed ops did is put back
    /// ([`super::bind_tree`]), or the record has no digest. Soft: changed since the scan.
    pub const TREE_CHANGED: &str = "gate.tree-changed";
    /// The validate pass could not read the tree of a key to delete for its digest (a link, a volatile
    /// key, a `REG_LINK` value or a name the backup cannot hold somewhere below it, or more keys than the
    /// item's limit); the blocker says which.
    pub const TREE_NOT_READ: &str = "gate.tree-not-read";
    /// The key a restore acts on does not exist: the parent of a key to re-create, or the key a value or
    /// segment goes back into. Soft: an undo conflict, skipped and reported.
    pub const UNDO_KEY_MISSING: &str = "gate.undo-key-missing";
    /// The destination directory opened by path is not the store's op directory (other volume serial or
    /// file id).
    pub const QUARANTINE_DIR_DIFFERS: &str = "gate.quarantine-dir-differs";
    /// The file or directory at the path is not the one the scan read: its file id or volume serial
    /// differs from the candidate's scan-time identity ([`purge_model::Candidate::item_fp`]), or either
    /// volume serial is 0. Soft: changed since the scan.
    pub const SCAN_IDENTITY: &str = "gate.scan-identity";
    /// Detail of a skipped object: the candidate carries no object fingerprint (or one that is not 64
    /// lower-case hex digits). The detail C-ACT names.
    pub const NO_OBJECT_FP: &str = "no object fingerprint";
    /// Detail of a skipped object: the object's identity digest is not the validated or planned one.
    pub const OBJECT_CHANGED: &str = "gate.object-changed";
    /// Detail of a skipped object: the object read is of another kind than the validated or planned one.
    pub const OBJECT_KIND: &str = "gate.object-kind";
    /// Detail of a skipped object: the object is gone at the act-time check (the caller's `Vanished`
    /// comes first; this is the fallback).
    pub const OBJECT_GONE: &str = "gate.object-gone";
    /// Detail of a skipped object: the op's validated record holds no object stamp.
    pub const OBJECT_NOT_VALIDATED: &str = "gate.object-not-validated";
}

/// A refusal for which no dedicated blocker exists: reported as a deny rule named after the reason, as
/// the guard does.
fn rule(reason: &'static str) -> Refusal {
    Refusal {
        blocker: Blocker::DenyListed {
            rule: reason.to_owned(),
        },
        reason,
    }
}

/// How a gate call ended.
#[derive(Debug)]
pub enum GateOutcome<T> {
    /// Every rule passed. For an act call, `T` holds the open handle to act on.
    Pass(T),
    /// The item no longer exists. Success: there is nothing to do.
    Vanished,
    /// The acting handle could not be opened because another process holds the item without delete
    /// sharing (a running image, an open file), or, for a directory, with access denied (something open
    /// below it); a read-only look let it through the gate. Only file-system items end like this.
    Locked(LockedPath),
    /// The guard or the gate refused the item. [`Refusal::is_hard`]: `false` means skip as changed.
    Refused(Refusal),
    /// The system refused to open the item (access denied and the like); the item is reported failed.
    Failed(Win32Error),
}

impl<T> GateOutcome<T> {
    /// The value of a `Pass`.
    pub fn pass(self) -> Option<T> {
        match self {
            GateOutcome::Pass(value) => Some(value),
            _ => None,
        }
    }

    /// The refusal of a `Refused`.
    pub fn refusal(&self) -> Option<&Refusal> {
        match self {
            GateOutcome::Refused(refusal) => Some(refusal),
            _ => None,
        }
    }

    /// Whether the item vanished.
    pub fn is_vanished(&self) -> bool {
        matches!(self, GateOutcome::Vanished)
    }

    fn map<U>(self, f: impl FnOnce(T) -> U) -> GateOutcome<U> {
        self.and_then(|value| GateOutcome::Pass(f(value)))
    }

    /// `f` of the value of a `Pass`; every other outcome unchanged.
    fn and_then<U>(self, f: impl FnOnce(T) -> GateOutcome<U>) -> GateOutcome<U> {
        match self {
            GateOutcome::Pass(value) => f(value),
            GateOutcome::Vanished => GateOutcome::Vanished,
            GateOutcome::Locked(locked) => GateOutcome::Locked(locked),
            GateOutcome::Refused(refusal) => GateOutcome::Refused(refusal),
            GateOutcome::Failed(e) => GateOutcome::Failed(e),
        }
    }
}

/// A locked file-system item: what a read-only handle showed while the acting handle could not be opened.
/// The locked-file ladder (§7.6) works from this; it re-opens the item when it acts.
#[derive(Debug, Clone)]
pub struct LockedPath {
    /// The facts the read-only handle gave (they passed the gate against the stamp).
    pub facts: PathFacts,
    /// The item's stamp, equal to the validated one.
    pub stamp: PathStamp,
    /// The open error of the acting handle: a sharing or lock violation, or access denied on a directory
    /// (something open below it may cause that). The ladder decides by this error; for a directory with
    /// access denied it must not assume "in use" is certain.
    pub error: Win32Error,
}

// ---------------------------------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------------------------------

/// Owner and TrustedInstaller facts of one object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityFacts {
    /// The owner SID (`S-1-5-...`).
    pub owner: Option<String>,
    /// The owner is TrustedInstaller.
    pub owner_is_ti: Option<bool>,
    /// For a file or directory: an explicit (not inherited) ACE names TrustedInstaller. For a key: any
    /// ACE does.
    pub ti_ace: Option<bool>,
}

/// The facts the gate reads through this trait rather than directly, so tests can put in owners and
/// volumes a test machine cannot produce unelevated (TrustedInstaller ownership, removable or FAT
/// volumes). Releases always use [`LiveHost`]; only `cfg(test)` and the `test-support` feature can install
/// another one (`GateCtx::with_host`, which exists only in those builds).
pub trait HostFacts: Send + Sync + fmt::Debug {
    /// Owner and TrustedInstaller facts of a file or directory from its security descriptor (`None` when
    /// the descriptor could not be read from the handle).
    fn file_security(&self, security: Option<&Security>) -> SecurityFacts;
    /// Owner and TrustedInstaller facts of a key, read from its handle.
    fn key_security(&self, key: &WKey) -> SecurityFacts;
    /// Facts about the volume the item lies on: `final_path` is the handle's final path and
    /// `volume_serial` the serial of its `FILE_ID_INFO`. `None` when the volume cannot be told, or is not
    /// the one the handle is on.
    fn volume(&self, final_path: &str, volume_serial: u64) -> Option<VolumeFacts>;
    /// The SID of the user the process token belongs to (`None` when it cannot be read): whose package
    /// registrations a removal for the current user changes ([`GateCtx::package_user_refusal`]).
    fn process_user_sid(&self) -> Option<String> {
        purge_win::sid::current_user_sid().ok()
    }
}

/// The facts as the system gives them.
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveHost;

impl HostFacts for LiveHost {
    fn file_security(&self, security: Option<&Security>) -> SecurityFacts {
        let Some(security) = security else {
            return SecurityFacts::default();
        };
        SecurityFacts {
            owner: security.owner.clone(),
            owner_is_ti: security
                .owner
                .as_deref()
                .map(|owner| owner == TRUSTED_INSTALLER_SID),
            ti_ace: Some(security.aces().iter().any(|ace| {
                !ace.is_inherited() && ace.sid.as_deref() == Some(TRUSTED_INSTALLER_SID)
            })),
        }
    }

    fn key_security(&self, key: &WKey) -> SecurityFacts {
        match key.security() {
            Ok(security) => SecurityFacts {
                owner_is_ti: security
                    .owner_sid
                    .as_deref()
                    .map(|owner| owner == TRUSTED_INSTALLER_SID),
                owner: security.owner_sid,
                ti_ace: Some(security.dacl_names_trusted_installer),
            },
            Err(_) => SecurityFacts::default(),
        }
    }

    fn volume(&self, final_path: &str, volume_serial: u64) -> Option<VolumeFacts> {
        let info = volume_info(Path::new(final_path)).ok()?;
        // The 32-bit serial of GetVolumeInformationW is the low half of the 64-bit FILE_ID_INFO serial.
        (u64::from(info.serial) == volume_serial & 0xFFFF_FFFF).then(|| VolumeFacts {
            drive_fixed: info.is_fixed(),
            fs_name: info.fs_name,
        })
    }
}

/// Why a [`GateCtx`] could not be set up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GateSetupError {
    /// `RtlSetProcessPlaceholderCompatibilityMode(PHCM_EXPOSE_PLACEHOLDERS)` failed or did not stick
    /// (the mode or error code the system reported instead).
    #[error("cannot expose cloud placeholders to the process (mode {0})")]
    Placeholders(i8),
}

/// Switches the process to `PHCM_EXPOSE_PLACEHOLDERS`, so cloud placeholders show their attributes and
/// tags (gate G7). [`GateCtx::new`] calls it; calling it again is harmless.
pub fn expose_placeholders() -> Result<(), GateSetupError> {
    ffi::expose_placeholders().map_err(GateSetupError::Placeholders)
}

/// What every gate call of one run shares.
#[derive(Debug)]
pub struct GateCtx {
    deny: DenyList,
    removed_whole: Vec<String>,
    scope: StoreScope,
    host: Box<dyn HostFacts>,
    validated: BTreeMap<OpId, Recorded>,
    /// The run's ops by op id ([`GateCtx::set_run_ops`]), for the same-run dependencies.
    run_ops: Vec<RunOp>,
    /// What this run's own completed registry ops did to the keys later ops are bound to
    /// ([`GateCtx::note_done`]), by the op that did it.
    effects: BTreeMap<OpId, OwnEffect>,
    /// The user the scan was made for (the run's `user_sid` setting, [`GateCtx::bind_user`]).
    user_sid: Option<String>,
    /// The run's M1b exemption lists ([`GateCtx::set_gone`]), applied to every recorded op.
    gone: Gone,
}

/// The run's M1b exemption lists as the guard's [`Exemptions`] take them (`&'static` slices, interned
/// once per distinct list for the process: [`intern`]).
#[derive(Debug, Clone, Copy, Default)]
struct Gone {
    msi_products: &'static [String],
    cache_dirs: &'static [String],
    burn: &'static [String],
}

impl Gone {
    /// `exemptions` with these lists in place of its own.
    fn apply(self, exemptions: Exemptions<'static>) -> Exemptions<'static> {
        Exemptions {
            gone_msi_products: self.msi_products,
            gone_cache_dirs: self.cache_dirs,
            gone_burn: self.burn,
            ..exemptions
        }
    }
}

/// A process-lifetime copy of `list`, shared by every caller with an equal list. The guard's
/// [`Exemptions`] borrow their lists for `'static`; a process runs a handful of sessions, each with one
/// set of lists, so the copies stay few.
fn intern(list: &[String]) -> &'static [String] {
    static INTERNED: std::sync::Mutex<Vec<&'static [String]>> = std::sync::Mutex::new(Vec::new());
    if list.is_empty() {
        return &[];
    }
    let mut interned = INTERNED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(found) = interned.iter().find(|known| **known == list) {
        return found;
    }
    let leaked: &'static [String] = Box::leak(list.to_vec().into_boxed_slice());
    interned.push(leaked);
    leaked
}

/// One op of the run, with the canonical address of the key it acts on (the key itself for a key op,
/// the key holding the value for a value or segment op; `None` for other ops and for a target the guard
/// cannot canonicalise, which then counts for nothing).
#[derive(Debug, Clone)]
struct RunOp {
    op: OpId,
    exec_op: ExecOp,
    key: Option<KeyAddress>,
}

/// The effect a completed registry op of this run had on one key (see "Same-run dependencies" on
/// [`GateCtx::note_done`]).
#[derive(Debug, Clone)]
struct OwnEffect {
    /// The key whose facts the op changed: the key holding a deleted or edited value, or the parent of a
    /// deleted key.
    key: KeyAddress,
    /// Values the op removed from `key`.
    values: u32,
    /// Direct subkeys the op removed from `key`.
    subkeys: u32,
    /// For a segment edit: the value (by name) and the SHA-256 of the data the op wrote into it.
    rewritten: Option<(String, [u8; 32])>,
    /// When the gate learned of the effect: the op's own change to `key` happened no later than this
    /// (registry times come from the coarse system clock, which never runs ahead of the precise one).
    noted_at: FileTime,
    /// Exactly what the op changed in the content of `key`, for the tree binding ([`bind_tree`]);
    /// `None` when the journal does not say it exactly, which refuses every tree holding `key`.
    content: Option<ContentChange>,
}

/// What one own op changed in the content of one key, as [`bind_tree`] puts it back. Names are folded
/// (`regbackup::fold_str`); hashes are SHA-256 of raw value data.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ContentChange {
    /// A value was deleted; it had this type and data hash (the intent's `pre`, read on the acting
    /// handle; the delete happened only while the value was exactly its backup).
    ValueDeleted {
        name: Vec<u16>,
        ty: u32,
        sha256: [u8; 32],
    },
    /// A segment edit replaced the data with hash `original` by the data with hash `written` (the
    /// intent's inverse); the type stayed.
    ValueRewritten {
        name: Vec<u16>,
        original: [u8; 32],
        written: [u8; 32],
    },
    /// A direct subkey was deleted whole; its tree had the digest recorded when it was validated (its
    /// act was bound to that digest).
    SubkeyDeleted { name: Vec<u16>, digest: [u8; 32] },
}

impl ContentChange {
    /// Puts the change back into `content`, the content of the key now: what the key held before the
    /// op. `false` when `content` is not what the op left (the value or subkey is there again, or the
    /// rewritten value does not hold what the edit wrote): someone else changed the key since.
    fn put_back(&self, content: &mut regbackup::KeyContent) -> bool {
        match self {
            ContentChange::ValueDeleted { name, ty, sha256 } => content
                .values
                .insert(name.clone(), (*ty, *sha256))
                .is_none(),
            ContentChange::ValueRewritten {
                name,
                original,
                written,
            } => match content.values.get_mut(name) {
                Some((_, now)) if now == written => {
                    *now = *original;
                    true
                }
                _ => false,
            },
            ContentChange::SubkeyDeleted { name, digest } => {
                content.subkeys.insert(name.clone(), *digest).is_none()
            }
        }
    }
}

/// What this run's own completed ops explain about one key: the facts recorded at validation may
/// differ from the live ones by exactly this much.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct OwnChanges {
    /// Values removed by own ops.
    values: u32,
    /// Direct subkeys removed by own ops.
    subkeys: u32,
    /// The latest time an own op may have written the key (`None`: no own op touched it).
    touched_until: Option<FileTime>,
}

impl OwnChanges {
    /// Whether the live facts `now` are the recorded ones changed only by these own effects: subkey and
    /// value counts exactly the recorded ones less the own removals, link state and owner equal, and the
    /// last write time equal or, when an own op wrote the key, at least the recorded one and no later
    /// than the latest own write could have been. With no own effect this is plain equality (review S5).
    fn explain(&self, recorded: &RegFacts, now: &RegFacts) -> bool {
        // Destructured without `..`, so a field added to the record fails to compile here.
        let RegFacts {
            subkeys,
            values,
            is_link,
            owner,
            last_write_time,
            // The tree is compared on its capture, with every own change put back ([`bind_tree`]).
            tree_sha256: _,
        } = recorded;
        let time_explained = now.last_write_time == *last_write_time
            || self.touched_until.is_some_and(|until| {
                now.last_write_time.0 >= last_write_time.0 && now.last_write_time.0 <= until.0
            });
        subkeys.checked_sub(self.subkeys) == Some(now.subkeys)
            && values.checked_sub(self.values) == Some(now.values)
            && *is_link == now.is_link
            && *owner == now.owner
            && time_explained
    }
}

/// The current time as a FILETIME (100 ns ticks since 1601-01-01 UTC), from the precise system clock.
fn filetime_now() -> FileTime {
    /// FILETIME of 1970-01-01.
    const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ticks = u64::try_from(since.as_nanos() / 100).unwrap_or(u64::MAX);
    FileTime(UNIX_EPOCH_TICKS.saturating_add(ticks))
}

/// The canonical address of the key `op` acts on (for a value or segment op: the key holding it).
fn op_key(op: &ExecOp, deny: &DenyList) -> Option<KeyAddress> {
    if !op.is_registry() {
        return None;
    }
    live::key_probe(&op.target(), deny.env())
        .ok()
        .map(|probe| probe.open)
}

/// The effect a completed op (`intent`, whose `done` is `Done`) had on the key a later op may be bound
/// to; `None` for an op that changes no key's facts (file and package ops, a key directly below its hive
/// root, a target that does not canonicalise). `validated` is the stamp the op's act was bound to (for a
/// key op: the digest of its tree, which the parent's content held).
fn own_effect(
    intent: &Intent,
    validated: Option<&Stamp>,
    deny: &DenyList,
    noted_at: FileTime,
) -> Option<OwnEffect> {
    let probe = live::key_probe(&intent.exec_op.target(), deny.env()).ok()?;
    let effect = |key, values, subkeys, rewritten, content| OwnEffect {
        key,
        values,
        subkeys,
        rewritten,
        noted_at,
        content,
    };
    match &intent.exec_op {
        ExecOp::DeleteValue { name, .. } => {
            let content = match &intent.pre {
                ItemFacts::Value(pre) => Some(ContentChange::ValueDeleted {
                    name: regbackup::fold_str(name),
                    ty: pre.value_type,
                    sha256: pre.data_sha256.0,
                }),
                _ => None,
            };
            Some(effect(probe.open, 1, 0, None, content))
        }
        ExecOp::EditSegment { name, .. } => {
            let (rewritten, content) = match &intent.inverse {
                Inverse::ReinsertSegment {
                    original_value_hash,
                    written_value_hash,
                    ..
                } => (
                    Some((name.clone(), written_value_hash.0)),
                    Some(ContentChange::ValueRewritten {
                        name: regbackup::fold_str(name),
                        original: original_value_hash.0,
                        written: written_value_hash.0,
                    }),
                ),
                _ => (None, None),
            };
            Some(effect(probe.open, 0, 0, rewritten, content))
        }
        ExecOp::DeleteKeyTree { .. } | ExecOp::DeleteKeyIfEmpty { .. } => {
            let content = match (prefix::leaf(&probe.open.path), validated) {
                (Some(leaf), Some(Stamp::Key(facts))) => {
                    facts
                        .tree_sha256
                        .map(|digest| ContentChange::SubkeyDeleted {
                            name: regbackup::fold_str(leaf),
                            digest: digest.0,
                        })
                }
                _ => None,
            };
            Some(effect(probe.ancestors.last()?.clone(), 0, 1, None, content))
        }
        // Not a key: nothing a later registry op is bound to changes. An object op's hive is flushed by
        // its own module.
        ExecOp::QuarantineMove { .. }
        | ExecOp::RemoveDirIfEmpty { .. }
        | ExecOp::RemovePackage { .. }
        | ExecOp::DeleteService { .. }
        | ExecOp::DeleteTask { .. }
        | ExecOp::DeleteFirewallRule { .. } => None,
    }
}

/// What the act-time gate takes for one op: the stamp and the exemptions of its journal `validated`
/// record, the op that record was accepted for, and the blast-radius limit.
#[derive(Debug, Clone)]
struct Recorded {
    op: ExecOp,
    record: Validated,
    stamp: Stamp,
    exemptions: Exemptions<'static>,
    max_files: u32,
}

impl Recorded {
    /// The item as the gate functions take it, with the recorded exemptions and limit.
    fn item(&self) -> GateItem<'_> {
        // The act is bound to the recorded stamp, which the validate pass already compared with the
        // scan-time identity; the act-time gate does not compare again.
        // The key limit is not used at act time: the act's capture takes the run's limit itself.
        GateItem {
            op: &self.op,
            exemptions: self.exemptions,
            max_files: self.max_files,
            max_keys: regbackup::DEFAULT_KEY_LIMIT,
            scan_identity: None,
        }
    }
}

impl GateCtx {
    /// A context for one run.
    ///
    /// - `deny`: the deny-list compiled from the live `GuardEnv` (its `purge_dirs` must hold Purge's
    ///   store roots).
    /// - `selected`: the ops of every selected item. The paths of the `QuarantineMove` ops are the paths
    ///   this run removes whole, against which hard links are judged (G6).
    /// - `scope`: this session's own store directories, for quarantine destinations and store items.
    ///
    /// Sets `PHCM_EXPOSE_PLACEHOLDERS` for the process and fails if that is not possible.
    pub fn new(
        deny: DenyList,
        selected: &[ExecOp],
        scope: StoreScope,
    ) -> Result<GateCtx, GateSetupError> {
        Self::build(deny, selected, scope, Box::new(LiveHost))
    }

    /// [`GateCtx::new`] with injected [`HostFacts`]. Tests only.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_host(
        deny: DenyList,
        selected: &[ExecOp],
        scope: StoreScope,
        host: Box<dyn HostFacts>,
    ) -> Result<GateCtx, GateSetupError> {
        Self::build(deny, selected, scope, host)
    }

    fn build(
        deny: DenyList,
        selected: &[ExecOp],
        scope: StoreScope,
        host: Box<dyn HostFacts>,
    ) -> Result<GateCtx, GateSetupError> {
        expose_placeholders()?;
        let removed_whole = selected
            .iter()
            .filter_map(|op| match op {
                ExecOp::QuarantineMove { path } => Some(path.clone()),
                _ => None,
            })
            .collect();
        Ok(GateCtx {
            deny,
            removed_whole,
            scope,
            host,
            validated: BTreeMap::new(),
            run_ops: Vec::new(),
            effects: BTreeMap::new(),
            user_sid: None,
            gone: Gone::default(),
        })
    }

    /// Sets the run's M1b exemption lists (C-GUARD): the ones its `settings` record holds
    /// (`RunSettings::gone_*`, [`crate::plan_in::GoneLists`]), which the run's caller computed from the
    /// app's fingerprint and fresh system queries when the run started. They apply to every op of the
    /// run, as the plan's decide step gives them to every candidate: to the records accepted before and
    /// after this call ([`GateCtx::exemptions`]) and to [`GateCtx::with_gone`]. Without a call they
    /// are empty, which keeps every exemption they open closed.
    pub fn set_gone(&mut self, lists: &crate::plan_in::GoneLists) {
        self.gone = Gone {
            msi_products: intern(&lists.msi_products),
            cache_dirs: intern(&lists.cache_dirs),
            burn: intern(&lists.burn),
        };
        let gone = self.gone;
        for recorded in self.validated.values_mut() {
            recorded.exemptions = gone.apply(recorded.exemptions);
        }
    }

    /// `exemptions` with the run's M1b exemption lists ([`GateCtx::set_gone`]) in place of its own: what
    /// the validate pass judges an item with.
    pub fn with_gone(&self, exemptions: Exemptions<'static>) -> Exemptions<'static> {
        self.gone.apply(exemptions)
    }

    /// Tells the gate whom the scan was made for: the run's `user_sid` setting (journalled with the
    /// run's settings). The executor calls it once, when it makes the context. Package removals compare
    /// it with the process token's user ([`GateCtx::package_user_refusal`]).
    pub fn bind_user(&mut self, user_sid: Option<&str>) {
        self.user_sid = user_sid.map(str::to_owned);
    }

    /// The user the scan was made for ([`GateCtx::bind_user`]), whose profile tokens a task's program
    /// path may use; `None` when the run names none.
    pub fn user_sid(&self) -> Option<&str> {
        self.user_sid.as_deref()
    }

    /// Why a package removal (always for the process token's user, `RemovalScope::CurrentUser`) must not
    /// run in this context: the scan was made for a user (`user_sid`) and the process token belongs to
    /// another user, or its user cannot be read (review M2 final M12: an elevated run under another
    /// administrator account would remove that account's registration of the package, irreversibly).
    /// `None` when they are the same user (SIDs compare without case), or when the run names no user,
    /// in which case the removal is for the process's own user as before.
    pub fn package_user_refusal(&self) -> Option<String> {
        let scan_user = self.user_sid.as_deref()?;
        match self.host.process_user_sid() {
            Some(token_user) if token_user.eq_ignore_ascii_case(scan_user) => None,
            Some(token_user) => Some(format!(
                "the scan was made for user {scan_user}, but Purge runs as user {token_user}; a \
                 package is removed only for the user Purge runs as"
            )),
            None => Some(format!(
                "the scan was made for user {scan_user}, and the user Purge runs as cannot be read"
            )),
        }
    }

    /// Tells the gate every op of the run with its op id (plan order is op order: an item inside another
    /// comes first). The executor calls it once, right after making the context and before the validate
    /// pass; a later call replaces the list. Without it nothing below changes the gate's verdicts.
    ///
    /// The validate pass uses it for a `DeleteKeyIfEmpty` that is not empty when the run starts: such a
    /// key is not refused as not empty when every value and every direct subkey it holds is the target
    /// of an earlier op of the run that removes it whole (a `DeleteValue` of that value, a
    /// `DeleteKeyTree` or `DeleteKeyIfEmpty` of that subkey). Its facts are journalled as they are
    /// (counts above zero); whether it is empty is decided at the act, on the handle, as always.
    pub fn set_run_ops(&mut self, ops: impl IntoIterator<Item = (OpId, ExecOp)>) {
        self.run_ops = ops
            .into_iter()
            .map(|(op, exec_op)| RunOp {
                op,
                key: op_key(&exec_op, &self.deny),
                exec_op,
            })
            .collect();
    }

    /// Notes what op `op` of this run did, once its `done` record is written (or read back), so that
    /// later ops bound to a key it changed are judged against the recorded facts **as this run's own
    /// ops changed them**. Only an op with an intent and the outcome `Done` counts; any other op is
    /// ignored. Noting the same op again changes nothing.
    ///
    /// # Same-run dependencies
    ///
    /// A key op is bound to the facts its `validated` record holds (review S5): counts, link state, owner
    /// and last write time, read when the run started. Items of the same run that act inside the key
    /// before it (a value of the key, a subkey) change those facts. What is noted, per completed op:
    ///
    /// | Op (outcome `Done`) | Key whose facts it changed | Noted effect |
    /// |---|---|---|
    /// | `DeleteValue` | the key holding the value | one value less; the key written |
    /// | `EditSegment` | the key holding the value | the key written; the value now holds the data whose hash the intent's inverse records |
    /// | `DeleteKeyTree`, `DeleteKeyIfEmpty` | the parent key | one subkey less; the key written |
    ///
    /// with the time the gate noted it, which the op's own write to the key cannot be later than. The
    /// act-time gate ([`open_and_check_key`]) then accepts a key whose live facts are exactly the
    /// recorded ones adjusted by the effects on that key: both counts exactly the recorded counts less
    /// the own removals, link state and owner equal, the last write time equal or (only when an own op
    /// wrote the key) between the recorded one and the latest noted time. A `DeleteValue` of a value an
    /// own `EditSegment` rewrote is bound to the recorded type and the data that edit wrote. Anything
    /// else is still [`reason::KEY_CHANGED`] / `VALUE_CHANGED`: a value or subkey added or removed by
    /// someone else, a key replaced or written after the own ops were noted, a key that became a link,
    /// another owner. Outcomes other than `Done` note nothing (a vanished item, a failed or partial
    /// delete): what changed then is not this run's doing, and the key is refused as changed.
    ///
    /// These counts and times cannot tell an outside change from an own one when both touch the same key
    /// (an outside value added and an own value deleted keep the count). The content is bound separately:
    /// each noted effect also records exactly what it changed (the value deleted, with its type and data
    /// hash; the data an edit replaced and wrote; the subkey deleted, with the tree digest its own act
    /// was bound to), and [`bind_tree`] puts these back into the tree a key action captured and compares
    /// it with the digest its validation journalled (review M2 final S4, S5).
    ///
    /// The effects come from journal records only (the intent's op, `pre` and inverse, the done's
    /// outcome, the deleted key's `validated` record), so a resumed run rebuilds them with
    /// [`GateCtx::note_journal`].
    pub fn note_done(&mut self, op: &OpState) {
        if self.effects.contains_key(&op.op) {
            return;
        }
        let (Some(intent), Some(ItemOutcome::Done)) = (&op.intent, &op.outcome) else {
            return;
        };
        if intent.op != op.op {
            return;
        }
        let validated = self.validated.get(&op.op).map(|recorded| &recorded.stamp);
        if let Some(effect) = own_effect(intent, validated, &self.deny, filetime_now()) {
            self.effects.insert(op.op, effect);
        }
    }

    /// [`GateCtx::note_done`] for every op of `state`: how a resumed run (and a run whose journal was
    /// written by someone else meanwhile, such as recovery ending an open intent) learns what its own
    /// earlier ops did. Ops already noted keep their effect.
    pub fn note_journal(&mut self, state: &JournalState) {
        for op in state.ops() {
            self.note_done(op);
        }
    }

    /// The op id `op` has in the run ([`GateCtx::set_run_ops`]), when it is in the run.
    fn run_op_id(&self, op: &ExecOp) -> Option<OpId> {
        self.run_ops
            .iter()
            .find(|run_op| run_op.exec_op == *op)
            .map(|run_op| run_op.op)
    }

    /// What this run's own completed ops explain about the key at `key`.
    fn own_changes(&self, key: &KeyAddress) -> OwnChanges {
        self.effects
            .values()
            .filter(|effect| effect.key.is_same(key))
            .fold(OwnChanges::default(), |sum, effect| OwnChanges {
                values: sum.values.saturating_add(effect.values),
                subkeys: sum.subkeys.saturating_add(effect.subkeys),
                touched_until: Some(
                    sum.touched_until
                        .map_or(effect.noted_at, |t| t.max(effect.noted_at)),
                ),
            })
    }

    /// The hash of the data the last own segment edit (by op id: run order) wrote into value `name` of
    /// the key at `key`, if one did.
    fn own_rewrite(&self, key: &KeyAddress, name: &str) -> Option<[u8; 32]> {
        self.effects
            .values()
            .filter(|effect| effect.key.is_same(key))
            .filter_map(|effect| effect.rewritten.as_ref())
            .filter(|(value, _)| prefix::eq_ci(value, name))
            .map(|(_, hash)| *hash)
            .next_back()
    }

    /// Whether every value and every direct subkey of `key` (at `addr`, with the counts `info`) is the
    /// target of an op of this run before op `before` that removes it whole. Any read that fails, or a
    /// listing whose length is not the count, answers no.
    fn emptied_by_earlier_ops(
        &self,
        key: &WKey,
        addr: &KeyAddress,
        info: &WKeyInfo,
        before: OpId,
    ) -> bool {
        let (Ok(values), Ok(subkeys)) = (key.values(), key.subkey_names()) else {
            return false;
        };
        if u32::try_from(values.len()).ok() != Some(info.n_values)
            || u32::try_from(subkeys.len()).ok() != Some(info.n_subkeys)
        {
            return false;
        }
        let earlier = || self.run_ops.iter().filter(move |run_op| run_op.op < before);
        let value_removed = |value: &RegValue| {
            earlier().any(|run_op| {
                matches!(&run_op.exec_op, ExecOp::DeleteValue { name, .. } if prefix::eq_ci(name, &value.name))
                    && run_op.key.as_ref().is_some_and(|k| k.is_same(addr))
            })
        };
        let subkey_removed = |name: &String| {
            let child = KeyAddress {
                root: addr.root,
                view: addr.view,
                path: format!(r"{}\{name}", addr.path),
            };
            earlier().any(|run_op| {
                matches!(
                    run_op.exec_op,
                    ExecOp::DeleteKeyTree { .. } | ExecOp::DeleteKeyIfEmpty { .. }
                ) && run_op.key.as_ref().is_some_and(|k| k.is_same(&child))
            })
        };
        values.iter().all(value_removed) && subkeys.iter().all(subkey_removed)
    }

    /// The deny-list.
    pub fn deny(&self) -> &DenyList {
        &self.deny
    }

    /// The paths this run removes whole.
    pub fn removed_whole(&self) -> &[String] {
        &self.removed_whole
    }

    /// This session's store directories.
    pub fn scope(&self) -> &StoreScope {
        &self.scope
    }

    /// Records the journal's `validated` record of `op`, the only source of the stamp and the exemptions
    /// the act-time gate ([`open_and_check_path`], [`open_and_check_key`]) uses for `validated.op`. Call it
    /// once the record is written (a fresh run: from [`Validation::to_journal`]) or read back (a resumed
    /// run). `max_files` is the item's blast-radius limit ([`GateItem::max_files`]; not journalled).
    ///
    /// Refused, recording nothing: `op` acts on another target than the record
    /// ([`reason::VALIDATION_MISMATCH`]), the op id already has a record (the same), or the facts do not
    /// fit the op ([`reason::STAMP_KIND`]). A record of an absent item ([`ItemFacts::Absent`]) or of an
    /// item the validate pass refused ([`ItemFacts::Refused`]) is accepted and records nothing: there is
    /// nothing to act on, and the act-time gate refuses the id.
    pub fn record(
        &mut self,
        op: &ExecOp,
        validated: &Validated,
        max_files: u32,
    ) -> Result<(), Refusal> {
        if self.validated.contains_key(&validated.op) || op.target() != validated.target {
            return Err(rule(reason::VALIDATION_MISMATCH));
        }
        let Some(stamp) = Stamp::from_item_facts(&validated.facts) else {
            return Ok(());
        };
        if !stamp.fits(op) {
            return Err(rule(reason::STAMP_KIND));
        }
        self.validated.insert(
            validated.op,
            Recorded {
                op: op.clone(),
                record: validated.clone(),
                stamp,
                exemptions: self
                    .gone
                    .apply(exemptions_from_journal(&validated.exemptions)),
                max_files,
            },
        );
        Ok(())
    }

    /// The stamp recorded for `op`.
    pub fn stamp(&self, op: OpId) -> Option<&Stamp> {
        self.validated.get(&op).map(|recorded| &recorded.stamp)
    }

    /// The exemptions recorded for `op`: those of its journal `validated` record, with the run's M1b
    /// exemption lists ([`GateCtx::set_gone`]).
    pub fn exemptions(&self, op: OpId) -> Option<Exemptions<'static>> {
        self.validated.get(&op).map(|recorded| recorded.exemptions)
    }

    /// The op and the journal `validated` record [`GateCtx::record`] accepted for `op`: what the actions
    /// build their intents from (plan item, recorded facts), so that an act is never prepared from facts
    /// other than the journalled ones. `None` for an op id without a record.
    pub fn journalled(&self, op: OpId) -> Option<(&ExecOp, &Validated)> {
        self.validated
            .get(&op)
            .map(|recorded| (&recorded.op, &recorded.record))
    }

    /// The record of `op`, or the refusal for an op id that has none.
    fn recorded(&self, op: OpId) -> Result<&Recorded, Refusal> {
        self.validated
            .get(&op)
            .ok_or_else(|| rule(reason::NOT_VALIDATED))
    }
}

/// The plan-time exemptions of a candidate: [`purge_plan::decide::deny_exemptions`], the derivation the
/// plan's decide step uses, with the machine layout of `deny` (`DenyList::env`). `user_sid` and
/// `long_names_resolved` must be the values of the scan that produced the plan. `mode` is not consulted
/// (the derivation does not depend on the scan mode); it stays for source compatibility.
pub fn exemptions_for(
    candidate: &Candidate,
    deny: &DenyList,
    _mode: ScanMode,
    user_sid: Option<&str>,
    long_names_resolved: bool,
) -> Exemptions<'static> {
    purge_plan::decide::deny_exemptions(candidate, deny.env(), user_sid, long_names_resolved)
}

/// The journal form of the exemptions a verdict was given ([`Validation::exemptions`]), for the
/// `validated` record's `exemptions` field. Every field is carried over unchanged;
/// [`exemptions_from_journal`] is the exact inverse.
pub fn exemptions_to_journal(exemptions: &Exemptions<'_>) -> GateExemptions {
    // Destructured without `..`, so a field added to either type fails to compile here. The three M1b
    // gone lists are the run's, not the item's: they are journalled once, in the run's `settings`
    // record (`RunSettings::gone_*`), and `GateCtx::set_gone` applies them to every record.
    let Exemptions {
        proven_owned_skeleton,
        environment_segment_edit,
        tier_a_start_menu_entry,
        long_names_resolved,
        shared_com_value,
        gone_burn: _,
        gone_msi_products: _,
        gone_cache_dirs: _,
    } = *exemptions;
    GateExemptions {
        proven_owned_skeleton,
        environment_segment_edit,
        tier_a_start_menu_entry,
        long_names_resolved,
        shared_com_value,
    }
}

/// The exemptions a journal `validated` record holds, as the gate takes them: what undo and recovery
/// pass to [`check_undo_path`] and [`check_undo_key`], and what [`GateCtx::record`] keeps for the
/// act-time gate, instead of deriving them again from the scan. The exact inverse of
/// [`exemptions_to_journal`].
pub fn exemptions_from_journal(exemptions: &GateExemptions) -> Exemptions<'static> {
    let GateExemptions {
        proven_owned_skeleton,
        environment_segment_edit,
        tier_a_start_menu_entry,
        long_names_resolved,
        shared_com_value,
    } = *exemptions;
    Exemptions {
        proven_owned_skeleton,
        environment_segment_edit,
        tier_a_start_menu_entry,
        long_names_resolved,
        shared_com_value,
        // The run's lists, journalled in its `settings` record: `GateCtx::set_gone` fills them in.
        gone_burn: &[],
        gone_msi_products: &[],
        gone_cache_dirs: &[],
    }
}

// ---------------------------------------------------------------------------------------------------
// Items and stamps
// ---------------------------------------------------------------------------------------------------

/// One item as the validate pass sees it. The act-time gate does not take one: it rebuilds the item
/// from the op's journal record ([`GateCtx::record`]).
#[derive(Debug, Clone, Copy)]
pub struct GateItem<'a> {
    /// What the executor does with the item.
    pub op: &'a ExecOp,
    /// The candidate's exemptions ([`exemptions_for`]). The validation hands them back for the journal
    /// ([`Validation::exemptions`]).
    pub exemptions: Exemptions<'static>,
    /// The most files, and separately the most directories, the tree below a directory moved whole may
    /// hold; more is refused with [`Blocker::TooLarge`]. The plan's limit: 5,000, or 50,000 for a
    /// manifest-backed install root.
    pub max_files: u32,
    /// The most keys the tree of a key delete may hold, the run's key limit (`RunSettings::key_limit`)
    /// that the act's backup capture applies too; more is refused with [`Blocker::TooLarge`]. The
    /// validate pass reads the tree with it (F6 of the M2 fix-round review: it used `max_files`).
    pub max_keys: usize,
    /// The identity the scan read for the item (the candidate's `item_fp`), when it has one. For a
    /// file-system op the validate pass compares it with the file id and volume serial read from the
    /// handle its facts come from; any difference, or a volume serial of 0 on either side, is refused
    /// with [`reason::SCAN_IDENTITY`] (soft: changed since the scan). `None`: no comparison, the validate
    /// pass alone applies. Not consulted for any other op, and not by the act-time gate, which is bound
    /// to the validated stamp.
    pub scan_identity: Option<ItemFp>,
}

impl<'a> GateItem<'a> {
    /// An item with the default blast-radius limit (`purge_plan::decide::Limits::default().max_files`),
    /// the default key limit ([`regbackup::DEFAULT_KEY_LIMIT`]) and no scan-time identity.
    pub fn new(op: &'a ExecOp, exemptions: Exemptions<'static>) -> GateItem<'a> {
        GateItem {
            op,
            exemptions,
            max_files: purge_plan::decide::Limits::default().max_files,
            max_keys: regbackup::DEFAULT_KEY_LIMIT,
            scan_identity: None,
        }
    }

    /// The item with the key limit `max_keys` ([`GateItem::max_keys`]).
    #[must_use]
    pub fn with_key_limit(self, max_keys: usize) -> GateItem<'a> {
        GateItem { max_keys, ..self }
    }

    /// The item with the scan-time identity `scan_identity` ([`GateItem::scan_identity`]).
    #[must_use]
    pub fn with_scan_identity(self, scan_identity: Option<ItemFp>) -> GateItem<'a> {
        GateItem {
            scan_identity,
            ..self
        }
    }
}

/// The refusal of a file-system item whose identity, read from the validated handle, is not the one the
/// scan recorded (`expected`). `None` when there is no scan-time identity, or when both the file id and
/// the volume serial are equal and neither serial is 0. An identity that could not be read is refused
/// too (the guard refuses such facts first).
fn scan_identity_refusal(expected: Option<&ItemFp>, read: Option<FileIdentity>) -> Option<Refusal> {
    let expected = expected?;
    let same = read.is_some_and(|read| {
        expected.volume_serial != 0
            && read.volume_serial != 0
            && expected.matches(&FileIdHex(read.file_id), read.volume_serial)
    });
    (!same).then_some(Refusal {
        blocker: Blocker::ChangedSinceScan,
        reason: reason::SCAN_IDENTITY,
    })
}

/// What the validate pass binds an item to, and the act re-checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Stamp {
    /// A file or directory: identity and kind.
    Path(PathStamp),
    /// A key action. A key has no identity Windows reports, so the act is bound to every fact the
    /// journal records about it: subkey and value counts, link state, owner and last write time. Any
    /// change to the key's values or direct subkeys moves its last write time, and so does re-creating
    /// it. A difference is [`reason::KEY_CHANGED`].
    Key(RegFacts),
    /// A value or segment action: type, length and hash of the raw data.
    Value(ValueStamp),
    /// A package removal (no live facts).
    Package,
    /// A service, scheduled task or firewall rule (M1b): its kind and identity digest
    /// ([`ObjectFp`], C-OBJECT). The act-time gate of the object's act module re-reads the identity and
    /// requires the same kind and digest ([`check_object_stamp`]).
    Object {
        /// The kind of object.
        kind: ObjectKind,
        /// The identity digest as validated, 64 lower-case hex digits.
        sha256: String,
    },
}

impl Stamp {
    /// The stamp a journal `validated` record stands for. `None` for [`ItemFacts::Absent`] and
    /// [`ItemFacts::Refused`], which bind nothing.
    pub fn from_item_facts(facts: &ItemFacts) -> Option<Stamp> {
        Some(match facts {
            ItemFacts::File(file) => Stamp::Path(PathStamp {
                identity: FileIdentity {
                    volume_serial: file.volume_serial,
                    file_id: file.file_id.0,
                },
                is_dir: file.is_dir,
            }),
            ItemFacts::Key(key) => Stamp::Key(key.clone()),
            ItemFacts::Value(value) => Stamp::Value(ValueStamp {
                ty: value.value_type,
                len: u64::from(value.size),
                sha256: value.data_sha256.0,
            }),
            ItemFacts::Package => Stamp::Package,
            ItemFacts::Absent | ItemFacts::Refused { .. } => return None,
            // A running object is never acted on (nothing is stopped), and a digest in another
            // spelling matches no object: such a record binds nothing, so the act-time gate refuses
            // the op.
            ItemFacts::Object {
                kind,
                sha256,
                running,
            } => {
                if *running || !is_object_digest(sha256) {
                    return None;
                }
                Stamp::Object {
                    kind: *kind,
                    sha256: sha256.clone(),
                }
            }
        })
    }

    /// Whether the stamp is of the kind `op` is validated with.
    fn fits(&self, op: &ExecOp) -> bool {
        matches!(
            (op, self),
            (
                ExecOp::QuarantineMove { .. } | ExecOp::RemoveDirIfEmpty { .. },
                Stamp::Path(_)
            ) | (
                ExecOp::DeleteKeyTree { .. } | ExecOp::DeleteKeyIfEmpty { .. },
                Stamp::Key(_)
            ) | (
                ExecOp::DeleteValue { .. } | ExecOp::EditSegment { .. },
                Stamp::Value(_)
            ) | (ExecOp::RemovePackage { .. }, Stamp::Package)
        ) || matches!(self, Stamp::Object { kind, .. } if op.object_kind() == Some(*kind))
    }
}

/// Whether `s` is an object digest as C-OBJECT spells it: 64 lower-case hex digits.
fn is_object_digest(s: &str) -> bool {
    ObjectFp {
        kind: ObjectKind::Service,
        sha256: s.to_owned(),
    }
    .is_well_formed()
}

/// The one root check of the object ops (M1b review R2b B1, M5): whether `file`, a program path already
/// resolved to one canonical absolute file by the op's own rules, lies strictly inside one of `roots`,
/// the program roots of the journal header (`Header::program_roots`). Each root is canonicalised with
/// `env` (per-user tokens with `user_sid`); a root that does not canonicalise, needs 8.3 resolution,
/// steps back or is a drive root counts for nothing, so no roots at all means outside. A `file` that
/// steps back or needs 8.3 resolution is outside too.
///
/// The service, task and firewall modules apply exactly this before a delete (prepare and the act-time
/// gate) and before a re-create (undo), so a delete never runs whose undo is certain to refuse with
/// `UndoConflict::ProgramOutsideRoot`.
pub fn file_in_roots(
    file: &str,
    roots: &[String],
    env: &purge_guard::canon::GuardEnv,
    user_sid: Option<&str>,
) -> bool {
    if file.trim().is_empty() || prefix::steps_back(file) {
        return false;
    }
    let Ok(file) = purge_guard::canon::canon_path(file, env, user_sid) else {
        return false;
    };
    if file.needs_long_name {
        return false;
    }
    roots.iter().any(|root| {
        let root = root.trim();
        let root = root
            .strip_prefix('"')
            .and_then(|r| r.strip_suffix('"'))
            .unwrap_or(root)
            .trim();
        !root.is_empty()
            && !prefix::steps_back(root)
            && purge_guard::canon::canon_path(root, env, user_sid).is_ok_and(|root| {
                !root.needs_long_name
                    && prefix::depth(&root.path) >= 2
                    && prefix::is_inside(&file.path, &root.path)
            })
    })
}

/// The act-time check of an object: `live` is the fingerprint of the identity the act module has just
/// read, `validated` the stamp the journal's `validated` record gave the op ([`GateCtx::stamp`]).
///
/// `Ok` only when `validated` is a [`Stamp::Object`] and `live` is `Some` with the same kind and the same
/// digest (64 lower-case hex digits). An object that is gone (`None`) is the caller's `Vanished`, decided
/// before this check; here it is refused like every other difference, with
/// [`SkipReason::ChangedSinceScan`]. Nothing is changed on a refusal.
pub fn check_object_stamp(validated: &Stamp, live: Option<&ObjectFp>) -> Result<(), SkipReason> {
    check_object_stamp_detailed(validated, live).map_err(|(reason, _)| reason)
}

/// [`check_object_stamp`], with the detail for the journal's `done` record.
pub fn check_object_stamp_detailed(
    validated: &Stamp,
    live: Option<&ObjectFp>,
) -> Result<(), (SkipReason, &'static str)> {
    let changed = |detail| Err((SkipReason::ChangedSinceScan, detail));
    let Stamp::Object { kind, sha256 } = validated else {
        return changed(reason::OBJECT_NOT_VALIDATED);
    };
    let Some(live) = live else {
        return changed(reason::OBJECT_GONE);
    };
    if live.kind != *kind {
        return changed(reason::OBJECT_KIND);
    }
    if !is_object_digest(sha256) || !live.is_well_formed() || live.sha256 != *sha256 {
        return changed(reason::OBJECT_CHANGED);
    }
    Ok(())
}

/// The validate-time check of an object against the plan: `live` is the fingerprint of the identity
/// the act module has just read, `cand` the plan item. `Ok` only when the candidate carries an object
/// fingerprint ([`Candidate::object_fp`]) of 64 lower-case hex digits, of the kind of its target and
/// of `live`'s kind, with `live`'s digest. A candidate without one is refused with
/// [`SkipReason::ChangedSinceScan`] and the detail [`reason::NO_OBJECT_FP`] (`resolve` already refuses
/// such an item; this is the second lock); every other difference is `ChangedSinceScan` too.
pub fn check_plan_fp(cand: &Candidate, live: &ObjectFp) -> Result<(), SkipReason> {
    check_plan_fp_detailed(cand, live).map_err(|(reason, _)| reason)
}

/// [`check_plan_fp`], with the detail for the journal's `done` record.
pub fn check_plan_fp_detailed(
    cand: &Candidate,
    live: &ObjectFp,
) -> Result<(), (SkipReason, &'static str)> {
    let changed = |detail| Err((SkipReason::ChangedSinceScan, detail));
    let Some(planned) = &cand.object_fp else {
        return changed(reason::NO_OBJECT_FP);
    };
    if !planned.is_well_formed() {
        return changed(reason::NO_OBJECT_FP);
    }
    if ObjectKind::of(&cand.target) != Some(planned.kind) || planned.kind != live.kind {
        return changed(reason::OBJECT_KIND);
    }
    if !live.is_well_formed() || live.sha256 != planned.sha256 {
        return changed(reason::OBJECT_CHANGED);
    }
    Ok(())
}

/// The result of the validate pass for one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validation {
    /// What the act is bound to.
    pub stamp: Stamp,
    /// The journal form of the facts.
    pub facts: ItemFacts,
    /// The exemptions the verdict was given ([`GateItem::exemptions`]), for the journal. The act is gated
    /// with the ones of the journal record ([`GateCtx::record`]).
    pub exemptions: Exemptions<'static>,
}

impl Validation {
    /// The journal `validated` record of this validation: its facts and exemptions, for op `op` of plan
    /// item `item` acting on `target` (the op's [`ExecOp::target`]). Write it, then hand the same record
    /// to [`GateCtx::record`].
    pub fn to_journal(&self, op: OpId, item: CandidateId, target: Target) -> Validated {
        Validated {
            op,
            item,
            target,
            facts: self.facts.clone(),
            exemptions: exemptions_to_journal(&self.exemptions),
        }
    }
}

impl GateOutcome<Validation> {
    /// The facts for the journal's `validated` record: the facts of a pass, [`ItemFacts::Absent`] for a
    /// vanished item, `None` otherwise.
    pub fn item_facts(&self) -> Option<ItemFacts> {
        match self {
            GateOutcome::Pass(validation) => Some(validation.facts.clone()),
            GateOutcome::Vanished => Some(ItemFacts::Absent),
            _ => None,
        }
    }
}

/// The validate pass for one item: read-only handles, [`Binding::Capture`]. The item's op id is the one
/// the run gives its op ([`GateCtx::set_run_ops`]; the first op equal to it), which decides which ops
/// of the run come before it; [`validate_all`] passes the op ids it is given instead.
pub fn validate(ctx: &GateCtx, item: &GateItem<'_>) -> GateOutcome<Validation> {
    validate_as(ctx, item, ctx.run_op_id(item.op))
}

/// [`validate`] for the item of op `op` (`None`: an item outside the run, before which no op of the run
/// counts).
fn validate_as(ctx: &GateCtx, item: &GateItem<'_>, op: Option<OpId>) -> GateOutcome<Validation> {
    match item.op {
        ExecOp::QuarantineMove { .. } | ExecOp::RemoveDirIfEmpty { .. } => match op_path(item) {
            Ok((path, op)) => validate_path(ctx, path, op, item).map(|(stamp, facts)| Validation {
                stamp: Stamp::Path(stamp),
                facts: ItemFacts::File(facts),
                exemptions: item.exemptions,
            }),
            Err(refusal) => GateOutcome::Refused(refusal),
        },
        ExecOp::DeleteKeyTree { .. }
        | ExecOp::DeleteKeyIfEmpty { .. }
        | ExecOp::DeleteValue { .. }
        | ExecOp::EditSegment { .. } => validate_key(ctx, item, op),
        // Packages are not locations: the guard has no live rule for them.
        ExecOp::RemovePackage { .. } => GateOutcome::Pass(Validation {
            stamp: Stamp::Package,
            facts: ItemFacts::Package,
            exemptions: item.exemptions,
        }),
        // An object op is validated by its action module (`act_service::validate`,
        // `act_task::validate_task`, `act_firewall::validate`), which the run calls with the object
        // backends; never by the location gate.
        ExecOp::DeleteService { .. }
        | ExecOp::DeleteTask { .. }
        | ExecOp::DeleteFirewallRule { .. } => GateOutcome::Refused(rule(reason::OP_KIND)),
    }
}

/// The validate pass over every selected item, in the order given. Records nothing: the caller writes
/// one journal `validated` record per item (from [`Validation::to_journal`], or with
/// [`GateOutcome::item_facts`]) and hands each written record to [`GateCtx::record`], so that the act
/// is gated with exactly what was journalled. Each item is validated as the op id it comes with (see
/// [`GateCtx::set_run_ops`] for what the ops before it change).
pub fn validate_all<'a>(
    ctx: &GateCtx,
    items: impl IntoIterator<Item = (OpId, GateItem<'a>)>,
) -> Vec<(OpId, GateOutcome<Validation>)> {
    items
        .into_iter()
        .map(|(op, item)| (op, validate_as(ctx, &item, Some(op))))
        .collect()
}

fn path_op(op: &ExecOp) -> Option<PathOp> {
    match op {
        ExecOp::QuarantineMove { .. } => Some(PathOp::QuarantineMove),
        ExecOp::RemoveDirIfEmpty { .. } => Some(PathOp::RemoveDirIfEmpty),
        _ => None,
    }
}

fn key_op(op: &ExecOp) -> Option<KeyOp> {
    match op {
        ExecOp::DeleteKeyTree { .. } => Some(KeyOp::DeleteKeyTree),
        ExecOp::DeleteKeyIfEmpty { .. } => Some(KeyOp::DeleteKeyIfEmpty),
        ExecOp::DeleteValue { .. } => Some(KeyOp::DeleteValue),
        ExecOp::EditSegment { .. } => Some(KeyOp::EditSegment),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------------
// Files and directories
// ---------------------------------------------------------------------------------------------------

/// `path` with a `\\?\` prefix removed when a drive path follows it (the form the guard and the journal
/// use). Anything else is returned unchanged.
fn strip_verbatim(path: &str) -> &str {
    match path.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest,
        _ => path,
    }
}

/// The `\\?\` form of an absolute path, or `None` for a path that has none.
fn ext(path: &str) -> Option<PathBuf> {
    extended_path(Path::new(path)).ok()
}

/// The full paths of every name of the file at `path`, with the volume's mount path put in front.
fn link_names(path: &str) -> Option<Vec<String>> {
    let p = ext(path)?;
    let root = volume_info(&p).ok()?.root;
    let root = strip_verbatim(&root).trim_end_matches('\\').to_owned();
    let names = ffi::file_names(&p).ok()?;
    Some(
        names
            .into_iter()
            .map(|name| format!("{root}{name}"))
            .collect(),
    )
}

/// Whether every name of the file at `path` (plain form, `n_links` names, the object `identity`) lies
/// inside the plan (G6): a path this run removes whole or below one, or a name strictly inside one of
/// this session's quarantine directories ([`StoreScope::quarantine_dirs`]) where an earlier op of the
/// session moved the file's other name. Such a quarantine name counts only when it opens, without
/// following a final reparse point, to a file with `identity` whose final path is that name: the path
/// prefix alone proves nothing. `None` when the names cannot be listed.
fn links_inside(ctx: &GateCtx, path: &str, n_links: u32, identity: FileIdentity) -> Option<bool> {
    let names = link_names(path)?;
    let quarantined: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|name| quarantined_link(ctx, name, identity))
        .collect();
    let inside: Vec<&str> = ctx
        .removed_whole
        .iter()
        .map(String::as_str)
        .chain(quarantined)
        .collect();
    Some(live::links_inside_plan(&names, n_links, &inside))
}

/// Whether `name` lies strictly inside one of this session's quarantine directories and is the file
/// `identity` (a plain file, its final path `name`).
fn quarantined_link(ctx: &GateCtx, name: &str, identity: FileIdentity) -> bool {
    let in_quarantine = ctx
        .scope
        .quarantine_dirs()
        .iter()
        .any(|dir| prefix::is_inside(name, dir));
    in_quarantine
        && ext(name)
            .and_then(|p| FileHandle::open(&p).ok())
            .is_some_and(|handle| {
                let same_file = handle.metadata().is_ok_and(|m| {
                    !m.is_dir
                        && m.reparse_tag == 0
                        && m.file_id.volume_serial == identity.volume_serial
                        && m.file_id.id == identity.file_id
                });
                same_file
                    && handle
                        .final_path()
                        .is_ok_and(|at| prefix::is_same(strip_verbatim(&at), name))
            })
}

/// What a walk below a directory moved whole found.
#[derive(Debug, Clone, Default)]
struct Walk {
    facts: TreeFacts,
    entries: u64,
    bytes: u64,
}

fn too_large() -> Refusal {
    Refusal {
        blocker: Blocker::TooLarge,
        reason: reason::BLAST_RADIUS,
    }
}

/// Whether the directory at `dir` (plain form) is the plain directory its path names, and, for the root,
/// the object the acting handle is on.
fn plain_dir(dir: &str, identity: Option<FileIdentity>) -> Option<PathBuf> {
    let p = ext(dir)?;
    let handle = FileHandle::open(&p).ok()?;
    let meta = handle.metadata().ok()?;
    let final_path = handle.final_path().ok()?;
    let same_object = identity.is_none_or(|id| {
        meta.file_id.volume_serial == id.volume_serial && meta.file_id.id == id.file_id
    });
    (meta.is_dir
        && meta.reparse_tag == 0
        && same_object
        && prefix::is_same(strip_verbatim(&final_path), dir))
    .then_some(p)
}

/// The bounded walk below a directory that is moved whole (G6, G7, blast radius). Never descends into a
/// reparse point; opens every non-directory entry without following it to read its link count. Holds at
/// most `2 * max` listed entries of one directory at a time.
fn walk_tree(ctx: &GateCtx, root: &str, identity: FileIdentity, max: u32) -> Result<Walk, Refusal> {
    let max = u64::from(max);
    let mut walk = Walk {
        facts: TreeFacts {
            complete: true,
            ..TreeFacts::default()
        },
        ..Walk::default()
    };
    let (mut files, mut dirs) = (0u64, 0u64);
    let mut stack = vec![(root.to_owned(), Some(identity))];
    while let Some((dir, expect)) = stack.pop() {
        let Some(dir_ext) = plain_dir(&dir, expect) else {
            walk.facts.complete = false;
            continue;
        };
        // More than `2 * max` entries in all means more than `max` files or more than `max`
        // directories, so no listing is read past what is left of that budget (M5 of the wave 2
        // review: memory stays bounded by the limit, not by the largest directory).
        let budget = (2 * max).saturating_sub(files + dirs);
        let entries = match ffi::list_dir_capped(&dir_ext, budget) {
            Ok(Some(entries)) => entries,
            Ok(None) => return Err(too_large()),
            Err(_) => {
                walk.facts.complete = false;
                continue;
            }
        };
        for entry in entries {
            let child = format!(r"{}\{}", dir.trim_end_matches('\\'), entry.name);
            walk.entries += 1;
            if entry.attributes & PLACEHOLDER_ATTRIBUTES != 0
                || is_cloud_reparse_tag(entry.reparse_tag)
            {
                walk.facts.placeholders += 1;
            }
            if entry.is_dir() {
                dirs += 1;
                if dirs > max {
                    return Err(too_large());
                }
                if !entry.is_reparse_point() {
                    stack.push((child, None));
                }
                continue;
            }
            files += 1;
            walk.bytes = walk.bytes.saturating_add(entry.size);
            if files > max {
                return Err(too_large());
            }
            let links = ext(&child)
                .and_then(|p| FileHandle::open(&p).ok())
                .and_then(|h| h.metadata().ok())
                .map(|m| {
                    let identity = FileIdentity {
                        volume_serial: m.file_id.volume_serial,
                        file_id: m.file_id.id,
                    };
                    (m.n_links, identity)
                });
            match links {
                None => walk.facts.complete = false,
                Some((n, identity)) if n > 1 => {
                    let inside = links_inside(ctx, &child, n, identity) == Some(true);
                    if !inside {
                        walk.facts.hard_links_outside_plan += 1;
                    }
                }
                Some(_) => {}
            }
        }
    }
    Ok(walk)
}

/// What the gate read about a file-system item from one handle.
#[derive(Debug, Clone)]
struct PathSeen {
    facts: PathFacts,
    meta: Option<FileMeta>,
    walk: Option<Walk>,
}

/// Reads every fact [`live::check_path`] needs from `handle` (and `security`, read from the same handle).
/// Fails only with the blast-radius refusal of the walk.
fn collect_path(
    ctx: &GateCtx,
    lexical: &str,
    op: PathOp,
    handle: &FileHandle,
    security: Option<&Security>,
    max_files: u32,
) -> Result<PathSeen, Refusal> {
    let final_path = handle.final_path().ok();
    let meta = handle.metadata().ok();
    let identity = meta.as_ref().map(|m| FileIdentity {
        volume_serial: m.file_id.volume_serial,
        file_id: m.file_id.id,
    });
    let volume = match (&final_path, identity) {
        (Some(path), Some(id)) => ctx.host.volume(path, id.volume_serial),
        _ => None,
    };
    let security = ctx.host.file_security(security);
    let n_links = meta.as_ref().map(|m| m.n_links);
    let is_dir = meta.as_ref().map(|m| m.is_dir);
    let links_inside_plan = match (n_links, is_dir, final_path.as_deref(), identity) {
        (Some(n), Some(false), Some(path), Some(id)) if n > 1 => {
            links_inside(ctx, strip_verbatim(path), n, id)
        }
        (Some(n), ..) if n > 1 => None,
        (Some(_), ..) => Some(true),
        (None, ..) => None,
    };

    // The walk runs only below the plain directory the plan names; anything else is refused before the
    // tree matters.
    let walk = match (&meta, identity, final_path.as_deref()) {
        (Some(m), Some(id), Some(path))
            if op == PathOp::QuarantineMove
                && m.is_dir
                && m.reparse_tag == 0
                && !m.is_reparse_point()
                && prefix::is_same(strip_verbatim(path), lexical) =>
        {
            Some(walk_tree(ctx, strip_verbatim(path), id, max_files)?)
        }
        _ => None,
    };

    let facts = PathFacts {
        final_path,
        reparse_tag: meta.as_ref().map(|m| m.reparse_tag),
        attributes: meta.as_ref().map(|m| m.attributes),
        identity,
        n_links,
        is_dir,
        volume,
        owner_is_ti: security.owner_is_ti,
        explicit_ti_ace: security.ti_ace,
        links_inside_plan,
        tree: walk.as_ref().map(|w| w.facts.clone()),
    };
    Ok(PathSeen { facts, meta, walk })
}

/// The journal form of facts that passed the gate. `None` if a field is missing (the guard refuses such
/// facts first).
fn file_facts(seen: &PathSeen) -> Option<FileFacts> {
    let facts = &seen.facts;
    let meta = seen.meta.as_ref()?;
    let identity = facts.identity?;
    Some(FileFacts {
        final_path: strip_verbatim(facts.final_path.as_deref()?).to_owned(),
        file_id: FileIdHex(identity.file_id),
        volume_serial: identity.volume_serial,
        reparse_tag: meta.reparse_tag,
        attributes: meta.attributes,
        n_links: meta.n_links,
        is_dir: meta.is_dir,
        size: if meta.is_dir { 0 } else { meta.size },
        tree_entries: seen.walk.as_ref().map(|w| w.entries),
        tree_bytes: seen.walk.as_ref().map(|w| w.bytes),
    })
}

/// Opens `path` read-only for facts: with `READ_CONTROL` when the object grants it, else without (then no
/// security facts).
fn open_read_only(path: &Path) -> Result<(FileHandle, Option<Security>), Win32Error> {
    match open_for_security(path) {
        Ok(handle) => {
            let security = handle_security(&handle).ok();
            Ok((handle, security))
        }
        Err(Win32Error::ACCESS_DENIED) => Ok((FileHandle::open(path)?, None)),
        Err(e) => Err(e),
    }
}

/// The path of a file-system op, or the refusal for an op that is not one.
fn op_path<'a>(item: &GateItem<'a>) -> Result<(&'a str, PathOp), Refusal> {
    match (item.op, path_op(item.op)) {
        (ExecOp::QuarantineMove { path } | ExecOp::RemoveDirIfEmpty { path }, Some(op)) => {
            Ok((path.as_str(), op))
        }
        _ => Err(rule(reason::OP_KIND)),
    }
}

fn validate_path(
    ctx: &GateCtx,
    path: &str,
    op: PathOp,
    item: &GateItem<'_>,
) -> GateOutcome<(PathStamp, FileFacts)> {
    let Some(p) = ext(path) else {
        return GateOutcome::Refused(rule(reason::PATH_FORM));
    };
    let (handle, security) = match open_read_only(&p) {
        Ok(opened) => opened,
        Err(e) if e.is_not_found() => return GateOutcome::Vanished,
        Err(e) => return GateOutcome::Failed(e),
    };
    let seen = match collect_path(ctx, path, op, &handle, security.as_ref(), item.max_files) {
        Ok(seen) => seen,
        Err(refusal) => return GateOutcome::Refused(refusal),
    };
    let check = PathCheck {
        lexical: path,
        op,
        binding: Binding::Capture,
        exemptions: item.exemptions,
    };
    if let Err(refusal) = live::check_path(&check, &seen.facts, &ctx.deny) {
        return GateOutcome::Refused(refusal);
    }
    // The scan-time identity is compared with the identity read from the same handle the facts above
    // come from; it can only narrow what passes (ENGINE_PLAN.md Appendix B, M2-3).
    if let Some(refusal) = scan_identity_refusal(item.scan_identity.as_ref(), seen.facts.identity) {
        return GateOutcome::Refused(refusal);
    }
    match (seen.facts.stamp(), file_facts(&seen)) {
        (Some(stamp), Some(facts)) => GateOutcome::Pass((stamp, facts)),
        _ => GateOutcome::Refused(rule(reason::FACTS_UNREADABLE)),
    }
}

/// A file or directory that passed the gate, with the handle to act on.
///
/// The handle was opened with `DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES` (and `READ_CONTROL`) without
/// following a final reparse point, and every fact in here was read from it. Perform the action on
/// [`CheckedPath::handle`]; never reopen the path.
#[derive(Debug)]
pub struct CheckedPath {
    path: String,
    handle: MoveHandle,
    facts: PathFacts,
    stamp: PathStamp,
    meta: FileMeta,
    security: Option<Security>,
    file_facts: FileFacts,
}

impl CheckedPath {
    /// The plan's (lexical) path of the item.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The handle the gate inspected; the action must use it.
    pub fn handle(&self) -> &MoveHandle {
        &self.handle
    }

    /// The facts the verdict was given.
    pub fn facts(&self) -> &PathFacts {
        &self.facts
    }

    /// The identity and kind of the item (equal to the validated stamp).
    pub fn stamp(&self) -> PathStamp {
        self.stamp
    }

    /// The item's metadata as read from the handle (attributes, times, size, link count).
    pub fn meta(&self) -> &FileMeta {
        &self.meta
    }

    /// The item's security descriptor (owner, group, DACL, SDDL) as read from the handle; always present
    /// on a pass.
    pub fn security(&self) -> Option<&Security> {
        self.security.as_ref()
    }

    /// The facts in journal form, for the intent's `pre` record.
    pub fn file_facts(&self) -> &FileFacts {
        &self.file_facts
    }

    /// The handle, giving up the rest.
    pub fn into_handle(self) -> MoveHandle {
        self.handle
    }
}

/// The act-time gate for the file-system item of op `op` (`QuarantineMove`, `RemoveDirIfEmpty`). The op,
/// its stamp, its exemptions and its blast-radius limit are those of its journal record
/// ([`GateCtx::record`]); an op id without one is refused ([`reason::NOT_VALIDATED`]). Opens the acting
/// handle first, reads every fact from it, and checks them against the recorded stamp
/// ([`Binding::Recheck`]). On a pass the open handle is returned for the action.
///
/// When the acting handle cannot be opened (sharing violation, access denied, ...) the item is looked at
/// through a read-only handle: a refusal is reported as `Refused`; otherwise a sharing violation is
/// `Locked` and any other error `Failed`.
pub fn open_and_check_path(ctx: &GateCtx, op: OpId) -> GateOutcome<CheckedPath> {
    let recorded = match ctx.recorded(op) {
        Ok(recorded) => recorded,
        Err(refusal) => return GateOutcome::Refused(refusal),
    };
    let item = &recorded.item();
    let (path, op) = match op_path(item) {
        Ok(found) => found,
        Err(refusal) => return GateOutcome::Refused(refusal),
    };
    let Stamp::Path(stamp) = &recorded.stamp else {
        return GateOutcome::Refused(rule(reason::STAMP_KIND));
    };
    let Some(p) = ext(path) else {
        return GateOutcome::Refused(rule(reason::PATH_FORM));
    };
    let check = PathCheck {
        lexical: path,
        op,
        binding: Binding::Recheck(stamp),
        exemptions: item.exemptions,
    };
    let handle = match MoveHandle::open(&p) {
        Ok(handle) => handle,
        Err(FsError::NotFound) => return GateOutcome::Vanished,
        Err(error) => return look_without_acting(ctx, &p, &check, error, item.max_files),
    };
    let security = if handle.has_read_control() {
        handle.security().ok()
    } else {
        None
    };
    let seen = match collect_path(
        ctx,
        path,
        op,
        handle.as_file(),
        security.as_ref(),
        item.max_files,
    ) {
        Ok(seen) => seen,
        Err(refusal) => return GateOutcome::Refused(refusal),
    };
    if let Err(refusal) = live::check_path(&check, &seen.facts, &ctx.deny) {
        return GateOutcome::Refused(refusal);
    }
    let file_facts = file_facts(&seen);
    match (seen.facts.stamp(), seen.meta, file_facts) {
        (Some(now), Some(meta), Some(file_facts)) if security.is_some() => {
            GateOutcome::Pass(CheckedPath {
                path: path.to_owned(),
                handle,
                facts: seen.facts,
                stamp: now,
                meta,
                security,
                file_facts,
            })
        }
        _ => GateOutcome::Refused(rule(reason::FACTS_UNREADABLE)),
    }
}

/// The acting handle could not be opened: decide from a read-only handle what to report.
fn look_without_acting<T>(
    ctx: &GateCtx,
    p: &Path,
    check: &PathCheck<'_>,
    fs_error: FsError,
    max_files: u32,
) -> GateOutcome<T> {
    let error = Win32Error(fs_error.code());
    let (handle, security) = match open_read_only(p) {
        Ok(opened) => opened,
        Err(e) if e.is_not_found() => return GateOutcome::Vanished,
        Err(_) => return GateOutcome::Failed(error),
    };
    let seen = match collect_path(
        ctx,
        check.lexical,
        check.op,
        &handle,
        security.as_ref(),
        max_files,
    ) {
        Ok(seen) => seen,
        Err(refusal) => return GateOutcome::Refused(refusal),
    };
    if let Err(refusal) = live::check_path(check, &seen.facts, &ctx.deny) {
        return GateOutcome::Refused(refusal);
    }
    match seen.facts.stamp() {
        Some(stamp) if may_be_in_use(fs_error, stamp.is_dir) => GateOutcome::Locked(LockedPath {
            facts: seen.facts,
            stamp,
            error,
        }),
        _ => GateOutcome::Failed(error),
    }
}

/// **The one place** that decides whether an open error on the acting handle may mean "in use" (for the
/// locked-file ladder) rather than a final failure: a sharing or lock violation always; access denied on
/// a directory too, because a directory with an open handle anywhere below it can refuse with access
/// denied; and [`FsError::DirInUseOrDenied`], which `MoveHandle::rename_into` reports for exactly that
/// case on a directory. An open of the acting handle reports plain [`FsError::AccessDenied`], so that
/// variant still counts for a directory.
pub(crate) fn may_be_in_use(error: FsError, is_dir: bool) -> bool {
    match error {
        FsError::SharingViolation | FsError::DirInUseOrDenied => true,
        FsError::AccessDenied => is_dir,
        _ => false,
    }
}

// ---------------------------------------------------------------------------------------------------
// Destinations and the session's own store
// ---------------------------------------------------------------------------------------------------

/// A checked destination of a rename: the destination's parent directory, open as a
/// [`purge_win::fs_write::DestDir`] (no-follow), the leaf name, and the [`DestinationFacts`] the verdict
/// was given (read from that open directory handle). The one destination type the gate hands out.
///
/// Rename with `MoveHandle::rename_into(dest.dir(), dest.leaf())`, so the directory that was checked is
/// the one the item lands in, whatever happens to its path. There is no rename by path.
#[derive(Debug)]
pub struct CheckedDest {
    dir: DestDir,
    leaf: String,
    path: String,
    facts: DestinationFacts,
}

impl CheckedDest {
    /// The destination's parent directory, opened without following a reparse point
    /// (`FILE_READ_ATTRIBUTES | SYNCHRONIZE`); pass it to `MoveHandle::rename_into`.
    pub fn dir(&self) -> &DestDir {
        &self.dir
    }

    /// The facts of the destination, taken from [`CheckedDest::dir`].
    pub fn facts(&self) -> &DestinationFacts {
        &self.facts
    }

    /// The name the item gets inside [`CheckedDest::dir`].
    pub fn leaf(&self) -> &str {
        &self.leaf
    }

    /// The full destination path that was checked.
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Opens the parent directory of `destination` as a [`DestDir`] (without following a reparse point)
/// and reads the [`DestinationFacts`] from that handle ([`DestDir::facts`]). Whether the leaf is taken
/// is probed by path (there is no handle-relative open here) and counts only while the parent handle's
/// final path is the same before and after the probe. A rename into the handle never replaces
/// anything, so a name taken after the probe makes the rename fail, never overwrite.
fn destination_facts(destination: &str) -> Option<(DestDir, String, DestinationFacts)> {
    let target = Path::new(destination);
    let leaf = target.file_name()?.to_str()?.to_owned();
    let parent_ext = target.parent()?.to_str().and_then(ext)?;
    let dir = DestDir::open(&parent_ext).ok()?;
    let mut facts = DestinationFacts::default();
    if let Ok(dir_facts) = dir.facts() {
        facts.parent_reparse_tag = Some(dir_facts.reparse_tag);
        facts.parent_is_dir = Some(dir_facts.is_dir);
        facts.parent_volume_serial = Some(dir_facts.volume_serial());
        facts.parent_final_path = Some(dir_facts.final_path);
    }
    let occupied = match ext(destination).map(|p| FileHandle::open(&p)) {
        Some(Ok(_)) => Some(true),
        Some(Err(e)) if e.is_not_found() => Some(false),
        _ => None,
    };
    let unchanged = facts.parent_final_path.is_some()
        && dir.as_file().final_path().ok() == facts.parent_final_path;
    facts.occupied = occupied.filter(|_| unchanged);
    Some((dir, leaf, facts))
}

/// [`destination_facts`], or empty facts and no handle when the parent could not be opened at all (the
/// guard is still asked, with nothing known, so it names the rule).
fn open_destination(destination: &str) -> (DestinationFacts, Option<(DestDir, String)>) {
    match destination_facts(destination) {
        Some((dir, leaf, facts)) => (facts, Some((dir, leaf))),
        None => (DestinationFacts::default(), None),
    }
}

/// The [`DestinationFacts`] of `destination`, read as the destination checks read them (a no-follow
/// handle on its parent, the leaf probed while that handle's final path stays the same); unknown facts
/// stay `None`, which the guard refuses. For callers that judge a destination they do not rename into
/// by handle (the locked-file ladder's facts by path). Nothing is compared with the store's op
/// directory: [`check_quarantine_destination_for`] does that.
pub fn destination_facts_at(destination: &str) -> DestinationFacts {
    open_destination(destination).0
}

/// Whether `source` may be moved to `<op_dir>\<leaf>` in this session's quarantine
/// ([`live::check_quarantine_destination`]): `<quarantine dir>\<op>\<leaf>`, same volume, parent the plain
/// directory its path names, nothing there yet.
///
/// `op_dir` is the store's checked op directory (`SessionDir::create_op_dir`). The directory the gate
/// opens by path to read the facts from must be that very directory: equal volume serial and file id
/// with the store's handle, else [`reason::QUARANTINE_DIR_DIFFERS`]. So the directory the verdict is
/// about, the one the store checked, and the one [`CheckedDest::dir`] renames into are one object.
pub fn check_quarantine_destination(
    ctx: &GateCtx,
    source: &CheckedPath,
    op_dir: &QuarantineDir,
    leaf: &str,
) -> Result<CheckedDest, Refusal> {
    let serial = source.stamp().identity.volume_serial;
    check_quarantine_destination_for(ctx, source.path(), serial, op_dir, leaf)
}

/// [`check_quarantine_destination`] for an item that has no [`CheckedPath`] because no acting handle
/// could be opened on it (the locked-file ladder's boot-time move): `source` is the item's recorded
/// path and `source_serial` the volume serial its validation recorded (`0` is unknown and refused).
/// The same checks, the same comparison of the opened directory with the store's `op_dir`.
pub fn check_quarantine_destination_for(
    ctx: &GateCtx,
    source: &str,
    source_serial: u64,
    op_dir: &QuarantineDir,
    leaf: &str,
) -> Result<CheckedDest, Refusal> {
    let item_path = op_dir.item_path(leaf);
    let destination = item_path.to_str().ok_or_else(|| rule(reason::PATH_FORM))?;
    let (facts, parent) = open_destination(destination);
    let check = QuarantineCheck {
        source,
        source_volume_serial: Some(source_serial),
        destination,
    };
    live::check_quarantine_destination(&check, &facts, &ctx.scope)?;
    let (dir, leaf) = parent.ok_or_else(|| rule(reason::FACTS_UNREADABLE))?;
    let store_id = op_dir.dir().file_id();
    let same_dir = dir.facts().is_ok_and(|now| {
        now.file_id.volume_serial == store_id.volume_serial && now.file_id.id == store_id.id
    });
    if !same_dir {
        return Err(Refusal {
            blocker: Blocker::CannotBackUp,
            reason: reason::QUARANTINE_DIR_DIFFERS,
        });
    }
    Ok(CheckedDest {
        dir,
        leaf,
        path: destination.to_owned(),
        facts,
    })
}

/// Whether a quarantined item may be renamed back to `original` (§7.8, [`live::check_undo_path`]): G2 on
/// the original path as it is now, its parent the plain directory its path names on the item's volume,
/// nothing there.
pub fn check_undo_path(
    ctx: &GateCtx,
    original: &str,
    volume_serial: u64,
    exemptions: Exemptions,
) -> Result<CheckedDest, Refusal> {
    let (facts, parent) = open_destination(original);
    let check = UndoPathCheck {
        original,
        volume_serial,
        exemptions,
    };
    live::check_undo_path(&check, &facts, &ctx.deny)?;
    let (dir, leaf) = parent.ok_or_else(|| rule(reason::FACTS_UNREADABLE))?;
    Ok(CheckedDest {
        dir,
        leaf,
        path: original.to_owned(),
        facts,
    })
}

/// An item in the session's own store that passed [`live::check_store_item`], with the handle to act on.
#[derive(Debug)]
pub struct CheckedStoreItem {
    handle: MoveHandle,
    facts: PathFacts,
}

impl CheckedStoreItem {
    /// The handle the gate inspected; the action must use it.
    pub fn handle(&self) -> &MoveHandle {
        &self.handle
    }

    /// The facts the verdict was given.
    pub fn facts(&self) -> &PathFacts {
        &self.facts
    }

    /// The handle, giving up the rest.
    pub fn into_handle(self) -> MoveHandle {
        self.handle
    }
}

/// The gate for executor-internal work on an item in this session's store (undo's move back, expiry's
/// descend and remove): opens the acting handle (with `FILE_WRITE_ATTRIBUTES` too when
/// `attribute_write`), reads final path, tag, attributes, kind and identity from it and asks
/// [`live::check_store_item`].
pub fn open_store_item(
    ctx: &GateCtx,
    path: &str,
    op: StoreOp,
    binding: Binding<'_, PathStamp>,
    volume_serial: u64,
    attribute_write: bool,
) -> GateOutcome<CheckedStoreItem> {
    let Some(p) = ext(path) else {
        return GateOutcome::Refused(rule(reason::PATH_FORM));
    };
    let opened = if attribute_write {
        MoveHandle::open_with_attribute_write(&p)
    } else {
        MoveHandle::open(&p)
    };
    let handle = match opened {
        Ok(handle) => handle,
        Err(FsError::NotFound) => return GateOutcome::Vanished,
        Err(error) => return GateOutcome::Failed(Win32Error(error.code())),
    };
    let meta = handle.metadata().ok();
    let facts = PathFacts {
        final_path: handle.final_path().ok(),
        reparse_tag: meta.as_ref().map(|m| m.reparse_tag),
        attributes: meta.as_ref().map(|m| m.attributes),
        identity: meta.as_ref().map(|m| FileIdentity {
            volume_serial: m.file_id.volume_serial,
            file_id: m.file_id.id,
        }),
        n_links: meta.as_ref().map(|m| m.n_links),
        is_dir: meta.as_ref().map(|m| m.is_dir),
        ..PathFacts::default()
    };
    let check = StoreCheck {
        path,
        op,
        binding,
        volume_serial,
    };
    match live::check_store_item(&check, &facts, &ctx.scope) {
        Ok(()) => GateOutcome::Pass(CheckedStoreItem { handle, facts }),
        Err(refusal) => GateOutcome::Refused(refusal),
    }
}

// ---------------------------------------------------------------------------------------------------
// Boot-time moves (§7.6)
// ---------------------------------------------------------------------------------------------------

/// The facts [`live::admin_only_ancestors`] needs for `source` (absolute, plain form): one entry for the
/// item and each ancestor up to the drive root. `admin_only` comes from `sid::is_admin_only_writable`
/// on the item, which checks the whole chain at once (leaf mask for the item, ancestor mask above); its
/// answer is given to every component, so a chain with any user-writable part holds the item. `reparse`
/// is read per component from a handle opened without following it.
pub fn boot_move_chain(source: &str) -> Vec<AncestorWrite> {
    let path = Path::new(source);
    let admin_only = is_admin_only_writable(path).ok();
    path.ancestors()
        .filter_map(|component| component.to_str())
        .filter(|component| !component.is_empty())
        .map(|component| AncestorWrite {
            path: component.to_owned(),
            admin_only,
            reparse: ext(component)
                .and_then(|p| open_for_security(&p).ok())
                .and_then(|h| h.reparse_tag().ok())
                .map(|tag| tag != 0),
        })
        .collect()
}

/// Whether a locked item may be moved at boot (§7.6): [`live::admin_only_ancestors`] over
/// [`boot_move_chain`].
pub fn admin_only_ancestors(source: &str) -> BootMove {
    live::admin_only_ancestors(source, &boot_move_chain(source))
}

// ---------------------------------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------------------------------

/// **The one place** where a guard [`KeyAddress`] becomes the arguments of [`WKey::open`]: the root and
/// view one-to-one, the path as it is (the 32-bit view is reached by the view flag, never through a
/// `WOW6432Node` segment; see [`KeyAddress`]). Every component is opened with `REG_OPTION_OPEN_LINK`.
fn open_addr(addr: &KeyAddress, access: KeyAccess) -> Result<WKey, Win32Error> {
    let root = match addr.root {
        KeyRoot::Hklm => RegRoot::Hklm,
        KeyRoot::Hku => RegRoot::Hku,
    };
    let view = match addr.view {
        View::K64 => RegView::K64,
        View::K32 => RegView::K32,
    };
    WKey::open(root, &addr.path, view, access)
}

/// The link state of one key, probed by itself.
fn probe_node(addr: &KeyAddress) -> KeyNode {
    match open_addr(addr, KeyAccess::READ) {
        Ok(key) => match key.is_link() {
            Ok(true) => KeyNode::Link,
            Ok(false) => KeyNode::Plain,
            Err(_) => KeyNode::Unknown,
        },
        Err(e) if e.is_not_found() => KeyNode::Missing,
        // A link above this key: the chain holds a link, whatever this key is.
        Err(Win32Error::LINK_ON_PATH) => KeyNode::Link,
        Err(_) => KeyNode::Unknown,
    }
}

/// Every ancestor of the probe, each opened by itself at its own address (G11).
fn probe_ancestors(probe: &KeyProbe) -> Vec<KeyAncestor> {
    probe
        .ancestors
        .iter()
        .map(|addr| KeyAncestor {
            key: addr.clone(),
            node: probe_node(addr),
        })
        .collect()
}

fn value_name(target: &Target) -> Option<&str> {
    match target {
        Target::RegValue { name, .. } | Target::RegMultiSzSegment { name, .. } => Some(name),
        _ => None,
    }
}

fn value_stamp(value: &RegValue) -> Option<ValueStamp> {
    Some(ValueStamp {
        ty: value.ty,
        len: u64::try_from(value.data.len()).ok()?,
        sha256: Sha256::digest(&value.data).into(),
    })
}

/// What the gate read about a registry item from one key handle.
#[derive(Debug)]
struct KeySeen {
    facts: KeyFacts,
    info: Option<WKeyInfo>,
    owner: Option<String>,
    value: Option<RegValue>,
}

fn collect_key(ctx: &GateCtx, key: &WKey, probe: &KeyProbe, target: &Target) -> KeySeen {
    let node = match key.is_link() {
        Ok(true) => KeyNode::Link,
        Ok(false) => KeyNode::Plain,
        Err(_) => KeyNode::Unknown,
    };
    let security = ctx.host.key_security(key);
    let info = key.info().ok();
    let (value_state, value) = match value_name(target) {
        Some(name) => match key.value(name) {
            Ok(Some(value)) => match value_stamp(&value) {
                Some(stamp) => (ValueState::Present(stamp), Some(value)),
                None => (ValueState::Unknown, None),
            },
            Ok(None) => (ValueState::Absent, None),
            Err(_) => (ValueState::Unknown, None),
        },
        None => (ValueState::Unknown, None),
    };
    KeySeen {
        facts: KeyFacts {
            node,
            ancestors: probe_ancestors(probe),
            owner_is_ti: security.owner_is_ti,
            has_ti_ace: security.ti_ace,
            subkeys: info.as_ref().map(|i| i.n_subkeys),
            values: info.as_ref().map(|i| i.n_values),
            value: value_state,
        },
        info,
        owner: security.owner,
        value,
    }
}

/// The journal form of key facts that passed the gate.
fn key_item_facts(op: KeyOp, seen: &KeySeen) -> Option<ItemFacts> {
    match op {
        KeyOp::DeleteKeyTree | KeyOp::DeleteKeyIfEmpty => {
            let info = seen.info.as_ref()?;
            Some(ItemFacts::Key(RegFacts {
                subkeys: info.n_subkeys,
                values: info.n_values,
                is_link: seen.facts.node == KeyNode::Link,
                owner: seen.owner.clone()?,
                last_write_time: FileTime(info.last_write_time),
                // Filled by the validate pass from the tree it reads ([`validate_key`]); the act-time
                // gate compares the tree separately ([`bind_tree`]).
                tree_sha256: None,
            }))
        }
        KeyOp::DeleteValue | KeyOp::EditSegment => {
            let ValueState::Present(stamp) = seen.facts.value else {
                return None;
            };
            Some(ItemFacts::Value(ValueFacts {
                value_type: stamp.ty,
                size: u32::try_from(stamp.len).ok()?,
                data_sha256: Sha256Hex(stamp.sha256),
            }))
        }
    }
}

/// Maps an error opening the item's key.
fn key_open_error<T>(e: Win32Error) -> GateOutcome<T> {
    if e.is_not_found() {
        GateOutcome::Vanished
    } else if e == Win32Error::LINK_ON_PATH {
        GateOutcome::Refused(Refusal {
            blocker: Blocker::RegLink,
            reason: live::reason::ANCESTOR_IS_LINK,
        })
    } else if e == NAME_NOT_REPRESENTABLE {
        GateOutcome::Refused(rule(reason::NAME_NOT_REPRESENTABLE))
    } else {
        GateOutcome::Failed(e)
    }
}

/// Whether a value or segment item vanished: its value is absent from a key that is an ordinary key. A
/// key replaced by a registry link has no such value either (the link key holds only its target), but
/// that is the guard's link refusal, not a vanished item, so it goes on to the verdict.
fn value_vanished(facts: &KeyFacts) -> bool {
    facts.value == ValueState::Absent && facts.node == KeyNode::Plain
}

/// The access the act needs on the key.
fn act_access(op: KeyOp) -> KeyAccess {
    match op {
        KeyOp::DeleteKeyTree | KeyOp::DeleteKeyIfEmpty => KeyAccess::DELETE,
        KeyOp::DeleteValue | KeyOp::EditSegment => KeyAccess::SET_VALUE,
    }
}

/// Opens, reads and judges a registry item. `binding` is the guard's binding for value actions.
/// `emptied_before`: the validate pass of the run's op with this id; a `DeleteKeyIfEmpty` key that
/// [`GateCtx::emptied_by_earlier_ops`] says the run's earlier ops empty is judged by the guard as the
/// empty key it will be (every other fact as read). Never at the act, where emptiness is the live one.
fn gate_key(
    ctx: &GateCtx,
    item: &GateItem<'_>,
    access: KeyAccess,
    binding: Binding<'_, ValueStamp>,
    emptied_before: Option<OpId>,
) -> GateOutcome<Gated> {
    let Some(op) = key_op(item.op) else {
        return GateOutcome::Refused(rule(reason::OP_KIND));
    };
    let target = item.op.target();
    let probe = match live::key_probe(&target, ctx.deny.env()) {
        Ok(probe) => probe,
        Err(refusal) => return GateOutcome::Refused(refusal),
    };
    let check = KeyCheck {
        target: &target,
        op,
        binding,
        exemptions: item.exemptions,
    };
    let key = match open_addr(&probe.open, access) {
        Ok(key) => key,
        Err(e) if e == Win32Error::ACCESS_DENIED => {
            // Report a refusal as a refusal: look through a read-only handle first.
            return match open_addr(&probe.open, KeyAccess::READ) {
                Ok(read) => {
                    let seen = collect_key(ctx, &read, &probe, &target);
                    if value_vanished(&seen.facts) {
                        return GateOutcome::Vanished;
                    }
                    match live::check_key(&check, &seen.facts, &ctx.deny) {
                        Err(refusal) => GateOutcome::Refused(refusal),
                        Ok(()) => GateOutcome::Failed(e),
                    }
                }
                Err(read_error) if read_error.is_not_found() => GateOutcome::Vanished,
                Err(_) => GateOutcome::Failed(e),
            };
        }
        Err(e) => return key_open_error(e),
    };
    let seen = collect_key(ctx, &key, &probe, &target);
    // "Not found" is the executor's business, not the guard's.
    if value_vanished(&seen.facts) {
        return GateOutcome::Vanished;
    }
    // A delete-if-empty key that this run's earlier items empty is judged as empty at validation; its
    // real counts are what the journal records and what the act is bound to.
    let emptied = match (op, emptied_before, &seen.info) {
        (KeyOp::DeleteKeyIfEmpty, Some(before), Some(info))
            if (info.n_subkeys, info.n_values) != (0, 0)
                && ctx.emptied_by_earlier_ops(&key, &probe.open, info, before) =>
        {
            Some(KeyFacts {
                subkeys: Some(0),
                values: Some(0),
                ..seen.facts.clone()
            })
        }
        _ => None,
    };
    if let Err(refusal) =
        live::check_key(&check, emptied.as_ref().unwrap_or(&seen.facts), &ctx.deny)
    {
        return GateOutcome::Refused(refusal);
    }
    match (key_item_facts(op, &seen), seen.info) {
        (Some(item_facts), Some(info)) => GateOutcome::Pass(Gated {
            key,
            address: probe.open,
            facts: seen.facts,
            info,
            value: seen.value,
            item_facts,
        }),
        _ => GateOutcome::Refused(rule(reason::FACTS_UNREADABLE)),
    }
}

/// A registry item that passed [`gate_key`].
#[derive(Debug)]
struct Gated {
    key: WKey,
    address: KeyAddress,
    facts: KeyFacts,
    info: WKeyInfo,
    value: Option<RegValue>,
    item_facts: ItemFacts,
}

fn validate_key(ctx: &GateCtx, item: &GateItem<'_>, op: Option<OpId>) -> GateOutcome<Validation> {
    gate_key(ctx, item, KeyAccess::READ, Binding::Capture, op).and_then(|gated| {
        let (stamp, facts) = match (gated.item_facts, gated.facts.value) {
            (ItemFacts::Key(facts), _) => match validated_tree(&gated.key, item) {
                Ok(digest) => {
                    let facts = RegFacts {
                        tree_sha256: Some(digest),
                        ..facts
                    };
                    (Stamp::Key(facts.clone()), ItemFacts::Key(facts))
                }
                Err(outcome) => return *outcome,
            },
            (facts @ ItemFacts::Value(_), ValueState::Present(stamp)) => {
                (Stamp::Value(stamp), facts)
            }
            _ => return GateOutcome::Refused(rule(reason::FACTS_UNREADABLE)),
        };
        GateOutcome::Pass(Validation {
            stamp,
            facts,
            exemptions: item.exemptions,
        })
    })
}

/// The key facts the gate reads for `item` now, without the tree: for tests that journal a record the
/// validate pass itself would refuse, to reach the act-time checks.
#[cfg(test)]
pub(crate) fn key_facts_without_tree(ctx: &GateCtx, item: &GateItem<'_>) -> Option<ItemFacts> {
    match gate_key(ctx, item, KeyAccess::READ, Binding::Capture, None) {
        GateOutcome::Pass(gated) => Some(gated.item_facts),
        _ => None,
    }
}

/// The digest of the whole tree of a key to delete, read through the validate pass's handle `key` the
/// way its backup will be read ([`regbackup::capture_tree`], at most [`GateItem::max_keys`] keys): what
/// the act is bound to ([`bind_tree`]; review M2 final S5). A tree that cannot be read whole is refused
/// here with the capture's blocker (a link, a volatile key, a `REG_LINK` value, a name the backup cannot
/// hold, too many keys or bytes): the act would refuse it the same way. A key gone meanwhile is
/// `Vanished`; any other failed call is `Failed`.
fn validated_tree<T>(key: &WKey, item: &GateItem<'_>) -> Result<Sha256Hex, Box<GateOutcome<T>>> {
    let (ExecOp::DeleteKeyTree { key: spelled } | ExecOp::DeleteKeyIfEmpty { key: spelled }) =
        item.op
    else {
        return Err(Box::new(GateOutcome::Refused(rule(reason::OP_KIND))));
    };
    let doc = match regbackup::capture_tree(key, spelled, item.max_keys) {
        Ok(doc) => doc,
        Err(regbackup::CaptureError::Vanished) => return Err(Box::new(GateOutcome::Vanished)),
        Err(e) => {
            return Err(Box::new(match (e.blocker(), e) {
                (Some(blocker), _) => GateOutcome::Refused(Refusal {
                    blocker,
                    reason: reason::TREE_NOT_READ,
                }),
                (None, regbackup::CaptureError::Os(e)) => GateOutcome::Failed(e.error),
                (None, _) => GateOutcome::Refused(rule(reason::FACTS_UNREADABLE)),
            }));
        }
    };
    doc.tree()
        .and_then(regbackup::tree_digest)
        .ok_or_else(|| Box::new(GateOutcome::Refused(rule(reason::FACTS_UNREADABLE))))
}

/// Binds the tree of a key action to its validation (review M2 final S4, S5): `tree` is the tree the
/// action's backup holds, captured through the acting handle of `checked` right after
/// [`open_and_check_key`] passed for op `op`. It passes only when its digest
/// ([`regbackup::tree_digest_with`]), with what this run's own completed ops changed in any key of the
/// tree put back exactly ([`GateCtx::note_done`]), equals the digest of the op's journal `validated`
/// record. Every value (name, type, data), subkey, class, security descriptor and volatility of every key
/// of the tree is compared, so a change anywhere below the key, also one made between the validation and
/// an own op on the same key, is refused, as is a record without a digest ([`reason::TREE_CHANGED`],
/// soft). Last write times are not compared: content written back as it was is the content the backup
/// holds and the user confirmed.
///
/// What is put back, per key and in reverse op order: a value an own `DeleteValue` deleted (its type and
/// data hash from the intent's `pre`; it must be absent now), the data an own `EditSegment` replaced (the
/// value must hold exactly what the edit wrote), a subkey an own key delete removed (with the digest its
/// own act was bound to; it must be absent now). An own op whose change the journal does not record
/// exactly refuses every tree holding its key.
pub fn bind_tree(
    ctx: &GateCtx,
    op: OpId,
    checked: &CheckedKey,
    tree: &purge_model::exec::regbackup::RegTree,
) -> Result<(), Refusal> {
    let changed = || Refusal {
        blocker: Blocker::ChangedSinceScan,
        reason: reason::TREE_CHANGED,
    };
    let recorded = ctx.recorded(op)?;
    let Stamp::Key(facts) = &recorded.stamp else {
        return Err(rule(reason::STAMP_KIND));
    };
    let expected = facts.tree_sha256.ok_or_else(changed)?;
    // The own effects on keys of this tree, by path below its root (folded names), in op order.
    let root = checked.address();
    let mut effects: Vec<(Vec<Vec<u16>>, &ContentChange)> = Vec::new();
    for effect in ctx.effects.values() {
        let Some(rel) = relative_path(root, &effect.key) else {
            continue;
        };
        effects.push((rel, effect.content.as_ref().ok_or_else(changed)?));
    }
    let digest = regbackup::tree_digest_with(tree, |path, content| {
        effects
            .iter()
            .rev()
            .filter(|(rel, _)| rel.as_slice() == path)
            .all(|(_, change)| change.put_back(content))
    });
    if digest == Some(expected) {
        Ok(())
    } else {
        Err(changed())
    }
}

/// The path of `key` below `root` as folded names (empty for `root` itself); `None` when `key` is not
/// `root` or below it.
fn relative_path(root: &KeyAddress, key: &KeyAddress) -> Option<Vec<Vec<u16>>> {
    if root.root != key.root || root.view != key.view {
        return None;
    }
    let segments =
        |path: &str| -> Vec<Vec<u16>> { path.split('\\').map(regbackup::fold_str).collect() };
    let (root_path, key_path) = (segments(&root.path), segments(&key.path));
    key_path
        .strip_prefix(root_path.as_slice())
        .map(<[Vec<u16>]>::to_vec)
}

/// A registry item that passed the gate, with the key handle to act on.
///
/// The key was opened component by component with `REG_OPTION_OPEN_LINK` at the guard's
/// [`KeyProbe::open`] address (root, view flag, logical path), with the
/// access the action needs (`DELETE` for key actions, `KEY_SET_VALUE` for value and segment actions,
/// `KEY_READ` always), and every fact here was read from it. Perform the action on
/// [`CheckedKey::key`]; never reopen the key.
#[derive(Debug)]
pub struct CheckedKey {
    key: WKey,
    address: KeyAddress,
    facts: KeyFacts,
    info: WKeyInfo,
    value: Option<RegValue>,
    item_facts: ItemFacts,
}

impl CheckedKey {
    /// The key the gate inspected: the key itself for a key action, the key holding the value for a value
    /// or segment action.
    pub fn key(&self) -> &WKey {
        &self.key
    }

    /// The canonical address [`CheckedKey::key`] was opened at (aliases resolved, the 32-bit view by its
    /// flag): what a registry backup should record, rather than the plan's spelling (review finding S3).
    pub fn address(&self) -> &KeyAddress {
        &self.address
    }

    /// The facts the verdict was given.
    pub fn facts(&self) -> &KeyFacts {
        &self.facts
    }

    /// Counts, class and last write time of the key, from the handle.
    pub fn info(&self) -> &WKeyInfo {
        &self.info
    }

    /// For a value or segment action: the value (raw type and bytes) as read from the handle; its hash is
    /// the validated one.
    pub fn value(&self) -> Option<&RegValue> {
        self.value.as_ref()
    }

    /// The facts in journal form, for the intent's `pre` record.
    pub fn item_facts(&self) -> &ItemFacts {
        &self.item_facts
    }

    /// The key handle, giving up the rest.
    pub fn into_key(self) -> WKey {
        self.key
    }
}

/// The act-time gate for the registry item of op `op` (`DeleteKeyTree`, `DeleteKeyIfEmpty`,
/// `DeleteValue`, `EditSegment`). The op, its stamp and its exemptions are those of its journal record
/// ([`GateCtx::record`]); an op id without one is refused ([`reason::NOT_VALIDATED`]). Opens the key with
/// the access the action needs, reads every fact from that handle and probes each ancestor by itself
/// (G11), then asks [`live::check_key`]. Value actions are re-checked against the recorded type and data;
/// key actions against the recorded [`RegFacts`] (counts, link state, owner, last write time), a
/// difference being [`reason::KEY_CHANGED`]. On a pass the open key is returned for the action.
///
/// The recorded facts are compared as this run's own completed ops changed them, and only by what those
/// ops explain ([`GateCtx::note_done`]): a key whose values or subkeys earlier items of the run removed,
/// or a value an earlier segment edit of the run rewrote. With nothing noted the comparison is exact.
///
/// A missing key or value is `Vanished`. Access denied is `Failed` unless a read-only look refuses the
/// item, which is then `Refused`.
pub fn open_and_check_key(ctx: &GateCtx, op: OpId) -> GateOutcome<CheckedKey> {
    let recorded = match ctx.recorded(op) {
        Ok(recorded) => recorded,
        Err(refusal) => return GateOutcome::Refused(refusal),
    };
    let item = &recorded.item();
    let Some(op) = key_op(item.op) else {
        return GateOutcome::Refused(rule(reason::OP_KIND));
    };
    // A value this run's own segment edit rewrote is bound to what that edit wrote, not to the data
    // recorded at validation: compared below, on the same handle, as the guard would.
    let rewritten = match (item.op, &recorded.stamp) {
        (ExecOp::DeleteValue { name, .. }, Stamp::Value(value)) => op_key(item.op, &ctx.deny)
            .and_then(|key| ctx.own_rewrite(&key, name))
            .map(|hash| (value.ty, hash)),
        _ => None,
    };
    // The guard compares values itself; it ignores the binding for key actions, whose recorded facts
    // are compared below, from the same handle. A segment edit has its own binding (see below).
    let (binding, key_facts, segment_type) = match (op, &recorded.stamp) {
        (KeyOp::DeleteKeyTree | KeyOp::DeleteKeyIfEmpty, Stamp::Key(facts)) => {
            (Binding::Capture, Some(facts), None)
        }
        (KeyOp::DeleteValue, Stamp::Value(_)) if rewritten.is_some() => {
            (Binding::Capture, None, None)
        }
        (KeyOp::DeleteValue, Stamp::Value(value)) => (Binding::Recheck(value), None, None),
        (KeyOp::EditSegment, Stamp::Value(value)) => (Binding::Capture, None, Some(value.ty)),
        _ => return GateOutcome::Refused(rule(reason::STAMP_KIND)),
    };
    gate_key(ctx, item, act_access(op), binding, None).and_then(|gated| {
        if let Some(recorded) = key_facts {
            let own = ctx.own_changes(&gated.address);
            if !matches!(&gated.item_facts, ItemFacts::Key(now) if own.explain(recorded, now)) {
                // The acting handle is closed when `gated` drops here.
                return GateOutcome::Refused(Refusal {
                    blocker: Blocker::ChangedSinceScan,
                    reason: reason::KEY_CHANGED,
                });
            }
        }
        if let Some((ty, hash)) = rewritten {
            if !matches!(gated.facts.value, ValueState::Present(now) if now.ty == ty && now.sha256 == hash)
            {
                return GateOutcome::Refused(Refusal {
                    blocker: Blocker::ChangedSinceScan,
                    reason: live::reason::VALUE_CHANGED,
                });
            }
        }
        // The segment binding. A segment edit is one read-modify-write of the value as it is at the act,
        // and its backup is that value, so a value whose content changed since validation is acted on
        // as long as the segment is in it; whether it is, is decided on this handle when the edit is
        // planned (`act_reg`), not here. What is compared with the record: the value's type (a list
        // turned into another type, or `REG_SZ` into `REG_EXPAND_SZ`, is another value). Length and hash
        // are what any edit of the list changes, and are not compared. The key's link state and the
        // ancestors' were judged by the guard above on this handle (a link is refused whatever the
        // record says); a value record holds no key owner, so the owner is judged only by G3 on this
        // handle.
        if let Some(recorded_ty) = segment_type {
            if !matches!(gated.facts.value, ValueState::Present(now) if now.ty == recorded_ty) {
                return GateOutcome::Refused(Refusal {
                    blocker: Blocker::ChangedSinceScan,
                    reason: live::reason::VALUE_CHANGED,
                });
            }
        }
        GateOutcome::Pass(CheckedKey {
            key: gated.key,
            address: gated.address,
            facts: gated.facts,
            info: gated.info,
            value: gated.value,
            item_facts: gated.item_facts,
        })
    })
}

// ---------------------------------------------------------------------------------------------------
// Registry undo destinations (§7.8)
// ---------------------------------------------------------------------------------------------------

/// A place a registry backup may be restored to ([`check_undo_key`]), with the open key the restore must
/// act on. As with [`CheckedDest`], the facts of the verdict were read from that handle, so whatever
/// happens to the key's path afterwards, the restore lands in the key that was checked.
#[derive(Debug)]
pub enum CheckedUndoKey {
    /// A key target ([`Target::RegKey`]): the key is re-created (or merged into) below its parent.
    Recreate(CheckedKeyParent),
    /// A value or segment target: the value goes back into the key that held it.
    Restore(CheckedValueKey),
}

impl CheckedUndoKey {
    /// The parent of a key to re-create; `None` for a value or segment target.
    pub fn into_parent(self) -> Option<CheckedKeyParent> {
        match self {
            CheckedUndoKey::Recreate(parent) => Some(parent),
            CheckedUndoKey::Restore(_) => None,
        }
    }

    /// The key a value or segment goes back into; `None` for a key target.
    pub fn into_value_key(self) -> Option<CheckedValueKey> {
        match self {
            CheckedUndoKey::Recreate(_) => None,
            CheckedUndoKey::Restore(key) => Some(key),
        }
    }
}

/// The parent of a key to re-create, open with `KEY_CREATE_SUB_KEY` (and `KEY_READ`) at the parent's
/// [`KeyAddress`], every component with `REG_OPTION_OPEN_LINK`. Create or merge the key as
/// [`CheckedKeyParent::leaf`] below [`CheckedKeyParent::parent`]; never reopen the parent by path.
#[derive(Debug)]
pub struct CheckedKeyParent {
    parent: WKey,
    leaf: String,
    address: KeyAddress,
    facts: UndoKeyFacts,
}

impl CheckedKeyParent {
    /// The parent key the verdict was given for; the key is created below it.
    pub fn parent(&self) -> &WKey {
        &self.parent
    }

    /// The name of the key to re-create, one component below [`CheckedKeyParent::parent`].
    pub fn leaf(&self) -> &str {
        &self.leaf
    }

    /// The canonical address of the key to re-create (the one the gate resolved: aliases resolved, the
    /// 32-bit view by its flag); what a backup should record, not the plan's spelling.
    pub fn address(&self) -> &KeyAddress {
        &self.address
    }

    /// The facts the verdict was given: the parent's link state read from [`CheckedKeyParent::parent`],
    /// the key's own state read below it.
    pub fn facts(&self) -> &UndoKeyFacts {
        &self.facts
    }

    /// Whether the key to re-create exists already (a plain key; the restore then merges or refuses).
    pub fn key_exists(&self) -> bool {
        self.facts.node == KeyNode::Plain
    }

    /// The parent handle, giving up the rest.
    pub fn into_parent(self) -> WKey {
        self.parent
    }
}

/// The key a value or segment goes back into, open with `KEY_SET_VALUE` (and `KEY_READ`) at its
/// [`KeyAddress`], every component with `REG_OPTION_OPEN_LINK`. Restore through
/// [`CheckedValueKey::key`]; never reopen the key by path.
#[derive(Debug)]
pub struct CheckedValueKey {
    key: WKey,
    address: KeyAddress,
    facts: UndoKeyFacts,
}

impl CheckedValueKey {
    /// The key the verdict was given for.
    pub fn key(&self) -> &WKey {
        &self.key
    }

    /// The canonical address of the key (see [`CheckedKeyParent::address`]).
    pub fn address(&self) -> &KeyAddress {
        &self.address
    }

    /// The facts the verdict was given; the key's link state was read from [`CheckedValueKey::key`].
    pub fn facts(&self) -> &UndoKeyFacts {
        &self.facts
    }

    /// The key handle, giving up the rest.
    pub fn into_key(self) -> WKey {
        self.key
    }
}

/// Undo destinations the gate did not check, for the unit tests of the restore engine
/// (`regbackup`) only, which exercise the engine on handles they open themselves. The executor's
/// tests go through [`check_undo_key`].
#[cfg(test)]
impl CheckedKeyParent {
    pub(crate) fn unchecked_for_tests(parent: WKey, leaf: &str, address: KeyAddress) -> Self {
        CheckedKeyParent {
            parent,
            leaf: leaf.to_owned(),
            address,
            facts: UndoKeyFacts::default(),
        }
    }
}

#[cfg(test)]
impl CheckedValueKey {
    pub(crate) fn unchecked_for_tests(key: WKey, address: KeyAddress) -> Self {
        CheckedValueKey {
            key,
            address,
            facts: UndoKeyFacts::default(),
        }
    }
}

/// The link state of an open key.
fn node_of(key: &WKey) -> KeyNode {
    match key.is_link() {
        Ok(true) => KeyNode::Link,
        Ok(false) => KeyNode::Plain,
        Err(_) => KeyNode::Unknown,
    }
}

/// The state of `leaf` below the open `parent`, opened by itself with `REG_OPTION_OPEN_LINK`.
fn child_node(parent: &WKey, leaf: &str) -> KeyNode {
    match parent.open_subkey(leaf, KeyAccess::READ) {
        Ok(key) => node_of(&key),
        Err(e) if e.is_not_found() => KeyNode::Missing,
        Err(e) if e == Win32Error::LINK_ON_PATH => KeyNode::Link,
        Err(_) => KeyNode::Unknown,
    }
}

/// Whether a key, value or segment may be restored at `target` (§7.8, [`live::check_undo_key`]), and the
/// open key the restore must act on.
///
/// The acting key is opened **first**, with the access the restore needs: for a key target its parent
/// (`KEY_CREATE_SUB_KEY`), for a value or segment target the key itself (`KEY_SET_VALUE`), each at its
/// canonical [`KeyAddress`] with `REG_OPTION_OPEN_LINK` on every component. Its link state is read from
/// that handle, the key to re-create is probed below it, and the ancestors above are probed each by
/// itself; the guard decides on those facts, and on a pass the handle is returned in a
/// [`CheckedUndoKey`]. The restore must act through it.
///
/// After the guard's verdict the gate refuses what it has no handle for: a missing parent or key is
/// [`reason::UNDO_KEY_MISSING`] (soft, an undo conflict: a parent removed by this session is restored
/// first by undo's reverse order; a key directly below a hive root has no parent to open), and any
/// other open failure is [`reason::FACTS_UNREADABLE`].
pub fn check_undo_key(
    ctx: &GateCtx,
    target: &Target,
    exemptions: &Exemptions,
) -> Result<CheckedUndoKey, Refusal> {
    let probe = live::key_probe(target, ctx.deny.env())?;
    let recreate = matches!(target, Target::RegKey { .. });
    let missing = || Refusal {
        blocker: Blocker::ChangedSinceScan,
        reason: reason::UNDO_KEY_MISSING,
    };
    // The address of the key acted on, and the access the restore needs on it.
    let (acting, access) = if recreate {
        (probe.ancestors.last(), KeyAccess::CREATE_SUB_KEY)
    } else {
        (Some(&probe.open), KeyAccess::SET_VALUE)
    };
    let opened = acting.map(|addr| open_addr(addr, access));
    let held = opened.as_ref().and_then(|opened| opened.as_ref().ok());

    // Every ancestor by itself, except the one held open, whose state is read from its handle.
    let mut ancestors = probe_ancestors(&probe);
    let node = match (held, recreate) {
        (Some(parent), true) => {
            if let Some(last) = ancestors.last_mut() {
                last.node = node_of(parent);
            }
            prefix::leaf(&probe.open.path).map_or(KeyNode::Unknown, |leaf| child_node(parent, leaf))
        }
        (Some(key), false) => node_of(key),
        (None, _) => probe_node(&probe.open),
    };
    let facts = UndoKeyFacts { node, ancestors };
    live::check_undo_key(target, &facts, &ctx.deny, exemptions)?;

    let key = match opened {
        Some(Ok(key)) => key,
        None => return Err(missing()),
        Some(Err(e)) if e.is_not_found() => return Err(missing()),
        Some(Err(_)) => return Err(rule(reason::FACTS_UNREADABLE)),
    };
    let address = probe.open;
    if recreate {
        let leaf = prefix::leaf(&address.path)
            .ok_or_else(|| rule(reason::FACTS_UNREADABLE))?
            .to_owned();
        Ok(CheckedUndoKey::Recreate(CheckedKeyParent {
            parent: key,
            leaf,
            address,
            facts,
        }))
    } else {
        Ok(CheckedUndoKey::Restore(CheckedValueKey {
            key,
            address,
            facts,
        }))
    }
}

#[cfg(test)]
mod object_stamp_tests {
    use super::*;

    const DIGEST: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn facts(kind: ObjectKind, sha256: &str, running: bool) -> ItemFacts {
        ItemFacts::Object {
            kind,
            sha256: sha256.into(),
            running,
        }
    }

    /// A journal `validated` record of an object binds the act to its kind and digest, and only an op
    /// of that kind fits it; a running object or a malformed digest binds nothing.
    #[test]
    fn object_facts_make_an_object_stamp_that_fits_only_its_op() {
        let stamp = Stamp::from_item_facts(&facts(ObjectKind::Service, DIGEST, false)).unwrap();
        assert_eq!(
            stamp,
            Stamp::Object {
                kind: ObjectKind::Service,
                sha256: DIGEST.into()
            }
        );
        let service = ExecOp::DeleteService { name: "S".into() };
        let task = ExecOp::DeleteTask { path: r"\T".into() };
        let rule = ExecOp::DeleteFirewallRule { id: "{R}".into() };
        let key = ExecOp::DeleteKeyTree {
            key: r"HKLM\SYSTEM\CurrentControlSet\Services\S".into(),
        };
        assert!(stamp.fits(&service));
        assert!(!stamp.fits(&task) && !stamp.fits(&rule) && !stamp.fits(&key));
        let task_stamp = Stamp::from_item_facts(&facts(ObjectKind::Task, DIGEST, false)).unwrap();
        assert!(task_stamp.fits(&task) && !task_stamp.fits(&service));
        let rule_stamp =
            Stamp::from_item_facts(&facts(ObjectKind::FirewallRule, DIGEST, false)).unwrap();
        assert!(rule_stamp.fits(&rule) && !rule_stamp.fits(&task));
        // No other stamp fits an object op.
        assert!(!Stamp::Package.fits(&service));

        assert_eq!(
            Stamp::from_item_facts(&facts(ObjectKind::Service, DIGEST, true)),
            None
        );
        assert_eq!(
            Stamp::from_item_facts(&facts(ObjectKind::Service, &DIGEST.to_uppercase(), false)),
            None
        );
        assert_eq!(
            Stamp::from_item_facts(&facts(ObjectKind::Service, "", false)),
            None
        );
    }
}
