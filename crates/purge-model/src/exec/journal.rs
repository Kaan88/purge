//! Journal records of `purge.journal/1` (ENGINE_PLAN.md §7.8).
//!
//! A session's `journal.jsonl` holds one [`Record`] per line, each a JSON object tagged by `"rec"`. The
//! first line is the [`Header`], which carries the schema id; a journal of another version does not parse.
//!
//! The order of a run is: `header`, `settings` (journals written before that record existed have none),
//! one `validated` per selected item, then per item `intent` (flushed before the action) and `done`, with
//! a `group_end` after at most 64 intents, and at the end `commit` or `aborted`. An item that is decided
//! before any backup is taken (already gone, refused by a gate) gets a `done` with no `intent`; see
//! [`ItemOutcome::allowed_without_intent`]. Later runs append `undo_intent`, `undo_done`,
//! `undo_conflict`, `reconcile`, `retry_intent` and `expire` records.
//!
//! Compatibility: additions keep every older document readable. New fields have defaults, and new
//! variants and record kinds leave the encoding of the old ones as it was. An older reader refuses a
//! journal holding a record kind or variant it does not know (it never skips one), so no addition of
//! that kind is silently ignored.
//!
//! This module only defines the records. Writing, flushing and reading them back, with the rule for a
//! torn last line, is `purge-exec`'s job.
//!
//! Records do not refuse unknown members: the journal writer appends a `chain` member to every line. An
//! addition that a reader must not ignore needs a new schema id. Volume serials, [`FileTime`]s and byte
//! counts are 64-bit JSON integers that can exceed 2^53; a reader must not keep them as doubles.

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

use super::op::{
    BackupRef, ExecOp, FailCode, FileIdHex, Inverse, ItemOutcome, OpId, OutcomeCounts, Sha256Hex,
};
use super::session::{RetentionClass, SessionId};
use crate::ids::schema_id;
use crate::{Blocker, CandidateId, FileTime, ScanMode, Target};

schema_id!(
    /// The `schema` field of a journal's header: always the literal string `purge.journal/1`.
    /// Deserialising any other value fails.
    JournalSchema = "purge.journal/1"
);

/// The most intents a group may hold before a [`GroupEnd`] and a flush (§7.8).
pub const MAX_GROUP_INTENTS: u32 = 64;

/// What a handle on a file or directory showed (gate G1 of §7.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct FileFacts {
    /// The final path of the handle, without a `\\?\` prefix. Equal to the lexical path unless a reparse
    /// point lies on the way.
    pub final_path: String,
    /// The file id.
    pub file_id: FileIdHex,
    /// Serial of the volume the item is on.
    pub volume_serial: u64,
    /// Reparse tag; 0 unless the item is a reparse point.
    pub reparse_tag: u32,
    /// `FILE_ATTRIBUTE_*` bits.
    pub attributes: u32,
    /// Hard link count.
    pub n_links: u32,
    /// Whether the item is a directory.
    pub is_dir: bool,
    /// End of file in bytes; 0 for a directory.
    pub size: u64,
    /// For a directory: how many files and directories lie below it, when counted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_entries: Option<u64>,
    /// For a directory: the total size in bytes of the files below it, when counted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_bytes: Option<u64>,
}

/// What an open registry key showed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct RegFacts {
    /// Number of direct subkeys.
    pub subkeys: u32,
    /// Number of values.
    pub values: u32,
    /// Whether the key is a registry link.
    pub is_link: bool,
    /// SID of the key's owner, as a string (`S-1-5-32-544`).
    pub owner: String,
    /// The key's last write time.
    pub last_write_time: FileTime,
    /// For a key to delete: the digest of the whole subtree as it was read (every key's class, security,
    /// volatility, values by name, type and data hash, and subkeys by name and digest; last write times
    /// are not in it). A key action is bound to it at the act; a record without one binds nothing and is
    /// refused there. Absent in journals written before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_sha256: Option<Sha256Hex>,
}

/// What one registry value showed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ValueFacts {
    /// The raw value type (`REG_*`).
    #[serde(rename = "type")]
    pub value_type: u32,
    /// Size of the raw data in bytes.
    pub size: u32,
    /// SHA-256 of the raw data.
    pub data_sha256: Sha256Hex,
}

/// The state of an item as seen through a handle, recorded at validation and again before the action.
/// A difference between the two is [`SkipReason::ChangedSinceScan`](super::op::SkipReason). Serialised as
/// an object tagged by `"kind"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind")]
pub enum ItemFacts {
    /// A file or directory.
    File(FileFacts),
    /// A registry key.
    Key(RegFacts),
    /// A registry value (also the value a segment edit rewrites).
    Value(ValueFacts),
    /// An installed package.
    Package,
    /// The item does not exist.
    Absent,
    /// The item did not pass validation: a gate refused it, or it could not be opened or read. Nothing
    /// acts on it in the run (the act-time gate keeps no record of it), exactly as for
    /// [`ItemFacts::Absent`], but the journal says why.
    Refused {
        /// The blocker the gate raised; `None` when the item could not be opened or read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blocker: Option<Blocker>,
        /// The code of the rule that refused (`gate.*`, `live.*`, `exec.*`), or of what failed.
        reason: String,
        /// The Win32 error code, when the item could not be opened or read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        os_error: Option<u32>,
    },
}

impl ItemFacts {
    /// Whether the facts describe an item the run may act on: not [`ItemFacts::Absent`] and not
    /// [`ItemFacts::Refused`].
    pub fn is_actionable(&self) -> bool {
        !matches!(self, ItemFacts::Absent | ItemFacts::Refused { .. })
    }
}

/// One volume a session touches.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct VolumeRecord {
    /// Root of the volume, e.g. `C:\`.
    pub root: String,
    /// Its serial number.
    pub serial: u64,
    /// Its file system, e.g. `NTFS`.
    pub file_system: String,
    /// Absolute path of this session's quarantine directory on the volume.
    pub quarantine: String,
}

/// The first record: which plan and selection the session executes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Header {
    /// Always `purge.journal/1`.
    pub schema: JournalSchema,
    /// The session id.
    pub session: SessionId,
    /// When the session was opened.
    pub created: FileTime,
    /// Version of the engine that writes the journal.
    pub engine_version: String,
    /// The app id of the plan.
    pub app: String,
    /// The plan hash the run is bound to.
    pub plan_hash: Sha256Hex,
    /// The hash of the selection (SHA-256 over the sorted selected candidate ids).
    pub selection_hash: Sha256Hex,
    /// The policy version that decided the plan.
    pub policy_version: String,
    /// The scan mode of the plan.
    pub mode: ScanMode,
    /// How many items are selected; one `validated` record follows for each.
    pub items: u32,
    /// Whether irreversible ops were acknowledged for this run.
    pub allow_irreversible: bool,
    /// The volumes the session keeps quarantine data on.
    pub volumes: Vec<VolumeRecord>,
}

/// When a run asks for a restore point (Settings S5, "Restore point"), as the journal records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum RestorePointPolicy {
    /// Never.
    Off,
    /// Only for a high-risk run.
    HighRiskOnly,
    /// For every run.
    Always,
}

/// The settings a run was started with: the `settings` record, written right after the [`Header`] and
/// before the first `validated` record. A resumed run reads them from here, never from its caller. The
/// acknowledgement of irreversible removals is the header's [`Header::allow_irreversible`].
///
/// Journals written before this record existed have none; they still read, and a reader treats the
/// settings as unknown.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct RunSettings {
    /// The SID of the user the scan ran for, as the scan gave it to the plan's decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_sid: Option<String>,
    /// Whether the scan resolved 8.3 names, as the scan gave it to the plan's decisions.
    pub long_names_resolved: bool,
    /// The most keys a registry tree may hold to be deleted.
    pub key_limit: u64,
    /// When the run asks for a restore point.
    pub restore_point: RestorePointPolicy,
    /// The selected candidate ids in op order (op 1 first), so that a run interrupted before every
    /// item was validated is bound to its selection again without searching for it (review M2 M3).
    /// Empty in journals written before the field existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected: Vec<CandidateId>,
}

/// The deny-list exemptions an item was judged with (ENGINE_PLAN.md §5.10). The same four inputs as the
/// guard's `Exemptions`, recorded so that undo needs no second derivation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct GateExemptions {
    /// The key carries `ProvenOwnedSkeleton` evidence (the `shell` / `shellex` roots under Classes).
    pub proven_owned_skeleton: bool,
    /// The action is a segment edit of a value under `Session Manager\Environment`.
    pub environment_segment_edit: bool,
    /// The candidate has Tier A evidence for an item below the all-users `Start Menu\Programs` folder.
    pub tier_a_start_menu_entry: bool,
    /// The path had its 8.3 names resolved.
    pub long_names_resolved: bool,
}

/// The state of one selected item when the run started. The per-item re-check compares against this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Validated {
    /// The op id the item has in this session.
    pub op: OpId,
    /// The candidate id of the plan item.
    pub item: CandidateId,
    /// What the item acts on.
    pub target: Target,
    /// What the item looked like.
    pub facts: ItemFacts,
    /// The exemptions the gate applied to the item when it was validated. Undo passes exactly these to
    /// the gate for the item's original path or key (`UndoPathCheck.exemptions`, `check_undo_key`); it
    /// never derives them again from the scan, whose rules may have changed since.
    pub exemptions: GateExemptions,
}

/// The write-ahead record of one op: everything needed to finish or undo it. It is flushed before the
/// action starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Intent {
    /// The op id.
    pub op: OpId,
    /// The candidate id of the plan item.
    pub item: CandidateId,
    /// What is about to be done.
    pub exec_op: ExecOp,
    /// How it is undone. Any backup it names has been written, read back and hashed.
    pub inverse: Inverse,
    /// A definition file kept for the record when the op has no inverse that reads one (the full
    /// definition of a removed package). Undo does not read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition: Option<BackupRef>,
    /// The item as seen through the handle the action will use.
    pub pre: ItemFacts,
}

impl Intent {
    /// Every backup file the record names: the inverse's backup, then the definition.
    pub fn backups(&self) -> impl Iterator<Item = &BackupRef> {
        self.inverse.backup().into_iter().chain(&self.definition)
    }

    /// Whether the record hangs together. A reader refuses a journal with an intent that fails this:
    ///
    /// - the inverse is the kind that undoes the op and addresses the same item ([`Inverse::undoes`]);
    /// - `pre` is the kind of facts the op acts on: [`ItemFacts::File`] for the path ops (a directory for
    ///   [`ExecOp::RemoveDirIfEmpty`]), [`ItemFacts::Key`] for the key ops, [`ItemFacts::Value`] for the
    ///   value and segment ops, [`ItemFacts::Package`] for a package. An intent is only written for an item
    ///   that is there, so `Absent` never fits;
    /// - for [`Inverse::MoveBack`], the recorded file id and volume serial are those of `pre`, the handle
    ///   the move uses;
    /// - every backup path stays inside the session directory ([`BackupRef::is_session_relative`]).
    pub fn is_consistent(&self) -> bool {
        let pre_fits = match (&self.exec_op, &self.pre) {
            (ExecOp::QuarantineMove { .. }, ItemFacts::File(_)) => true,
            (ExecOp::RemoveDirIfEmpty { .. }, ItemFacts::File(facts)) => facts.is_dir,
            (ExecOp::DeleteKeyTree { .. } | ExecOp::DeleteKeyIfEmpty { .. }, ItemFacts::Key(_)) => {
                true
            }
            (ExecOp::DeleteValue { .. } | ExecOp::EditSegment { .. }, ItemFacts::Value(_)) => true,
            (ExecOp::RemovePackage { .. }, ItemFacts::Package) => true,
            _ => false,
        };
        let same_file = match (&self.inverse, &self.pre) {
            (
                Inverse::MoveBack {
                    file_id,
                    volume_serial,
                    ..
                },
                ItemFacts::File(facts),
            ) => *file_id == facts.file_id && *volume_serial == facts.volume_serial,
            _ => true,
        };
        pre_fits
            && same_file
            && self.inverse.undoes(&self.exec_op)
            && self.backups().all(BackupRef::is_session_relative)
    }
}

/// How one item ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Done {
    /// The op id.
    pub op: OpId,
    /// The candidate id of the plan item.
    pub item: CandidateId,
    /// The outcome.
    pub outcome: ItemOutcome,
}

/// The end of a group of intents; the journal is flushed after it.
///
/// Reading a group number of 0, or a count outside 1 to [`MAX_GROUP_INTENTS`], fails. That the numbers
/// match the journal is checked where the journal is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct GroupEnd {
    /// Number of the group, counted from 1.
    #[serde(deserialize_with = "group_number")]
    #[schemars(range(min = 1))]
    pub group: u32,
    /// How many intent records the group holds: 1 to [`MAX_GROUP_INTENTS`]. The field is not called
    /// `intents` so that only the two intent records spell that word in a journal line.
    #[serde(deserialize_with = "group_count")]
    #[schemars(range(min = 1, max = 64))]
    pub ops: u32,
}

/// Reads a group number: at least 1.
fn group_number<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    match u32::deserialize(deserializer)? {
        0 => Err(serde::de::Error::custom("group numbers count from 1")),
        n => Ok(n),
    }
}

/// Reads the intent count of a group: 1 to [`MAX_GROUP_INTENTS`].
fn group_count<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    let n = u32::deserialize(deserializer)?;
    if (1..=MAX_GROUP_INTENTS).contains(&n) {
        Ok(n)
    } else {
        Err(serde::de::Error::custom(format_args!(
            "a group holds 1 to {MAX_GROUP_INTENTS} intents, not {n}"
        )))
    }
}

/// The run finished: every selected item has a `done` record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Commit {
    /// When the run finished.
    pub at: FileTime,
    /// How many items ended in each outcome.
    pub counts: OutcomeCounts,
    /// Bytes of quarantine and backup data the session holds.
    pub backup_bytes: u64,
}

/// Why a run stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum AbortReason {
    /// A backup could not be written or verified in a way that puts the storage in doubt.
    BackupWriteFailed,
    /// The journal could not be written or flushed.
    JournalWriteFailed,
    /// A storage directory failed its integrity check during the run.
    StorageIntegrity,
    /// The run was cancelled.
    Cancelled,
    /// Recovery rolled the session back after a crash.
    RolledBack,
}

/// The run stopped early. Items without a `done` record were not touched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Aborted {
    /// When the run stopped.
    pub at: FileTime,
    /// Why.
    pub reason: AbortReason,
    /// Free text for the report; may be empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// The write-ahead record of undoing one op. It is flushed before the inverse starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct UndoIntent {
    /// The op that is about to be undone.
    pub op: OpId,
}

/// How an inverse that ran ended. Serialised as an object tagged by `"kind"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind")]
pub enum UndoOutcome {
    /// The previous state was restored.
    Restored,
    /// The previous state was already in place (for example the value exists with the same type and
    /// data).
    AlreadyRestored,
    /// The op had changed nothing (it was skipped, had failed, or its item was already gone).
    NothingToUndo,
    /// The inverse failed.
    Failed {
        /// The kind of failure.
        code: FailCode,
        /// The Win32 error code, when there is one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        os_error: Option<u32>,
        /// Free text for the report; may be empty.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        detail: String,
    },
}

/// Why an inverse was not applied (§7.8). A conflict is reported, never forced. Serialised as an object
/// tagged by `"kind"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind")]
pub enum UndoConflict {
    /// The backup file's SHA-256 does not match the journal.
    BackupTampered,
    /// The backup file is missing.
    BackupMissing,
    /// The backup or the quarantined item was deleted by a confirmed expiry.
    Expired,
    /// The quarantined item is missing.
    QuarantineMissing,
    /// The item in quarantine is not the recorded one (other file id or volume serial).
    FileIdMismatch,
    /// Something exists at the original path.
    DestinationExists,
    /// The key exists again: under `Installer\*`, `Services` or a COM root, or with content elsewhere.
    KeyExists,
    /// The value exists with another type or other data.
    ValueDiffers,
    /// The list value was changed since the edit in a way that makes re-inserting the segment unsafe.
    ValueChanged,
    /// A gate refused the destination (deny-list, registry link, reparse point).
    GateBlocked {
        /// The blocker the gate raised.
        blocker: Blocker,
    },
    /// The op has no inverse.
    Irreversible,
    /// The parent directory or key the item goes back into is gone. It is recreated only by an inverse
    /// of the same session (a `RecreateDir` or `RestoreKeyTree` that must run first); nothing was created
    /// for this op.
    ParentMissing,
}

/// An inverse ran to an end.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UndoDone {
    /// The op that was undone.
    pub op: OpId,
    /// How it ended.
    pub outcome: UndoOutcome,
}

/// An inverse was not applied. This record ends the undo of the op, with or without an `undo_intent`
/// before it (a tampered backup is found before the intent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UndoConflictEntry {
    /// The op that was to be undone.
    pub op: OpId,
    /// What stood in the way.
    pub conflict: UndoConflict,
    /// Free text for the report; may be empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// What reconcile found for an op that was left pending (§7.6). Serialised as an object tagged by
/// `"kind"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind")]
pub enum ReconcileResult {
    /// The boot-time move happened and the item in quarantine is the recorded one.
    Completed,
    /// The moved item has another file id or volume serial: it was moved back at once.
    MismatchMovedBack,
    /// The boot-time move has not happened yet.
    StillPending,
    /// Purge removed its own pending pair; the item stays where it was.
    Cancelled,
    /// A held item was tried again, with this outcome. Written after the op's [`RetryIntent`]; the
    /// outcome takes the place of `HeldRetry`.
    Retried {
        /// The outcome of the new attempt.
        outcome: ItemOutcome,
    },
    /// The boot-time move did not happen: the pair is gone from the list, nothing reached quarantine and
    /// the item is still at its source path. Nothing changed, so there is nothing to undo; the op is no
    /// longer pending.
    NotMoved {
        /// The kind of failure (`VerifyFailed`: the registration was confirmed, the item stayed).
        code: FailCode,
        /// The Win32 error code, when there is one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        os_error: Option<u32>,
        /// Free text for the report; may be empty.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        detail: String,
    },
    /// Another object than the recorded one is in quarantine and could not be moved back; it stays in
    /// the admin-only quarantine. The op is no longer pending; it needs attention and its undo reports a
    /// conflict.
    MismatchKept {
        /// Why the object could not be moved back.
        code: FailCode,
        /// The Win32 error code, when there is one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        os_error: Option<u32>,
        /// Free text for the report; may be empty.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        detail: String,
    },
    /// The item is neither at its source path nor in quarantine. The op is no longer pending; it needs
    /// attention and its undo reports a conflict.
    Lost {
        /// Free text for the report; may be empty.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        detail: String,
    },
}

impl ReconcileResult {
    /// Whether the result leaves the op in a state that needs the user's attention (an object kept in
    /// quarantine that is not the recorded one, or an item lost): [`ReconcileResult::MismatchKept`] and
    /// [`ReconcileResult::Lost`]. Undo answers such an op with a conflict.
    pub fn needs_attention(&self) -> bool {
        matches!(
            self,
            ReconcileResult::MismatchKept { .. } | ReconcileResult::Lost { .. }
        )
    }
}

/// The write-ahead record of a retry of a held item (an op whose outcome is `HeldRetry`). It is flushed
/// before the retry acts; the retry ends with a `reconcile` record whose result is
/// [`ReconcileResult::Retried`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct RetryIntent {
    /// When the retry started.
    pub at: FileTime,
    /// The held op.
    pub op: OpId,
}

/// The ops one undo run is about to undo, written before its first `undo_intent`: the selected ops and
/// those pulled in because a selected restore depends on them, in the order the run undoes them. A run
/// that is interrupted is finished from this list by recovery. Journals written before the record
/// existed have none; their recovery finishes only the op whose undo was in progress.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct UndoPlan {
    /// When the undo run started.
    pub at: FileTime,
    /// The ops, in undo order.
    pub ops: Vec<OpId>,
}

/// What a later start found for a pending op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Reconcile {
    /// When reconcile ran.
    pub at: FileTime,
    /// The pending op.
    pub op: OpId,
    /// What was found.
    pub result: ReconcileResult,
}

/// A confirmed expiry deleted an op's quarantined item or backup. The op can no longer be undone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Expire {
    /// When the data was deleted.
    pub at: FileTime,
    /// The op whose data it was.
    pub op: OpId,
    /// What was deleted: [`RetentionClass::Quarantine`] or [`RetentionClass::Backup`].
    pub class: RetentionClass,
    /// How many bytes were freed.
    pub bytes: u64,
}

/// One line of `journal.jsonl`. Serialised as an object tagged by `"rec"`, in snake case: `header`,
/// `settings`, `validated`, `intent`, `done`, `group_end`, `commit`, `aborted`, `undo_intent`,
/// `undo_done`, `undo_conflict`, `undo_plan`, `reconcile`, `retry_intent`, `expire`.
///
/// Only the three write-ahead records (`intent`, `undo_intent`, `retry_intent`) spell the word "intent"
/// in their line; of those only `intent` holds an item path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "rec", rename_all = "snake_case")]
// Records are built, written and dropped one at a time, so the size of the largest variant costs nothing
// and boxing it would only add noise at every use.
#[allow(clippy::large_enum_variant)]
pub enum Record {
    /// The first record of a journal.
    Header(Header),
    /// The state of one selected item when the run started.
    Validated(Validated),
    /// An op is about to run.
    Intent(Intent),
    /// An item ended.
    Done(Done),
    /// A group of intents ended.
    GroupEnd(GroupEnd),
    /// The run finished.
    Commit(Commit),
    /// The run stopped early.
    Aborted(Aborted),
    /// An op is about to be undone.
    UndoIntent(UndoIntent),
    /// An inverse ran to an end.
    UndoDone(UndoDone),
    /// An inverse was not applied.
    UndoConflict(UndoConflictEntry),
    /// A pending op was looked at again.
    Reconcile(Reconcile),
    /// An op's kept data was deleted by expiry.
    Expire(Expire),
    /// The settings of the run; only right after the header.
    Settings(RunSettings),
    /// A held op is about to be tried again.
    RetryIntent(RetryIntent),
    /// An undo run is about to undo these ops.
    UndoPlan(UndoPlan),
}

impl Record {
    /// The record's name as serialised in `"rec"`.
    pub fn name(&self) -> &'static str {
        match self {
            Record::Header(_) => "header",
            Record::Settings(_) => "settings",
            Record::RetryIntent(_) => "retry_intent",
            Record::Validated(_) => "validated",
            Record::Intent(_) => "intent",
            Record::Done(_) => "done",
            Record::GroupEnd(_) => "group_end",
            Record::Commit(_) => "commit",
            Record::Aborted(_) => "aborted",
            Record::UndoIntent(_) => "undo_intent",
            Record::UndoDone(_) => "undo_done",
            Record::UndoConflict(_) => "undo_conflict",
            Record::Reconcile(_) => "reconcile",
            Record::Expire(_) => "expire",
            Record::UndoPlan(_) => "undo_plan",
        }
    }

    /// The op the record is about; `None` for the records that concern the whole session.
    pub fn op(&self) -> Option<OpId> {
        match self {
            Record::Validated(r) => Some(r.op),
            Record::Intent(r) => Some(r.op),
            Record::Done(r) => Some(r.op),
            Record::UndoIntent(r) => Some(r.op),
            Record::UndoDone(r) => Some(r.op),
            Record::UndoConflict(r) => Some(r.op),
            Record::Reconcile(r) => Some(r.op),
            Record::Expire(r) => Some(r.op),
            Record::RetryIntent(r) => Some(r.op),
            Record::Header(_)
            | Record::Settings(_)
            | Record::GroupEnd(_)
            | Record::Commit(_)
            | Record::Aborted(_)
            | Record::UndoPlan(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "20261115T101502Z-9f3a6c1d2b7e4a50";
    const HASH_A: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const HASH_B: &str = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";
    /// The file of the sample journal: a path with a space, as the rig's traps use.
    const ITEM_PATH: &str = r"C:\Program Files\Vendor App\app.exe";

    /// A sample journal: one line per record kind, in the order a run, an undo, a reconcile and an expiry
    /// would write them.
    fn sample_journal() -> Vec<String> {
        let file_facts = r#"{"kind":"File","final_path":"C:\\Program Files\\Vendor App\\app.exe","file_id":"000102030405060708090a0b0c0d0e0f","volume_serial":13902625541364831864,"reparse_tag":0,"attributes":32,"n_links":1,"is_dir":false,"size":1048576}"#;
        let none = r#""exemptions":{"proven_owned_skeleton":false,"environment_segment_edit":false,"tier_a_start_menu_entry":false,"long_names_resolved":false}"#;
        let long = r#""exemptions":{"proven_owned_skeleton":false,"environment_segment_edit":false,"tier_a_start_menu_entry":false,"long_names_resolved":true}"#;
        vec![
            format!(
                r#"{{"rec":"header","schema":"purge.journal/1","session":"{ID}","created":134078121020000000,"engine_version":"0.1.0","app":"vendor-app","plan_hash":"{HASH_A}","selection_hash":"{HASH_B}","policy_version":"m1a.6","mode":"post","items":3,"allow_irreversible":false,"volumes":[{{"root":"C:\\","serial":13902625541364831864,"file_system":"NTFS","quarantine":"C:\\ProgramData\\Purge\\Quarantine\\{ID}"}}]}}"#
            ),
            format!(
                r#"{{"rec":"validated","op":1,"item":"c-01","target":{{"type":"Path","path":"C:\\Program Files\\Vendor App\\app.exe"}},"facts":{file_facts},{long}}}"#
            ),
            r#"{"rec":"validated","op":2,"item":"c-02","target":{"type":"RegKey","path":"HKLM\\SOFTWARE\\Vendor"},"facts":{"kind":"Key","subkeys":2,"values":5,"is_link":false,"owner":"S-1-5-32-544","last_write_time":134078000000000000},"exemptions":{"proven_owned_skeleton":true,"environment_segment_edit":false,"tier_a_start_menu_entry":false,"long_names_resolved":false}}"#.to_owned(),
            format!(
                r#"{{"rec":"validated","op":3,"item":"c-03","target":{{"type":"RegValue","path":"HKLM\\SOFTWARE\\Other","name":""}},"facts":{{"kind":"Value","type":2,"size":38,"data_sha256":"{HASH_B}"}},{none}}}"#
            ),
            r#"{"rec":"validated","op":4,"item":"c-04","target":{"type":"Path","path":"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Vendor App"},"facts":{"kind":"File","final_path":"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Vendor App","file_id":"ffffffffffffffffffffffffffffffff","volume_serial":1,"reparse_tag":0,"attributes":16,"n_links":1,"is_dir":true,"size":0,"tree_entries":12,"tree_bytes":4096},"exemptions":{"proven_owned_skeleton":false,"environment_segment_edit":false,"tier_a_start_menu_entry":true,"long_names_resolved":true}}"#.to_owned(),
            format!(
                r#"{{"rec":"validated","op":5,"item":"c-05","target":{{"type":"AppxPackage","full_name":"Vendor.App_1.0.0.0_x64__abc"}},"facts":{{"kind":"Package"}},{none}}}"#
            ),
            r#"{"rec":"validated","op":6,"item":"c-06","target":{"type":"RegMultiSzSegment","path":"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment","name":"Path","segment":"C:\\Vendor\\bin"},"facts":{"kind":"Absent"},"exemptions":{"proven_owned_skeleton":false,"environment_segment_edit":true,"tier_a_start_menu_entry":false,"long_names_resolved":false}}"#.to_owned(),
            format!(
                r#"{{"rec":"intent","op":1,"item":"c-01","exec_op":{{"kind":"QuarantineMove","path":"C:\\Program Files\\Vendor App\\app.exe"}},"inverse":{{"kind":"MoveBack","quarantine_path":"C:\\ProgramData\\Purge\\Quarantine\\{ID}\\000001\\app.exe","original_path":"C:\\Program Files\\Vendor App\\app.exe","file_id":"000102030405060708090a0b0c0d0e0f","volume_serial":13902625541364831864}},"pre":{file_facts}}}"#
            ),
            r#"{"rec":"done","op":1,"item":"c-01","outcome":{"kind":"Done"}}"#.to_owned(),
            format!(
                r#"{{"rec":"intent","op":2,"item":"c-02","exec_op":{{"kind":"DeleteKeyTree","key":"HKLM\\SOFTWARE\\Vendor"}},"inverse":{{"kind":"RestoreKeyTree","backup":{{"path":"reg\\000002.regbackup.json","sha256":"{HASH_A}","bytes":4096}}}},"pre":{{"kind":"Key","subkeys":2,"values":5,"is_link":false,"owner":"S-1-5-32-544","last_write_time":134078000000000000}}}}"#
            ),
            r#"{"rec":"done","op":2,"item":"c-02","outcome":{"kind":"Failed","code":"AccessDenied","os_error":5}}"#.to_owned(),
            r#"{"rec":"done","op":3,"item":"c-03","outcome":{"kind":"Skipped","reason":{"kind":"GateBlocked","blocker":{"kind":"RegLink"}}}}"#.to_owned(),
            format!(
                r#"{{"rec":"intent","op":5,"item":"c-05","exec_op":{{"kind":"RemovePackage","full_name":"Vendor.App_1.0.0.0_x64__abc"}},"inverse":{{"kind":"None"}},"definition":{{"path":"def\\000005.json","sha256":"{HASH_B}","bytes":900}},"pre":{{"kind":"Package"}}}}"#
            ),
            r#"{"rec":"done","op":5,"item":"c-05","outcome":{"kind":"Done"}}"#.to_owned(),
            r#"{"rec":"group_end","group":1,"ops":3}"#.to_owned(),
            r#"{"rec":"commit","at":134078121950000000,"counts":{"done":2,"vanished":1,"skipped":1,"held_retry":0,"pending_reboot":0,"failed":1},"backup_bytes":1053572}"#.to_owned(),
            r#"{"rec":"aborted","at":134078121950000000,"reason":"BackupWriteFailed","detail":"disk full"}"#.to_owned(),
            r#"{"rec":"aborted","at":1,"reason":"RolledBack"}"#.to_owned(),
            r#"{"rec":"undo_intent","op":1}"#.to_owned(),
            r#"{"rec":"undo_done","op":1,"outcome":{"kind":"Restored"}}"#.to_owned(),
            r#"{"rec":"undo_done","op":3,"outcome":{"kind":"NothingToUndo"}}"#.to_owned(),
            r#"{"rec":"undo_done","op":2,"outcome":{"kind":"Failed","code":"Os","os_error":1392,"detail":"x"}}"#.to_owned(),
            r#"{"rec":"undo_conflict","op":2,"conflict":{"kind":"BackupTampered"}}"#.to_owned(),
            r#"{"rec":"undo_conflict","op":2,"conflict":{"kind":"GateBlocked","blocker":{"kind":"DenyListed","rule":"fs.purge"}},"detail":"the path is protected now"}"#.to_owned(),
            r#"{"rec":"reconcile","at":134078999990000000,"op":5,"result":{"kind":"Completed"}}"#.to_owned(),
            r#"{"rec":"reconcile","at":2,"op":5,"result":{"kind":"Retried","outcome":{"kind":"Vanished"}}}"#.to_owned(),
            r#"{"rec":"expire","at":134104041020000000,"op":1,"class":"Quarantine","bytes":1048576}"#.to_owned(),
        ]
    }

    /// Lines of the record kinds and variants added after the first journals were written: the
    /// `settings` and `retry_intent` records, `Refused` facts, and the reconcile results that end a
    /// pending boot move.
    fn added_lines() -> Vec<String> {
        vec![
            r#"{"rec":"settings","user_sid":"S-1-5-21-1-2-3-1001","long_names_resolved":true,"key_limit":10000,"restore_point":"HighRiskOnly"}"#.to_owned(),
            r#"{"rec":"settings","long_names_resolved":false,"key_limit":1,"restore_point":"Off"}"#.to_owned(),
            r#"{"rec":"validated","op":7,"item":"c-07","target":{"type":"Path","path":"C:\\Windows\\x"},"facts":{"kind":"Refused","blocker":{"kind":"DenyListed","rule":"fs.windows"},"reason":"live.deny-listed"},"exemptions":{"proven_owned_skeleton":false,"environment_segment_edit":false,"tier_a_start_menu_entry":false,"long_names_resolved":false}}"#.to_owned(),
            r#"{"rec":"validated","op":8,"item":"c-08","target":{"type":"Path","path":"C:\\x"},"facts":{"kind":"Refused","reason":"gate.open-failed","os_error":5},"exemptions":{"proven_owned_skeleton":false,"environment_segment_edit":false,"tier_a_start_menu_entry":false,"long_names_resolved":false}}"#.to_owned(),
            r#"{"rec":"retry_intent","at":3,"op":2}"#.to_owned(),
            r#"{"rec":"reconcile","at":4,"op":3,"result":{"kind":"NotMoved","code":"VerifyFailed","detail":"still in place"}}"#.to_owned(),
            r#"{"rec":"reconcile","at":4,"op":3,"result":{"kind":"MismatchKept","code":"InUse","os_error":32}}"#.to_owned(),
            r#"{"rec":"reconcile","at":4,"op":3,"result":{"kind":"Lost"}}"#.to_owned(),
            r#"{"rec":"undo_conflict","op":2,"conflict":{"kind":"ParentMissing"},"detail":"C:\\A is gone"}"#.to_owned(),
            r#"{"rec":"undo_plan","at":5,"ops":[6,2,1]}"#.to_owned(),
            r#"{"rec":"undo_plan","at":6,"ops":[]}"#.to_owned(),
        ]
    }

    /// Documents written before the additions read unchanged, and the additions round-trip without
    /// changing the encoding of anything older.
    #[test]
    fn added_records_round_trip_and_old_lines_are_unchanged() {
        for line in added_lines() {
            let record: Record =
                serde_json::from_str(&line).unwrap_or_else(|e| panic!("{line}: {e}"));
            assert_eq!(serde_json::to_string(&record).unwrap(), line);
            assert_eq!(record.op().is_some(), line.contains(r#","op":"#), "{line}");
        }
        // A header of the first version has no settings field and reads exactly as before.
        let header = sample_journal().remove(0);
        assert!(!header.contains("settings"));
        let record: Record = serde_json::from_str(&header).unwrap();
        assert_eq!(serde_json::to_string(&record).unwrap(), header);

        let facts = |line: &str| match serde_json::from_str::<Record>(line).unwrap() {
            Record::Validated(v) => v.facts,
            other => panic!("{other:?}"),
        };
        let lines = added_lines();
        assert!(!facts(&lines[2]).is_actionable());
        assert!(!ItemFacts::Absent.is_actionable());
        assert!(ItemFacts::Package.is_actionable());
        let results: Vec<ReconcileResult> = lines[5..8]
            .iter()
            .map(|line| match serde_json::from_str::<Record>(line).unwrap() {
                Record::Reconcile(r) => r.result,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            results
                .iter()
                .map(ReconcileResult::needs_attention)
                .collect::<Vec<_>>(),
            [false, true, true]
        );
        assert!(!ReconcileResult::Completed.needs_attention());

        // Fields the additions require are required.
        for bad in [
            r#"{"rec":"settings","key_limit":1,"restore_point":"Off"}"#,
            r#"{"rec":"settings","long_names_resolved":true,"key_limit":1,"restore_point":"Sometimes"}"#,
            r#"{"rec":"retry_intent","op":2}"#,
            r#"{"rec":"retry_intent","at":3,"op":0}"#,
            r#"{"rec":"reconcile","at":4,"op":3,"result":{"kind":"NotMoved"}}"#,
            r#"{"kind":"Refused"}"#,
            r#"{"rec":"undo_plan","ops":[1]}"#,
            r#"{"rec":"undo_plan","at":5}"#,
            r#"{"rec":"undo_plan","at":5,"ops":[0]}"#,
        ] {
            assert!(
                serde_json::from_str::<Record>(bad).is_err()
                    && serde_json::from_str::<ItemFacts>(bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn every_record_round_trips_byte_for_byte() {
        let mut seen = Vec::new();
        for line in sample_journal() {
            let record: Record =
                serde_json::from_str(&line).unwrap_or_else(|e| panic!("{line}: {e}"));
            assert_eq!(serde_json::to_string(&record).unwrap(), line);
            assert!(
                line.starts_with(&format!(r#"{{"rec":"{}""#, record.name())),
                "{line}"
            );
            assert!(!line.contains('\n'));
            assert_eq!(record.op().is_some(), line.contains(r#","op":"#), "{line}");
            if !seen.contains(&record.name()) {
                seen.push(record.name());
            }
        }
        assert_eq!(
            seen,
            [
                "header",
                "validated",
                "intent",
                "done",
                "group_end",
                "commit",
                "aborted",
                "undo_intent",
                "undo_done",
                "undo_conflict",
                "reconcile",
                "expire"
            ]
        );
    }

    #[test]
    fn every_enum_value_round_trips() {
        fn all<T: Serialize + for<'de> Deserialize<'de>>(texts: &[&str]) {
            for text in texts {
                let value: T = serde_json::from_str(text).unwrap_or_else(|e| panic!("{text}: {e}"));
                assert_eq!(&serde_json::to_string(&value).unwrap(), text);
            }
        }
        all::<AbortReason>(&[
            r#""BackupWriteFailed""#,
            r#""JournalWriteFailed""#,
            r#""StorageIntegrity""#,
            r#""Cancelled""#,
            r#""RolledBack""#,
        ]);
        all::<UndoOutcome>(&[
            r#"{"kind":"Restored"}"#,
            r#"{"kind":"AlreadyRestored"}"#,
            r#"{"kind":"NothingToUndo"}"#,
            r#"{"kind":"Failed","code":"Internal"}"#,
        ]);
        all::<UndoConflict>(&[
            r#"{"kind":"BackupTampered"}"#,
            r#"{"kind":"BackupMissing"}"#,
            r#"{"kind":"Expired"}"#,
            r#"{"kind":"QuarantineMissing"}"#,
            r#"{"kind":"FileIdMismatch"}"#,
            r#"{"kind":"DestinationExists"}"#,
            r#"{"kind":"KeyExists"}"#,
            r#"{"kind":"ValueDiffers"}"#,
            r#"{"kind":"ValueChanged"}"#,
            r#"{"kind":"GateBlocked","blocker":{"kind":"ReparseMismatch"}}"#,
            r#"{"kind":"Irreversible"}"#,
            r#"{"kind":"ParentMissing"}"#,
        ]);
        all::<ReconcileResult>(&[
            r#"{"kind":"Completed"}"#,
            r#"{"kind":"MismatchMovedBack"}"#,
            r#"{"kind":"StillPending"}"#,
            r#"{"kind":"Cancelled"}"#,
            r#"{"kind":"Retried","outcome":{"kind":"HeldRetry"}}"#,
            r#"{"kind":"NotMoved","code":"VerifyFailed"}"#,
            r#"{"kind":"MismatchKept","code":"Internal","detail":"x"}"#,
            r#"{"kind":"Lost"}"#,
        ]);
        all::<RestorePointPolicy>(&[r#""Off""#, r#""HighRiskOnly""#, r#""Always""#]);
        all::<ItemFacts>(&[
            r#"{"kind":"Absent"}"#,
            r#"{"kind":"Refused","reason":"exec.unsupported"}"#,
            r#"{"kind":"Refused","blocker":{"kind":"CannotBackUp"},"reason":"exec.unsupported"}"#,
        ]);
    }

    #[test]
    fn header_refuses_other_schema_ids() {
        let header = sample_journal().remove(0);
        assert!(serde_json::from_str::<Record>(&header).is_ok());
        for other in ["purge.journal/0", "purge.journal/2", "purge.plan/0", ""] {
            let changed = header.replace("purge.journal/1", other);
            assert!(serde_json::from_str::<Record>(&changed).is_err(), "{other}");
        }
        let without = header.replace(r#""schema":"purge.journal/1","#, "");
        assert!(serde_json::from_str::<Record>(&without).is_err());
    }

    #[test]
    fn malformed_records_are_refused() {
        for bad in [
            r#"{}"#,
            r#"{"op":1}"#,
            r#"{"rec":"Intent","op":1}"#,
            r#"{"rec":"finished"}"#,
            r#"{"rec":"done","op":1,"item":"c-01"}"#,
            r#"{"rec":"done","op":-1,"item":"c-01","outcome":{"kind":"Done"}}"#,
            r#"{"rec":"done","op":1,"item":"c-01","outcome":{"kind":"Maybe"}}"#,
            r#"{"rec":"group_end","group":1}"#,
            r#"{"rec":"expire","at":1,"op":1,"class":"Everything","bytes":1}"#,
            r#"{"rec":"undo_conflict","op":2,"conflict":"BackupTampered"}"#,
            r#"[]"#,
            r#""intent""#,
        ] {
            assert!(serde_json::from_str::<Record>(bad).is_err(), "{bad}");
        }
        // A session id that is not one is refused where it is read.
        let header = sample_journal().remove(0).replace(ID, r"..\\..\\x");
        assert!(serde_json::from_str::<Record>(&header).is_err());
    }

    /// The contract the rig's swap helper relies on (docs/M2_DESIGN.json, cross-package notes): the intent
    /// line of an item holds the JSON-escaped item path and the text `intent`, and no earlier line of the
    /// run holds both.
    #[test]
    fn intent_line_is_the_first_with_path_and_the_word_intent() {
        let escaped = serde_json::to_string(ITEM_PATH).unwrap();
        let escaped = escaped.trim_matches('"');
        assert_eq!(escaped, r"C:\\Program Files\\Vendor App\\app.exe");

        let lines = sample_journal();
        let hits = |line: &String| line.contains(escaped) && line.to_lowercase().contains("intent");
        let first = lines.iter().position(hits).unwrap();
        assert!(
            lines[first].starts_with(r#"{"rec":"intent","op":1,"#),
            "{}",
            lines[first]
        );
        // The header and the validated records come before it and name the path, without the word.
        assert!(first >= 2);
        assert!(lines[..first].iter().any(|line| line.contains(escaped)));

        // No record other than the three write-ahead kinds spells the word through its own field names
        // or values, and of those only `intent` names a path.
        for line in lines.iter().chain(&added_lines()) {
            let record: Record = serde_json::from_str(line).unwrap();
            let is_intent_kind = matches!(
                record,
                Record::Intent(_) | Record::UndoIntent(_) | Record::RetryIntent(_)
            );
            assert_eq!(
                line.to_lowercase().contains("intent"),
                is_intent_kind,
                "{line}"
            );
        }
    }

    #[test]
    fn intent_lists_its_backups_and_checks_itself() {
        let lines = sample_journal();
        let intents: Vec<Intent> = lines
            .iter()
            .filter_map(|line| match serde_json::from_str::<Record>(line).unwrap() {
                Record::Intent(intent) => Some(intent),
                _ => None,
            })
            .collect();
        assert_eq!(intents.len(), 3);
        let paths =
            |intent: &Intent| -> Vec<String> { intent.backups().map(|b| b.path.clone()).collect() };
        assert!(paths(&intents[0]).is_empty());
        assert_eq!(paths(&intents[1]), [r"reg\000002.regbackup.json"]);
        assert_eq!(paths(&intents[2]), [r"def\000005.json"]);
        for intent in &intents {
            assert!(intent.is_consistent(), "{intent:?}");
        }

        // An inverse of the wrong kind, or a backup outside the session, makes the record inconsistent.
        let mut wrong_inverse = intents[1].clone();
        wrong_inverse.inverse = Inverse::None;
        assert!(!wrong_inverse.is_consistent());
        let mut outside = intents[1].clone();
        if let Inverse::RestoreKeyTree { backup } = &mut outside.inverse {
            backup.path = r"..\other\000002.regbackup.json".into();
        }
        assert!(!outside.is_consistent());
        let mut absolute = intents[2].clone();
        absolute.definition.as_mut().unwrap().path = r"C:\def\000005.json".into();
        assert!(!absolute.is_consistent());
    }

    /// The reviewer's two counter-examples (review S6), and `pre` facts of the wrong kind.
    #[test]
    fn intent_halves_must_address_the_same_item() {
        let hash: Sha256Hex = HASH_A.parse().unwrap();
        let file = |is_dir: bool| {
            ItemFacts::File(FileFacts {
                final_path: r"C:\Users\me\AppData\Local\App".into(),
                file_id: FileIdHex([3; 16]),
                volume_serial: 9,
                reparse_tag: 0,
                attributes: if is_dir { 16 } else { 32 },
                n_links: 1,
                is_dir,
                size: 0,
                tree_entries: None,
                tree_bytes: None,
            })
        };
        let move_intent = |original: &str, quarantine: &str, pre: ItemFacts| Intent {
            op: OpId(1),
            item: CandidateId("c-01".into()),
            exec_op: ExecOp::QuarantineMove {
                path: r"C:\Users\me\AppData\Local\App".into(),
            },
            inverse: Inverse::MoveBack {
                quarantine_path: quarantine.into(),
                original_path: original.into(),
                file_id: FileIdHex([3; 16]),
                volume_serial: 9,
            },
            definition: None,
            pre,
        };
        let q = r"C:\ProgramData\Purge\Quarantine\s\000001\App";
        assert!(move_intent(r"C:\Users\me\AppData\Local\App", q, file(true)).is_consistent());
        // Counter-example 1: the inverse moves something else back, and `pre` says nothing exists.
        let evil = move_intent(
            r"C:\Windows\System32\evil",
            r"C:\Windows\System32\drivers\etc",
            ItemFacts::Absent,
        );
        assert!(evil.inverse.fits(&evil.exec_op));
        assert!(!evil.is_consistent());
        assert!(!move_intent(r"C:\Windows\System32\evil", q, file(true)).is_consistent());
        assert!(
            !move_intent(r"C:\Users\me\AppData\Local\App", q, ItemFacts::Absent).is_consistent()
        );
        // The moved item must be the one the handle showed.
        let mut other_file = move_intent(r"C:\Users\me\AppData\Local\App", q, file(false));
        assert!(other_file.is_consistent());
        if let Inverse::MoveBack { file_id, .. } = &mut other_file.inverse {
            *file_id = FileIdHex([4; 16]);
        }
        assert!(!other_file.is_consistent());
        let mut other_volume = move_intent(r"C:\Users\me\AppData\Local\App", q, file(false));
        if let Inverse::MoveBack { volume_serial, .. } = &mut other_volume.inverse {
            *volume_serial = 10;
        }
        assert!(!other_volume.is_consistent());

        // Counter-example 2: a segment edit of `A`/`Path` whose inverse re-inserts into `B`/`Other`.
        let value = ItemFacts::Value(ValueFacts {
            value_type: 2,
            size: 10,
            data_sha256: hash,
        });
        let edit_intent = |key: &str, name: &str, segment: &str, pre: ItemFacts| Intent {
            op: OpId(2),
            item: CandidateId("c-02".into()),
            exec_op: ExecOp::EditSegment {
                key: r"HKLM\SOFTWARE\A".into(),
                name: "Path".into(),
                segment: r"C:\A\bin".into(),
                index: None,
            },
            inverse: Inverse::ReinsertSegment {
                key: key.into(),
                name: name.into(),
                index: 0,
                segment: segment.into(),
                original_value_hash: hash,
                written_value_hash: hash,
                backup: None,
            },
            definition: None,
            pre,
        };
        assert!(
            edit_intent(r"HKLM\SOFTWARE\A", "Path", r"C:\A\bin", value.clone()).is_consistent()
        );
        let swapped = edit_intent(r"HKLM\SOFTWARE\B", "Other", r"C:\B\bin", value.clone());
        assert!(swapped.inverse.fits(&swapped.exec_op));
        assert!(!swapped.is_consistent());
        for pre in [ItemFacts::Absent, ItemFacts::Package, file(false)] {
            assert!(!edit_intent(r"HKLM\SOFTWARE\A", "Path", r"C:\A\bin", pre).is_consistent());
        }

        // The other ops need their own facts kind too.
        let key_facts = ItemFacts::Key(RegFacts {
            subkeys: 0,
            values: 0,
            is_link: false,
            owner: "S-1-5-32-544".into(),
            last_write_time: FileTime(1),
            tree_sha256: None,
        });
        let backup = BackupRef {
            path: r"reg\000003.regbackup.json".into(),
            sha256: hash,
            bytes: 10,
        };
        let with = |exec_op: ExecOp, inverse: Inverse, pre: ItemFacts| Intent {
            op: OpId(3),
            item: CandidateId("c-03".into()),
            exec_op,
            inverse,
            definition: None,
            pre,
        };
        let key = || r"HKLM\SOFTWARE\K".to_owned();
        let tree = || Inverse::RestoreKeyTree {
            backup: backup.clone(),
        };
        assert!(
            with(
                ExecOp::DeleteKeyTree { key: key() },
                tree(),
                key_facts.clone()
            )
            .is_consistent()
        );
        assert!(!with(ExecOp::DeleteKeyTree { key: key() }, tree(), value.clone()).is_consistent());
        let recreate_key = || Inverse::RecreateKey {
            backup: backup.clone(),
        };
        assert!(
            with(
                ExecOp::DeleteKeyIfEmpty { key: key() },
                recreate_key(),
                key_facts.clone()
            )
            .is_consistent()
        );
        assert!(
            !with(
                ExecOp::DeleteKeyIfEmpty { key: key() },
                recreate_key(),
                ItemFacts::Absent
            )
            .is_consistent()
        );
        let delete_value = || ExecOp::DeleteValue {
            key: key(),
            name: "v".into(),
        };
        let restore_value = || Inverse::RestoreValue {
            backup: backup.clone(),
        };
        assert!(with(delete_value(), restore_value(), value.clone()).is_consistent());
        assert!(!with(delete_value(), restore_value(), key_facts.clone()).is_consistent());
        let package = || ExecOp::RemovePackage {
            full_name: "V.A_1.0.0.0_x64__abc".into(),
        };
        assert!(with(package(), Inverse::None, ItemFacts::Package).is_consistent());
        assert!(!with(package(), Inverse::None, ItemFacts::Absent).is_consistent());
        // Removing a directory if empty needs facts of a directory, at the same path.
        let rmdir = || ExecOp::RemoveDirIfEmpty {
            path: r"C:\Users\me\AppData\Local\App".into(),
        };
        let recreate_dir = |path: &str| Inverse::RecreateDir {
            path: path.into(),
            attributes: 16,
            sddl: "O:BAG:SYD:".into(),
            creation_time: None,
            last_write_time: None,
        };
        assert!(
            with(
                rmdir(),
                recreate_dir(r"C:\Users\me\AppData\Local\App"),
                file(true)
            )
            .is_consistent()
        );
        assert!(
            !with(
                rmdir(),
                recreate_dir(r"C:\Users\me\AppData\Local\App"),
                file(false)
            )
            .is_consistent()
        );
        assert!(!with(rmdir(), recreate_dir(r"C:\Windows"), file(true)).is_consistent());
    }

    /// Undo reads the exemptions back from the `validated` record (review S4); a record without them
    /// does not read.
    #[test]
    fn validated_records_carry_the_exemptions() {
        let lines = sample_journal();
        let exemptions: Vec<GateExemptions> = lines
            .iter()
            .filter_map(|line| match serde_json::from_str::<Record>(line).unwrap() {
                Record::Validated(v) => Some(v.exemptions),
                _ => None,
            })
            .collect();
        assert_eq!(exemptions.len(), 6);
        assert!(exemptions[0].long_names_resolved && !exemptions[0].tier_a_start_menu_entry);
        assert!(exemptions[1].proven_owned_skeleton);
        assert_eq!(exemptions[2], GateExemptions::default());
        assert!(exemptions[3].tier_a_start_menu_entry && exemptions[3].long_names_resolved);
        assert!(exemptions[5].environment_segment_edit);

        let first = &lines[1];
        let start = first.find(r#","exemptions":"#).unwrap();
        let without = format!("{}}}", &first[..start]);
        assert!(
            serde_json::from_str::<Record>(&without).is_err(),
            "{without}"
        );
        let partial = first.replace(r#""long_names_resolved":true"#, "");
        assert!(serde_json::from_str::<Record>(&partial).is_err());
    }

    /// Group numbers count from 1 and a group holds 1 to 64 intents (review M4).
    #[test]
    fn group_end_counters_are_in_range() {
        for good in [
            r#"{"rec":"group_end","group":1,"ops":1}"#,
            r#"{"rec":"group_end","group":4294967295,"ops":64}"#,
        ] {
            let record: Record = serde_json::from_str(good).unwrap();
            assert_eq!(serde_json::to_string(&record).unwrap(), good);
        }
        for bad in [
            r#"{"rec":"group_end","group":0,"ops":9999}"#,
            r#"{"rec":"group_end","group":0,"ops":1}"#,
            r#"{"rec":"group_end","group":1,"ops":0}"#,
            r#"{"rec":"group_end","group":1,"ops":65}"#,
            r#"{"rec":"group_end","group":1,"ops":-1}"#,
            r#"{"rec":"done","op":0,"item":"c-01","outcome":{"kind":"Done"}}"#,
            r#"{"rec":"undo_intent","op":0}"#,
        ] {
            assert!(serde_json::from_str::<Record>(bad).is_err(), "{bad}");
        }
        let schema = serde_json::to_string(&schemars::schema_for!(GroupEnd)).unwrap();
        assert!(schema.contains(r#""maximum":64"#), "{schema}");
    }

    #[test]
    fn json_schema_is_generated() {
        let text = serde_json::to_string(&schemars::schema_for!(Record)).unwrap();
        for name in [
            r#""const":"purge.journal/1""#,
            "undo_conflict",
            "group_end",
            "selection_hash",
            "final_path",
            "n_links",
            "data_sha256",
            "MismatchMovedBack",
            "QuarantineMove",
            "RestoreKeyTree",
            "BackupTampered",
            "RolledBack",
            "retry_intent",
            "key_limit",
            "ParentMissing",
            "MismatchKept",
            "Refused",
        ] {
            assert!(text.contains(name), "schema lacks {name}");
        }
        assert_eq!(MAX_GROUP_INTENTS, 64);
    }
}
