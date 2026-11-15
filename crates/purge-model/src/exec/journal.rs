//! Journal records of `purge.journal/1` (ENGINE_PLAN.md §7.8).
//!
//! A session's `journal.jsonl` holds one [`Record`] per line, each a JSON object tagged by `"rec"`. The
//! first line is the [`Header`], which carries the schema id; a journal of another version does not parse.
//!
//! The order of a run is: `header`, one `validated` per selected item, then per item `intent` (flushed
//! before the action) and `done`, with a `group_end` after at most 64 intents, and at the end `commit` or
//! `aborted`. An item that is decided before any backup is taken (already gone, refused by a gate) gets a
//! `done` with no `intent`; see [`ItemOutcome::allowed_without_intent`]. Later runs append `undo_intent`,
//! `undo_done`, `undo_conflict`, `reconcile` and `expire` records.
//!
//! This module only defines the records. Writing, flushing and reading them back, with the rule for a
//! torn last line, is `purge-exec`'s job.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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

    /// Whether the record hangs together: the inverse is the kind that undoes the op, and every backup
    /// path stays inside the session directory. A reader refuses a journal with an intent that fails this.
    pub fn is_consistent(&self) -> bool {
        self.inverse.fits(&self.exec_op) && self.backups().all(BackupRef::is_session_relative)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct GroupEnd {
    /// Number of the group, counted from 1.
    pub group: u32,
    /// How many intent records the group holds: 1 to [`MAX_GROUP_INTENTS`]. The field is not called
    /// `intents` so that only the two intent records spell that word in a journal line.
    pub ops: u32,
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
    /// A held item was tried again, with this outcome.
    Retried {
        /// The outcome of the new attempt.
        outcome: ItemOutcome,
    },
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
/// `validated`, `intent`, `done`, `group_end`, `commit`, `aborted`, `undo_intent`, `undo_done`,
/// `undo_conflict`, `reconcile`, `expire`.
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
}

impl Record {
    /// The record's name as serialised in `"rec"`.
    pub fn name(&self) -> &'static str {
        match self {
            Record::Header(_) => "header",
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
            Record::Header(_) | Record::GroupEnd(_) | Record::Commit(_) | Record::Aborted(_) => {
                None
            }
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
        vec![
            format!(
                r#"{{"rec":"header","schema":"purge.journal/1","session":"{ID}","created":134078121020000000,"engine_version":"0.1.0","app":"vendor-app","plan_hash":"{HASH_A}","selection_hash":"{HASH_B}","policy_version":"m1a.6","mode":"post","items":3,"allow_irreversible":false,"volumes":[{{"root":"C:\\","serial":13902625541364831864,"file_system":"NTFS","quarantine":"C:\\ProgramData\\Purge\\Quarantine\\{ID}"}}]}}"#
            ),
            format!(
                r#"{{"rec":"validated","op":1,"item":"c-01","target":{{"type":"Path","path":"C:\\Program Files\\Vendor App\\app.exe"}},"facts":{file_facts}}}"#
            ),
            r#"{"rec":"validated","op":2,"item":"c-02","target":{"type":"RegKey","path":"HKLM\\SOFTWARE\\Vendor"},"facts":{"kind":"Key","subkeys":2,"values":5,"is_link":false,"owner":"S-1-5-32-544","last_write_time":134078000000000000}}"#.to_owned(),
            format!(
                r#"{{"rec":"validated","op":3,"item":"c-03","target":{{"type":"RegValue","path":"HKLM\\SOFTWARE\\Other","name":""}},"facts":{{"kind":"Value","type":2,"size":38,"data_sha256":"{HASH_B}"}}}}"#
            ),
            r#"{"rec":"validated","op":4,"item":"c-04","target":{"type":"Path","path":"C:\\Program Files\\Vendor App"},"facts":{"kind":"File","final_path":"C:\\Program Files\\Vendor App","file_id":"ffffffffffffffffffffffffffffffff","volume_serial":1,"reparse_tag":0,"attributes":16,"n_links":1,"is_dir":true,"size":0,"tree_entries":12,"tree_bytes":4096}}"#.to_owned(),
            r#"{"rec":"validated","op":5,"item":"c-05","target":{"type":"AppxPackage","full_name":"Vendor.App_1.0.0.0_x64__abc"},"facts":{"kind":"Package"}}"#.to_owned(),
            r#"{"rec":"validated","op":6,"item":"c-06","target":{"type":"RegKey","path":"HKLM\\SOFTWARE\\Gone"},"facts":{"kind":"Absent"}}"#.to_owned(),
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
        ]);
        all::<ReconcileResult>(&[
            r#"{"kind":"Completed"}"#,
            r#"{"kind":"MismatchMovedBack"}"#,
            r#"{"kind":"StillPending"}"#,
            r#"{"kind":"Cancelled"}"#,
            r#"{"kind":"Retried","outcome":{"kind":"HeldRetry"}}"#,
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

        // No record other than the two intent kinds spells the word through its own field names or
        // values.
        for line in &lines {
            let record: Record = serde_json::from_str(line).unwrap();
            let is_intent_kind = matches!(record, Record::Intent(_) | Record::UndoIntent(_));
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
        ] {
            assert!(text.contains(name), "schema lacks {name}");
        }
        assert_eq!(MAX_GROUP_INTENTS, 64);
    }
}
