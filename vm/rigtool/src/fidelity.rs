//! `rigtool fidelity`: compares two deep snapshots (before execute, after undo) over the ENGINE_PLAN.md §10.3
//! fields and reports, per executor action type, how many objects came back identical.
//!
//! Compared: every field `deep` records, except the §10.3 exclusions: registry LastWriteTime, file and
//! directory LastWriteTime (parent directories change when a child moves), 8.3 names, and the ambient set.
//! FileId and volume serial are compared only for objects that the journal says were renamed (a quarantine move
//! of the object or of a directory above it); a directory recreated by undo has a new FileId by design.
//!
//! Attribution: each object goes to the journal op that covers it (exact value ops first, then ops that ran
//! (effective outcome Done, PendingReboot, HeldRetry or none) before the others, then the deepest target).
//! Objects of ops that never got an intent record form the "not executed" row; objects no op covers form the
//! "outside plan" row: parents and siblings, which must not change either.
//!
//! The journal is read by [`journal::parse_journal`], shared with `execdiff`.

use crate::ambient::AmbientSet;
use crate::canon;
use crate::deep::{self, DeepDoc, FileRec, KeyRec, ValueRec};
use crate::err::{Context, Result, bail};
use crate::jsonio;
use crate::target::Target;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

pub use journal::{JOp, parse_journal};

pub const SCHEMA: &str = "purge.rig.fidelity/1";

/// Row labels, in report order.
pub const ROWS: &[&str] = &[
    "QuarantineMove file",
    "QuarantineMove dir",
    "RemoveDirIfEmpty",
    "DeleteKeyTree",
    "DeleteKeyIfEmpty",
    "DeleteValue",
    "EditSegment",
    "DeleteService",
    "DeleteTask",
    "DeleteFirewallRule",
    "RemovePackage",
    NOT_EXECUTED,
    OUTSIDE,
];
pub const OUTSIDE: &str = "outside plan";
/// Ops that ended without an intent record (refused by a gate, already gone, failed before any backup).
pub const NOT_EXECUTED: &str = "not executed";
/// Ops of items the run left quarantined on purpose (`--keep-items`, e.g. the m2-traps expiry item): reported, not
/// compared.
pub const KEPT: &str = "kept quarantined";

/// Fields never compared (documented in the report).
pub const EXCLUDED: &[&str] = &[
    "file.last_write (incl. parent directories)",
    "file.short_name (8.3)",
    "file.file_id, file.volume_serial unless renamed by a journal op",
    "key.last_write",
    "objects in the ambient set",
];
const FILE_META: &[&str] = &["path", "typed", "last_write", "short_name"];
const FILE_ID_FIELDS: &[&str] = &["file_id", "volume_serial"];
const KEY_META: &[&str] = &["key", "typed", "last_write", "values", "only_values", "omitted"];
const VALUE_META: &[&str] = &["name"];

pub struct FidelityArgs {
    pub before: PathBuf,
    pub after: PathBuf,
    pub journal: PathBuf,
    pub ambient: Option<PathBuf>,
    pub sid: Option<String>,
    /// Item ids whose ops the run did not undo on purpose (row `kept quarantined`, not compared).
    pub keep_items: Vec<String>,
    pub out: PathBuf,
}

// ---------------------------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------------------------

/// Reader of a session's `journal.jsonl` (`purge.journal/1`, purge-model `exec::journal::Record`), shared by
/// `fidelity` and `execdiff`. rigtool does not link purge-model: the record types below mirror its serde
/// shapes (records tagged by `"rec"` in snake case; ExecOp, Inverse, ItemOutcome, SkipReason, ItemFacts and the
/// undo / reconcile results tagged by `"kind"`), with every required field required here too.
///
/// Strict: the first line must be the header with the exact schema id; every line must parse as a record;
/// a `validated` record must precede the `intent` and `done` of its op; an intent's inverse must fit its op;
/// `Done`, `HeldRetry` and `PendingReboot` need an intent before them. The one tolerance is a torn final line
/// (the file does not end with a newline and the last line is an incomplete JSON text), which is reported as a
/// warning and ignored.
pub mod journal {
    use crate::canon;
    use crate::err::{Result, bail};
    use crate::target::Target;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    pub const JOURNAL_SCHEMA: &str = "purge.journal/1";

    /// purge-model `ExecOp`.
    #[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
    #[serde(tag = "kind")]
    pub enum ExecOp {
        QuarantineMove {
            path: String,
        },
        RemoveDirIfEmpty {
            path: String,
        },
        DeleteKeyTree {
            key: String,
        },
        DeleteKeyIfEmpty {
            key: String,
        },
        DeleteValue {
            key: String,
            name: String,
        },
        EditSegment {
            key: String,
            name: String,
            segment: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            index: Option<u32>,
        },
        RemovePackage {
            full_name: String,
        },
    }

    impl ExecOp {
        pub fn name(&self) -> &'static str {
            match self {
                ExecOp::QuarantineMove { .. } => "QuarantineMove",
                ExecOp::RemoveDirIfEmpty { .. } => "RemoveDirIfEmpty",
                ExecOp::DeleteKeyTree { .. } => "DeleteKeyTree",
                ExecOp::DeleteKeyIfEmpty { .. } => "DeleteKeyIfEmpty",
                ExecOp::DeleteValue { .. } => "DeleteValue",
                ExecOp::EditSegment { .. } => "EditSegment",
                ExecOp::RemovePackage { .. } => "RemovePackage",
            }
        }

        /// The target the op acts on (purge-model `ExecOp::target`).
        pub fn target(&self) -> Target {
            match self.clone() {
                ExecOp::QuarantineMove { path } | ExecOp::RemoveDirIfEmpty { path } => Target::Path { path },
                ExecOp::DeleteKeyTree { key } | ExecOp::DeleteKeyIfEmpty { key } => Target::RegKey { path: key },
                ExecOp::DeleteValue { key, name } => Target::RegValue { path: key, name },
                ExecOp::EditSegment { key, name, segment, .. } => {
                    Target::RegMultiSzSegment { path: key, name, segment }
                }
                ExecOp::RemovePackage { full_name } => Target::AppxPackage { full_name },
            }
        }
    }

    /// purge-model `Blocker`: an object tagged by `"kind"`; other fields are kept as they are.
    #[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
    pub struct Blocker {
        pub kind: String,
        #[serde(flatten)]
        pub fields: serde_json::Map<String, serde_json::Value>,
    }

    /// purge-model `SkipReason`.
    #[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
    #[serde(tag = "kind")]
    pub enum SkipReason {
        ChangedSinceScan,
        NoLongerEmpty,
        GateBlocked { blocker: Blocker },
        NoVerifiedBackup,
        CapExceeded,
        NotAttempted,
    }

    /// purge-model `ItemOutcome`.
    #[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
    #[serde(tag = "kind")]
    pub enum Outcome {
        Done,
        Vanished,
        Skipped {
            reason: SkipReason,
        },
        HeldRetry,
        PendingReboot,
        Failed {
            code: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            os_error: Option<u32>,
            #[serde(default, skip_serializing_if = "String::is_empty")]
            detail: String,
        },
    }

    impl Outcome {
        pub fn name(&self) -> &'static str {
            match self {
                Outcome::Done => "Done",
                Outcome::Vanished => "Vanished",
                Outcome::Skipped { .. } => "Skipped",
                Outcome::HeldRetry => "HeldRetry",
                Outcome::PendingReboot => "PendingReboot",
                Outcome::Failed { .. } => "Failed",
            }
        }
        /// The skip reason's kind (Skipped only).
        pub fn reason(&self) -> Option<&'static str> {
            match self {
                Outcome::Skipped { reason } => Some(match reason {
                    SkipReason::ChangedSinceScan => "ChangedSinceScan",
                    SkipReason::NoLongerEmpty => "NoLongerEmpty",
                    SkipReason::GateBlocked { .. } => "GateBlocked",
                    SkipReason::NoVerifiedBackup => "NoVerifiedBackup",
                    SkipReason::CapExceeded => "CapExceeded",
                    SkipReason::NotAttempted => "NotAttempted",
                }),
                _ => None,
            }
        }
        /// The blocker's kind (Skipped / GateBlocked only).
        pub fn blocker(&self) -> Option<&str> {
            match self {
                Outcome::Skipped { reason: SkipReason::GateBlocked { blocker } } => Some(&blocker.kind),
                _ => None,
            }
        }
        /// `Done`, `Skipped/GateBlocked/RegLink`, ...
        pub fn summary(&self) -> String {
            let mut s = self.name().to_string();
            for x in [self.reason(), self.blocker()].into_iter().flatten() {
                s.push('/');
                s.push_str(x);
            }
            s
        }
        /// purge-model `ItemOutcome::allowed_without_intent`.
        pub fn allowed_without_intent(&self) -> bool {
            matches!(self, Outcome::Vanished | Outcome::Skipped { .. } | Outcome::Failed { .. })
        }
    }

    /// purge-model `BackupRef`.
    #[derive(Deserialize, Clone, Debug, PartialEq)]
    pub struct BackupRef {
        pub path: String,
        pub sha256: String,
        pub bytes: u64,
    }

    /// purge-model `Inverse`.
    #[derive(Deserialize, Clone, Debug, PartialEq)]
    #[serde(tag = "kind")]
    #[allow(dead_code)] // fields are read to check the record's shape
    pub enum Inverse {
        MoveBack {
            quarantine_path: String,
            original_path: String,
            file_id: String,
            volume_serial: u64,
        },
        RestoreKeyTree {
            backup: BackupRef,
        },
        RestoreValue {
            backup: BackupRef,
        },
        ReinsertSegment {
            key: String,
            name: String,
            index: u32,
            segment: String,
            original_value_hash: String,
            written_value_hash: String,
            #[serde(default)]
            backup: Option<BackupRef>,
        },
        RecreateDir {
            path: String,
            attributes: u32,
            sddl: String,
            #[serde(default)]
            creation_time: Option<u64>,
            #[serde(default)]
            last_write_time: Option<u64>,
        },
        RecreateKey {
            backup: BackupRef,
        },
        None,
    }

    impl Inverse {
        /// purge-model `Inverse::fits`.
        pub fn fits(&self, op: &ExecOp) -> bool {
            matches!(
                (op, self),
                (ExecOp::QuarantineMove { .. }, Inverse::MoveBack { .. })
                    | (ExecOp::RemoveDirIfEmpty { .. }, Inverse::RecreateDir { .. })
                    | (ExecOp::DeleteKeyTree { .. }, Inverse::RestoreKeyTree { .. })
                    | (ExecOp::DeleteKeyIfEmpty { .. }, Inverse::RecreateKey { .. })
                    | (ExecOp::DeleteValue { .. }, Inverse::RestoreValue { .. })
                    | (ExecOp::EditSegment { .. }, Inverse::ReinsertSegment { .. })
                    | (ExecOp::RemovePackage { .. }, Inverse::None)
            )
        }
    }

    /// purge-model `ItemFacts`.
    #[derive(Deserialize, Clone, Debug, PartialEq)]
    #[serde(tag = "kind")]
    #[allow(dead_code)] // fields are read to check the record's shape
    pub enum Facts {
        File {
            final_path: String,
            file_id: String,
            volume_serial: u64,
            reparse_tag: u32,
            attributes: u32,
            n_links: u32,
            is_dir: bool,
            size: u64,
            #[serde(default)]
            tree_entries: Option<u64>,
            #[serde(default)]
            tree_bytes: Option<u64>,
        },
        Key {
            subkeys: u32,
            values: u32,
            is_link: bool,
            owner: String,
            last_write_time: u64,
        },
        Value {
            #[serde(rename = "type")]
            value_type: u32,
            size: u32,
            data_sha256: String,
        },
        Package,
        Absent,
        /// The validate pass refused the item (or could not open it); nothing was bound.
        Refused {
            #[serde(default)]
            blocker: Option<Blocker>,
            reason: String,
            #[serde(default)]
            os_error: Option<u32>,
        },
    }

    impl Facts {
        fn is_dir(&self) -> Option<bool> {
            match self {
                Facts::File { is_dir, .. } => Some(*is_dir),
                _ => None,
            }
        }
    }

    /// purge-model `VolumeRecord`.
    #[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
    pub struct Volume {
        pub root: String,
        pub serial: u64,
        pub file_system: String,
        pub quarantine: String,
    }

    /// purge-model `exec::journal::Header`.
    #[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Default)]
    pub struct Header {
        pub schema: String,
        pub session: String,
        pub created: u64,
        pub engine_version: String,
        pub app: String,
        pub plan_hash: String,
        pub selection_hash: String,
        pub policy_version: String,
        pub mode: String,
        pub items: u32,
        pub allow_irreversible: bool,
        pub volumes: Vec<Volume>,
    }

    /// purge-model `OutcomeCounts` (every field defaults to 0).
    #[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
    #[serde(default)]
    pub struct Counts {
        pub done: u32,
        pub vanished: u32,
        pub skipped: u32,
        pub held_retry: u32,
        pub pending_reboot: u32,
        pub failed: u32,
    }

    impl Counts {
        pub fn record(&mut self, o: &Outcome) {
            *match o {
                Outcome::Done => &mut self.done,
                Outcome::Vanished => &mut self.vanished,
                Outcome::Skipped { .. } => &mut self.skipped,
                Outcome::HeldRetry => &mut self.held_retry,
                Outcome::PendingReboot => &mut self.pending_reboot,
                Outcome::Failed { .. } => &mut self.failed,
            } += 1;
        }
    }

    #[derive(Deserialize, Clone, Debug, PartialEq)]
    pub struct Validated {
        pub op: u32,
        pub item: String,
        pub target: Target,
        pub facts: Facts,
    }

    #[derive(Deserialize, Clone, Debug, PartialEq)]
    #[allow(dead_code)] // fields are read to check the record's shape
    pub struct Intent {
        pub op: u32,
        pub item: String,
        pub exec_op: ExecOp,
        pub inverse: Inverse,
        #[serde(default)]
        pub definition: Option<BackupRef>,
        pub pre: Facts,
    }

    #[derive(Deserialize, Clone, Debug, PartialEq)]
    pub struct DoneRec {
        pub op: u32,
        pub item: String,
        pub outcome: Outcome,
        /// Free text the engine adds for a skipped item (engine ceb5999 on; absent before).
        #[serde(default)]
        pub detail: Option<String>,
    }

    #[derive(Deserialize, Clone, Copy, Debug, PartialEq)]
    pub enum AbortReason {
        BackupWriteFailed,
        JournalWriteFailed,
        StorageIntegrity,
        Cancelled,
        RolledBack,
    }

    #[derive(Deserialize, Clone, Copy, Debug, PartialEq)]
    pub enum RetentionClass {
        Quarantine,
        Backup,
        Journal,
    }

    #[derive(Deserialize, Clone, Debug, PartialEq)]
    #[serde(tag = "kind")]
    #[allow(dead_code)] // fields are read to check the record's shape
    pub enum UndoOutcome {
        Restored,
        AlreadyRestored,
        NothingToUndo,
        Failed {
            code: String,
            #[serde(default)]
            os_error: Option<u32>,
            #[serde(default)]
            detail: String,
        },
    }

    #[derive(Deserialize, Clone, Debug, PartialEq)]
    #[serde(tag = "kind")]
    #[allow(dead_code)] // fields are read to check the record's shape
    pub enum UndoConflict {
        BackupTampered,
        BackupMissing,
        Expired,
        QuarantineMissing,
        FileIdMismatch,
        DestinationExists,
        KeyExists,
        ValueDiffers,
        ValueChanged,
        GateBlocked { blocker: Blocker },
        Irreversible,
        ParentMissing,
    }

    /// purge-model `ReconcileResult`.
    #[derive(Deserialize, Clone, Debug, PartialEq)]
    #[serde(tag = "kind")]
    #[allow(dead_code)] // fields are read to check the record's shape
    pub enum ReconcileResult {
        Completed,
        MismatchMovedBack,
        StillPending,
        Cancelled,
        Retried {
            outcome: Outcome,
        },
        /// The boot-time move did not happen: the item stayed where it was.
        NotMoved {
            code: String,
            #[serde(default)]
            os_error: Option<u32>,
            #[serde(default)]
            detail: String,
        },
        /// Something else was in quarantine and could not be moved back.
        MismatchKept {
            code: String,
            #[serde(default)]
            os_error: Option<u32>,
            #[serde(default)]
            detail: String,
        },
        /// Neither at its source nor in quarantine.
        Lost {
            #[serde(default)]
            detail: String,
        },
    }

    /// purge-model `exec::journal::Record`.
    #[derive(Deserialize, Clone, Debug, PartialEq)]
    #[serde(tag = "rec", rename_all = "snake_case")]
    #[allow(dead_code)] // fields are read to check the record's shape
    #[allow(clippy::large_enum_variant)] // read and dropped one line at a time
    pub enum Record {
        Header(Header),
        /// The run's settings, right after the header (absent in older journals).
        Settings {
            #[serde(default)]
            user_sid: Option<String>,
            long_names_resolved: bool,
            key_limit: u64,
            restore_point: String,
        },
        Validated(Validated),
        Intent(Intent),
        Done(DoneRec),
        GroupEnd {
            group: u32,
            ops: u32,
        },
        Commit {
            at: u64,
            counts: Counts,
            backup_bytes: u64,
        },
        Aborted {
            at: u64,
            reason: AbortReason,
            #[serde(default)]
            detail: String,
        },
        UndoIntent {
            op: u32,
        },
        /// The ops an undo run is about to undo, in order, before its first undo record (absent in
        /// older journals).
        UndoPlan {
            at: u64,
            ops: Vec<u32>,
        },
        /// A held op is about to be tried again; its `reconcile` `Retried` follows.
        RetryIntent {
            at: u64,
            op: u32,
        },
        UndoDone {
            op: u32,
            outcome: UndoOutcome,
        },
        UndoConflict {
            op: u32,
            conflict: UndoConflict,
            #[serde(default)]
            detail: String,
        },
        Reconcile {
            at: u64,
            op: u32,
            result: ReconcileResult,
        },
        Expire {
            at: u64,
            op: u32,
            class: RetentionClass,
            bytes: u64,
        },
    }

    /// One op of the session, folded from its records.
    #[derive(Serialize, Clone, Debug, PartialEq)]
    pub struct JOp {
        /// The op id as text (`OpId`).
        pub id: String,
        pub op: u32,
        /// Candidate id of the plan item.
        pub item: String,
        /// ExecOp name from the intent; `None` when the op never got an intent.
        pub kind: Option<String>,
        /// The intent's ExecOp, when there is one.
        pub exec_op: Option<ExecOp>,
        /// From the intent's ExecOp, else the validated target.
        pub target: Option<Target>,
        /// A quarantine move (the object keeps its FileId).
        pub renamed: bool,
        /// From the intent's or the validated record's file facts.
        pub is_dir: Option<bool>,
        /// The `done` record's outcome.
        pub done: Option<Outcome>,
        /// The `done` record's optional `detail` (why an item was skipped).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub done_detail: Option<String>,
        /// Effective outcome name: the done outcome, changed by later reconcile records (Completed -> Done,
        /// StillPending -> PendingReboot, Retried -> its outcome, MismatchMovedBack -> MovedBack, Cancelled ->
        /// Cancelled, NotMoved / MismatchKept / Lost -> that name). `None` = no done record yet.
        pub outcome: Option<String>,
        /// Effective outcome as a purge-model ItemOutcome, when it is one.
        pub effective: Option<Outcome>,
        /// Reconcile results seen, in order.
        pub reconciled: Vec<String>,
        /// Undo records seen for the op (`undo_done:<kind>` / `undo_conflict:<kind>`).
        pub undo: Vec<String>,
        /// Line of the validated record.
        pub line: usize,
    }

    impl JOp {
        /// The effective outcome lets the op's change stand (Done) or says the item was already gone.
        pub fn removed(&self) -> bool {
            matches!(self.outcome.as_deref(), Some("Done" | "Vanished"))
        }
    }

    #[derive(Serialize, Clone, Debug, PartialEq, Default)]
    pub struct Journal {
        pub header: Header,
        pub ops: Vec<JOp>,
        pub committed: bool,
        /// Abort reason, when the run stopped early.
        pub aborted: Option<String>,
        /// The commit record's counts.
        pub commit_counts: Option<Counts>,
        pub undo_records: usize,
        pub reconcile_records: usize,
        pub warnings: Vec<String>,
    }

    impl Journal {
        pub fn op(&self, id: u32) -> Option<&JOp> {
            self.ops.iter().find(|o| o.op == id)
        }
        /// `committed`, `aborted` or `open`.
        pub fn state(&self) -> &'static str {
            if self.committed {
                "committed"
            } else if self.aborted.is_some() {
                "aborted"
            } else {
                "open"
            }
        }
    }

    fn undo_name<T: std::fmt::Debug>(prefix: &str, x: &T) -> String {
        let d = format!("{x:?}");
        let k: String = d.chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
        format!("{prefix}:{k}")
    }

    /// The text of a journal file. A torn final line can end inside a multi-byte character: an incomplete
    /// UTF-8 sequence at the very end is dropped (the torn-line rule then applies); invalid UTF-8 anywhere else
    /// is an error.
    pub fn read_journal_text(path: &std::path::Path) -> Result<String> {
        let b = std::fs::read(path).map_err(|e| crate::err::Error(format!("read {}: {e}", path.display())))?;
        utf8_torn_tail(&b).map_err(|e| crate::err::Error(format!("{}: {e}", path.display())))
    }

    pub fn utf8_torn_tail(b: &[u8]) -> std::result::Result<String, std::str::Utf8Error> {
        let b = b.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(b);
        match std::str::from_utf8(b) {
            Ok(s) => Ok(s.to_string()),
            Err(e) if e.error_len().is_none() && !b.ends_with(b"\n") => {
                Ok(String::from_utf8_lossy(&b[..e.valid_up_to()]).into_owned())
            }
            Err(e) => Err(e),
        }
    }

    /// Reads a journal (see the module comment).
    pub fn parse_journal(text: &str) -> Result<Journal> {
        let mut j = Journal::default();
        let mut idx: HashMap<u32, usize> = HashMap::new();
        let mut have_header = false;
        let parts: Vec<&str> = text.split('\n').collect();
        // `split` yields one empty part after a final newline.
        let n = if text.ends_with('\n') { parts.len() - 1 } else { parts.len() };
        for (i, raw) in parts.iter().take(n).enumerate() {
            let ln = i + 1;
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            let rec: Record = match serde_json::from_str(line) {
                Ok(r) => r,
                Err(e) if i + 1 == n && !text.ends_with('\n') && e.is_eof() => {
                    j.warnings.push(format!("journal line {ln}: torn final record ignored ({e})"));
                    continue;
                }
                Err(e) => bail!("journal line {ln}: {e}"),
            };
            if !have_header {
                let Record::Header(h) = rec else { bail!("journal line {ln}: the first record is not the header") };
                if h.schema != JOURNAL_SCHEMA {
                    bail!("journal line {ln}: schema {:?}, want {JOURNAL_SCHEMA}", h.schema);
                }
                j.header = h;
                have_header = true;
                continue;
            }
            let get = |idx: &HashMap<u32, usize>, op: u32, what: &str| -> Result<usize> {
                match idx.get(&op) {
                    Some(&p) => Ok(p),
                    None => bail!("journal line {ln}: {what} for op {op}, which has no validated record"),
                }
            };
            match rec {
                Record::Header(_) => bail!("journal line {ln}: a second header"),
                Record::Validated(v) => {
                    if idx.contains_key(&v.op) {
                        bail!("journal line {ln}: op {} validated twice", v.op);
                    }
                    idx.insert(v.op, j.ops.len());
                    j.ops.push(JOp {
                        id: v.op.to_string(),
                        op: v.op,
                        item: v.item,
                        kind: None,
                        exec_op: None,
                        target: Some(v.target),
                        renamed: false,
                        is_dir: v.facts.is_dir(),
                        done: None,
                        done_detail: None,
                        outcome: None,
                        effective: None,
                        reconciled: Vec::new(),
                        undo: Vec::new(),
                        line: ln,
                    });
                }
                Record::Intent(x) => {
                    let p = get(&idx, x.op, "intent")?;
                    if !x.inverse.fits(&x.exec_op) {
                        bail!("journal line {ln}: op {}: inverse does not fit {}", x.op, x.exec_op.name());
                    }
                    let o = &mut j.ops[p];
                    if o.item != x.item {
                        bail!("journal line {ln}: op {} intent names item {:?}, validated {:?}", x.op, x.item, o.item);
                    }
                    if o.kind.is_some() {
                        j.warnings
                            .push(format!("journal line {ln}: second intent for op {}; the last one counts", x.op));
                    }
                    let t = x.exec_op.target();
                    if let Some(v) = &o.target
                        && o.kind.is_none()
                        && !canon::ci_eq(&v.canonical(None).canon_string(), &t.canonical(None).canon_string())
                    {
                        j.warnings.push(format!(
                            "journal line {ln}: op {}: exec_op target {} differs from the validated target {}",
                            x.op,
                            t.canon_string(),
                            v.canon_string()
                        ));
                    }
                    o.kind = Some(x.exec_op.name().to_string());
                    o.renamed = matches!(x.exec_op, ExecOp::QuarantineMove { .. });
                    o.is_dir = x.pre.is_dir().or(o.is_dir);
                    o.target = Some(t);
                    o.exec_op = Some(x.exec_op);
                }
                Record::Done(d) => {
                    let p = get(&idx, d.op, "done")?;
                    let o = &mut j.ops[p];
                    if o.item != d.item {
                        bail!("journal line {ln}: op {} done names item {:?}, validated {:?}", d.op, d.item, o.item);
                    }
                    if o.kind.is_none() && !d.outcome.allowed_without_intent() {
                        bail!("journal line {ln}: op {}: outcome {} without an intent", d.op, d.outcome.name());
                    }
                    if o.done.is_some() {
                        j.warnings.push(format!("journal line {ln}: second done for op {}; the last one counts", d.op));
                    }
                    o.outcome = Some(d.outcome.name().to_string());
                    o.effective = Some(d.outcome.clone());
                    o.done = Some(d.outcome);
                    o.done_detail = d.detail;
                    o.reconciled.clear();
                }
                Record::Reconcile { op, result, .. } => {
                    j.reconcile_records += 1;
                    let p = get(&idx, op, "reconcile")?;
                    let o = &mut j.ops[p];
                    let (name, eff): (&str, Option<Outcome>) = match &result {
                        ReconcileResult::Completed => ("Completed", Some(Outcome::Done)),
                        ReconcileResult::StillPending => ("StillPending", Some(Outcome::PendingReboot)),
                        ReconcileResult::Retried { outcome } => ("Retried", Some(outcome.clone())),
                        ReconcileResult::MismatchMovedBack => ("MismatchMovedBack", None),
                        ReconcileResult::Cancelled => ("Cancelled", None),
                        ReconcileResult::NotMoved { .. } => ("NotMoved", None),
                        ReconcileResult::MismatchKept { .. } => ("MismatchKept", None),
                        ReconcileResult::Lost { .. } => ("Lost", None),
                    };
                    o.reconciled.push(name.to_string());
                    o.outcome = Some(match (&eff, &result) {
                        (Some(e), _) => e.name().to_string(),
                        (None, ReconcileResult::MismatchMovedBack) => "MovedBack".to_string(),
                        (None, ReconcileResult::Cancelled) => "Cancelled".to_string(),
                        _ => name.to_string(),
                    });
                    o.effective = eff;
                }
                Record::UndoDone { op, outcome } => {
                    j.undo_records += 1;
                    let p = get(&idx, op, "undo_done")?;
                    j.ops[p].undo.push(undo_name("undo_done", &outcome));
                }
                Record::UndoConflict { op, conflict, .. } => {
                    j.undo_records += 1;
                    let p = get(&idx, op, "undo_conflict")?;
                    j.ops[p].undo.push(undo_name("undo_conflict", &conflict));
                }
                Record::UndoIntent { op } => {
                    j.undo_records += 1;
                    get(&idx, op, "undo_intent")?;
                }
                Record::RetryIntent { op, .. } => {
                    get(&idx, op, "retry_intent")?;
                }
                Record::UndoPlan { ops, .. } => {
                    for op in ops {
                        get(&idx, op, "undo_plan")?;
                    }
                }
                Record::Settings { .. } => {}
                Record::Expire { op, .. } => {
                    get(&idx, op, "expire")?;
                }
                Record::Commit { counts, .. } => {
                    j.committed = true;
                    j.commit_counts = Some(counts);
                }
                Record::Aborted { reason, .. } => j.aborted = Some(format!("{reason:?}")),
                Record::GroupEnd { .. } => {}
            }
        }
        if !have_header {
            bail!("journal has no header");
        }
        if j.ops.len() != j.header.items as usize {
            j.warnings.push(format!(
                "journal: header announces {} items, {} validated records",
                j.header.items,
                j.ops.len()
            ));
        }
        Ok(j)
    }

    /// Journal lines for tests, written the way purge-model serialises its records.
    #[cfg(test)]
    pub mod fixture {
        use serde_json::{Value, json};

        pub const SESSION: &str = "20261115T101502Z-9f3a6c1d2b7e4a50";
        pub const HASH_A: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        pub const HASH_B: &str = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";

        pub fn header(items: usize) -> Value {
            json!({"rec": "header", "schema": "purge.journal/1", "session": SESSION, "created": 134078121020000000u64,
                "engine_version": "0.1.0", "app": "fixture", "plan_hash": HASH_A, "selection_hash": HASH_B,
                "policy_version": "m1a.6", "mode": "post", "items": items, "allow_irreversible": false,
                "volumes": [{"root": "C:\\", "serial": 1, "file_system": "NTFS",
                    "quarantine": format!("C:\\ProgramData\\Purge\\Quarantine\\{SESSION}")}]})
        }

        fn file_facts(path: &str, is_dir: bool) -> Value {
            json!({"kind": "File", "final_path": path, "file_id": "000102030405060708090a0b0c0d0e0f",
                "volume_serial": 1, "reparse_tag": 0, "attributes": if is_dir { 16 } else { 32 }, "n_links": 1,
                "is_dir": is_dir, "size": 0})
        }

        fn key_facts() -> Value {
            json!({"kind": "Key", "subkeys": 0, "values": 1, "is_link": false, "owner": "S-1-5-32-544",
                "last_write_time": 1})
        }

        fn value_facts() -> Value {
            json!({"kind": "Value", "type": 1, "size": 4, "data_sha256": HASH_A})
        }

        fn backup(op: u32) -> Value {
            json!({"path": format!("reg\\{op:06}.regbackup.json"), "sha256": HASH_A, "bytes": 10})
        }

        /// (target, exec_op, inverse, facts) for an ExecOp kind.
        fn parts(op: u32, kind: &str, a: &str, b: &str, c: &str, dir: bool) -> (Value, Value, Value, Value) {
            match kind {
                "QuarantineMove" => (
                    json!({"type": "Path", "path": a}),
                    json!({"kind": kind, "path": a}),
                    json!({"kind": "MoveBack", "quarantine_path": format!("C:\\ProgramData\\Purge\\Quarantine\\{SESSION}\\{op:06}\\x"),
                        "original_path": a, "file_id": "000102030405060708090a0b0c0d0e0f", "volume_serial": 1}),
                    file_facts(a, dir),
                ),
                "RemoveDirIfEmpty" => (
                    json!({"type": "Path", "path": a}),
                    json!({"kind": kind, "path": a}),
                    json!({"kind": "RecreateDir", "path": a, "attributes": 16, "sddl": "O:BAG:SYD:(A;;FA;;;BA)"}),
                    file_facts(a, true),
                ),
                "DeleteKeyTree" => (
                    json!({"type": "RegKey", "path": a}),
                    json!({"kind": kind, "key": a}),
                    json!({"kind": "RestoreKeyTree", "backup": backup(op)}),
                    key_facts(),
                ),
                "DeleteKeyIfEmpty" => (
                    json!({"type": "RegKey", "path": a}),
                    json!({"kind": kind, "key": a}),
                    json!({"kind": "RecreateKey", "backup": backup(op)}),
                    key_facts(),
                ),
                "DeleteValue" => (
                    json!({"type": "RegValue", "path": a, "name": b}),
                    json!({"kind": kind, "key": a, "name": b}),
                    json!({"kind": "RestoreValue", "backup": backup(op)}),
                    value_facts(),
                ),
                "EditSegment" => (
                    json!({"type": "RegMultiSzSegment", "path": a, "name": b, "segment": c}),
                    json!({"kind": kind, "key": a, "name": b, "segment": c}),
                    json!({"kind": "ReinsertSegment", "key": a, "name": b, "index": 1, "segment": c,
                        "original_value_hash": HASH_A, "written_value_hash": HASH_B}),
                    value_facts(),
                ),
                "RemovePackage" => (
                    json!({"type": "AppxPackage", "full_name": a}),
                    json!({"kind": kind, "full_name": a}),
                    json!({"kind": "None"}),
                    json!({"kind": "Package"}),
                ),
                k => panic!("fixture: unknown kind {k}"),
            }
        }

        /// One op: `validated`, then (when `intent`) `intent`, then (when `outcome` is not null) `done`.
        /// `a` is the path or key, `b` the value name, `c` the segment.
        #[allow(clippy::too_many_arguments)]
        pub fn op(
            op: u32,
            kind: &str,
            a: &str,
            b: &str,
            c: &str,
            dir: bool,
            intent: bool,
            outcome: Value,
        ) -> Vec<Value> {
            let item = format!("c-{op:02}");
            let (target, exec_op, inverse, facts) = parts(op, kind, a, b, c, dir);
            let mut v = vec![json!({"rec": "validated", "op": op, "item": item, "target": target, "facts": facts})];
            if intent {
                v.push(json!({"rec": "intent", "op": op, "item": item, "exec_op": exec_op, "inverse": inverse,
                    "pre": facts}));
            }
            if !outcome.is_null() {
                v.push(json!({"rec": "done", "op": op, "item": item, "outcome": outcome}));
            }
            v
        }

        pub fn done() -> Value {
            json!({"kind": "Done"})
        }

        pub fn blocked(blocker: &str) -> Value {
            json!({"kind": "Skipped", "reason": {"kind": "GateBlocked", "blocker": {"kind": blocker}}})
        }

        pub fn skipped(reason: &str) -> Value {
            json!({"kind": "Skipped", "reason": {"kind": reason}})
        }

        pub fn commit() -> Value {
            json!({"rec": "commit", "at": 134078121950000000u64,
                "counts": {"done": 0, "vanished": 0, "skipped": 0, "held_retry": 0, "pending_reboot": 0, "failed": 0},
                "backup_bytes": 0})
        }

        /// Lines (each ending in a newline) of a journal: header, the records, commit.
        pub fn text(items: usize, records: &[Value]) -> String {
            let mut s = format!("{}\n", header(items));
            for r in records {
                s.push_str(&format!("{r}\n"));
            }
            s.push_str(&format!("{}\n", commit()));
            s
        }
    }

    #[cfg(test)]
    mod tests {
        use super::fixture::*;
        use super::*;
        use serde_json::json;

        /// The sample journal of purge-model `exec::journal` tests, line for line (one record of each kind).
        const MODEL_SAMPLE: &[&str] = &[
            r#"{"rec":"header","schema":"purge.journal/1","session":"20261115T101502Z-9f3a6c1d2b7e4a50","created":134078121020000000,"engine_version":"0.1.0","app":"vendor-app","plan_hash":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","selection_hash":"60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752","policy_version":"m1a.6","mode":"post","items":3,"allow_irreversible":false,"volumes":[{"root":"C:\\","serial":13902625541364831864,"file_system":"NTFS","quarantine":"C:\\ProgramData\\Purge\\Quarantine\\20261115T101502Z-9f3a6c1d2b7e4a50"}]}"#,
            r#"{"rec":"validated","op":1,"item":"c-01","target":{"type":"Path","path":"C:\\Program Files\\Vendor App\\app.exe"},"facts":{"kind":"File","final_path":"C:\\Program Files\\Vendor App\\app.exe","file_id":"000102030405060708090a0b0c0d0e0f","volume_serial":13902625541364831864,"reparse_tag":0,"attributes":32,"n_links":1,"is_dir":false,"size":1048576}}"#,
            r#"{"rec":"validated","op":2,"item":"c-02","target":{"type":"RegKey","path":"HKLM\\SOFTWARE\\Vendor"},"facts":{"kind":"Key","subkeys":2,"values":5,"is_link":false,"owner":"S-1-5-32-544","last_write_time":134078000000000000}}"#,
            r#"{"rec":"validated","op":3,"item":"c-03","target":{"type":"RegValue","path":"HKLM\\SOFTWARE\\Other","name":""},"facts":{"kind":"Value","type":2,"size":38,"data_sha256":"60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"}}"#,
            r#"{"rec":"validated","op":4,"item":"c-04","target":{"type":"Path","path":"C:\\Program Files\\Vendor App"},"facts":{"kind":"File","final_path":"C:\\Program Files\\Vendor App","file_id":"ffffffffffffffffffffffffffffffff","volume_serial":1,"reparse_tag":0,"attributes":16,"n_links":1,"is_dir":true,"size":0,"tree_entries":12,"tree_bytes":4096}}"#,
            r#"{"rec":"validated","op":5,"item":"c-05","target":{"type":"AppxPackage","full_name":"Vendor.App_1.0.0.0_x64__abc"},"facts":{"kind":"Package"}}"#,
            r#"{"rec":"validated","op":6,"item":"c-06","target":{"type":"RegKey","path":"HKLM\\SOFTWARE\\Gone"},"facts":{"kind":"Absent"}}"#,
            r#"{"rec":"intent","op":1,"item":"c-01","exec_op":{"kind":"QuarantineMove","path":"C:\\Program Files\\Vendor App\\app.exe"},"inverse":{"kind":"MoveBack","quarantine_path":"C:\\ProgramData\\Purge\\Quarantine\\20261115T101502Z-9f3a6c1d2b7e4a50\\000001\\app.exe","original_path":"C:\\Program Files\\Vendor App\\app.exe","file_id":"000102030405060708090a0b0c0d0e0f","volume_serial":13902625541364831864},"pre":{"kind":"File","final_path":"C:\\Program Files\\Vendor App\\app.exe","file_id":"000102030405060708090a0b0c0d0e0f","volume_serial":13902625541364831864,"reparse_tag":0,"attributes":32,"n_links":1,"is_dir":false,"size":1048576}}"#,
            r#"{"rec":"done","op":1,"item":"c-01","outcome":{"kind":"Done"}}"#,
            r#"{"rec":"intent","op":2,"item":"c-02","exec_op":{"kind":"DeleteKeyTree","key":"HKLM\\SOFTWARE\\Vendor"},"inverse":{"kind":"RestoreKeyTree","backup":{"path":"reg\\000002.regbackup.json","sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","bytes":4096}},"pre":{"kind":"Key","subkeys":2,"values":5,"is_link":false,"owner":"S-1-5-32-544","last_write_time":134078000000000000}}"#,
            r#"{"rec":"done","op":2,"item":"c-02","outcome":{"kind":"Failed","code":"AccessDenied","os_error":5}}"#,
            r#"{"rec":"done","op":3,"item":"c-03","outcome":{"kind":"Skipped","reason":{"kind":"GateBlocked","blocker":{"kind":"RegLink"}}},"detail":"value is a link"}"#,
            r#"{"rec":"intent","op":5,"item":"c-05","exec_op":{"kind":"RemovePackage","full_name":"Vendor.App_1.0.0.0_x64__abc"},"inverse":{"kind":"None"},"definition":{"path":"def\\000005.json","sha256":"60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752","bytes":900},"pre":{"kind":"Package"}}"#,
            r#"{"rec":"done","op":5,"item":"c-05","outcome":{"kind":"Done"}}"#,
            r#"{"rec":"group_end","group":1,"ops":3}"#,
            r#"{"rec":"commit","at":134078121950000000,"counts":{"done":2,"vanished":1,"skipped":1,"held_retry":0,"pending_reboot":0,"failed":1},"backup_bytes":1053572}"#,
            r#"{"rec":"aborted","at":134078121950000000,"reason":"BackupWriteFailed","detail":"disk full"}"#,
            r#"{"rec":"aborted","at":1,"reason":"RolledBack"}"#,
            r#"{"rec":"undo_intent","op":1}"#,
            r#"{"rec":"undo_done","op":1,"outcome":{"kind":"Restored"}}"#,
            r#"{"rec":"undo_done","op":3,"outcome":{"kind":"NothingToUndo"}}"#,
            r#"{"rec":"undo_done","op":2,"outcome":{"kind":"Failed","code":"Os","os_error":1392,"detail":"x"}}"#,
            r#"{"rec":"undo_conflict","op":2,"conflict":{"kind":"BackupTampered"}}"#,
            r#"{"rec":"undo_conflict","op":2,"conflict":{"kind":"GateBlocked","blocker":{"kind":"DenyListed","rule":"fs.purge"}},"detail":"the path is protected now"}"#,
            r#"{"rec":"reconcile","at":134078999990000000,"op":5,"result":{"kind":"Completed"}}"#,
            r#"{"rec":"reconcile","at":2,"op":5,"result":{"kind":"Retried","outcome":{"kind":"Vanished"}}}"#,
            r#"{"rec":"expire","at":134104041020000000,"op":1,"class":"Quarantine","bytes":1048576}"#,
        ];

        #[test]
        fn reads_the_model_sample() {
            let text: String = MODEL_SAMPLE.iter().map(|l| format!("{l}\n")).collect();
            let j = parse_journal(&text).unwrap();
            assert_eq!(j.header.session, SESSION);
            assert_eq!(j.ops.len(), 6);
            let o1 = j.op(1).unwrap();
            assert_eq!(
                (o1.kind.as_deref(), o1.outcome.as_deref(), o1.renamed),
                (Some("QuarantineMove"), Some("Done"), true)
            );
            assert_eq!(o1.is_dir, Some(false));
            assert_eq!(o1.target, Some(Target::Path { path: "C:\\Program Files\\Vendor App\\app.exe".into() }));
            assert_eq!(o1.undo, ["undo_done:Restored"]);
            let o2 = j.op(2).unwrap();
            assert_eq!(o2.outcome.as_deref(), Some("Failed"));
            assert_eq!(o2.undo.len(), 3);
            let o3 = j.op(3).unwrap();
            assert_eq!(o3.kind, None);
            assert_eq!(o3.effective.as_ref().unwrap().summary(), "Skipped/GateBlocked/RegLink");
            assert_eq!(o3.done_detail.as_deref(), Some("value is a link"));
            assert_eq!(j.op(1).unwrap().done_detail, None);
            assert_eq!(o3.target, Some(Target::RegValue { path: "HKLM\\SOFTWARE\\Other".into(), name: String::new() }));
            let o4 = j.op(4).unwrap();
            assert_eq!((o4.is_dir, o4.outcome.as_deref()), (Some(true), None));
            // Reconcile: Completed, then Retried(Vanished).
            let o5 = j.op(5).unwrap();
            assert_eq!(o5.done, Some(Outcome::Done));
            assert_eq!(o5.outcome.as_deref(), Some("Vanished"));
            assert_eq!(o5.reconciled, ["Completed", "Retried"]);
            assert!(j.committed);
            assert_eq!(j.aborted.as_deref(), Some("RolledBack"));
            assert_eq!(j.commit_counts.unwrap().failed, 1);
            assert_eq!(j.undo_records, 6);
            assert_eq!(j.reconcile_records, 2);
            assert!(j.warnings.iter().any(|w| w.contains("announces 3 items")), "{:?}", j.warnings);
        }

        /// The record kinds and variants purge-model added in the M2 gap pass (its `added_lines`), in a
        /// journal of their own: the settings record, refused facts, a retry under its own intent, the
        /// reconcile results that end a boot move, and the ParentMissing undo conflict.
        #[test]
        fn reads_the_records_added_later() {
            let lines = [
                MODEL_SAMPLE[0],
                r#"{"rec":"settings","user_sid":"S-1-5-21-1-2-3-1001","long_names_resolved":true,"key_limit":10000,"restore_point":"HighRiskOnly"}"#,
                MODEL_SAMPLE[1],
                r#"{"rec":"validated","op":2,"item":"c-02","target":{"type":"Path","path":"C:\\Windows\\x"},"facts":{"kind":"Refused","blocker":{"kind":"DenyListed","rule":"fs.windows"},"reason":"live.deny-listed"},"exemptions":{"proven_owned_skeleton":false,"environment_segment_edit":false,"tier_a_start_menu_entry":false,"long_names_resolved":false}}"#,
                r#"{"rec":"validated","op":3,"item":"c-03","target":{"type":"Path","path":"C:\\x"},"facts":{"kind":"Refused","reason":"gate.open-failed","os_error":5}}"#,
                MODEL_SAMPLE[7],
                r#"{"rec":"done","op":1,"item":"c-01","outcome":{"kind":"HeldRetry"}}"#,
                r#"{"rec":"done","op":2,"item":"c-02","outcome":{"kind":"Skipped","reason":{"kind":"GateBlocked","blocker":{"kind":"DenyListed","rule":"fs.windows"}}}}"#,
                r#"{"rec":"commit","at":2,"counts":{"skipped":1,"held_retry":1},"backup_bytes":0}"#,
                r#"{"rec":"retry_intent","at":3,"op":1}"#,
                r#"{"rec":"reconcile","at":3,"op":1,"result":{"kind":"Retried","outcome":{"kind":"Done"}}}"#,
                r#"{"rec":"reconcile","at":4,"op":1,"result":{"kind":"NotMoved","code":"VerifyFailed","detail":"still in place"}}"#,
                r#"{"rec":"reconcile","at":4,"op":1,"result":{"kind":"MismatchKept","code":"InUse","os_error":32}}"#,
                r#"{"rec":"reconcile","at":4,"op":1,"result":{"kind":"Lost"}}"#,
                r#"{"rec":"undo_plan","at":5,"ops":[1]}"#,
                r#"{"rec":"undo_conflict","op":1,"conflict":{"kind":"ParentMissing"},"detail":"C:\\A is gone"}"#,
            ];
            let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
            let j = parse_journal(&text).unwrap();
            assert_eq!(j.ops.len(), 3);
            assert!(j.warnings.is_empty(), "{:?}", j.warnings);
            let o1 = j.op(1).unwrap();
            assert_eq!(o1.reconciled, ["Retried", "NotMoved", "MismatchKept", "Lost"]);
            assert_eq!((o1.outcome.as_deref(), o1.effective.as_ref()), (Some("Lost"), None));
            assert!(!o1.removed());
            assert_eq!(o1.undo, ["undo_conflict:ParentMissing"]);
            let o2 = j.op(2).unwrap();
            assert_eq!((o2.kind.as_deref(), o2.is_dir), (None, None));
            assert_eq!(j.op(3).unwrap().outcome, None);
            assert_eq!(j.reconcile_records, 4);
            // A retry intent names an op that has a validated record.
            let stray = text.replace(r#""retry_intent","at":3,"op":1"#, r#""retry_intent","at":3,"op":9"#);
            assert!(parse_journal(&stray).is_err());
            // So does every op of an undo plan.
            let stray = text.replace(r#""undo_plan","at":5,"ops":[1]"#, r#""undo_plan","at":5,"ops":[1,9]"#);
            assert!(parse_journal(&stray).is_err());
        }

        #[test]
        fn torn_final_line_only() {
            let mut text =
                fixture::text(1, &fixture::op(1, "DeleteValue", "HKLM\\SOFTWARE\\X", "v", "", false, true, done()));
            let full = text.clone();
            text.push_str("{\"rec\":\"done\",\"op\":");
            let j = parse_journal(&text).unwrap();
            assert!(j.warnings.iter().any(|w| w.contains("torn")));
            assert_eq!(j.op(1).unwrap().outcome.as_deref(), Some("Done"));
            // A torn line followed by a newline, or anywhere but last, is corruption.
            assert!(parse_journal(&format!("{text}\n")).is_err());
            let mut lines: Vec<&str> = full.lines().collect();
            lines.insert(2, "{\"rec\":\"done\",\"op\":");
            assert!(parse_journal(&lines.join("\n")).is_err());
            // Torn inside a multi-byte character (a path with a non-ASCII name).
            let mut bytes = full.clone().into_bytes();
            bytes.extend_from_slice(b"{\"rec\":\"done\",\"op\":1,\"item\":\"c-\xC3");
            let j = parse_journal(&utf8_torn_tail(&bytes).unwrap()).unwrap();
            assert!(j.warnings.iter().any(|w| w.contains("torn")));
            let mut bad = full.clone().into_bytes();
            bad.insert(10, 0xFF);
            assert!(utf8_torn_tail(&bad).is_err());
            // A complete final line of the wrong shape is not torn.
            assert!(parse_journal(&format!("{full}{{\"rec\":\"done\",\"op\":1}}")).is_err());
        }

        #[test]
        fn refuses_what_the_model_refuses() {
            let ok = fixture::op(1, "QuarantineMove", "C:\\A\\f", "", "", false, true, done());
            let good = fixture::text(1, &ok);
            assert!(parse_journal(&good).is_ok());
            let bad_cases: Vec<String> = vec![
                // Other schema id.
                good.replace("purge.journal/1", "purge.journal/2"),
                // Header missing / not first.
                good.lines().skip(1).map(|l| format!("{l}\n")).collect(),
                // Old guessed shapes.
                format!("{}\n{}\n", header(1), json!({"record": "Intent", "op_id": 1, "op": "QuarantineMove"})),
                // Tag spelled like the Rust variant.
                good.replace("\"rec\":\"done\"", "\"rec\":\"Done\""),
                // Unknown outcome kind.
                good.replace("{\"kind\":\"Done\"}", "{\"kind\":\"Maybe\"}"),
                // Inverse that does not fit the op.
                good.replace("\"MoveBack\"", "\"RecreateDir\""),
                // Done for an op that was never validated.
                format!("{}\n{}\n", header(0), json!({"rec": "done", "op": 9, "item": "c-09", "outcome": done()})),
                // Done without an intent.
                fixture::text(1, &fixture::op(1, "QuarantineMove", "C:\\A\\f", "", "", false, false, done())),
                // A required field missing.
                good.replace(",\"pre\":", ",\"pre_\":"),
                // A blank line inside.
                good.replacen('\n', "\n\n", 2),
            ];
            for (i, b) in bad_cases.iter().enumerate() {
                assert!(parse_journal(b).is_err(), "case {i} parsed: {b}");
            }
            // Skipped, Vanished and Failed may come without an intent.
            let j = fixture::text(
                1,
                &fixture::op(1, "QuarantineMove", "C:\\A\\f", "", "", false, false, blocked("SyncRoot")),
            );
            assert_eq!(parse_journal(&j).unwrap().op(1).unwrap().outcome.as_deref(), Some("Skipped"));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FieldDiff {
    pub field: String,
    pub before: Value,
    pub after: Value,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Difference {
    /// `P:<path>`, `K:<key>` or `V:<key>|<name>`.
    pub object: String,
    pub action: String,
    pub op: Option<String>,
    pub fields: Vec<FieldDiff>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Row {
    pub action: String,
    pub ops: u64,
    pub objects: u64,
    pub identical: u64,
    pub differing: u64,
    /// identical / objects, in percent; `null` when nothing was compared.
    pub percent: Option<f64>,
    /// `null` = not compared (RemovePackage: Inverse None).
    pub pass: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OpRow {
    pub id: String,
    pub action: String,
    pub target: Option<String>,
    pub outcome: Option<String>,
    pub renamed: bool,
    pub objects: u64,
    pub differing: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Excluded {
    pub fields: Vec<String>,
    pub ambient_objects: u64,
    /// Present file objects compared without FileId / volume serial (no rename covers them).
    pub file_id_not_required: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FidelityReport {
    pub schema: String,
    pub before: String,
    pub after: String,
    pub journal: String,
    pub ambient: Option<String>,
    pub ok: bool,
    pub rows: Vec<Row>,
    pub differences: Vec<Difference>,
    pub ops: Vec<OpRow>,
    pub excluded: Excluded,
    pub warnings: Vec<String>,
}

impl FidelityReport {
    pub fn failing_rows(&self) -> usize {
        self.rows.iter().filter(|r| r.pass == Some(false)).count()
    }
}

// ---------------------------------------------------------------------------------------------
// Compare
// ---------------------------------------------------------------------------------------------

/// An op prepared for attribution.
struct Prep {
    id: String,
    label: String,
    kind: String,
    /// Primitive targets (canonical).
    prims: Vec<Target>,
    renamed: bool,
    ran: bool,
}

enum Obj<'a> {
    File(&'a str),
    Key(&'a str),
    Value(&'a str, &'a str),
}

impl Prep {
    /// Some((exact value op, target depth)) when this op covers the object.
    fn covers(&self, o: &Obj) -> Option<(bool, usize)> {
        let depth = |p: &str| p.split('\\').count();
        let k = self.kind.as_str();
        for t in &self.prims {
            match (o, t) {
                (Obj::File(p), Target::Path { path }) => {
                    let hit = match k {
                        "RemoveDirIfEmpty" => canon::ci_eq(p, path),
                        _ => canon::is_under_or_eq(p, path),
                    };
                    if hit {
                        return Some((false, depth(path)));
                    }
                }
                (Obj::Key(key) | Obj::Value(key, _), Target::RegKey { path }) => {
                    let hit = match k {
                        "DeleteKeyIfEmpty" => canon::ci_eq(key, path),
                        _ => canon::is_under_or_eq(key, path),
                    };
                    if hit {
                        return Some((false, depth(path)));
                    }
                }
                (
                    Obj::Value(key, name),
                    Target::RegValue { path, name: tn }
                    | Target::RegValueChanged { path, name: tn, .. }
                    | Target::RegMultiSzSegment { path, name: tn, .. },
                ) if canon::ci_eq(key, path) && name.eq_ignore_ascii_case(tn) => {
                    return Some((true, depth(path) + 1));
                }
                _ => {}
            }
        }
        None
    }
}

fn attribute<'p>(preps: &'p [Prep], o: &Obj) -> Option<&'p Prep> {
    preps
        .iter()
        .filter_map(|p| p.covers(o).map(|(exact, d)| (p, exact, d)))
        .max_by_key(|(p, exact, d)| (*exact, p.ran, *d))
        .map(|(p, _, _)| p)
}

fn absent() -> Value {
    json!({ "present": false })
}

/// Differing fields between two records (`None` = no record), skipping `skip`. A record with an `error` on either
/// side is never identical (its fields could not all be read).
fn diff_fields(a: Option<Value>, b: Option<Value>, skip: &[&str]) -> Vec<FieldDiff> {
    let (a, b) = (a.unwrap_or_else(absent), b.unwrap_or_else(absent));
    let pa = a.get("present").and_then(Value::as_bool).unwrap_or(true);
    let pb = b.get("present").and_then(Value::as_bool).unwrap_or(true);
    if pa != pb {
        return vec![FieldDiff { field: "present".into(), before: json!(pa), after: json!(pb) }];
    }
    let (Some(ma), Some(mb)) = (a.as_object(), b.as_object()) else {
        return Vec::new();
    };
    let mut names: Vec<&String> = ma.keys().chain(mb.keys()).collect();
    names.sort();
    names.dedup();
    let mut out = Vec::new();
    for n in names {
        if skip.contains(&n.as_str()) {
            continue;
        }
        let va = ma.get(n).cloned().unwrap_or(Value::Null);
        let vb = mb.get(n).cloned().unwrap_or(Value::Null);
        if va != vb || (n == "error" && !va.is_null()) {
            out.push(FieldDiff { field: n.clone(), before: va, after: vb });
        }
    }
    out
}

fn to_value<T: Serialize>(x: Option<&T>) -> Option<Value> {
    x.map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
}

/// Compares two deep snapshots against the journal's ops.
pub fn compare(a: &DeepDoc, c: &DeepDoc, ops: &[JOp], amb: Option<&AmbientSet>, sid: Option<&str>) -> FidelityReport {
    let mut warnings = Vec::new();
    if a.scope.paths != c.scope.paths || a.scope.keys != c.scope.keys || a.scope.values != c.scope.values {
        warnings.push("before and after were captured with different scopes".to_string());
    }
    let fa: HashMap<String, &FileRec> = a.files.iter().map(|r| (canon::fold(&r.path), r)).collect();
    let fc: HashMap<String, &FileRec> = c.files.iter().map(|r| (canon::fold(&r.path), r)).collect();
    let ka: HashMap<String, &KeyRec> = a.keys.iter().map(|r| (canon::fold(&r.key), r)).collect();
    let kc: HashMap<String, &KeyRec> = c.keys.iter().map(|r| (canon::fold(&r.key), r)).collect();

    // Ops -> attribution entries.
    let mut preps: Vec<Prep> = Vec::new();
    let mut op_rows: Vec<OpRow> = Vec::new();
    for o in ops {
        let t = o.target.as_ref().map(|t| t.canonical(sid));
        // No intent: the op never acted (refused by a gate, already gone, or failed before any backup).
        let kind = o.kind.clone().unwrap_or_else(|| NOT_EXECUTED.into());
        let label = if kind == "QuarantineMove" {
            let dir = t
                .as_ref()
                .and_then(|t| fa.get(&canon::fold(t.path())))
                .and_then(|r| r.is_dir)
                .or(o.is_dir)
                .unwrap_or(false);
            if dir { "QuarantineMove dir" } else { "QuarantineMove file" }.to_string()
        } else {
            kind.clone()
        };
        if o.outcome.is_none() {
            warnings.push(format!("op {} (journal line {}): no done record", o.id, o.line));
        }
        op_rows.push(OpRow {
            id: o.id.clone(),
            action: label.clone(),
            target: t.as_ref().map(Target::canon_string),
            outcome: o.outcome.clone(),
            renamed: o.renamed,
            objects: 0,
            differing: 0,
        });
        if let Some(t) = t {
            let ran = o.kind.is_some()
                && !matches!(o.outcome.as_deref(), Some("Vanished" | "Skipped" | "Failed" | "MovedBack" | "Cancelled"));
            preps.push(Prep { id: o.id.clone(), label, kind, prims: t.primitives(), renamed: o.renamed, ran });
        }
    }
    let op_pos: HashMap<String, usize> = op_rows.iter().enumerate().map(|(i, r)| (r.id.clone(), i)).collect();

    let mut tally: BTreeMap<String, u64> = BTreeMap::new(); // label -> ops
    for r in &op_rows {
        *tally.entry(r.action.clone()).or_default() += 1;
    }
    let mut objects: BTreeMap<String, (u64, u64)> = BTreeMap::new(); // label -> (objects, differing)
    let mut differences = Vec::new();
    let mut excluded = Excluded {
        fields: EXCLUDED.iter().map(|s| s.to_string()).collect(),
        ambient_objects: 0,
        file_id_not_required: 0,
    };

    let is_ambient = |t: Target| amb.and_then(|m| m.union.matches(&t)).is_some();
    let mut record = |cs: String, o: Obj, fields: Box<dyn Fn(bool) -> Vec<FieldDiff> + '_>, excluded: &mut Excluded| {
        let p = attribute(&preps, &o);
        let label = p.map_or(OUTSIDE.to_string(), |p| p.label.clone());
        let renamed = p.is_some_and(|p| p.renamed);
        let e = objects.entry(label.clone()).or_default();
        e.0 += 1;
        if let Some(p) = p
            && let Some(&i) = op_pos.get(&p.id)
        {
            op_rows[i].objects += 1;
        }
        if p.is_some_and(|p| p.kind == "RemovePackage" || p.kind == KEPT) {
            return;
        }
        if matches!(o, Obj::File(_)) && !renamed {
            excluded.file_id_not_required += 1;
        }
        let f = fields(renamed);
        if f.is_empty() {
            return;
        }
        e.1 += 1;
        if let Some(p) = p
            && let Some(&i) = op_pos.get(&p.id)
        {
            op_rows[i].differing += 1;
        }
        differences.push(Difference { object: cs, action: label, op: p.map(|p| p.id.clone()), fields: f });
    };

    // Files.
    let mut fkeys: Vec<&String> = fa.keys().chain(fc.keys()).collect();
    fkeys.sort();
    fkeys.dedup();
    for f in fkeys {
        let (ra, rc) = (fa.get(f).copied(), fc.get(f).copied());
        let path = ra.or(rc).map(|r| r.path.as_str()).unwrap_or_default();
        if is_ambient(Target::Path { path: path.to_string() }) {
            excluded.ambient_objects += 1;
            continue;
        }
        let fields = Box::new(move |renamed: bool| {
            let mut skip: Vec<&str> = FILE_META.to_vec();
            if !renamed {
                skip.extend_from_slice(FILE_ID_FIELDS);
            }
            diff_fields(to_value(ra), to_value(rc), &skip)
        });
        record(format!("P:{path}"), Obj::File(path), fields, &mut excluded);
    }

    // Keys and their values.
    let mut kkeys: Vec<&String> = ka.keys().chain(kc.keys()).collect();
    kkeys.sort();
    kkeys.dedup();
    for k in kkeys {
        let (ra, rc) = (ka.get(k).copied(), kc.get(k).copied());
        let key = ra.or(rc).map(|r| r.key.as_str()).unwrap_or_default();
        if is_ambient(Target::RegKey { path: key.to_string() }) {
            excluded.ambient_objects += 1;
        } else {
            let fields = Box::new(move |_: bool| diff_fields(to_value(ra), to_value(rc), KEY_META));
            record(format!("K:{key}"), Obj::Key(key), fields, &mut excluded);
        }
        let vals = |r: Option<&'_ KeyRec>| -> BTreeMap<String, ValueRec> {
            r.map(|r| r.values.iter().map(|v| (v.name.to_lowercase(), v.clone())).collect()).unwrap_or_default()
        };
        let (va, vc) = (vals(ra), vals(rc));
        let mut names: Vec<&String> = va.keys().chain(vc.keys()).collect();
        names.sort();
        names.dedup();
        for n in names {
            let (xa, xc) = (va.get(n), vc.get(n));
            let name = xa.or(xc).map(|v| v.name.as_str()).unwrap_or_default();
            if is_ambient(Target::RegValue { path: key.to_string(), name: name.to_string() }) {
                excluded.ambient_objects += 1;
                continue;
            }
            let (ja, jc) = (to_value(xa), to_value(xc));
            let fields = Box::new(move |_: bool| diff_fields(ja.clone(), jc.clone(), VALUE_META));
            record(format!("V:{key}|{name}"), Obj::Value(key, name), fields, &mut excluded);
        }
    }

    // Rows.
    let mut out_rows = Vec::new();
    let mut labels: Vec<String> = ROWS.iter().map(|s| s.to_string()).collect();
    for l in tally.keys().chain(objects.keys()) {
        if !labels.contains(l) {
            labels.push(l.clone());
        }
    }
    for l in labels {
        let n_ops = tally.get(&l).copied().unwrap_or(0);
        let (n_obj, n_diff) = objects.get(&l).copied().unwrap_or((0, 0));
        if n_ops == 0 && n_obj == 0 && l != OUTSIDE {
            continue;
        }
        let mut r = Row {
            action: l.clone(),
            ops: n_ops,
            objects: n_obj,
            identical: 0,
            differing: 0,
            percent: None,
            pass: None,
            note: None,
        };
        if l == "RemovePackage" {
            r.note = Some("Inverse None: not compared".into());
        } else if l == KEPT {
            r.note = Some("left quarantined by the run on purpose (--keep-items): not compared".into());
        } else {
            r.identical = n_obj - n_diff;
            r.differing = n_diff;
            if n_obj > 0 {
                r.percent = Some(((r.identical as f64) * 10000.0 / n_obj as f64).round() / 100.0);
                r.pass = Some(n_diff == 0);
            } else if l == OUTSIDE || l == NOT_EXECUTED {
                r.pass = Some(true);
            } else {
                r.pass = Some(false);
                r.note = Some("no deep object in scope for these ops (scope incomplete?)".into());
            }
        }
        out_rows.push(r);
    }
    let ok = !out_rows.iter().any(|r| r.pass == Some(false));
    FidelityReport {
        schema: SCHEMA.to_string(),
        before: String::new(),
        after: String::new(),
        journal: String::new(),
        ambient: None,
        ok,
        rows: out_rows,
        differences,
        ops: op_rows,
        excluded,
        warnings,
    }
}

pub(crate) fn read_deep(p: &Path) -> Result<DeepDoc> {
    let d: DeepDoc = jsonio::read(p)?;
    if d.schema != deep::SCHEMA {
        bail!("{}: schema {:?}, want {}", p.display(), d.schema, deep::SCHEMA);
    }
    Ok(d)
}

pub fn cmd_fidelity(a: &FidelityArgs) -> Result<FidelityReport> {
    let before = read_deep(&a.before)?;
    let after = read_deep(&a.after)?;
    let text = journal::read_journal_text(&a.journal)?;
    let j = parse_journal(&text).with_context(|| format!("journal {}", a.journal.display()))?;
    let (mut ops, jw) = (j.ops, j.warnings);
    for o in &mut ops {
        if o.kind.is_some() && a.keep_items.iter().any(|k| k == &o.item) {
            o.kind = Some(KEPT.into());
        }
    }
    let amb = match &a.ambient {
        Some(p) => Some(AmbientSet::load(p)?),
        None => None,
    };
    let sid = a.sid.clone().or_else(|| before.sid.clone());
    let mut rep = compare(&before, &after, &ops, amb.as_ref(), sid.as_deref());
    rep.before = a.before.display().to_string();
    rep.after = a.after.display().to_string();
    rep.journal = a.journal.display().to_string();
    rep.ambient = a.ambient.as_ref().map(|p| p.display().to_string());
    let mut w = jw;
    w.append(&mut rep.warnings);
    rep.warnings = w;
    jsonio::write(&a.out, &rep)?;
    for r in &rep.rows {
        eprintln!(
            "fidelity: {:<20} ops {:>4}  objects {:>6}  differing {:>4}  {}",
            r.action,
            r.ops,
            r.objects,
            r.differing,
            match (r.pass, r.percent) {
                (None, _) => "not compared".to_string(),
                (Some(p), Some(pc)) => format!("{pc:.2} % {}", if p { "pass" } else { "FAIL" }),
                (Some(p), None) => (if p { "pass" } else { "FAIL (nothing compared)" }).to_string(),
            }
        );
    }
    for w in &rep.warnings {
        eprintln!("fidelity: warning: {w}");
    }
    eprintln!("fidelity: {} -> {}", if rep.ok { "ok" } else { "FAILED" }, a.out.display());
    Ok(rep)
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deep::{StreamRec, sha256_hex};

    const R: &str = "C:\\Program Files\\Fx";
    const K: &str = "HKLM\\SOFTWARE\\Fx";

    fn file(path: &str, content: &str, n: u64) -> FileRec {
        FileRec {
            path: path.into(),
            present: true,
            is_dir: Some(false),
            attributes: Some("0x00000020".into()),
            size: Some(content.len() as u64),
            sha256: Some(sha256_hex(content.as_bytes())),
            streams: Some(Vec::new()),
            links: Some(1),
            file_id: Some(format!("{n:016x}")),
            volume_serial: Some(0x1234),
            owner: Some("BA".into()),
            sddl: Some("O:BAG:SYD:AI(A;ID;FA;;;BA)".into()),
            short_name: None,
            last_write: Some(100 + n),
            ..Default::default()
        }
    }

    fn dir(path: &str, n: u64) -> FileRec {
        FileRec {
            is_dir: Some(true),
            attributes: Some("0x00000010".into()),
            size: None,
            sha256: None,
            ..file(path, "", n)
        }
    }

    fn val(name: &str, typ: u32, data: &str) -> ValueRec {
        ValueRec { name: name.into(), name_hex: None, typ, len: data.len() as u32, sha256: sha256_hex(data.as_bytes()) }
    }

    fn key(k: &str, class: &str, values: Vec<ValueRec>) -> KeyRec {
        KeyRec {
            key: k.into(),
            present: true,
            class: Some(class.into()),
            owner: Some("BA".into()),
            sddl: Some("O:BAG:SYD:PAI(A;CI;KA;;;BA)".into()),
            is_link: Some(false),
            last_write: Some(5),
            values,
            ..Default::default()
        }
    }

    fn doc() -> DeepDoc {
        let mut ads = file(&format!("{R}\\ads\\ads.bin"), "ads", 1);
        ads.streams = Some(vec![StreamRec { name: ":meta:$DATA".into(), size: 3, sha256: Some(sha256_hex(b"abc")) }]);
        let mut hl = file(&format!("{R}\\hl\\a.dll"), "hl", 2);
        hl.links = Some(2);
        let mut hl2 = file(&format!("{R}\\hl\\copy\\a-link.dll"), "hl", 2);
        hl2.links = Some(2);
        DeepDoc {
            schema: deep::SCHEMA.into(),
            files: vec![
                dir(R, 10),
                dir(&format!("{R}\\ads"), 11),
                ads,
                dir(&format!("{R}\\hl"), 12),
                hl,
                dir(&format!("{R}\\hl\\copy"), 13),
                hl2,
                file(&format!("{R}\\single.txt"), "single", 3),
                dir(&format!("{R}\\empty-dir"), 14),
                file(&format!("{R}\\sibling.txt"), "not in plan", 4),
            ],
            keys: vec![
                key(K, "", vec![]),
                key(&format!("{K}\\Tree"), "TreeClass", vec![val("", 1, "d"), val("bin", 3, "xyz")]),
                key(&format!("{K}\\Tree\\Sub"), "SubClass", vec![val("v", 4, "1234")]),
                key(&format!("{K}\\Empty"), "", vec![]),
                key(&format!("{K}\\Values"), "", vec![val("keep", 1, "k"), val("del", 2, "x"), val("Path", 2, "a;b")]),
            ],
            ..Default::default()
        }
    }

    fn journal() -> String {
        use journal::fixture::{done, header, op, skipped};
        let n = Value::Null;
        let ops = [
            op(1, "QuarantineMove", &format!("{R}\\ads\\ads.bin"), "", "", false, true, done()),
            op(2, "QuarantineMove", &format!("{R}\\hl"), "", "", true, true, n.clone()),
            op(3, "QuarantineMove", &format!("{R}\\single.txt"), "", "", false, true, n.clone()),
            op(4, "RemoveDirIfEmpty", &format!("{R}\\empty-dir"), "", "", true, true, n.clone()),
            op(5, "DeleteKeyTree", &format!("{K}\\Tree"), "", "", false, true, n.clone()),
            op(6, "DeleteKeyIfEmpty", &format!("{K}\\Empty"), "", "", false, true, skipped("NoLongerEmpty")),
            op(7, "DeleteValue", &format!("{K}\\Values"), "del", "", false, true, n.clone()),
            op(8, "EditSegment", &format!("{K}\\Values"), "Path", "b", false, true, n),
        ];
        let mut s = format!("{}\n", header(8));
        for l in ops.iter().flatten() {
            s.push_str(&format!("{l}\n"));
        }
        s.push_str("{\"rec\":\"done\",\"op\":3,\"it");
        s
    }

    fn ops_of(text: &str) -> Vec<JOp> {
        parse_journal(text).unwrap().ops
    }

    fn run(a: &DeepDoc, c: &DeepDoc) -> FidelityReport {
        compare(a, c, &ops_of(&journal()), None, None)
    }

    fn row<'a>(r: &'a FidelityReport, l: &str) -> &'a Row {
        r.rows.iter().find(|x| x.action == l).unwrap_or_else(|| panic!("row {l}"))
    }

    #[test]
    fn journal_shapes() {
        let j = parse_journal(&journal()).unwrap();
        let (ops, w) = (j.ops, j.warnings);
        assert_eq!(ops.len(), 8);
        let k: Vec<&str> = ops.iter().map(|o| o.kind.as_deref().unwrap()).collect();
        assert_eq!(
            k,
            [
                "QuarantineMove",
                "QuarantineMove",
                "QuarantineMove",
                "RemoveDirIfEmpty",
                "DeleteKeyTree",
                "DeleteKeyIfEmpty",
                "DeleteValue",
                "EditSegment"
            ]
        );
        assert!(ops[0].renamed && ops[1].renamed && !ops[3].renamed);
        assert_eq!(ops[0].outcome.as_deref(), Some("Done"));
        assert_eq!(ops[5].outcome.as_deref(), Some("Skipped"));
        assert_eq!(ops[7].id, "8");
        assert!(w.iter().any(|x| x.contains("torn")));
        assert!(parse_journal("{bad\n{\"rec\":\"intent\"}\n").is_err());
    }

    #[test]
    fn identical_is_full_fidelity() {
        let r = run(&doc(), &doc());
        assert!(r.ok, "{:#?}", r.differences);
        for l in [
            "QuarantineMove file",
            "QuarantineMove dir",
            "RemoveDirIfEmpty",
            "DeleteKeyTree",
            "DeleteKeyIfEmpty",
            "DeleteValue",
            "EditSegment",
            OUTSIDE,
        ] {
            let x = row(&r, l);
            assert_eq!(x.percent, Some(100.0), "{l}");
            assert_eq!(x.pass, Some(true), "{l}");
            assert!(x.objects > 0, "{l}");
        }
        assert_eq!(row(&r, "QuarantineMove dir").objects, 4);
        assert_eq!(row(&r, "DeleteValue").objects, 1);
        assert_eq!(row(&r, "EditSegment").objects, 1);
        // keep value + Values key + root key + root dir + sibling + ads dir
        assert_eq!(row(&r, OUTSIDE).objects, 6);
    }

    /// Each single-field mutation is detected once, on the expected row and field.
    #[test]
    fn single_field_mutations() {
        type Mut = Box<dyn Fn(&mut DeepDoc)>;
        let fi = |d: &mut DeepDoc, p: &str| -> usize { d.files.iter().position(|f| f.path == p).unwrap() };
        let ki = |d: &mut DeepDoc, k: &str| -> usize { d.keys.iter().position(|x| x.key == k).unwrap() };
        let ads = format!("{R}\\ads\\ads.bin");
        let hl = format!("{R}\\hl\\a.dll");
        let single = format!("{R}\\single.txt");
        let empty = format!("{R}\\empty-dir");
        let tree = format!("{K}\\Tree");
        let sub = format!("{K}\\Tree\\Sub");
        let values = format!("{K}\\Values");
        let cases: Vec<(&str, &str, Mut)> = vec![
            (
                "QuarantineMove file",
                "sha256",
                Box::new({
                    let p = single.clone();
                    move |d| {
                        let i = fi(d, &p);
                        d.files[i].sha256 = Some(sha256_hex(b"changed byte"))
                    }
                }),
            ),
            (
                "QuarantineMove file",
                "attributes",
                Box::new({
                    let p = single.clone();
                    move |d| {
                        let i = fi(d, &p);
                        d.files[i].attributes = Some("0x00000021".into())
                    }
                }),
            ),
            (
                "QuarantineMove file",
                "streams",
                Box::new({
                    let p = ads.clone();
                    move |d| {
                        let i = fi(d, &p);
                        d.files[i].streams = Some(vec![])
                    }
                }),
            ),
            (
                "QuarantineMove file",
                "file_id",
                Box::new({
                    let p = ads.clone();
                    move |d| {
                        let i = fi(d, &p);
                        d.files[i].file_id = Some("ffff".into())
                    }
                }),
            ),
            (
                "QuarantineMove dir",
                "links",
                Box::new({
                    let p = hl.clone();
                    move |d| {
                        let i = fi(d, &p);
                        d.files[i].links = Some(1)
                    }
                }),
            ),
            (
                "QuarantineMove dir",
                "file_id",
                Box::new({
                    let p = hl.clone();
                    move |d| {
                        let i = fi(d, &p);
                        d.files[i].file_id = Some("ffff".into())
                    }
                }),
            ),
            (
                "RemoveDirIfEmpty",
                "attributes",
                Box::new({
                    let p = empty.clone();
                    move |d| {
                        let i = fi(d, &p);
                        d.files[i].attributes = Some("0x00000012".into())
                    }
                }),
            ),
            (
                "DeleteKeyTree",
                "sddl",
                Box::new({
                    let k = tree.clone();
                    move |d| {
                        let i = ki(d, &k);
                        d.keys[i].sddl = Some("O:BAG:SYD:PAI(A;CI;KA;;;BA)(A;CI;KR;;;BU)".into())
                    }
                }),
            ),
            (
                "DeleteKeyTree",
                "class",
                Box::new({
                    let k = sub.clone();
                    move |d| {
                        let i = ki(d, &k);
                        d.keys[i].class = Some(String::new())
                    }
                }),
            ),
            (
                "DeleteKeyTree",
                "type",
                Box::new({
                    let k = tree.clone();
                    move |d| {
                        let i = ki(d, &k);
                        d.keys[i].values[1].typ = 0
                    }
                }),
            ),
            (
                "DeleteKeyTree",
                "is_link",
                Box::new({
                    let k = sub.clone();
                    move |d| {
                        let i = ki(d, &k);
                        d.keys[i].is_link = Some(true)
                    }
                }),
            ),
            (
                "DeleteKeyIfEmpty",
                "present",
                Box::new({
                    let k = format!("{K}\\Empty");
                    move |d| {
                        let i = ki(d, &k);
                        d.keys[i] = KeyRec { key: d.keys[i].key.clone(), present: false, ..Default::default() }
                    }
                }),
            ),
            (
                "DeleteValue",
                "type",
                Box::new({
                    let k = values.clone();
                    move |d| {
                        let i = ki(d, &k);
                        d.keys[i].values[1].typ = 1
                    }
                }),
            ),
            (
                "DeleteValue",
                "present",
                Box::new({
                    let k = values.clone();
                    move |d| {
                        let i = ki(d, &k);
                        d.keys[i].values.remove(1);
                    }
                }),
            ),
            (
                "EditSegment",
                "sha256",
                Box::new({
                    let k = values.clone();
                    move |d| {
                        let i = ki(d, &k);
                        d.keys[i].values[2].sha256 = sha256_hex(b"a;b;b")
                    }
                }),
            ),
            (
                OUTSIDE,
                "sha256",
                Box::new(move |d| {
                    let i = fi(d, &format!("{R}\\sibling.txt"));
                    d.files[i].sha256 = Some(sha256_hex(b"collateral"))
                }),
            ),
            (
                OUTSIDE,
                "error",
                Box::new(move |d| {
                    let i = fi(d, R);
                    d.files[i].error = Some("sddl: 5".into())
                }),
            ),
        ];
        for (want_row, want_field, m) in cases {
            let a = doc();
            let mut c = doc();
            m(&mut c);
            let r = run(&a, &c);
            assert!(!r.ok, "{want_row}/{want_field} not detected");
            assert_eq!(r.differences.len(), 1, "{want_row}/{want_field}: {:#?}", r.differences);
            let d = &r.differences[0];
            assert_eq!(d.action, want_row, "{want_field}: {d:#?}");
            assert_eq!(d.fields.len(), 1, "{d:#?}");
            assert_eq!(d.fields[0].field, want_field);
            let x = row(&r, want_row);
            assert_eq!((x.differing, x.pass), (1, Some(false)));
            assert!(x.percent.unwrap() < 100.0);
            for other in r.rows.iter().filter(|x| x.action != want_row) {
                assert_ne!(other.pass, Some(false), "{want_row}/{want_field} also failed {}", other.action);
            }
        }
    }

    #[test]
    fn excluded_fields_never_fail() {
        let a = doc();
        let mut c = doc();
        for f in &mut c.files {
            f.last_write = Some(999_999);
            f.short_name = Some("PROGRA~1".into());
        }
        for k in &mut c.keys {
            k.last_write = Some(999_999);
        }
        // Not renamed: a recreated directory and a parent get new FileIds.
        for p in [format!("{R}\\empty-dir"), R.to_string(), format!("{R}\\sibling.txt")] {
            let i = c.files.iter().position(|f| f.path == p).unwrap();
            c.files[i].file_id = Some("abcdef".into());
            c.files[i].volume_serial = Some(9);
        }
        let r = run(&a, &c);
        assert!(r.ok, "{:#?}", r.differences);
        assert!(r.excluded.file_id_not_required >= 3);
    }

    #[test]
    fn ambient_objects_are_excluded() {
        let a = doc();
        let mut c = doc();
        let i = c.files.iter().position(|f| f.path.ends_with("sibling.txt")).unwrap();
        c.files[i].sha256 = Some("00".into());
        let amb = AmbientSet {
            union: crate::ambient::Matcher::new("u", &[format!("P:{R}\\sibling.txt")], &[]).unwrap(),
            runs: Vec::new(),
            records: None,
        };
        let r = compare(&a, &c, &ops_of(&journal()), Some(&amb), None);
        assert!(r.ok, "{:#?}", r.differences);
        assert_eq!(r.excluded.ambient_objects, 1);
    }

    #[test]
    fn op_without_objects_fails_its_row() {
        let a = doc();
        use journal::fixture::{done, op, text};
        let j = text(1, &op(1, "DeleteKeyTree", "HKLM\\SOFTWARE\\NotCaptured", "", "", false, true, done()));
        let r = compare(&a, &a, &ops_of(&j), None, None);
        assert!(!r.ok);
        let x = row(&r, "DeleteKeyTree");
        assert_eq!((x.objects, x.pass), (0, Some(false)));
        // RemovePackage is reported, never compared.
        let j = text(1, &op(1, "RemovePackage", "A_1", "", "", false, true, done()));
        let r = compare(&a, &a, &ops_of(&j), None, None);
        assert!(r.ok);
        assert_eq!(row(&r, "RemovePackage").pass, None);
    }

    #[test]
    fn nested_ops_attribute_to_the_op_that_ran() {
        let a = doc();
        let mut c = doc();
        let i = c.files.iter().position(|f| f.path.ends_with("a-link.dll")).unwrap();
        c.files[i].file_id = Some("ff".into());
        use journal::fixture::{done, op, text};
        let child = op(1, "QuarantineMove", &format!("{R}\\hl\\copy"), "", "", true, true, json!({"kind": "Vanished"}));
        let parent = op(2, "QuarantineMove", &format!("{R}\\hl"), "", "", true, true, done());
        let j = text(2, &[child, parent].concat());
        let r = compare(&a, &c, &ops_of(&j), None, None);
        assert_eq!(r.differences.len(), 1);
        assert_eq!(r.differences[0].op.as_deref(), Some("2"));
        assert_eq!(r.differences[0].fields[0].field, "file_id");
    }

    /// Live: deep on a temp tree and a test key, twice; then real mutations (key DACL ACE, file attribute,
    /// ADS removed, value data) are found on the right rows.
    #[cfg(windows)]
    #[test]
    fn live_round_trip() {
        use crate::deep::testenv::{TempDir, TestKey};
        use crate::deep::{Scope, capture};
        let td = TempDir::new();
        let root = td.path();
        std::fs::create_dir_all(format!("{root}\\app\\tree\\sub")).unwrap();
        std::fs::write(format!("{root}\\app\\tree\\sub\\f.txt"), b"tree file").unwrap();
        let single = format!("{root}\\app\\single.bin");
        std::fs::write(&single, b"single").unwrap();
        std::fs::write(format!("{single}:meta"), b"m").unwrap();
        let k = TestKey::new();
        k.create("Tree", Some("Cls"));
        k.create("Tree\\Sub", None);
        k.set("Tree\\Sub", "v", 4, &1u32.to_le_bytes());
        k.create("Vals", None);
        k.set("Vals", "del", 3, &[1, 2, 3]);
        k.set("Vals", "keep", 3, &[4]);

        let mut b = deep::ScopeBuilder::new(None, None);
        let targets = json!({"schema": "purge.rig.targets/0", "targets": [
            {"target": {"type": "Path", "path": format!("{root}\\app\\tree")}},
            {"target": {"type": "Path", "path": single}},
            {"target": {"type": "RegKey", "path": k.canon("Tree")}},
            {"target": {"type": "RegValue", "path": k.canon("Vals"), "name": "del"}}
        ]});
        b.add_doc(&targets).unwrap();
        let scope: Scope = b.finish();
        assert!(scope.warnings.is_empty(), "{:?}", scope.warnings);
        use journal::fixture::{done, op, text};
        let recs = [
            op(1, "QuarantineMove", &format!("{root}\\app\\tree"), "", "", true, true, done()),
            op(2, "QuarantineMove", &single, "", "", false, true, done()),
            op(3, "DeleteKeyTree", &k.canon("Tree"), "", "", false, true, done()),
            op(4, "DeleteValue", &k.canon("Vals"), "del", "", false, true, done()),
        ]
        .concat();
        let j = parse_journal(&text(4, &recs)).unwrap();
        assert!(j.warnings.is_empty(), "{:?}", j.warnings);
        let ops = j.ops;

        let a = capture(&scope, None);
        assert_eq!(a.errors, 0, "{:#?}", a.files.iter().chain([]).filter(|f| f.error.is_some()).collect::<Vec<_>>());
        let c = capture(&scope, None);
        let r = compare(&a, &c, &ops, None, None);
        assert!(r.ok, "{:#?}", r.differences);
        assert_eq!(row(&r, "QuarantineMove dir").percent, Some(100.0));
        assert_eq!(row(&r, "QuarantineMove file").objects, 1);
        assert_eq!(row(&r, "DeleteKeyTree").objects, 3); // Tree, Sub, Sub|v
        assert_eq!(row(&r, "DeleteValue").objects, 1);

        k.set_sddl("Tree\\Sub", "D:PAI(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KA;;;OW)(A;CI;KR;;;BU)");
        k.set("Vals", "del", 3, &[1, 2, 4]);
        std::fs::remove_file(format!("{single}:meta")).unwrap();
        let f = format!("{root}\\app\\tree\\sub\\f.txt");
        let mut p = std::fs::metadata(&f).unwrap().permissions();
        p.set_readonly(true);
        std::fs::set_permissions(&f, p.clone()).unwrap();
        let c2 = capture(&scope, None);
        #[allow(clippy::permissions_set_readonly_false)]
        p.set_readonly(false);
        std::fs::set_permissions(&f, p).unwrap();
        let r = compare(&a, &c2, &ops, None, None);
        assert!(!r.ok);
        let got: Vec<(String, String)> = r
            .differences
            .iter()
            .map(|d| (d.action.clone(), d.fields.iter().map(|f| f.field.clone()).collect::<Vec<_>>().join(",")))
            .collect();
        assert!(got.contains(&("DeleteKeyTree".into(), "sddl".into())), "{got:?}");
        assert!(got.contains(&("DeleteValue".into(), "sha256".into())), "{got:?}");
        assert!(got.contains(&("QuarantineMove file".into(), "streams".into())), "{got:?}");
        assert!(got.contains(&("QuarantineMove dir".into(), "attributes".into())), "{got:?}");
        assert_eq!(r.differences.len(), 4, "{got:?}");
    }
}
