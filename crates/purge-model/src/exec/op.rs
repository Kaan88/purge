//! `ExecOp` and `Inverse`: what the executor does to one plan item and how that is undone
//! (ENGINE_PLAN.md §7.5, §7.8).
//!
//! A plan item is a ([`Target`], [`Action`]) pair. [`resolve`] maps the legal pairs to an [`ExecOp`] and
//! refuses every other pair, so the executor never has to guess what an item means. Each executed op is
//! journalled with its [`Inverse`], and ends in one [`ItemOutcome`].
//!
//! Service, task and firewall ops are not part of this vocabulary yet: their execution is deferred to M1b,
//! and [`resolve`] refuses those targets with [`Mismatch::NoExecutor`].
//!
//! The small scalars the executor documents share live here too: [`OpId`], [`Sha256Hex`], [`FileIdHex`]
//! and [`BackupRef`].

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Action, Blocker, FileTime, Target};

/// Why a string is not a fixed-length lower-case hex value ([`Sha256Hex`], [`FileIdHex`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// The text does not have exactly two characters per byte.
    BadLength,
    /// A character is not one of `0-9a-f`. Upper-case digits are refused, so one value has one spelling.
    BadDigit,
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadLength => "hex value has the wrong length",
            Self::BadDigit => "hex value may only contain the digits 0-9 and a-f",
        })
    }
}

impl std::error::Error for HexError {}

/// Reads exactly `N` bytes of lower-case hex.
fn parse_hex<const N: usize>(text: &str) -> Result<[u8; N], HexError> {
    let digits = text.as_bytes();
    if digits.len() != N * 2 {
        return Err(HexError::BadLength);
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(HexError::BadDigit),
    };
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}

/// Writes bytes as lower-case hex.
fn write_hex(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

/// Defines a fixed-length byte value that serialises as a lower-case hex string and refuses any other
/// spelling when read.
macro_rules! hex_value {
    ($(#[$meta:meta])* $name:ident, $len:literal, $pattern:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            /// The raw bytes.
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_hex(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self)
            }
        }

        impl FromStr for $name {
            type Err = HexError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_hex::<$len>(s).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = Cow::<str>::deserialize(deserializer)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }

            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({ "type": "string", "pattern": $pattern })
            }
        }
    };
}

hex_value!(
    /// A SHA-256 digest, serialised as 64 lower-case hex digits (the form `purge_plan::hash::plan_hash`
    /// writes). Reading any other spelling fails.
    Sha256Hex,
    32,
    "^[0-9a-f]{64}$"
);

hex_value!(
    /// The 128-bit file identifier of a file or directory (`FILE_ID_INFO.FileId`), serialised as 32
    /// lower-case hex digits in the byte order Windows returns. Only meaningful together with the volume
    /// serial it was read on.
    FileIdHex,
    16,
    "^[0-9a-f]{32}$"
);

/// The number of one op within a session, counted from 1 in plan order.
///
/// Every selected plan item gets an op id, whether or not it ends up acted on. The id also names the op's
/// directory and backup files, through [`OpId::file_stem`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct OpId(pub u32);

impl OpId {
    /// The name used for the op's quarantine directory and backup files: six digits, zero-padded
    /// (`000042`), so names sort in op order.
    pub fn file_stem(self) -> String {
        format!("{:06}", self.0)
    }
}

impl fmt::Display for OpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A backup or definition file of a session, with the hash the journal binds it to (§7.4).
///
/// Undo reads the file only after its SHA-256 matched.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct BackupRef {
    /// Path of the file relative to the session directory, with `\` separators, e.g.
    /// `reg\000042.regbackup.json`. Never absolute; see [`BackupRef::is_session_relative`].
    pub path: String,
    /// SHA-256 of the file's bytes, taken from the read-back after the write.
    pub sha256: Sha256Hex,
    /// Size of the file in bytes.
    pub bytes: u64,
}

impl BackupRef {
    /// Whether `path` stays inside the session directory: not empty, no drive or stream (`:`), no `/`, no
    /// leading `\`, and no empty, `.` or `..` component. A reader must refuse a reference that fails this
    /// before joining it to the session directory.
    pub fn is_session_relative(&self) -> bool {
        !self.path.is_empty()
            && !self.path.contains([':', '/'])
            && self
                .path
                .split('\\')
                .all(|part| !part.is_empty() && part != "." && part != "..")
    }
}

/// What the executor does to one plan item. Serialised as an object tagged by `"kind"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind")]
pub enum ExecOp {
    /// Move a file or directory into the same-volume quarantine.
    QuarantineMove {
        /// Absolute path of the file or directory.
        path: String,
    },
    /// Remove a directory if it is empty when its turn comes (non-recursive).
    RemoveDirIfEmpty {
        /// Absolute path of the directory.
        path: String,
    },
    /// Delete a registry key with its subtree, after a verified backup.
    DeleteKeyTree {
        /// Canonical key path, as [`Target::RegKey`] spells it.
        key: String,
    },
    /// Delete a registry key if it has no values and no subkeys when its turn comes.
    DeleteKeyIfEmpty {
        /// Canonical key path.
        key: String,
    },
    /// Delete one registry value.
    DeleteValue {
        /// Canonical key path.
        key: String,
        /// Value name; empty for the default value.
        name: String,
    },
    /// Remove one segment from a list-like value in a single read-modify-write.
    EditSegment {
        /// Canonical key path.
        key: String,
        /// Value name; empty for the default value.
        name: String,
        /// The segment text.
        segment: String,
        /// Zero-based position of the segment, when the plan knows it; `None` means the first match.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        index: Option<u32>,
    },
    /// Remove an AppX/MSIX package. It cannot be undone ([`Inverse::None`]).
    RemovePackage {
        /// Package full name.
        full_name: String,
    },
}

impl ExecOp {
    /// The op's name as serialised in `"kind"`.
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

    /// The target the op acts on. `resolve(&op.target(), op.action())` gives the op back.
    pub fn target(&self) -> Target {
        match self.clone() {
            ExecOp::QuarantineMove { path } | ExecOp::RemoveDirIfEmpty { path } => {
                Target::Path { path }
            }
            ExecOp::DeleteKeyTree { key } | ExecOp::DeleteKeyIfEmpty { key } => {
                Target::RegKey { path: key }
            }
            ExecOp::DeleteValue { key, name } => Target::RegValue { path: key, name },
            ExecOp::EditSegment {
                key,
                name,
                segment,
                index,
            } => Target::RegMultiSzSegment {
                path: key,
                name,
                segment,
                index,
            },
            ExecOp::RemovePackage { full_name } => Target::AppxPackage { full_name },
        }
    }

    /// The plan action the op resolves from.
    pub fn action(&self) -> Action {
        match self {
            ExecOp::QuarantineMove { .. } => Action::Quarantine,
            ExecOp::RemoveDirIfEmpty { .. } | ExecOp::DeleteKeyIfEmpty { .. } => {
                Action::RemoveDirIfEmpty
            }
            ExecOp::DeleteKeyTree { .. } => Action::DeleteKey,
            ExecOp::DeleteValue { .. } => Action::DeleteValue,
            ExecOp::EditSegment { .. } => Action::EditSegment,
            ExecOp::RemovePackage { .. } => Action::RemovePackage,
        }
    }

    /// Whether the op acts on the registry.
    pub fn is_registry(&self) -> bool {
        matches!(
            self,
            ExecOp::DeleteKeyTree { .. }
                | ExecOp::DeleteKeyIfEmpty { .. }
                | ExecOp::DeleteValue { .. }
                | ExecOp::EditSegment { .. }
        )
    }

    /// Whether the op has no inverse, so it needs the explicit irreversible acknowledgement.
    pub fn is_irreversible(&self) -> bool {
        matches!(self, ExecOp::RemovePackage { .. })
    }
}

/// Why a ([`Target`], [`Action`]) pair has no [`ExecOp`]. An item that does not resolve is never executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mismatch {
    /// The action is [`Action::ReportOnly`]: the item is shown, never executed.
    ReportOnly,
    /// The target is [`Target::RegValueChanged`], which exists in rig truth only. The fix for a changed
    /// value is a segment edit, never a removal.
    TruthOnlyTarget,
    /// The target is a service, task or firewall rule. Executing those is deferred to M1b.
    NoExecutor,
    /// The action does not apply to this kind of target (for example `DeleteKey` on a file).
    WrongAction,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReportOnly => "the item is report-only",
            Self::TruthOnlyTarget => "a changed value is never removed",
            Self::NoExecutor => "services, tasks and firewall rules are not executed yet",
            Self::WrongAction => "the action does not apply to this kind of target",
        })
    }
}

impl std::error::Error for Mismatch {}

/// Maps a plan item to the op that executes it. These are the only legal pairs:
///
/// | Target | Action | Op |
/// |---|---|---|
/// | `Path` | `Quarantine` | [`ExecOp::QuarantineMove`] |
/// | `Path` | `RemoveDirIfEmpty` | [`ExecOp::RemoveDirIfEmpty`] |
/// | `RegKey` | `DeleteKey` | [`ExecOp::DeleteKeyTree`] |
/// | `RegKey` | `RemoveDirIfEmpty` | [`ExecOp::DeleteKeyIfEmpty`] |
/// | `RegValue` | `DeleteValue` | [`ExecOp::DeleteValue`] |
/// | `RegMultiSzSegment` | `EditSegment` | [`ExecOp::EditSegment`] |
/// | `AppxPackage` | `RemovePackage` | [`ExecOp::RemovePackage`] |
///
/// Every other pair is a [`Mismatch`]. [`Action::ReportOnly`] and [`Target::RegValueChanged`] never
/// resolve; `ReportOnly` is reported first when both apply.
pub fn resolve(target: &Target, action: Action) -> Result<ExecOp, Mismatch> {
    if action == Action::ReportOnly {
        return Err(Mismatch::ReportOnly);
    }
    match target {
        Target::Path { path } => match action {
            Action::Quarantine => Ok(ExecOp::QuarantineMove { path: path.clone() }),
            Action::RemoveDirIfEmpty => Ok(ExecOp::RemoveDirIfEmpty { path: path.clone() }),
            _ => Err(Mismatch::WrongAction),
        },
        Target::RegKey { path } => match action {
            Action::DeleteKey => Ok(ExecOp::DeleteKeyTree { key: path.clone() }),
            Action::RemoveDirIfEmpty => Ok(ExecOp::DeleteKeyIfEmpty { key: path.clone() }),
            _ => Err(Mismatch::WrongAction),
        },
        Target::RegValue { path, name } => match action {
            Action::DeleteValue => Ok(ExecOp::DeleteValue {
                key: path.clone(),
                name: name.clone(),
            }),
            _ => Err(Mismatch::WrongAction),
        },
        Target::RegValueChanged { .. } => Err(Mismatch::TruthOnlyTarget),
        Target::RegMultiSzSegment {
            path,
            name,
            segment,
            index,
        } => match action {
            Action::EditSegment => Ok(ExecOp::EditSegment {
                key: path.clone(),
                name: name.clone(),
                segment: segment.clone(),
                index: *index,
            }),
            _ => Err(Mismatch::WrongAction),
        },
        Target::Service { .. } | Target::Task { .. } | Target::FirewallRule { .. } => {
            Err(Mismatch::NoExecutor)
        }
        Target::AppxPackage { full_name } => match action {
            Action::RemovePackage => Ok(ExecOp::RemovePackage {
                full_name: full_name.clone(),
            }),
            _ => Err(Mismatch::WrongAction),
        },
    }
}

/// How an executed op is undone (§7.8). Written into the journal with the op's intent, before the op
/// runs. Serialised as an object tagged by `"kind"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind")]
pub enum Inverse {
    /// Rename the quarantined item back to its original path, after checking that it is still the
    /// recorded item. Inverse of [`ExecOp::QuarantineMove`].
    MoveBack {
        /// Absolute path of the item inside the quarantine.
        quarantine_path: String,
        /// Absolute path the item was moved from, as recorded before the move.
        original_path: String,
        /// File id of the item. A rename keeps it, so the item in quarantine must still have it.
        file_id: FileIdHex,
        /// Serial of the volume the item is on (source and quarantine share it).
        volume_serial: u64,
    },
    /// Restore a key and its subtree from a registry backup. Inverse of [`ExecOp::DeleteKeyTree`].
    RestoreKeyTree {
        /// The `purge.regbackup/1` file holding the tree.
        backup: BackupRef,
    },
    /// Restore one value from a registry backup. Inverse of [`ExecOp::DeleteValue`].
    RestoreValue {
        /// The `purge.regbackup/1` file holding the value.
        backup: BackupRef,
    },
    /// Put a removed segment back into its value. Inverse of [`ExecOp::EditSegment`].
    ReinsertSegment {
        /// Canonical key path.
        key: String,
        /// Value name; empty for the default value.
        name: String,
        /// Zero-based position the segment was removed from.
        index: u32,
        /// The segment text.
        segment: String,
        /// SHA-256 of the value's raw data before the edit.
        original_value_hash: Sha256Hex,
        /// SHA-256 of the raw data the edit writes. Undo re-inserts only while the value still holds this
        /// data or merely lacks the segment.
        written_value_hash: Sha256Hex,
        /// Backup of the whole value before the edit, when one was written.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        backup: Option<BackupRef>,
    },
    /// Create the directory again. Inverse of [`ExecOp::RemoveDirIfEmpty`].
    RecreateDir {
        /// Absolute path of the directory.
        path: String,
        /// `FILE_ATTRIBUTE_*` bits the directory had.
        attributes: u32,
        /// Owner, group and DACL of the directory as one SDDL string.
        sddl: String,
        /// Creation time the directory had, when recorded.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        creation_time: Option<FileTime>,
        /// Last write time the directory had, when recorded.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_write_time: Option<FileTime>,
    },
    /// Create the empty key again, with its class and security. Inverse of [`ExecOp::DeleteKeyIfEmpty`].
    RecreateKey {
        /// The `purge.regbackup/1` file holding the key (a tree of one key).
        backup: BackupRef,
    },
    /// The op cannot be undone ([`ExecOp::RemovePackage`]).
    None,
}

impl Inverse {
    /// The inverse's name as serialised in `"kind"`.
    pub fn name(&self) -> &'static str {
        match self {
            Inverse::MoveBack { .. } => "MoveBack",
            Inverse::RestoreKeyTree { .. } => "RestoreKeyTree",
            Inverse::RestoreValue { .. } => "RestoreValue",
            Inverse::ReinsertSegment { .. } => "ReinsertSegment",
            Inverse::RecreateDir { .. } => "RecreateDir",
            Inverse::RecreateKey { .. } => "RecreateKey",
            Inverse::None => "None",
        }
    }

    /// The backup file the inverse reads, if it reads one.
    pub fn backup(&self) -> Option<&BackupRef> {
        match self {
            Inverse::RestoreKeyTree { backup }
            | Inverse::RestoreValue { backup }
            | Inverse::RecreateKey { backup } => Some(backup),
            Inverse::ReinsertSegment { backup, .. } => backup.as_ref(),
            Inverse::MoveBack { .. } | Inverse::RecreateDir { .. } | Inverse::None => None,
        }
    }

    /// Whether this inverse is the kind that undoes `op`. The journal reader uses it to refuse an intent
    /// whose inverse does not fit its op.
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

/// Why an item was not acted on. Serialised as an object tagged by `"kind"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind")]
pub enum SkipReason {
    /// The item is no longer what was validated (other file id, type, data or content).
    ChangedSinceScan,
    /// A delete-if-empty item has content now.
    NoLongerEmpty,
    /// A gate of §7.2 refused the item at execute time.
    GateBlocked {
        /// The blocker the gate raised, e.g. `RegLink`, `DenyListed` or `ReversibilityNone` (the
        /// irreversible acknowledgement is missing).
        blocker: Blocker,
    },
    /// The backup could not be written or did not verify, so nothing was deleted.
    NoVerifiedBackup,
    /// Taking the backup would exceed the quarantine size cap.
    CapExceeded,
    /// The run was aborted before the item's turn came.
    NotAttempted,
}

/// What kind of failure ended an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum FailCode {
    /// Access was denied. Purge never raises its own access to get past this.
    AccessDenied,
    /// The item stayed in use after the retries and nothing on the locked-file ladder applied.
    InUse,
    /// Controlled Folder Access refused the change.
    ControlledFolderAccess,
    /// The action reported success but the item is still there.
    VerifyFailed,
    /// The package API refused or failed.
    PackageApi,
    /// Any other operating-system error; `os_error` holds the code.
    Os,
    /// An unexpected state inside the executor.
    Internal,
}

/// How one item ended. Serialised as an object tagged by `"kind"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind")]
pub enum ItemOutcome {
    /// The action ran and was verified.
    Done,
    /// The item was already gone. Counts as success.
    Vanished,
    /// The item was left untouched.
    Skipped {
        /// Why.
        reason: SkipReason,
    },
    /// The item is locked and its path is user-writable: it is left in place and retried at the next
    /// Purge run.
    HeldRetry,
    /// A boot-time move into quarantine is registered; the item goes at the next restart.
    PendingReboot,
    /// The action failed. The item is in its original state unless `code` is
    /// [`FailCode::VerifyFailed`].
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

impl ItemOutcome {
    /// Whether the item is gone as planned ([`ItemOutcome::Done`] or [`ItemOutcome::Vanished`]).
    pub fn is_success(&self) -> bool {
        matches!(self, ItemOutcome::Done | ItemOutcome::Vanished)
    }

    /// Whether the system was changed, so undo has something to do: [`ItemOutcome::Done`], or
    /// [`ItemOutcome::PendingReboot`] (a registered boot-time move).
    pub fn changed_system(&self) -> bool {
        matches!(self, ItemOutcome::Done | ItemOutcome::PendingReboot)
    }

    /// Whether the outcome may be journalled without an intent record before it. Only outcomes that are
    /// decided before any backup is taken qualify: [`ItemOutcome::Vanished`], [`ItemOutcome::Skipped`] and
    /// [`ItemOutcome::Failed`]. `Done`, `HeldRetry` and `PendingReboot` always follow an intent.
    pub fn allowed_without_intent(&self) -> bool {
        matches!(
            self,
            ItemOutcome::Vanished | ItemOutcome::Skipped { .. } | ItemOutcome::Failed { .. }
        )
    }
}

/// How many items ended in each [`ItemOutcome`]. Every field reads as 0 when missing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct OutcomeCounts {
    /// Items with [`ItemOutcome::Done`].
    pub done: u32,
    /// Items with [`ItemOutcome::Vanished`].
    pub vanished: u32,
    /// Items with [`ItemOutcome::Skipped`].
    pub skipped: u32,
    /// Items with [`ItemOutcome::HeldRetry`].
    pub held_retry: u32,
    /// Items with [`ItemOutcome::PendingReboot`].
    pub pending_reboot: u32,
    /// Items with [`ItemOutcome::Failed`].
    pub failed: u32,
}

impl OutcomeCounts {
    /// Counts one outcome.
    pub fn record(&mut self, outcome: &ItemOutcome) {
        let slot = match outcome {
            ItemOutcome::Done => &mut self.done,
            ItemOutcome::Vanished => &mut self.vanished,
            ItemOutcome::Skipped { .. } => &mut self.skipped,
            ItemOutcome::HeldRetry => &mut self.held_retry,
            ItemOutcome::PendingReboot => &mut self.pending_reboot,
            ItemOutcome::Failed { .. } => &mut self.failed,
        };
        *slot = slot.saturating_add(1);
    }

    /// The number of outcomes counted.
    pub fn total(&self) -> u32 {
        [
            self.done,
            self.vanished,
            self.skipped,
            self.held_retry,
            self.pending_reboot,
            self.failed,
        ]
        .into_iter()
        .fold(0, u32::saturating_add)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;

    /// Reads `text` and checks that writing it back gives the same bytes.
    fn round_trip<T: Serialize + DeserializeOwned>(text: &str) -> T {
        let value: T = serde_json::from_str(text).unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(serde_json::to_string(&value).unwrap(), text);
        value
    }

    const HASH_A: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const HASH_B: &str = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";

    fn all_targets() -> Vec<Target> {
        let key = || r"HKLM\SOFTWARE\Vendor".to_owned();
        let targets = vec![
            Target::Path {
                path: r"C:\Program Files\Vendor".into(),
            },
            Target::RegKey { path: key() },
            Target::RegValue {
                path: key(),
                name: "Start".into(),
            },
            Target::RegValueChanged {
                path: key(),
                name: "Path".into(),
                before: "a".into(),
                after: "a;b".into(),
            },
            Target::RegMultiSzSegment {
                path: key(),
                name: "Path".into(),
                segment: r"C:\Vendor\bin".into(),
                index: Some(3),
            },
            Target::Service {
                name: "VendorSvc".into(),
            },
            Target::Task {
                path: r"\Vendor\Update".into(),
            },
            Target::FirewallRule { id: "{1}".into() },
            Target::AppxPackage {
                full_name: "Vendor.App_1.0.0.0_x64__abc".into(),
            },
        ];
        // One sample per variant: this match stops compiling when `Target` gains a variant, which is the
        // reminder to extend the list and the table.
        for target in &targets {
            match target {
                Target::Path { .. }
                | Target::RegKey { .. }
                | Target::RegValue { .. }
                | Target::RegValueChanged { .. }
                | Target::RegMultiSzSegment { .. }
                | Target::Service { .. }
                | Target::Task { .. }
                | Target::FirewallRule { .. }
                | Target::AppxPackage { .. } => {}
            }
        }
        targets
    }

    fn all_actions() -> Vec<Action> {
        let actions = vec![
            Action::Quarantine,
            Action::DeleteKey,
            Action::DeleteValue,
            Action::EditSegment,
            Action::RemoveDirIfEmpty,
            Action::RemovePackage,
            Action::ReportOnly,
        ];
        for action in &actions {
            match action {
                Action::Quarantine
                | Action::DeleteKey
                | Action::DeleteValue
                | Action::EditSegment
                | Action::RemoveDirIfEmpty
                | Action::RemovePackage
                | Action::ReportOnly => {}
            }
        }
        actions
    }

    /// The expected result for one pair, written out independently of `resolve`: the op name for the seven
    /// legal pairs, the mismatch otherwise.
    fn expected(target: &Target, action: Action) -> Result<&'static str, Mismatch> {
        use Action as A;
        if action == A::ReportOnly {
            return Err(Mismatch::ReportOnly);
        }
        match (target, action) {
            (Target::Path { .. }, A::Quarantine) => Ok("QuarantineMove"),
            (Target::Path { .. }, A::RemoveDirIfEmpty) => Ok("RemoveDirIfEmpty"),
            (Target::RegKey { .. }, A::DeleteKey) => Ok("DeleteKeyTree"),
            (Target::RegKey { .. }, A::RemoveDirIfEmpty) => Ok("DeleteKeyIfEmpty"),
            (Target::RegValue { .. }, A::DeleteValue) => Ok("DeleteValue"),
            (Target::RegMultiSzSegment { .. }, A::EditSegment) => Ok("EditSegment"),
            (Target::AppxPackage { .. }, A::RemovePackage) => Ok("RemovePackage"),
            (Target::RegValueChanged { .. }, _) => Err(Mismatch::TruthOnlyTarget),
            (Target::Service { .. } | Target::Task { .. } | Target::FirewallRule { .. }, _) => {
                Err(Mismatch::NoExecutor)
            }
            _ => Err(Mismatch::WrongAction),
        }
    }

    #[test]
    fn resolve_table_is_total_and_exact() {
        let targets = all_targets();
        let actions = all_actions();
        let mut legal = 0;
        for target in &targets {
            for &action in &actions {
                let got = resolve(target, action);
                assert_eq!(
                    got.as_ref().map(ExecOp::name).map_err(|m| *m),
                    expected(target, action),
                    "{target:?} x {action:?}"
                );
                if let Ok(op) = got {
                    legal += 1;
                    // The op carries the whole target, and maps back to the same pair.
                    assert_eq!(&op.target(), target);
                    assert_eq!(op.action(), action);
                    assert_eq!(resolve(&op.target(), op.action()), Ok(op));
                }
            }
        }
        assert_eq!(targets.len() * actions.len(), 63);
        assert_eq!(legal, 7);
    }

    #[test]
    fn report_only_and_changed_values_never_resolve() {
        for target in all_targets() {
            assert_eq!(
                resolve(&target, Action::ReportOnly),
                Err(Mismatch::ReportOnly)
            );
        }
        let changed = Target::RegValueChanged {
            path: "HKLM\\X".into(),
            name: String::new(),
            before: String::new(),
            after: String::new(),
        };
        for action in all_actions() {
            assert!(resolve(&changed, action).is_err(), "{action:?}");
        }
        assert!(!Mismatch::NoExecutor.to_string().is_empty());
    }

    #[test]
    fn exec_ops_round_trip_byte_for_byte() {
        let samples = [
            r#"{"kind":"QuarantineMove","path":"C:\\Program Files\\Vendor\\app.exe"}"#,
            r#"{"kind":"RemoveDirIfEmpty","path":"C:\\ProgramData\\Vendor"}"#,
            r#"{"kind":"DeleteKeyTree","key":"HKLM\\SOFTWARE\\WOW6432Node\\Vendor"}"#,
            r#"{"kind":"DeleteKeyIfEmpty","key":"HKU\\S-1-5-21-1-2-3-1001\\Software\\Vendor"}"#,
            r#"{"kind":"DeleteValue","key":"HKLM\\SOFTWARE\\Vendor","name":""}"#,
            r#"{"kind":"EditSegment","key":"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment","name":"Path","segment":"C:\\Vendor\\bin"}"#,
            r#"{"kind":"EditSegment","key":"HKLM\\X","name":"Path","segment":"s","index":2}"#,
            r#"{"kind":"RemovePackage","full_name":"Vendor.App_1.0.0.0_x64__abcdefghijklm"}"#,
        ];
        let mut names = Vec::new();
        for text in samples {
            let op: ExecOp = round_trip(text);
            assert!(text.contains(&format!(r#""kind":"{}""#, op.name())));
            names.push(op.name());
            assert_eq!(op.is_irreversible(), op.name() == "RemovePackage");
            assert_eq!(op.is_registry(), op.target().is_registry());
        }
        names.dedup();
        assert_eq!(names.len(), 7);
        assert!(serde_json::from_str::<ExecOp>(r#"{"kind":"DeleteService","name":"x"}"#).is_err());
        assert!(serde_json::from_str::<ExecOp>(r#"{"kind":"QuarantineMove"}"#).is_err());
    }

    fn inverse_samples() -> Vec<String> {
        vec![
            r#"{"kind":"MoveBack","quarantine_path":"C:\\ProgramData\\Purge\\Quarantine\\20261115T101502Z-9f3a6c1d2b7e4a50\\000001\\app.exe","original_path":"C:\\Program Files\\Vendor\\app.exe","file_id":"000102030405060708090a0b0c0d0e0f","volume_serial":18446744073709551615}"#
                .to_owned(),
            format!(
                r#"{{"kind":"RestoreKeyTree","backup":{{"path":"reg\\000002.regbackup.json","sha256":"{HASH_A}","bytes":4096}}}}"#
            ),
            format!(
                r#"{{"kind":"RestoreValue","backup":{{"path":"reg\\000003.regbackup.json","sha256":"{HASH_B}","bytes":212}}}}"#
            ),
            format!(
                r#"{{"kind":"ReinsertSegment","key":"HKLM\\X","name":"Path","index":4,"segment":"C:\\Vendor\\bin","original_value_hash":"{HASH_A}","written_value_hash":"{HASH_B}"}}"#
            ),
            format!(
                r#"{{"kind":"ReinsertSegment","key":"HKLM\\X","name":"","index":0,"segment":"s","original_value_hash":"{HASH_A}","written_value_hash":"{HASH_B}","backup":{{"path":"reg\\000004.regbackup.json","sha256":"{HASH_A}","bytes":90}}}}"#
            ),
            r#"{"kind":"RecreateDir","path":"C:\\ProgramData\\Vendor","attributes":16,"sddl":"O:BAG:SYD:AI(A;OICIID;FA;;;SY)"}"#.to_owned(),
            r#"{"kind":"RecreateDir","path":"C:\\V","attributes":18,"sddl":"O:BAG:SYD:","creation_time":133000000000000000,"last_write_time":133000000000000001}"#.to_owned(),
            format!(
                r#"{{"kind":"RecreateKey","backup":{{"path":"reg\\000005.regbackup.json","sha256":"{HASH_A}","bytes":150}}}}"#
            ),
            r#"{"kind":"None"}"#.to_owned(),
        ]
    }

    #[test]
    fn inverses_round_trip_byte_for_byte() {
        let mut names = Vec::new();
        for text in inverse_samples() {
            let inverse: Inverse = round_trip(&text);
            assert!(text.contains(&format!(r#""kind":"{}""#, inverse.name())));
            assert_eq!(
                inverse.backup().is_some(),
                text.contains("regbackup.json"),
                "{text}"
            );
            if let Some(backup) = inverse.backup() {
                assert!(backup.is_session_relative());
            }
            names.push(inverse.name());
        }
        names.dedup();
        assert_eq!(names.len(), 7);
        assert!(
            serde_json::from_str::<Inverse>(r#"{"kind":"RecreateService","definition":"x"}"#)
                .is_err()
        );
    }

    #[test]
    fn each_op_has_exactly_one_fitting_inverse() {
        let inverses: Vec<Inverse> = inverse_samples()
            .iter()
            .map(|text| serde_json::from_str(text).unwrap())
            .collect();
        for target in all_targets() {
            for action in all_actions() {
                let Ok(op) = resolve(&target, action) else {
                    continue;
                };
                let mut fitting: Vec<&str> = inverses
                    .iter()
                    .filter(|inverse| inverse.fits(&op))
                    .map(Inverse::name)
                    .collect();
                fitting.dedup();
                assert_eq!(fitting.len(), 1, "{op:?}: {fitting:?}");
                assert_eq!(fitting[0] == "None", op.is_irreversible());
            }
        }
    }

    #[test]
    fn hex_values_are_strict() {
        let hash: Sha256Hex = HASH_A.parse().unwrap();
        assert_eq!(hash.to_string(), HASH_A);
        assert_eq!(hash.as_bytes()[0], 0x9f);
        assert_eq!(Sha256Hex::from(*hash.as_bytes()), hash);
        assert_eq!(format!("{hash:?}"), format!("Sha256Hex({HASH_A})"));
        assert_eq!(
            HASH_A.to_uppercase().parse::<Sha256Hex>(),
            Err(HexError::BadDigit)
        );
        assert_eq!(HASH_A[1..].parse::<Sha256Hex>(), Err(HexError::BadLength));
        assert_eq!("".parse::<Sha256Hex>(), Err(HexError::BadLength));
        assert_eq!(
            format!("{HASH_A}00").parse::<Sha256Hex>(),
            Err(HexError::BadLength)
        );
        // 64 bytes of text that are not 64 characters.
        assert!("é".repeat(32).parse::<Sha256Hex>().is_err());
        assert!(serde_json::from_str::<Sha256Hex>(&format!("\"{HASH_A}\"")).is_ok());
        assert!(serde_json::from_str::<Sha256Hex>("\"abc\"").is_err());
        assert!(serde_json::from_str::<Sha256Hex>("5").is_err());

        let id: FileIdHex = round_trip(r#""000102030405060708090a0b0c0d0e0f""#);
        assert_eq!(id.0[15], 0x0f);
        assert_eq!(
            id,
            FileIdHex([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        );
        assert!(HASH_A.parse::<FileIdHex>().is_err());
        assert!(!HexError::BadLength.to_string().is_empty());
    }

    #[test]
    fn backup_ref_must_stay_inside_the_session() {
        let hash: Sha256Hex = HASH_A.parse().unwrap();
        let at = |path: &str| BackupRef {
            path: path.into(),
            sha256: hash,
            bytes: 1,
        };
        for good in [
            r"reg\000001.regbackup.json",
            "report.json",
            r"def\000002.json",
        ] {
            assert!(at(good).is_session_relative(), "{good}");
        }
        for bad in [
            "",
            r"\reg\x.json",
            r"C:\x.json",
            r"..\x.json",
            r"reg\..\..\x.json",
            r"reg\\x.json",
            r"reg\.\x.json",
            "reg/x.json",
            r"reg\x.json:stream",
            r"\\server\share\x",
            r"reg\",
        ] {
            assert!(!at(bad).is_session_relative(), "{bad}");
        }
    }

    #[test]
    fn op_id_names_sort_in_op_order() {
        assert_eq!(OpId(42).file_stem(), "000042");
        assert_eq!(OpId(42).to_string(), "42");
        assert!(OpId(9).file_stem() < OpId(10).file_stem());
        assert_eq!(OpId(1_234_567).file_stem(), "1234567");
        let id: OpId = round_trip("7");
        assert_eq!(id, OpId(7));
    }

    #[test]
    fn outcomes_round_trip_byte_for_byte() {
        let samples = [
            r#"{"kind":"Done"}"#,
            r#"{"kind":"Vanished"}"#,
            r#"{"kind":"Skipped","reason":{"kind":"ChangedSinceScan"}}"#,
            r#"{"kind":"Skipped","reason":{"kind":"NoLongerEmpty"}}"#,
            r#"{"kind":"Skipped","reason":{"kind":"GateBlocked","blocker":{"kind":"RegLink"}}}"#,
            r#"{"kind":"Skipped","reason":{"kind":"GateBlocked","blocker":{"kind":"DenyListed","rule":"fs.purge"}}}"#,
            r#"{"kind":"Skipped","reason":{"kind":"GateBlocked","blocker":{"kind":"ReversibilityNone"}}}"#,
            r#"{"kind":"Skipped","reason":{"kind":"NoVerifiedBackup"}}"#,
            r#"{"kind":"Skipped","reason":{"kind":"CapExceeded"}}"#,
            r#"{"kind":"Skipped","reason":{"kind":"NotAttempted"}}"#,
            r#"{"kind":"HeldRetry"}"#,
            r#"{"kind":"PendingReboot"}"#,
            r#"{"kind":"Failed","code":"AccessDenied","os_error":5}"#,
            r#"{"kind":"Failed","code":"Os","os_error":1392,"detail":"the file is corrupt"}"#,
            r#"{"kind":"Failed","code":"VerifyFailed"}"#,
        ];
        let mut counts = OutcomeCounts::default();
        for text in samples {
            let outcome: ItemOutcome = round_trip(text);
            counts.record(&outcome);
            assert_eq!(
                outcome.is_success(),
                matches!(outcome, ItemOutcome::Done | ItemOutcome::Vanished)
            );
            assert!(!(outcome.changed_system() && outcome.allowed_without_intent()));
        }
        assert_eq!(
            counts,
            OutcomeCounts {
                done: 1,
                vanished: 1,
                skipped: 8,
                held_retry: 1,
                pending_reboot: 1,
                failed: 3,
            }
        );
        assert_eq!(counts.total(), 15);
        for code in [
            "AccessDenied",
            "InUse",
            "ControlledFolderAccess",
            "VerifyFailed",
            "PackageApi",
            "Os",
            "Internal",
        ] {
            round_trip::<FailCode>(&format!("\"{code}\""));
        }
        assert!(serde_json::from_str::<ItemOutcome>(r#"{"kind":"Skipped"}"#).is_err());
        assert!(serde_json::from_str::<ItemOutcome>(r#"{"kind":"Gone"}"#).is_err());
    }

    #[test]
    fn outcome_counts_read_with_fields_missing() {
        let counts: OutcomeCounts = serde_json::from_str("{}").unwrap();
        assert_eq!(counts, OutcomeCounts::default());
        let counts: OutcomeCounts = serde_json::from_str(r#"{"failed":2}"#).unwrap();
        assert_eq!((counts.failed, counts.total()), (2, 2));
        round_trip::<OutcomeCounts>(
            r#"{"done":3,"vanished":1,"skipped":0,"held_retry":0,"pending_reboot":2,"failed":0}"#,
        );
        let mut full = OutcomeCounts {
            done: u32::MAX,
            ..OutcomeCounts::default()
        };
        full.record(&ItemOutcome::Done);
        full.record(&ItemOutcome::Vanished);
        assert_eq!((full.done, full.total()), (u32::MAX, u32::MAX));
    }

    #[test]
    fn json_schemas_generate() {
        let text = [
            serde_json::to_string(&schemars::schema_for!(ExecOp)).unwrap(),
            serde_json::to_string(&schemars::schema_for!(Inverse)).unwrap(),
            serde_json::to_string(&schemars::schema_for!(ItemOutcome)).unwrap(),
            serde_json::to_string(&schemars::schema_for!(OutcomeCounts)).unwrap(),
        ]
        .concat();
        for name in [
            "QuarantineMove",
            "DeleteKeyIfEmpty",
            "ReinsertSegment",
            "written_value_hash",
            "^[0-9a-f]{64}$",
            "^[0-9a-f]{32}$",
            "GateBlocked",
            "ControlledFolderAccess",
            "pending_reboot",
            "BackupRef",
        ] {
            assert!(text.contains(name), "schema lacks {name}");
        }
    }
}
