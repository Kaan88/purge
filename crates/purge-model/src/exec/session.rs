//! Session documents: the session id, the session index `sessions\index.json`, and the reports of an
//! execute and an undo run (ENGINE_PLAN.md §3.3 history methods, §7.4, §7.8).
//!
//! | Document | Schema id | Written by |
//! |---|---|---|
//! | [`SessionIndex`] | `purge.sessions/1` | the executor, after every run, undo and expiry |
//! | [`ExecReport`] | `purge.exec/1` | `purge-engine exec` (also `report.json` in the session directory) |
//! | [`UndoReport`] | `purge.undo/1` | `purge-engine undo` |
//!
//! The index is the one file standard users may read: the UI shows history and "N items expire soon" from
//! it without elevation. The installer creates it as the empty object `{}`, so every field of
//! [`SessionIndex`] has a default.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::journal::{UndoConflict, UndoOutcome};
use super::op::{ExecOp, ItemOutcome, OpId, OutcomeCounts, Sha256Hex};
use crate::ids::schema_id;
use crate::{AppRef, CandidateId, FileTime, Target};

schema_id!(
    /// The `schema` field of the session index: always the literal string `purge.sessions/1`. A missing
    /// field reads as this id (the installer writes `{}`); any other value fails.
    SessionIndexSchema = "purge.sessions/1"
);

schema_id!(
    /// The `schema` field of an execute report: always the literal string `purge.exec/1`.
    ExecReportSchema = "purge.exec/1"
);

schema_id!(
    /// The `schema` field of an undo report: always the literal string `purge.undo/1`.
    UndoReportSchema = "purge.undo/1"
);

/// Days a quarantined file or directory is kept before expiry may propose deleting it (§7.8).
pub const RETAIN_QUARANTINE_DAYS: u32 = 30;
/// Days a registry backup or a typed definition is kept (§7.8).
pub const RETAIN_BACKUP_DAYS: u32 = 180;
/// Days a session's journal is kept (§7.8).
pub const RETAIN_JOURNAL_DAYS: u32 = 365;

const TICKS_PER_SEC: u64 = 10_000_000;
const SECS_PER_DAY: i64 = 86_400;
/// 9999-12-31T23:59:59Z in Unix seconds: the last instant a four-digit year can spell.
const MAX_UNIX_SECS: i64 = 253_402_300_799;
/// 1601-01-01T00:00:00Z in Unix seconds: `FileTime(0)`.
const MIN_UNIX_SECS: i64 = -11_644_473_600;

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let year_of_era = y.rem_euclid(400);
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The proleptic Gregorian date (year, month, day) of a day count since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Why a string is not a session id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionIdError;

impl fmt::Display for SessionIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("session id needs the form YYYYMMDDTHHMMSSZ-<16 lower-case hex digits>")
    }
}

impl std::error::Error for SessionIdError {}

/// The id of one executor session: the UTC start time to the second plus 64 random bits, e.g.
/// `20261115T101502Z-9f3a6c1d2b7e4a50`.
///
/// The id is also the name of the session's directories, so its form is fixed and checked on every read:
/// 33 ASCII characters, a real calendar time, lower-case hex. No other string (a path, `..`, a name with a
/// separator) is a session id. Ids sort by start time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(String);

impl SessionId {
    /// Builds the id of a session that starts at `started`, with `random` from the system's random
    /// source. Times outside the years 1601 to 9999 are clamped.
    pub fn new(started: FileTime, random: u64) -> Self {
        let secs = started.to_unix_secs().clamp(MIN_UNIX_SECS, MAX_UNIX_SECS);
        let (year, month, day) = civil_from_days(secs.div_euclid(SECS_PER_DAY));
        let in_day = secs.rem_euclid(SECS_PER_DAY);
        Self(format!(
            "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z-{random:016x}",
            in_day / 3600,
            in_day / 60 % 60,
            in_day % 60
        ))
    }

    /// The id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The start time the id spells, to the second.
    pub fn started(&self) -> FileTime {
        // The text was checked when the id was built, so every field parses.
        let field = |range: std::ops::Range<usize>| self.0[range].parse::<i64>().unwrap_or(0);
        let days = days_from_civil(field(0..4), field(4..6), field(6..8));
        let secs = days * SECS_PER_DAY + field(9..11) * 3600 + field(11..13) * 60 + field(13..15);
        FileTime::from_unix_secs(secs)
    }

    /// The 64 random bits of the id.
    pub fn random(&self) -> u64 {
        u64::from_str_radix(&self.0[17..], 16).unwrap_or(0)
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SessionId {
    type Err = SessionIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        let shape_ok = bytes.len() == 33
            && bytes.iter().enumerate().all(|(i, &b)| match i {
                8 => b == b'T',
                15 => b == b'Z',
                16 => b == b'-',
                0..=14 => b.is_ascii_digit(),
                _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
            });
        if !shape_ok {
            return Err(SessionIdError);
        }
        // Writing the parsed time back catches every impossible date or time (month 13, 30 February,
        // hour 24, a year before 1601): those do not come out as the same text.
        let candidate = SessionId(s.to_owned());
        if SessionId::new(candidate.started(), candidate.random()) == candidate {
            Ok(candidate)
        } else {
            Err(SessionIdError)
        }
    }
}

impl Serialize for SessionId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = Cow::<str>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for SessionId {
    fn schema_name() -> Cow<'static, str> {
        "SessionId".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "description": "UTC start time and 64 random bits, e.g. 20261115T101502Z-9f3a6c1d2b7e4a50",
            "pattern": "^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$"
        })
    }
}

/// Where a session stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum SessionState {
    /// The journal has neither a commit nor an aborted record: the run is in progress, or it crashed and
    /// waits for recovery.
    Open,
    /// The run finished and was committed.
    Committed,
    /// The run stopped early (a backup or journal write failed); items after the stop are untouched.
    Aborted,
    /// Every op that changed the system was undone.
    Undone,
    /// Some ops were undone; others remain, or ended in a conflict.
    PartiallyUndone,
}

/// What a retention period applies to (§7.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum RetentionClass {
    /// Quarantined files and directories: [`RETAIN_QUARANTINE_DAYS`].
    Quarantine,
    /// Registry backups and typed definitions: [`RETAIN_BACKUP_DAYS`].
    Backup,
    /// The journal and the session's reports: [`RETAIN_JOURNAL_DAYS`].
    Journal,
}

impl RetentionClass {
    /// The retention period of the class in days.
    pub fn days(self) -> u32 {
        match self {
            RetentionClass::Quarantine => RETAIN_QUARANTINE_DAYS,
            RetentionClass::Backup => RETAIN_BACKUP_DAYS,
            RetentionClass::Journal => RETAIN_JOURNAL_DAYS,
        }
    }
}

/// When each class of a session's data expires. Expiry only proposes; nothing is deleted on these dates
/// without a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Expiry {
    /// When the quarantined files expire (start + 30 days).
    pub quarantine: FileTime,
    /// When the registry backups and definitions expire (start + 180 days).
    pub backups: FileTime,
    /// When the journal expires (start + 1 year).
    pub journal: FileTime,
}

impl Expiry {
    /// The expiry dates of a session that started at `started`.
    pub fn from_start(started: FileTime) -> Self {
        let after = |class: RetentionClass| {
            let ticks = u64::from(class.days()) * SECS_PER_DAY.unsigned_abs() * TICKS_PER_SEC;
            FileTime(started.0.saturating_add(ticks))
        };
        Self {
            quarantine: after(RetentionClass::Quarantine),
            backups: after(RetentionClass::Backup),
            journal: after(RetentionClass::Journal),
        }
    }

    /// The expiry date of one class.
    pub fn of(&self, class: RetentionClass) -> FileTime {
        match class {
            RetentionClass::Quarantine => self.quarantine,
            RetentionClass::Backup => self.backups,
            RetentionClass::Journal => self.journal,
        }
    }
}

/// How many bytes a session holds on one volume. The size cap (§7.8) is per volume.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct VolumeUsage {
    /// Serial number of the volume.
    pub serial: u64,
    /// Root of the volume as it was mounted during the run, e.g. `C:\`. For display only.
    pub root: String,
    /// Bytes of quarantine and backup data the session holds on the volume.
    pub bytes: u64,
}

/// One session in the index: enough for the history list and the expiry notice, without reading the
/// journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionSummary {
    /// The session id.
    pub id: SessionId,
    /// The app id of the plan that was executed.
    pub app: String,
    /// The app the plan's items belong to, when the plan names one.
    #[serde(default)]
    pub owner: Option<AppRef>,
    /// The hash of the executed plan.
    pub plan_hash: Sha256Hex,
    /// Where the session stands.
    pub state: SessionState,
    /// When the run started.
    pub started: FileTime,
    /// When the run was committed or aborted; `None` while the session is open.
    #[serde(default)]
    pub finished: Option<FileTime>,
    /// How many items ended in each outcome.
    #[serde(default)]
    pub counts: OutcomeCounts,
    /// How many ops have been undone.
    #[serde(default)]
    pub undone: u32,
    /// Bytes of quarantine and backup data the session still holds, over all volumes.
    #[serde(default)]
    pub backup_bytes: u64,
    /// The same bytes per volume.
    #[serde(default)]
    pub usage: Vec<VolumeUsage>,
    /// When each class of the session's data expires.
    pub expires: Expiry,
    /// The classes whose data has already been deleted by a confirmed expiry.
    #[serde(default)]
    pub purged: Vec<RetentionClass>,
    /// Whether a boot-time move of this session still waits for a restart.
    #[serde(default)]
    pub pending_reboot: bool,
}

/// The session index, `sessions\index.json`.
///
/// Every field has a default, so the installer's empty object `{}` reads as an index with no sessions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SessionIndex {
    /// Always `purge.sessions/1`.
    pub schema: SessionIndexSchema,
    /// The sessions, ordered by id (oldest first).
    pub sessions: Vec<SessionSummary>,
}

impl SessionIndex {
    /// The summary of one session.
    pub fn get(&self, id: &SessionId) -> Option<&SessionSummary> {
        self.sessions.iter().find(|s| &s.id == id)
    }

    /// Adds a session, or replaces the summary with the same id, and keeps the list ordered by id.
    pub fn upsert(&mut self, summary: SessionSummary) {
        match self.sessions.binary_search_by(|s| s.id.cmp(&summary.id)) {
            Ok(at) => self.sessions[at] = summary,
            Err(at) => self.sessions.insert(at, summary),
        }
    }

    /// Removes a session from the index and returns its summary.
    pub fn remove(&mut self, id: &SessionId) -> Option<SessionSummary> {
        let at = self.sessions.iter().position(|s| &s.id == id)?;
        Some(self.sessions.remove(at))
    }

    /// Bytes all sessions hold on the volume with this serial: the figure the size cap is checked
    /// against.
    pub fn bytes_on_volume(&self, serial: u64) -> u64 {
        self.sessions
            .iter()
            .flat_map(|s| &s.usage)
            .filter(|u| u.serial == serial)
            .fold(0, |sum, u| sum.saturating_add(u.bytes))
    }
}

/// A process that holds a file open, as Restart Manager reports it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Locker {
    /// Process id.
    pub pid: u32,
    /// Application name.
    pub name: String,
    /// Short name of the service, when the process is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

/// What became of the restore point (§7.7). Serialised as an object tagged by `"kind"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind")]
pub enum RestorePointOutcome {
    /// The policy did not ask for one.
    NotRequested,
    /// A restore point was created.
    Created {
        /// Its sequence number.
        sequence: i64,
    },
    /// Windows skipped it because another one was created within the last 24 hours.
    Throttled,
    /// System Restore is turned off.
    Disabled,
    /// Creating it failed. The run went on: restore points supplement quarantine, never replace it.
    Failed {
        /// The Win32 error code.
        os_error: u32,
    },
}

/// One item of an execute report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ItemReport {
    /// The candidate id of the plan item.
    pub item: CandidateId,
    /// The op id the item had in the session.
    pub op: OpId,
    /// What the item acts on, as the plan spells it.
    pub target: Target,
    /// The op the item resolved to.
    pub exec_op: ExecOp,
    /// How it ended.
    pub outcome: ItemOutcome,
    /// Bytes of quarantine and backup data kept for the item.
    #[serde(default)]
    pub backup_bytes: u64,
    /// Who held the item open, when it was locked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lockers: Vec<Locker>,
}

/// The result of one execute run, `purge.exec/1`: what `purge-engine exec` prints and what the rig reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExecReport {
    /// Always `purge.exec/1`.
    pub schema: ExecReportSchema,
    /// The session the run created.
    pub session: SessionId,
    /// The app id of the plan.
    pub app: String,
    /// The hash of the executed plan.
    pub plan_hash: Sha256Hex,
    /// The hash of the selection (SHA-256 over the sorted selected candidate ids).
    pub selection_hash: Sha256Hex,
    /// How the session ended: `Committed` or `Aborted`.
    pub state: SessionState,
    /// When the run started.
    pub started: FileTime,
    /// When the run was committed or aborted.
    pub finished: FileTime,
    /// One entry per selected item, in plan order.
    pub items: Vec<ItemReport>,
    /// How many items ended in each outcome; equals the tally of `items`.
    pub counts: OutcomeCounts,
    /// Bytes of quarantine and backup data the session holds.
    pub backup_bytes: u64,
    /// Whether a restart is needed to finish a boot-time move.
    pub pending_reboot: bool,
    /// What became of the restore point.
    pub restore_point: RestorePointOutcome,
    /// Anything else the user should know, one message per entry.
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl ExecReport {
    /// The tally of the item outcomes. A well-formed report has `counts == self.tally()`.
    pub fn tally(&self) -> OutcomeCounts {
        let mut counts = OutcomeCounts::default();
        for item in &self.items {
            counts.record(&item.outcome);
        }
        counts
    }
}

/// How undoing one op ended. Serialised as an object tagged by `"result"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "result")]
pub enum UndoResult {
    /// The inverse ran to an end; see the outcome.
    Finished {
        /// How it ended.
        outcome: UndoOutcome,
    },
    /// The inverse was not applied because the system no longer matches what it expects. Nothing is
    /// forced.
    Conflict {
        /// What stood in the way.
        conflict: UndoConflict,
        /// Free text for the report; may be empty.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        detail: String,
    },
}

/// One op of an undo report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UndoItemReport {
    /// The op that was to be undone.
    pub op: OpId,
    /// The candidate id of its plan item.
    pub item: CandidateId,
    /// What the item acts on.
    pub target: Target,
    /// How undoing it ended.
    pub result: UndoResult,
}

/// How many ops of an undo run ended in each way. Every field reads as 0 when missing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct UndoCounts {
    /// Ops whose previous state was restored.
    pub restored: u32,
    /// Ops whose previous state was already in place.
    pub already_restored: u32,
    /// Ops that had changed nothing.
    pub nothing_to_undo: u32,
    /// Ops left alone because of a conflict.
    pub conflicts: u32,
    /// Ops whose inverse failed.
    pub failed: u32,
}

impl UndoCounts {
    /// Counts one result.
    pub fn record(&mut self, result: &UndoResult) {
        let slot = match result {
            UndoResult::Finished { outcome } => match outcome {
                UndoOutcome::Restored => &mut self.restored,
                UndoOutcome::AlreadyRestored => &mut self.already_restored,
                UndoOutcome::NothingToUndo => &mut self.nothing_to_undo,
                UndoOutcome::Failed { .. } => &mut self.failed,
            },
            UndoResult::Conflict { .. } => &mut self.conflicts,
        };
        *slot = slot.saturating_add(1);
    }
}

/// The result of one undo run, `purge.undo/1`: what `purge-engine undo` prints and what the rig reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UndoReport {
    /// Always `purge.undo/1`.
    pub schema: UndoReportSchema,
    /// The session that was undone.
    pub session: SessionId,
    /// The session's state after the run: `Undone` or `PartiallyUndone`.
    pub state: SessionState,
    /// When the undo run started.
    pub started: FileTime,
    /// When it ended.
    pub finished: FileTime,
    /// One entry per op the run covered, in the order they were undone (the reverse of execution).
    pub items: Vec<UndoItemReport>,
    /// How many ops ended in each way; equals the tally of `items`.
    pub counts: UndoCounts,
    /// Anything else the user should know, one message per entry.
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl UndoReport {
    /// The tally of the item results. A well-formed report has `counts == self.tally()`.
    pub fn tally(&self) -> UndoCounts {
        let mut counts = UndoCounts::default();
        for item in &self.items {
            counts.record(&item.result);
        }
        counts
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

    const ID: &str = "20261115T101502Z-9f3a6c1d2b7e4a50";
    const HASH_A: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const HASH_B: &str = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";

    #[test]
    fn session_id_spells_time_and_random_bits() {
        // 2026-11-15T10:15:02Z.
        let started = FileTime::from_unix_secs(1_794_737_702);
        let id = SessionId::new(started, 0x9f3a_6c1d_2b7e_4a50);
        assert_eq!(id.as_str(), ID);
        assert_eq!(id.to_string(), ID);
        assert_eq!(id.started(), started);
        assert_eq!(id.random(), 0x9f3a_6c1d_2b7e_4a50);
        assert_eq!(ID.parse::<SessionId>().unwrap(), id);

        // Sub-second ticks are dropped; small random values are padded.
        let id = SessionId::new(FileTime(started.0 + 9_999_999), 1);
        assert_eq!(id.as_str(), "20261115T101502Z-0000000000000001");

        // The ends of the range, a leap day, and clamping beyond the range.
        assert_eq!(
            SessionId::new(FileTime(0), 0).as_str(),
            "16010101T000000Z-0000000000000000"
        );
        assert_eq!(
            SessionId::new(FileTime(u64::MAX), u64::MAX).as_str(),
            "99991231T235959Z-ffffffffffffffff"
        );
        let leap = SessionId::new(FileTime::from_unix_secs(1_709_251_199), 7);
        assert_eq!(leap.as_str(), "20240229T235959Z-0000000000000007");
        assert_eq!(leap.started(), FileTime::from_unix_secs(1_709_251_199));
        for text in [
            "16010101T000000Z-0000000000000000",
            "99991231T235959Z-ffffffffffffffff",
            "19700101T000000Z-0123456789abcdef",
        ] {
            assert_eq!(text.parse::<SessionId>().unwrap().as_str(), text);
        }
    }

    #[test]
    fn session_ids_sort_by_start_time() {
        let mut previous = SessionId::new(FileTime(0), u64::MAX);
        for secs in [
            -11_000_000_000,
            -1,
            0,
            1,
            951_782_400,
            1_794_737_702,
            4_102_444_800,
        ] {
            let id = SessionId::new(FileTime::from_unix_secs(secs), 0);
            assert!(id > previous, "{id} after {previous}");
            assert_eq!(id.started(), FileTime::from_unix_secs(secs));
            previous = id;
        }
    }

    #[test]
    fn session_id_refuses_everything_else() {
        for bad in [
            "",
            "..",
            r"..\..\Windows",
            "20261115T101502Z-9f3a6c1d2b7e4a5",
            "20261115T101502Z-9f3a6c1d2b7e4a500",
            "20261115T101502Z-9F3A6C1D2B7E4A50",
            "20261115T101502Z_9f3a6c1d2b7e4a50",
            "20261115t101502Z-9f3a6c1d2b7e4a50",
            "20261115T101502z-9f3a6c1d2b7e4a50",
            "2026111aT101502Z-9f3a6c1d2b7e4a50",
            "20261315T101502Z-9f3a6c1d2b7e4a50",
            "20260015T101502Z-9f3a6c1d2b7e4a50",
            "20261100T101502Z-9f3a6c1d2b7e4a50",
            "20260230T101502Z-9f3a6c1d2b7e4a50",
            "20250229T101502Z-9f3a6c1d2b7e4a50",
            "20261115T241502Z-9f3a6c1d2b7e4a50",
            "20261115T106002Z-9f3a6c1d2b7e4a50",
            "20261115T101560Z-9f3a6c1d2b7e4a50",
            "16001231T235959Z-9f3a6c1d2b7e4a50",
            "00000101T000000Z-9f3a6c1d2b7e4a50",
            "20261115T101502Z-9f3a6c1d2b7e4a5\\",
            "20261115T101502Z-9f3a6c1d2b7e4a5é",
            " 20261115T101502Z-9f3a6c1d2b7e4a50",
        ] {
            assert_eq!(bad.parse::<SessionId>(), Err(SessionIdError), "{bad:?}");
            assert!(serde_json::from_value::<SessionId>(serde_json::json!(bad)).is_err());
        }
        assert!(!SessionIdError.to_string().is_empty());
        round_trip::<SessionId>(&format!("\"{ID}\""));
    }

    #[test]
    fn civil_dates_convert_both_ways() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(days_from_civil(1601, 1, 1)), (1601, 1, 1));
        for days in (-134_774..2_932_897).step_by(997) {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    #[test]
    fn expiry_follows_the_retention_periods() {
        let started = FileTime::from_unix_secs(1_794_737_702);
        let expiry = Expiry::from_start(started);
        let day = 86_400;
        assert_eq!(expiry.quarantine.to_unix_secs(), 1_794_737_702 + 30 * day);
        assert_eq!(expiry.backups.to_unix_secs(), 1_794_737_702 + 180 * day);
        assert_eq!(expiry.journal.to_unix_secs(), 1_794_737_702 + 365 * day);
        for class in [
            RetentionClass::Quarantine,
            RetentionClass::Backup,
            RetentionClass::Journal,
        ] {
            let ticks = u64::from(class.days()) * 864_000_000_000;
            assert_eq!(expiry.of(class).0, started.0 + ticks);
        }
        assert_eq!(
            Expiry::from_start(FileTime(u64::MAX)).journal,
            FileTime(u64::MAX)
        );
        round_trip::<Expiry>(
            r#"{"quarantine":134100000000000000,"backups":134200000000000000,"journal":134300000000000000}"#,
        );
    }

    fn summary_json(id: &str, state: &str, serial: u64, bytes: u64) -> String {
        format!(
            r#"{{"id":"{id}","app":"firefox","owner":{{"program_id":"HKLM|64|Mozilla Firefox","display_name":"Mozilla Firefox"}},"plan_hash":"{HASH_A}","state":"{state}","started":134078121020000000,"finished":134078121950000000,"counts":{{"done":41,"vanished":2,"skipped":1,"held_retry":0,"pending_reboot":1,"failed":0}},"undone":0,"backup_bytes":{bytes},"usage":[{{"serial":{serial},"root":"C:\\","bytes":{bytes}}}],"expires":{{"quarantine":134104041020000000,"backups":134233641020000000,"journal":134393481020000000}},"purged":[],"pending_reboot":true}}"#
        )
    }

    #[test]
    fn empty_object_reads_as_an_empty_index() {
        let index: SessionIndex = serde_json::from_str("{}").unwrap();
        assert_eq!(index, SessionIndex::default());
        assert!(index.sessions.is_empty());
        assert_eq!(
            serde_json::to_string(&index).unwrap(),
            r#"{"schema":"purge.sessions/1","sessions":[]}"#
        );
        // A partly written index is still read: each field has its own default.
        let index: SessionIndex = serde_json::from_str(r#"{"sessions":[]}"#).unwrap();
        assert_eq!(index, SessionIndex::default());
        let index: SessionIndex = serde_json::from_str(r#"{"schema":"purge.sessions/1"}"#).unwrap();
        assert_eq!(index, SessionIndex::default());
    }

    #[test]
    fn index_round_trips_byte_for_byte() {
        let text = format!(
            r#"{{"schema":"purge.sessions/1","sessions":[{},{}]}}"#,
            summary_json(ID, "Committed", 0xC0FF_EE00_1234_5678, 52_428_800),
            summary_json("20261116T000000Z-0000000000000001", "PartiallyUndone", 7, 0),
        );
        let index: SessionIndex = round_trip(&text);
        assert_eq!(index.sessions.len(), 2);
        let first = index.get(&ID.parse().unwrap()).unwrap();
        assert_eq!(first.state, SessionState::Committed);
        assert_eq!(first.counts.total(), 45);
        assert_eq!(
            first.owner.as_ref().unwrap().display_name,
            "Mozilla Firefox"
        );
        assert_eq!(index.bytes_on_volume(0xC0FF_EE00_1234_5678), 52_428_800);
        assert_eq!(index.bytes_on_volume(1), 0);
    }

    #[test]
    fn index_refuses_other_schema_ids() {
        for bad in [
            r#"{"schema":"purge.sessions/0"}"#,
            r#"{"schema":"purge.sessions/2","sessions":[]}"#,
            r#"{"schema":"purge.exec/1"}"#,
            r#"{"schema":null}"#,
            r#"{"schema":1}"#,
        ] {
            assert!(serde_json::from_str::<SessionIndex>(bad).is_err(), "{bad}");
        }
        // A summary with a malformed id makes the whole index unreadable, not silently shorter.
        let text = format!(
            r#"{{"sessions":[{}]}}"#,
            summary_json("..", "Committed", 1, 1)
        );
        assert!(serde_json::from_str::<SessionIndex>(&text).is_err());
    }

    #[test]
    fn summary_reads_with_optional_fields_missing() {
        let text = format!(
            r#"{{"id":"{ID}","app":"a","plan_hash":"{HASH_A}","state":"Open","started":1,"expires":{{"quarantine":2,"backups":3,"journal":4}}}}"#
        );
        let summary: SessionSummary = serde_json::from_str(&text).unwrap();
        assert_eq!(summary.state, SessionState::Open);
        assert_eq!(
            (summary.finished, summary.owner.is_none(), summary.undone),
            (None, true, 0)
        );
        assert_eq!(summary.counts, OutcomeCounts::default());
        assert!(summary.usage.is_empty() && summary.purged.is_empty() && !summary.pending_reboot);
        for state in ["Open", "Committed", "Aborted", "Undone", "PartiallyUndone"] {
            round_trip::<SessionState>(&format!("\"{state}\""));
        }
        assert!(serde_json::from_str::<SessionState>("\"Expired\"").is_err());
    }

    #[test]
    fn upsert_keeps_the_index_ordered_and_unique() {
        let summary = |id: &str, bytes: u64| -> SessionSummary {
            serde_json::from_str(&summary_json(id, "Committed", 9, bytes)).unwrap()
        };
        let (a, b, c) = (
            "20260101T000000Z-0000000000000002",
            "20260101T000000Z-0000000000000003",
            "20260102T000000Z-0000000000000001",
        );
        let mut index = SessionIndex::default();
        index.upsert(summary(c, 1));
        index.upsert(summary(a, 2));
        index.upsert(summary(b, 4));
        let ids: Vec<&str> = index.sessions.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, [a, b, c]);
        assert_eq!(index.bytes_on_volume(9), 7);

        index.upsert(summary(b, 100));
        assert_eq!(index.sessions.len(), 3);
        assert_eq!(index.bytes_on_volume(9), 103);

        let removed = index.remove(&b.parse().unwrap()).unwrap();
        assert_eq!(removed.backup_bytes, 100);
        assert!(index.remove(&b.parse().unwrap()).is_none());
        assert!(index.get(&b.parse().unwrap()).is_none());
        assert_eq!(index.bytes_on_volume(9), 3);

        // Sums saturate instead of wrapping.
        index.upsert(summary(b, u64::MAX));
        assert_eq!(index.bytes_on_volume(9), u64::MAX);
    }

    fn exec_report_json(schema: &str) -> String {
        format!(
            concat!(
                r#"{{"schema":"{schema}","session":"{id}","app":"firefox","plan_hash":"{a}","selection_hash":"{b}","#,
                r#""state":"Committed","started":134078121020000000,"finished":134078121950000000,"items":["#,
                r#"{{"item":"c-01","op":1,"target":{{"type":"RegValue","path":"HKLM\\SOFTWARE\\Vendor","name":"Start"}},"#,
                r#""exec_op":{{"kind":"DeleteValue","key":"HKLM\\SOFTWARE\\Vendor","name":"Start"}},"outcome":{{"kind":"Done"}},"backup_bytes":212}},"#,
                r#"{{"item":"c-02","op":2,"target":{{"type":"Path","path":"C:\\Program Files\\Vendor\\app.exe"}},"#,
                r#""exec_op":{{"kind":"QuarantineMove","path":"C:\\Program Files\\Vendor\\app.exe"}},"outcome":{{"kind":"HeldRetry"}},"#,
                r#""backup_bytes":0,"lockers":[{{"pid":4312,"name":"Vendor App"}},{{"pid":900,"name":"Vendor Service","service":"VendorSvc"}}]}},"#,
                r#"{{"item":"c-03","op":3,"target":{{"type":"AppxPackage","full_name":"Vendor.App_1.0.0.0_x64__abc"}},"#,
                r#""exec_op":{{"kind":"RemovePackage","full_name":"Vendor.App_1.0.0.0_x64__abc"}},"#,
                r#""outcome":{{"kind":"Skipped","reason":{{"kind":"GateBlocked","blocker":{{"kind":"ReversibilityNone"}}}}}},"backup_bytes":0}}"#,
                r#"],"counts":{{"done":1,"vanished":0,"skipped":1,"held_retry":1,"pending_reboot":0,"failed":0}},"#,
                r#""backup_bytes":212,"pending_reboot":false,"restore_point":{{"kind":"Created","sequence":118}},"#,
                r#""warnings":["1 item is held until the next run"]}}"#
            ),
            schema = schema,
            id = ID,
            a = HASH_A,
            b = HASH_B,
        )
    }

    #[test]
    fn exec_report_round_trips_byte_for_byte() {
        let report: ExecReport = round_trip(&exec_report_json("purge.exec/1"));
        assert_eq!(report.items.len(), 3);
        assert_eq!(report.counts, report.tally());
        assert_eq!(
            report.items[1].lockers[1].service.as_deref(),
            Some("VendorSvc")
        );
        for item in &report.items {
            assert_eq!(item.exec_op.target(), item.target);
        }
        for bad in [
            "purge.exec/0",
            "purge.exec/2",
            "purge.undo/1",
            "purge.plan/0",
        ] {
            assert!(
                serde_json::from_str::<ExecReport>(&exec_report_json(bad)).is_err(),
                "{bad}"
            );
        }
        for text in [
            r#"{"kind":"NotRequested"}"#,
            r#"{"kind":"Created","sequence":-1}"#,
            r#"{"kind":"Throttled"}"#,
            r#"{"kind":"Disabled"}"#,
            r#"{"kind":"Failed","os_error":1058}"#,
        ] {
            round_trip::<RestorePointOutcome>(text);
        }
    }

    fn undo_report_json(schema: &str) -> String {
        format!(
            concat!(
                r#"{{"schema":"{schema}","session":"{id}","state":"PartiallyUndone","started":134078130000000000,"#,
                r#""finished":134078130050000000,"items":["#,
                r#"{{"op":3,"item":"c-03","target":{{"type":"RegKey","path":"HKLM\\SOFTWARE\\Vendor"}},"#,
                r#""result":{{"result":"Conflict","conflict":{{"kind":"KeyExists"}},"detail":"the key has 2 values"}}}},"#,
                r#"{{"op":2,"item":"c-02","target":{{"type":"Path","path":"C:\\V\\a.txt"}},"#,
                r#""result":{{"result":"Finished","outcome":{{"kind":"Restored"}}}}}},"#,
                r#"{{"op":1,"item":"c-01","target":{{"type":"RegValue","path":"HKLM\\X","name":""}},"#,
                r#""result":{{"result":"Finished","outcome":{{"kind":"Failed","code":"AccessDenied","os_error":5}}}}}}"#,
                r#"],"counts":{{"restored":1,"already_restored":0,"nothing_to_undo":0,"conflicts":1,"failed":1}},"warnings":[]}}"#
            ),
            schema = schema,
            id = ID,
        )
    }

    #[test]
    fn undo_report_round_trips_byte_for_byte() {
        let report: UndoReport = round_trip(&undo_report_json("purge.undo/1"));
        assert_eq!(report.items.len(), 3);
        assert_eq!(report.counts, report.tally());
        assert_eq!(report.state, SessionState::PartiallyUndone);
        for bad in ["purge.undo/0", "purge.exec/1", ""] {
            assert!(
                serde_json::from_str::<UndoReport>(&undo_report_json(bad)).is_err(),
                "{bad}"
            );
        }
        let mut counts = UndoCounts::default();
        for text in [
            r#"{"result":"Finished","outcome":{"kind":"AlreadyRestored"}}"#,
            r#"{"result":"Finished","outcome":{"kind":"NothingToUndo"}}"#,
            r#"{"result":"Conflict","conflict":{"kind":"BackupTampered"}}"#,
        ] {
            counts.record(&round_trip::<UndoResult>(text));
        }
        assert_eq!(
            (
                counts.already_restored,
                counts.nothing_to_undo,
                counts.conflicts
            ),
            (1, 1, 1)
        );
        assert_eq!(
            serde_json::from_str::<UndoCounts>("{}").unwrap(),
            UndoCounts::default()
        );
    }

    #[test]
    fn json_schemas_generate() {
        let text = [
            serde_json::to_string(&schemars::schema_for!(SessionIndex)).unwrap(),
            serde_json::to_string(&schemars::schema_for!(ExecReport)).unwrap(),
            serde_json::to_string(&schemars::schema_for!(UndoReport)).unwrap(),
        ]
        .concat();
        for name in [
            r#""const":"purge.sessions/1""#,
            r#""const":"purge.exec/1""#,
            r#""const":"purge.undo/1""#,
            "PartiallyUndone",
            "pending_reboot",
            "backup_bytes",
            "^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$",
            "Throttled",
            "lockers",
            "BackupTampered",
            "already_restored",
        ] {
            assert!(text.contains(name), "schema lacks {name}");
        }
    }
}
