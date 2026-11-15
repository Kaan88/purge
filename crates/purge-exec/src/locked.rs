//! Locked-file ladder, boot-time moves, reconcile after reboot (M2-X-LOCK; ENGINE_PLAN.md §7.6, §10.2,
//! §11.2).
//!
//! A boot-time move is performed by the session manager, as SYSTEM, by **path**, at the next start. Nobody
//! looks at the path again in between, so a pair in `PendingFileRenameOperations` whose source a user can
//! redirect (a junction in a writable ancestor) would let that user move any file of the system. Every
//! rule here therefore fails closed: when anything is unknown, the item is held for the next run and no
//! pair is written.
//!
//! # The ladder
//!
//! The file action hands over an item that stayed locked after its retries as a [`LockedItem`] (built
//! from the gate's [`LockedPath`] with [`LockedItem::from_gate`], or by hand when a rename met a lock after
//! the intent). [`Ladder::prepare`] then climbs, in this order:
//!
//! 1. **Name the lockers** ([`LockerQuery`], query only, this process filtered out). Directories are not
//!    queried (Restart Manager takes files).
//! 2. **Closing them needs consent** ([`ConsentCallback`], asked only when there are lockers). The default
//!    answer is [`DenyAll`]. Nothing is ever closed, stopped or restarted in M2, whatever the answer: the
//!    answer is only recorded ([`LockResult::close_consent`]).
//! 3. **Boot-time move into quarantine**, only when every row below holds; the first that fails holds the
//!    item ([`ItemOutcome::HeldRetry`], "retry at the next run", where the handle-based gate validates it
//!    again):
//!
//!    | # | Condition | Hold code when it fails |
//!    |---|---|---|
//!    | a | the item is a file, not a directory (what lies below a directory may change before the restart) | [`reason::DIRECTORY`] |
//!    | b | the gate says the item and every ancestor up to the drive root are writable by administrators and SYSTEM only and none is a reparse point ([`gate::admin_only_ancestors`]) | the guard's `live.boot.*` code |
//!    | c | the recorded volume serial is known (not 0) | [`reason::VOLUME_UNKNOWN`] |
//!    | d | the quarantine destination passes [`live::check_quarantine_destination`] for this session's [`StoreScope`] (inside `<quarantine>\<session>\<op>\`, parent the plain directory its path names, same drive, both serials known and equal, nothing there) | the guard's `live.quarantine.*` code |
//!    | e | the destination directory's serial equals the recorded serial | [`reason::OTHER_VOLUME`] |
//!
//! 4. **A boot-time delete is never chosen.** It has no inverse and needs its own prompt (§7.6 step 5),
//!    which M2 does not have: [`request_boot_delete`] always answers
//!    `Skipped{GateBlocked{ReversibilityNone}}`, and no code path here writes a pair with an empty
//!    destination.
//!
//! Before the ladder, an item that no longer is what was validated is decided without an intent:
//!
//! | Situation | Outcome |
//! |---|---|
//! | not a `QuarantineMove`, invalid recorded identity, journalled intent differs | `Failed{Internal}` |
//! | the open error does not mean "in use" ([`gate`]'s rule) | `Failed{AccessDenied}` / `Failed{Os}` |
//! | the gate saw another identity or kind than validated | `Skipped{ChangedSinceScan}` |
//! | the source is gone now | `Vanished` |
//! | the source is another object now | `Skipped{ChangedSinceScan}` |
//! | the source cannot be read now | `Failed{Os}` |
//!
//! # Journal contract
//!
//! Like [`crate::act_typed`], this module never writes the journal; it returns what the executor journals:
//!
//! 1. [`Ladder::prepare`] returns [`LockPrepared::Decided`] (journal the outcome with
//!    `done_without_intent`, or with `done(token, ..)` when the op already holds a token) or
//!    [`LockPrepared::Ready`].
//! 2. For `Ready`: when [`LockAction::intent_to_write`] is `Some`, write it with `JournalWriter::intent`
//!    and take the token; when it is `None` the file action already journalled this very intent (checked
//!    by `prepare`), so use that token. Then hit `act.before`.
//! 3. [`Ladder::act`] takes the token as proof of the durable intent. For a hold it changes nothing and
//!    returns `HeldRetry`. For a boot move it re-checks the source and the whole boot-move rung, looks for
//!    the pair in the list (one already there is adopted, never doubled), registers it, hits
//!    `bootmove.registered`, reads the list back and returns `PendingReboot{pair, confirmed}` with the pair
//!    **as it stands in the list**. Journal the result with `JournalWriter::done(token, ..)`.
//!
//! The intent is the one a quarantine move would write: `QuarantineMove{path}` with
//! `MoveBack{quarantine_path, original_path, file_id, volume_serial}` and `pre` = the validated facts (a
//! locked item has no acting handle). So a held item that a later run moves, and a boot move that a
//! restart completes, are undone by the ordinary move back to the recorded quarantine path.
//!
//! # After the restart
//!
//! - [`reconcile`] (at the next start, per op still pending a reboot) returns a [`Reconciled`] per op; see
//!   [`ReconcileVerdict`] for the table. Journal [`Reconciled::record`] when it is `Some`.
//! - [`retry_held`] tries the held items again through a [`RetryMove`] the executor supplies (the move
//!   belongs to the file action) and returns `Retried{outcome}` results to journal.
//! - [`undo_locked`] says how to undo a lock op; a pending boot move is undone by removing **our exact
//!   pair only** ([`remove_boot_move`], under an undo token).
//! - [`pending_after_crash`] tells recovery whether an intent-only op left a registered pair.
//!
//! # The boot-time move list
//!
//! Every access goes through [`PendingRenames`]: [`SystemPendingRenames`] over `purge_win::fs_write`, and
//! `MemoryPendingRenames` (tests and `test-support`) over a byte buffer with the same cutting code. Pairs
//! of other programs are never touched or reordered: registering appends, removing cuts the exact byte
//! range of our pair and only after the list showed it exactly once.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use purge_guard::live::{
    self, BootMove, DestinationFacts, FileIdentity, PathStamp, QuarantineCheck, StoreScope,
};
use purge_model::exec::journal::{
    FileFacts, GateExemptions, Intent, ItemFacts, Reconcile, ReconcileResult, Record, UndoOutcome,
};
use purge_model::exec::op::{
    BootMovePair, ExecOp, FailCode, Inverse, ItemOutcome, OpId, SkipReason,
};
use purge_model::exec::session::Locker;
use purge_model::{Blocker, CandidateId, FileTime};
use purge_win::fs::FileHandle;
use purge_win::fs_write::{self, DestDir, FsError, MoveHandle, PendingPair, extended_path};
use purge_win::os::Win32Error;
use purge_win::rm::RebootReasons;

use crate::fault;
use crate::gate::{self, GateCtx, LockedPath};
use crate::journal::{IntentToken, JournalState, OpState, UndoToken};
use crate::prepare::LockerQuery;
use crate::storage::SessionDir;

#[cfg(test)]
mod tests;

/// Codes for why an item was held or decided here (the guard's own `live.boot.*` and
/// `live.quarantine.*` codes are passed through unchanged).
pub mod reason {
    /// A directory is never moved at boot.
    pub const DIRECTORY: &str = "lock.directory";
    /// The recorded volume serial is 0 (unknown).
    pub const VOLUME_UNKNOWN: &str = "lock.volume-unknown";
    /// The destination directory is on another volume than the item.
    pub const OTHER_VOLUME: &str = "lock.other-volume";
    /// The op is not a quarantine move of a file-system item.
    pub const NOT_A_MOVE: &str = "lock.not-a-move";
    /// The recorded file id cannot identify anything.
    pub const IDENTITY_INVALID: &str = "lock.identity-invalid";
    /// The journalled intent of the op differs from the one the ladder would write.
    pub const INTENT_DIFFERS: &str = "lock.intent-differs";
    /// The open error of the acting handle does not mean "in use".
    pub const NOT_IN_USE: &str = "lock.not-in-use";
    /// The item is another object than the one validated.
    pub const CHANGED: &str = "lock.changed";
    /// The item is gone.
    pub const VANISHED: &str = "lock.vanished";
    /// The item cannot be looked at.
    pub const UNREADABLE: &str = "lock.unreadable";
    /// The boot-time move list could not be read or written.
    pub const LIST_FAILED: &str = "lock.list-failed";
    /// Our pair stands in the list more than once.
    pub const PAIR_COUNT: &str = "lock.pair-count";
    /// The token belongs to another op.
    pub const FOREIGN_TOKEN: &str = "lock.foreign-token";
    /// A boot-time delete was asked for: it is never chosen without its own consent prompt.
    pub const BOOT_DELETE: &str = "lock.boot-delete-needs-consent";
}

// ---------------------------------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------------------------------

/// The hand-over from the file action for an item that stayed locked after its retries.
///
/// - `exec_op` must be [`ExecOp::QuarantineMove`]; its `path` is the recorded source path, the plan's
///   lexical path that the gate judged (G1: equal to the handle's final path).
/// - `validated` is the item's `validated` record facts (identity, kind, size ...). They become the
///   intent's `pre`, because a locked item has no acting handle to read them from.
/// - `seen` is what the gate's read-only look showed now ([`LockedPath::stamp`]); it must equal the
///   validated identity and kind.
/// - `error` is the open (or rename) error of the acting handle.
/// - `quarantine_path` is `<op dir>\<leaf>` for this op, the op directory created by
///   `SessionDir::create_op_dir(source, serial, op)` (`QuarantineDir::item_path`); it is what the intent's
///   `MoveBack` records and the destination of a boot move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedItem {
    /// The op id.
    pub op: OpId,
    /// The candidate id of the plan item.
    pub item: CandidateId,
    /// The op; must be [`ExecOp::QuarantineMove`].
    pub exec_op: ExecOp,
    /// The facts of the item's `validated` record.
    pub validated: FileFacts,
    /// Identity and kind the gate saw on its read-only look now.
    pub seen: PathStamp,
    /// The error that stopped the acting handle.
    pub error: FsError,
    /// Absolute path of the item inside this op's quarantine directory.
    pub quarantine_path: String,
}

impl LockedItem {
    /// The hand-over from a [`gate::open_and_check_path`] that ended in `GateOutcome::Locked`.
    pub fn from_gate(
        op: OpId,
        item: CandidateId,
        exec_op: ExecOp,
        validated: FileFacts,
        locked: &LockedPath,
        quarantine_path: impl Into<String>,
    ) -> LockedItem {
        LockedItem {
            op,
            item,
            exec_op,
            validated,
            seen: locked.stamp,
            error: FsError::from(locked.error),
            quarantine_path: quarantine_path.into(),
        }
    }

    /// The source path, when the op is a quarantine move.
    pub fn source(&self) -> Option<&str> {
        match &self.exec_op {
            ExecOp::QuarantineMove { path } => Some(path),
            _ => None,
        }
    }

    /// The identity the validated record holds.
    pub fn identity(&self) -> FileIdentity {
        FileIdentity {
            volume_serial: self.validated.volume_serial,
            file_id: self.validated.file_id.0,
        }
    }

    /// The intent a quarantine move of this item writes (and the ladder too).
    pub fn intent(&self) -> Option<Intent> {
        let source = self.source()?;
        Some(Intent {
            op: self.op,
            item: self.item.clone(),
            exec_op: self.exec_op.clone(),
            inverse: Inverse::MoveBack {
                quarantine_path: self.quarantine_path.clone(),
                original_path: source.to_owned(),
                file_id: self.validated.file_id,
                volume_serial: self.validated.volume_serial,
            },
            definition: None,
            pre: ItemFacts::File(self.validated.clone()),
        })
    }
}

// ---------------------------------------------------------------------------------------------------
// Facts the ladder reads
// ---------------------------------------------------------------------------------------------------

/// What a read-only, no-follow look at a path shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceState {
    /// Nothing is there.
    Absent,
    /// An object with this identity and kind is there.
    Present {
        /// Its identity.
        identity: FileIdentity,
        /// Whether it is a directory.
        is_dir: bool,
    },
    /// The look failed with this Win32 error.
    Unreadable(u32),
}

/// The live facts the ladder needs. [`LiveLadder`] reads them from the system; tests inject verdicts a
/// test machine cannot produce unelevated (an admin-only ancestor chain).
pub trait LadderEnv {
    /// The boot-move verdict on the item and its ancestors ([`gate::admin_only_ancestors`]).
    fn ancestors(&self, source: &str) -> BootMove;
    /// The facts of a rename destination, read from a no-follow handle on its parent directory.
    fn destination(&self, destination: &str) -> DestinationFacts;
    /// A read-only, no-follow look at `path`.
    fn look(&self, path: &str) -> SourceState;
}

/// The facts as the system gives them.
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveLadder;

impl LadderEnv for LiveLadder {
    fn ancestors(&self, source: &str) -> BootMove {
        gate::admin_only_ancestors(source)
    }

    fn destination(&self, destination: &str) -> DestinationFacts {
        live_destination(destination)
    }

    fn look(&self, path: &str) -> SourceState {
        look(path)
    }
}

/// The `\\?\` form of an absolute path.
fn ext(path: &str) -> Option<PathBuf> {
    extended_path(Path::new(path)).ok()
}

/// A read-only, no-follow look (`FILE_READ_ATTRIBUTES`, full sharing, so a locked file can be looked at).
fn look(path: &str) -> SourceState {
    let Some(p) = ext(path) else {
        return SourceState::Unreadable(Win32Error::INVALID_PARAMETER.0);
    };
    match FileHandle::open(&p).and_then(|h| h.metadata()) {
        Ok(meta) => SourceState::Present {
            identity: FileIdentity {
                volume_serial: meta.file_id.volume_serial,
                file_id: meta.file_id.id,
            },
            is_dir: meta.is_dir,
        },
        Err(e) if e.is_not_found() => SourceState::Absent,
        Err(e) => SourceState::Unreadable(e.0),
    }
}

/// The [`DestinationFacts`] of `destination`, from a no-follow handle on its parent (the same reading as
/// the gate's for an acting handle). Whether the leaf is taken counts only while the parent handle's final
/// path is the same before and after the probe. Unknown facts stay `None`, which the guard refuses.
fn live_destination(destination: &str) -> DestinationFacts {
    let mut facts = DestinationFacts::default();
    let target = Path::new(destination);
    let Some(parent) = target.parent().and_then(|p| extended_path(p).ok()) else {
        return facts;
    };
    let Ok(dir) = DestDir::open(&parent) else {
        return facts;
    };
    let Ok(dir_facts) = dir.facts() else {
        return facts;
    };
    facts.parent_reparse_tag = Some(dir_facts.reparse_tag);
    facts.parent_is_dir = Some(dir_facts.is_dir);
    facts.parent_volume_serial = Some(dir_facts.volume_serial());
    let occupied = match ext(destination).map(|p| FileHandle::open(&p)) {
        Some(Ok(_)) => Some(true),
        Some(Err(e)) if e.is_not_found() => Some(false),
        _ => None,
    };
    let unchanged = dir.as_file().final_path().ok().as_deref() == Some(&dir_facts.final_path);
    facts.parent_final_path = Some(dir_facts.final_path);
    facts.occupied = occupied.filter(|_| unchanged);
    facts
}

// ---------------------------------------------------------------------------------------------------
// The boot-time move list
// ---------------------------------------------------------------------------------------------------

/// Access to `PendingFileRenameOperations`. Implementations never rewrite the list wholesale.
pub trait PendingRenames {
    /// Every pair, `PendingFileRenameOperations` first, then `...2`, in stored order.
    fn list(&self) -> Result<Vec<PendingPair>, FsError>;
    /// Appends a rename of `src` to `dst` (both absolute) for the next boot, without
    /// `MOVEFILE_REPLACE_EXISTING`, and reports the pair as stored.
    fn register(&mut self, src: &Path, dst: &Path) -> Result<fs_write::BootMove, FsError>;
    /// Cuts every occurrence of exactly `pair` (unit for unit) and returns how many were cut. Callers
    /// count first: [`remove_boot_move`] calls it only after the list showed the pair exactly once.
    fn remove_exact(&mut self, pair: &PendingPair) -> Result<usize, FsError>;
}

/// The real list in `HKLM\SYSTEM\<current control set>\Control\Session Manager`. Registering and
/// removing need administrative rights; reading does not.
///
/// The registry has no compare-and-swap: between the count [`remove_boot_move`] takes and the removal a
/// writer could add the same pair (only Purge writes pairs into its own quarantine), and
/// `remove_pending_pairs` itself has a two-call window (see its docs).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemPendingRenames;

impl PendingRenames for SystemPendingRenames {
    fn list(&self) -> Result<Vec<PendingPair>, FsError> {
        fs_write::pending_renames()
    }

    fn register(&mut self, src: &Path, dst: &Path) -> Result<fs_write::BootMove, FsError> {
        fs_write::move_delay_until_reboot(src, dst)
    }

    fn remove_exact(&mut self, pair: &PendingPair) -> Result<usize, FsError> {
        fs_write::remove_pending_pairs(std::slice::from_ref(pair))
    }
}

/// An in-memory `PendingFileRenameOperations` value (raw `REG_MULTI_SZ` bytes) for tests. Removal uses
/// `purge_win::fs_write::remove_pairs_from_value`, the cutting code of the real removal.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryPendingRenames {
    value: Vec<u8>,
    marker: String,
    /// How many times [`PendingRenames::register`] was called.
    pub registers: usize,
    /// How many times [`PendingRenames::remove_exact`] was called.
    pub removals: usize,
    /// Makes every call fail with this error.
    pub fail: Option<FsError>,
}

#[cfg(any(test, feature = "test-support"))]
impl MemoryPendingRenames {
    /// A list holding `pairs` (source, destination), each a raw string as stored.
    pub fn with_pairs(pairs: &[(&str, &str)]) -> MemoryPendingRenames {
        let mut value = Vec::new();
        for (src, dst) in pairs {
            push_units(&mut value, src);
            push_units(&mut value, dst);
        }
        if !value.is_empty() {
            value.extend_from_slice(&[0, 0]);
        }
        MemoryPendingRenames {
            value,
            ..MemoryPendingRenames::default()
        }
    }

    /// Registers pairs with this marker in front of the source (`*1`), as newer Windows builds may.
    pub fn with_marker(mut self, marker: &str) -> MemoryPendingRenames {
        self.marker = marker.to_owned();
        self
    }

    /// The raw value.
    pub fn bytes(&self) -> &[u8] {
        &self.value
    }

    fn check(&self) -> Result<(), FsError> {
        self.fail.map_or(Ok(()), Err)
    }
}

#[cfg(any(test, feature = "test-support"))]
fn push_units(out: &mut Vec<u8>, s: &str) {
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
}

#[cfg(any(test, feature = "test-support"))]
impl PendingRenames for MemoryPendingRenames {
    fn list(&self) -> Result<Vec<PendingPair>, FsError> {
        self.check()?;
        Ok(fs_write::parse_pending_renames(&self.value))
    }

    fn register(&mut self, src: &Path, dst: &Path) -> Result<fs_write::BootMove, FsError> {
        self.check()?;
        self.registers += 1;
        let expected = fs_write::pending_pair(src, dst)?;
        let stored = PendingPair {
            src: format!("{}{}", self.marker, expected.src),
            dst: expected.dst,
        };
        // Append after the last complete pair, before the terminator, as MoveFileExW does.
        let end: usize = fs_write::parse_pending_renames(&self.value)
            .iter()
            .map(|p| (p.src.encode_utf16().count() + p.dst.encode_utf16().count() + 2) * 2)
            .sum();
        let mut pair = Vec::new();
        push_units(&mut pair, &stored.src);
        push_units(&mut pair, &stored.dst);
        let mut value = self.value[..end].to_vec();
        value.extend_from_slice(&pair);
        if self.value.len() > end {
            value.extend_from_slice(&self.value[end..]);
        } else {
            value.extend_from_slice(&[0, 0]);
        }
        self.value = value;
        Ok(fs_write::BootMove {
            pair: stored,
            confirmed: true,
        })
    }

    fn remove_exact(&mut self, pair: &PendingPair) -> Result<usize, FsError> {
        self.check()?;
        self.removals += 1;
        let edit = fs_write::remove_pairs_from_value(&self.value, std::slice::from_ref(pair));
        if edit.removed > 0 {
            self.value = edit.value.unwrap_or_default();
        }
        Ok(edit.removed)
    }
}

/// An entry without the leading `*<digits>` marker newer Windows builds may write.
fn strip_marker(entry: &str) -> &str {
    match entry.strip_prefix('*') {
        Some(rest) => rest.trim_start_matches(|c: char| c.is_ascii_digit()),
        None => entry,
    }
}

/// Whether a listed pair is `ours`, the marker aside on both sides; otherwise unit for unit.
fn is_ours(listed: &PendingPair, ours: &BootMovePair) -> bool {
    strip_marker(&listed.src) == strip_marker(&ours.src)
        && strip_marker(&listed.dst) == strip_marker(&ours.dst)
}

/// The listed occurrences of `ours`, as stored.
fn occurrences(list: &[PendingPair], ours: &BootMovePair) -> Vec<PendingPair> {
    list.iter().filter(|p| is_ours(p, ours)).cloned().collect()
}

fn model_pair(pair: &PendingPair) -> BootMovePair {
    BootMovePair {
        src: pair.src.clone(),
        dst: pair.dst.clone(),
    }
}

/// The pair a boot move of `source` to `destination` registers, in the spelling `MoveFileExW` stores
/// (without a marker).
fn expected_pair(source: &str, destination: &str) -> Result<BootMovePair, FsError> {
    fs_write::pending_pair(Path::new(source), Path::new(destination)).map(|p| model_pair(&p))
}

// ---------------------------------------------------------------------------------------------------
// Consent
// ---------------------------------------------------------------------------------------------------

/// What the ladder asks consent for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentRequest<'a> {
    /// Close the programs and stop the services holding the item (§7.6 step 3).
    CloseLockers {
        /// The op.
        op: OpId,
        /// The item's path.
        path: &'a str,
        /// Who holds it.
        lockers: &'a [Locker],
    },
}

/// An answer to a [`ConsentRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent {
    /// No.
    Deny,
    /// Yes.
    Allow,
}

/// Asks the user (M3: the broker's dialog). Closures `Fn(&ConsentRequest) -> Consent` qualify.
pub trait ConsentCallback {
    /// The answer to `request`.
    fn ask(&self, request: &ConsentRequest<'_>) -> Consent;
}

impl<F: Fn(&ConsentRequest<'_>) -> Consent> ConsentCallback for F {
    fn ask(&self, request: &ConsentRequest<'_>) -> Consent {
        self(request)
    }
}

/// The default callback: denies everything (the rig path and every M2 caller).
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAll;

impl ConsentCallback for DenyAll {
    fn ask(&self, _: &ConsentRequest<'_>) -> Consent {
        Consent::Deny
    }
}

/// What became of the consent question for one item.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConsentAnswer {
    /// Not asked (no lockers, or the item was decided before).
    #[default]
    NotAsked,
    /// Asked and denied.
    Denied,
    /// Asked and allowed. Nothing was closed: M2 cannot close programs.
    Allowed,
}

// ---------------------------------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------------------------------

/// How the ladder ended for one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockResult {
    /// The outcome to journal.
    pub outcome: ItemOutcome,
    /// Why, for the report.
    pub detail: String,
    /// The code of the rule that decided, held or failed the item (`None` for a registered boot move).
    pub code: Option<&'static str>,
    /// Who holds the item, this process left out (for `ItemReport.lockers`).
    pub lockers: Vec<Locker>,
    /// Whether the locker list is complete (false: not queried, query failed, or not elevated enough).
    pub lockers_complete: bool,
    /// What the consent question to close the lockers was answered.
    pub close_consent: ConsentAnswer,
}

impl LockResult {
    fn new(outcome: ItemOutcome, code: Option<&'static str>, detail: impl Into<String>) -> Self {
        LockResult {
            outcome,
            detail: detail.into(),
            code,
            lockers: Vec::new(),
            lockers_complete: false,
            close_consent: ConsentAnswer::NotAsked,
        }
    }

    fn failed(code: FailCode, os_error: Option<u32>, rule: &'static str, detail: String) -> Self {
        LockResult::new(
            ItemOutcome::Failed {
                code,
                os_error,
                detail: detail.clone(),
            },
            Some(rule),
            detail,
        )
    }

    fn skipped(reason: SkipReason, rule: &'static str, detail: String) -> Self {
        LockResult::new(ItemOutcome::Skipped { reason }, Some(rule), detail)
    }

    /// The same naming facts (and their notes, appended to `detail`) with another outcome.
    fn with(&self, outcome: ItemOutcome, code: Option<&'static str>, detail: String) -> Self {
        let detail = if self.detail.is_empty() {
            detail
        } else {
            format!("{detail}; {}", self.detail)
        };
        LockResult {
            outcome,
            detail,
            code,
            ..self.clone()
        }
    }
}

/// The fail code and Win32 code of a file error.
fn fail_of(e: FsError) -> (FailCode, Option<u32>) {
    match e {
        FsError::AccessDenied | FsError::DirInUseOrDenied => {
            (FailCode::AccessDenied, Some(e.code()))
        }
        FsError::SharingViolation => (FailCode::InUse, Some(e.code())),
        other => (FailCode::Os, Some(other.code())),
    }
}

/// The answer to a request for a boot-time delete of `item` (§7.6 step 5): always
/// `Skipped{GateBlocked{ReversibilityNone}}`. A boot-time delete cannot be undone and needs its own
/// consent prompt, which M2 does not have; nothing is registered.
pub fn request_boot_delete(item: &LockedItem) -> LockResult {
    LockResult::skipped(
        SkipReason::GateBlocked {
            blocker: Blocker::ReversibilityNone,
        },
        reason::BOOT_DELETE,
        format!(
            "{}: a boot-time delete cannot be undone and needs its own consent; it is never chosen \
             automatically. Left in place.",
            item.source().unwrap_or("the item")
        ),
    )
}

// ---------------------------------------------------------------------------------------------------
// The ladder
// ---------------------------------------------------------------------------------------------------

/// What the ladder plans for an item that needs an intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockPlan {
    /// Leave it in place for the next run, for this reason code.
    Hold(&'static str),
    /// Register a boot-time move into the quarantine destination.
    BootMove,
}

/// What [`Ladder::prepare`] decided.
#[derive(Debug)]
pub enum LockPrepared {
    /// Decided without changing anything; every outcome here passes `allowed_without_intent`.
    Decided(LockResult),
    /// Journal the intent (unless already journalled), then call [`Ladder::act`] with its token.
    Ready(Box<LockAction>),
}

/// A ladder step that needs a durable intent. Only [`Ladder::prepare`] makes one.
#[derive(Debug)]
pub struct LockAction {
    intent: Intent,
    already_journalled: bool,
    plan: LockPlan,
    hold_detail: String,
    item: LockedItem,
    named: LockResult,
}

impl LockAction {
    /// The intent of the op (a quarantine move with its `MoveBack`; passes `Intent::is_consistent`).
    pub fn intent(&self) -> &Intent {
        &self.intent
    }

    /// The intent to write, or `None` when the file action already journalled exactly this intent and
    /// holds its token.
    pub fn intent_to_write(&self) -> Option<&Intent> {
        (!self.already_journalled).then_some(&self.intent)
    }

    /// What [`Ladder::act`] will do.
    pub fn plan(&self) -> LockPlan {
        self.plan
    }

    /// The lockers and the consent answer, for the report.
    pub fn named(&self) -> &LockResult {
        &self.named
    }
}

/// Why the boot-move rung did not apply.
struct Hold {
    code: &'static str,
    detail: String,
}

/// Everything the ladder works with.
#[derive(Clone, Copy)]
pub struct Ladder<'a> {
    /// Live facts (ancestors, destination, looks).
    pub env: &'a dyn LadderEnv,
    /// This session's store directories (the destination must lie in them).
    pub scope: &'a StoreScope,
    /// Restart Manager, query only.
    pub lockers: &'a dyn LockerQuery,
    /// Who answers consent questions.
    pub consent: &'a dyn ConsentCallback,
}

impl std::fmt::Debug for Ladder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ladder")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl<'a> Ladder<'a> {
    /// The ladder with live facts and the default consent answer ([`DenyAll`]).
    pub fn live(scope: &'a StoreScope, lockers: &'a dyn LockerQuery) -> Ladder<'a> {
        Ladder {
            env: &LiveLadder,
            scope,
            lockers,
            consent: &DenyAll,
        }
    }

    /// Climbs the ladder for `item` up to the decision (see the module docs). Changes nothing.
    ///
    /// `journalled` is the op's intent when the file action already wrote one (a lock met by the rename
    /// after the intent); it must equal the intent the ladder builds, or the item fails with
    /// `Failed{Internal}` and nothing is done.
    pub fn prepare(&self, item: &LockedItem, journalled: Option<&Intent>) -> LockPrepared {
        let decided = LockPrepared::Decided;
        let (Some(source), Some(intent)) = (item.source(), item.intent()) else {
            return decided(LockResult::failed(
                FailCode::Internal,
                None,
                reason::NOT_A_MOVE,
                format!(
                    "op {} is a {}, not a quarantine move; the locked-file ladder does not apply",
                    item.op,
                    item.exec_op.name()
                ),
            ));
        };
        // A volume serial of 0 is left to the boot-move rung (row c), which holds the item.
        let id = item.validated.file_id.0;
        if id == [0u8; 16] || id == [0xFFu8; 16] || !intent.is_consistent() {
            return decided(LockResult::failed(
                FailCode::Internal,
                None,
                reason::IDENTITY_INVALID,
                format!("{source}: the recorded file id identifies nothing"),
            ));
        }
        if journalled.is_some_and(|j| *j != intent) {
            return decided(LockResult::failed(
                FailCode::Internal,
                None,
                reason::INTENT_DIFFERS,
                format!(
                    "{source}: the journalled intent of op {} is not the move the ladder would \
                     register; nothing done",
                    item.op
                ),
            ));
        }
        if !gate::may_be_in_use(item.error, item.validated.is_dir) {
            let (code, os_error) = fail_of(item.error);
            return decided(LockResult::failed(
                code,
                os_error,
                reason::NOT_IN_USE,
                format!("{source}: {} (not a lock)", item.error),
            ));
        }
        if item.seen.identity != item.identity() || item.seen.is_dir != item.validated.is_dir {
            return decided(LockResult::skipped(
                SkipReason::ChangedSinceScan,
                reason::CHANGED,
                format!("{source}: the gate saw another object than the one validated"),
            ));
        }
        if let Some(result) = self.look_again(item, source) {
            return decided(result);
        }

        let named = self.name_lockers(item, source);
        let (plan, hold_detail) = match self.boot_move_rung(item, source) {
            Ok(()) => (LockPlan::BootMove, String::new()),
            Err(hold) => (LockPlan::Hold(hold.code), hold.detail),
        };
        LockPrepared::Ready(Box::new(LockAction {
            intent,
            already_journalled: journalled.is_some(),
            plan,
            hold_detail,
            item: item.clone(),
            named,
        }))
    }

    /// A fresh look at the source: `None` while it is still the validated object.
    fn look_again(&self, item: &LockedItem, source: &str) -> Option<LockResult> {
        match self.env.look(source) {
            SourceState::Present { identity, is_dir }
                if identity == item.identity() && is_dir == item.validated.is_dir =>
            {
                None
            }
            SourceState::Present { .. } => Some(LockResult::skipped(
                SkipReason::ChangedSinceScan,
                reason::CHANGED,
                format!("{source}: another object is at the path now"),
            )),
            SourceState::Absent => Some(LockResult::new(
                ItemOutcome::Vanished,
                Some(reason::VANISHED),
                format!("{source}: gone before the locked-file ladder acted"),
            )),
            SourceState::Unreadable(code) => Some(LockResult::failed(
                FailCode::Os,
                Some(code),
                reason::UNREADABLE,
                format!("{source}: cannot be looked at (Win32 error {code})"),
            )),
        }
    }

    /// Rungs 1 and 2: who holds the item, and the consent question to close them (never acted on).
    fn name_lockers(&self, item: &LockedItem, source: &str) -> LockResult {
        let mut named = LockResult::new(ItemOutcome::HeldRetry, None, String::new());
        if item.validated.is_dir {
            return named;
        }
        let mut notes = Vec::new();
        match self.lockers.query(&[PathBuf::from(source)]) {
            Ok(list) => {
                named.lockers_complete = !list.reboot_reasons.has(RebootReasons::PERMISSION_DENIED);
                let own = std::process::id();
                for raw in list.lockers.iter().filter(|l| l.pid != own) {
                    let locker = Locker {
                        pid: raw.pid,
                        name: raw.app_name.clone(),
                        service: raw.service_name.clone(),
                    };
                    if !named.lockers.contains(&locker) {
                        named.lockers.push(locker);
                    }
                }
            }
            Err(e) => notes.push(format!(
                "Restart Manager could not list the holders (Win32 error {})",
                e.0
            )),
        }
        if !named.lockers.is_empty() {
            let answer = self.consent.ask(&ConsentRequest::CloseLockers {
                op: item.op,
                path: source,
                lockers: &named.lockers,
            });
            named.close_consent = match answer {
                Consent::Deny => ConsentAnswer::Denied,
                Consent::Allow => {
                    notes.push(
                        "closing programs was allowed, but this version never closes programs or \
                         stops services; nothing was closed"
                            .to_owned(),
                    );
                    ConsentAnswer::Allowed
                }
            };
        }
        named.detail = notes.join("; ");
        named
    }

    /// Rung 3: whether a boot-time move may be registered (rows a to e of the module docs).
    fn boot_move_rung(&self, item: &LockedItem, source: &str) -> Result<(), Hold> {
        let hold = |code: &'static str, detail: String| Err(Hold { code, detail });
        if item.validated.is_dir {
            return hold(
                reason::DIRECTORY,
                "a directory is never moved at boot: what lies below it may change before the restart"
                    .to_owned(),
            );
        }
        if let BootMove::Hold(code) = self.env.ancestors(source) {
            return hold(
                code,
                "the item or an ancestor can be changed by a non-administrator, is a reparse point, \
                 or could not be checked"
                    .to_owned(),
            );
        }
        let serial = item.validated.volume_serial;
        if serial == 0 {
            return hold(
                reason::VOLUME_UNKNOWN,
                "the item's volume serial is unknown".to_owned(),
            );
        }
        let destination = item.quarantine_path.as_str();
        let facts = self.env.destination(destination);
        let check = QuarantineCheck {
            source,
            source_volume_serial: Some(serial),
            destination,
        };
        if let Err(refusal) = live::check_quarantine_destination(&check, &facts, self.scope) {
            return hold(
                refusal.reason,
                format!("the quarantine destination {destination} was refused ({refusal})"),
            );
        }
        if facts.parent_volume_serial != Some(serial) {
            return hold(
                reason::OTHER_VOLUME,
                format!("the quarantine destination {destination} is on another volume"),
            );
        }
        Ok(())
    }

    /// Carries out a [`LockAction`] whose intent `token` proves durable. Journal the result with
    /// `JournalWriter::done(token, result.outcome)`.
    ///
    /// A hold changes nothing (`HeldRetry`). A boot move re-checks the source and the boot-move rung (a
    /// hold now is `HeldRetry`), then: our pair already listed once is adopted (`PendingReboot`, nothing
    /// written), listed more than once is `Failed{Internal}`; otherwise it is registered,
    /// `bootmove.registered` is hit, and the list is read back: the pair as stored, `confirmed` when it
    /// stands there exactly once. A registration that fails is `Failed` (nothing registered). A token of
    /// another op is `Failed{Internal}` and nothing is called.
    pub fn act(
        &self,
        action: Box<LockAction>,
        token: &IntentToken,
        store: &mut dyn PendingRenames,
    ) -> LockResult {
        let LockAction {
            intent,
            plan,
            hold_detail,
            item,
            named,
            ..
        } = *action;
        let source = item.source().unwrap_or_default().to_owned();
        if token.op() != intent.op || token.item() != &intent.item {
            return named.with(
                failed_outcome(FailCode::Internal, None, "token of another op"),
                Some(reason::FOREIGN_TOKEN),
                format!(
                    "the intent token is for op {}, not op {}; {source} left in place",
                    token.op(),
                    intent.op
                ),
            );
        }
        let hold = |code: &'static str, detail: &str| {
            named.with(
                ItemOutcome::HeldRetry,
                Some(code),
                format!("{source}: in use; {detail}; held for a retry at the next run"),
            )
        };
        if let LockPlan::Hold(code) = plan {
            return hold(code, &hold_detail);
        }
        if let Some(result) = self.look_again(&item, &source) {
            return named.with(result.outcome, result.code, result.detail);
        }
        if let Err(h) = self.boot_move_rung(&item, &source) {
            return hold(h.code, &h.detail);
        }
        self.register(&item, &source, &named, store)
    }

    /// Registers (or adopts) the pair and reads it back.
    fn register(
        &self,
        item: &LockedItem,
        source: &str,
        named: &LockResult,
        store: &mut dyn PendingRenames,
    ) -> LockResult {
        let destination = item.quarantine_path.as_str();
        let fail = |code: FailCode, os_error: Option<u32>, rule: &'static str, text: String| {
            named.with(failed_outcome(code, os_error, &text), Some(rule), text)
        };
        let expected = match expected_pair(source, destination) {
            Ok(pair) => pair,
            Err(e) => {
                return fail(
                    FailCode::Internal,
                    Some(e.code()),
                    reason::NOT_A_MOVE,
                    format!("{source}: no boot-time move pair can be spelled ({e})"),
                );
            }
        };
        let before = match store.list() {
            Ok(list) => occurrences(&list, &expected),
            Err(e) => {
                return fail(
                    FailCode::Os,
                    Some(e.code()),
                    reason::LIST_FAILED,
                    format!(
                        "{source}: the boot-time move list cannot be read ({e}); nothing registered"
                    ),
                );
            }
        };
        match before.as_slice() {
            [] => {}
            [stored] => {
                return named.with(
                    ItemOutcome::PendingReboot {
                        pair: model_pair(stored),
                        confirmed: true,
                    },
                    None,
                    format!(
                        "{source}: its boot-time move was already registered; adopted, not doubled"
                    ),
                );
            }
            many => {
                return fail(
                    FailCode::Internal,
                    None,
                    reason::PAIR_COUNT,
                    format!(
                        "{source}: the boot-time move list already holds this move {} times; nothing \
                         registered",
                        many.len()
                    ),
                );
            }
        }
        let registered = match store.register(Path::new(source), Path::new(destination)) {
            Ok(registered) => registered,
            Err(e) => {
                let (code, os_error) = fail_of(e);
                return fail(
                    code,
                    os_error,
                    reason::LIST_FAILED,
                    format!(
                        "{source}: the boot-time move could not be registered ({e}); left in place"
                    ),
                );
            }
        };
        fault::point(fault::BOOTMOVE_REGISTERED);
        let pending = |pair: BootMovePair, confirmed: bool, detail: String| {
            named.with(ItemOutcome::PendingReboot { pair, confirmed }, None, detail)
        };
        let moved = format!("{source}: in use; moves into quarantine at the next restart");
        match store.list().map(|list| occurrences(&list, &expected)) {
            Ok(after) => match after.as_slice() {
                [stored] => pending(model_pair(stored), true, moved),
                [] => pending(
                    expected,
                    false,
                    format!("{moved} (registered, but not found in the list when read back)"),
                ),
                many => pending(
                    model_pair(&registered.pair),
                    false,
                    format!(
                        "{moved} (the list holds this move {} times; undo will refuse to remove it)",
                        many.len()
                    ),
                ),
            },
            Err(e) => pending(
                model_pair(&registered.pair),
                registered.confirmed,
                format!("{moved} (the list could not be read back: {e})"),
            ),
        }
    }
}

fn failed_outcome(code: FailCode, os_error: Option<u32>, detail: &str) -> ItemOutcome {
    ItemOutcome::Failed {
        code,
        os_error,
        detail: detail.to_owned(),
    }
}

/// For crash recovery: whether an op the journal shows with an intent and no `done` left a registered
/// boot-time move. `Some(PendingReboot{pair as stored, confirmed: true})` when our pair stands in the list
/// exactly once (journal it with `done`); `None` otherwise (not a boot move, or not determinable: probe
/// the item as for any quarantine move). Read-only.
pub fn pending_after_crash(intent: &Intent, store: &dyn PendingRenames) -> Option<ItemOutcome> {
    let Inverse::MoveBack {
        quarantine_path,
        original_path,
        ..
    } = &intent.inverse
    else {
        return None;
    };
    let expected = expected_pair(original_path, quarantine_path).ok()?;
    match occurrences(&store.list().ok()?, &expected).as_slice() {
        [stored] => Some(ItemOutcome::PendingReboot {
            pair: model_pair(stored),
            confirmed: true,
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------------
// Undo
// ---------------------------------------------------------------------------------------------------

/// Where a lock op stands, from its `done` outcome and the `reconcile` records after it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LockState {
    /// Held for a retry.
    Held,
    /// A boot-time move is registered and not reconciled.
    Pending(BootMovePair),
    /// The item went into quarantine (reconcile `Completed`, or a retry ended `Done`).
    Moved,
    /// The system is as before (mismatch moved back, cancelled, retried without change).
    Unchanged,
    /// Not a lock op.
    Other,
}

fn lock_state(op: &OpState) -> LockState {
    let of = |outcome: &ItemOutcome| match outcome {
        ItemOutcome::HeldRetry => LockState::Held,
        ItemOutcome::PendingReboot { pair, .. } => LockState::Pending(pair.clone()),
        ItemOutcome::Done => LockState::Moved,
        _ => LockState::Unchanged,
    };
    let mut state = match &op.outcome {
        Some(outcome @ (ItemOutcome::HeldRetry | ItemOutcome::PendingReboot { .. })) => of(outcome),
        _ => return LockState::Other,
    };
    for result in &op.reconciles {
        state = match result {
            ReconcileResult::StillPending => state,
            ReconcileResult::Completed => LockState::Moved,
            ReconcileResult::MismatchMovedBack | ReconcileResult::Cancelled => LockState::Unchanged,
            ReconcileResult::Retried { outcome } => of(outcome),
        };
    }
    state
}

/// A pending boot move to cancel. Only [`undo_locked`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairRemoval {
    op: OpId,
    pair: BootMovePair,
}

impl PairRemoval {
    /// The op.
    pub fn op(&self) -> OpId {
        self.op
    }

    /// The pair the journal recorded.
    pub fn pair(&self) -> &BootMovePair {
        &self.pair
    }
}

/// How to undo a lock op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockUndo {
    /// Nothing changed the system: `undo_done_without_intent(op, outcome)`.
    Done(UndoOutcome),
    /// A boot-time move is still registered: write `undo_intent(op)`, call [`remove_boot_move`] with the
    /// token, then `undo_done(token, outcome)`.
    RemovePair(PairRemoval),
    /// The pair is no longer listed (the restart may have moved the item) or the list cannot be read:
    /// run [`reconcile`] first and undo after it. Nothing to journal now.
    ReconcileFirst {
        /// Why.
        detail: String,
    },
}

/// The undo of a lock op, in the style of `act_typed::undo_typed`: `None` when the op is not a lock op
/// or its undo is the ordinary move back (a held item a retry moved, a boot move reconcile completed),
/// and for an op with an intent and no `done` (recovery's case, see [`pending_after_crash`]).
pub fn undo_locked(op: &OpState, store: &dyn PendingRenames) -> Option<LockUndo> {
    match lock_state(op) {
        LockState::Other | LockState::Moved => None,
        LockState::Held | LockState::Unchanged => Some(LockUndo::Done(UndoOutcome::NothingToUndo)),
        LockState::Pending(pair) => Some(match store.list() {
            Err(e) => LockUndo::ReconcileFirst {
                detail: format!("the boot-time move list cannot be read ({e})"),
            },
            Ok(list) if occurrences(&list, &pair).is_empty() => LockUndo::ReconcileFirst {
                detail:
                    "the boot-time move is no longer listed; the restart may have moved the item"
                        .to_owned(),
            },
            Ok(_) => LockUndo::RemovePair(PairRemoval { op: op.op, pair }),
        }),
    }
}

/// Cancels a pending boot move under the undo intent `token`: removes our pair, and only ours, only
/// when it stands in the list exactly once (the marker aside), cutting exactly the stored spelling. Hits
/// `undo.act.after` after the removal. Foreign pairs stay byte-identical.
///
/// | Listed | Result |
/// |---|---|
/// | once, one cut | `Restored` |
/// | not at all | `AlreadyRestored` |
/// | more than once | `Failed{Internal}`, nothing removed |
/// | list unreadable, removal failed | `Failed{..}` with the error |
/// | once, but the cut removed another count | `Failed{VerifyFailed}` |
pub fn remove_boot_move(
    removal: PairRemoval,
    token: &UndoToken,
    store: &mut dyn PendingRenames,
) -> UndoOutcome {
    let failed = |code: FailCode, os_error: Option<u32>, detail: String| UndoOutcome::Failed {
        code,
        os_error,
        detail,
    };
    if token.op() != removal.op {
        return failed(
            FailCode::Internal,
            None,
            format!(
                "the undo token is for op {}, not op {}; nothing removed",
                token.op(),
                removal.op
            ),
        );
    }
    let listed = match store.list() {
        Ok(list) => occurrences(&list, &removal.pair),
        Err(e) => {
            return failed(
                FailCode::Os,
                Some(e.code()),
                format!("the boot-time move list cannot be read ({e}); nothing removed"),
            );
        }
    };
    let stored = match listed.as_slice() {
        [] => return UndoOutcome::AlreadyRestored,
        [stored] => stored.clone(),
        many => {
            return failed(
                FailCode::Internal,
                None,
                format!(
                    "the boot-time move stands {} times in the list; Purge added it once, so nothing \
                     was removed",
                    many.len()
                ),
            );
        }
    };
    let removed = store.remove_exact(&stored);
    fault::point(fault::UNDO_ACT_AFTER);
    match removed {
        Ok(1) => UndoOutcome::Restored,
        Ok(0) => UndoOutcome::AlreadyRestored,
        Ok(n) => failed(
            FailCode::VerifyFailed,
            None,
            format!("{n} copies of the boot-time move were removed instead of one"),
        ),
        Err(e) => {
            let (code, os_error) = fail_of(e);
            failed(
                code,
                os_error,
                format!("the boot-time move could not be removed ({e})"),
            )
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Reconcile
// ---------------------------------------------------------------------------------------------------

/// What [`reconcile`] found for one op whose boot-time move was pending.
///
/// | Our pair listed | Quarantine destination | Source path | Verdict | Journal |
/// |---|---|---|---|---|
/// | list unreadable | - | - | `Indeterminate` | nothing |
/// | yes | - | - | `StillPending` | `StillPending` |
/// | no | the recorded item (file id and serial equal) | - | `Completed` | `Completed` |
/// | no | something else, moved back | - | `MismatchMovedBack`, alert | `MismatchMovedBack` |
/// | no | something else, cannot be moved back | - | `MismatchKept`, alert | nothing |
/// | no | cannot be checked | - | `Indeterminate` | nothing |
/// | no | empty | present | `NotMoved` (failed) | nothing |
/// | no | empty | absent | `Lost` | nothing |
/// | no | empty | cannot be looked at | `Indeterminate` | nothing |
///
/// "Nothing": the journal model has no reconcile result for these (no failed and no kept variant), so
/// the op stays pending a reboot in the journal and is reported again at each start, and its undo answers
/// [`LockUndo::ReconcileFirst`]. Settling such an op needs a model result for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileVerdict {
    /// The move has not happened yet.
    StillPending,
    /// The recorded item is in quarantine.
    Completed,
    /// Another object was in quarantine; it was moved back to the source path at once.
    MismatchMovedBack,
    /// Another object is in quarantine and could not be moved back (the undo-destination check refused
    /// or the rename failed). It stays in the admin-only quarantine.
    MismatchKept,
    /// The pair is gone but nothing reached quarantine; something is at the source path. The move failed.
    NotMoved,
    /// The pair is gone, nothing reached quarantine and nothing is at the source path.
    Lost,
    /// The state could not be told.
    Indeterminate,
}

/// An object in quarantine that is not the recorded item (§7.6): reported to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileAlert {
    /// The op.
    pub op: OpId,
    /// The source path of the boot-time move.
    pub original_path: String,
    /// The quarantine path the object was found at.
    pub quarantine_path: String,
    /// The recorded identity.
    pub expected: FileIdentity,
    /// The identity of what was found.
    pub found: FileIdentity,
    /// Whether it was moved back to `original_path`.
    pub moved_back: bool,
}

/// What [`reconcile`] found for one op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconciled {
    /// The op.
    pub op: OpId,
    /// The verdict.
    pub verdict: ReconcileVerdict,
    /// Why, for the report.
    pub detail: String,
    /// An object in quarantine that was not ours.
    pub alert: Option<ReconcileAlert>,
}

impl Reconciled {
    /// The result to journal, when the model has one for the verdict.
    pub fn result(&self) -> Option<ReconcileResult> {
        match self.verdict {
            ReconcileVerdict::StillPending => Some(ReconcileResult::StillPending),
            ReconcileVerdict::Completed => Some(ReconcileResult::Completed),
            ReconcileVerdict::MismatchMovedBack => Some(ReconcileResult::MismatchMovedBack),
            ReconcileVerdict::MismatchKept
            | ReconcileVerdict::NotMoved
            | ReconcileVerdict::Lost
            | ReconcileVerdict::Indeterminate => None,
        }
    }

    /// The `reconcile` record to journal (`JournalWriter::reconcile`), stamped `at`.
    pub fn record(&self, at: FileTime) -> Option<Reconcile> {
        Some(Reconcile {
            at,
            op: self.op,
            result: self.result()?,
        })
    }
}

/// The exemptions each op was validated with, from a journal's records (`JournalRead::records`), for
/// [`reconcile`]'s undo-destination check.
pub fn exemptions_of(records: &[Record]) -> BTreeMap<OpId, GateExemptions> {
    records
        .iter()
        .filter_map(|r| match r {
            Record::Validated(v) => Some((v.op, v.exemptions)),
            _ => None,
        })
        .collect()
}

/// What sits at an op's quarantine destination.
enum Destination {
    Empty,
    Ours,
    Other(FileIdentity, PathBuf),
    Unknown(String),
}

/// Reconciles every op of `state` whose boot-time move is pending ([`JournalState::pending_reboot`]); see
/// [`ReconcileVerdict`] for the table. The list is read once. A mismatch is moved back at once, by
/// handle, into the parent of the source path after [`gate::check_undo_path`] (with the op's journalled
/// exemptions, default when missing), and never over anything; the move happens before the caller
/// journals it.
pub fn reconcile(
    state: &JournalState,
    exemptions: &BTreeMap<OpId, GateExemptions>,
    session: &SessionDir,
    ctx: &GateCtx,
    env: &dyn LadderEnv,
    store: &dyn PendingRenames,
) -> Vec<Reconciled> {
    let list = store.list();
    state
        .pending_reboot()
        .map(|op| {
            let found = |verdict, detail: String| Reconciled {
                op: op.op,
                verdict,
                detail,
                alert: None,
            };
            let (LockState::Pending(pair), Some(intent)) = (lock_state(op), &op.intent) else {
                return found(
                    ReconcileVerdict::Indeterminate,
                    "the journal shows no boot-time move for this op".to_owned(),
                );
            };
            let Inverse::MoveBack {
                quarantine_path,
                original_path,
                file_id,
                volume_serial,
            } = &intent.inverse
            else {
                return found(
                    ReconcileVerdict::Indeterminate,
                    "the op's intent is not a quarantine move".to_owned(),
                );
            };
            let listed = match &list {
                Ok(list) => !occurrences(list, &pair).is_empty(),
                Err(e) => {
                    return found(
                        ReconcileVerdict::Indeterminate,
                        format!("the boot-time move list cannot be read ({e})"),
                    );
                }
            };
            if listed {
                return found(
                    ReconcileVerdict::StillPending,
                    format!("{original_path}: moves at the next restart"),
                );
            }
            let expected = FileIdentity {
                volume_serial: *volume_serial,
                file_id: file_id.0,
            };
            match destination_state(session, op.op, quarantine_path, expected) {
                Destination::Ours => found(
                    ReconcileVerdict::Completed,
                    format!("{original_path}: moved into quarantine at the restart"),
                ),
                Destination::Unknown(why) => found(
                    ReconcileVerdict::Indeterminate,
                    format!("{quarantine_path}: cannot be checked ({why})"),
                ),
                Destination::Other(identity, item) => {
                    let ex = exemptions.get(&op.op).copied().unwrap_or_default();
                    let moved = move_back(ctx, &item, identity, original_path, *volume_serial, ex);
                    let alert = ReconcileAlert {
                        op: op.op,
                        original_path: original_path.clone(),
                        quarantine_path: quarantine_path.clone(),
                        expected,
                        found: identity,
                        moved_back: moved.is_ok(),
                    };
                    let (verdict, detail) = match moved {
                        Ok(()) => (
                            ReconcileVerdict::MismatchMovedBack,
                            format!(
                                "{quarantine_path} held another object than the one recorded; it was \
                                 moved back to {original_path}"
                            ),
                        ),
                        Err(why) => (
                            ReconcileVerdict::MismatchKept,
                            format!(
                                "{quarantine_path} holds another object than the one recorded; it could \
                                 not be moved back to {original_path} ({why}) and stays in quarantine"
                            ),
                        ),
                    };
                    Reconciled {
                        op: op.op,
                        verdict,
                        detail,
                        alert: Some(alert),
                    }
                }
                Destination::Empty => match env.look(original_path) {
                    SourceState::Present { .. } => found(
                        ReconcileVerdict::NotMoved,
                        format!(
                            "{original_path}: the boot-time move did not happen; the item is still in \
                             place"
                        ),
                    ),
                    SourceState::Absent => found(
                        ReconcileVerdict::Lost,
                        format!(
                            "{original_path}: neither in place nor in quarantine after the restart"
                        ),
                    ),
                    SourceState::Unreadable(code) => found(
                        ReconcileVerdict::Indeterminate,
                        format!("{original_path}: cannot be looked at (Win32 error {code})"),
                    ),
                },
            }
        })
        .collect()
}

/// Looks at the op's quarantine destination through the store-checked op directory.
fn destination_state(
    session: &SessionDir,
    op: OpId,
    quarantine_path: &str,
    expected: FileIdentity,
) -> Destination {
    let (dir, leaf) =
        match session.open_op_dir(Path::new(quarantine_path), op, expected.volume_serial) {
            Ok(opened) => opened,
            Err(e) => return Destination::Unknown(e.to_string()),
        };
    let item = dir.item_path(&leaf);
    let Some(p) = item.to_str().and_then(ext) else {
        return Destination::Unknown("the path has no extended form".to_owned());
    };
    let handle = match FileHandle::open(&p) {
        Ok(handle) => handle,
        Err(e) if e.is_not_found() => return Destination::Empty,
        Err(e) => return Destination::Unknown(format!("Win32 error {}", e.0)),
    };
    let (Ok(meta), Ok(final_path)) = (handle.metadata(), handle.final_path()) else {
        return Destination::Unknown("its facts cannot be read".to_owned());
    };
    let inside = format!(r"{}\{leaf}", dir.dir().final_path().trim_end_matches('\\'));
    if !final_path.eq_ignore_ascii_case(&inside) {
        return Destination::Unknown(format!("its final path is {final_path}"));
    }
    let identity = FileIdentity {
        volume_serial: meta.file_id.volume_serial,
        file_id: meta.file_id.id,
    };
    if identity == expected && meta.reparse_tag == 0 && !meta.is_dir {
        Destination::Ours
    } else {
        Destination::Other(identity, p)
    }
}

/// Moves the object at `item` (inside the op directory, with identity `found`) back to `original`, by
/// handle into the parent [`gate::check_undo_path`] checked. A rename never replaces anything.
fn move_back(
    ctx: &GateCtx,
    item: &Path,
    found: FileIdentity,
    original: &str,
    volume_serial: u64,
    exemptions: GateExemptions,
) -> Result<(), String> {
    let handle = MoveHandle::open(item).map_err(|e| e.to_string())?;
    let now = handle.file_id().map_err(|e| e.to_string())?;
    if now.volume_serial != found.volume_serial || now.id != found.file_id {
        return Err("the object changed while it was looked at".to_owned());
    }
    let dest = gate::check_undo_path(
        ctx,
        original,
        volume_serial,
        gate::exemptions_from_journal(&exemptions),
    )
    .map_err(|refusal| refusal.to_string())?;
    handle
        .rename_into(dest.dir(), dest.leaf())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------------------------------
// Held items
// ---------------------------------------------------------------------------------------------------

/// How a retry of a held item ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryAttempt {
    /// Moved into the intent's `MoveBack::quarantine_path`, exactly (undo relies on it).
    Moved,
    /// The item is gone.
    Vanished,
    /// Still locked: it stays held.
    StillLocked,
    /// Left untouched for this reason.
    Skipped(SkipReason),
    /// Failed; the item is in its original state.
    Failed {
        /// The kind of failure.
        code: FailCode,
        /// The Win32 error code, when there is one.
        os_error: Option<u32>,
    },
}

/// The move of a held item, supplied by the executor (it belongs to the file action): validate the item
/// again through the handle-based gate against the op's validated stamp and the journalled exemptions,
/// then move it by handle to the intent's `MoveBack::quarantine_path` (the op directory already exists:
/// `SessionDir::open_op_dir`). A retry never registers a boot-time move.
pub trait RetryMove {
    /// Tries op `op` once more; `intent` is its journalled intent.
    fn retry(&mut self, op: &OpState, intent: &Intent) -> RetryAttempt;
}

/// The result of one retry, to journal as `reconcile` `Retried{outcome}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retried {
    /// The op.
    pub op: OpId,
    /// The outcome of the new attempt.
    pub outcome: ItemOutcome,
}

impl Retried {
    /// The `reconcile` record to journal, stamped `at`.
    pub fn record(&self, at: FileTime) -> Reconcile {
        Reconcile {
            at,
            op: self.op,
            result: ReconcileResult::Retried {
                outcome: self.outcome.clone(),
            },
        }
    }
}

/// Tries every held op of `state` ([`JournalState::held_retry`]) again through `mover`. An op whose
/// intent is not a quarantine move with a `MoveBack` is not passed to the mover and ends
/// `Failed{Internal}`. Still locked stays `HeldRetry`.
pub fn retry_held(state: &JournalState, mover: &mut dyn RetryMove) -> Vec<Retried> {
    state
        .held_retry()
        .map(|op| {
            let outcome = match &op.intent {
                Some(
                    intent @ Intent {
                        exec_op: ExecOp::QuarantineMove { .. },
                        inverse: Inverse::MoveBack { .. },
                        ..
                    },
                ) => match mover.retry(op, intent) {
                    RetryAttempt::Moved => ItemOutcome::Done,
                    RetryAttempt::Vanished => ItemOutcome::Vanished,
                    RetryAttempt::StillLocked => ItemOutcome::HeldRetry,
                    RetryAttempt::Skipped(reason) => ItemOutcome::Skipped { reason },
                    RetryAttempt::Failed { code, os_error } => ItemOutcome::Failed {
                        code,
                        os_error,
                        detail: String::new(),
                    },
                },
                _ => failed_outcome(
                    FailCode::Internal,
                    None,
                    "the held op has no quarantine-move intent",
                ),
            };
            Retried { op: op.op, outcome }
        })
        .collect()
}
