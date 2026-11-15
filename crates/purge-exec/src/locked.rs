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
//! The file action hands over an item that stayed locked after its retries as a [`LockedItem`], built
//! only with [`LockedItem::from_gate`] from the gate's [`LockedPath`] (at the open, or when a rename met a
//! lock after the intent) and the op's journal `validated` record as the executor handed it to
//! `GateCtx::record`: the op, plan item and validated facts are never taken from the caller.
//! [`Ladder::prepare`] then climbs, in this order:
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
//! | not a `QuarantineMove`, invalid recorded identity, journalled intent is another action | `Failed{Internal}` |
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
//!    and take the token; when it is `None` the file action already journalled this very action (checked
//!    by `prepare`), so use that token. Then hit `act.before`.
//! 3. [`Ladder::act`] takes the token as proof of the durable intent. For a hold it changes nothing and
//!    returns `HeldRetry`. For a boot move it re-checks the source and the whole boot-move rung, looks for
//!    the pair in the list (one already there is adopted, never doubled), registers it, reads the list
//!    back and returns `PendingReboot{pair, confirmed}` with the pair **as it stands in the list**.
//!    Journal the result with `JournalWriter::done(token, ..)`, which hits `bootmove.registered` (the
//!    move is registered, its `done` not yet written) and flushes that `done` before it returns.
//!
//! The intent is the one a quarantine move would write: `QuarantineMove{path}` with
//! `MoveBack{quarantine_path, original_path, file_id, volume_serial}` and `pre` = the validated facts (a
//! locked item has no acting handle). So a held item that a later run moves, and a boot move that a
//! restart completes, are undone by the ordinary move back to the recorded quarantine path.
//!
//! # After the restart
//!
//! - [`reconcile`] (at the next start, per op still pending a reboot) returns a [`Reconciled`] per op; see
//!   [`ReconcileVerdict`] for the table. Journal [`Reconciled::record`] when it is `Some` (every verdict
//!   but `Indeterminate`).
//! - [`retry_held`] tries the held items again through a [`RetryMove`] the executor supplies (the move
//!   belongs to the file action). It journals each retry itself, write-ahead: `retry_intent` (flushed)
//!   before the move, which takes the [`RetryToken`] as proof, and the `reconcile` `Retried{outcome}`
//!   that ends it after.
//! - [`undo_locked`] says how to undo a lock op; a pending boot move is undone by removing **our exact
//!   pair only** ([`remove_boot_move`], under an undo token).
//! - [`pending_after_crash`] tells recovery whether an intent-only op left a registered pair.
//!
//! # The boot-time move list
//!
//! Every access goes through [`PendingRenames`]: [`SystemPendingRenames`] over `purge_win::fs_write`, and
//! `MemoryPendingRenames` (tests and `test-support`) over a byte buffer with the same cutting code. Pairs
//! of other programs are never touched or reordered: registering appends, removing cuts the exact byte
//! range of our pair, and only when one compared read-modify-write finds it exactly once
//! ([`PendingRenames::remove_counted`]).
//!
//! # The boot move's destination
//!
//! Row d is asked through [`LadderEnv::check_destination`]. With [`StoreLadder`] ([`Ladder::in_store`])
//! the op directory is opened through the store's checks and the directory the destination facts are read
//! from must be that very directory ([`gate::check_quarantine_destination_for`]); [`LiveLadder`]
//! ([`Ladder::live`]) reads the same facts by path without that comparison.

use std::path::{Path, PathBuf};

use purge_guard::deny::Exemptions;
use purge_guard::live::{
    self, BootMove, DestinationFacts, FileIdentity, PathStamp, QuarantineCheck, Refusal, StoreScope,
};
use purge_model::exec::journal::{
    FileFacts, Intent, ItemFacts, Reconcile, ReconcileResult, UndoConflict, UndoOutcome,
};
use purge_model::exec::op::{
    BootMovePair, ExecOp, FailCode, Inverse, ItemOutcome, OpId, SkipReason,
};
use purge_model::exec::session::Locker;
use purge_model::{Blocker, CandidateId, FileTime};
use purge_win::fs::FileHandle;
use purge_win::fs_write::{self, FsError, MoveHandle, PendingPair, extended_path, strip_marker};
use purge_win::os::Win32Error;
use purge_win::rm::RebootReasons;

use crate::act_fs;
use crate::fault;
use crate::gate::{self, GateCtx, LockedPath};
use crate::journal::{
    IntentToken, JournalError, JournalState, JournalWriter, OpState, RetryToken, UndoToken,
};
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
    /// The op directory of the boot move's destination did not pass the store's checks (missing,
    /// another op, session or volume, or a failed integrity check).
    pub const QUARANTINE_DIR: &str = "lock.quarantine-dir-unchecked";
    /// At undo, the state of a registered boot-time move cannot be told (the pair is no longer listed,
    /// or the list cannot be read): reported as the conflict `GateBlocked{DenyListed{rule: <this>}}`
    /// until reconcile has decided it.
    pub const BOOT_MOVE_INDETERMINATE: &str = "lock.boot-move-indeterminate";
}

// ---------------------------------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------------------------------

/// The hand-over from the file action for an item that stayed locked after its retries. Built only by
/// [`LockedItem::from_gate`]:
///
/// - the op, its plan item and its validated facts (identity, kind, size ...) are those of the op's
///   journal `validated` record in the gate context; the facts become the intent's `pre`, because a
///   locked item has no acting handle to read them from. The op must be [`ExecOp::QuarantineMove`]; its
///   `path` is the recorded source path, the plan's lexical path that the gate judged (G1: equal to the
///   handle's final path).
/// - `seen` is what the gate's read-only look showed now ([`LockedPath::stamp`]); it must equal the
///   validated identity and kind.
/// - `error` is the open (or rename) error of the acting handle.
/// - `quarantine_path` is `<op dir>\<leaf>` for this op, the op directory created by
///   `SessionDir::create_op_dir(source, serial, op)` (`QuarantineDir::item_path`); it is what the intent's
///   `MoveBack` records and the destination of a boot move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedItem {
    op: OpId,
    item: CandidateId,
    exec_op: ExecOp,
    validated: FileFacts,
    seen: PathStamp,
    error: FsError,
    quarantine_path: String,
}

impl LockedItem {
    /// The hand-over for op `op` after the gate ([`gate::open_and_check_path`], or the file action's
    /// rename after the intent) reported it locked as `locked`. The op, its plan item and its validated
    /// facts are taken from the op's journal `validated` record ([`GateCtx::journalled`]). `None` when the
    /// op has no record in `ctx` or the record holds no file facts.
    pub fn from_gate(
        ctx: &GateCtx,
        op: OpId,
        locked: &LockedPath,
        quarantine_path: impl Into<String>,
    ) -> Option<LockedItem> {
        let (exec_op, record) = ctx.journalled(op)?;
        let ItemFacts::File(validated) = &record.facts else {
            return None;
        };
        Some(LockedItem {
            op,
            item: record.item.clone(),
            exec_op: exec_op.clone(),
            validated: validated.clone(),
            seen: locked.stamp,
            error: FsError::from(locked.error),
            quarantine_path: quarantine_path.into(),
        })
    }

    /// The op id.
    pub fn op(&self) -> OpId {
        self.op
    }

    /// The candidate id of the plan item.
    pub fn item(&self) -> &CandidateId {
        &self.item
    }

    /// The op (a [`ExecOp::QuarantineMove`] for the ladder to apply).
    pub fn exec_op(&self) -> &ExecOp {
        &self.exec_op
    }

    /// The facts of the op's journal `validated` record.
    pub fn validated(&self) -> &FileFacts {
        &self.validated
    }

    /// Absolute path of the item inside this op's quarantine directory.
    pub fn quarantine_path(&self) -> &str {
        &self.quarantine_path
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

/// The live facts the ladder needs. [`LiveLadder`] and [`StoreLadder`] read them from the system; tests
/// inject verdicts a test machine cannot produce unelevated (an admin-only ancestor chain).
pub trait LadderEnv {
    /// The boot-move verdict on the item and its ancestors ([`gate::admin_only_ancestors`]).
    fn ancestors(&self, source: &str) -> BootMove;
    /// The facts of a rename destination, read from a no-follow handle on its parent directory.
    fn destination(&self, destination: &str) -> DestinationFacts;
    /// A read-only, no-follow look at `path`.
    fn look(&self, path: &str) -> SourceState;
    /// Row d of the boot-move rung: the verdict on `item`'s quarantine destination
    /// ([`LockedItem::quarantine_path`]) for a move from `source` within `scope`, and the facts it was
    /// given. By default [`live::check_quarantine_destination`] over [`LadderEnv::destination`];
    /// [`StoreLadder`] also requires the directory read to be the store's checked op directory.
    fn check_destination(
        &self,
        scope: &StoreScope,
        item: &LockedItem,
        source: &str,
    ) -> Result<DestinationFacts, Refusal> {
        let destination = item.quarantine_path();
        let facts = self.destination(destination);
        let check = QuarantineCheck {
            source,
            source_volume_serial: Some(item.validated.volume_serial),
            destination,
        };
        live::check_quarantine_destination(&check, &facts, scope)?;
        Ok(facts)
    }
}

/// The facts as the system gives them, the destination read by path ([`gate::destination_facts_at`]): the
/// directory read is not compared with the store's op directory. Prefer [`StoreLadder`] where the session
/// is at hand ([`Ladder::in_store`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveLadder;

impl LadderEnv for LiveLadder {
    fn ancestors(&self, source: &str) -> BootMove {
        gate::admin_only_ancestors(source)
    }

    fn destination(&self, destination: &str) -> DestinationFacts {
        gate::destination_facts_at(destination)
    }

    fn look(&self, path: &str) -> SourceState {
        look(path)
    }
}

/// The facts as the system gives them, with the boot move's destination checked against this session's
/// store (wave 2 review M3): the op directory is opened through the store's checks
/// (`SessionDir::open_op_dir`, which also requires the recorded op and session in its path and the
/// recorded volume), and the directory the gate reads the destination facts from must be that very
/// directory ([`gate::check_quarantine_destination_for`]: equal volume serial and file id).
#[derive(Debug, Clone, Copy)]
pub struct StoreLadder<'a> {
    ctx: &'a GateCtx,
    session: &'a SessionDir,
}

impl<'a> StoreLadder<'a> {
    /// The facts of the run with gate context `ctx` in session `session`.
    pub fn new(ctx: &'a GateCtx, session: &'a SessionDir) -> StoreLadder<'a> {
        StoreLadder { ctx, session }
    }
}

impl LadderEnv for StoreLadder<'_> {
    fn ancestors(&self, source: &str) -> BootMove {
        gate::admin_only_ancestors(source)
    }

    fn destination(&self, destination: &str) -> DestinationFacts {
        gate::destination_facts_at(destination)
    }

    fn look(&self, path: &str) -> SourceState {
        look(path)
    }

    /// Opens the op directory of `item.quarantine_path()` through the store (op, session and volume as
    /// recorded) and asks [`gate::check_quarantine_destination_for`] with it. `scope` is not used: the
    /// gate context's own scope (this session's) decides.
    fn check_destination(
        &self,
        _scope: &StoreScope,
        item: &LockedItem,
        source: &str,
    ) -> Result<DestinationFacts, Refusal> {
        let serial = item.validated.volume_serial;
        let (op_dir, leaf) = self
            .session
            .open_op_dir(Path::new(item.quarantine_path()), item.op, serial)
            .map_err(|_| Refusal {
                blocker: Blocker::CannotBackUp,
                reason: reason::QUARANTINE_DIR,
            })?;
        let dest =
            gate::check_quarantine_destination_for(self.ctx, source, serial, &op_dir, &leaf)?;
        Ok(dest.facts().clone())
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
    /// Cuts every occurrence of exactly `pair` (unit for unit) and returns how many were cut, whatever
    /// their number. [`remove_boot_move`] does not use it: it uses [`PendingRenames::remove_counted`].
    fn remove_exact(&mut self, pair: &PendingPair) -> Result<usize, FsError>;
    /// Cuts the occurrences of exactly `pair` (unit for unit, marker included) only if the list holds
    /// exactly `expected` of them, and returns that count; any other count is
    /// [`FsError::PendingCountMismatch`] with the number found, and nothing is changed. Count and cut
    /// are one compared read-modify-write (`purge_win::fs_write::remove_pending_pairs_exactly`), so a
    /// copy added between a count and a cut cannot be cut with ours (up to the registry's own two-call
    /// window, see there).
    ///
    /// The default, for implementations without a compared write, counts with
    /// [`PendingRenames::list`], then calls [`PendingRenames::remove_exact`] and fails with
    /// [`FsError::PendingCountMismatch`] if that cut another number than counted (it may then have
    /// changed the list); [`SystemPendingRenames`] and `MemoryPendingRenames` override it.
    fn remove_counted(&mut self, pair: &PendingPair, expected: usize) -> Result<usize, FsError> {
        let found = self.list()?.iter().filter(|p| *p == pair).count();
        if found != expected {
            return Err(FsError::PendingCountMismatch {
                found: u32::try_from(found).unwrap_or(u32::MAX),
            });
        }
        if expected == 0 {
            return Ok(0);
        }
        let removed = self.remove_exact(pair)?;
        if removed != expected {
            return Err(FsError::PendingCountMismatch {
                found: u32::try_from(removed).unwrap_or(u32::MAX),
            });
        }
        Ok(removed)
    }
}

/// The real list in `HKLM\SYSTEM\<current control set>\Control\Session Manager`. Registering and
/// removing need administrative rights; reading does not.
///
/// [`PendingRenames::remove_counted`] is `remove_pending_pairs_exactly`: count and cut in one compared
/// read-modify-write of `PendingFileRenameOperations`. The registry has no compare-and-swap, so that call
/// still has a two-call window (see its docs).
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

    fn remove_counted(&mut self, pair: &PendingPair, expected: usize) -> Result<usize, FsError> {
        fs_write::remove_pending_pairs_exactly(pair, expected)
    }
}

/// An in-memory `PendingFileRenameOperations` value (raw `REG_MULTI_SZ` bytes) for tests. Removal uses
/// the cutting code of the real removal: `purge_win::fs_write::remove_pairs_from_value` for
/// [`PendingRenames::remove_exact`], `remove_pair_exactly_from_value` (count and cut in one step,
/// nothing changed on another count) for [`PendingRenames::remove_counted`].
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryPendingRenames {
    value: Vec<u8>,
    marker: String,
    /// How many times [`PendingRenames::register`] was called.
    pub registers: usize,
    /// How many times [`PendingRenames::remove_exact`] or [`PendingRenames::remove_counted`] was
    /// called.
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

    fn remove_counted(&mut self, pair: &PendingPair, expected: usize) -> Result<usize, FsError> {
        self.check()?;
        self.removals += 1;
        let edit = fs_write::remove_pair_exactly_from_value(&self.value, pair, expected)?;
        if edit.removed > 0 {
            self.value = edit.value.unwrap_or_default();
        }
        Ok(edit.removed)
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

    /// The ladder with the facts of `env` (live, the destination checked against the session's store),
    /// the scope of `env`'s gate context and the default consent answer ([`DenyAll`]).
    pub fn in_store(env: &'a StoreLadder<'a>, lockers: &'a dyn LockerQuery) -> Ladder<'a> {
        Ladder {
            env,
            scope: env.ctx.scope(),
            lockers,
            consent: &DenyAll,
        }
    }

    /// Climbs the ladder for `item` up to the decision (see the module docs). Changes nothing.
    ///
    /// `journalled` is the op's intent when the file action already wrote one (a lock met by the rename
    /// after the intent); it must be the same action as the intent the ladder builds
    /// (`act_fs::same_action`: sizes and times in `pre` may differ), or the item fails with
    /// `Failed{Internal}` and nothing is done. The journalled intent is the one the action then carries.
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
        // The file action's intent carries `pre` from its act-time handle, the ladder's from the
        // validated record: the same action when op, item, operation, inverse, identity and kind agree
        // (M4 of the final M2 review; byte equality failed a directory that gained a file).
        if journalled.is_some_and(|j| !act_fs::same_action(&intent, j)) {
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
            // What the journal holds is what undo and recovery read.
            intent: journalled.cloned().unwrap_or(intent),
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
        let facts = match self.env.check_destination(self.scope, item, source) {
            Ok(facts) => facts,
            Err(refusal) => {
                return hold(
                    refusal.reason,
                    format!("the quarantine destination {destination} was refused ({refusal})"),
                );
            }
        };
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
    /// written), listed more than once is `Failed{Internal}`; otherwise it is registered and the list is
    /// read back: the pair as stored, `confirmed` when it stands there exactly once. The fault point
    /// `bootmove.registered` is not hit here: `JournalWriter::done` hits it for the `PendingReboot`
    /// outcome before it writes and flushes the `done`. A registration that fails is `Failed` (nothing registered). A token of
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
        // `bootmove.registered` is hit by `JournalWriter::done` for the `PendingReboot` outcome, before
        // it writes and flushes that `done`: once per registered move.
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
/// boot-time move. Read-only.
///
/// - `Ok(Some(PendingReboot{pair as stored, confirmed: true}))` when our pair stands in the list exactly
///   once: journal it with `done`.
/// - `Ok(None)` when the intent is not a quarantine move, or our pair is not listed: probe the item as
///   for any quarantine move.
/// - `Err(why)` when the list cannot be read or holds our pair more than once: whether a restart will
///   still move the item cannot be told, so nothing may move it by handle now (M7 of the final M2
///   review); the op needs attention.
pub fn pending_after_crash(
    intent: &Intent,
    store: &dyn PendingRenames,
) -> Result<Option<ItemOutcome>, String> {
    let Inverse::MoveBack {
        quarantine_path,
        original_path,
        ..
    } = &intent.inverse
    else {
        return Ok(None);
    };
    let Ok(expected) = expected_pair(original_path, quarantine_path) else {
        return Ok(None);
    };
    let list = store
        .list()
        .map_err(|e| format!("the boot-time move list cannot be read ({e})"))?;
    match occurrences(&list, &expected).as_slice() {
        [] => Ok(None),
        [stored] => Ok(Some(ItemOutcome::PendingReboot {
            pair: model_pair(stored),
            confirmed: true,
        })),
        more => Err(format!(
            "the boot-time move of the item is registered {} times",
            more.len()
        )),
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
    /// The system is as before (mismatch moved back, not moved, cancelled, retried without change).
    Unchanged,
    /// Reconcile found the op needing attention (`MismatchKept`, `Lost`): its undo is this conflict.
    Attention(UndoConflict),
    /// Not a lock op.
    Other,
}

fn lock_state(op: &OpState) -> LockState {
    let of = |outcome: &ItemOutcome| match outcome {
        ItemOutcome::HeldRetry => LockState::Held,
        ItemOutcome::PendingReboot { pair, .. } => LockState::Pending(pair.clone()),
        // A failed verify may have left the item in quarantine: the ordinary move back, in its
        // completing form, looks where it is.
        ItemOutcome::Done
        | ItemOutcome::Failed {
            code: FailCode::VerifyFailed,
            ..
        } => LockState::Moved,
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
            ReconcileResult::MismatchMovedBack
            | ReconcileResult::Cancelled
            | ReconcileResult::NotMoved { .. } => LockState::Unchanged,
            ReconcileResult::MismatchKept { .. } => {
                LockState::Attention(UndoConflict::FileIdMismatch)
            }
            ReconcileResult::Lost { .. } => LockState::Attention(UndoConflict::QuarantineMissing),
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
    /// Reconcile left the op needing attention: another object than the recorded one is kept in
    /// quarantine ([`UndoConflict::FileIdMismatch`]), or the item is neither in place nor in quarantine
    /// ([`UndoConflict::QuarantineMissing`]). Nothing can be undone:
    /// `undo_conflict_without_intent(op, conflict, detail)`.
    Conflict {
        /// The conflict to journal.
        conflict: UndoConflict,
        /// Why, for the report.
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
        LockState::Attention(conflict) => Some(LockUndo::Conflict {
            detail: match conflict {
                UndoConflict::FileIdMismatch => {
                    "reconcile found another object than the recorded one in quarantine; it was kept \
                     there"
                }
                _ => "reconcile found the item neither in place nor in quarantine",
            }
            .to_owned(),
            conflict,
        }),
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
/// when it stands in the list exactly once (the marker aside), cutting exactly the stored spelling with
/// [`PendingRenames::remove_counted`] (count and cut in one compared read-modify-write, expected count
/// 1). Hits `undo.act.after` after the removal. Foreign pairs stay byte-identical.
///
/// | Listed | Result |
/// |---|---|
/// | once, one cut | `Restored` |
/// | not at all (in the list, or at the removal) | `AlreadyRestored` |
/// | more than once (in the list, or at the removal) | `Failed{Internal}`, nothing removed |
/// | list unreadable, removal failed | `Failed{..}` with the error |
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
    // Count and cut in one compared read-modify-write: a copy that appeared since the list above is
    // never cut with ours.
    let removed = store.remove_counted(&stored, 1);
    fault::point(fault::UNDO_ACT_AFTER);
    match removed {
        Ok(1) => UndoOutcome::Restored,
        Ok(0) | Err(FsError::PendingCountMismatch { found: 0 }) => UndoOutcome::AlreadyRestored,
        Err(FsError::PendingCountMismatch { found }) => failed(
            FailCode::Internal,
            None,
            format!(
                "the boot-time move stands {found} times in the list at the removal; Purge added it \
                 once, so nothing was removed"
            ),
        ),
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
/// | no | something else, cannot be moved back | - | `MismatchKept`, alert | `MismatchKept{code}` |
/// | no | cannot be checked | - | `Indeterminate` | nothing |
/// | no | empty | present | `NotMoved` (failed) | `NotMoved{VerifyFailed}` |
/// | no | empty | absent | `Lost` | `Lost` |
/// | no | empty | cannot be looked at | `Indeterminate` | nothing |
///
/// Every journalled result but `StillPending` ends the op's pending state. After `NotMoved` the op's
/// undo is "nothing to undo"; after `MismatchKept` and `Lost` it needs attention
/// (`OpState::attention`) and its undo is a conflict ([`LockUndo::Conflict`]). "Nothing": the state
/// could not be told; the op stays pending a reboot and is reconciled again at the next start.
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
    /// For `MismatchKept`, why the object could not be moved back (the failure kind and the Win32
    /// error, when there is one); for `NotMoved`, `VerifyFailed`. `None` otherwise.
    pub failure: Option<(FailCode, Option<u32>)>,
}

impl Reconciled {
    /// The result to journal; `None` only for `Indeterminate`, which decides nothing.
    pub fn result(&self) -> Option<ReconcileResult> {
        let (code, os_error) = self.failure.unwrap_or((FailCode::Internal, None));
        match self.verdict {
            ReconcileVerdict::StillPending => Some(ReconcileResult::StillPending),
            ReconcileVerdict::Completed => Some(ReconcileResult::Completed),
            ReconcileVerdict::MismatchMovedBack => Some(ReconcileResult::MismatchMovedBack),
            ReconcileVerdict::MismatchKept => Some(ReconcileResult::MismatchKept {
                code,
                os_error,
                detail: self.detail.clone(),
            }),
            ReconcileVerdict::NotMoved => Some(ReconcileResult::NotMoved {
                code,
                os_error,
                detail: self.detail.clone(),
            }),
            ReconcileVerdict::Lost => Some(ReconcileResult::Lost {
                detail: self.detail.clone(),
            }),
            ReconcileVerdict::Indeterminate => None,
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

/// What sits at an op's quarantine destination.
enum Destination {
    Empty,
    Ours,
    /// Another object: its identity, and the handle that identity was read from when it could be
    /// opened for a rename (the move back acts on that very handle).
    Other(FileIdentity, Option<MoveHandle>),
    Unknown(String),
}

/// Reconciles every op of `state` whose boot-time move is pending ([`JournalState::pending_reboot`]); see
/// [`ReconcileVerdict`] for the table. The list is read once. The quarantine destination is reached
/// through the store-checked op directory (`SessionDir::open_op_dir`) and its handle's final path, and a
/// mismatch is moved back at once with the very handle its identity was read from, into the parent of the
/// source path after [`gate::check_undo_path`], never over anything; the move happens before the caller
/// journals it.
///
/// The undo-destination check takes the exemptions of the op's journal `validated` record, which the
/// caller handed to `ctx` (`GateCtx::record`, read with `GateCtx::exemptions`). An op without a record
/// is checked with no exemptions at all (the strictest check), never with wider ones.
pub fn reconcile(
    state: &JournalState,
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
                failure: None,
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
                    let ex = ctx.exemptions(op.op).unwrap_or_default();
                    let moved = move_back(ctx, item, identity, original_path, *volume_serial, ex);
                    let alert = ReconcileAlert {
                        op: op.op,
                        original_path: original_path.clone(),
                        quarantine_path: quarantine_path.clone(),
                        expected,
                        found: identity,
                        moved_back: moved.is_ok(),
                    };
                    let (verdict, detail, failure) = match moved {
                        Ok(()) => (
                            ReconcileVerdict::MismatchMovedBack,
                            format!(
                                "{quarantine_path} held another object than the one recorded; it was \
                                 moved back to {original_path}"
                            ),
                            None,
                        ),
                        Err((code, os_error, why)) => (
                            ReconcileVerdict::MismatchKept,
                            format!(
                                "{quarantine_path} holds another object than the one recorded; it could \
                                 not be moved back to {original_path} ({why}) and stays in quarantine"
                            ),
                            Some((code, os_error)),
                        ),
                    };
                    Reconciled {
                        op: op.op,
                        verdict,
                        detail,
                        alert: Some(alert),
                        failure,
                    }
                }
                Destination::Empty => match env.look(original_path) {
                    SourceState::Present { .. } => Reconciled {
                        failure: Some((FailCode::VerifyFailed, None)),
                        ..found(
                            ReconcileVerdict::NotMoved,
                            format!(
                                "{original_path}: the boot-time move did not happen; the item is still \
                                 in place"
                            ),
                        )
                    },
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

/// Looks at the op's quarantine destination through the store-checked op directory: the item is
/// opened relative to that directory's handle (`QuarantineDir::open_item`: one name component, a
/// reparse point opened itself, its final path the directory's plus the leaf), so no path is resolved
/// again. The identity is read from the handle a mismatch is then moved back with
/// ([`Destination::Other`]); only when that handle cannot be had (in use, denied) is a read-only
/// handle used for the identity, and nothing is moved.
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
    let item = match dir.open_item(&leaf) {
        Ok(Some(item)) => item,
        Ok(None) => return Destination::Empty,
        Err(e) => return Destination::Unknown(e.to_string()),
    };
    let identity = FileIdentity {
        volume_serial: item.file_id().volume_serial,
        file_id: item.file_id().id,
    };
    if identity == expected && item.reparse_tag() == 0 && !item.is_dir() {
        Destination::Ours
    } else {
        Destination::Other(identity, item.into_mover())
    }
}

/// Moves the object in quarantine whose identity `found` was read from `handle` back to `original`,
/// renaming that very handle into the parent [`gate::check_undo_path`] checked. A rename never replaces
/// anything. Without a handle (the object could not be opened for a rename) nothing is moved. A failure
/// carries the failure kind and Win32 error the journal's `MismatchKept` records, and the reason.
fn move_back(
    ctx: &GateCtx,
    handle: Option<MoveHandle>,
    found: FileIdentity,
    original: &str,
    volume_serial: u64,
    exemptions: Exemptions,
) -> Result<(), (FailCode, Option<u32>, String)> {
    let handle = handle.ok_or_else(|| {
        (
            FailCode::InUse,
            None,
            "it cannot be opened for a rename (in use or denied)".to_owned(),
        )
    })?;
    let now = handle.file_id().map_err(|e| {
        let (code, os_error) = fail_of(e);
        (code, os_error, e.to_string())
    })?;
    if now.volume_serial != found.volume_serial || now.id != found.file_id {
        return Err((
            FailCode::VerifyFailed,
            None,
            "the object changed while it was looked at".to_owned(),
        ));
    }
    let dest = gate::check_undo_path(ctx, original, volume_serial, exemptions)
        .map_err(|refusal| (FailCode::Internal, None, refusal.to_string()))?;
    handle.rename_into(dest.dir(), dest.leaf()).map_err(|e| {
        let (code, os_error) = fail_of(e);
        (code, os_error, e.to_string())
    })
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
/// then move it by handle to the intent's `MoveBack::quarantine_path`. For a file locked at the act the
/// op directory still exists (`SessionDir::open_op_dir`); for a directory, or a rename that failed, the
/// act removed its empty op directory again, and the retry makes it anew with
/// [`crate::act_fs::create_op_dir_for`]. A retry never registers a boot-time move.
pub trait RetryMove {
    /// Tries op `op` once more; `intent` is its journalled intent, and `token` proves its
    /// `retry_intent` is durable (the move must not run without it).
    fn retry(&mut self, op: &OpState, intent: &Intent, token: &RetryToken) -> RetryAttempt;
}

/// The result of one retry, journalled by [`retry_held`] as `reconcile` `Retried{outcome}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retried {
    /// The op.
    pub op: OpId,
    /// The outcome of the new attempt.
    pub outcome: ItemOutcome,
}

/// Tries every held op of the journal ([`JournalState::held_retry`]) again through `mover`, journalling
/// each retry write-ahead: `retry_intent` (flushed, [`JournalWriter::retry_intent`]) first, then the
/// move with the token, then `reconcile` `Retried{outcome}` ([`JournalWriter::retried`], flushed), whose
/// outcome replaces `HeldRetry`. An op whose intent is not a quarantine move with a `MoveBack` is not
/// passed to the mover and ends `Failed{Internal}`. Still locked stays `HeldRetry`.
///
/// Stops at the first journal error and returns it: the retries before it are journalled, and one whose
/// `retried` could not be written stays in flight (`OpState::retry_in_flight`), for recovery to probe
/// with the token of `JournalWriter::resume_retry`.
pub fn retry_held(
    journal: &mut JournalWriter,
    mover: &mut dyn RetryMove,
    at: FileTime,
) -> Result<Vec<Retried>, JournalError> {
    let held: Vec<OpState> = journal.state().held_retry().cloned().collect();
    let mut retried = Vec::with_capacity(held.len());
    for op in held {
        let token = journal.retry_intent(op.op, at)?;
        let outcome = match &op.intent {
            Some(
                intent @ Intent {
                    exec_op: ExecOp::QuarantineMove { .. },
                    inverse: Inverse::MoveBack { .. },
                    ..
                },
            ) => match mover.retry(&op, intent, &token) {
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
        journal.retried(token, at, outcome.clone())?;
        retried.push(Retried { op: op.op, outcome });
    }
    Ok(retried)
}
