//! Writing a journal: append-only, framed and chained lines, flushes where the write-ahead contract needs
//! them, and tokens that prove an intent is durable.

use std::collections::BTreeSet;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use purge_model::exec::journal::{
    AbortReason, Aborted, Commit, Done, Expire, GroupEnd, Header, Intent, MAX_GROUP_INTENTS,
    Reconcile, ReconcileResult, Record, RetryIntent, RunSettings, UndoConflict, UndoConflictEntry,
    UndoDone, UndoIntent, UndoOutcome,
};
use purge_model::exec::op::{ItemOutcome, OpId, Sha256Hex};
use purge_model::{CandidateId, FileTime};

use super::frame::{CHAIN_SEED, frame};
use super::reader::read_checked;
use super::state::{JournalState, OpStatus, UndoState, Violation};
use super::{JournalError, JournalRead, MAX_JOURNAL_BYTES};
use crate::fault;
use crate::storage::{FileMode, JOURNAL_FILE, SessionDir, StoreFile};

/// Source of writer ids, so a token is only accepted by the writer that issued it.
static NEXT_WRITER: AtomicU64 = AtomicU64::new(1);

/// Proof that an op's `intent` record is durable in the journal: [`JournalWriter::intent`] hands it out
/// only after the flush, and [`JournalWriter::done`] consumes it. It cannot be built, cloned or copied
/// outside the journal module, so an action that takes `&IntentToken` cannot run before its intent is on
/// disk.
///
/// ```compile_fail
/// use purge_exec::journal::IntentToken;
/// use purge_model::CandidateId;
/// use purge_model::exec::op::OpId;
/// // Fields are private: a token cannot be made up.
/// let token = IntentToken { writer: 1, op: OpId(1), item: CandidateId("c-1".into()) };
/// ```
///
/// Dropping a token without [`JournalWriter::done`] leaves the op as "intent only", which recovery
/// probes, and makes [`JournalWriter::commit`] fail.
#[derive(Debug)]
#[must_use = "an intent token must end in JournalWriter::done"]
pub struct IntentToken {
    writer: u64,
    op: OpId,
    item: CandidateId,
}

impl IntentToken {
    /// The op whose intent is durable.
    pub fn op(&self) -> OpId {
        self.op
    }

    /// The candidate id of the op's plan item.
    pub fn item(&self) -> &CandidateId {
        &self.item
    }
}

/// Proof that an op's `undo_intent` record is durable: handed out by [`JournalWriter::undo_intent`] after
/// the flush and consumed by [`JournalWriter::undo_done`] or [`JournalWriter::undo_conflict`]. An inverse
/// takes `&UndoToken`.
#[derive(Debug)]
#[must_use = "an undo token must end in JournalWriter::undo_done or undo_conflict"]
pub struct UndoToken {
    writer: u64,
    op: OpId,
}

impl UndoToken {
    /// The op whose undo intent is durable.
    pub fn op(&self) -> OpId {
        self.op
    }
}

/// Proof that a held op's `retry_intent` record is durable: handed out by
/// [`JournalWriter::retry_intent`] after the flush and consumed by [`JournalWriter::retried`]. The
/// retry's move takes `&RetryToken`, so it cannot run before its write-ahead record is on disk.
///
/// ```compile_fail
/// use purge_exec::journal::RetryToken;
/// use purge_model::exec::op::OpId;
/// // Fields are private: a token cannot be made up.
/// let token = RetryToken { writer: 1, op: OpId(1) };
/// ```
///
/// Dropping a token without [`JournalWriter::retried`] leaves the retry in flight
/// ([`OpState::retry_in_flight`](super::OpState::retry_in_flight)), which recovery probes; the op
/// takes no undo, expire or second retry meanwhile.
#[derive(Debug)]
#[must_use = "a retry token must end in JournalWriter::retried"]
pub struct RetryToken {
    writer: u64,
    op: OpId,
}

impl RetryToken {
    /// The held op whose retry intent is durable.
    pub fn op(&self) -> OpId {
        self.op
    }
}

/// The only writer of a session's journal. It checks every record against a [`JournalState`] first, so
/// it never writes what the reader would refuse, and applies it to that state only once it is written,
/// so the state never runs ahead of the file.
///
/// After a failed write or flush the writer is poisoned: the file may end in a partial line, which stays
/// the torn tail because nothing more is written ([`JournalError::Poisoned`]). Reopen it with
/// [`JournalWriter::open_append`].
#[derive(Debug)]
pub struct JournalWriter {
    file: StoreFile,
    id: u64,
    state: JournalState,
    chain: [u8; 32],
    len: u64,
    discarded_tail: u64,
    poisoned: bool,
    syncs: u64,
    /// Ops whose intent was open when [`JournalWriter::open_append`] read the journal and whose token
    /// [`JournalWriter::resume_intent`] has not handed out yet.
    resumable: BTreeSet<OpId>,
    /// Ops whose undo was in progress when the journal was opened, for
    /// [`JournalWriter::resume_undo`].
    resumable_undo: BTreeSet<OpId>,
    /// Ops whose retry was in flight when the journal was opened, for
    /// [`JournalWriter::resume_retry`].
    resumable_retry: BTreeSet<OpId>,
    /// Test hook: the next line write fails as a disk error would.
    #[cfg(test)]
    fail_next_write: bool,
}

impl JournalWriter {
    /// Creates the journal of `session` through the store ([`SessionDir::create_file`]: create-new,
    /// relative to the session directory's checked handle, with the store's file descriptor, checked
    /// on the handle it writes through), flushes the directory, writes `header` and flushes it. Fails
    /// if anything already has the name (nothing existing is opened) and if `header` names another
    /// session ([`JournalError::WrongSession`]). Hits [`fault::JOURNAL_HEADER`] at the end.
    pub fn create(session: &SessionDir, header: Header) -> Result<JournalWriter, JournalError> {
        if &header.session != session.id() {
            return Err(JournalError::WrongSession {
                header: header.session.clone(),
                dir: session.id().clone(),
            });
        }
        let record = Record::Header(header.clone());
        let body = encode(&record)?;
        let file = session
            .create_file(JOURNAL_FILE)
            .map_err(JournalError::Store)?;
        // The directory entry is made durable before the header; a crash in between leaves an empty
        // journal, which reads as "nothing ran".
        file.sync_dir().map_err(JournalError::Store)?;
        let mut writer = JournalWriter::with(file, JournalState::new(header), CHAIN_SEED, 0);
        writer.write_body(&body)?;
        writer.flush()?;
        fault::point(fault::JOURNAL_HEADER);
        Ok(writer)
    }

    /// Opens the existing journal of `session` to append to it (resume, rollback, undo, reconcile,
    /// expiry), through the store ([`SessionDir`]: relative to the session directory's checked handle,
    /// checked on the handle it then reads and writes; other handles may only read meanwhile, so a
    /// second writer is excluded). Reads and checks it in full first: a corrupt journal, or one whose
    /// header names another session, is refused and left byte for byte as it was. A torn tail is cut
    /// off ([`JournalWriter::discarded_tail`]) and the file flushed before anything is appended.
    pub fn open_append(session: &SessionDir) -> Result<JournalWriter, JournalError> {
        let mut file = session
            .open_file_with(JOURNAL_FILE, FileMode::Append)
            .map_err(JournalError::Store)?;
        let JournalRead {
            state,
            valid_len,
            torn_tail,
            head,
            ..
        } = read_checked(session, &mut file)?;
        let (resumable, resumable_undo) = if state.is_finished() {
            (
                BTreeSet::new(),
                state.undo_in_progress().map(|s| s.op).collect(),
            )
        } else {
            (
                state.open_intents().map(|s| s.op).collect(),
                state.undo_in_progress().map(|s| s.op).collect(),
            )
        };
        let resumable_retry = state.retries_in_flight().map(|s| s.op).collect();
        let mut writer = JournalWriter::with(file, state, head.0, valid_len);
        writer.resumable = resumable;
        writer.resumable_undo = resumable_undo;
        writer.resumable_retry = resumable_retry;
        writer.discarded_tail = torn_tail;
        if torn_tail != 0 {
            writer.file.file().set_len(valid_len).map_err(|source| {
                writer.poisoned = true;
                JournalError::Io {
                    context: "cutting off the torn tail",
                    source,
                }
            })?;
        }
        writer
            .file
            .seek(SeekFrom::Start(valid_len))
            .map_err(|source| {
                writer.poisoned = true;
                JournalError::Io {
                    context: "seeking to the end of the journal",
                    source,
                }
            })?;
        writer.flush()?;
        Ok(writer)
    }

    fn with(file: StoreFile, state: JournalState, chain: [u8; 32], len: u64) -> Self {
        JournalWriter {
            file,
            id: NEXT_WRITER.fetch_add(1, Ordering::Relaxed),
            state,
            chain,
            len,
            discarded_tail: 0,
            poisoned: false,
            syncs: 0,
            resumable: BTreeSet::new(),
            resumable_undo: BTreeSet::new(),
            resumable_retry: BTreeSet::new(),
            #[cfg(test)]
            fail_next_write: false,
        }
    }

    /// Where the journal is, for reports and messages only; it is never opened by this path.
    pub fn report_path(&self) -> PathBuf {
        self.file.report_path()
    }

    /// The session as written so far: every record whose line was written, none that was refused or
    /// whose write failed.
    pub fn state(&self) -> &JournalState {
        &self.state
    }
    /// The chain value of the last line written.
    pub fn head(&self) -> Sha256Hex {
        Sha256Hex::from(self.chain)
    }

    /// Length of the journal in bytes (written; durable after the next flush).
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the journal holds no bytes; never true for an open writer, which wrote or read a header.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes of a torn tail that [`JournalWriter::open_append`] cut off; 0 for a created journal.
    pub fn discarded_tail(&self) -> u64 {
        self.discarded_tail
    }

    /// Whether a write or flush failed; the writer then takes no more records.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Flushes the journal to disk (`FlushFileBuffers`).
    pub fn sync(&mut self) -> Result<(), JournalError> {
        self.flush()
    }

    /// Writes and flushes the run's `settings` record. Only right after the header
    /// ([`Violation::SettingsMisplaced`]): `Run::start` writes it before anything else, and
    /// `Run::resume` reads the settings back from it instead of taking them from its caller.
    pub fn settings(&mut self, settings: RunSettings) -> Result<(), JournalError> {
        self.append(&Record::Settings(settings), true)
    }

    /// Writes the `validated` record of one selected item. Flushed with the next intent; call
    /// [`JournalWriter::sync`] to flush earlier.
    pub fn validated(
        &mut self,
        validated: purge_model::exec::journal::Validated,
    ) -> Result<(), JournalError> {
        self.append(&Record::Validated(validated), false)
    }

    /// Writes and flushes the op's `intent`, closing the open group first if it is full, and returns the
    /// token the action and [`JournalWriter::done`] need. Hits [`fault::INTENT_FLUSHED`] after the flush.
    pub fn intent(&mut self, intent: Intent) -> Result<IntentToken, JournalError> {
        self.check_poison()?;
        if self.state.open_group_intents() >= MAX_GROUP_INTENTS {
            self.end_group()?;
        }
        let (op, item) = (intent.op, intent.item.clone());
        self.append(&Record::Intent(intent), true)?;
        fault::point(fault::INTENT_FLUSHED);
        Ok(IntentToken {
            writer: self.id,
            op,
            item,
        })
    }

    /// Writes the op's `done`, consuming its intent token; closes the group when it holds 64 intents and
    /// none is open. Hits [`fault::DONE_BEFORE`] first.
    ///
    /// A `done` is not flushed by itself (the next intent, group end, commit or abort flushes it): a
    /// lost `done` after a flushed intent is the "intent only" case recovery probes from the disk. The
    /// exception is [`ItemOutcome::PendingReboot`]: its pair is the only record of what was put in
    /// `PendingFileRenameOperations`, which the disk cannot tell, so that `done` is flushed before this
    /// returns (one `FlushFileBuffers` per boot-time move). [`fault::BOOTMOVE_REGISTERED`] is hit first
    /// for it: the move is registered, its `done` not yet written.
    pub fn done(&mut self, token: IntentToken, outcome: ItemOutcome) -> Result<(), JournalError> {
        self.check_poison()?;
        self.own(token.writer, token.op)?;
        let durable = needs_flush(&outcome);
        if durable {
            fault::point(fault::BOOTMOVE_REGISTERED);
        }
        fault::point(fault::DONE_BEFORE);
        self.append(
            &Record::Done(Done {
                op: token.op,
                item: token.item,
                outcome,
            }),
            durable,
        )?;
        self.close_full_group()
    }

    /// Writes the `done` of an op decided before any backup was taken (already gone, refused by a gate):
    /// only outcomes that pass [`ItemOutcome::allowed_without_intent`], only for an op with no intent
    /// (with one, use its token). Not flushed by itself. Hits [`fault::DONE_BEFORE`] first.
    pub fn done_without_intent(
        &mut self,
        op: OpId,
        outcome: ItemOutcome,
    ) -> Result<(), JournalError> {
        self.check_poison()?;
        let state = self
            .state
            .op(op)
            .ok_or(JournalError::Refused(Violation::UnknownOp(op)))?;
        if matches!(state.status(), OpStatus::IntentOnly) {
            return Err(JournalError::Refused(Violation::TokenRequired(op)));
        }
        let item = state.item.clone();
        fault::point(fault::DONE_BEFORE);
        self.append(&Record::Done(Done { op, item, outcome }), false)?;
        self.close_full_group()
    }

    /// The token of an op whose intent was open (no done after it) when [`JournalWriter::open_append`]
    /// read the journal, for recovery to finish the op. Handed out once per op: `None` on a second
    /// call, for any other op, on a writer made by [`JournalWriter::create`] (whose intents' tokens
    /// came from [`JournalWriter::intent`]), and when the run had already ended.
    pub fn resume_intent(&mut self, op: OpId) -> Option<IntentToken> {
        if !self.resumable.remove(&op) {
            return None;
        }
        let state = self.state.op(op)?;
        if self.state.is_finished() || !matches!(state.status(), OpStatus::IntentOnly) {
            return None;
        }
        Some(IntentToken {
            writer: self.id,
            op,
            item: state.item.clone(),
        })
    }

    /// Closes the open group with a `group_end` and flushes; returns whether there was one to close (a
    /// group with no intent is not closed). Hits [`fault::GROUP_END`] after the flush.
    pub fn end_group(&mut self) -> Result<bool, JournalError> {
        self.check_poison()?;
        let ops = self.state.open_group_intents();
        if ops == 0 {
            return Ok(false);
        }
        let group = self.state.groups_closed() + 1;
        self.append(&Record::GroupEnd(GroupEnd { group, ops }), true)?;
        fault::point(fault::GROUP_END);
        Ok(true)
    }

    /// Closes the group when it is full and no intent in it is waiting for its done.
    fn close_full_group(&mut self) -> Result<(), JournalError> {
        if self.state.open_group_intents() >= MAX_GROUP_INTENTS
            && self.state.open_intent_count() == 0
        {
            self.end_group()?;
        }
        Ok(())
    }

    /// Ends the run: closes the open group, hits [`fault::COMMIT_BEFORE`], then writes and flushes
    /// `commit` with the counts of the done records. Refused unless every op has its done.
    pub fn commit(&mut self, at: FileTime, backup_bytes: u64) -> Result<Commit, JournalError> {
        self.check_poison()?;
        // Refuse before closing the group, so a refused commit writes nothing.
        if self.state.is_finished() {
            return Err(JournalError::Refused(Violation::AfterFinish("commit")));
        }
        if let Some(open) = self.state.ops().find(|s| s.outcome.is_none()) {
            return Err(JournalError::Refused(Violation::MissingDone(open.op)));
        }
        self.end_group()?;
        fault::point(fault::COMMIT_BEFORE);
        let commit = Commit {
            at,
            counts: self.state.counts(),
            backup_bytes,
        };
        self.append(&Record::Commit(commit.clone()), true)?;
        Ok(commit)
    }

    /// Ends the run early: closes the open group, then writes and flushes `aborted`. Items without a done
    /// stay as they are (recovery probes those with an intent).
    pub fn abort(
        &mut self,
        at: FileTime,
        reason: AbortReason,
        detail: String,
    ) -> Result<(), JournalError> {
        self.check_poison()?;
        self.end_group()?;
        self.append(&Record::Aborted(Aborted { at, reason, detail }), true)
    }

    /// Writes and flushes the op's `undo_intent` and returns the token the inverse and
    /// [`JournalWriter::undo_done`] need. Hits [`fault::UNDO_INTENT`] after the flush.
    pub fn undo_intent(&mut self, op: OpId) -> Result<UndoToken, JournalError> {
        self.append(&Record::UndoIntent(UndoIntent { op }), true)?;
        fault::point(fault::UNDO_INTENT);
        Ok(UndoToken {
            writer: self.id,
            op,
        })
    }

    /// Writes and flushes the `undo_done` of an inverse that ran, consuming its token.
    pub fn undo_done(
        &mut self,
        token: UndoToken,
        outcome: UndoOutcome,
    ) -> Result<(), JournalError> {
        self.undo_owned(&token)?;
        self.append(
            &Record::UndoDone(UndoDone {
                op: token.op,
                outcome,
            }),
            true,
        )
    }

    /// Writes and flushes the `undo_conflict` that ends an undo after its `undo_intent`, consuming its
    /// token.
    pub fn undo_conflict(
        &mut self,
        token: UndoToken,
        conflict: UndoConflict,
        detail: String,
    ) -> Result<(), JournalError> {
        self.undo_owned(&token)?;
        self.append(
            &Record::UndoConflict(UndoConflictEntry {
                op: token.op,
                conflict,
                detail,
            }),
            true,
        )
    }

    /// Writes and flushes an `undo_done` decided without running an inverse: only
    /// [`UndoOutcome::NothingToUndo`] or [`UndoOutcome::AlreadyRestored`], and not while an undo intent of
    /// the op is open (use its token).
    pub fn undo_done_without_intent(
        &mut self,
        op: OpId,
        outcome: UndoOutcome,
    ) -> Result<(), JournalError> {
        self.no_open_undo(op)?;
        self.append(&Record::UndoDone(UndoDone { op, outcome }), true)
    }

    /// Writes and flushes an `undo_conflict` found before any `undo_intent` (a tampered or missing
    /// backup), and not while an undo intent of the op is open (use its token).
    pub fn undo_conflict_without_intent(
        &mut self,
        op: OpId,
        conflict: UndoConflict,
        detail: String,
    ) -> Result<(), JournalError> {
        self.no_open_undo(op)?;
        self.append(
            &Record::UndoConflict(UndoConflictEntry {
                op,
                conflict,
                detail,
            }),
            true,
        )
    }

    /// The token of an op whose undo was in progress (an `undo_intent` with nothing after it) when
    /// [`JournalWriter::open_append`] read the journal, for recovery to finish the interrupted undo.
    /// Handed out once per op, like [`JournalWriter::resume_intent`]: `None` on a second call, for any
    /// other op, and on a writer made by [`JournalWriter::create`].
    pub fn resume_undo(&mut self, op: OpId) -> Option<UndoToken> {
        if !self.resumable_undo.remove(&op) {
            return None;
        }
        (self.state.op(op)?.undo == UndoState::InProgress).then_some(UndoToken {
            writer: self.id,
            op,
        })
    }

    /// Writes and flushes a `reconcile` record for a pending op. A
    /// [`ReconcileResult::Retried`] ends a retry and needs its token: use [`JournalWriter::retried`]
    /// (refused here with [`Violation::RetryNotInFlight`]).
    pub fn reconcile(&mut self, reconcile: Reconcile) -> Result<(), JournalError> {
        if matches!(reconcile.result, ReconcileResult::Retried { .. }) {
            return Err(JournalError::Refused(Violation::RetryNotInFlight(
                reconcile.op,
            )));
        }
        self.append(&Record::Reconcile(reconcile), true)
    }

    /// Writes and flushes the `retry_intent` of a held op (one whose outcome, as changed by its
    /// reconcile records, is `HeldRetry`, after the run ended, with no retry in flight) and returns the
    /// token the retry's move and [`JournalWriter::retried`] need.
    pub fn retry_intent(&mut self, op: OpId, at: FileTime) -> Result<RetryToken, JournalError> {
        self.append(&Record::RetryIntent(RetryIntent { at, op }), true)?;
        Ok(RetryToken {
            writer: self.id,
            op,
        })
    }

    /// Writes and flushes the `reconcile` record that ends a retry, consuming its token: its
    /// [`ReconcileResult::Retried`] outcome replaces the op's `HeldRetry` (`HeldRetry` again when the
    /// item is still in use; never `PendingReboot`, which a retry does not register).
    pub fn retried(
        &mut self,
        token: RetryToken,
        at: FileTime,
        outcome: ItemOutcome,
    ) -> Result<(), JournalError> {
        self.check_poison()?;
        self.own(token.writer, token.op)?;
        match self.state.op(token.op) {
            Some(state) if state.retry_in_flight => {}
            _ => {
                return Err(JournalError::Refused(Violation::RetryNotInFlight(token.op)));
            }
        }
        self.append(
            &Record::Reconcile(Reconcile {
                at,
                op: token.op,
                result: ReconcileResult::Retried { outcome },
            }),
            true,
        )
    }

    /// The token of an op whose retry was in flight (a `retry_intent` with no `reconcile` after it)
    /// when [`JournalWriter::open_append`] read the journal, for recovery to probe the item and end the
    /// retry with [`JournalWriter::retried`]. Handed out once per op, like
    /// [`JournalWriter::resume_intent`]: `None` on a second call, for any other op, and on a writer made
    /// by [`JournalWriter::create`].
    pub fn resume_retry(&mut self, op: OpId) -> Option<RetryToken> {
        if !self.resumable_retry.remove(&op) {
            return None;
        }
        self.state.op(op)?.retry_in_flight.then_some(RetryToken {
            writer: self.id,
            op,
        })
    }

    /// Writes and flushes an `expire` record (after the run ended).
    pub fn expire(&mut self, expire: Expire) -> Result<(), JournalError> {
        self.append(&Record::Expire(expire), true)
    }

    fn check_poison(&self) -> Result<(), JournalError> {
        if self.poisoned {
            Err(JournalError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn own(&self, writer: u64, op: OpId) -> Result<(), JournalError> {
        if writer == self.id {
            Ok(())
        } else {
            Err(JournalError::Refused(Violation::ForeignToken(op)))
        }
    }

    fn undo_owned(&self, token: &UndoToken) -> Result<(), JournalError> {
        self.check_poison()?;
        self.own(token.writer, token.op)?;
        match self.state.op(token.op) {
            Some(state) if state.undo == UndoState::InProgress => Ok(()),
            _ => Err(JournalError::Refused(Violation::UndoNotInProgress(
                token.op,
            ))),
        }
    }

    fn no_open_undo(&self, op: OpId) -> Result<(), JournalError> {
        self.check_poison()?;
        match self.state.op(op) {
            Some(state) if state.undo == UndoState::InProgress => {
                Err(JournalError::Refused(Violation::TokenRequired(op)))
            }
            _ => Ok(()),
        }
    }

    /// Checks `record` against the rules, writes it, applies it to the state, and flushes when `sync`.
    /// A refused record writes nothing and changes nothing; a record whose write fails poisons the
    /// writer and is not applied. A record whose flush fails is in the file and in the state, and the
    /// writer is poisoned.
    fn append(&mut self, record: &Record, sync: bool) -> Result<(), JournalError> {
        self.check_poison()?;
        let body = encode(record)?;
        self.state.check(record).map_err(JournalError::Refused)?;
        self.write_body(&body)?;
        self.state.record(record);
        if sync {
            self.flush()?;
        }
        Ok(())
    }

    fn write_body(&mut self, body: &str) -> Result<(), JournalError> {
        self.check_poison()?;
        let (line, next) = frame(&self.chain, body);
        let grown = self.len.saturating_add(line.len() as u64);
        if grown > MAX_JOURNAL_BYTES {
            // Nothing is written: the reader would refuse a longer journal.
            return Err(JournalError::TooLarge {
                bytes: grown,
                max: MAX_JOURNAL_BYTES,
            });
        }
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_write) {
            self.poisoned = true;
            return Err(JournalError::Io {
                context: "writing a journal line",
                source: std::io::Error::from_raw_os_error(112),
            });
        }
        if let Err(source) = self.file.write_all(&line) {
            self.poisoned = true;
            return Err(JournalError::Io {
                context: "writing a journal line",
                source,
            });
        }
        self.chain = next;
        self.len = grown;
        self.state.advance(next);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), JournalError> {
        self.check_poison()?;
        if let Err(e) = self.file.sync() {
            self.poisoned = true;
            return Err(JournalError::Store(e));
        }
        self.syncs += 1;
        Ok(())
    }

    /// Test hook: makes the next line write fail as a full disk would (`ERROR_DISK_FULL`).
    #[cfg(test)]
    pub(super) fn inject_write_failure(&mut self) {
        self.fail_next_write = true;
    }

    /// How many flushes (`FlushFileBuffers`) this writer made.
    pub fn syncs(&self) -> u64 {
        self.syncs
    }
}

/// Whether a `done` with `outcome` must be flushed before [`JournalWriter::done`] returns: its outcome is
/// the only record of a system change the disk state cannot show (a registered boot-time move).
fn needs_flush(outcome: &ItemOutcome) -> bool {
    matches!(outcome, ItemOutcome::PendingReboot { .. })
}

/// The compact JSON of `record`, checked to be one line that reads back as an equal record.
fn encode(record: &Record) -> Result<String, JournalError> {
    let body = serde_json::to_string(record).map_err(|e| JournalError::Encoding(e.to_string()))?;
    if body.len() < 3 || !body.starts_with('{') || !body.ends_with('}') || body.contains('\n') {
        return Err(JournalError::Encoding(format!(
            "{} record is not a one-line JSON object",
            record.name()
        )));
    }
    let back: Record =
        serde_json::from_str(&body).map_err(|e| JournalError::Encoding(e.to_string()))?;
    if &back != record {
        return Err(JournalError::Encoding(format!(
            "{} record reads back different",
            record.name()
        )));
    }
    Ok(body)
}
