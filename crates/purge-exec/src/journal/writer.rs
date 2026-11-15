//! Writing a journal: append-only, framed and chained lines, flushes where the write-ahead contract needs
//! them, and tokens that prove an intent is durable.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use purge_model::exec::journal::{
    AbortReason, Aborted, Commit, Done, Expire, GroupEnd, Header, Intent, MAX_GROUP_INTENTS,
    Reconcile, Record, UndoConflict, UndoConflictEntry, UndoDone, UndoIntent, UndoOutcome,
};
use purge_model::exec::op::{ItemOutcome, OpId, Sha256Hex};
use purge_model::{CandidateId, FileTime};
use purge_win::fs_write;

use super::frame::{CHAIN_SEED, frame};
use super::reader::{open_plain, parse};
use super::state::{JournalState, OpStatus, UndoState, Violation};
use super::{JournalError, JournalRead};
use crate::fault;

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

/// The only writer of a session's journal. It applies every record to a [`JournalState`] first, so it
/// never writes what the reader would refuse.
///
/// After a failed write or flush the writer is poisoned: the file may end in a partial line, which stays
/// the torn tail because nothing more is written ([`JournalError::Poisoned`]).
#[derive(Debug)]
pub struct JournalWriter {
    file: File,
    path: PathBuf,
    id: u64,
    state: JournalState,
    chain: [u8; 32],
    len: u64,
    discarded_tail: u64,
    poisoned: bool,
    syncs: u64,
}

impl JournalWriter {
    /// Creates the journal at `path` (absolute, inside a session directory the storage layer has checked)
    /// with the security descriptor `sddl` applied at creation, writes `header`, and flushes the file and
    /// its directory. Fails if anything already has that name; nothing existing is opened. Hits
    /// [`fault::JOURNAL_HEADER`] at the end.
    pub fn create(path: &Path, sddl: &str, header: Header) -> Result<JournalWriter, JournalError> {
        let file = fs_write::create_file_secure(path, sddl).map_err(|source| JournalError::Fs {
            context: "creating the journal",
            source,
        })?;
        let record = Record::Header(header.clone());
        let body = encode(&record)?;
        let mut writer = JournalWriter::with(file, path, JournalState::new(header), CHAIN_SEED, 0);
        writer.write_body(&body)?;
        writer.flush()?;
        if let Some(dir) = path.parent() {
            fs_write::flush_dir(dir).map_err(|source| {
                writer.poisoned = true;
                JournalError::Fs {
                    context: "flushing the session directory",
                    source,
                }
            })?;
        }
        fault::point(fault::JOURNAL_HEADER);
        Ok(writer)
    }

    /// Opens an existing journal to append to it (resume, rollback, undo, reconcile, expiry). Reads and
    /// checks it in full first: a corrupt journal is refused and left byte for byte as it was. A torn tail
    /// is cut off ([`JournalWriter::discarded_tail`]) and the file flushed before anything is appended.
    pub fn open_append(path: &Path) -> Result<JournalWriter, JournalError> {
        let mut file = open_plain(path, true)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|source| JournalError::Io {
                context: "reading the journal",
                source,
            })?;
        let JournalRead {
            state,
            valid_len,
            torn_tail,
            head,
            ..
        } = parse(&bytes)?;
        let mut writer = JournalWriter::with(file, path, state, head.0, valid_len);
        writer.discarded_tail = torn_tail;
        if torn_tail != 0 {
            writer.file.set_len(valid_len).map_err(|source| {
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

    fn with(file: File, path: &Path, state: JournalState, chain: [u8; 32], len: u64) -> Self {
        JournalWriter {
            file,
            path: path.to_path_buf(),
            id: NEXT_WRITER.fetch_add(1, Ordering::Relaxed),
            state,
            chain,
            len,
            discarded_tail: 0,
            poisoned: false,
            syncs: 0,
        }
    }

    /// The journal's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The session as written so far.
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

    /// Writes the op's `done`, consuming its intent token. Not flushed by itself (the next intent,
    /// group end, commit or abort flushes it); closes the group when it holds 64 intents and none is open.
    /// Hits [`fault::DONE_BEFORE`] first.
    pub fn done(&mut self, token: IntentToken, outcome: ItemOutcome) -> Result<(), JournalError> {
        self.check_poison()?;
        self.own(token.writer, token.op)?;
        fault::point(fault::DONE_BEFORE);
        self.append(
            &Record::Done(Done {
                op: token.op,
                item: token.item,
                outcome,
            }),
            false,
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

    /// A token for an op whose intent is in the journal with no done after it, for recovery to finish the
    /// op after [`JournalWriter::open_append`]. `None` for any other op, or once the run ended.
    pub fn resume_intent(&self, op: OpId) -> Option<IntentToken> {
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

    /// A token for an op whose undo is in progress (an `undo_intent` with nothing after it), for recovery
    /// to finish the interrupted undo after [`JournalWriter::open_append`]. `None` for any other op.
    pub fn resume_undo(&self, op: OpId) -> Option<UndoToken> {
        (self.state.op(op)?.undo == UndoState::InProgress).then_some(UndoToken {
            writer: self.id,
            op,
        })
    }

    /// Writes and flushes a `reconcile` record for a pending op.
    pub fn reconcile(&mut self, reconcile: Reconcile) -> Result<(), JournalError> {
        self.append(&Record::Reconcile(reconcile), true)
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

    /// Checks `record` against the rules, then writes it (and flushes when `sync`). A refused record
    /// writes nothing.
    fn append(&mut self, record: &Record, sync: bool) -> Result<(), JournalError> {
        self.check_poison()?;
        let body = encode(record)?;
        self.state.apply(record).map_err(JournalError::Refused)?;
        self.write_body(&body)?;
        if sync {
            self.flush()?;
        }
        Ok(())
    }

    fn write_body(&mut self, body: &str) -> Result<(), JournalError> {
        self.check_poison()?;
        let (line, next) = frame(&self.chain, body);
        if let Err(source) = self.file.write_all(&line) {
            self.poisoned = true;
            return Err(JournalError::Io {
                context: "writing a journal line",
                source,
            });
        }
        self.chain = next;
        self.len += line.len() as u64;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), JournalError> {
        self.check_poison()?;
        if let Err(source) = fs_write::flush(&self.file) {
            self.poisoned = true;
            return Err(JournalError::Fs {
                context: "flushing the journal",
                source,
            });
        }
        self.syncs += 1;
        Ok(())
    }

    /// How many flushes (`FlushFileBuffers`) this writer made.
    pub fn syncs(&self) -> u64 {
        self.syncs
    }
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
