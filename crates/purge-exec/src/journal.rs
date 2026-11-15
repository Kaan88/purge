//! Journal writer and reader (`purge.journal/1`), hashing, group flushes (M2-X-JOURNAL; ENGINE_PLAN.md
//! §7.8).
//!
//! The journal is what undo and crash recovery rely on, so this module owns the one rule set for what a
//! journal may contain, and both sides apply it: [`JournalWriter`] refuses to write a record that
//! [`parse`] would refuse to read.
//!
//! # File format
//!
//! `journal.jsonl` ([`JOURNAL_FILE_NAME`]) is UTF-8 text, one record per line, each line ended by a single
//! `\n` (no `\r`, no BOM). A line is the compact `serde_json` form of one
//! [`Record`](purge_model::exec::journal::Record) (an object tagged by `"rec"`, default escaping, so a
//! record never spans lines) with one field appended as its last member:
//!
//! ```text
//! {"rec":"done","op":1,"item":"c-01","outcome":{"kind":"Done"},"chain":"<64 lower-case hex digits>"}
//! ```
//!
//! **Hash chain.** `chain` of line *i* is `SHA-256(chain[i-1] || body[i])`, where `chain[0]` is 32 zero
//! bytes (the value before the first line) and `body[i]` is the record's compact JSON exactly as written,
//! without the `chain` member (the line minus its last 76 bytes `,"chain":"<64 hex>"}`, plus a closing
//! `}`). The reader recomputes the chain over the raw bytes before it parses a line, so any changed,
//! removed, inserted, duplicated or reordered line is refused, as is a later line once an earlier one
//! changed. The chain detects corruption and edits that were not re-chained; it is not a signature (the
//! journal lives in an admin-only directory, §7.4), and it cannot tell a journal cut at a line boundary
//! from a shorter one: a missing `commit` or `aborted` is what marks a run as unfinished.
//!
//! **Torn tail.** Bytes after the last `\n` are an unfinished write (the writer writes a whole line,
//! newline included, in one call, and flushes only after it). They are ignored, whatever they hold, and
//! reported as [`JournalRead::torn_tail`]; [`JournalWriter::open_append`] cuts them off before it appends.
//! Every `\n`-terminated line must frame, chain, parse and obey the rules, or the whole journal is refused
//! with [`JournalError::Corrupt`] naming the first bad line, and nothing is acted on or changed. A journal
//! with no complete first line is [`JournalError::Empty`]: nothing durable was written, so no op ran.
//!
//! **Rules** (checked by [`JournalState`], refusals are [`Violation`]s): the first line is the `header`;
//! then one `validated` per selected item (op ids 1 to `header.items`, each once), all before the first
//! `intent` or `done`; an `intent` must hang together ([`Intent::is_consistent`](purge_model::exec::journal::Intent::is_consistent)),
//! repeat its op's candidate id and target, and come before that op's `done`; a `done` without an intent is
//! legal only for outcomes that pass
//! [`ItemOutcome::allowed_without_intent`](purge_model::exec::op::ItemOutcome::allowed_without_intent); each op has at most one
//! intent and one done; a `group_end` closes the intents since the previous one (1 to
//! [`MAX_GROUP_INTENTS`], numbered from 1, the count must match); `commit` needs every op done, no open
//! group and counts equal to the done records; nothing of the run follows `commit` or `aborted`. Undo,
//! reconcile and expire records follow the rules documented on [`JournalState`].
//!
//! **Durability.** The header is flushed (`FlushFileBuffers`) together with its directory; every `intent`
//! is flushed before [`JournalWriter::intent`] returns the token the action needs; `done` and `validated`
//! records are flushed with the next intent, `group_end` (written and flushed after at most 64 intents),
//! `commit` or `aborted`, except a `done` whose outcome is
//! [`ItemOutcome::PendingReboot`](purge_model::exec::op::ItemOutcome::PendingReboot), which is flushed at
//! once: its boot-move pair is the only record of the registration. Undo, reconcile and expire records
//! are flushed one by one.
//!
//! **Through the store only.** The journal is created, opened and read only through a
//! [`SessionDir`](crate::storage::SessionDir): relative to the session directory's checked handle,
//! checked on the handle it is then read or written through. Its header must name that session
//! ([`JournalError::WrongSession`]), and it is at most [`MAX_JOURNAL_BYTES`] long.
//!
//! # Write-ahead by construction
//!
//! [`JournalWriter::intent`] returns an [`IntentToken`] only after the intent is flushed, and
//! [`JournalWriter::done`] consumes it. Nothing outside this module can make a token, so code that acts
//! takes `&IntentToken` as its proof that the write-ahead record is durable; the same holds for undo with
//! [`UndoToken`].
//!
//! # Hashing
//!
//! [`sha256_reader`] streams a reader (a [`StoreFile`](crate::storage::StoreFile)) into SHA-256 (backups,
//! definition files); [`verify_backup`] checks a [`BackupRef`](purge_model::exec::op::BackupRef) before
//! undo reads the file, opening it through the store.

mod frame;
mod hash;
mod reader;
mod state;
mod writer;

#[cfg(test)]
mod tests;

pub use hash::{BackupCheckError, sha256_bytes, sha256_reader, verify_backup};
pub use reader::{JournalRead, parse, read};
pub use state::{JournalState, OpState, OpStatus, Pending, Phase, UndoState, Violation};
pub use writer::{IntentToken, JournalWriter, UndoToken};

pub use purge_model::exec::journal::MAX_GROUP_INTENTS;

/// The file name of a session's journal inside its session directory.
pub const JOURNAL_FILE_NAME: &str = crate::storage::JOURNAL_FILE;

/// The largest journal the reader reads and the writer writes (256 MiB). A run of thousands of items
/// stays far below; the limit keeps a planted or runaway file from exhausting memory.
pub const MAX_JOURNAL_BYTES: u64 = 256 << 20;

/// Why a journal could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// A read, write or seek on the journal file failed.
    #[error("journal I/O failed while {context}: {source}")]
    Io {
        /// What was being done.
        context: &'static str,
        /// The error.
        #[source]
        source: std::io::Error,
    },
    /// The store refused the journal or its directory (a directory, a reparse point or a second hard
    /// link at the journal's name, a foreign owner or DACL, a failed check of the chain from the data
    /// root), could not create or open it (already exists, missing, in use), or flushing it failed.
    #[error("the store refused the journal: {0}")]
    Store(crate::storage::StorageError),
    /// The header names another session than the directory the journal is in (a journal copied
    /// between sessions, or a header built for another session).
    #[error("the journal's header names session {header}, its directory is session {dir}")]
    WrongSession {
        /// The session the header names.
        header: purge_model::exec::session::SessionId,
        /// The session directory's id.
        dir: purge_model::exec::session::SessionId,
    },
    /// The journal is, or would become, larger than [`MAX_JOURNAL_BYTES`]. Nothing was read or
    /// written.
    #[error("the journal would hold {bytes} bytes, over the {max}-byte limit")]
    TooLarge {
        /// The size found or the size after the refused write.
        bytes: u64,
        /// The limit.
        max: u64,
    },
    /// The journal holds no complete line, so no header: nothing durable was written and no op ran.
    #[error(
        "the journal holds no complete header ({torn_bytes} bytes of an unfinished first line)"
    )]
    Empty {
        /// Length of the unfinished first line in bytes.
        torn_bytes: u64,
    },
    /// A complete line is corrupt or breaks the rules. The whole journal is refused.
    #[error("journal line {line} (byte {offset}) is refused: {kind}")]
    Corrupt {
        /// Line number, counted from 1.
        line: u64,
        /// Byte offset of the start of the line.
        offset: u64,
        /// What is wrong with it.
        kind: Corruption,
    },
    /// The writer refused a record that breaks the rules; nothing was written.
    #[error("journal record refused: {0}")]
    Refused(Violation),
    /// A record did not serialise to one line that reads back equal; nothing was written.
    #[error("journal record does not round-trip: {0}")]
    Encoding(String),
    /// An earlier write or flush failed, so the file may end in a partial line; the writer takes no more
    /// records. Reopen with [`JournalWriter::open_append`], which cuts off a torn tail.
    #[error("an earlier journal write or flush failed; the writer takes no more records")]
    Poisoned,
}

/// What is wrong with one complete journal line.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Corruption {
    /// The line does not end in `,"chain":"<64 lower-case hex>"}` or does not start with `{`.
    #[error("the line has no chain field")]
    NotFramed,
    /// The chain value does not match the line and the lines before it.
    #[error("the hash chain does not match")]
    ChainMismatch,
    /// The record does not parse (bad JSON, unknown record kind, missing field, wrong schema id).
    #[error("the record does not parse: {0}")]
    Json(String),
    /// The record parses but breaks the journal's rules.
    #[error("{0}")]
    Rule(Violation),
}
