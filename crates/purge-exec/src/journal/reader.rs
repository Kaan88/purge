//! Reading a journal back: framing, chain, records and rules, with the torn-tail rule.

use purge_model::exec::journal::Record;
use purge_model::exec::op::Sha256Hex;

use super::frame::{CHAIN_SEED, unframe};
use super::state::{JournalState, Violation};
use super::{Corruption, JournalError, MAX_JOURNAL_BYTES};
use crate::storage::{FileMode, JOURNAL_FILE, SessionDir, StoreFile};

/// A journal read back in full.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalRead {
    /// Every record of the complete lines, in order; the first is the header.
    pub records: Vec<Record>,
    /// The session the records describe.
    pub state: JournalState,
    /// Length in bytes of the complete lines.
    pub valid_len: u64,
    /// Length in bytes of the unfinished last line that was ignored; 0 when the journal ends in `\n`.
    pub torn_tail: u64,
    /// The chain value of the last complete line.
    pub head: Sha256Hex,
    /// The chain value of every complete line, in order (`line_heads[0]` is the header's): what
    /// [`check_mark`](super::check_mark) compares an index entry's [`JournalMark`] with.
    ///
    /// [`JournalMark`]: purge_model::exec::session::JournalMark
    pub line_heads: Vec<Sha256Hex>,
}

impl JournalRead {
    /// The chain value of the journal's first `lines` lines (of line `lines`, counted from 1), or `None`
    /// when it has fewer lines or `lines` is 0.
    pub fn head_at(&self, lines: u64) -> Option<Sha256Hex> {
        let index = usize::try_from(lines).ok()?.checked_sub(1)?;
        self.line_heads.get(index).copied()
    }
}

/// Reads the journal of `session` (see [`parse`]) through the store: the file is opened relative to
/// the session directory's checked handle and checked on that handle (a plain file with one link,
/// not a reparse point, admin-only; a failing one is renamed aside), and a writer may hold it open
/// meanwhile. Refuses a journal larger than [`MAX_JOURNAL_BYTES`] and one whose header names another
/// session than the directory ([`JournalError::WrongSession`]).
pub fn read(session: &SessionDir) -> Result<JournalRead, JournalError> {
    let mut file = session
        .open_file_with(JOURNAL_FILE, FileMode::ReadShared)
        .map_err(JournalError::Store)?;
    read_checked(session, &mut file)
}

/// Reads and parses the whole of an opened journal and checks that it belongs to `session`.
pub(super) fn read_checked(
    session: &SessionDir,
    file: &mut StoreFile,
) -> Result<JournalRead, JournalError> {
    let bytes = file.read_all(MAX_JOURNAL_BYTES).map_err(|e| match e {
        crate::storage::StorageError::TooLarge { bytes, max, .. } => {
            JournalError::TooLarge { bytes, max }
        }
        e => JournalError::Store(e),
    })?;
    let read = parse(&bytes)?;
    let header = read.state.session();
    if header != session.id() {
        return Err(JournalError::WrongSession {
            header: header.clone(),
            dir: session.id().clone(),
        });
    }
    Ok(read)
}

/// Parses journal bytes: every `\n`-terminated line must frame, chain, parse and obey the rules; bytes
/// after the last `\n` are a torn tail and ignored. Never panics: a journal cut at any byte gives either
/// the state of its complete lines or [`JournalError::Empty`].
pub fn parse(bytes: &[u8]) -> Result<JournalRead, JournalError> {
    let mut chain = CHAIN_SEED;
    let mut records = Vec::new();
    let mut line_heads = Vec::new();
    let mut state: Option<JournalState> = None;
    let mut start = 0usize;
    let mut line_no = 0u64;
    while let Some(len) = bytes[start..].iter().position(|&b| b == b'\n') {
        line_no += 1;
        let line = &bytes[start..start + len];
        let corrupt = |kind| JournalError::Corrupt {
            line: line_no,
            offset: start as u64,
            kind,
        };
        let (body, next) = unframe(&chain, line).map_err(corrupt)?;
        let record: Record =
            serde_json::from_slice(&body).map_err(|e| corrupt(Corruption::Json(e.to_string())))?;
        match state.as_mut() {
            None => match &record {
                Record::Header(header) => {
                    let mut first = JournalState::new(header.clone());
                    first.advance(next);
                    state = Some(first);
                }
                _ => return Err(corrupt(Corruption::Rule(Violation::HeaderNotFirst))),
            },
            Some(state) => {
                state
                    .apply(&record)
                    .map_err(|v| corrupt(Corruption::Rule(v)))?;
                state.advance(next);
            }
        }
        records.push(record);
        line_heads.push(Sha256Hex::from(next));
        chain = next;
        start += len + 1;
    }
    let torn_tail = (bytes.len() - start) as u64;
    let Some(state) = state else {
        return Err(JournalError::Empty {
            torn_bytes: torn_tail,
        });
    };
    Ok(JournalRead {
        records,
        state,
        valid_len: start as u64,
        torn_tail,
        head: Sha256Hex::from(chain),
        line_heads,
    })
}
