//! Reading a journal back: framing, chain, records and rules, with the torn-tail rule.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use purge_model::exec::journal::Record;
use purge_model::exec::op::Sha256Hex;
use purge_win::fs_write::FsError;

use super::frame::{CHAIN_SEED, unframe};
use super::hash::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use super::state::{JournalState, Violation};
use super::{Corruption, JournalError};

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
}

/// Reads the journal at `path` (see [`parse`]). The file is opened without following a reparse point and
/// refused unless it is a plain file with one link; a writer may hold it open meanwhile.
pub fn read(path: &Path) -> Result<JournalRead, JournalError> {
    let mut file = open_plain(path, false)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| JournalError::Io {
            context: "reading the journal",
            source,
        })?;
    parse(&bytes)
}

/// Parses journal bytes: every `\n`-terminated line must frame, chain, parse and obey the rules; bytes
/// after the last `\n` are a torn tail and ignored. Never panics: a journal cut at any byte gives either
/// the state of its complete lines or [`JournalError::Empty`].
pub fn parse(bytes: &[u8]) -> Result<JournalRead, JournalError> {
    let mut chain = CHAIN_SEED;
    let mut records = Vec::new();
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
                Record::Header(header) => state = Some(JournalState::new(header.clone())),
                _ => return Err(corrupt(Corruption::Rule(Violation::HeaderNotFirst))),
            },
            Some(state) => state
                .apply(&record)
                .map_err(|v| corrupt(Corruption::Rule(v)))?,
        }
        records.push(record);
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
    })
}

/// Opens an existing journal without following a reparse point at its last component, and refuses
/// anything but a plain file with one link. For writing, other handles may only read meanwhile (and an
/// open by a second writer fails); for reading, a writer may hold it.
pub(super) fn open_plain(path: &Path, write: bool) -> Result<File, JournalError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(write)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(if write {
            FILE_SHARE_READ
        } else {
            FILE_SHARE_READ | FILE_SHARE_WRITE
        });
    let file = options.open(path).map_err(|source| JournalError::Io {
        context: "opening the journal",
        source,
    })?;
    let meta = file.metadata().map_err(|source| JournalError::Io {
        context: "reading the journal's metadata",
        source,
    })?;
    if !meta.is_file() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(JournalError::NotPlainFile);
    }
    // The handle above shares no delete access, so the name cannot move to another file while it is open:
    // this second open by name sees the same file.
    let facts = purge_win::fs::FileHandle::open(path)
        .and_then(|h| h.metadata())
        .map_err(|e| JournalError::Fs {
            context: "checking the journal's link count",
            source: FsError::from(e),
        })?;
    if facts.n_links != 1 || facts.reparse_tag != 0 || facts.is_dir {
        return Err(JournalError::NotPlainFile);
    }
    Ok(file)
}
