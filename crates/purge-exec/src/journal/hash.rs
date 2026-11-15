//! SHA-256 helpers for backups and definition files (§7.4: the journal records the SHA-256 of every
//! backup file, and undo verifies it).

use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use purge_model::exec::journal::UndoConflict;
use purge_model::exec::op::{BackupRef, Sha256Hex};
use sha2::{Digest, Sha256};

/// `FILE_SHARE_READ`.
pub(super) const FILE_SHARE_READ: u32 = 0x1;
/// `FILE_SHARE_WRITE`.
pub(super) const FILE_SHARE_WRITE: u32 = 0x2;
/// `FILE_FLAG_OPEN_REPARSE_POINT`: open a reparse point itself, never what it points to.
pub(super) const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
pub(super) const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// Size of the read buffer when hashing a stream.
const CHUNK: usize = 64 * 1024;

/// SHA-256 of `data`.
pub fn sha256_bytes(data: &[u8]) -> Sha256Hex {
    Sha256Hex::from(<[u8; 32]>::from(Sha256::digest(data)))
}

/// SHA-256 of everything `reader` yields until its end, and the number of bytes read.
pub fn sha256_reader<R: Read + ?Sized>(reader: &mut R) -> io::Result<(Sha256Hex, u64)> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((Sha256Hex::from(<[u8; 32]>::from(hasher.finalize())), total))
}

/// SHA-256 of the file at `path` and its size in bytes, read as a stream.
///
/// The file is opened without following a reparse point at its last component and refused
/// (`InvalidInput`) unless it is a plain file; other handles may read it meanwhile but not write it.
pub fn sha256_file(path: &Path) -> io::Result<(Sha256Hex, u64)> {
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a plain file (a directory or a reparse point)",
        ));
    }
    sha256_reader(&mut file)
}

/// Why a backup file does not match the [`BackupRef`] the journal holds for it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackupCheckError {
    /// The reference's path would leave the session directory; it is never joined or opened.
    #[error("the backup path leaves the session directory")]
    NotSessionRelative,
    /// The file does not exist.
    #[error("the backup file is missing")]
    Missing,
    /// The file could not be opened or read (including: it is a directory or a reparse point).
    #[error("the backup file cannot be read: {0:?}")]
    Unreadable(io::ErrorKind),
    /// The file has another size than recorded.
    #[error("the backup file has {actual} bytes, the journal recorded {expected}")]
    SizeMismatch {
        /// Size the journal recorded.
        expected: u64,
        /// Size found.
        actual: u64,
    },
    /// The file's SHA-256 differs from the recorded one.
    #[error("the backup file's SHA-256 is {actual}, the journal recorded {expected}")]
    HashMismatch {
        /// Hash the journal recorded.
        expected: Sha256Hex,
        /// Hash found.
        actual: Sha256Hex,
    },
}

impl BackupCheckError {
    /// The undo conflict to journal for this failure: [`UndoConflict::BackupMissing`] for a missing file,
    /// [`UndoConflict::BackupTampered`] for everything else.
    pub fn conflict(&self) -> UndoConflict {
        match self {
            BackupCheckError::Missing => UndoConflict::BackupMissing,
            _ => UndoConflict::BackupTampered,
        }
    }
}

/// Checks that the backup `backup` names inside `session_dir` exists with the recorded size and SHA-256.
/// Undo must not read a backup that fails this.
pub fn verify_backup(session_dir: &Path, backup: &BackupRef) -> Result<(), BackupCheckError> {
    if !backup.is_session_relative() {
        return Err(BackupCheckError::NotSessionRelative);
    }
    let (actual, bytes) = sha256_file(&session_dir.join(&backup.path)).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            BackupCheckError::Missing
        } else {
            BackupCheckError::Unreadable(e.kind())
        }
    })?;
    if bytes != backup.bytes {
        return Err(BackupCheckError::SizeMismatch {
            expected: backup.bytes,
            actual: bytes,
        });
    }
    if actual != backup.sha256 {
        return Err(BackupCheckError::HashMismatch {
            expected: backup.sha256,
            actual,
        });
    }
    Ok(())
}
