//! SHA-256 helpers for backups and definition files (§7.4: the journal records the SHA-256 of every
//! backup file, and undo verifies it).

use std::io::{self, Read};

use purge_model::exec::journal::UndoConflict;
use purge_model::exec::op::{BackupRef, Sha256Hex};
use purge_win::fs_write::FsError;
use sha2::{Digest, Sha256};

use crate::storage::{SessionDir, StorageError};

/// Size of the read buffer when hashing a stream.
const CHUNK: usize = 64 * 1024;

/// SHA-256 of `data`.
pub fn sha256_bytes(data: &[u8]) -> Sha256Hex {
    Sha256Hex::from(<[u8; 32]>::from(Sha256::digest(data)))
}

/// SHA-256 of everything `reader` yields until its end, and the number of bytes read. To hash a file
/// of the store, pass the [`StoreFile`](crate::storage::StoreFile) the store opened.
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

/// Why a backup file does not match the [`BackupRef`] the journal holds for it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackupCheckError {
    /// The reference's path would leave the session directory; it is never joined or opened.
    #[error("the backup path leaves the session directory")]
    NotSessionRelative,
    /// The file does not exist.
    #[error("the backup file is missing")]
    Missing,
    /// The file could not be read.
    #[error("the backup file cannot be read: {0:?}")]
    Unreadable(io::ErrorKind),
    /// The store refused the file or its directory: a name the store does not hand out, a
    /// directory, a reparse point, a second hard link, a foreign owner or DACL (the object was
    /// renamed aside when the failure is definite), or the chain from the data root failed.
    #[error("the store refused the backup file: {0}")]
    Store(StorageError),
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

/// Checks that the backup `backup` names inside `session` exists with the recorded size and SHA-256.
/// The file is opened through the store ([`SessionDir::open_file`]: relative to its checked
/// directory's handle, checked on the handle that is then hashed). Undo must not read a backup that
/// fails this.
pub fn verify_backup(session: &SessionDir, backup: &BackupRef) -> Result<(), BackupCheckError> {
    if !backup.is_session_relative() {
        return Err(BackupCheckError::NotSessionRelative);
    }
    let mut file = session.open_file(&backup.path).map_err(|e| match e {
        StorageError::Io {
            source: FsError::NotFound,
            ..
        } => BackupCheckError::Missing,
        e => BackupCheckError::Store(e),
    })?;
    let size = file.len_at_open();
    if size != backup.bytes {
        return Err(BackupCheckError::SizeMismatch {
            expected: backup.bytes,
            actual: size,
        });
    }
    let (actual, bytes) =
        sha256_reader(&mut file).map_err(|e| BackupCheckError::Unreadable(e.kind()))?;
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
