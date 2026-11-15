//! Storage layout: session dirs, quarantine roots, integrity checks, size cap, session index (M2-X-STORE).
//!
//! ENGINE_PLAN.md §7.4, §7.5, §7.8. The layout below the data root (`C:\ProgramData\Purge`, created by
//! `install/install.ps1`; the SDDL constants are shared verbatim with `install/README.md`):
//!
//! ```text
//! <data root>\                       DataRoot
//!     sessions\                      Sessions
//!         index.json                 Index        (Users: read)
//!         <session>\                 Store        journal.jsonl, plan.scan.json, report.json
//!             reg\<op>.regbackup.json, def\<op>.json
//!     Quarantine\                    Store
//!         <session>\<op>\<leaf>      Store        items moved from the data root's volume
//! X:\.purge-q\<session>\<op>\<leaf>  Store        items from another fixed NTFS/ReFS volume
//! ```
//!
//! Rules:
//! - [`StorageRoots`] is a library parameter (data root + [`IntegrityPolicy`]), never an environment
//!   variable. The relaxed policy for unelevated tests exists only under `cfg(test)` or the
//!   `test-support` feature.
//! - **Every use** re-checks the chain it touches: each directory is opened with
//!   `FILE_FLAG_OPEN_REPARSE_POINT` ([`purge_win::secure::open_for_security`]) and the reparse tag, the
//!   kind, the owner, the DACL ([`verdict`]) and the final path are read from that one handle. A child's
//!   final path must equal its checked parent's final path plus its name.
//! - A definite failure refuses the use **and** renames the object aside to
//!   `<name>.rejected-<yyyyMMddTHHmmssZ>[-n]` in the same directory, through a handle opened on the
//!   object itself (a junction is renamed as a link). Nothing is ever deleted or recursed into. A path
//!   that resolves elsewhere is only refused.
//! - Op directories are created by Purge only (create-new). `X:\.purge-q` is created with the `Store`
//!   descriptor and marked hidden, system and not content indexed; one that fails the check (a user
//!   pre-created it) is renamed aside and the volume is refused for the run ([`CannotBackUpReason`]).
//!   It is created only at a drive root ([`CannotBackUpReason::MountedFolder`]) whose DACL lets
//!   nobody but Administrators and SYSTEM rename it away or rewrite the root's DACL
//!   ([`StorageError::VolumeRoot`], [`volume_root_verdict`]).
//! - Same volume is proven by the volume serial of the source handle against the quarantine op
//!   directory's handle.
//! - The size cap is min(10 GiB, 5 % of the volume) per volume ([`check_cap`]); a run that would exceed
//!   it is refused, nothing is evicted.
//! - `sessions\index.json` is rewritten atomically: a temporary file created with the `Index`
//!   descriptor, written and flushed, then renamed over the index inside the checked `sessions`
//!   directory, which is flushed too. A crash leaves the old or the new index, never a torn one.
//! - Files are never opened by path. Every file inside the layout (the index, its temporary file,
//!   the journal, reports, backups, definitions) is created or opened with `NtCreateFile` relative
//!   to the handle of its freshly checked directory, and its facts are checked on the handle that
//!   is then used ([`StoreFile`]). Directories below a checked directory are created the same way.
//! - The index is a convenience. A missing index while session directories exist is
//!   [`StorageError::IndexLost`] (never an empty index), and an index held open by another process
//!   is [`StorageError::IndexBusy`]; see [`StorageError::is_index_unavailable`] for what may go on
//!   without it.

mod at;
mod cap;
mod integrity;
mod sys;

use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::io::{AsHandle, BorrowedHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use purge_guard::live::{StoreScope, StoreScopeError};
use purge_model::exec::op::OpId;
use purge_model::exec::session::{SessionId, SessionIndex, VolumeUsage};
use purge_win::fs::{FileHandle, FileId};
use purge_win::fs_write::{
    self, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_SYSTEM,
    FsError, MoveHandle,
};
use purge_win::secure;

pub use cap::{CAP_ABSOLUTE_BYTES, CAP_VOLUME_PERCENT, CapExceeded, cap_bytes, check_cap};
pub use integrity::{
    IntegrityFailure, IntegrityPolicy, ObjectFacts, ObjectKind, ROOT_TAKEOVER_RIGHTS,
    SDDL_DATA_ROOT, SDDL_INDEX, SDDL_SESSIONS, SDDL_STORE, SDDL_STORE_FILE, verdict,
    volume_root_verdict,
};

// The three directory names of the layout that the guard's `StoreScope` derives the session's own
// directories from. They are the guard's constants, not copies, so the store and the gate cannot
// disagree about where a session's directories are: `SESSIONS_DIR` (`sessions`) under the data root,
// `QUARANTINE_DIR` (`Quarantine`) under the data root, `VOLUME_QUARANTINE_DIR` (`.purge-q`) at the
// root of every other volume.
pub use purge_guard::live::{QUARANTINE_DIR, SESSIONS_DIR, VOLUME_QUARANTINE_DIR};
/// Name of the session index in the sessions directory.
pub const INDEX_FILE: &str = "index.json";
/// Name of the temporary file of the index's atomic rewrite, in the sessions directory.
pub const INDEX_TEMP_FILE: &str = "index.json.tmp";
/// Name of the journal in a session directory.
pub const JOURNAL_FILE: &str = "journal.jsonl";
/// Name of the copy of the executed scan document in a session directory.
pub const SCAN_FILE: &str = "plan.scan.json";
/// Name of the execute report in a session directory.
pub const REPORT_FILE: &str = "report.json";
/// Subdirectory of a session directory holding registry backups.
pub const REG_BACKUP_DIR: &str = "reg";
/// Subdirectory of a session directory holding typed definitions.
pub const DEF_DIR: &str = "def";
/// The largest index the store reads.
pub const MAX_INDEX_BYTES: u64 = 64 << 20;

/// Attributes `X:\.purge-q` carries.
const VOLUME_QUARANTINE_ATTRIBUTES: u32 =
    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
/// `ERROR_FILE_INVALID`: the object at a path is no longer the one that was checked.
const ERROR_FILE_INVALID: u32 = 1006;
/// Waits between attempts to replace an index that a reader holds open without delete sharing.
const REPLACE_RETRY_MS: [u64; 3] = [100, 300, 1000];

/// Why the store refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    /// An object of the layout failed its integrity check. It was renamed aside when the failure is
    /// definite ([`IntegrityFailure::renames_aside`]) and the rename worked.
    #[error("{} {failure}{}", .path.display(), aside_text(.renamed_to.as_deref(), .rename_error.as_ref()))]
    Integrity {
        /// The object that failed.
        path: PathBuf,
        /// Why.
        failure: IntegrityFailure,
        /// Where it was renamed to.
        renamed_to: Option<PathBuf>,
        /// Why renaming it aside failed, when it was tried and failed.
        rename_error: Option<FsError>,
    },
    /// The data root does not exist.
    #[error("the data root {} does not exist; run install.ps1", .0.display())]
    NotInstalled(PathBuf),
    /// No session directory has this id.
    #[error("session {0} does not exist")]
    SessionNotFound(SessionId),
    /// An op directory already exists; op directories are created by Purge only, never adopted.
    #[error("{} already exists; op directories are never adopted", .0.display())]
    OpDirExists(PathBuf),
    /// Items on this volume cannot be quarantined in this run; they become `CannotBackUp`.
    #[error("cannot back up items on the volume of {}: {reason}", .path.display())]
    CannotBackUp {
        /// The source path whose volume was refused.
        path: PathBuf,
        /// Why.
        reason: CannotBackUpReason,
    },
    /// A quarantine op directory is on another volume than the journal recorded.
    #[error("{} is on volume {actual:#x}, the journal recorded {expected:#x}", .path.display())]
    VolumeMismatch {
        /// The op directory.
        path: PathBuf,
        /// The recorded serial.
        expected: u64,
        /// The serial of the directory's handle.
        actual: u64,
    },
    /// The run would exceed the size cap.
    #[error(transparent)]
    Cap(Box<CapExceeded>),
    /// A file-system call failed.
    #[error("{op} {}: {source}", .path.display())]
    Io {
        /// What was being done.
        op: &'static str,
        /// On what.
        path: PathBuf,
        /// The error.
        source: FsError,
    },
    /// The session index cannot be read or did not read back as written.
    #[error("{} is not a valid session index: {detail}", .path.display())]
    IndexMalformed {
        /// The index path.
        path: PathBuf,
        /// What is wrong.
        detail: String,
    },
    /// A path or name the store does not hand out or accept.
    #[error("{0} is not a path the store accepts")]
    InvalidPath(String),
    /// The session index is held open by another process without the sharing the store needs (a
    /// backup or indexing tool, or any process that can read it: users may). The index was not
    /// changed. See [`StorageError::is_index_unavailable`].
    #[error("{} is held open by another process ({source}); the index was not changed", .path.display())]
    IndexBusy {
        /// The index path.
        path: PathBuf,
        /// The error of the last attempt.
        source: FsError,
    },
    /// The session index is missing while session directories exist: it was rejected and renamed
    /// aside, or removed. An empty index would hide every session and start the cap accounting at
    /// zero, so it is never assumed; the caller rebuilds the index from the sessions' journals and
    /// computes the cap from the directories meanwhile.
    #[error("{} is missing while sessions exist; rebuild it from the session journals", .path.display())]
    IndexLost {
        /// The index path.
        path: PathBuf,
    },
    /// A store file is larger than the reader accepts. Nothing of it was read.
    #[error("{} has {bytes} bytes, over the {max}-byte limit", .path.display())]
    TooLarge {
        /// The file.
        path: PathBuf,
        /// Its size.
        bytes: u64,
        /// The limit.
        max: u64,
    },
    /// The root of a volume would let someone other than Administrators and SYSTEM take its
    /// `.purge-q` away (rename it, or rewrite the root's DACL), or is a reparse point. Nothing was
    /// created on the volume.
    #[error("the volume root {} {failure}", .root.display())]
    VolumeRoot {
        /// The volume root.
        root: PathBuf,
        /// What is wrong with it.
        failure: IntegrityFailure,
    },
}

impl StorageError {
    /// Whether the error is about the session index only: it is busy ([`StorageError::IndexBusy`]),
    /// lost ([`StorageError::IndexLost`]) or unreadable ([`StorageError::IndexMalformed`]).
    ///
    /// Undo, crash recovery, reconcile and expiry do not need the index: they open the session
    /// directories and journals, act, and update the index afterwards when they can. A new run
    /// needs it for the size cap, so it stops with this error until the index is rebuilt (the cap
    /// may instead be computed from the quarantine directories).
    pub fn is_index_unavailable(&self) -> bool {
        matches!(
            self,
            StorageError::IndexBusy { .. }
                | StorageError::IndexLost { .. }
                | StorageError::IndexMalformed { .. }
        )
    }
}

fn aside_text(renamed_to: Option<&Path>, rename_error: Option<&FsError>) -> String {
    match (renamed_to, rename_error) {
        (Some(to), _) => format!("; renamed aside to {}", to.display()),
        (None, Some(e)) => format!("; renaming it aside failed: {e}"),
        (None, None) => String::new(),
    }
}

fn io(op: &'static str, path: &Path, source: impl Into<FsError>) -> StorageError {
    StorageError::Io {
        op,
        path: path.to_path_buf(),
        source: source.into(),
    }
}

/// Why a volume cannot hold the quarantine of a run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CannotBackUpReason {
    /// The volume is removable, remote or otherwise not a fixed drive.
    #[error("the volume is not a fixed drive")]
    NotFixed,
    /// The file system is neither NTFS nor ReFS.
    #[error("the file system is {0}, not NTFS or ReFS")]
    FileSystem(String),
    /// The source and the quarantine op directory have different volume serials.
    #[error("the source is on volume {source_serial:#x}, the quarantine on {quarantine_serial:#x}")]
    WrongVolume {
        /// Serial of the source handle.
        source_serial: u64,
        /// Serial of the quarantine op directory's handle.
        quarantine_serial: u64,
    },
    /// The volume's quarantine directory failed its check (it was renamed aside when possible) or
    /// could not be created or opened, or the volume root does not keep it safe
    /// ([`StorageError::VolumeRoot`]).
    #[error("{0}")]
    Store(Box<StorageError>),
    /// The volume is mounted in a folder, not at a drive root: its `.purge-q` would not be at the
    /// root of a drive, which the guard's store scope refuses.
    #[error("the volume is mounted in a folder, not at a drive root")]
    MountedFolder,
}

/// Facts about the volume holding a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeFacts {
    /// Mount path of the volume, e.g. `C:\` or `C:\mnt\data\`.
    pub root: PathBuf,
    /// Whether it is a fixed drive.
    pub fixed: bool,
    /// File-system name, e.g. `NTFS`.
    pub fs_name: String,
    /// Total size in bytes.
    pub total_bytes: u64,
}

impl VolumeFacts {
    /// `Ok` when the volume may hold a quarantine: a fixed NTFS or ReFS volume (gate G10).
    pub fn quarantine_capable(&self) -> Result<(), CannotBackUpReason> {
        if !self.fixed {
            return Err(CannotBackUpReason::NotFixed);
        }
        if !(self.fs_name.eq_ignore_ascii_case("NTFS") || self.fs_name.eq_ignore_ascii_case("ReFS"))
        {
            return Err(CannotBackUpReason::FileSystem(self.fs_name.clone()));
        }
        Ok(())
    }
}

/// Where volume facts come from. [`SystemVolumes`] in real use; tests substitute their own to mock
/// volume roots and sizes.
pub trait VolumeProbe: fmt::Debug + Send + Sync {
    /// The facts of the volume holding `path` (absolute).
    fn volume(&self, path: &Path) -> Result<VolumeFacts, FsError>;
}

/// The real volume facts: `GetVolumePathNameW`, `GetVolumeInformationW`, `GetDriveTypeW`,
/// `GetDiskFreeSpaceExW`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemVolumes;

impl VolumeProbe for SystemVolumes {
    fn volume(&self, path: &Path) -> Result<VolumeFacts, FsError> {
        let info = purge_win::fs::volume_info(&plain(path))?;
        let root = PathBuf::from(&info.root);
        Ok(VolumeFacts {
            total_bytes: sys::volume_total_bytes(&root)?,
            fixed: info.is_fixed(),
            fs_name: info.fs_name,
            root,
        })
    }
}

/// `path` without a `\\?\` prefix (`\\?\C:\x` becomes `C:\x`, `\\?\UNC\s\x` becomes `\\s\x`).
fn plain(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path.to_path_buf()
    }
}

/// The `\\?\` form for Win32 calls; refuses relative paths and `.`/`..` components.
fn ext(path: &Path) -> Result<PathBuf, StorageError> {
    secure::extended_path(path).map_err(|_| StorageError::InvalidPath(path.display().to_string()))
}

/// Whether two paths name the same location, ignoring a `\\?\` prefix, trailing separators and case.
fn same_path(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| {
        plain(p)
            .to_string_lossy()
            .trim_end_matches('\\')
            .to_lowercase()
    };
    norm(a) == norm(b)
}

/// Whether `root` is the root of a drive, `X:\` (with or without the `\\?\` prefix).
fn is_drive_root(root: &Path) -> bool {
    let text = plain(root).to_string_lossy().into_owned();
    let bytes = text.as_bytes();
    bytes.len() == 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
}

/// A file name Purge generates: ASCII letters, digits, `.`, `_`, `-`; not `.`/`..`, no trailing dot.
fn is_store_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.ends_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A directory of the store that passed its integrity check, with the handle it was checked through.
///
/// The handle (`READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE`, full sharing, opened on the
/// directory itself) stays valid while the value lives: a rename into the directory through
/// [`MoveHandle::rename_into`] lands in this very directory whatever happens to its path.
#[derive(Debug)]
pub struct CheckedDir {
    path: PathBuf,
    handle: FileHandle,
    id: FileId,
    final_path: String,
    attributes: u32,
}

impl CheckedDir {
    /// The path the directory was checked at (no `\\?\` prefix).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The handle the directory was checked through.
    pub fn handle(&self) -> &FileHandle {
        &self.handle
    }

    /// Volume serial and file id of the directory.
    pub fn file_id(&self) -> FileId {
        self.id
    }

    /// The 64-bit serial of the volume the directory is on (`FILE_ID_INFO`), the one source handles
    /// are compared with.
    pub fn volume_serial(&self) -> u64 {
        self.id.volume_serial
    }

    /// The final path of the handle, in `\\?\C:\...` form.
    pub fn final_path(&self) -> &str {
        &self.final_path
    }
}

impl AsHandle for CheckedDir {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.handle.as_handle()
    }
}

impl CheckedDir {
    fn as_parent(&self) -> Parent<'_> {
        Parent {
            handle: &self.handle,
            final_path: &self.final_path,
        }
    }
}

/// The directory an object is checked in: the handle the object is opened, created and renamed
/// aside relative to, and the final path the object's own final path must extend by its name.
#[derive(Debug, Clone, Copy)]
struct Parent<'a> {
    handle: &'a FileHandle,
    final_path: &'a str,
}

/// A file of the store, created or opened relative to the handle of its freshly checked directory,
/// whose facts (kind, reparse tag, link count, owner, DACL, final path) were checked on this very
/// handle.
///
/// There is no call that returns a path to open: the handle is the file. [`StoreFile::report_path`]
/// names the file for reports and messages only. Reads, writes and seeks go to the handle
/// ([`Read`], [`Write`], [`Seek`]).
#[derive(Debug)]
pub struct StoreFile {
    file: File,
    dir: CheckedDir,
    leaf: String,
    rel: String,
    id: FileId,
    len: u64,
    created: bool,
}

impl StoreFile {
    /// The session-relative name the file was created or opened by (`journal.jsonl`,
    /// `reg\000042.regbackup.json`, ...).
    pub fn rel(&self) -> &str {
        &self.rel
    }

    /// Where the file is, for reports and error messages only. Never open it by this path: the
    /// object at the path may differ from the one this handle is on.
    pub fn report_path(&self) -> PathBuf {
        self.dir.path.join(&self.leaf)
    }

    /// Volume serial and file id of the file.
    pub fn file_id(&self) -> FileId {
        self.id
    }

    /// The file's size when it was opened (0 for a file this value created).
    pub fn len_at_open(&self) -> u64 {
        self.len
    }

    /// The open file.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// The open file, for writing.
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// The open file, giving up the directory handle (no [`StoreFile::sync_dir`] afterwards).
    pub fn into_file(self) -> File {
        self.file
    }

    /// The whole file from its start, refusing one larger than `max` bytes
    /// ([`StorageError::TooLarge`]) before and while reading.
    pub fn read_all(&mut self, max: u64) -> Result<Vec<u8>, StorageError> {
        let too_large = |bytes: u64, path: PathBuf| StorageError::TooLarge { path, bytes, max };
        let size = self.size()?;
        if size > max {
            return Err(too_large(size, self.report_path()));
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| io("seek in", &self.report_path(), os_error(&e)))?;
        let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
        (&mut self.file)
            .take(max.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| io("read", &self.report_path(), os_error(&e)))?;
        let read = bytes.len() as u64;
        if read > max {
            return Err(too_large(read, self.report_path()));
        }
        Ok(bytes)
    }

    /// The file's current size, read from the handle.
    pub fn size(&self) -> Result<u64, StorageError> {
        Ok(at::facts(&self.file)
            .map_err(|e| io("read the size of", &self.report_path(), e))?
            .size)
    }

    /// Flushes the file to disk (`FlushFileBuffers`); needs a handle with write access (a created
    /// file).
    pub fn sync(&self) -> Result<(), StorageError> {
        fs_write::flush(&self.file).map_err(|e| io("flush", &self.report_path(), e))
    }

    /// Flushes the directory the file was created in, through that directory's checked handle, so
    /// that the file's creation is durable.
    pub fn sync_dir(&self) -> Result<(), StorageError> {
        at::flush_dir_at(&self.dir.handle).map_err(|e| io("flush", &self.dir.path, e))
    }

    /// Deletes a file this value created (it holds no verified content), through its own handle;
    /// the name goes when the handle closes, here. A file that was opened, not created, is refused.
    pub fn discard(self) -> Result<(), StorageError> {
        if !self.created {
            return Err(io("discard", &self.report_path(), FsError::WrongKind));
        }
        at::dispose(&self.file).map_err(|e| io("delete", &self.report_path(), e))
    }
}

impl Read for StoreFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for StoreFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Seek for StoreFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}

impl AsHandle for StoreFile {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.file.as_handle()
    }
}

/// How a session file is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileMode {
    /// Read; others may read meanwhile, nobody may write or delete it.
    Read,
    /// Read while a writer may hold the file (the journal): others may read, write and delete.
    ReadShared,
    /// Read and write; others may only read meanwhile, so a second writer is excluded.
    Append,
}

impl FileMode {
    fn open(self) -> at::Open<'static> {
        let (access, share) = match self {
            FileMode::Read => (at::GENERIC_READ, at::SHARE_READ),
            FileMode::ReadShared => (at::GENERIC_READ, at::SHARE_ALL),
            FileMode::Append => (at::GENERIC_READ | at::GENERIC_WRITE, at::SHARE_READ),
        };
        at::Open {
            access: access | at::READ_CONTROL,
            share,
            create: None,
            kind: at::Kind::File,
        }
    }
}

/// Which quarantine root an op directory is under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineRoot {
    /// `<data root>\Quarantine`, for items on the data root's volume.
    DataRoot,
    /// `<volume root>\.purge-q`, for items on another fixed NTFS or ReFS volume.
    Volume {
        /// The volume root, e.g. `D:\`.
        root: PathBuf,
    },
}

/// A checked quarantine op directory, `<quarantine root>\<session>\<op>`, on the volume of the items it
/// receives.
#[derive(Debug)]
pub struct QuarantineDir {
    dir: CheckedDir,
    root: QuarantineRoot,
}

impl QuarantineDir {
    /// The checked op directory.
    pub fn dir(&self) -> &CheckedDir {
        &self.dir
    }

    /// The quarantine root it is under.
    pub fn root(&self) -> &QuarantineRoot {
        &self.root
    }

    /// The path of the op directory.
    pub fn path(&self) -> &Path {
        &self.dir.path
    }

    /// The path an item named `leaf` has inside the op directory (what `Inverse::MoveBack` records as
    /// the quarantine path).
    pub fn item_path(&self, leaf: &str) -> PathBuf {
        self.dir.path.join(leaf)
    }

    /// The serial of the volume the op directory is on.
    pub fn volume_serial(&self) -> u64 {
        self.dir.volume_serial()
    }

    /// Opens what sits at `leaf` in the op directory, relative to the directory's checked handle (one
    /// name component, a reparse point at the name opened itself, never followed), for reconcile, undo
    /// and expiry to read its identity and, when it could be opened for it, rename it by that very
    /// handle ([`QuarantinedItem::mover`]). `Ok(None)` when nothing has the name.
    ///
    /// The handle asks for `DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL`, then without
    /// `READ_CONTROL` when that is denied; when the object cannot be opened with `DELETE` (in use
    /// without delete sharing, or denied) a read-only handle (`FILE_READ_ATTRIBUTES`) is used for the
    /// facts and there is no mover. The handle's final path must be the op directory's plus `leaf`
    /// ([`IntegrityFailure::FinalPathMismatch`], nothing renamed). The object is not checked as a
    /// store object: it is the user's item (or whatever else is there), not Purge's file.
    pub fn open_item(&self, leaf: &str) -> Result<Option<QuarantinedItem>, StorageError> {
        let path = self.item_path(leaf);
        // An empty name would reopen the op directory itself.
        if !at::plain_leaf(leaf) {
            return Err(StorageError::InvalidPath(path.display().to_string()));
        }
        let open = |access: u32| {
            at::open_at(
                &self.dir.handle,
                leaf,
                at::Open {
                    access,
                    share: at::SHARE_ALL,
                    create: None,
                    kind: at::Kind::File,
                },
            )
        };
        let mover_access = at::DELETE | at::FILE_READ_ATTRIBUTES;
        let opened = match open(mover_access | at::READ_CONTROL) {
            Ok(handle) => Ok((handle, Some(true))),
            Err(FsError::AccessDenied) => match open(mover_access) {
                Ok(handle) => Ok((handle, Some(false))),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        };
        let (handle, read_control) = match opened {
            Ok(found) => found,
            Err(FsError::NotFound) => return Ok(None),
            Err(FsError::AccessDenied | FsError::SharingViolation) => {
                match open(at::FILE_READ_ATTRIBUTES) {
                    Ok(handle) => (handle, None),
                    Err(FsError::NotFound) => return Ok(None),
                    Err(e) => return Err(io("open", &path, e)),
                }
            }
            Err(e) => return Err(io("open", &path, e)),
        };
        let facts = at::facts(&handle).map_err(|e| io("read the attributes of", &path, e))?;
        let final_path =
            at::final_path(&handle).map_err(|e| io("read the final path of", &path, e))?;
        let expected = format!(r"{}\{leaf}", self.dir.final_path.trim_end_matches('\\'));
        if !same_path(Path::new(&expected), Path::new(&final_path)) {
            return Err(StorageError::Integrity {
                path,
                failure: IntegrityFailure::FinalPathMismatch {
                    expected,
                    actual: final_path,
                },
                renamed_to: None,
                rename_error: None,
            });
        }
        let mover =
            read_control.map(|read_control| MoveHandle::from_owned_handle(handle, read_control));
        Ok(Some(QuarantinedItem {
            leaf: leaf.to_owned(),
            file_id: facts.file_id,
            is_dir: facts.is_dir,
            reparse_tag: facts.reparse_tag,
            n_links: facts.n_links,
            size: facts.size,
            final_path,
            mover,
        }))
    }
}

/// What [`QuarantineDir::open_item`] found at a name inside a quarantine op directory: the facts read
/// from the handle it was opened with, and that handle when it can rename.
#[derive(Debug)]
pub struct QuarantinedItem {
    leaf: String,
    file_id: FileId,
    is_dir: bool,
    reparse_tag: u32,
    n_links: u32,
    size: u64,
    final_path: String,
    mover: Option<MoveHandle>,
}

impl QuarantinedItem {
    /// The name inside the op directory.
    pub fn leaf(&self) -> &str {
        &self.leaf
    }

    /// Volume serial and file id, read from the handle.
    pub fn file_id(&self) -> FileId {
        self.file_id
    }

    /// Whether it is a directory.
    pub fn is_dir(&self) -> bool {
        self.is_dir
    }

    /// Its reparse tag; 0 unless it is a reparse point (which was opened itself).
    pub fn reparse_tag(&self) -> u32 {
        self.reparse_tag
    }

    /// Its hard link count.
    pub fn n_links(&self) -> u32 {
        self.n_links
    }

    /// Its size in bytes (end of file; 0 for a directory).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The handle's final path, in `\\?\C:\...` form: the op directory's plus [`QuarantinedItem::leaf`].
    pub fn final_path(&self) -> &str {
        &self.final_path
    }

    /// The handle the facts were read from, when it could be opened with `DELETE`: renaming it
    /// ([`MoveHandle::rename_into`]) moves this very object. `None` when only a read-only handle could
    /// be had (in use, or denied).
    pub fn mover(&self) -> Option<&MoveHandle> {
        self.mover.as_ref()
    }

    /// [`QuarantinedItem::mover`], by value.
    pub fn into_mover(self) -> Option<MoveHandle> {
        self.mover
    }
}

impl AsHandle for QuarantineDir {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.dir.as_handle()
    }
}

/// The kind of a session backup file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupKind {
    /// A `purge.regbackup/1` file: `reg\<op>.regbackup.json`.
    Registry,
    /// A typed definition: `def\<op>.json`.
    Definition,
}

/// The session-relative path of op `op`'s backup file of `kind`, with `\` separators, as a
/// `BackupRef` records it.
pub fn backup_rel(kind: BackupKind, op: OpId) -> String {
    match kind {
        BackupKind::Registry => format!(r"{REG_BACKUP_DIR}\{}.regbackup.json", op.file_stem()),
        BackupKind::Definition => format!(r"{DEF_DIR}\{}.json", op.file_stem()),
    }
}

/// Splits a session-relative path into an optional subdirectory (`reg` or `def`) and a file name.
fn split_rel(rel: &str) -> Result<(Option<&str>, &str), StorageError> {
    let invalid = || StorageError::InvalidPath(rel.to_owned());
    let parts: Vec<&str> = rel.split('\\').collect();
    if !parts.iter().all(|p| is_store_name(p)) {
        return Err(invalid());
    }
    match parts.as_slice() {
        // A session-level name never names one of the subdirectories: the store would check the
        // directory as a file and rename it aside.
        [leaf] if *leaf == REG_BACKUP_DIR || *leaf == DEF_DIR => Err(invalid()),
        [leaf] => Ok((None, leaf)),
        [sub, leaf] if *sub == REG_BACKUP_DIR || *sub == DEF_DIR => Ok((Some(sub), leaf)),
        _ => Err(invalid()),
    }
}

/// What a listing of the sessions directory found.
#[derive(Debug, Default)]
pub struct SessionListing {
    /// The session directories that passed their check, in id order.
    pub sessions: Vec<SessionId>,
    /// Entries named like a session that failed their check; each was renamed aside where possible.
    pub rejected: Vec<StorageError>,
}

/// Whether a missing directory is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Create {
    /// Never: a missing directory is reported as missing.
    Never,
    /// Created with the kind's descriptor when missing; an existing one is checked.
    IfAbsent,
    /// Must be created now; an existing object is never adopted.
    New,
}

/// What [`StorageRoots::inspect`] read from a passing object.
#[derive(Debug)]
struct Inspected {
    handle: FileHandle,
    facts: at::Facts,
    final_path: String,
}

/// The checked top of the layout.
#[derive(Debug)]
struct Layout {
    sessions: CheckedDir,
    quarantine: CheckedDir,
}

/// Steps of the index rewrite, for crash tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IndexStep {
    /// The temporary file is written, flushed and closed; the index is not yet replaced.
    TempWritten,
}

/// The executor's storage: the data root, the integrity policy and the volume facts source.
///
/// Cheap to clone. Every method re-checks the part of the layout it uses.
#[derive(Debug, Clone)]
pub struct StorageRoots {
    data_root: PathBuf,
    policy: IntegrityPolicy,
    volumes: Arc<dyn VolumeProbe>,
}

impl StorageRoots {
    /// Storage under `data_root` (absolute drive path, e.g. `C:\ProgramData\Purge`) with the strict
    /// policy. Nothing is opened yet.
    pub fn new(data_root: &Path) -> Result<StorageRoots, StorageError> {
        Self::with_policy(data_root, IntegrityPolicy::strict())
    }

    /// Storage at the installed location, `%ProgramData%\Purge`, with the strict policy.
    pub fn installed() -> Result<StorageRoots, StorageError> {
        let program_data = purge_win::known_folders::known_folder(
            purge_win::known_folders::KnownFolder::ProgramData,
        )
        .map_err(|e| io("locate", Path::new("%ProgramData%"), e))?;
        Self::new(&program_data.join("Purge"))
    }

    fn with_policy(
        data_root: &Path,
        policy: IntegrityPolicy,
    ) -> Result<StorageRoots, StorageError> {
        let data_root = plain(data_root);
        let text = data_root.to_string_lossy();
        if text.starts_with(r"\\") || data_root.parent().is_none() {
            return Err(StorageError::InvalidPath(text.into_owned()));
        }
        ext(&data_root)?;
        Ok(StorageRoots {
            data_root,
            policy,
            volumes: Arc::new(SystemVolumes),
        })
    }

    /// Storage under `data_root` with the relaxed test policy for the current (unelevated) user.
    /// Only under `cfg(test)` or the `test-support` feature; see [`IntegrityPolicy`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn relaxed(data_root: &Path) -> Result<StorageRoots, StorageError> {
        let me = purge_win::sid::current_user_sid()
            .map_err(|e| io("read the user SID", data_root, e))?;
        Self::with_policy(data_root, IntegrityPolicy::relaxed(me))
    }

    /// Creates a fresh tree at `data_root` the way `install.ps1` does (data root, `sessions`,
    /// `Quarantine`, `index.json` as `{}`), with the relaxed policy's descriptors, and returns relaxed
    /// storage over it. `data_root` must not exist; its parent must. Only under `cfg(test)` or the
    /// `test-support` feature.
    #[cfg(any(test, feature = "test-support"))]
    pub fn install_relaxed(data_root: &Path) -> Result<StorageRoots, StorageError> {
        let roots = Self::relaxed(data_root)?;
        if !roots.make_dir(&roots.data_root, ObjectKind::DataRoot)? {
            return Err(io("create", &roots.data_root, FsError::AlreadyExists));
        }
        roots.make_dir(&roots.sessions_path(), ObjectKind::Sessions)?;
        roots.make_dir(&roots.quarantine_path(), ObjectKind::Store)?;
        let index = roots.index_path();
        let mut file =
            fs_write::create_file_secure(&ext(&index)?, &roots.policy.sddl_for(ObjectKind::Index))
                .map_err(|e| io("create", &index, e))?;
        file.write_all(b"{}")
            .map_err(|e| io("write", &index, os_error(&e)))?;
        Ok(roots)
    }

    /// Replaces the source of volume facts (tests mock volume roots, kinds and sizes). Only under
    /// `cfg(test)` or the `test-support` feature.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_volume_probe(mut self, probe: Arc<dyn VolumeProbe>) -> StorageRoots {
        self.volumes = probe;
        self
    }

    /// The data root.
    pub fn data_root(&self) -> &Path {
        &self.data_root
    }

    /// The integrity policy.
    pub fn policy(&self) -> &IntegrityPolicy {
        &self.policy
    }

    /// `<data root>\sessions`.
    pub fn sessions_path(&self) -> PathBuf {
        self.data_root.join(SESSIONS_DIR)
    }

    /// `<data root>\Quarantine`.
    pub fn quarantine_path(&self) -> PathBuf {
        self.data_root.join(QUARANTINE_DIR)
    }

    /// `<data root>\sessions\index.json`.
    pub fn index_path(&self) -> PathBuf {
        self.sessions_path().join(INDEX_FILE)
    }

    /// The guard's [`StoreScope`] of `session` in this store, the only way the executor builds one (no
    /// caller assembles store paths by hand): `<data root>\sessions\<session>`,
    /// `<data root>\Quarantine\<session>`, and `<volume root>\.purge-q\<session>` for every volume in
    /// `volume_roots` other than the data root's.
    ///
    /// `volume_roots` are the roots of the volumes the session quarantines on, as this store reports
    /// them: [`StorageRoots::volume`]`(source).root` for the items of a run, or the `root` of the
    /// journal header's `VolumeRecord`s (the index's `VolumeUsage`s) for undo, recovery and expiry. A
    /// root naming the data root's volume adds nothing (its items go to `<data root>\Quarantine`, as
    /// [`SessionDir::create_op_dir`] puts them). A root the guard does not accept as a quarantine root
    /// (a volume mounted in a folder, whose `.purge-q` is not at the root of a drive) or a data root it
    /// does not accept is [`StorageError::InvalidPath`].
    pub fn store_scope<P: AsRef<Path>>(
        &self,
        session: &SessionId,
        volume_roots: &[P],
    ) -> Result<StoreScope, StorageError> {
        let text = |path: &Path| {
            path.to_str()
                .map(str::to_owned)
                .ok_or_else(|| StorageError::InvalidPath(path.display().to_string()))
        };
        let data_root = text(&self.data_root)?;
        let data_volume = self.volume(&self.data_root)?;
        let mut quarantine_roots = Vec::new();
        for root in volume_roots {
            let root = plain(root.as_ref());
            if same_path(&root, &data_volume.root) {
                continue;
            }
            quarantine_roots.push(text(&root.join(VOLUME_QUARANTINE_DIR))?);
        }
        StoreScope::new(&data_root, &quarantine_roots, session).map_err(|e| match e {
            StoreScopeError::DataRoot(path) | StoreScopeError::QuarantineRoot(path) => {
                StorageError::InvalidPath(path)
            }
        })
    }

    /// The facts of the volume holding `path`, from the configured [`VolumeProbe`].
    pub fn volume(&self, path: &Path) -> Result<VolumeFacts, StorageError> {
        self.volumes
            .volume(path)
            .map_err(|e| io("read the volume of", path, e))
    }

    /// Checks the data root, `sessions` and `Quarantine` (creating the last two when missing, as the
    /// installer would). A pre-flight for callers; every other method checks on its own.
    pub fn check(&self) -> Result<(), StorageError> {
        self.layout().map(|_| ())
    }

    /// Creates a new session: a fresh id (UTC now + 64 random bits) and its directory under
    /// `sessions`, created new with the `Store` descriptor. The quarantine directories of the session
    /// are created later, per volume, by [`SessionDir::create_op_dir`].
    pub fn create_session(&self) -> Result<SessionDir, StorageError> {
        let layout = self.layout()?;
        for _ in 0..8 {
            let id = SessionId::new(sys::now(), sys::random_u64());
            if let Some(dir) = self.child_dir(
                &layout.sessions,
                id.as_str(),
                ObjectKind::Store,
                Create::New,
            )? {
                return Ok(SessionDir {
                    roots: self.clone(),
                    id,
                    dir,
                });
            }
        }
        Err(io(
            "create a session directory in",
            &layout.sessions.path,
            FsError::AlreadyExists,
        ))
    }

    /// Opens an existing session after checking the data root, `sessions` and the session directory.
    pub fn open_session(&self, id: &SessionId) -> Result<SessionDir, StorageError> {
        let layout = self.layout()?;
        let dir = self
            .child_dir(
                &layout.sessions,
                id.as_str(),
                ObjectKind::Store,
                Create::Never,
            )?
            .ok_or_else(|| StorageError::SessionNotFound(id.clone()))?;
        Ok(SessionDir {
            roots: self.clone(),
            id: id.clone(),
            dir,
        })
    }

    /// Lists the session directories. Entries not named like a session id (the index, its temporary
    /// file, renamed-aside objects) are ignored; entries named like one are checked, and those that fail
    /// are renamed aside and returned in [`SessionListing::rejected`].
    pub fn list_sessions(&self) -> Result<SessionListing, StorageError> {
        let layout = self.layout()?;
        let sessions = &layout.sessions;
        let entries = purge_win::fs::list_dir(&ext(&sessions.path)?)
            .map_err(|e| io("list", &sessions.path, e))?;
        let mut listing = SessionListing::default();
        for entry in entries {
            let Ok(id) = entry.name.parse::<SessionId>() else {
                continue;
            };
            match self.child_dir(sessions, id.as_str(), ObjectKind::Store, Create::Never) {
                Ok(Some(_)) => listing.sessions.push(id),
                Ok(None) => {}
                Err(e @ StorageError::Integrity { .. }) => listing.rejected.push(e),
                Err(e) => return Err(e),
            }
        }
        listing.sessions.sort();
        Ok(listing)
    }

    /// Reads `sessions\index.json` through a handle opened relative to the checked `sessions`
    /// directory, after checking it on that handle (a file, not a reparse point, one link, admin
    /// owner, protected DACL that gives others at most read). A missing index reads as empty, like
    /// the installer's `{}`, only while no session directory exists; otherwise it is
    /// [`StorageError::IndexLost`]. An index another process holds without read sharing is
    /// [`StorageError::IndexBusy`].
    pub fn read_index(&self) -> Result<SessionIndex, StorageError> {
        let layout = self.layout()?;
        self.read_index_in(&layout.sessions)
    }

    /// Rewrites `sessions\index.json` atomically; see the module documentation. The new index keeps
    /// the `Index` descriptor (Users: read). The written bytes are read back and compared.
    pub fn write_index(&self, index: &SessionIndex) -> Result<(), StorageError> {
        self.write_index_with(index, &mut |_| Ok(()))
    }

    /// Reads the index, lets `change` edit it, writes it back, and returns what was written.
    pub fn update_index(
        &self,
        change: impl FnOnce(&mut SessionIndex),
    ) -> Result<SessionIndex, StorageError> {
        let mut index = self.read_index()?;
        change(&mut index);
        self.write_index(&index)?;
        Ok(index)
    }

    /// Checks the planned backup bytes of a run against the cap of each volume (see [`check_cap`]);
    /// each entry's `root` must be the volume root the bytes land on.
    pub fn check_cap(
        &self,
        index: &SessionIndex,
        planned: &[VolumeUsage],
    ) -> Result<(), StorageError> {
        check_cap(index, planned, |usage| {
            Ok(self.volume(Path::new(&usage.root))?.total_bytes)
        })
    }

    // ---- internals ----

    /// Checks the data root, `sessions` and `Quarantine`.
    fn layout(&self) -> Result<Layout, StorageError> {
        let root = self
            .inspect(&self.data_root, ObjectKind::DataRoot, None)?
            .ok_or_else(|| StorageError::NotInstalled(self.data_root.clone()))?;
        let root = checked(self.data_root.clone(), root);
        let sessions = self
            .child_dir(&root, SESSIONS_DIR, ObjectKind::Sessions, Create::IfAbsent)?
            .ok_or_else(|| io("open", &self.sessions_path(), FsError::NotFound))?;
        let quarantine = self
            .child_dir(&root, QUARANTINE_DIR, ObjectKind::Store, Create::IfAbsent)?
            .ok_or_else(|| io("open", &self.quarantine_path(), FsError::NotFound))?;
        Ok(Layout {
            sessions,
            quarantine,
        })
    }

    /// Creates the directory `path` with the descriptor of `kind`. `Ok(false)` when something already
    /// has the name (it is not adopted here; the caller checks it). By path: only for the data root
    /// of a test install, which has no checked parent.
    #[cfg(any(test, feature = "test-support"))]
    fn make_dir(&self, path: &Path, kind: ObjectKind) -> Result<bool, StorageError> {
        match fs_write::create_dir_secure(&ext(path)?, &self.policy.sddl_for(kind)) {
            Ok(()) => Ok(true),
            Err(FsError::AlreadyExists) => Ok(false),
            Err(e) => Err(io("create", path, e)),
        }
    }

    /// Creates the directory `leaf` in the directory behind `parent` with the descriptor of `kind`,
    /// relative to that handle. `Ok(false)` when something already has the name (it is not adopted
    /// here; the caller checks it).
    fn make_dir_at(
        &self,
        parent: &FileHandle,
        path: &Path,
        leaf: &str,
        kind: ObjectKind,
    ) -> Result<bool, StorageError> {
        let sddl = self.policy.sddl_for(kind);
        let created = at::open_at(
            parent,
            leaf,
            at::Open {
                access: at::FILE_READ_ATTRIBUTES,
                share: at::SHARE_ALL,
                create: Some(&sddl),
                kind: at::Kind::Dir,
            },
        );
        match created {
            Ok(_) => Ok(true),
            Err(FsError::AlreadyExists) => Ok(false),
            Err(e) => Err(io("create", path, e)),
        }
    }

    /// The child `leaf` of the checked directory `parent`, checked as `kind`, created per `create`.
    /// `Ok(None)` when it does not exist (and `create` is [`Create::Never`]) or, for [`Create::New`],
    /// when something that passes the check already has the name.
    fn child_dir(
        &self,
        parent: &CheckedDir,
        leaf: &str,
        kind: ObjectKind,
        create: Create,
    ) -> Result<Option<CheckedDir>, StorageError> {
        let path = parent.path.join(leaf);
        let created = match create {
            Create::Never => false,
            Create::IfAbsent | Create::New => {
                self.make_dir_at(&parent.handle, &path, leaf, kind)?
            }
        };
        // An existing object is checked even under `New`, so that a planted one is renamed aside.
        let Some(inspected) = self.inspect(&path, kind, Some(parent.as_parent()))? else {
            return Ok(None);
        };
        if create == Create::New && !created {
            return Ok(None);
        }
        Ok(Some(checked(path, inspected)))
    }

    /// Opens the directory `path` without following a final reparse point and checks it as `kind`.
    /// `Ok(None)` when nothing has the name. With `parent`, the handle's final path must equal the
    /// parent's plus the object's name, and a definite failure renames the object aside inside the
    /// parent's handle.
    fn inspect(
        &self,
        path: &Path,
        kind: ObjectKind,
        parent: Option<Parent<'_>>,
    ) -> Result<Option<Inspected>, StorageError> {
        let handle = match secure::open_for_security(&ext(path)?) {
            Ok(h) => h,
            Err(e) if e.is_not_found() => return Ok(None),
            Err(e) => return Err(io("open", path, e)),
        };
        let (facts, final_path) = self.verify(path, kind, parent, &handle)?;
        Ok(Some(Inspected {
            handle,
            facts,
            final_path,
        }))
    }

    /// Reads the facts of the object behind `handle` (opened at `path`, with `READ_CONTROL`) and
    /// checks them as `kind`: final path below `parent`, then [`verdict`]. A definite failure
    /// renames the object aside.
    fn verify(
        &self,
        path: &Path,
        kind: ObjectKind,
        parent: Option<Parent<'_>>,
        handle: &impl AsHandle,
    ) -> Result<(at::Facts, String), StorageError> {
        match self.check_handle(path, kind, parent, handle)? {
            Ok(checked) => Ok(checked),
            Err((failure, id)) => Err(reject(path, parent, Some(id), failure)),
        }
    }

    /// [`StorageRoots::verify`] without the rename: a verdict failure is returned with the identity
    /// it was read on, so that the caller can first close a handle that does not share delete
    /// access (a file handle of the store) and then call [`reject`].
    #[allow(clippy::type_complexity)]
    fn check_handle(
        &self,
        path: &Path,
        kind: ObjectKind,
        parent: Option<Parent<'_>>,
        handle: &impl AsHandle,
    ) -> Result<Result<(at::Facts, String), (IntegrityFailure, FileId)>, StorageError> {
        let facts = at::facts(handle).map_err(|e| io("read the attributes of", path, e))?;
        let final_path =
            at::final_path(handle).map_err(|e| io("read the final path of", path, e))?;
        if let Some(parent) = parent {
            let leaf = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let expected = format!(r"{}\{leaf}", parent.final_path.trim_end_matches('\\'));
            if !same_path(Path::new(&expected), Path::new(&final_path)) {
                return Err(StorageError::Integrity {
                    path: path.to_path_buf(),
                    failure: IntegrityFailure::FinalPathMismatch {
                        expected,
                        actual: final_path,
                    },
                    renamed_to: None,
                    rename_error: None,
                });
            }
        }
        // The descriptor of a reparse point is irrelevant: the tag alone refuses it.
        let security = if facts.reparse_tag == 0 {
            Some(secure::handle_security(handle).map_err(|e| io("read the security of", path, e))?)
        } else {
            None
        };
        let object = ObjectFacts {
            reparse_tag: facts.reparse_tag,
            is_dir: facts.is_dir,
            n_links: facts.n_links,
            owner: security.as_ref().and_then(|s| s.owner.clone()),
            dacl_protected: security.as_ref().is_some_and(|s| s.dacl_protected),
            dacl: security.and_then(|s| s.dacl),
        };
        if let Err(failure) = verdict(&self.policy, kind, &object) {
            return Ok(Err((failure, facts.file_id)));
        }
        Ok(Ok((facts, final_path)))
    }

    /// Checks the store file `handle` (opened or created as `leaf` of `dir`) as `kind`. On a
    /// definite failure the handle is closed first, because it does not share delete access, and
    /// the file is then renamed aside if it is still the object checked.
    fn verify_file(
        &self,
        dir: &CheckedDir,
        path: &Path,
        kind: ObjectKind,
        handle: OwnedHandle,
    ) -> Result<(File, at::Facts), StorageError> {
        match self.check_handle(path, kind, Some(dir.as_parent()), &handle)? {
            Ok((facts, _)) => Ok((File::from(handle), facts)),
            Err((failure, id)) => {
                drop(handle);
                Err(reject(path, Some(dir.as_parent()), Some(id), failure))
            }
        }
    }

    /// Opens the existing file `leaf` of the checked directory `dir` relative to its handle with
    /// `how`, and checks it as `kind` on that handle. `Ok(None)` when nothing has the name.
    fn open_file_at(
        &self,
        dir: &CheckedDir,
        leaf: &str,
        kind: ObjectKind,
        how: at::Open<'_>,
    ) -> Result<Option<(File, at::Facts)>, StorageError> {
        let path = dir.path.join(leaf);
        let handle = match at::open_at(&dir.handle, leaf, how) {
            Ok(h) => h,
            Err(FsError::NotFound) => return Ok(None),
            Err(e) => return Err(io("open", &path, e)),
        };
        self.verify_file(dir, &path, kind, handle).map(Some)
    }

    /// Creates the file `leaf` new in the checked directory `dir`, relative to its handle, with the
    /// descriptor of `kind`, open for reading, writing and deleting (others may read), and checks
    /// it as `kind` on that handle.
    fn create_file_at(
        &self,
        dir: &CheckedDir,
        leaf: &str,
        kind: ObjectKind,
    ) -> Result<(File, at::Facts), StorageError> {
        let path = dir.path.join(leaf);
        let sddl = self.policy.sddl_for(kind);
        let handle = at::open_at(
            &dir.handle,
            leaf,
            at::Open {
                access: at::GENERIC_READ | at::GENERIC_WRITE | at::DELETE | at::READ_CONTROL,
                share: at::SHARE_READ,
                create: Some(&sddl),
                kind: at::Kind::File,
            },
        )
        .map_err(|e| io("create", &path, e))?;
        self.verify_file(dir, &path, kind, handle)
    }

    /// The root of a volume other than the data root's, opened without following a reparse point.
    /// With `for_create`, it must keep a `.purge-q` safe: not a reparse point, and nobody but
    /// Administrators and SYSTEM may take a child away or rewrite its DACL
    /// ([`volume_root_verdict`]).
    fn volume_root(
        &self,
        root: &Path,
        for_create: bool,
    ) -> Result<(FileHandle, String), StorageError> {
        let handle = secure::open_for_security(&ext(root)?).map_err(|e| io("open", root, e))?;
        let facts = at::facts(&handle).map_err(|e| io("read the attributes of", root, e))?;
        let refuse = |failure| StorageError::VolumeRoot {
            root: root.to_path_buf(),
            failure,
        };
        if facts.reparse_tag != 0 {
            return Err(refuse(IntegrityFailure::ReparsePoint {
                tag: facts.reparse_tag,
            }));
        }
        if for_create {
            let security = secure::handle_security(&handle)
                .map_err(|e| io("read the security of", root, e))?;
            volume_root_verdict(
                &self.policy,
                security.owner.as_deref(),
                security.dacl.as_deref(),
            )
            .map_err(refuse)?;
        }
        let final_path =
            at::final_path(&handle).map_err(|e| io("read the final path of", root, e))?;
        Ok((handle, final_path))
    }

    /// `<volume root>\.purge-q`, created when missing (and `create`), marked hidden, system and not
    /// content indexed, and checked: its final path must be the root's plus its name. Errors are the
    /// volume's, not the run's.
    fn volume_quarantine(&self, root: &Path, create: bool) -> Result<CheckedDir, StorageError> {
        let path = root.join(VOLUME_QUARANTINE_DIR);
        let (root_handle, root_final) = self.volume_root(root, create)?;
        if create {
            self.make_dir_at(
                &root_handle,
                &path,
                VOLUME_QUARANTINE_DIR,
                ObjectKind::Store,
            )?;
        }
        let parent = Parent {
            handle: &root_handle,
            final_path: &root_final,
        };
        let inspected = self
            .inspect(&path, ObjectKind::Store, Some(parent))?
            .ok_or_else(|| io("open", &path, FsError::NotFound))?;
        let dir = checked(path, inspected);
        if dir.attributes & VOLUME_QUARANTINE_ATTRIBUTES != VOLUME_QUARANTINE_ATTRIBUTES {
            let mover = MoveHandle::open_with_attribute_write(&ext(&dir.path)?)
                .map_err(|e| io("open for attributes", &dir.path, e))?;
            if mover
                .file_id()
                .map_err(|e| io("read the id of", &dir.path, e))?
                != dir.id
            {
                return Err(reject(
                    &dir.path,
                    Some(parent),
                    None,
                    IntegrityFailure::IdentityChanged,
                ));
            }
            mover
                .set_attributes(VOLUME_QUARANTINE_ATTRIBUTES, 0)
                .map_err(|e| io("set the attributes of", &dir.path, e))?;
        }
        Ok(dir)
    }

    /// The bytes of the index, read through a handle opened relative to `sessions` and checked;
    /// `Ok(None)` when there is no index.
    fn read_index_bytes(&self, sessions: &CheckedDir) -> Result<Option<Vec<u8>>, StorageError> {
        let path = sessions.path.join(INDEX_FILE);
        let opened = self.open_file_at(
            sessions,
            INDEX_FILE,
            ObjectKind::Index,
            at::Open {
                access: at::GENERIC_READ | at::READ_CONTROL,
                share: at::SHARE_ALL,
                create: None,
                kind: at::Kind::File,
            },
        );
        let (file, facts) = match opened {
            Ok(Some(found)) => found,
            Ok(None) => return Ok(None),
            Err(StorageError::Io {
                source: source @ (FsError::SharingViolation | FsError::AccessDenied),
                ..
            }) => return Err(StorageError::IndexBusy { path, source }),
            Err(e) => return Err(e),
        };
        if facts.size > MAX_INDEX_BYTES {
            return Err(StorageError::IndexMalformed {
                path,
                detail: format!(
                    "{} bytes, over the {MAX_INDEX_BYTES}-byte limit",
                    facts.size
                ),
            });
        }
        let mut bytes = Vec::new();
        file.take(MAX_INDEX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| io("read", &path, os_error(&e)))?;
        Ok(Some(bytes))
    }

    fn read_index_in(&self, sessions: &CheckedDir) -> Result<SessionIndex, StorageError> {
        let path = sessions.path.join(INDEX_FILE);
        match self.read_index_bytes(sessions)? {
            Some(bytes) => parse_index(&path, &bytes),
            None if self.has_session_dirs(sessions)? => Err(StorageError::IndexLost { path }),
            None => Ok(SessionIndex::default()),
        }
    }

    /// Whether anything in `sessions` is named like a session (checked or not: a lost index is
    /// reported, never replaced by an empty one, while anything could be a session).
    fn has_session_dirs(&self, sessions: &CheckedDir) -> Result<bool, StorageError> {
        let entries = purge_win::fs::list_dir(&ext(&sessions.path)?)
            .map_err(|e| io("list", &sessions.path, e))?;
        Ok(entries
            .iter()
            .any(|entry| entry.name.parse::<SessionId>().is_ok()))
    }

    fn write_index_with(
        &self,
        index: &SessionIndex,
        hook: &mut dyn FnMut(IndexStep) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        let layout = self.layout()?;
        let sessions = &layout.sessions;
        let dest = sessions.path.join(INDEX_FILE);
        let temp = sessions.path.join(INDEX_TEMP_FILE);
        let inspect_only = at::Open {
            access: at::READ_CONTROL | at::FILE_READ_ATTRIBUTES,
            share: at::SHARE_ALL,
            create: None,
            kind: at::Kind::File,
        };
        // The index being replaced must pass its own check: a planted object is refused and renamed
        // aside, never silently replaced.
        self.open_file_at(sessions, INDEX_FILE, ObjectKind::Index, inspect_only)?;
        // A temporary file left by a crash is Purge's own (it passed the Index check): remove it,
        // through the handle that was checked.
        let stale = at::Open {
            access: at::DELETE | at::READ_CONTROL | at::FILE_READ_ATTRIBUTES,
            ..inspect_only
        };
        if let Some((stale, _)) =
            self.open_file_at(sessions, INDEX_TEMP_FILE, ObjectKind::Index, stale)?
        {
            at::dispose(&stale).map_err(|e| io("delete", &temp, e))?;
        }

        let bytes = serde_json::to_vec(index).map_err(|e| StorageError::IndexMalformed {
            path: dest.clone(),
            detail: e.to_string(),
        })?;
        let (mut file, _) = self.create_file_at(sessions, INDEX_TEMP_FILE, ObjectKind::Index)?;
        file.write_all(&bytes)
            .map_err(|e| io("write", &temp, os_error(&e)))?;
        fs_write::flush(&file).map_err(|e| io("flush", &temp, e))?;
        crate::fault::point("index.write");
        hook(IndexStep::TempWritten)?;

        replace_index(&file, sessions, &dest)?;
        drop(file);
        at::flush_dir_at(&sessions.handle).map_err(|e| io("flush", &sessions.path, e))?;

        // Read back through the check: the replaced index must be the bytes just written.
        if self.read_index_bytes(sessions)?.as_deref() != Some(bytes.as_slice()) {
            return Err(StorageError::IndexMalformed {
                path: dest,
                detail: "the index did not read back as written".into(),
            });
        }
        Ok(())
    }
}

/// A checked directory from what [`StorageRoots::inspect`] read.
fn checked(path: PathBuf, inspected: Inspected) -> CheckedDir {
    CheckedDir {
        path,
        id: inspected.facts.file_id,
        attributes: inspected.facts.attributes,
        handle: inspected.handle,
        final_path: inspected.final_path,
    }
}

/// The Win32 error behind an I/O error, as an [`FsError`].
fn os_error(e: &std::io::Error) -> FsError {
    e.raw_os_error()
        .and_then(|c| u32::try_from(c).ok())
        .map_or(FsError::Other(0), |c| {
            FsError::from(purge_win::os::Win32Error(c))
        })
}

/// The error for an object that failed its check, renaming it aside when the failure is definite.
/// `checked_id` is the identity the check read; the rename happens only on that same object, inside
/// `parent` when given.
fn reject(
    path: &Path,
    parent: Option<Parent<'_>>,
    checked_id: Option<FileId>,
    failure: IntegrityFailure,
) -> StorageError {
    let (mut renamed_to, mut rename_error) = (None, None);
    if let (true, Some(id)) = (failure.renames_aside(), checked_id) {
        match rename_aside(path, parent, id) {
            Ok(to) => renamed_to = Some(to),
            Err(e) => rename_error = Some(e),
        }
    }
    StorageError::Integrity {
        path: path.to_path_buf(),
        failure,
        renamed_to,
        rename_error,
    }
}

/// Renames the object at `path` to `<name>.rejected-<utc>[-n]` in its directory, after checking it is
/// still the object with file id `id`. The object is opened (itself, not followed) and renamed
/// relative to the handle of `parent`; without one (the data root, whose parent the store does not
/// check), relative to a handle on the parent directory opened for the purpose.
fn rename_aside(path: &Path, parent: Option<Parent<'_>>, id: FileId) -> Result<PathBuf, FsError> {
    let (Some(parent_path), Some(leaf)) = (path.parent(), path.file_name()) else {
        return Err(FsError::Other(87));
    };
    let leaf = leaf.to_string_lossy();
    let opened;
    let dir = match parent {
        Some(parent) => parent.handle,
        None => {
            opened = secure::open_for_security(&secure::extended_path(parent_path)?)?;
            &opened
        }
    };
    let mover = at::open_at(
        dir,
        &leaf,
        at::Open {
            access: at::DELETE | at::FILE_READ_ATTRIBUTES,
            share: at::SHARE_ALL,
            create: None,
            kind: at::Kind::File,
        },
    )?;
    if at::facts(&mover)?.file_id != id {
        return Err(FsError::Other(ERROR_FILE_INVALID));
    }
    let stamp = SessionId::new(sys::now(), 0);
    let stamp = &stamp.as_str()[..16];
    for n in 1..=64 {
        let name = if n == 1 {
            format!("{leaf}.rejected-{stamp}")
        } else {
            format!("{leaf}.rejected-{stamp}-{n}")
        };
        match at::rename_at(&mover, dir, &name, false) {
            Ok(()) => return Ok(parent_path.join(&name)),
            Err(FsError::AlreadyExists) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(FsError::AlreadyExists)
}

fn parse_index(path: &Path, bytes: &[u8]) -> Result<SessionIndex, StorageError> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    serde_json::from_slice(bytes).map_err(|e| StorageError::IndexMalformed {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })
}

/// Renames the written temporary index `temp` (open with `DELETE`) over the index inside the
/// checked `sessions` directory, replacing it, through the two handles. Retries while another
/// process holds the index open without delete sharing; then [`StorageError::IndexBusy`].
fn replace_index(temp: &File, sessions: &CheckedDir, dest: &Path) -> Result<(), StorageError> {
    let mut waits = REPLACE_RETRY_MS.iter();
    loop {
        match at::rename_at(temp, &sessions.handle, INDEX_FILE, true) {
            Ok(()) => return Ok(()),
            Err(e @ (FsError::SharingViolation | FsError::AccessDenied)) => match waits.next() {
                Some(&ms) => std::thread::sleep(Duration::from_millis(ms)),
                None => {
                    return Err(StorageError::IndexBusy {
                        path: dest.to_path_buf(),
                        source: e,
                    });
                }
            },
            Err(e) => return Err(io("replace", dest, e)),
        }
    }
}

/// One session's storage: its checked directory under `sessions`, and its quarantine directories.
///
/// Every method re-checks the chain from the data root and that the session directory is still the
/// one opened.
#[derive(Debug)]
pub struct SessionDir {
    roots: StorageRoots,
    id: SessionId,
    dir: CheckedDir,
}

impl SessionDir {
    /// The session id.
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// The storage the session belongs to.
    pub fn roots(&self) -> &StorageRoots {
        &self.roots
    }

    /// `<data root>\sessions\<session>`.
    pub fn path(&self) -> &Path {
        &self.dir.path
    }

    /// The session directory as checked when the session was created or opened.
    pub fn dir(&self) -> &CheckedDir {
        &self.dir
    }

    /// Re-checks the data root, `sessions` and the session directory, and that the directory is
    /// still the object opened first. Returns the freshly checked directory.
    pub fn recheck(&self) -> Result<CheckedDir, StorageError> {
        let layout = self.roots.layout()?;
        let dir = self
            .roots
            .child_dir(
                &layout.sessions,
                self.id.as_str(),
                ObjectKind::Store,
                Create::Never,
            )?
            .ok_or_else(|| StorageError::SessionNotFound(self.id.clone()))?;
        if dir.id != self.dir.id {
            return Err(reject(
                &dir.path,
                Some(layout.sessions.as_parent()),
                None,
                IntegrityFailure::IdentityChanged,
            ));
        }
        Ok(dir)
    }

    /// The checked directory a session-relative file lives in, created when `create`.
    fn parent_of(&self, sub: Option<&str>, create: bool) -> Result<CheckedDir, StorageError> {
        let session = self.recheck()?;
        let Some(sub) = sub else {
            return Ok(session);
        };
        let mode = if create {
            Create::IfAbsent
        } else {
            Create::Never
        };
        self.roots
            .child_dir(&session, sub, ObjectKind::Store, mode)?
            .ok_or_else(|| io("open", &session.path.join(sub), FsError::NotFound))
    }

    /// Creates the session file `rel` (`journal.jsonl`, `report.json`, `reg\000042.regbackup.json`,
    /// ...; see [`backup_rel`]) with the admin-only file descriptor, create-new, after re-checking the
    /// chain (and creating `reg` or `def` when needed, relative to the session directory's handle).
    ///
    /// The file is created relative to the handle of its checked directory and checked on the
    /// handle returned, which is open for reading, writing and deleting ([`StoreFile::discard`]);
    /// others may only read it meanwhile. Fails with [`FsError::AlreadyExists`] when anything has
    /// the name (nothing existing is opened or truncated).
    pub fn create_file(&self, rel: &str) -> Result<StoreFile, StorageError> {
        let (sub, leaf) = split_rel(rel)?;
        let dir = self.parent_of(sub, true)?;
        let (file, facts) = self
            .roots
            .create_file_at(&dir, leaf, ObjectKind::StoreFile)?;
        Ok(StoreFile {
            file,
            leaf: leaf.to_owned(),
            rel: rel.to_owned(),
            id: facts.file_id,
            len: facts.size,
            created: true,
            dir,
        })
    }

    /// Opens the existing session file `rel` for reading, after re-checking the chain, and checks
    /// the file itself on the handle returned (a file, not a reparse point, one link, admin owner, no
    /// access for others, final path inside its checked directory). Others may read it meanwhile but
    /// not write or delete it. A file that fails is renamed aside ([`StorageError::Integrity`]); a
    /// missing one is [`StorageError::Io`] with [`FsError::NotFound`].
    pub fn open_file(&self, rel: &str) -> Result<StoreFile, StorageError> {
        self.open_file_with(rel, FileMode::Read)
    }

    /// [`SessionDir::open_file`] with another access and share mode (the journal's reader and
    /// appender).
    pub(crate) fn open_file_with(
        &self,
        rel: &str,
        mode: FileMode,
    ) -> Result<StoreFile, StorageError> {
        let (sub, leaf) = split_rel(rel)?;
        let dir = self.parent_of(sub, false)?;
        let (file, facts) = self
            .roots
            .open_file_at(&dir, leaf, ObjectKind::StoreFile, mode.open())?
            .ok_or_else(|| io("open", &dir.path.join(leaf), FsError::NotFound))?;
        Ok(StoreFile {
            file,
            leaf: leaf.to_owned(),
            rel: rel.to_owned(),
            id: facts.file_id,
            len: facts.size,
            created: false,
            dir,
        })
    }

    /// Creates the quarantine op directory for op `op`, for an item at `source_path` whose handle
    /// reports volume serial `source_serial`.
    ///
    /// The source volume must be fixed NTFS or ReFS. On the data root's volume the directory is
    /// `<data root>\Quarantine\<session>\<op>`; on any other volume it is
    /// `<volume root>\.purge-q\<session>\<op>`, with `.purge-q` created when missing. Every directory
    /// on the way is checked; the op directory is created new (an existing one is never adopted:
    /// [`StorageError::OpDirExists`], or renamed aside if it fails the check). The op directory's
    /// handle must report `source_serial`, else [`CannotBackUpReason::WrongVolume`].
    ///
    /// Every failure that concerns only the source's volume is [`StorageError::CannotBackUp`]: the
    /// caller skips the item and goes on.
    pub fn create_op_dir(
        &self,
        source_path: &Path,
        source_serial: u64,
        op: OpId,
    ) -> Result<QuarantineDir, StorageError> {
        let cannot = |reason: CannotBackUpReason| StorageError::CannotBackUp {
            path: source_path.to_path_buf(),
            reason,
        };
        let roots = &self.roots;
        let volume = roots
            .volume(source_path)
            .map_err(|e| cannot(CannotBackUpReason::Store(Box::new(e))))?;
        volume.quarantine_capable().map_err(cannot)?;
        let data_volume = roots.volume(&roots.data_root)?;
        let stem = op.file_stem();

        let (dir, root) = if same_path(&volume.root, &data_volume.root) {
            let layout = roots.layout()?;
            let session = roots
                .child_dir(
                    &layout.quarantine,
                    self.id.as_str(),
                    ObjectKind::Store,
                    Create::IfAbsent,
                )?
                .ok_or_else(|| {
                    io(
                        "open",
                        &layout.quarantine.path.join(self.id.as_str()),
                        FsError::NotFound,
                    )
                })?;
            let dir = roots.child_dir(&session, &stem, ObjectKind::Store, Create::New)?;
            (
                dir.ok_or_else(|| StorageError::OpDirExists(session.path.join(&stem)))?,
                QuarantineRoot::DataRoot,
            )
        } else {
            // The guard's store scope accepts `.purge-q` only at a drive root. The relaxed test
            // policy accepts folders, because the tests' mocked volumes are folders.
            if roots.policy.is_strict() && !is_drive_root(&volume.root) {
                return Err(cannot(CannotBackUpReason::MountedFolder));
            }
            let on_volume = || -> Result<CheckedDir, StorageError> {
                let top = roots.volume_quarantine(&volume.root, true)?;
                let session = roots
                    .child_dir(&top, self.id.as_str(), ObjectKind::Store, Create::IfAbsent)?
                    .ok_or_else(|| {
                        io("open", &top.path.join(self.id.as_str()), FsError::NotFound)
                    })?;
                roots
                    .child_dir(&session, &stem, ObjectKind::Store, Create::New)?
                    .ok_or_else(|| StorageError::OpDirExists(session.path.join(&stem)))
            };
            let dir = on_volume().map_err(|e| match e {
                e @ StorageError::OpDirExists(_) => e,
                e => cannot(CannotBackUpReason::Store(Box::new(e))),
            })?;
            (
                dir,
                QuarantineRoot::Volume {
                    root: volume.root.clone(),
                },
            )
        };
        if dir.volume_serial() != source_serial {
            return Err(cannot(CannotBackUpReason::WrongVolume {
                source_serial,
                quarantine_serial: dir.volume_serial(),
            }));
        }
        Ok(QuarantineDir { dir, root })
    }

    /// Opens the existing op directory of a quarantined item for undo, reconcile or expiry.
    ///
    /// `quarantine_path` is the item path the journal recorded (`Inverse::MoveBack::quarantine_path`):
    /// it must be `<quarantine root>\<this session>\<op>\<leaf>` under `<data root>\Quarantine` or a
    /// volume root's `.purge-q`. The whole chain is checked (nothing is created) and the op directory
    /// must be on `volume_serial`. Returns the checked op directory and the item's leaf name.
    pub fn open_op_dir(
        &self,
        quarantine_path: &Path,
        op: OpId,
        volume_serial: u64,
    ) -> Result<(QuarantineDir, String), StorageError> {
        let roots = &self.roots;
        let item = plain(quarantine_path);
        let invalid = || StorageError::InvalidPath(item.display().to_string());
        ext(&item)?;
        let name = |p: Option<&Path>| -> Option<String> {
            p.and_then(Path::file_name)
                .map(|n| n.to_string_lossy().into_owned())
        };
        let leaf = name(Some(&item)).ok_or_else(invalid)?;
        let op_dir = item.parent().ok_or_else(invalid)?;
        let session_dir = op_dir.parent().ok_or_else(invalid)?;
        let top = session_dir.parent().ok_or_else(invalid)?;
        if name(Some(op_dir)).as_deref() != Some(op.file_stem().as_str())
            || name(Some(session_dir)).as_deref() != Some(self.id.as_str())
        {
            return Err(invalid());
        }
        let (top_dir, root) = if same_path(top, &roots.quarantine_path()) {
            (roots.layout()?.quarantine, QuarantineRoot::DataRoot)
        } else if name(Some(top)).as_deref() == Some(VOLUME_QUARANTINE_DIR) {
            let volume_root = top.parent().ok_or_else(invalid)?;
            if !same_path(&roots.volume(volume_root)?.root, volume_root) {
                return Err(invalid());
            }
            let dir = roots.volume_quarantine(volume_root, false)?;
            (
                dir,
                QuarantineRoot::Volume {
                    root: volume_root.to_path_buf(),
                },
            )
        } else {
            return Err(invalid());
        };
        let missing = |p: &Path| io("open", p, FsError::NotFound);
        let session = roots
            .child_dir(&top_dir, self.id.as_str(), ObjectKind::Store, Create::Never)?
            .ok_or_else(|| missing(session_dir))?;
        let dir = roots
            .child_dir(&session, &op.file_stem(), ObjectKind::Store, Create::Never)?
            .ok_or_else(|| missing(op_dir))?;
        if dir.volume_serial() != volume_serial {
            return Err(StorageError::VolumeMismatch {
                path: dir.path.clone(),
                expected: volume_serial,
                actual: dir.volume_serial(),
            });
        }
        Ok((QuarantineDir { dir, root }, leaf))
    }

    /// Removes the directory of a session that never got a journal (the run failed after
    /// [`StorageRoots::create_session`] and before the journal's header was durable), by handle: the
    /// chain is re-checked, the directory is opened again relative to the checked `sessions` handle
    /// with `DELETE | FILE_LIST_DIRECTORY` and must be the directory this value checked (same file
    /// id), and it is listed through that handle. It may hold nothing, or only the scan copy
    /// ([`SCAN_FILE`], which must pass the store file check and is deleted through the handle it
    /// was checked on). Anything else is refused with [`FsError::DirNotEmpty`] and nothing is
    /// deleted; so is a directory that gains an entry before it goes. The `sessions` directory is
    /// flushed afterwards. The session never had an index entry, so none is touched.
    pub fn remove_unstarted(self) -> Result<(), StorageError> {
        let layout = self.roots.layout()?;
        let checked = self.recheck()?;
        let path = checked.path.clone();
        let handle = at::open_at(
            &layout.sessions.handle,
            self.id.as_str(),
            at::Open {
                access: at::DELETE | at::FILE_LIST_DIRECTORY | at::FILE_READ_ATTRIBUTES,
                share: at::SHARE_ALL,
                create: None,
                kind: at::Kind::Dir,
            },
        )
        .map_err(|e| io("open", &path, e))?;
        let facts = at::facts(&handle).map_err(|e| io("read the attributes of", &path, e))?;
        if facts.file_id != self.dir.id || !facts.is_dir || facts.reparse_tag != 0 {
            return Err(StorageError::Integrity {
                path,
                failure: IntegrityFailure::IdentityChanged,
                renamed_to: None,
                rename_error: None,
            });
        }
        let names = at::list_names(&handle).map_err(|e| io("list", &path, e))?;
        match names.as_slice() {
            [] => {}
            [only] if only.eq_ignore_ascii_case(SCAN_FILE) => {
                let scan = self.roots.open_file_at(
                    &checked,
                    SCAN_FILE,
                    ObjectKind::StoreFile,
                    at::Open {
                        access: at::DELETE | at::READ_CONTROL | at::FILE_READ_ATTRIBUTES,
                        share: at::SHARE_READ,
                        create: None,
                        kind: at::Kind::File,
                    },
                )?;
                if let Some((scan, _)) = scan {
                    at::dispose(&scan).map_err(|e| io("delete", &path.join(SCAN_FILE), e))?;
                }
            }
            _ => return Err(io("remove", &path, FsError::DirNotEmpty)),
        }
        // The scan copy's handle is closed: its name is gone, so the directory can be marked.
        at::dispose(&handle).map_err(|e| io("remove", &path, e))?;
        drop(handle);
        drop(checked);
        let name = self.id.as_str().to_owned();
        // Every handle on the directory is closed now; the last close removes it.
        drop(self);
        match at::open_at(
            &layout.sessions.handle,
            &name,
            at::Open {
                access: at::FILE_READ_ATTRIBUTES,
                share: at::SHARE_ALL,
                create: None,
                kind: at::Kind::Dir,
            },
        ) {
            Err(FsError::NotFound) => {}
            Ok(_) => return Err(io("remove", &path, FsError::DirNotEmpty)),
            Err(e) => return Err(io("remove", &path, e)),
        }
        at::flush_dir_at(&layout.sessions.handle).map_err(|e| io("flush", &layout.sessions.path, e))
    }

    /// Deletes the session file `rel`, which must be in `reg` or `def` ([`backup_rel`]: a registry
    /// backup or a typed definition), by handle: its directory is re-checked through the chain, the
    /// file is opened relative to that directory's checked handle with `DELETE` (others may only read
    /// it meanwhile, so a reader that does not share delete makes this fail) and must pass the store
    /// file check on that handle (a plain file, one link, admin-only; a failing object is renamed
    /// aside and nothing is deleted), and it is deleted through that handle. Returns its size, or
    /// `None` when it, or its directory, does not exist. Any other name (the journal, the scan copy,
    /// the report, a directory) is refused with [`StorageError::InvalidPath`]. Expiry's deletion of a
    /// session's backups; it writes no journal record (the caller does).
    pub fn delete_backup_file(&self, rel: &str) -> Result<Option<u64>, StorageError> {
        let (sub, leaf) = split_rel(rel)?;
        if sub.is_none() {
            return Err(StorageError::InvalidPath(rel.to_owned()));
        }
        let dir = match self.parent_of(sub, false) {
            Ok(dir) => dir,
            Err(StorageError::Io {
                source: FsError::NotFound,
                ..
            }) => return Ok(None),
            Err(e) => return Err(e),
        };
        let path = dir.path.join(leaf);
        let Some((file, facts)) = self.roots.open_file_at(
            &dir,
            leaf,
            ObjectKind::StoreFile,
            at::Open {
                access: at::DELETE | at::READ_CONTROL | at::FILE_READ_ATTRIBUTES,
                share: at::SHARE_READ,
                create: None,
                kind: at::Kind::File,
            },
        )?
        else {
            return Ok(None);
        };
        at::dispose(&file).map_err(|e| io("delete", &path, e))?;
        drop(file);
        match at::open_at(
            &dir.handle,
            leaf,
            at::Open {
                access: at::FILE_READ_ATTRIBUTES,
                share: at::SHARE_ALL,
                create: None,
                kind: at::Kind::File,
            },
        ) {
            Err(FsError::NotFound) => {}
            Ok(_) => return Err(io("delete", &path, FsError::Other(ERROR_FILE_INVALID))),
            Err(e) => return Err(io("delete", &path, e)),
        }
        at::flush_dir_at(&dir.handle).map_err(|e| io("flush", &dir.path, e))?;
        Ok(Some(facts.size))
    }
}

#[cfg(test)]
mod tests;
