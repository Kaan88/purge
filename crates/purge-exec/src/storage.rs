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
//! - Same volume is proven by the volume serial of the source handle against the quarantine op
//!   directory's handle.
//! - The size cap is min(10 GiB, 5 % of the volume) per volume ([`check_cap`]); a run that would exceed
//!   it is refused, nothing is evicted.
//! - `sessions\index.json` is rewritten atomically: a temporary file created with the `Index`
//!   descriptor, written and flushed, then renamed over the index inside the checked `sessions`
//!   directory, which is flushed too. A crash leaves the old or the new index, never a torn one.

mod cap;
mod integrity;
mod sys;

use std::fmt;
use std::io::Write;
use std::os::windows::io::{AsHandle, BorrowedHandle};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use purge_model::exec::op::OpId;
use purge_model::exec::session::{SessionId, SessionIndex, VolumeUsage};
use purge_win::fs::{FileHandle, FileId, FileMeta};
use purge_win::fs_write::{
    self, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_SYSTEM,
    FsError, MoveHandle,
};
use purge_win::secure;

pub use cap::{CAP_ABSOLUTE_BYTES, CAP_VOLUME_PERCENT, CapExceeded, cap_bytes, check_cap};
pub use integrity::{
    IntegrityFailure, IntegrityPolicy, ObjectFacts, ObjectKind, SDDL_DATA_ROOT, SDDL_INDEX,
    SDDL_SESSIONS, SDDL_STORE, SDDL_STORE_FILE, verdict,
};

/// Name of the sessions directory under the data root.
pub const SESSIONS_DIR: &str = "sessions";
/// Name of the quarantine directory under the data root.
pub const QUARANTINE_DIR: &str = "Quarantine";
/// Name of the quarantine directory at the root of every other volume.
pub const VOLUME_QUARANTINE_DIR: &str = ".purge-q";
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
    /// could not be created or opened.
    #[error("{0}")]
    Store(Box<StorageError>),
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
    meta: FileMeta,
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

    /// Reads `sessions\index.json` after checking it (a file, not a reparse point, one link, admin
    /// owner, protected DACL that gives others at most read). A missing index reads as empty, like the
    /// installer's `{}`.
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
    /// has the name (it is not adopted here; the caller checks it).
    fn make_dir(&self, path: &Path, kind: ObjectKind) -> Result<bool, StorageError> {
        match fs_write::create_dir_secure(&ext(path)?, &self.policy.sddl_for(kind)) {
            Ok(()) => Ok(true),
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
            Create::IfAbsent | Create::New => self.make_dir(&path, kind)?,
        };
        // An existing object is checked even under `New`, so that a planted one is renamed aside.
        let Some(inspected) = self.inspect(&path, kind, Some(&parent.final_path))? else {
            return Ok(None);
        };
        if create == Create::New && !created {
            return Ok(None);
        }
        Ok(Some(checked(path, inspected)))
    }

    /// Opens `path` without following a final reparse point and checks it as `kind`. `Ok(None)` when
    /// nothing has the name. With `parent_final`, the handle's final path must equal it plus the
    /// object's name. A definite failure renames the object aside.
    fn inspect(
        &self,
        path: &Path,
        kind: ObjectKind,
        parent_final: Option<&str>,
    ) -> Result<Option<Inspected>, StorageError> {
        let handle = match secure::open_for_security(&ext(path)?) {
            Ok(h) => h,
            Err(e) if e.is_not_found() => return Ok(None),
            Err(e) => return Err(io("open", path, e)),
        };
        let meta = handle
            .metadata()
            .map_err(|e| io("read the attributes of", path, e))?;
        let final_path = handle
            .final_path()
            .map_err(|e| io("read the final path of", path, e))?;
        if let Some(parent_final) = parent_final {
            let leaf = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let expected = format!(r"{}\{leaf}", parent_final.trim_end_matches('\\'));
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
        let security = if meta.reparse_tag == 0 {
            Some(
                secure::handle_security(&handle)
                    .map_err(|e| io("read the security of", path, e))?,
            )
        } else {
            None
        };
        let facts = ObjectFacts {
            reparse_tag: meta.reparse_tag,
            is_dir: meta.is_dir,
            n_links: meta.n_links,
            owner: security.as_ref().and_then(|s| s.owner.clone()),
            dacl_protected: security.as_ref().is_some_and(|s| s.dacl_protected),
            dacl: security.and_then(|s| s.dacl),
        };
        if let Err(failure) = verdict(&self.policy, kind, &facts) {
            return Err(reject(path, Some(meta.file_id), failure));
        }
        Ok(Some(Inspected {
            handle,
            meta,
            final_path,
        }))
    }

    /// `<volume root>\.purge-q`, created when missing (and `create`), marked hidden, system and not
    /// content indexed, and checked. Errors are the volume's, not the run's.
    fn volume_quarantine(&self, root: &Path, create: bool) -> Result<CheckedDir, StorageError> {
        let path = root.join(VOLUME_QUARANTINE_DIR);
        if create {
            self.make_dir(&path, ObjectKind::Store)?;
        }
        let inspected = self
            .inspect(&path, ObjectKind::Store, None)?
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
                return Err(reject(&dir.path, None, IntegrityFailure::IdentityChanged));
            }
            mover
                .set_attributes(VOLUME_QUARANTINE_ATTRIBUTES, 0)
                .map_err(|e| io("set the attributes of", &dir.path, e))?;
        }
        Ok(dir)
    }

    fn read_index_in(&self, sessions: &CheckedDir) -> Result<SessionIndex, StorageError> {
        let path = sessions.path.join(INDEX_FILE);
        let Some(inspected) = self.inspect(&path, ObjectKind::Index, Some(&sessions.final_path))?
        else {
            return Ok(SessionIndex::default());
        };
        drop(inspected.handle);
        if inspected.meta.size > MAX_INDEX_BYTES {
            return Err(StorageError::IndexMalformed {
                path,
                detail: format!(
                    "{} bytes, over the {MAX_INDEX_BYTES}-byte limit",
                    inspected.meta.size
                ),
            });
        }
        let bytes = read_file(&path)?;
        parse_index(&path, &bytes)
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
        // The index being replaced must pass its own check: a planted object is refused and renamed
        // aside, never silently replaced.
        self.inspect(&dest, ObjectKind::Index, Some(&sessions.final_path))?;
        // A temporary file left by a crash is Purge's own (it passed the Index check): remove it.
        if let Some(stale) = self.inspect(&temp, ObjectKind::Index, Some(&sessions.final_path))? {
            let mover = MoveHandle::open(&ext(&temp)?).map_err(|e| io("open", &temp, e))?;
            if mover
                .file_id()
                .map_err(|e| io("read the id of", &temp, e))?
                != stale.meta.file_id
            {
                return Err(reject(&temp, None, IntegrityFailure::IdentityChanged));
            }
            mover.delete(true).map_err(|e| io("delete", &temp, e))?;
        }

        let bytes = serde_json::to_vec(index).map_err(|e| StorageError::IndexMalformed {
            path: dest.clone(),
            detail: e.to_string(),
        })?;
        let mut file =
            fs_write::create_file_secure(&ext(&temp)?, &self.policy.sddl_for(ObjectKind::Index))
                .map_err(|e| io("create", &temp, e))?;
        file.write_all(&bytes)
            .map_err(|e| io("write", &temp, os_error(&e)))?;
        fs_write::flush(&file).map_err(|e| io("flush", &temp, e))?;
        drop(file);
        hook(IndexStep::TempWritten)?;

        replace_file(&temp, &dest)?;
        fs_write::flush_dir(&ext(&sessions.path)?).map_err(|e| io("flush", &sessions.path, e))?;

        // Read back through the check: the replaced index must be the bytes just written.
        self.inspect(&dest, ObjectKind::Index, Some(&sessions.final_path))?
            .ok_or_else(|| io("open", &dest, FsError::NotFound))?;
        if read_file(&dest)? != bytes {
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
        id: inspected.meta.file_id,
        attributes: inspected.meta.attributes,
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
/// `checked_id` is the identity the check read; the rename happens only on that same object.
fn reject(path: &Path, checked_id: Option<FileId>, failure: IntegrityFailure) -> StorageError {
    let (mut renamed_to, mut rename_error) = (None, None);
    if let (true, Some(id)) = (failure.renames_aside(), checked_id) {
        match rename_aside(path, id) {
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

/// Renames the object at `path` to `<name>.rejected-<utc>[-n]` in the same directory, through a
/// handle opened on the object itself, after checking it is still the object with file id `id`.
fn rename_aside(path: &Path, id: FileId) -> Result<PathBuf, FsError> {
    let (Some(parent), Some(leaf)) = (path.parent(), path.file_name()) else {
        return Err(FsError::Other(87));
    };
    let ext_path = secure::extended_path(path)?;
    let mover = MoveHandle::open(&ext_path)?;
    if mover.file_id()? != id {
        return Err(FsError::Other(ERROR_FILE_INVALID));
    }
    let stamp = SessionId::new(sys::now(), 0);
    let stamp = &stamp.as_str()[..16];
    let leaf = leaf.to_string_lossy();
    let dir = fs_write::DestDir::open(&secure::extended_path(parent)?)?;
    for n in 1..=64 {
        let name = if n == 1 {
            format!("{leaf}.rejected-{stamp}")
        } else {
            format!("{leaf}.rejected-{stamp}-{n}")
        };
        let dest = parent.join(&name);
        match mover.rename_into(&dir, &name) {
            Ok(()) => return Ok(dest),
            Err(FsError::AlreadyExists) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(FsError::AlreadyExists)
}

/// Reads a whole store file (at most [`MAX_INDEX_BYTES`] + 1 bytes) without following a reparse
/// point.
fn read_file(path: &Path) -> Result<Vec<u8>, StorageError> {
    let max = usize::try_from(MAX_INDEX_BYTES + 1).unwrap_or(usize::MAX);
    purge_win::fs::read_bytes(&ext(path)?, max).map_err(|e| io("read", path, e))
}

fn parse_index(path: &Path, bytes: &[u8]) -> Result<SessionIndex, StorageError> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    serde_json::from_slice(bytes).map_err(|e| StorageError::IndexMalformed {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })
}

/// Renames `temp` over `dest` (replacing it), retrying while a reader holds `dest` open without
/// delete sharing.
fn replace_file(temp: &Path, dest: &Path) -> Result<(), StorageError> {
    let (from, to) = (ext(temp)?, ext(dest)?);
    let mut waits = REPLACE_RETRY_MS.iter();
    loop {
        match std::fs::rename(&from, &to) {
            Ok(()) => return Ok(()),
            Err(e) => {
                let code = os_error(&e);
                let busy = matches!(code, FsError::SharingViolation | FsError::AccessDenied);
                match waits.next() {
                    Some(&ms) if busy => std::thread::sleep(Duration::from_millis(ms)),
                    _ => return Err(io("replace", dest, code)),
                }
            }
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
            return Err(reject(&dir.path, None, IntegrityFailure::IdentityChanged));
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
    /// chain (and creating `reg` or `def` when needed). Returns its path and the file open for reading
    /// and writing.
    pub fn create_file(&self, rel: &str) -> Result<(PathBuf, std::fs::File), StorageError> {
        let (sub, leaf) = split_rel(rel)?;
        let parent = self.parent_of(sub, true)?;
        let path = parent.path.join(leaf);
        let file = fs_write::create_file_secure(
            &ext(&path)?,
            &self.roots.policy.sddl_for(ObjectKind::StoreFile),
        )
        .map_err(|e| io("create", &path, e))?;
        Ok((path, file))
    }

    /// The path of the existing session file `rel`, after re-checking the chain and the file itself
    /// (a file, not a reparse point, one link, admin owner, no access for others).
    pub fn open_file(&self, rel: &str) -> Result<PathBuf, StorageError> {
        let (sub, leaf) = split_rel(rel)?;
        let parent = self.parent_of(sub, false)?;
        let path = parent.path.join(leaf);
        self.roots
            .inspect(&path, ObjectKind::StoreFile, Some(&parent.final_path))?
            .ok_or_else(|| io("open", &path, FsError::NotFound))?;
        Ok(path)
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
}

#[cfg(test)]
mod tests;
