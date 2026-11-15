//! Handle-based file writes: rename, delete, boot-time moves (`write` feature) (M2-WIN-FS).
//!
//! ENGINE_PLAN.md §7.5 / §7.6 / §7.8. Thin and policy-free: every decision (what may be moved,
//! where to, whether a boot-time move is allowed) belongs to `purge-exec`.
//!
//! - [`MoveHandle`] opens a path with `DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES` (plus
//!   `READ_CONTROL` when the object grants it) and
//!   `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`, so the handle is on the object
//!   itself, never on what a junction or symbolic link points to. Facts (metadata, file id, final
//!   path, reparse tag, streams, security) and the action (rename, delete) use that one handle, so
//!   nothing can be swapped between the check and the act.
//! - The destination of a rename is a directory handle too: [`DestDir`] opens it without following
//!   a reparse point and reports the facts the gate judges; [`MoveHandle::rename_into`] renames into
//!   that very directory under one leaf name. There is no rename to a path, because the kernel would
//!   resolve the path again after the check and follow a junction planted in the meantime.
//! - Renames never replace an existing destination. Deletes are non-recursive.
//! - [`create_dir_secure`] and [`create_file_secure`] create a new object with a security
//!   descriptor given at creation and fail if anything already has that name.
//!   [`DestDir::create_dir`] does the same for a directory relative to a directory handle, so a
//!   path swapped for a junction after the check cannot redirect it.
//! - [`MoveHandle::set_times`] and [`MoveHandle::set_security`] put recorded timestamps and a
//!   recorded owner, group and DACL back on an object, through its handle.
//! - [`move_delay_until_reboot`], [`pending_renames`], [`remove_pending_pairs`] and
//!   [`remove_pending_pairs_exactly`] cover the boot-time move list
//!   (`PendingFileRenameOperations`). The list is never rewritten wholesale: removal cuts the
//!   exact byte ranges of the caller's own pairs and leaves every other byte as it was.
//!
//! Nothing here raises access: ownership is never taken and no privilege is enabled. The only
//! security write, [`MoveHandle::set_security`], stores a descriptor through a handle the caller's
//! token was granted `WRITE_DAC` / `WRITE_OWNER` on, and fails where the token may not. Paths are
//! turned into their `\\?\` form by [`extended_path`] and are not normalised, so long paths work
//! and names ending in a dot or a space keep their spelling. Stream syntax (a `:` after the drive,
//! as in `name::$DATA` or `dir::$INDEX_ALLOCATION`) is refused by every function that takes a path.
#![cfg(feature = "write")]

use std::mem::{offset_of, size_of};
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree, OBJ_CASE_INSENSITIVE,
    RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetSecurityDescriptorGroup, GetSecurityDescriptorOwner,
    GetSecurityDescriptorSacl, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_AUTO_INHERIT_REQ, SE_DACL_AUTO_INHERITED, SECURITY_ATTRIBUTES, SetKernelObjectSecurity,
    SetSecurityDescriptorControl,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ADD_FILE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO,
    FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_INFO_BY_HANDLE_CLASS,
    FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_ATTRIBUTES, FileAttributeTagInfo, FileBasicInfo, FileDispositionInfo,
    FileDispositionInfoEx, FileStreamInfo, FlushFileBuffers, GetFileInformationByHandleEx,
    MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
    SetFileInformationByHandle, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_MULTI_SZ,
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};

use crate::fs::{FileHandle, FileId, FileMeta};
use crate::os::{Win32Error, wide};
use crate::secure::{Security, extended_units};

pub use crate::secure::extended_path;

/// `FILE_ATTRIBUTE_READONLY`.
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
/// `FILE_ATTRIBUTE_HIDDEN`.
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
/// `FILE_ATTRIBUTE_SYSTEM`.
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
/// `FILE_ATTRIBUTE_ARCHIVE`.
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
/// `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`.
pub const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x2000;

/// The attribute bits [`MoveHandle::set_attributes`] lets a caller set or clear.
pub const CHANGEABLE_ATTRIBUTES: u32 = FILE_ATTRIBUTE_READONLY
    | FILE_ATTRIBUTE_HIDDEN
    | FILE_ATTRIBUTE_SYSTEM
    | FILE_ATTRIBUTE_ARCHIVE
    | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;

/// Attribute bits that `FileBasicInfo` stores and that are written back unchanged: the changeable
/// ones plus temporary, offline, no-scrub-data, pinned and unpinned.
const STORED_ATTRIBUTES: u32 =
    CHANGEABLE_ATTRIBUTES | 0x100 | 0x1000 | 0x2_0000 | 0x8_0000 | 0x10_0000;

const ERROR_INVALID_FUNCTION: u32 = 1;
const ERROR_NOT_SAME_DEVICE: u32 = 17;
const ERROR_SHARING_VIOLATION: u32 = 32;
const ERROR_LOCK_VIOLATION: u32 = 33;
const ERROR_HANDLE_EOF: u32 = 38;
const ERROR_NOT_SUPPORTED: u32 = 50;
const ERROR_FILE_EXISTS: u32 = 80;
const ERROR_DIR_NOT_EMPTY: u32 = 145;
const ERROR_ALREADY_EXISTS: u32 = 183;
/// `ERROR_RETRY`: [`remove_pending_pairs`] or [`remove_pending_pairs_exactly`] gave up because the
/// list kept changing under it.
pub const ERROR_RETRY: u32 = 1237;

/// `FileRenameInformation` (`FILE_INFORMATION_CLASS`).
const NT_FILE_RENAME_INFORMATION: i32 = 10;
/// `FileRenameInformationEx` (`FILE_INFORMATION_CLASS`).
const NT_FILE_RENAME_INFORMATION_EX: i32 = 65;

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    /// `NtSetInformationFile`. Used only for a rename relative to a directory handle, which
    /// `SetFileInformationByHandle` refuses.
    fn NtSetInformationFile(
        file: HANDLE,
        io_status: *mut IO_STATUS_BLOCK,
        info: *const core::ffi::c_void,
        length: u32,
        class: i32,
    ) -> i32;

    /// `NtCreateFile`. Used only by [`DestDir::create_dir`], to create a directory relative to a
    /// directory handle (`OBJECT_ATTRIBUTES.RootDirectory`), which no Win32 call can do.
    fn NtCreateFile(
        file: *mut HANDLE,
        access: u32,
        attributes: *const ObjectAttributes,
        io_status: *mut IO_STATUS_BLOCK,
        allocation_size: *const i64,
        file_attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
        ea: *const core::ffi::c_void,
        ea_length: u32,
    ) -> i32;
}

/// `OBJECT_ATTRIBUTES` (the `windows-sys` definition sits behind the WDK feature set).
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *const UNICODE_STRING,
    attributes: u32,
    security_descriptor: *const core::ffi::c_void,
    security_quality_of_service: *const core::ffi::c_void,
}

/// `FILE_CREATE` (`NtCreateFile` disposition): fail if the name exists.
const NT_FILE_CREATE: u32 = 2;
/// `FILE_DIRECTORY_FILE` (`NtCreateFile` option).
const NT_FILE_DIRECTORY_FILE: u32 = 0x1;
/// `FILE_SYNCHRONOUS_IO_NONALERT` (`NtCreateFile` option), what `CreateFileW` asks for without
/// `FILE_FLAG_OVERLAPPED`.
const NT_FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
/// `FILE_OPEN_REPARSE_POINT` (`NtCreateFile` option).
const NT_FILE_OPEN_REPARSE_POINT: u32 = 0x20_0000;

/// Why a file operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FsError {
    /// The object, or a directory on its path, does not exist.
    #[error("not found")]
    NotFound,
    /// Another handle holds the object open without sharing the access that was asked for.
    #[error("in use by another process")]
    SharingViolation,
    /// The caller's token is not allowed to do this. Purge reports it and never raises its access.
    ///
    /// Not returned by [`MoveHandle::rename_into`] for a directory: there the same Win32 error
    /// also means "in use" and is reported as [`FsError::DirInUseOrDenied`].
    #[error("access denied")]
    AccessDenied,
    /// Renaming a directory failed with `ERROR_ACCESS_DENIED`. NTFS refuses to rename a directory
    /// while any handle is open on a file or directory below it, whatever that handle shares and
    /// even if it only reads attributes, and reports exactly this error; a token without the right
    /// to add a subdirectory to the destination, or a filter driver that vetoes the rename, gets
    /// the same code. The cases cannot be told apart from the error, so the caller must treat it
    /// as possibly locked (retry, ask Restart Manager about the files below) before it reports
    /// access denied. [`FsError::code`] is `ERROR_ACCESS_DENIED`.
    #[error("access denied renaming a directory: something below it may be in use")]
    DirInUseOrDenied,
    /// The directory still has entries.
    #[error("directory not empty")]
    DirNotEmpty,
    /// Source and destination are on different volumes.
    #[error("not on the same volume")]
    NotSameDevice,
    /// The destination name is already taken; nothing was replaced.
    #[error("destination already exists")]
    AlreadyExists,
    /// The object is not of the kind the operation is for (a plain directory given to
    /// [`MoveHandle::delete`], a file or a reparse point given to
    /// [`MoveHandle::remove_dir_if_empty`], a destination handle for
    /// [`MoveHandle::rename_into`] that is not a plain directory). Nothing was changed.
    #[error("wrong kind of object for this operation")]
    WrongKind,
    /// [`remove_pending_pairs_exactly`] found the pair a number of times other than the caller
    /// expected, and changed nothing. [`FsError::code`] is `ERROR_INVALID_DATA`.
    #[error("the boot-time move list holds the pair {found} time(s), not the expected count")]
    PendingCountMismatch {
        /// How many occurrences of the pair the list holds (saturating).
        found: u32,
    },
    /// Any other Win32 error code.
    #[error("Win32 error {0}")]
    Other(u32),
}

impl FsError {
    /// The Win32 error code this error stands for ([`FsError::WrongKind`] reports
    /// `ERROR_INVALID_PARAMETER`).
    pub fn code(self) -> u32 {
        match self {
            FsError::NotFound => Win32Error::FILE_NOT_FOUND.0,
            FsError::SharingViolation => ERROR_SHARING_VIOLATION,
            FsError::AccessDenied | FsError::DirInUseOrDenied => Win32Error::ACCESS_DENIED.0,
            FsError::DirNotEmpty => ERROR_DIR_NOT_EMPTY,
            FsError::NotSameDevice => ERROR_NOT_SAME_DEVICE,
            FsError::AlreadyExists => ERROR_ALREADY_EXISTS,
            FsError::WrongKind => Win32Error::INVALID_PARAMETER.0,
            FsError::PendingCountMismatch { .. } => Win32Error::INVALID_DATA.0,
            FsError::Other(code) => code,
        }
    }
}

impl From<Win32Error> for FsError {
    fn from(e: Win32Error) -> FsError {
        match e.0 {
            2 | 3 => FsError::NotFound,
            5 => FsError::AccessDenied,
            ERROR_NOT_SAME_DEVICE => FsError::NotSameDevice,
            ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION => FsError::SharingViolation,
            ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS => FsError::AlreadyExists,
            ERROR_DIR_NOT_EMPTY => FsError::DirNotEmpty,
            code => FsError::Other(code),
        }
    }
}

/// Whether an information class was refused as unknown by the filesystem or the OS, so that the
/// older class may be tried instead.
fn class_unsupported(e: Win32Error) -> bool {
    matches!(
        e.0,
        ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED | 87 /* ERROR_INVALID_PARAMETER */
    )
}

/// NUL-terminated `\\?\` form of an absolute path.
fn ext_wide(path: &Path) -> Result<Vec<u16>, Win32Error> {
    let mut p = extended_units(path)?;
    p.push(0);
    Ok(p)
}

/// `CreateFileW(OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)` with
/// read, write and delete sharing.
fn open_no_follow(path: &Path, access: u32) -> Result<OwnedHandle, Win32Error> {
    let p = ext_wide(path)?;
    // SAFETY: `p` is NUL-terminated; no security attributes or template handle.
    let h = unsafe {
        CreateFileW(
            p.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(Win32Error::last());
    }
    // SAFETY: `h` is a freshly opened, valid handle owned by nobody else.
    Ok(unsafe { OwnedHandle::from_raw_handle(h) })
}

/// One data stream of a file or directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamInfo {
    /// Stream name as NTFS reports it: `::$DATA` for the unnamed stream, `:name:$DATA` for an
    /// alternate data stream.
    pub name: String,
    /// Stream size in bytes.
    pub size: u64,
    /// Allocated size in bytes.
    pub allocation_size: u64,
}

impl StreamInfo {
    /// The unnamed (main) data stream.
    pub fn is_default(&self) -> bool {
        self.name == "::$DATA"
    }
}

/// A handle that can rename or delete the object it was opened on.
///
/// Opened with `FILE_FLAG_OPEN_REPARSE_POINT`: for a junction, a symbolic link or any other
/// reparse point the handle is on the link itself, so a rename moves the link and a delete removes
/// the link; the target is never touched. Sharing is read, write and delete.
///
/// The only rename is [`MoveHandle::rename_into`], into a directory handle. A rename to a path does
/// not exist:
///
/// ```compile_fail
/// # fn f(h: &purge_win::fs_write::MoveHandle) {
/// h.rename_to(std::path::Path::new(r"C:\dir\name")).unwrap();
/// # }
/// ```
#[derive(Debug)]
pub struct MoveHandle {
    file: FileHandle,
    read_control: bool,
}

impl AsHandle for MoveHandle {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.file.as_handle()
    }
}

impl MoveHandle {
    /// Opens `path` (absolute) with `DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES`, adding
    /// `READ_CONTROL` when the object grants it (see [`MoveHandle::has_read_control`]).
    pub fn open(path: &Path) -> Result<MoveHandle, FsError> {
        Self::open_access(path, DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES)
    }

    /// Like [`MoveHandle::open`], with `FILE_WRITE_ATTRIBUTES` added so that
    /// [`MoveHandle::set_attributes`] works.
    pub fn open_with_attribute_write(path: &Path) -> Result<MoveHandle, FsError> {
        Self::open_access(
            path,
            DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
        )
    }

    fn open_access(path: &Path, access: u32) -> Result<MoveHandle, FsError> {
        match open_no_follow(path, access | READ_CONTROL) {
            Ok(h) => Ok(MoveHandle {
                file: FileHandle(h),
                read_control: true,
            }),
            // DELETE can be granted by the parent directory while the object's own DACL refuses
            // READ_CONTROL; the move is still possible, only the security facts are not.
            Err(Win32Error::ACCESS_DENIED) => Ok(MoveHandle {
                file: FileHandle(open_no_follow(path, access)?),
                read_control: false,
            }),
            Err(e) => Err(e.into()),
        }
    }

    /// Wraps a handle the caller opened itself, without a path: relative to a checked directory
    /// handle (`NtCreateFile` with a root directory), for a store that must act on the object it
    /// checked. The handle must be on the object itself (opened without following a reparse point)
    /// with at least `DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES`; `read_control` says whether it
    /// also carries `READ_CONTROL` ([`MoveHandle::has_read_control`]). A handle without `DELETE`
    /// makes every rename and delete fail with [`FsError::AccessDenied`]; nothing else is assumed.
    pub fn from_owned_handle(handle: OwnedHandle, read_control: bool) -> MoveHandle {
        MoveHandle {
            file: FileHandle(handle),
            read_control,
        }
    }

    /// Whether the handle carries `READ_CONTROL`, which [`MoveHandle::security`] needs.
    pub fn has_read_control(&self) -> bool {
        self.read_control
    }

    /// The read-side view of the same handle.
    pub fn as_file(&self) -> &FileHandle {
        &self.file
    }

    fn raw(&self) -> HANDLE {
        self.file.as_handle().as_raw_handle()
    }

    /// Attributes, sizes, times, link count, reparse tag and file id of the opened object.
    pub fn metadata(&self) -> Result<FileMeta, FsError> {
        Ok(self.file.metadata()?)
    }

    /// Volume serial and 128-bit file id.
    pub fn file_id(&self) -> Result<FileId, FsError> {
        Ok(self.file.file_id()?)
    }

    /// The path the handle really is on, in `\\?\C:\...` form.
    pub fn final_path(&self) -> Result<String, FsError> {
        Ok(self.file.final_path()?)
    }

    /// Reparse tag of the opened object (`0` if it is not a reparse point).
    pub fn reparse_tag(&self) -> Result<u32, FsError> {
        Ok(self.file.reparse_tag()?)
    }

    /// Owner, group, DACL and SDDL string of the opened object. Fails with
    /// [`FsError::AccessDenied`] when [`MoveHandle::has_read_control`] is false.
    pub fn security(&self) -> Result<Security, FsError> {
        Ok(crate::secure::handle_security(self)?)
    }

    /// The data streams of the opened object (`FileStreamInfo` on the handle). A file has at
    /// least `::$DATA`; a directory has none unless it carries alternate data streams.
    pub fn streams(&self) -> Result<Vec<StreamInfo>, FsError> {
        Ok(streams_of(self.raw())?)
    }

    /// Renames the object into the directory behind `dest_dir`, under the single name `leaf`.
    /// The destination is the directory the handle is on, whatever happens to its path in the
    /// meantime: a junction planted at the old path later is not followed. Pass the handle whose
    /// facts the gate checked, normally a [`DestDir`] (any handle opened with
    /// `FILE_FLAG_OPEN_REPARSE_POINT` and `FILE_READ_ATTRIBUTES` works, for example one from
    /// [`crate::secure::open_for_security`]). The kernel needs no particular access on it; whether
    /// an entry may be added is checked against the directory's security descriptor at the time
    /// of the rename. The handle stays valid and follows the object.
    ///
    /// - `leaf` must be one plain path component: not empty, not `.` or `..`, no `\`, `/`, `:` or
    ///   NUL; otherwise `FsError::Other(ERROR_INVALID_PARAMETER)`. A trailing dot or space is
    ///   kept exactly (a leftover with such a name must come back under the same name).
    /// - A `dest_dir` handle that is not a directory, or is a reparse point (junction, symbolic
    ///   link, mount point), is refused with [`FsError::WrongKind`].
    /// - [`FsError::AlreadyExists`] if anything has that name; nothing is ever replaced.
    /// - [`FsError::NotSameDevice`] if the destination is on another volume.
    /// - [`FsError::DirInUseOrDenied`] when the object is a directory and the rename is refused
    ///   with `ERROR_ACCESS_DENIED`, which is how NTFS reports an open handle anywhere below it.
    ///
    /// Uses `NtSetInformationFile(FileRenameInformationEx)` with the root directory set and no
    /// replace flag, falling back to `FileRenameInformation` where the newer class is unknown.
    pub fn rename_into(&self, dest_dir: &impl AsHandle, leaf: &str) -> Result<(), FsError> {
        check_leaf(leaf)?;
        let root = dest_dir.as_handle().as_raw_handle();
        require_plain_dir(root)?;
        let name: Vec<u16> = leaf.encode_utf16().collect();
        match self.rename_raw(root, &name) {
            Err(FsError::AccessDenied)
                if self
                    .metadata()
                    .is_ok_and(|m| m.is_dir && m.reparse_tag == 0) =>
            {
                Err(FsError::DirInUseOrDenied)
            }
            other => other,
        }
    }

    fn rename_raw(&self, root: HANDLE, name: &[u16]) -> Result<(), FsError> {
        let name_off = offset_of!(FILE_RENAME_INFO, FileName);
        let bytes = (name_off + (name.len() + 1) * 2).max(size_of::<FILE_RENAME_INFO>());
        let Ok(name_bytes) = u32::try_from(name.len() * 2) else {
            return Err(Win32Error::INVALID_PARAMETER.into());
        };
        // u64 storage keeps the buffer aligned for FILE_RENAME_INFO; it is zeroed, so the flags
        // word is 0 (no replace) and the name is NUL-terminated.
        let mut buf = vec![0u64; bytes.div_ceil(8)];
        let info = buf.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        // SAFETY: `buf` is at least `bytes` long, aligned and zeroed; the fixed fields lie inside
        // it and the name is copied to `name_off`, where `name.len() + 1` units fit.
        unsafe {
            (*info).Anonymous.Flags = 0;
            (*info).RootDirectory = root;
            (*info).FileNameLength = name_bytes;
            ptr::copy_nonoverlapping(
                name.as_ptr(),
                buf.as_mut_ptr().cast::<u8>().add(name_off).cast::<u16>(),
                name.len(),
            );
        }
        let mut last = Win32Error::INVALID_PARAMETER;
        // With no flag set, the newer and the older class mean the same: rename, never replacing.
        // SetFileInformationByHandle does not take a root directory, so the structure goes to the
        // native call it wraps.
        for class in [NT_FILE_RENAME_INFORMATION_EX, NT_FILE_RENAME_INFORMATION] {
            let mut io = IO_STATUS_BLOCK::default();
            // SAFETY: live handles; `io` is a writable status block; `buf` holds a complete
            // FILE_RENAME_INFORMATION (same layout as FILE_RENAME_INFO) of `bytes` bytes.
            let status = unsafe {
                NtSetInformationFile(
                    self.raw(),
                    &mut io,
                    buf.as_ptr().cast(),
                    bytes as u32,
                    class,
                )
            };
            let result = if status >= 0 {
                Ok(())
            } else {
                // SAFETY: a pure status-to-code mapping.
                Err(Win32Error(unsafe { RtlNtStatusToDosError(status) }))
            };
            match result {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last = e;
                    if !class_unsupported(e) {
                        break;
                    }
                }
            }
        }
        Err(last.into())
    }

    /// Deletes a file, or a reparse point of any kind (junction, symbolic link, mount point):
    /// the link itself is removed, its target is never opened. A plain directory is refused with
    /// [`FsError::WrongKind`]; use [`MoveHandle::remove_dir_if_empty`] for it.
    ///
    /// A read-only object is refused with [`FsError::AccessDenied`] unless `ignore_readonly` is
    /// set. The name is gone at the latest when this handle and every other handle on the object
    /// are closed.
    pub fn delete(&self, ignore_readonly: bool) -> Result<(), FsError> {
        let meta = self.metadata()?;
        if meta.is_dir && meta.reparse_tag == 0 {
            return Err(FsError::WrongKind);
        }
        self.dispose(ignore_readonly)
    }

    /// Removes a directory if it has no entries; never recursive. A directory with entries gives
    /// [`FsError::DirNotEmpty`]. A file or a reparse point is refused with
    /// [`FsError::WrongKind`]. The read-only attribute, which has no meaning for a directory, is
    /// ignored where the OS supports that.
    pub fn remove_dir_if_empty(&self) -> Result<(), FsError> {
        let meta = self.metadata()?;
        if !meta.is_dir || meta.reparse_tag != 0 {
            return Err(FsError::WrongKind);
        }
        self.dispose(true)
    }

    /// Marks the object for deletion through the handle.
    fn dispose(&self, ignore_readonly: bool) -> Result<(), FsError> {
        let posix = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
        let mut attempts = Vec::with_capacity(2);
        if ignore_readonly {
            attempts.push(posix | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE);
        }
        attempts.push(posix);
        for flags in attempts {
            let info = FILE_DISPOSITION_INFO_EX { Flags: flags };
            match set_info(self.raw(), FileDispositionInfoEx, &info) {
                Ok(()) => return Ok(()),
                Err(e) if class_unsupported(e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let info = FILE_DISPOSITION_INFO { DeleteFile: true };
        Ok(set_info(self.raw(), FileDispositionInfo, &info)?)
    }

    /// Sets the bits in `set` and clears the bits in `clear`, both limited to
    /// [`CHANGEABLE_ATTRIBUTES`] (read-only, hidden, system, archive, not-content-indexed), and
    /// returns the attributes written. Every other attribute and all timestamps stay as they are.
    /// Needs a handle from [`MoveHandle::open_with_attribute_write`].
    pub fn set_attributes(&self, set: u32, clear: u32) -> Result<u32, FsError> {
        if (set | clear) & !CHANGEABLE_ATTRIBUTES != 0 || set & clear != 0 {
            return Err(Win32Error::INVALID_PARAMETER.into());
        }
        let current = self.metadata()?.attributes;
        let wanted = ((current | set) & !clear) & STORED_ATTRIBUTES;
        let info = FILE_BASIC_INFO {
            // Zero timestamps mean "leave unchanged".
            CreationTime: 0,
            LastAccessTime: 0,
            LastWriteTime: 0,
            ChangeTime: 0,
            // Zero attributes would also mean "leave unchanged"; NORMAL clears them.
            FileAttributes: if wanted == 0 {
                FILE_ATTRIBUTE_NORMAL
            } else {
                wanted
            },
        };
        set_info(self.raw(), FileBasicInfo, &info)?;
        Ok(wanted)
    }

    /// Sets the creation time and the last-write time of the opened object, as FILETIME ticks
    /// (100 ns since 1601-01-01 UTC, the unit of [`FileMeta::creation_time`] and
    /// [`FileMeta::last_write_time`]). The last-access time and the attributes are left as they
    /// are; the change time is the file system's to update.
    ///
    /// `SetFileInformationByHandle(FileBasicInfo)` with the two times given and `0` in the other
    /// time fields and in `FileAttributes`, which Microsoft documents as "keep the current value".
    /// The values `-1` and `-2`, which would switch the handle's own timestamp updates off and on,
    /// are never written. So `0` and anything above `i64::MAX` (negative as a `LARGE_INTEGER`) are
    /// refused with `FsError::Other(ERROR_INVALID_PARAMETER)`.
    ///
    /// Needs `FILE_WRITE_ATTRIBUTES` on the handle: one from
    /// [`MoveHandle::open_with_attribute_write`], [`MoveHandle::open_with_security_write`] or
    /// [`DestDir::create_dir`]; otherwise [`FsError::AccessDenied`]. Set the times of a directory
    /// after its content is in place: adding an entry updates its last-write time.
    pub fn set_times(&self, creation: u64, last_write: u64) -> Result<(), FsError> {
        let (Ok(creation), Ok(last_write)) = (i64::try_from(creation), i64::try_from(last_write))
        else {
            return Err(Win32Error::INVALID_PARAMETER.into());
        };
        if creation == 0 || last_write == 0 {
            return Err(Win32Error::INVALID_PARAMETER.into());
        }
        let info = FILE_BASIC_INFO {
            CreationTime: creation,
            LastAccessTime: 0,
            LastWriteTime: last_write,
            ChangeTime: 0,
            FileAttributes: 0,
        };
        Ok(set_info(self.raw(), FileBasicInfo, &info)?)
    }

    /// Like [`MoveHandle::open`], with `FILE_WRITE_ATTRIBUTES`, `WRITE_DAC` and `WRITE_OWNER`
    /// added so that [`MoveHandle::set_times`] and [`MoveHandle::set_security`] work. Fails with
    /// [`FsError::AccessDenied`] when the object's security descriptor does not grant all of them
    /// to the caller's token; no privilege is used to get them.
    pub fn open_with_security_write(path: &Path) -> Result<MoveHandle, FsError> {
        Self::open_access(
            path,
            DELETE
                | SYNCHRONIZE
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | WRITE_DAC
                | WRITE_OWNER,
        )
    }

    /// Sets the owner (`O:`), group (`G:`) and DACL (`D:`) parts present in `sddl` (any subset,
    /// at least one) on the opened object, through this handle. The DACL is stored as given,
    /// with its ACEs and their inherited flags, its protected flag (`P`) and its auto-inherited
    /// flag (`AI`); nothing is recomputed from the parent and nothing is propagated to children.
    ///
    /// - A SACL part (`S:`) is refused with `FsError::Other(ERROR_INVALID_PARAMETER)`, as is a
    ///   string with none of the three parts or one that is not SDDL.
    /// - An owner the caller's token may not assign fails with
    ///   `FsError::Other(ERROR_INVALID_OWNER)` (1307), and nothing is changed. No privilege is
    ///   enabled and ownership is never taken.
    /// - The handle needs `WRITE_DAC` for a DACL and `WRITE_OWNER` for an owner or group: one from
    ///   [`MoveHandle::open_with_security_write`] or [`DestDir::create_dir`]; otherwise
    ///   [`FsError::AccessDenied`].
    ///
    /// `SetKernelObjectSecurity` on the handle (never `SetSecurityInfo`, which recomputes the
    /// inherited part from the parent and walks the children).
    pub fn set_security(&self, sddl: &str) -> Result<(), FsError> {
        let mut sd = SddlDescriptor::parse(sddl)?;
        let (info, control) = sd.parts()?;
        Ok(write_security(self.raw(), &mut sd, info, control)?)
    }
}

/// `SetKernelObjectSecurity` on `h` with the parts `info` of `sd` (`control` is its control word).
///
/// The kernel stores the auto-inherited flag of a new DACL only when the descriptor also carries
/// `SE_DACL_AUTO_INHERIT_REQ`; without it `D:AI(...)` is stored as `D:(...)` and `D:PAI(...)` as
/// `D:P(...)`. With it, NTFS stores the given DACL unchanged (ACE order and inherited ACEs
/// included) and sets the flag; it propagates nothing to children. So the request bit is set
/// exactly when the given DACL has the auto-inherited flag (`set_security_round_trips_*` tests).
fn write_security(
    h: HANDLE,
    sd: &mut SddlDescriptor,
    info: u32,
    control: u16,
) -> Result<(), Win32Error> {
    let auto_inherited =
        info & DACL_SECURITY_INFORMATION != 0 && control & SE_DACL_AUTO_INHERITED != 0;
    sd.set_auto_inherit_req(auto_inherited)?;
    // SAFETY: `h` is live for the call; `sd.0` is a valid descriptor kept alive by `sd`.
    if unsafe { SetKernelObjectSecurity(h, info, sd.0) } == 0 {
        return Err(Win32Error::last());
    }
    Ok(())
}

/// The leaf rule of [`MoveHandle::rename_into`] and [`DestDir::create_dir`]: one plain path
/// component, not empty, not `.` or `..`, no `\`, `/`, `:` or NUL. A trailing dot or space is
/// allowed and kept.
fn check_leaf(leaf: &str) -> Result<(), FsError> {
    if leaf.is_empty() || leaf == "." || leaf == ".." || leaf.contains(['\\', '/', ':', '\0']) {
        return Err(Win32Error::INVALID_PARAMETER.into());
    }
    Ok(())
}

/// [`FsError::WrongKind`] unless `h` is on a directory that is not a reparse point.
fn require_plain_dir(h: HANDLE) -> Result<(), FsError> {
    let tag = attribute_tag(h)?;
    if tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(FsError::WrongKind);
    }
    Ok(())
}

/// `SetFileInformationByHandle` for a fixed-size information struct.
fn set_info<T>(h: HANDLE, class: FILE_INFO_BY_HANDLE_CLASS, info: &T) -> Result<(), Win32Error> {
    // SAFETY: `info` points to `size_of::<T>()` readable bytes; callers pair each class with its
    // documented struct.
    let ok = unsafe {
        SetFileInformationByHandle(h, class, ptr::from_ref(info).cast(), size_of::<T>() as u32)
    };
    if ok == 0 {
        Err(Win32Error::last())
    } else {
        Ok(())
    }
}

/// `GetFileInformationByHandleEx(FileAttributeTagInfo)`: attributes and reparse tag of the object
/// behind any handle that carries `FILE_READ_ATTRIBUTES`.
fn attribute_tag(h: HANDLE) -> Result<FILE_ATTRIBUTE_TAG_INFO, Win32Error> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO {
        FileAttributes: 0,
        ReparseTag: 0,
    };
    // SAFETY: `info` is a writable FILE_ATTRIBUTE_TAG_INFO of the size passed; the caller keeps
    // the handle alive for the call.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            h,
            FileAttributeTagInfo,
            (&raw mut info).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(Win32Error::last());
    }
    Ok(info)
}

/// A directory opened as the destination of [`MoveHandle::rename_into`], together with the facts
/// the gate judges it by, all read from this one handle.
///
/// Opened with `FILE_READ_ATTRIBUTES | SYNCHRONIZE`, read, write and delete sharing, and
/// `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`: a junction, symbolic link or mount
/// point at the path is opened as itself and shows in [`DestDir::facts`] with its reparse tag; it
/// is never followed. Opening refuses nothing that exists (the facts are for the caller to judge);
/// [`MoveHandle::rename_into`] refuses a handle that is not a plain directory.
///
/// Keep the value from the gate's check until the rename and pass it to `rename_into`: the rename
/// then lands in the directory that was checked, even if its path is swapped for a junction in
/// between.
#[derive(Debug)]
pub struct DestDir {
    file: FileHandle,
}

/// What [`DestDir::facts`] reads from the destination directory's handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirFacts {
    /// The path the handle really is on, in `\\?\C:\...` form (for a reparse point, its own path).
    pub final_path: String,
    /// The reparse tag; `0` when the object is not a reparse point.
    pub reparse_tag: u32,
    /// Whether the object is a directory (a junction is a directory with a reparse tag).
    pub is_dir: bool,
    /// Volume serial (64-bit, `FILE_ID_INFO`) and 128-bit file id.
    pub file_id: FileId,
}

impl DirFacts {
    /// The serial of the volume the directory is on, the value source handles are compared with.
    pub fn volume_serial(&self) -> u64 {
        self.file_id.volume_serial
    }

    /// A directory that is not a reparse point: the only kind [`MoveHandle::rename_into`] accepts.
    pub fn is_plain_dir(&self) -> bool {
        self.is_dir && self.reparse_tag == 0
    }
}

impl AsHandle for DestDir {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.file.as_handle()
    }
}

impl DestDir {
    /// Opens `path` (absolute) without following a final reparse point. Fails with
    /// [`FsError::NotFound`] when nothing is there and with `FsError::Other(87)` for a relative
    /// path, a `.`/`..` component or stream syntax.
    pub fn open(path: &Path) -> Result<DestDir, FsError> {
        Ok(DestDir {
            file: FileHandle(open_no_follow(path, FILE_READ_ATTRIBUTES | SYNCHRONIZE)?),
        })
    }

    /// Final path, reparse tag, directory flag, volume serial and file id, read from the handle.
    pub fn facts(&self) -> Result<DirFacts, FsError> {
        let meta = self.file.metadata()?;
        Ok(DirFacts {
            final_path: self.file.final_path()?,
            reparse_tag: meta.reparse_tag,
            is_dir: meta.is_dir,
            file_id: meta.file_id,
        })
    }

    /// The read-side view of the same handle.
    pub fn as_file(&self) -> &FileHandle {
        &self.file
    }

    /// Creates a new directory named `leaf` directly inside the directory this handle is on, with
    /// the security descriptor `sddl` applied at creation, and returns a handle on it.
    ///
    /// The parent is this handle, not its path: if the directory was renamed and a junction put
    /// at its old path since it was opened, the new directory still lands in the directory the
    /// handle is on. Rules:
    ///
    /// - `leaf` follows the rule of [`MoveHandle::rename_into`]: one plain component, not empty,
    ///   not `.` or `..`, no `\`, `/`, `:` or NUL, otherwise `FsError::Other(ERROR_INVALID_PARAMETER)`;
    ///   a trailing dot or space is kept exactly.
    /// - A handle that is not a plain directory (a file, a junction, a symbolic link, a mount
    ///   point) is refused with [`FsError::WrongKind`].
    /// - [`FsError::AlreadyExists`] if anything already has that name (a directory, a file, a
    ///   link, dangling or not); the existing object is never opened or adopted.
    /// - As with [`create_dir_secure`], an SDDL string without an owner part leaves the owner to
    ///   the caller's token, and an owner the token may not assign fails with
    ///   `FsError::Other(ERROR_INVALID_OWNER)`. A DACL without `P` also receives the parent's
    ///   inheritable ACEs; use [`MoveHandle::set_security`] on the result to store a recorded
    ///   descriptor exactly.
    ///
    /// The returned handle carries `DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES |
    /// FILE_WRITE_ATTRIBUTES | READ_CONTROL | WRITE_DAC | WRITE_OWNER` (the creator of an object
    /// is granted what it asks for), with read, write and delete sharing, so
    /// [`MoveHandle::set_times`], [`MoveHandle::set_security`] and [`MoveHandle::security`] work
    /// on it. Whether an entry may be added is checked against the parent's security descriptor
    /// at the time of the call; this handle needs no particular access.
    ///
    /// `NtCreateFile` with `RootDirectory` set to this handle, `FILE_CREATE`, and
    /// `FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT`; no backup
    /// intent, so no privilege takes part.
    pub fn create_dir(&self, leaf: &str, sddl: &str) -> Result<MoveHandle, FsError> {
        check_leaf(leaf)?;
        let root = self.file.as_handle().as_raw_handle();
        require_plain_dir(root)?;
        let sd = SddlDescriptor::parse(sddl)?;
        let mut name: Vec<u16> = leaf.encode_utf16().collect();
        let Ok(name_bytes) = u16::try_from(name.len() * 2) else {
            return Err(Win32Error::INVALID_PARAMETER.into());
        };
        let object_name = UNICODE_STRING {
            Length: name_bytes,
            MaximumLength: name_bytes,
            Buffer: name.as_mut_ptr(),
        };
        let attributes = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: root,
            object_name: &object_name,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: sd.0.cast_const(),
            security_quality_of_service: ptr::null(),
        };
        let access = DELETE
            | SYNCHRONIZE
            | FILE_READ_ATTRIBUTES
            | FILE_WRITE_ATTRIBUTES
            | READ_CONTROL
            | WRITE_DAC
            | WRITE_OWNER;
        let mut handle: HANDLE = ptr::null_mut();
        let mut io = IO_STATUS_BLOCK::default();
        // SAFETY: `attributes` points to a complete OBJECT_ATTRIBUTES whose name (`name`, of
        // `name_bytes` bytes) and descriptor (kept alive by `sd`) outlive the call; `root` is a
        // live handle borrowed from `self`; `handle` and `io` are writable locals; no allocation
        // size and no extended attributes.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                access,
                &attributes,
                &mut io,
                ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NT_FILE_CREATE,
                NT_FILE_DIRECTORY_FILE
                    | NT_FILE_OPEN_REPARSE_POINT
                    | NT_FILE_SYNCHRONOUS_IO_NONALERT,
                ptr::null(),
                0,
            )
        };
        if status < 0 {
            // SAFETY: a pure status-to-code mapping.
            return Err(Win32Error(unsafe { RtlNtStatusToDosError(status) }).into());
        }
        Ok(MoveHandle {
            // SAFETY: on success `handle` is a freshly created, valid handle owned by nobody else.
            file: FileHandle(unsafe { OwnedHandle::from_raw_handle(handle) }),
            read_control: true,
        })
    }
}

/// `GetFileInformationByHandleEx(FileStreamInfo)`, decoded.
fn streams_of(h: HANDLE) -> Result<Vec<StreamInfo>, Win32Error> {
    let mut buf = vec![0u64; 128];
    loop {
        // SAFETY: `buf` has `buf.len() * 8` writable bytes and is aligned for FILE_STREAM_INFO.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                h,
                FileStreamInfo,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
            )
        };
        if ok != 0 {
            break;
        }
        match Win32Error::last() {
            Win32Error(ERROR_HANDLE_EOF) => return Ok(Vec::new()),
            Win32Error::MORE_DATA | Win32Error::INSUFFICIENT_BUFFER if buf.len() < (1 << 20) => {
                let n = buf.len() * 4;
                buf.resize(n, 0);
            }
            e => return Err(e),
        }
    }
    let bytes: Vec<u8> = buf.iter().flat_map(|w| w.to_ne_bytes()).collect();
    parse_stream_info(&bytes).ok_or(Win32Error::INVALID_DATA)
}

/// Decodes a chain of `FILE_STREAM_INFO` records (next offset, name length in bytes, size,
/// allocation size, name).
fn parse_stream_info(bytes: &[u8]) -> Option<Vec<StreamInfo>> {
    let u32_at = |o: usize| Some(u32::from_le_bytes(bytes.get(o..o + 4)?.try_into().ok()?));
    let u64_at = |o: usize| Some(u64::from_le_bytes(bytes.get(o..o + 8)?.try_into().ok()?));
    let mut out = Vec::new();
    let mut off = 0usize;
    loop {
        let next = u32_at(off)? as usize;
        let name_len = u32_at(off + 4)? as usize;
        let name: Vec<u16> = bytes
            .get(off + 24..off + 24 + name_len)?
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        out.push(StreamInfo {
            name: String::from_utf16_lossy(&name),
            size: u64_at(off + 8)?,
            allocation_size: u64_at(off + 16)?,
        });
        if next == 0 {
            return Some(out);
        }
        off = off.checked_add(next)?;
    }
}

/// The data streams of `path` (absolute), read through a handle opened on the path itself; a final
/// reparse point is not followed. See [`MoveHandle::streams`].
pub fn list_streams(path: &Path) -> Result<Vec<StreamInfo>, FsError> {
    let h = open_no_follow(path, FILE_READ_ATTRIBUTES | SYNCHRONIZE)?;
    Ok(streams_of(h.as_raw_handle())?)
}

/// A security descriptor built from an SDDL string, freed on drop.
struct SddlDescriptor(PSECURITY_DESCRIPTOR);

impl SddlDescriptor {
    fn parse(sddl: &str) -> Result<SddlDescriptor, Win32Error> {
        let text = wide(sddl);
        let mut psd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `text` is NUL-terminated; `psd` receives a LocalAlloc block; the size is not
        // requested.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(Win32Error::last());
        }
        Ok(SddlDescriptor(psd))
    }

    /// The `SECURITY_INFORMATION` bits for the parts the descriptor holds (owner, group, DACL) and
    /// its control word. A SACL part is refused with `ERROR_INVALID_PARAMETER` (writing one needs
    /// a privilege, and Purge enables none), and so is a descriptor with none of the three parts.
    fn parts(&self) -> Result<(u32, u16), Win32Error> {
        let mut info = 0u32;
        let (mut sid, mut defaulted): (PSID, i32) = (ptr::null_mut(), 0);
        // SAFETY: `self.0` is a valid descriptor kept alive by `self`; out-pointers are locals.
        if unsafe { GetSecurityDescriptorOwner(self.0, &mut sid, &mut defaulted) } == 0 {
            return Err(Win32Error::last());
        }
        if !sid.is_null() {
            info |= OWNER_SECURITY_INFORMATION;
        }
        sid = ptr::null_mut();
        // SAFETY: as above.
        if unsafe { GetSecurityDescriptorGroup(self.0, &mut sid, &mut defaulted) } == 0 {
            return Err(Win32Error::last());
        }
        if !sid.is_null() {
            info |= GROUP_SECURITY_INFORMATION;
        }
        let (mut present, mut acl): (i32, *mut ACL) = (0, ptr::null_mut());
        // SAFETY: as above.
        if unsafe { GetSecurityDescriptorSacl(self.0, &mut present, &mut acl, &mut defaulted) } == 0
        {
            return Err(Win32Error::last());
        }
        if present != 0 {
            return Err(Win32Error::INVALID_PARAMETER);
        }
        // SAFETY: as above.
        if unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut acl, &mut defaulted) } == 0
        {
            return Err(Win32Error::last());
        }
        if present != 0 {
            info |= DACL_SECURITY_INFORMATION;
        }
        if info == 0 {
            return Err(Win32Error::INVALID_PARAMETER);
        }
        let (mut control, mut revision) = (0u16, 0u32);
        // SAFETY: as above.
        if unsafe { GetSecurityDescriptorControl(self.0, &mut control, &mut revision) } == 0 {
            return Err(Win32Error::last());
        }
        Ok((info, control))
    }

    /// Sets or clears `SE_DACL_AUTO_INHERIT_REQ` in the descriptor's control word.
    fn set_auto_inherit_req(&mut self, on: bool) -> Result<(), Win32Error> {
        let bits = if on { SE_DACL_AUTO_INHERIT_REQ } else { 0 };
        // SAFETY: `self.0` is a valid descriptor owned by `self`; the bit is one of those
        // SetSecurityDescriptorControl documents as settable.
        if unsafe { SetSecurityDescriptorControl(self.0, SE_DACL_AUTO_INHERIT_REQ, bits) } == 0 {
            return Err(Win32Error::last());
        }
        Ok(())
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

impl Drop for SddlDescriptor {
    fn drop(&mut self) {
        // SAFETY: the block came from ConvertStringSecurityDescriptorToSecurityDescriptorW, which
        // documents LocalFree as its deallocator; freed exactly once.
        unsafe { LocalFree(self.0) };
    }
}

/// Creates the directory `path` (absolute) with the security descriptor `sddl`, applied at
/// creation. Fails with [`FsError::AlreadyExists`] if anything has that name (a directory, a
/// file, a junction or a dangling link): an existing object is never adopted. The parent must
/// exist. An SDDL string without an owner part leaves the owner to the caller's token.
pub fn create_dir_secure(path: &Path, sddl: &str) -> Result<(), FsError> {
    let p = ext_wide(path)?;
    let sd = SddlDescriptor::parse(sddl)?;
    let sa = sd.attributes();
    // SAFETY: `p` is NUL-terminated; `sa` points to a descriptor that `sd` keeps alive.
    if unsafe { CreateDirectoryW(p.as_ptr(), &sa) } == 0 {
        return Err(Win32Error::last().into());
    }
    Ok(())
}

/// Creates the file `path` (absolute) with the security descriptor `sddl`, applied at creation,
/// and returns it open for reading and writing (other handles may read). Fails with
/// [`FsError::AlreadyExists`] if a file or a file symbolic link has that name (a dangling link
/// included), and with [`FsError::AccessDenied`] if a directory, a junction or a directory link
/// has it (dangling or not); nothing existing is ever opened or truncated, and the target of a
/// link is never created.
///
/// `CREATE_NEW` alone follows a symbolic link whose target does not exist and creates the target;
/// `FILE_FLAG_OPEN_REPARSE_POINT` makes the existing link itself count as the name being taken.
pub fn create_file_secure(path: &Path, sddl: &str) -> Result<std::fs::File, FsError> {
    let p = ext_wide(path)?;
    let sd = SddlDescriptor::parse(sddl)?;
    let sa = sd.attributes();
    // SAFETY: `p` is NUL-terminated; `sa` points to a descriptor that `sd` keeps alive; no
    // template handle.
    let h = unsafe {
        CreateFileW(
            p.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            &sa,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(Win32Error::last().into());
    }
    // SAFETY: `h` is a freshly created, valid handle owned by nobody else.
    Ok(std::fs::File::from(unsafe {
        OwnedHandle::from_raw_handle(h)
    }))
}

/// `FlushFileBuffers` on a handle opened with write access (a file being written, for example one
/// from [`create_file_secure`]).
pub fn flush(handle: &impl AsHandle) -> Result<(), FsError> {
    // SAFETY: the borrowed handle is live for the call.
    if unsafe { FlushFileBuffers(handle.as_handle().as_raw_handle()) } == 0 {
        return Err(Win32Error::last().into());
    }
    Ok(())
}

/// Flushes the directory `path` (absolute) to disk, so that a rename or a creation inside it is
/// durable. A reparse point is refused with [`FsError::WrongKind`], a file likewise.
pub fn flush_dir(path: &Path) -> Result<(), FsError> {
    let h = open_no_follow(path, FILE_ADD_FILE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)?;
    let dir = FileHandle(h);
    let meta = dir.metadata()?;
    if !meta.is_dir || meta.reparse_tag != 0 {
        return Err(FsError::WrongKind);
    }
    flush(&dir)
}

/// One entry of the boot-time move list: at the next boot the session manager renames `src` to
/// `dst`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PendingPair {
    /// Source in NT form (`\??\C:\dir\name`), exactly as stored; newer Windows builds may put a
    /// `*<digit>` marker in front.
    pub src: String,
    /// Destination in NT form; empty for a boot-time delete; a leading `!` means "replace an
    /// existing destination".
    pub dst: String,
}

/// The value names of the boot-time move list under the session manager key.
pub const PENDING_VALUE_NAMES: [&str; 2] = [
    "PendingFileRenameOperations",
    "PendingFileRenameOperations2",
];

/// A pair found in the raw value, with the byte range it occupies.
struct PairSpan {
    bytes: std::ops::Range<usize>,
    src: Vec<u16>,
    dst: Vec<u16>,
}

/// Walks the raw value: `src NUL dst NUL` repeated, ended by an empty source. A destination may
/// be empty (delete), so this is not an ordinary `REG_MULTI_SZ` split. Stops at the first thing
/// that is not a complete pair; whatever follows is left alone by every caller.
fn scan_pairs(bytes: &[u8]) -> Vec<PairSpan> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < units.len() {
        let Some(src_len) = units[i..].iter().position(|&c| c == 0) else {
            break;
        };
        if src_len == 0 {
            break;
        }
        let dst_start = i + src_len + 1;
        let Some(dst_len) = units
            .get(dst_start..)
            .and_then(|rest| rest.iter().position(|&c| c == 0))
        else {
            break;
        };
        let end = dst_start + dst_len + 1;
        out.push(PairSpan {
            bytes: i * 2..end * 2,
            src: units[i..i + src_len].to_vec(),
            dst: units[dst_start..dst_start + dst_len].to_vec(),
        });
        i = end;
    }
    out
}

/// Decodes the raw bytes of a `PendingFileRenameOperations` value into pairs. Malformed trailing
/// data is ignored.
pub fn parse_pending_renames(bytes: &[u8]) -> Vec<PendingPair> {
    scan_pairs(bytes)
        .into_iter()
        .map(|p| PendingPair {
            src: String::from_utf16_lossy(&p.src),
            dst: String::from_utf16_lossy(&p.dst),
        })
        .collect()
}

/// Result of [`remove_pairs_from_value`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEdit {
    /// How many pair occurrences were cut.
    pub removed: usize,
    /// The new raw value. `None` means that no pair is left and the value should be deleted
    /// (only when `removed > 0`). With `removed == 0` this is the input, unchanged.
    pub value: Option<Vec<u8>>,
}

/// Cuts every occurrence of the pairs in `own` out of the raw bytes of a
/// `PendingFileRenameOperations` value. A pair matches only if source and destination are equal
/// unit for unit (case-sensitive). Every other byte, including pairs of other programs, the
/// terminator and any malformed tail, stays exactly as it was and in the same order.
pub fn remove_pairs_from_value(bytes: &[u8], own: &[PendingPair]) -> PendingEdit {
    let own: Vec<(Vec<u16>, Vec<u16>)> = own
        .iter()
        .map(|p| {
            (
                p.src.encode_utf16().collect(),
                p.dst.encode_utf16().collect(),
            )
        })
        .collect();
    let mut out = Vec::with_capacity(bytes.len());
    let mut copied = 0usize;
    let mut removed = 0usize;
    for span in scan_pairs(bytes) {
        if own.iter().any(|(s, d)| *s == span.src && *d == span.dst) {
            out.extend_from_slice(&bytes[copied..span.bytes.start]);
            copied = span.bytes.end;
            removed += 1;
        }
    }
    if removed == 0 {
        return PendingEdit {
            removed,
            value: Some(bytes.to_vec()),
        };
    }
    out.extend_from_slice(&bytes[copied..]);
    let empty = out.iter().all(|&b| b == 0);
    PendingEdit {
        removed,
        value: if empty { None } else { Some(out) },
    }
}

/// Cuts the occurrences of `pair` out of the raw bytes of a `PendingFileRenameOperations` value
/// if, and only if, there are exactly `expected` of them.
///
/// Equality is that of [`remove_pairs_from_value`]: source and destination equal unit for unit,
/// case-sensitive, a `*<digit>` marker included (a pair stored as `*1\??\C:\x` is not the pair
/// `\??\C:\x`; take the spelling from [`pending_renames`] or [`BootMove::pair`]). Every other byte
/// stays as it was and in the same order. With `expected == 0` and no occurrence the input comes
/// back unchanged with `removed == 0`.
///
/// Any other count gives [`FsError::PendingCountMismatch`] with the number found, and nothing is
/// edited.
pub fn remove_pair_exactly_from_value(
    bytes: &[u8],
    pair: &PendingPair,
    expected: usize,
) -> Result<PendingEdit, FsError> {
    let edit = remove_pairs_from_value(bytes, std::slice::from_ref(pair));
    if edit.removed != expected {
        return Err(FsError::PendingCountMismatch {
            found: u32::try_from(edit.removed).unwrap_or(u32::MAX),
        });
    }
    Ok(edit)
}

/// Where the boot-time move list is stored; lets the removal logic run against a stand-in.
trait PendingStore {
    /// Raw type and bytes of a value, `None` if it does not exist.
    fn read(&mut self, name: &str) -> Result<Option<(u32, Vec<u8>)>, Win32Error>;
    /// Replaces the value.
    fn write(&mut self, name: &str, ty: u32, data: &[u8]) -> Result<(), Win32Error>;
    /// Deletes the value.
    fn delete(&mut self, name: &str) -> Result<(), Win32Error>;
}

/// How many times [`remove_pairs_in`] writes one value before it gives up.
const MAX_PENDING_WRITES: usize = 8;

/// Removes `own` from both values of `store`. Each write is preceded by a second read that must
/// equal the first (compare before write), and followed by a new read, so the loop ends only when
/// a read shows none of the own pairs.
fn remove_pairs_in(store: &mut impl PendingStore, own: &[PendingPair]) -> Result<usize, FsError> {
    let mut total = 0usize;
    for name in PENDING_VALUE_NAMES {
        let mut writes = 0usize;
        while let Some((ty, before)) = store.read(name)? {
            if ty != REG_MULTI_SZ {
                break;
            }
            let edit = remove_pairs_from_value(&before, own);
            if edit.removed == 0 {
                break;
            }
            if writes == MAX_PENDING_WRITES {
                return Err(FsError::Other(ERROR_RETRY));
            }
            writes += 1;
            // Someone changed the list since the first read: start over from the new content.
            if store.read(name)? != Some((ty, before)) {
                continue;
            }
            match &edit.value {
                Some(v) => store.write(name, ty, v)?,
                None => store.delete(name)?,
            }
            total += edit.removed;
        }
    }
    Ok(total)
}

/// [`remove_pending_pairs_exactly`] against `store`: one read-modify-write of
/// `PendingFileRenameOperations`. The edit is written only if a second read equals the first;
/// otherwise nothing is written and the edit is redone from the new content, at most
/// [`MAX_PENDING_WRITES`] times.
fn remove_pair_exactly_in(
    store: &mut impl PendingStore,
    pair: &PendingPair,
    expected: usize,
) -> Result<usize, FsError> {
    let name = PENDING_VALUE_NAMES[0];
    for _ in 0..MAX_PENDING_WRITES {
        let before = store.read(name)?;
        let edit = match &before {
            Some((REG_MULTI_SZ, bytes)) => remove_pair_exactly_from_value(bytes, pair, expected)?,
            // No list (or not a list): the pair is there zero times.
            _ if expected == 0 => return Ok(0),
            _ => return Err(FsError::PendingCountMismatch { found: 0 }),
        };
        if edit.removed == 0 {
            return Ok(0);
        }
        if store.read(name)? != before {
            continue;
        }
        match &edit.value {
            Some(v) => store.write(name, REG_MULTI_SZ, v)?,
            None => store.delete(name)?,
        }
        return Ok(edit.removed);
    }
    Err(FsError::Other(ERROR_RETRY))
}

/// An open registry key, closed on drop.
struct OwnedKey(HKEY);

impl Drop for OwnedKey {
    fn drop(&mut self) {
        // SAFETY: the key came from RegOpenKeyExW and is closed exactly once.
        unsafe { RegCloseKey(self.0) };
    }
}

/// Opens `HKLM\SYSTEM\<current control set>\Control\Session Manager` in the 64-bit view.
fn open_session_manager(access: u32) -> Result<OwnedKey, Win32Error> {
    let path = wide(format!(
        r"SYSTEM\{}\Control\Session Manager",
        crate::reg::current_control_set()?
    ));
    let mut key: HKEY = ptr::null_mut();
    // SAFETY: `path` is NUL-terminated; `key` is a valid out-pointer.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            access | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    Win32Error::check(rc)?;
    Ok(OwnedKey(key))
}

/// The boot-time move list in the registry. The key is opened for writing only when a write is
/// actually needed.
struct RegistryPending {
    read_key: OwnedKey,
    write_key: Option<OwnedKey>,
}

impl RegistryPending {
    fn open() -> Result<RegistryPending, Win32Error> {
        Ok(RegistryPending {
            read_key: open_session_manager(KEY_QUERY_VALUE)?,
            write_key: None,
        })
    }

    fn write_key(&mut self) -> Result<HKEY, Win32Error> {
        if self.write_key.is_none() {
            self.write_key = Some(open_session_manager(KEY_QUERY_VALUE | KEY_SET_VALUE)?);
        }
        Ok(self.write_key.as_ref().map_or(ptr::null_mut(), |k| k.0))
    }
}

impl PendingStore for RegistryPending {
    fn read(&mut self, name: &str) -> Result<Option<(u32, Vec<u8>)>, Win32Error> {
        let name = wide(name);
        let mut buf = vec![0u8; 4096];
        loop {
            let mut ty = 0u32;
            let mut len = buf.len() as u32;
            // SAFETY: `name` is NUL-terminated; `buf` has `len` writable bytes; out-pointers are
            // locals.
            let rc = unsafe {
                RegQueryValueExW(
                    self.read_key.0,
                    name.as_ptr(),
                    ptr::null(),
                    &mut ty,
                    buf.as_mut_ptr(),
                    &mut len,
                )
            };
            match Win32Error::check(rc) {
                Ok(()) => {
                    buf.truncate(len as usize);
                    return Ok(Some((ty, buf)));
                }
                Err(Win32Error::MORE_DATA) => buf.resize((len as usize).max(buf.len() * 2), 0),
                Err(e) if e.is_not_found() => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }

    fn write(&mut self, name: &str, ty: u32, data: &[u8]) -> Result<(), Win32Error> {
        let key = self.write_key()?;
        let name = wide(name);
        let len = u32::try_from(data.len()).map_err(|_| Win32Error::INVALID_PARAMETER)?;
        // SAFETY: `key` is a live key opened with KEY_SET_VALUE; `name` is NUL-terminated;
        // `data` has `len` readable bytes.
        let rc = unsafe { RegSetValueExW(key, name.as_ptr(), 0, ty, data.as_ptr(), len) };
        Win32Error::check(rc)
    }

    fn delete(&mut self, name: &str) -> Result<(), Win32Error> {
        let key = self.write_key()?;
        let name = wide(name);
        // SAFETY: `key` is a live key opened with KEY_SET_VALUE; `name` is NUL-terminated.
        let rc = unsafe { RegDeleteValueW(key, name.as_ptr()) };
        Win32Error::check(rc)
    }
}

/// Every pair of the boot-time move list, `PendingFileRenameOperations` first, then
/// `PendingFileRenameOperations2`, in stored order. Read-only.
pub fn pending_renames() -> Result<Vec<PendingPair>, FsError> {
    let mut store = RegistryPending::open()?;
    let mut out = Vec::new();
    for name in PENDING_VALUE_NAMES {
        if let Some((REG_MULTI_SZ, bytes)) = store.read(name)? {
            out.extend(parse_pending_renames(&bytes));
        }
    }
    Ok(out)
}

/// Removes every occurrence of the pairs in `own` from the boot-time move list and returns how
/// many occurrences were cut. Pairs match only when source and destination are exactly equal;
/// all other content of the values stays byte-identical, and a value is deleted only when
/// nothing but terminators would be left in it.
///
/// The list is read, edited in memory, read again and written only if the second read equals the
/// first; then it is read once more, until a read shows none of the own pairs. The registry has no
/// compare-and-swap, so a writer that lands between the second read and the write can still be
/// overwritten; the window is two registry calls wide. If the list keeps changing, the call ends
/// with `FsError::Other(ERROR_RETRY)`.
///
/// Opens the key for writing only if there is something to remove, so it returns `Ok(0)` without
/// administrative rights when none of the pairs is listed.
pub fn remove_pending_pairs(own: &[PendingPair]) -> Result<usize, FsError> {
    let mut store = RegistryPending::open()?;
    remove_pairs_in(&mut store, own)
}

/// Removes the occurrences of `pair` from `PendingFileRenameOperations` only if the value holds
/// exactly `expected` of them, and returns that count. With any other count nothing is changed
/// and the call fails with [`FsError::PendingCountMismatch`], which carries the count found.
///
/// Equality is exact (see [`remove_pair_exactly_from_value`]); every other entry stays
/// byte-identical and in order, and the value is deleted only when nothing but terminators would
/// be left. `PendingFileRenameOperations2`, which `MoveFileExW` does not write, is neither read
/// nor changed.
///
/// One read-modify-write: the value is read, edited in memory, read again and written only if
/// the second read equals the first; if another program changed it in between, nothing is
/// written and the edit is redone from the new content (at most eight attempts, then
/// `FsError::Other(ERROR_RETRY)`). The registry has no compare-and-swap, so a writer that
/// lands between the second read and the write can still be overwritten.
///
/// Opens the key for writing only if something is to be removed: with `expected == 0` and the
/// pair absent it returns `Ok(0)` without administrative rights.
pub fn remove_pending_pairs_exactly(pair: &PendingPair, expected: usize) -> Result<usize, FsError> {
    let mut store = RegistryPending::open()?;
    remove_pair_exactly_in(&mut store, pair, expected)
}

/// NT form (`\??\C:\dir\name`) of an absolute path, the spelling `MoveFileExW` stores.
fn nt_string(path: &Path) -> Result<String, Win32Error> {
    let ext = extended_units(path)?;
    let mut nt: Vec<u16> = r"\??\".encode_utf16().collect();
    nt.extend_from_slice(&ext[4..]);
    Ok(String::from_utf16_lossy(&nt))
}

/// The pair [`move_delay_until_reboot`] registers for `src` and `dst` (both absolute).
pub fn pending_pair(src: &Path, dst: &Path) -> Result<PendingPair, FsError> {
    Ok(PendingPair {
        src: nt_string(src)?,
        dst: nt_string(dst)?,
    })
}

/// A boot-time move list entry (a [`PendingPair::src`] or [`PendingPair::dst`]) without the
/// leading `*<digits>` marker that newer Windows builds may write in front of the NT path:
/// `*1\??\C:\x` gives `\??\C:\x`. An entry without the marker comes back unchanged, and a `*` or
/// digits elsewhere are kept. A leading `!` (replace an existing destination) is not a marker and
/// is kept.
///
/// Use it to recognise a stored pair as the one [`pending_pair`] spells; the removal functions
/// compare exactly and need the stored spelling, marker included.
pub fn strip_marker(entry: &str) -> &str {
    match entry.strip_prefix('*') {
        Some(rest) => rest.trim_start_matches(|c: char| c.is_ascii_digit()),
        None => entry,
    }
}

/// What [`move_delay_until_reboot`] registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootMove {
    /// The pair exactly as it stands in the boot-time move list when `confirmed` is true (this
    /// is what [`remove_pending_pairs`] needs); otherwise the expected spelling from
    /// [`pending_pair`].
    pub pair: PendingPair,
    /// Whether the pair was found in the list right after the registration. If false, read
    /// [`pending_renames`] before relying on [`remove_pending_pairs`] to undo it.
    pub confirmed: bool,
}

/// Registers a rename of `src` to `dst` (both absolute, same volume) for the next boot:
/// `MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT)` without `MOVEFILE_REPLACE_EXISTING`, so an existing
/// destination makes the boot-time rename fail instead of being replaced. Needs administrative
/// rights. The rename is done by path at boot; the caller decides whether that is safe for `src`.
pub fn move_delay_until_reboot(src: &Path, dst: &Path) -> Result<BootMove, FsError> {
    let pair = pending_pair(src, dst)?;
    let s = ext_wide(src)?;
    let d = ext_wide(dst)?;
    // SAFETY: both strings are NUL-terminated.
    if unsafe { MoveFileExW(s.as_ptr(), d.as_ptr(), MOVEFILE_DELAY_UNTIL_REBOOT) } == 0 {
        return Err(Win32Error::last().into());
    }
    // Newer Windows builds may put a `*<digit>` marker in front of an entry; take the spelling
    // that is really in the list, so that a later removal matches it exactly.
    let found = pending_renames().ok().and_then(|list| {
        list.into_iter()
            .rev()
            .find(|p| strip_marker(&p.src) == pair.src && strip_marker(&p.dst) == pair.dst)
    });
    Ok(match found {
        Some(pair) => BootMove {
            pair,
            confirmed: true,
        },
        None => BootMove {
            pair,
            confirmed: false,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{IO_REPARSE_TAG_MOUNT_POINT, list_dir};
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use std::process::Command;

    /// A unique scratch directory under `std::env::temp_dir()`, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir()
                .join(format!("purge-fsw-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.0.join(rel)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            // The `\\?\` form reaches long paths and names ending in a dot; remove_dir_all
            // removes junctions as links.
            let _ = std::fs::remove_dir_all(extended_path(&self.0).unwrap());
        }
    }

    fn mklink_junction(link: &Path, target: &Path) {
        let st = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "mklink /J failed");
    }

    fn ext(p: &Path) -> PathBuf {
        extended_path(p).unwrap()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = list_dir(dir).unwrap().into_iter().map(|e| e.name).collect();
        v.sort();
        v
    }

    /// Renames `h` to the absolute path `dest` through the one public route: a [`DestDir`] on the
    /// parent and the leaf name.
    fn move_to(h: &MoveHandle, dest: &Path) -> Result<(), FsError> {
        let (Some(parent), Some(leaf)) = (dest.parent(), dest.file_name()) else {
            return Err(FsError::Other(87));
        };
        h.rename_into(&DestDir::open(parent)?, leaf.to_str().unwrap())
    }

    /// Creates a file symbolic link, or says loudly why the caller has to skip: creating one
    /// needs a privilege or developer mode.
    fn try_symlink_file(target: &Path, link: &Path, test: &str) -> bool {
        match std::os::windows::fs::symlink_file(target, link) {
            Ok(()) => true,
            Err(e) => {
                eprintln!(
                    "SKIPPED part of {test}: cannot create a file symbolic link without \
                     elevation or developer mode ({e})"
                );
                false
            }
        }
    }

    #[test]
    fn rename_file_keeps_identity_and_never_replaces() {
        let s = Scratch::new("file");
        let (a, b, c) = (s.path("a.txt"), s.path("b.txt"), s.path("c.txt"));
        std::fs::write(&a, b"alpha").unwrap();
        std::fs::write(&c, b"gamma").unwrap();

        let h = MoveHandle::open(&a).unwrap();
        assert!(h.has_read_control());
        let id = h.file_id().unwrap();
        let before = h.metadata().unwrap();

        // An existing destination is never replaced, whether file or directory.
        assert_eq!(move_to(&h, &c), Err(FsError::AlreadyExists));
        assert_eq!(move_to(&h, &s.0), Err(FsError::AlreadyExists));
        assert_eq!(std::fs::read(&c).unwrap(), b"gamma");
        assert_eq!(std::fs::read(&a).unwrap(), b"alpha");

        move_to(&h, &b).unwrap();
        assert!(!a.exists());
        assert_eq!(std::fs::read(&b).unwrap(), b"alpha");
        // The handle follows the file.
        assert_eq!(h.file_id().unwrap(), id);
        let canon = std::fs::canonicalize(&b).unwrap();
        assert!(
            h.final_path()
                .unwrap()
                .eq_ignore_ascii_case(&canon.to_string_lossy())
        );
        let after = h.metadata().unwrap();
        assert_eq!(
            (after.size, after.creation_time, after.last_write_time),
            (before.size, before.creation_time, before.last_write_time)
        );
        assert_eq!(crate::fs::file_id(&b).unwrap(), id);

        // And back again on the same handle (the undo direction).
        move_to(&h, &a).unwrap();
        assert_eq!(names(&s.0), ["a.txt", "c.txt"]);

        // Missing parent, missing source, relative destination.
        assert_eq!(
            move_to(&h, &s.path(r"no-such-dir\x.txt")),
            Err(FsError::NotFound)
        );
        assert_eq!(
            MoveHandle::open(&s.path("missing")).unwrap_err(),
            FsError::NotFound
        );
        assert_eq!(
            move_to(&h, Path::new("relative.txt")),
            Err(FsError::Other(87))
        );
        assert_eq!(std::fs::read(&a).unwrap(), b"alpha");
    }

    #[test]
    fn rename_directory_with_content() {
        let s = Scratch::new("dir");
        let src = s.path("app");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join(r"sub\f.bin"), [7u8; 100]).unwrap();
        let q = s.path("q");
        std::fs::create_dir(&q).unwrap();

        let h = MoveHandle::open(&src).unwrap();
        let id = h.file_id().unwrap();
        assert!(h.metadata().unwrap().is_dir);
        let child_id = crate::fs::file_id(&src.join(r"sub\f.bin")).unwrap();
        move_to(&h, &q.join("app")).unwrap();
        assert!(!src.exists());
        assert_eq!(crate::fs::file_id(&q.join("app")).unwrap(), id);
        assert_eq!(
            crate::fs::file_id(&q.join(r"app\sub\f.bin")).unwrap(),
            child_id
        );
        assert_eq!(std::fs::read(q.join(r"app\sub\f.bin")).unwrap(), [7u8; 100]);

        // A directory is not renamed onto an existing one.
        std::fs::create_dir(&src).unwrap();
        assert_eq!(move_to(&h, &src), Err(FsError::AlreadyExists));
    }

    #[test]
    fn rename_into_directory_handle() {
        let s = Scratch::new("into");
        let f = s.path("f.txt");
        std::fs::write(&f, b"x").unwrap();
        let q = s.path("q");
        std::fs::create_dir(&q).unwrap();
        std::fs::write(q.join("taken"), b"y").unwrap();
        let q_handle = crate::secure::open_for_security(&q).unwrap();

        let h = MoveHandle::open(&f).unwrap();
        let id = h.file_id().unwrap();
        assert_eq!(
            h.rename_into(&q_handle, "taken"),
            Err(FsError::AlreadyExists)
        );
        for bad in ["", ".", "..", r"a\b", "a/b", "a:b", "a::$DATA", "a\0b"] {
            assert_eq!(
                h.rename_into(&q_handle, bad),
                Err(FsError::Other(87)),
                "{bad:?}"
            );
        }
        // A destination handle that is not a plain directory is refused: a file, a junction.
        let other = s.path("other.txt");
        std::fs::write(&other, b"o").unwrap();
        let file_handle = DestDir::open(&other).unwrap();
        assert!(!file_handle.facts().unwrap().is_dir);
        assert_eq!(h.rename_into(&file_handle, "x"), Err(FsError::WrongKind));
        let link = s.path("link");
        mklink_junction(&link, &q);
        let link_handle = DestDir::open(&link).unwrap();
        let link_facts = link_handle.facts().unwrap();
        assert_eq!(link_facts.reparse_tag, IO_REPARSE_TAG_MOUNT_POINT);
        assert!(link_facts.is_dir && !link_facts.is_plain_dir());
        assert_eq!(h.rename_into(&link_handle, "x"), Err(FsError::WrongKind));
        drop(link_handle);
        std::fs::remove_dir(&link).unwrap();
        std::fs::remove_file(&other).unwrap();
        assert!(f.exists());
        assert_eq!(names(&q), ["taken"]);

        // The directory handle, not its path, names the destination: rename the directory away
        // and the file still lands inside it.
        let q2 = s.path("q-renamed");
        std::fs::rename(&q, &q2).unwrap();
        h.rename_into(&q_handle, "moved. ").unwrap();
        assert!(!f.exists());
        assert_eq!(names(&q2), ["moved. ", "taken"]);
        assert_eq!(crate::fs::file_id(&ext(&q2).join("moved. ")).unwrap(), id);
        assert_eq!(names(&s.0), ["q-renamed"]);
    }

    #[test]
    fn a_destination_swapped_for_a_junction_after_the_check_does_not_receive_the_file() {
        // Review finding B1: the gate checks the destination directory through a handle; the
        // rename must land in that directory, not in whatever its path names by then.
        let s = Scratch::new("swap");
        let (userdir, protected, quarantine) =
            (s.path("userdir"), s.path("protected"), s.path("quarantine"));
        for d in [&userdir, &protected, &quarantine] {
            std::fs::create_dir(d).unwrap();
        }
        let payload = quarantine.join("payload.dll");
        std::fs::write(&payload, b"payload").unwrap();
        let mover = MoveHandle::open(&payload).unwrap();

        // The check: a plain directory on the item's volume, at the path it was asked about.
        let checked = DestDir::open(&userdir).unwrap();
        let facts = checked.facts().unwrap();
        assert!(facts.is_plain_dir(), "{facts:?}");
        assert_eq!(
            facts.volume_serial(),
            mover.file_id().unwrap().volume_serial
        );
        let canon = std::fs::canonicalize(&userdir).unwrap();
        assert!(
            facts
                .final_path
                .eq_ignore_ascii_case(&canon.to_string_lossy())
        );

        // Between check and act the directory is renamed away and a junction to a protected
        // directory takes its name.
        let old = s.path("userdir.old");
        std::fs::rename(&userdir, &old).unwrap();
        mklink_junction(&userdir, &protected);

        mover.rename_into(&checked, "payload.dll").unwrap();
        assert_eq!(names(&old), ["payload.dll"]);
        assert_eq!(std::fs::read(old.join("payload.dll")).unwrap(), b"payload");
        assert!(names(&protected).is_empty());
        assert!(names(&quarantine).is_empty());

        // A fresh look at the path sees the junction, and a rename into it is refused.
        let fresh = DestDir::open(&userdir).unwrap();
        assert_eq!(
            fresh.facts().unwrap().reparse_tag,
            IO_REPARSE_TAG_MOUNT_POINT
        );
        assert_eq!(
            mover.rename_into(&fresh, "payload.dll"),
            Err(FsError::WrongKind)
        );
        assert!(names(&protected).is_empty());
        assert_eq!(names(&old), ["payload.dll"]);
    }

    #[test]
    fn a_directory_with_an_open_handle_below_is_reported_as_possibly_in_use() {
        // Review finding S8: NTFS refuses to rename a directory with ERROR_ACCESS_DENIED while a
        // handle is open anywhere below it, whatever that handle shares.
        let s = Scratch::new("inuse");
        let app = s.path("app");
        std::fs::create_dir_all(app.join("sub")).unwrap();
        std::fs::write(app.join(r"sub\held.txt"), b"x").unwrap();
        let q = DestDir::open(&s.0).unwrap();
        let h = MoveHandle::open(&app).unwrap();

        let read_only_sharing = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(app.join(r"sub\held.txt"))
            .unwrap();
        assert_eq!(
            h.rename_into(&q, "app-moved"),
            Err(FsError::DirInUseOrDenied)
        );
        drop(read_only_sharing);
        let full_sharing = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(app.join(r"sub\held.txt"))
            .unwrap();
        assert_eq!(
            h.rename_into(&q, "app-moved"),
            Err(FsError::DirInUseOrDenied)
        );
        drop(full_sharing);
        // An attribute-only handle on a subdirectory is enough.
        let sub = crate::fs::FileHandle::open(&app.join("sub")).unwrap();
        let err = h.rename_into(&q, "app-moved").unwrap_err();
        assert_eq!(err, FsError::DirInUseOrDenied);
        assert_eq!(err.code(), 5);
        drop(sub);
        assert!(app.exists());

        // With every handle below closed, the same rename goes through.
        h.rename_into(&q, "app-moved").unwrap();
        assert_eq!(names(&s.0), ["app-moved"]);

        // A file keeps the plain mapping: a holder without delete sharing stops the open.
        let f = s.path(r"app-moved\sub\held.txt");
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&f)
            .unwrap();
        assert_eq!(MoveHandle::open(&f).unwrap_err(), FsError::SharingViolation);
        drop(holder);
    }

    #[test]
    fn creation_never_follows_a_dangling_link() {
        // Review finding S7: CREATE_NEW alone follows a dangling file symbolic link and creates
        // its target.
        let s = Scratch::new("dangling");
        let me = crate::sid::current_user_sid().unwrap();
        let sddl = format!("D:P(A;OICI;FA;;;{me})");

        // A junction to a missing directory needs no privilege.
        let junction = s.path("journal-j");
        mklink_junction(&junction, &s.path("victim-j"));
        assert_eq!(
            create_file_secure(&junction, &sddl).unwrap_err(),
            FsError::AccessDenied
        );
        assert_eq!(
            create_dir_secure(&junction, &sddl),
            Err(FsError::AlreadyExists)
        );
        assert!(!s.path("victim-j").exists());
        assert_ne!(crate::fs::metadata(&junction).unwrap().reparse_tag, 0);

        if !try_symlink_file(
            &s.path("victim.txt"),
            &s.path("journal.jsonl"),
            "creation_never_follows_a_dangling_link",
        ) {
            return;
        }
        let link = s.path("journal.jsonl");
        assert_eq!(
            create_file_secure(&link, &sddl).unwrap_err(),
            FsError::AlreadyExists
        );
        assert_eq!(create_dir_secure(&link, &sddl), Err(FsError::AlreadyExists));
        assert!(!s.path("victim.txt").exists());
        assert_eq!(
            crate::fs::metadata(&link).unwrap().reparse_tag,
            crate::fs::IO_REPARSE_TAG_SYMLINK
        );

        // A directory symbolic link to a missing directory, likewise.
        let dir_link = s.path("dir-link");
        if std::os::windows::fs::symlink_dir(s.path("victim-d"), &dir_link).is_ok() {
            assert_eq!(
                create_file_secure(&dir_link, &sddl).unwrap_err(),
                FsError::AccessDenied
            );
            assert_eq!(
                create_dir_secure(&dir_link, &sddl),
                Err(FsError::AlreadyExists)
            );
            assert!(!s.path("victim-d").exists());
        }
        for victim in ["victim-j", "victim.txt", "victim-d"] {
            assert!(!names(&s.0).contains(&victim.to_string()), "{victim}");
        }
    }

    #[test]
    fn stream_syntax_is_refused_by_every_path_wrapper() {
        // Review finding M3: `name::$DATA` reached the file itself, `dir::$INDEX_ALLOCATION` the
        // directory, `name:stream` one stream.
        let s = Scratch::new("streams");
        let host = s.path("host.txt");
        std::fs::write(&host, b"main").unwrap();
        std::fs::write(s.path("host.txt:second"), b"2").unwrap();
        let dir = s.path("dir");
        std::fs::create_dir(&dir).unwrap();
        let sddl = format!("D:P(A;;FA;;;{})", crate::sid::current_user_sid().unwrap());
        let inv = FsError::Other(87);
        let spell = |p: &Path, suffix: &str| PathBuf::from(format!("{}{suffix}", p.display()));

        for p in [
            spell(&host, "::$DATA"),
            spell(&host, ":second"),
            spell(&host, ":second:$DATA"),
            spell(&dir, "::$INDEX_ALLOCATION"),
            spell(&dir, ":$I30:$INDEX_ALLOCATION"),
            ext(&host).join("::$DATA"),
            PathBuf::from(format!("{}::$DATA", ext(&host).display())),
        ] {
            assert_eq!(MoveHandle::open(&p).unwrap_err(), inv, "{p:?}");
            assert_eq!(
                MoveHandle::open_with_attribute_write(&p).unwrap_err(),
                inv,
                "{p:?}"
            );
            assert_eq!(DestDir::open(&p).unwrap_err(), inv, "{p:?}");
            assert_eq!(list_streams(&p).unwrap_err(), inv, "{p:?}");
            assert_eq!(flush_dir(&p), Err(inv), "{p:?}");
            assert_eq!(create_dir_secure(&p, &sddl), Err(inv), "{p:?}");
            assert_eq!(create_file_secure(&p, &sddl).unwrap_err(), inv, "{p:?}");
            assert_eq!(pending_pair(&p, &dir).unwrap_err(), inv, "{p:?}");
            assert_eq!(pending_pair(&dir, &p).unwrap_err(), inv, "{p:?}");
            assert_eq!(move_delay_until_reboot(&p, &dir).unwrap_err(), inv, "{p:?}");
        }
        let new_stream = spell(&host, ":new");
        assert_eq!(create_file_secure(&new_stream, &sddl).unwrap_err(), inv);
        assert_eq!(std::fs::read(&host).unwrap(), b"main");
        assert_eq!(list_streams(&host).unwrap().len(), 2);
        assert!(dir.is_dir());
    }

    #[test]
    fn junction_is_moved_and_deleted_as_a_link() {
        let s = Scratch::new("junction");
        let target = s.path("real");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("inside.txt"), b"keep me").unwrap();
        let link = s.path("link");
        mklink_junction(&link, &target);
        let target_id = crate::fs::file_id(&target).unwrap();

        let h = MoveHandle::open(&link).unwrap();
        assert_eq!(h.reparse_tag().unwrap(), IO_REPARSE_TAG_MOUNT_POINT);
        let link_id = h.file_id().unwrap();
        assert_ne!(link_id, target_id);
        // A junction is not an "empty directory" for delete-if-empty.
        assert_eq!(h.remove_dir_if_empty(), Err(FsError::WrongKind));

        let moved = s.path("moved-link");
        move_to(&h, &moved).unwrap();
        assert!(!link.exists());
        let m = crate::fs::metadata(&moved).unwrap();
        assert_eq!(m.reparse_tag, IO_REPARSE_TAG_MOUNT_POINT);
        assert_eq!(m.file_id, link_id);
        // The target did not move and still holds its file; the link still resolves to it.
        assert_eq!(crate::fs::file_id(&target).unwrap(), target_id);
        assert_eq!(names(&target), ["inside.txt"]);
        assert_eq!(std::fs::read(moved.join("inside.txt")).unwrap(), b"keep me");

        h.delete(false).unwrap();
        drop(h);
        assert_eq!(names(&s.0), ["real"]);
        assert_eq!(
            std::fs::read(target.join("inside.txt")).unwrap(),
            b"keep me"
        );
        assert_eq!(crate::fs::file_id(&target).unwrap(), target_id);
    }

    #[test]
    fn file_symlink_is_deleted_as_a_link() {
        let s = Scratch::new("symlink");
        let target = s.path("target.txt");
        std::fs::write(&target, b"keep me").unwrap();
        let link = s.path("link.txt");
        if !try_symlink_file(&target, &link, "file_symlink_is_deleted_as_a_link") {
            return;
        }
        let h = MoveHandle::open(&link).unwrap();
        assert_eq!(h.reparse_tag().unwrap(), crate::fs::IO_REPARSE_TAG_SYMLINK);
        move_to(&h, &s.path("moved.txt")).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"keep me");
        h.delete(false).unwrap();
        drop(h);
        assert_eq!(names(&s.0), ["target.txt"]);
        assert_eq!(std::fs::read(&target).unwrap(), b"keep me");
    }

    #[test]
    fn long_path_and_trailing_dot_names() {
        let s = Scratch::new("long");
        let mut deep = s.0.clone();
        for i in 0..8 {
            deep.push(format!("{i}-{}", "d".repeat(40)));
        }
        assert!(deep.as_os_str().len() > 300);
        std::fs::create_dir_all(ext(&deep)).unwrap();

        // Names that Win32 normalisation would change: trailing dot, trailing space.
        let dotted = deep.join("name.");
        let spaced = deep.join("name ");
        std::fs::write(ext(&dotted), b"dot").unwrap();
        std::fs::write(ext(&spaced), b"space").unwrap();
        assert_eq!(names(&ext(&deep)), ["name ", "name."]);

        let h = MoveHandle::open(&dotted).unwrap();
        assert_eq!(h.metadata().unwrap().size, 3);
        assert!(h.final_path().unwrap().ends_with(r"\name."));
        let dest = deep.join("moved..");
        move_to(&h, &dest).unwrap();
        assert_eq!(names(&ext(&deep)), ["moved..", "name "]);
        assert_eq!(std::fs::read(ext(&dest)).unwrap(), b"dot");
        assert_eq!(list_streams(&dest).unwrap().len(), 1);

        // Out of the deep directory into a short one and back, by absolute path.
        let short = s.path("short. ");
        move_to(&h, &short).unwrap();
        assert_eq!(names(&s.0).len(), 2);
        assert!(names(&s.0).contains(&"short. ".to_string()));
        move_to(&h, &dotted).unwrap();
        assert_eq!(names(&ext(&deep)), ["name ", "name."]);

        let sp = MoveHandle::open(&spaced).unwrap();
        sp.delete(false).unwrap();
        drop(sp);
        assert_eq!(names(&ext(&deep)), ["name."]);

        // A long directory, removed when empty.
        let d = MoveHandle::open(&deep).unwrap();
        assert_eq!(d.remove_dir_if_empty(), Err(FsError::DirNotEmpty));
        h.delete(false).unwrap();
        drop(h);
        d.remove_dir_if_empty().unwrap();
        drop(d);
        assert!(!ext(&deep).exists());
    }

    #[test]
    fn readonly_hidden_file_keeps_attributes() {
        let s = Scratch::new("attrs");
        let f = s.path("ro.dat");
        std::fs::write(&f, b"data").unwrap();
        let h = MoveHandle::open_with_attribute_write(&f).unwrap();
        let base = h.metadata().unwrap().attributes;
        let written = h
            .set_attributes(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN, 0)
            .unwrap();
        assert_eq!(
            written,
            base | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN
        );
        drop(h);

        // The plain move handle is enough to move a read-only, hidden file.
        let h = MoveHandle::open(&f).unwrap();
        let before = h.metadata().unwrap();
        assert_eq!(before.attributes, written);
        let dest = s.path("moved.dat");
        move_to(&h, &dest).unwrap();
        let after = crate::fs::metadata(&dest).unwrap();
        assert_eq!(after.attributes, written);
        assert_eq!(after.last_write_time, before.last_write_time);
        assert_eq!(after.file_id, before.file_id);

        // It has no attribute-write access, and a read-only file is not deleted by default.
        assert_eq!(
            h.set_attributes(0, FILE_ATTRIBUTE_HIDDEN),
            Err(FsError::AccessDenied)
        );
        assert_eq!(h.delete(false), Err(FsError::AccessDenied));
        assert!(dest.exists());
        assert_eq!(h.set_attributes(0x10, 0), Err(FsError::Other(87)));
        assert_eq!(h.set_attributes(1, 1), Err(FsError::Other(87)));
        h.delete(true).unwrap();
        drop(h);
        assert!(names(&s.0).is_empty());
    }

    #[test]
    fn set_attributes_on_directory_and_clear_all() {
        let s = Scratch::new("dirattrs");
        let d = s.path("q");
        std::fs::create_dir(&d).unwrap();
        let h = MoveHandle::open_with_attribute_write(&d).unwrap();
        let hidden =
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
        h.set_attributes(hidden, 0).unwrap();
        let m = crate::fs::metadata(&d).unwrap();
        assert_eq!(m.attributes & hidden, hidden);
        assert!(m.is_dir);
        let times = (m.creation_time, m.last_write_time);
        assert_eq!(h.set_attributes(0, CHANGEABLE_ATTRIBUTES).unwrap(), 0);
        let m = crate::fs::metadata(&d).unwrap();
        assert_eq!(m.attributes & CHANGEABLE_ATTRIBUTES, 0);
        assert_eq!((m.creation_time, m.last_write_time), times);

        // A read-only directory is still removed when empty.
        h.set_attributes(FILE_ATTRIBUTE_READONLY, 0).unwrap();
        h.remove_dir_if_empty().unwrap();
        drop(h);
        assert!(!d.exists());
    }

    #[test]
    fn hard_link_count_survives_a_move() {
        let s = Scratch::new("hardlink");
        let (a, b) = (s.path("a.bin"), s.path("b.bin"));
        std::fs::write(&a, b"shared").unwrap();
        std::fs::hard_link(&a, &b).unwrap();
        let q = s.path("q");
        std::fs::create_dir(&q).unwrap();

        let h = MoveHandle::open(&a).unwrap();
        assert_eq!(h.metadata().unwrap().n_links, 2);
        let id = h.file_id().unwrap();
        move_to(&h, &q.join("a.bin")).unwrap();
        // Only the one name moved; the other name and the link count are as before.
        assert_eq!(h.metadata().unwrap().n_links, 2);
        assert_eq!(crate::fs::file_id(&b).unwrap(), id);
        assert_eq!(std::fs::read(&b).unwrap(), b"shared");
        assert!(!a.exists());

        // Deleting through the handle removes that one name only.
        h.delete(false).unwrap();
        drop(h);
        assert!(names(&q).is_empty());
        assert_eq!(crate::fs::metadata(&b).unwrap().n_links, 1);
        assert_eq!(std::fs::read(&b).unwrap(), b"shared");
    }

    #[test]
    fn remove_dir_if_empty_mapping() {
        let s = Scratch::new("empty");
        let d = s.path("d");
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join("child"), b"").unwrap();

        let h = MoveHandle::open(&d).unwrap();
        assert_eq!(h.remove_dir_if_empty(), Err(FsError::DirNotEmpty));
        assert_eq!(h.delete(true), Err(FsError::WrongKind));
        assert!(d.join("child").exists());

        let f = MoveHandle::open(&d.join("child")).unwrap();
        assert_eq!(f.remove_dir_if_empty(), Err(FsError::WrongKind));
        f.delete(false).unwrap();
        drop(f);

        h.remove_dir_if_empty().unwrap();
        drop(h);
        assert!(!d.exists());
        assert_eq!(FsError::DirNotEmpty.code(), 145);
        assert_eq!(FsError::from(Win32Error(17)), FsError::NotSameDevice);
        assert_eq!(FsError::from(Win32Error(33)), FsError::SharingViolation);
        assert_eq!(FsError::from(Win32Error(80)), FsError::AlreadyExists);
        assert_eq!(FsError::from(Win32Error(1)), FsError::Other(1));
        assert_eq!(FsError::Other(1).code(), 1);
        assert_eq!(FsError::NotSameDevice.to_string(), "not on the same volume");
    }

    #[test]
    fn sharing_violation_is_typed() {
        let s = Scratch::new("share");
        let f = s.path("held.txt");
        std::fs::write(&f, b"x").unwrap();
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&f)
            .unwrap();
        assert_eq!(MoveHandle::open(&f).unwrap_err(), FsError::SharingViolation);
        drop(holder);
        MoveHandle::open(&f).unwrap();
    }

    #[test]
    fn secure_directory_and_file_creation() {
        let s = Scratch::new("secure");
        let me = crate::sid::current_user_sid().unwrap();
        let sddl = format!("D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)");
        let d = s.path(".purge-q");
        create_dir_secure(&d, &sddl).unwrap();

        let h = MoveHandle::open(&d).unwrap();
        let sec = h.security().unwrap();
        assert!(sec.dacl_protected, "{}", sec.sddl);
        assert!(sec.sddl.contains("D:P"), "{}", sec.sddl);
        let aces = sec.aces();
        assert_eq!(aces.len(), 2, "{}", sec.sddl);
        assert!(aces.iter().all(|a| a.is_allow() && !a.is_inherited()));
        assert_eq!(aces[0].sid.as_deref(), Some(me.as_str()));
        assert_eq!(aces[1].sid.as_deref(), Some(crate::sid::LOCAL_SYSTEM_SID));
        assert_eq!(aces[0].mask, 0x001F_01FF);
        assert!(sec.owner.is_some());
        assert_eq!(
            crate::secure::handle_sddl(&crate::secure::open_for_security(&d).unwrap()).unwrap(),
            sec.sddl
        );
        drop(h);

        // Anything already there is refused, never adopted: directory, file, junction.
        assert_eq!(create_dir_secure(&d, &sddl), Err(FsError::AlreadyExists));
        let file = s.path("plain");
        std::fs::write(&file, b"").unwrap();
        assert_eq!(create_dir_secure(&file, &sddl), Err(FsError::AlreadyExists));
        let link = s.path("planted");
        mklink_junction(&link, &d);
        assert_eq!(create_dir_secure(&link, &sddl), Err(FsError::AlreadyExists));
        assert_eq!(
            create_file_secure(&link, &sddl).unwrap_err(),
            FsError::AccessDenied
        );
        assert!(names(&d).is_empty());
        assert_eq!(
            create_dir_secure(&s.path(r"missing\child"), &sddl),
            Err(FsError::NotFound)
        );
        assert!(matches!(
            create_dir_secure(&s.path("bad"), "not sddl"),
            Err(FsError::Other(_))
        ));
        assert!(!s.path("bad").exists());

        // A file with its own descriptor, written, flushed and read back.
        use std::io::Write;
        let idx = d.join("index.json.tmp");
        let file_sddl = format!("D:P(A;;FA;;;{me})(A;;FR;;;BU)");
        let mut f = create_file_secure(&idx, &file_sddl).unwrap();
        f.write_all(b"{}").unwrap();
        flush(&f).unwrap();
        drop(f);
        assert_eq!(std::fs::read(&idx).unwrap(), b"{}");
        let fsec = crate::secure::handle_security(&crate::secure::open_for_security(&idx).unwrap())
            .unwrap();
        assert!(fsec.dacl_protected);
        assert_eq!(fsec.aces().len(), 2);
        assert_eq!(fsec.aces()[1].sid.as_deref(), Some("S-1-5-32-545"));
        assert_eq!(
            create_file_secure(&idx, &file_sddl).unwrap_err(),
            FsError::AlreadyExists
        );
        assert_eq!(std::fs::read(&idx).unwrap(), b"{}");

        flush_dir(&d).unwrap();
        assert_eq!(flush_dir(&idx), Err(FsError::WrongKind));
        assert_eq!(flush_dir(&link), Err(FsError::WrongKind));
    }

    #[test]
    fn alternate_data_streams_are_listed_and_move_with_the_file() {
        let s = Scratch::new("ads");
        let f = s.path("host.txt");
        std::fs::write(&f, b"main").unwrap();
        std::fs::write(s.path("host.txt:Zone.Identifier"), b"[ZoneTransfer]").unwrap();
        std::fs::write(s.path("host.txt:second"), b"").unwrap();

        let mut streams = list_streams(&f).unwrap();
        streams.sort_by(|a, b| a.name.cmp(&b.name));
        let got: Vec<(&str, u64)> = streams.iter().map(|s| (s.name.as_str(), s.size)).collect();
        assert_eq!(
            got,
            [
                ("::$DATA", 4),
                (":Zone.Identifier:$DATA", 14),
                (":second:$DATA", 0)
            ]
        );
        assert!(streams[0].is_default() && !streams[1].is_default());

        let h = MoveHandle::open(&f).unwrap();
        let dest = s.path("moved.txt");
        move_to(&h, &dest).unwrap();
        let mut after = h.streams().unwrap();
        after.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(after, streams);
        assert_eq!(
            std::fs::read(s.path("moved.txt:Zone.Identifier")).unwrap(),
            b"[ZoneTransfer]"
        );

        // A directory has no stream until one is added.
        let d = s.path("dir");
        std::fs::create_dir(&d).unwrap();
        assert!(list_streams(&d).unwrap().is_empty());
        std::fs::write(s.path("dir:tag"), b"abc").unwrap();
        let ds = list_streams(&d).unwrap();
        assert_eq!(ds.len(), 1);
        assert_eq!((ds[0].name.as_str(), ds[0].size), (":tag:$DATA", 3));
        assert_eq!(
            list_streams(&s.path("missing")).unwrap_err(),
            FsError::NotFound
        );
    }

    fn multi(strings: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for s in strings {
            for u in s.encode_utf16().chain(std::iter::once(0)) {
                out.extend_from_slice(&u.to_le_bytes());
            }
        }
        out
    }

    fn pair(src: &str, dst: &str) -> PendingPair {
        PendingPair {
            src: src.into(),
            dst: dst.into(),
        }
    }

    #[test]
    fn pending_value_parsing() {
        // Two moves, one delete (empty destination), one replacing move, then the terminator.
        let v = multi(&[
            r"\??\C:\a\old.dll",
            r"\??\C:\a\new.dll",
            r"\??\C:\tmp\junk.tmp",
            "",
            r"\??\C:\b\x",
            r"!\??\C:\b\y",
            "",
        ]);
        let pairs = parse_pending_renames(&v);
        assert_eq!(
            pairs,
            [
                pair(r"\??\C:\a\old.dll", r"\??\C:\a\new.dll"),
                pair(r"\??\C:\tmp\junk.tmp", ""),
                pair(r"\??\C:\b\x", r"!\??\C:\b\y"),
            ]
        );
        assert!(parse_pending_renames(&[]).is_empty());
        assert!(parse_pending_renames(&[0, 0]).is_empty());
        // No terminator after the last pair, an odd trailing byte, an unterminated tail.
        let mut loose = multi(&["s", "d"]);
        assert_eq!(parse_pending_renames(&loose), [pair("s", "d")]);
        loose.push(0x41);
        assert_eq!(parse_pending_renames(&loose), [pair("s", "d")]);
        let mut tail = multi(&["s", "d"]);
        tail.extend_from_slice(&[0x41, 0, 0x42, 0]);
        assert_eq!(parse_pending_renames(&tail), [pair("s", "d")]);
        // A source without any destination is not a pair.
        assert!(parse_pending_renames(&multi(&["only"])).is_empty());
    }

    #[test]
    fn pending_removal_leaves_foreign_pairs_byte_identical() {
        let foreign_a = multi(&[r"\??\C:\Windows\a.tmp", ""]);
        let ours_1 = multi(&[
            r"\??\C:\App\locked.dll",
            r"\??\C:\ProgramData\Purge\Q\1\locked.dll",
        ]);
        let foreign_b = multi(&[r"\??\C:\x\Old.exe", r"!\??\C:\x\New.exe"]);
        let ours_2 = multi(&[r"\??\C:\App\b", r"\??\C:\ProgramData\Purge\Q\2\b"]);
        // Same source as ours but another destination, and ours in another letter case.
        let near_1 = multi(&[r"\??\C:\App\locked.dll", ""]);
        let near_2 = multi(&[
            r"\??\c:\app\locked.dll",
            r"\??\C:\ProgramData\Purge\Q\1\locked.dll",
        ]);
        let term = vec![0u8, 0];
        let value = [
            &foreign_a[..],
            &ours_1,
            &foreign_b,
            &near_1,
            &ours_2,
            &near_2,
            &ours_1,
            &term,
        ]
        .concat();
        let own = [
            pair(
                r"\??\C:\App\locked.dll",
                r"\??\C:\ProgramData\Purge\Q\1\locked.dll",
            ),
            pair(r"\??\C:\App\b", r"\??\C:\ProgramData\Purge\Q\2\b"),
            pair(r"\??\C:\never\registered", "x"),
        ];
        let edit = remove_pairs_from_value(&value, &own);
        assert_eq!(edit.removed, 3);
        let expect = [&foreign_a[..], &foreign_b, &near_1, &near_2, &term].concat();
        assert_eq!(edit.value.as_deref(), Some(&expect[..]));

        // Nothing of ours: the bytes come back untouched.
        let none = remove_pairs_from_value(&expect, &own);
        assert_eq!(
            (none.removed, none.value.as_deref()),
            (0, Some(&expect[..]))
        );

        // Only ours: nothing but the terminator is left, so the value goes.
        let only = [&ours_1[..], &ours_2, &term].concat();
        let gone = remove_pairs_from_value(&only, &own);
        assert_eq!((gone.removed, gone.value), (2, None));
        let unterminated = remove_pairs_from_value(&ours_1, &own);
        assert_eq!((unterminated.removed, unterminated.value), (1, None));

        // A malformed tail (odd byte, half a pair) survives byte for byte.
        let junk = [0x41u8, 0, 0x42, 0, 0x43];
        let with_junk = [&ours_2[..], &foreign_a, &junk].concat();
        let kept = remove_pairs_from_value(&with_junk, &own);
        assert_eq!(kept.removed, 1);
        assert_eq!(kept.value.unwrap(), [&foreign_a[..], &junk].concat());
        let junk_only = [&ours_2[..], &junk].concat();
        assert_eq!(
            remove_pairs_from_value(&junk_only, &own).value.unwrap(),
            junk
        );

        // A delete entry of ours is matched with its empty destination only.
        let del = multi(&[r"\??\C:\App\b", "", r"\??\C:\keep", "", ""]);
        let e = remove_pairs_from_value(&del, &[pair(r"\??\C:\App\b", "")]);
        assert_eq!(e.removed, 1);
        assert_eq!(e.value.unwrap(), multi(&[r"\??\C:\keep", "", ""]));
        assert_eq!(remove_pairs_from_value(&del, &own).removed, 0);
    }

    /// An in-memory stand-in for the session manager key. `interfere` runs before the n-th read
    /// and plays another program changing the list.
    struct FakeStore {
        values: std::collections::BTreeMap<String, (u32, Vec<u8>)>,
        reads: usize,
        writes: usize,
        interfere: Vec<(usize, Vec<u8>)>,
        always_readd: Option<Vec<u8>>,
    }

    impl FakeStore {
        fn new(primary: Option<Vec<u8>>) -> FakeStore {
            let mut values = std::collections::BTreeMap::new();
            if let Some(v) = primary {
                values.insert(PENDING_VALUE_NAMES[0].to_string(), (REG_MULTI_SZ, v));
            }
            FakeStore {
                values,
                reads: 0,
                writes: 0,
                interfere: Vec::new(),
                always_readd: None,
            }
        }

        fn primary(&self) -> Option<&[u8]> {
            self.values
                .get(PENDING_VALUE_NAMES[0])
                .map(|(_, v)| v.as_slice())
        }
    }

    impl PendingStore for FakeStore {
        fn read(&mut self, name: &str) -> Result<Option<(u32, Vec<u8>)>, Win32Error> {
            if name == PENDING_VALUE_NAMES[0] {
                self.reads += 1;
                let n = self.reads;
                if let Some((_, v)) = self.interfere.iter().find(|(at, _)| *at == n) {
                    self.values
                        .insert(name.to_string(), (REG_MULTI_SZ, v.clone()));
                }
            }
            Ok(self.values.get(name).cloned())
        }

        fn write(&mut self, name: &str, ty: u32, data: &[u8]) -> Result<(), Win32Error> {
            self.writes += 1;
            self.values.insert(name.to_string(), (ty, data.to_vec()));
            if let Some(v) = &self.always_readd {
                self.values.insert(name.to_string(), (ty, v.clone()));
            }
            Ok(())
        }

        fn delete(&mut self, name: &str) -> Result<(), Win32Error> {
            self.writes += 1;
            self.values.remove(name);
            if let Some(v) = &self.always_readd {
                self.values
                    .insert(name.to_string(), (REG_MULTI_SZ, v.clone()));
            }
            Ok(())
        }
    }

    #[test]
    fn pending_removal_compares_before_writing() {
        let ours = multi(&["src", "dst"]);
        let foreign = multi(&["other", ""]);
        let late = multi(&["late", "comer"]);
        let term = vec![0u8, 0];
        let own = [pair("src", "dst")];

        // Undisturbed: one write, foreign pair and terminator intact.
        let mut st = FakeStore::new(Some([&foreign[..], &ours, &term].concat()));
        assert_eq!(remove_pairs_in(&mut st, &own).unwrap(), 1);
        assert_eq!(st.primary().unwrap(), [&foreign[..], &term].concat());
        assert_eq!(st.writes, 1);

        // Only ours: the value is deleted.
        let mut st = FakeStore::new(Some([&ours[..], &term].concat()));
        assert_eq!(remove_pairs_in(&mut st, &own).unwrap(), 1);
        assert_eq!(st.primary(), None);

        // Nothing of ours, or no value at all: no write.
        let mut st = FakeStore::new(Some([&foreign[..], &term].concat()));
        assert_eq!(remove_pairs_in(&mut st, &own).unwrap(), 0);
        assert_eq!(st.writes, 0);
        let mut st = FakeStore::new(None);
        assert_eq!(remove_pairs_in(&mut st, &own).unwrap(), 0);
        assert_eq!((st.writes, st.reads), (0, 1));

        // Another program appends a pair between the first read and the write: the stale edit
        // is dropped, the removal is redone on the new content, and the newcomer survives.
        let mut st = FakeStore::new(Some([&foreign[..], &ours, &term].concat()));
        st.interfere = vec![(2, [&foreign[..], &ours, &late, &term].concat())];
        assert_eq!(remove_pairs_in(&mut st, &own).unwrap(), 1);
        assert_eq!(st.primary().unwrap(), [&foreign[..], &late, &term].concat());
        assert_eq!(st.writes, 1);

        // A value of another type is not touched.
        let mut st = FakeStore::new(None);
        st.values.insert(
            PENDING_VALUE_NAMES[0].to_string(),
            (3, [&ours[..], &term].concat()),
        );
        assert_eq!(remove_pairs_in(&mut st, &own).unwrap(), 0);
        assert_eq!(st.writes, 0);

        // The second value is handled the same way.
        let mut st = FakeStore::new(Some([&foreign[..], &term].concat()));
        st.values.insert(
            PENDING_VALUE_NAMES[1].to_string(),
            (REG_MULTI_SZ, [&ours[..], &foreign, &term].concat()),
        );
        assert_eq!(remove_pairs_in(&mut st, &own).unwrap(), 1);
        assert_eq!(st.primary().unwrap(), [&foreign[..], &term].concat());
        assert_eq!(
            st.values[PENDING_VALUE_NAMES[1]].1,
            [&foreign[..], &term].concat()
        );

        // A list that puts our pair back after every write ends in ERROR_RETRY, not a loop.
        let mut st = FakeStore::new(Some([&ours[..], &term].concat()));
        st.always_readd = Some([&ours[..], &term].concat());
        assert_eq!(
            remove_pairs_in(&mut st, &own),
            Err(FsError::Other(ERROR_RETRY))
        );
        assert_eq!(st.writes, MAX_PENDING_WRITES);
    }

    #[test]
    fn pending_pair_spelling_and_live_list_is_readable() {
        let p = pending_pair(
            Path::new(r"C:\Program Files\App\locked.dll"),
            Path::new(r"\\?\C:\ProgramData\Purge\Quarantine\s\1\locked.dll"),
        )
        .unwrap();
        assert_eq!(p.src, r"\??\C:\Program Files\App\locked.dll");
        assert_eq!(p.dst, r"\??\C:\ProgramData\Purge\Quarantine\s\1\locked.dll");
        assert_eq!(
            pending_pair(Path::new("rel"), Path::new(r"C:\x")).unwrap_err(),
            FsError::Other(87)
        );

        // Reading the real list needs no rights; every source is an NT path, possibly marked.
        for pair in pending_renames().unwrap() {
            assert!(strip_marker(&pair.src).starts_with(r"\??\"), "{pair:?}");
        }
        assert_eq!(strip_marker(r"*1\??\C:\x"), r"\??\C:\x");
        assert_eq!(strip_marker(r"\??\C:\*1"), r"\??\C:\*1");
        // A pair that is not listed is a no-op and does not need write access.
        let absent = pair(
            r"\??\C:\purge-test\never-registered-7f3a",
            r"\??\C:\purge-test\x",
        );
        assert_eq!(remove_pending_pairs(&[absent]).unwrap(), 0);
    }

    #[test]
    fn boot_move_needs_administrative_rights() {
        if crate::sid::is_elevated().unwrap() {
            // Elevated, the call would really register a move; that case is the ignored test
            // below.
            return;
        }
        let s = Scratch::new("bootdenied");
        let f = s.path("f.txt");
        std::fs::write(&f, b"x").unwrap();
        let before = pending_renames().unwrap();
        assert_eq!(
            move_delay_until_reboot(&f, &s.path("g.txt")),
            Err(FsError::AccessDenied)
        );
        assert_eq!(pending_renames().unwrap(), before);
    }

    #[test]
    #[ignore = "needs administrative rights: writes PendingFileRenameOperations in HKLM (VM only)"]
    fn boot_move_registers_and_removes_only_its_own_pair() {
        let s = Scratch::new("bootmove");
        let f = s.path("locked. ");
        std::fs::write(ext(&f), b"x").unwrap();
        let dst = s.path(r"q.dat");
        let before = pending_renames().unwrap();

        let reg = move_delay_until_reboot(&f, &dst).unwrap();
        assert!(reg.confirmed, "{reg:?}");
        let expected = pending_pair(&f, &dst).unwrap();
        assert_eq!(strip_marker(&reg.pair.src), expected.src);
        assert_eq!(strip_marker(&reg.pair.dst), expected.dst);
        let during = pending_renames().unwrap();
        assert_eq!(during.len(), before.len() + 1);
        assert!(during.contains(&reg.pair));

        assert_eq!(
            remove_pending_pairs(std::slice::from_ref(&reg.pair)).unwrap(),
            1
        );
        assert_eq!(pending_renames().unwrap(), before);
        assert_eq!(remove_pending_pairs(&[reg.pair]).unwrap(), 0);
    }

    #[test]
    #[ignore = "needs a second volume: set PURGE_TEST_OTHER_VOLUME_DIR to a writable directory on it (VM only)"]
    fn rename_across_volumes_is_not_same_device() {
        let other = PathBuf::from(
            std::env::var_os("PURGE_TEST_OTHER_VOLUME_DIR")
                .expect("PURGE_TEST_OTHER_VOLUME_DIR is not set"),
        );
        let s = Scratch::new("xvol");
        let f = s.path("f.txt");
        std::fs::write(&f, b"stay").unwrap();
        let dest = other.join(format!("purge-fsw-xvol-{}.txt", std::process::id()));
        let h = MoveHandle::open(&f).unwrap();
        assert_ne!(
            h.file_id().unwrap().volume_serial,
            crate::fs::file_id(&other).unwrap().volume_serial
        );
        assert_eq!(move_to(&h, &dest), Err(FsError::NotSameDevice));
        let other_handle = crate::secure::open_for_security(&other).unwrap();
        assert_eq!(
            h.rename_into(&other_handle, "purge-fsw-xvol.txt"),
            Err(FsError::NotSameDevice)
        );
        assert!(!dest.exists());
        assert_eq!(std::fs::read(&f).unwrap(), b"stay");
    }

    /// The SDDL string of `path`, read through a handle on the path itself.
    fn sddl_of(path: &Path) -> String {
        crate::secure::handle_sddl(&crate::secure::open_for_security(path).unwrap()).unwrap()
    }

    #[test]
    fn create_dir_lands_in_the_handle_directory_after_a_path_swap() {
        let s = Scratch::new("mkdir-swap");
        let (parent, protected) = (s.path("parent"), s.path("protected"));
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&protected).unwrap();
        let me = crate::sid::current_user_sid().unwrap();
        let sddl = format!("O:{me}G:{me}D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)");

        let dir = DestDir::open(&parent).unwrap();
        assert!(dir.facts().unwrap().is_plain_dir());
        // Between the check and the creation, the directory is renamed away and a junction to a
        // protected directory takes its name.
        let old = s.path("parent.old");
        std::fs::rename(&parent, &old).unwrap();
        mklink_junction(&parent, &protected);

        let created = dir.create_dir("child", &sddl).unwrap();
        assert!(names(&protected).is_empty());
        assert_eq!(names(&old), ["child"]);
        let meta = created.metadata().unwrap();
        assert!(meta.is_dir && meta.reparse_tag == 0, "{meta:?}");
        assert_eq!(
            meta.file_id,
            crate::fs::file_id(&old.join("child")).unwrap()
        );
        let canon = std::fs::canonicalize(old.join("child")).unwrap();
        assert!(
            created
                .final_path()
                .unwrap()
                .eq_ignore_ascii_case(&canon.to_string_lossy())
        );

        // The descriptor was applied at creation, exactly.
        assert!(created.has_read_control());
        let sec = created.security().unwrap();
        assert_eq!(sec.sddl, sddl);
        assert_eq!(sddl_of(&old.join("child")), sddl);

        // A fresh look at the path sees the junction, and creating through it is refused.
        let fresh = DestDir::open(&parent).unwrap();
        assert_eq!(
            fresh.create_dir("x", &sddl).unwrap_err(),
            FsError::WrongKind
        );
        assert!(names(&protected).is_empty());
    }

    #[test]
    fn create_dir_never_adopts_an_existing_object_and_refuses_bad_leaves() {
        let s = Scratch::new("mkdir-exists");
        let me = crate::sid::current_user_sid().unwrap();
        let sddl = format!("D:P(A;OICI;FA;;;{me})");
        let d = s.path("d");
        std::fs::create_dir(&d).unwrap();
        let dir = DestDir::open(&d).unwrap();

        // Existing objects of every kind: a directory with content, a file, a junction (live and
        // dangling), a file symbolic link to a missing target if one can be made.
        std::fs::create_dir(d.join("taken")).unwrap();
        std::fs::write(d.join(r"taken\inner.txt"), b"inner").unwrap();
        std::fs::write(d.join("file.txt"), b"file").unwrap();
        mklink_junction(&d.join("live-j"), &s.path("elsewhere"));
        std::fs::create_dir(s.path("elsewhere")).unwrap();
        mklink_junction(&d.join("dangling-j"), &s.path("victim-j"));
        let mut taken = vec!["taken", "file.txt", "live-j", "dangling-j"];
        if try_symlink_file(
            &s.path("victim.txt"),
            &d.join("dangling-f"),
            "create_dir_never_adopts_an_existing_object_and_refuses_bad_leaves",
        ) {
            taken.push("dangling-f");
        }
        let before: Vec<(String, crate::fs::FileMeta, String)> = taken
            .iter()
            .map(|n| {
                let p = d.join(n);
                (n.to_string(), crate::fs::metadata(&p).unwrap(), sddl_of(&p))
            })
            .collect();
        let listing = names(&d);
        for name in &taken {
            assert_eq!(
                dir.create_dir(name, &sddl).unwrap_err(),
                FsError::AlreadyExists,
                "{name}"
            );
            // Another letter case is the same name.
            assert_eq!(
                dir.create_dir(&name.to_uppercase(), &sddl).unwrap_err(),
                FsError::AlreadyExists,
                "{name}"
            );
        }
        for (name, meta, sd) in &before {
            let p = d.join(name);
            assert_eq!(&crate::fs::metadata(&p).unwrap(), meta, "{name}");
            assert_eq!(&sddl_of(&p), sd, "{name}");
        }
        assert_eq!(names(&d), listing);
        assert_eq!(names(&d.join("taken")), ["inner.txt"]);
        assert_eq!(std::fs::read(d.join("file.txt")).unwrap(), b"file");
        assert!(names(&s.path("elsewhere")).is_empty());
        for victim in ["victim-j", "victim.txt"] {
            assert!(!s.path(victim).exists(), "{victim}");
        }

        // Leaves that are not one plain component.
        for bad in [
            "", ".", "..", r"a\b", "a/b", "a:b", "a::$DATA", "a\0b", r"..\up",
        ] {
            assert_eq!(
                dir.create_dir(bad, &sddl).unwrap_err(),
                FsError::Other(87),
                "{bad:?}"
            );
        }
        // A descriptor that is not SDDL creates nothing.
        assert!(matches!(
            dir.create_dir("bad-sddl", "not sddl").unwrap_err(),
            FsError::Other(_)
        ));
        assert_eq!(names(&d), listing);
        assert_eq!(names(&s.0), ["d", "elsewhere"]);

        // A trailing dot or space is kept, as for rename_into.
        let dotted = dir.create_dir("kept. ", &sddl).unwrap();
        assert!(dotted.final_path().unwrap().ends_with(r"\kept. "));
        assert!(names(&d).contains(&"kept. ".to_string()));

        // A handle that is not a plain directory: a file, a junction.
        let on_file = DestDir::open(&d.join("file.txt")).unwrap();
        assert_eq!(
            on_file.create_dir("x", &sddl).unwrap_err(),
            FsError::WrongKind
        );
        let on_junction = DestDir::open(&d.join("live-j")).unwrap();
        assert_eq!(
            on_junction.create_dir("x", &sddl).unwrap_err(),
            FsError::WrongKind
        );
        assert!(names(&s.path("elsewhere")).is_empty());
    }

    #[test]
    fn create_dir_handle_carries_the_rights_it_asked_for() {
        // The creator is granted the access it requests, even when the new descriptor grants the
        // caller nothing but reading.
        let s = Scratch::new("mkdir-rights");
        let me = crate::sid::current_user_sid().unwrap();
        let dir = DestDir::open(&s.0).unwrap();
        let h = dir
            .create_dir("readonly", &format!("O:{me}D:P(A;;FR;;;WD)"))
            .unwrap();
        let sec = h.security().unwrap();
        assert_eq!(sec.aces().len(), 1, "{}", sec.sddl);
        let m = h.metadata().unwrap();
        h.set_times(m.creation_time - 10_000_000, m.last_write_time - 20_000_000)
            .unwrap();
        let open = format!("D:P(A;OICI;FA;;;{me})");
        h.set_security(&open).unwrap();
        assert!(h.security().unwrap().sddl.ends_with(&open));
        h.remove_dir_if_empty().unwrap();
        drop(h);
        assert!(names(&s.0).is_empty());
    }

    #[test]
    fn set_times_round_trips_through_metadata() {
        let s = Scratch::new("times");
        let (src, f, d) = (s.path("src.txt"), s.path("f.txt"), s.path("d"));
        std::fs::write(&src, b"source").unwrap();
        std::fs::write(&f, b"target").unwrap();
        std::fs::create_dir(&d).unwrap();
        let _ = MoveHandle::open_with_attribute_write(&src)
            .unwrap()
            .set_attributes(FILE_ATTRIBUTE_HIDDEN, 0)
            .unwrap();
        // 2001-02-03 and 2002-03-04, odd tick counts to see that nothing is rounded.
        let (creation, last_write) = (126_257_000_001_234_567u64, 126_597_000_007_654_321u64);

        for path in [&f, &d] {
            let h = MoveHandle::open_with_attribute_write(path).unwrap();
            let before = h.metadata().unwrap();
            h.set_times(creation, last_write).unwrap();
            let after = h.metadata().unwrap();
            assert_eq!(
                (after.creation_time, after.last_write_time),
                (creation, last_write)
            );
            assert_eq!(after.last_access_time, before.last_access_time);
            assert_eq!(after.attributes, before.attributes);
            drop(h);
            let fresh = crate::fs::metadata(path).unwrap();
            assert_eq!(
                (fresh.creation_time, fresh.last_write_time),
                (creation, last_write)
            );
        }

        // Times captured on one file and written on another come back equal. (The content is
        // read first: reading updates the last-access time, which the checks below compare.)
        assert_eq!(std::fs::read(&f).unwrap(), b"target");
        let captured = crate::fs::metadata(&src).unwrap();
        let h = MoveHandle::open_with_security_write(&f).unwrap();
        h.set_times(captured.creation_time, captured.last_write_time)
            .unwrap();
        drop(h);
        let copy = crate::fs::metadata(&f).unwrap();
        assert_eq!(
            (copy.creation_time, copy.last_write_time),
            (captured.creation_time, captured.last_write_time)
        );
        assert_eq!(copy.attributes & FILE_ATTRIBUTE_HIDDEN, 0);

        // Values that FILE_BASIC_INFO gives another meaning to are refused; nothing changes.
        let h = MoveHandle::open_with_attribute_write(&f).unwrap();
        for (c, w) in [
            (0, last_write),
            (creation, 0),
            (u64::MAX, last_write),
            (creation, u64::MAX - 1),
            (1 << 63, last_write),
        ] {
            assert_eq!(h.set_times(c, w), Err(FsError::Other(87)), "{c} {w}");
        }
        assert_eq!(crate::fs::metadata(&f).unwrap(), copy);

        // A handle without FILE_WRITE_ATTRIBUTES cannot.
        let plain = MoveHandle::open(&f).unwrap();
        assert_eq!(
            plain.set_times(creation, last_write),
            Err(FsError::AccessDenied)
        );
        assert_eq!(crate::fs::metadata(&f).unwrap(), copy);
    }

    #[test]
    fn set_security_round_trips_auto_inherited_and_protected_dacls() {
        let s = Scratch::new("setsec");
        let me = crate::sid::current_user_sid().unwrap();
        let d = s.path("d");
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join("child.txt"), b"c").unwrap();
        let child_sddl = sddl_of(&d.join("child.txt"));
        let h = MoveHandle::open_with_security_write(&d).unwrap();

        // What the directory inherited from the temp directory: an auto-inherited DACL.
        let inherited = h.security().unwrap();
        assert!(inherited.sddl.contains("D:AI("), "{}", inherited.sddl);
        assert_ne!(inherited.control & SE_DACL_AUTO_INHERITED, 0);

        let full = |dacl: &str| format!("O:{me}G:{me}{dacl}");
        let cases = [
            // Protected, then auto-inherited again (SetKernelObjectSecurity alone drops AI here).
            full(&format!("D:P(A;OICI;FA;;;{me})(A;;FR;;;BU)")),
            inherited.sddl.clone(),
            // Protected and auto-inherited, with an inherited ACE kept as given.
            full(&format!("D:PAI(A;;FR;;;BU)(A;OICIID;FA;;;{me})")),
            // Auto-inherited with explicit and inherited ACEs that differ from the parent's.
            full(&format!(
                "D:AI(A;;FR;;;BU)(A;OICIID;FA;;;{me})(A;OICIID;FA;;;SY)"
            )),
            // Neither flag: AI must not appear.
            full(&format!("D:(A;;FR;;;BU)(A;OICIID;FA;;;{me})")),
            inherited.sddl.clone(),
        ];
        for sddl in &cases {
            h.set_security(sddl).unwrap();
            let got = h.security().unwrap();
            assert_eq!(&got.sddl, sddl);
            assert_eq!(&sddl_of(&d), sddl);
            assert_eq!(
                got.control & SE_DACL_AUTO_INHERITED != 0,
                sddl.contains(":AI(") || sddl.contains(":PAI("),
                "{sddl}"
            );
            assert_eq!(got.dacl_protected, sddl.contains("D:P"), "{sddl}");
        }
        // Nothing was propagated to the child.
        assert_eq!(sddl_of(&d.join("child.txt")), child_sddl);

        // A descriptor captured on one object is stored exactly on another.
        let f = s.path("f.txt");
        std::fs::write(&f, b"f").unwrap();
        let fh = MoveHandle::open_with_security_write(&f).unwrap();
        let mixed = &cases[3];
        fh.set_security(mixed).unwrap();
        assert_eq!(&fh.security().unwrap().sddl, mixed);
        fh.set_security(&child_sddl).unwrap();
        assert_eq!(fh.security().unwrap().sddl, child_sddl);

        // The DACL alone leaves owner and group; the owner alone leaves the DACL.
        let protected_dacl = format!("D:P(A;OICI;FA;;;{me})");
        h.set_security(&protected_dacl).unwrap();
        assert_eq!(h.security().unwrap().sddl, full(&protected_dacl));
        h.set_security(&format!("O:{me}")).unwrap();
        assert_eq!(h.security().unwrap().sddl, full(&protected_dacl));
        let now = h.security().unwrap().sddl;

        // Refused inputs change nothing.
        let inv = FsError::Other(87);
        assert_eq!(h.set_security("S:(AU;SA;FA;;;WD)"), Err(inv));
        assert_eq!(h.set_security(&format!("{now}S:(AU;SA;FA;;;WD)")), Err(inv));
        assert!(h.set_security("not sddl").is_err());
        assert!(h.set_security("").is_err());
        assert_eq!(h.security().unwrap().sddl, now);

        // An owner the token may not assign is an error; no privilege is enabled for it.
        let trusted_installer = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        assert_eq!(
            h.set_security(&format!("O:{trusted_installer}")),
            Err(FsError::Other(1307))
        );
        assert_eq!(
            h.set_security(&cases[3].replacen(
                &format!("O:{me}"),
                &format!("O:{trusted_installer}"),
                1
            )),
            Err(FsError::Other(1307))
        );
        assert_eq!(h.security().unwrap().sddl, now);

        // A handle without WRITE_DAC / WRITE_OWNER cannot write the descriptor.
        let plain = MoveHandle::open(&d).unwrap();
        assert_eq!(
            plain.set_security(&inherited.sddl),
            Err(FsError::AccessDenied)
        );
        let attrs = MoveHandle::open_with_attribute_write(&d).unwrap();
        assert_eq!(
            attrs.set_security(&protected_dacl),
            Err(FsError::AccessDenied)
        );
        assert_eq!(h.security().unwrap().sddl, now);

        // Back to the inherited descriptor, so the scratch directory goes as usual.
        h.set_security(&inherited.sddl).unwrap();
        assert_eq!(sddl_of(&d), inherited.sddl);
    }

    #[test]
    fn strip_marker_is_public_and_strips_only_a_leading_marker() {
        assert_eq!(strip_marker(r"*1\??\C:\x"), r"\??\C:\x");
        assert_eq!(strip_marker(r"*12\??\C:\x"), r"\??\C:\x");
        assert_eq!(strip_marker(r"\??\C:\x"), r"\??\C:\x");
        assert_eq!(strip_marker(r"!\??\C:\x"), r"!\??\C:\x");
        assert_eq!(strip_marker(r"\??\C:\*1\2"), r"\??\C:\*1\2");
        assert_eq!(strip_marker(""), "");
    }

    #[test]
    fn pending_exact_removal_cuts_only_an_exact_count() {
        let ours = pair(r"\??\C:\App\locked.dll", r"\??\C:\Q\1\locked.dll");
        let ours_b = multi(&[&ours.src, &ours.dst]);
        let foreign_a = multi(&[r"\??\C:\Windows\a.tmp", ""]);
        let foreign_b = multi(&[r"\??\C:\x\Old.exe", r"!\??\C:\x\New.exe"]);
        let foreign_c = multi(&[r"\??\C:\y", r"\??\C:\z"]);
        // Near misses: letter case of either half, a marker, a delete or replacing variant.
        let near = [
            multi(&[r"\??\c:\app\locked.dll", &ours.dst]),
            multi(&[&ours.src, r"\??\C:\q\1\locked.dll"]),
            multi(&[&format!("*1{}", ours.src), &ours.dst]),
            multi(&[&ours.src, &format!("*1{}", ours.dst)]),
            multi(&[&ours.src, ""]),
            multi(&[&ours.src, &format!("!{}", ours.dst)]),
        ]
        .concat();
        let term = vec![0u8, 0];
        let value = [
            &foreign_a[..],
            &ours_b,
            &foreign_b,
            &near,
            &ours_b,
            &foreign_c,
            &term,
        ]
        .concat();
        let expect = [&foreign_a[..], &foreign_b, &near, &foreign_c, &term].concat();

        let edit = remove_pair_exactly_from_value(&value, &ours, 2).unwrap();
        assert_eq!(edit.removed, 2);
        assert_eq!(edit.value.as_deref(), Some(&expect[..]));
        // Any other count is refused with the count found.
        for wrong in [0, 1, 3] {
            assert_eq!(
                remove_pair_exactly_from_value(&value, &ours, wrong),
                Err(FsError::PendingCountMismatch { found: 2 })
            );
        }
        // After the cut, only the near misses remain: zero is the count.
        assert_eq!(
            remove_pair_exactly_from_value(&expect, &ours, 1),
            Err(FsError::PendingCountMismatch { found: 0 })
        );
        let none = remove_pair_exactly_from_value(&expect, &ours, 0).unwrap();
        assert_eq!(
            (none.removed, none.value.as_deref()),
            (0, Some(&expect[..]))
        );
        // A marked spelling is its own pair.
        let marked = pair(&format!("*1{}", ours.src), &ours.dst);
        let m = remove_pair_exactly_from_value(&value, &marked, 1).unwrap();
        assert_eq!(m.removed, 1);
        assert_eq!(remove_pairs_from_value(&value, &[marked]).value, m.value);
        // Only ours: the value goes.
        let only = [&ours_b[..], &term].concat();
        assert_eq!(
            remove_pair_exactly_from_value(&only, &ours, 1).unwrap(),
            PendingEdit {
                removed: 1,
                value: None
            }
        );
        assert_eq!(FsError::PendingCountMismatch { found: 3 }.code(), 13);
    }

    #[test]
    fn pending_exact_removal_is_one_compared_write() {
        let ours = pair("src", "dst");
        let ours_b = multi(&["src", "dst"]);
        let foreign = multi(&["other", ""]);
        let late = multi(&["late", "comer"]);
        let term = vec![0u8, 0];
        let value = [&foreign[..], &ours_b, &late, &ours_b, &term].concat();

        // The right count: one write, foreign pairs byte-identical and in order.
        let mut st = FakeStore::new(Some(value.clone()));
        assert_eq!(remove_pair_exactly_in(&mut st, &ours, 2).unwrap(), 2);
        assert_eq!(st.primary().unwrap(), [&foreign[..], &late, &term].concat());
        assert_eq!(st.writes, 1);

        // The wrong count: nothing written, value unchanged, the count found reported.
        let mut st = FakeStore::new(Some(value.clone()));
        assert_eq!(
            remove_pair_exactly_in(&mut st, &ours, 1),
            Err(FsError::PendingCountMismatch { found: 2 })
        );
        assert_eq!((st.writes, st.primary()), (0, Some(&value[..])));

        // No value, or a value of another type: the pair is there zero times.
        let mut st = FakeStore::new(None);
        assert_eq!(remove_pair_exactly_in(&mut st, &ours, 0), Ok(0));
        assert_eq!(
            remove_pair_exactly_in(&mut st, &ours, 1),
            Err(FsError::PendingCountMismatch { found: 0 })
        );
        st.values
            .insert(PENDING_VALUE_NAMES[0].to_string(), (3, value.clone()));
        assert_eq!(
            remove_pair_exactly_in(&mut st, &ours, 2),
            Err(FsError::PendingCountMismatch { found: 0 })
        );
        assert_eq!(st.writes, 0);

        // The second value is neither counted nor changed.
        let mut st = FakeStore::new(Some([&foreign[..], &term].concat()));
        let second = [&ours_b[..], &term].concat();
        st.values.insert(
            PENDING_VALUE_NAMES[1].to_string(),
            (REG_MULTI_SZ, second.clone()),
        );
        assert_eq!(
            remove_pair_exactly_in(&mut st, &ours, 1),
            Err(FsError::PendingCountMismatch { found: 0 })
        );
        assert_eq!(st.values[PENDING_VALUE_NAMES[1]].1, second);
        assert_eq!(st.writes, 0);

        // Only ours: the value is deleted.
        let mut st = FakeStore::new(Some([&ours_b[..], &term].concat()));
        assert_eq!(remove_pair_exactly_in(&mut st, &ours, 1), Ok(1));
        assert_eq!(st.primary(), None);

        // Another program adds a pair between the first read and the write: nothing stale is
        // written, the count is taken again on the new content, and the newcomer survives.
        let start = [&foreign[..], &ours_b, &term].concat();
        let mut st = FakeStore::new(Some(start.clone()));
        st.interfere = vec![(2, [&foreign[..], &ours_b, &late, &term].concat())];
        assert_eq!(remove_pair_exactly_in(&mut st, &ours, 1), Ok(1));
        assert_eq!(st.primary().unwrap(), [&foreign[..], &late, &term].concat());
        assert_eq!(st.writes, 1);
        // If the newcomer is a second copy of ours, the count no longer matches: no write.
        let mut st = FakeStore::new(Some(start.clone()));
        let doubled = [&foreign[..], &ours_b, &ours_b, &term].concat();
        st.interfere = vec![(2, doubled.clone())];
        assert_eq!(
            remove_pair_exactly_in(&mut st, &ours, 1),
            Err(FsError::PendingCountMismatch { found: 2 })
        );
        assert_eq!((st.writes, st.primary()), (0, Some(&doubled[..])));

        // A list that changes between every pair of reads ends in ERROR_RETRY, unwritten.
        let mut st = FakeStore::new(Some(start.clone()));
        let a = [&ours_b[..], &foreign, &term].concat();
        let b = [&ours_b[..], &late, &term].concat();
        st.interfere = (1..=MAX_PENDING_WRITES)
            .map(|k| (2 * k, if k % 2 == 0 { a.clone() } else { b.clone() }))
            .collect();
        assert_eq!(
            remove_pair_exactly_in(&mut st, &ours, 1),
            Err(FsError::Other(ERROR_RETRY))
        );
        assert_eq!(st.writes, 0);
    }

    #[test]
    fn pending_exact_removal_of_an_absent_pair_needs_no_rights() {
        // Reads the real list only; nothing is written because nothing is to be removed.
        let absent = pair(
            r"\??\C:\purge-test\never-registered-4c1d",
            r"\??\C:\purge-test\y",
        );
        let before = pending_renames().unwrap();
        assert_eq!(remove_pending_pairs_exactly(&absent, 0), Ok(0));
        assert_eq!(
            remove_pending_pairs_exactly(&absent, 1),
            Err(FsError::PendingCountMismatch { found: 0 })
        );
        assert_eq!(pending_renames().unwrap(), before);
    }

    #[test]
    #[ignore = "needs administrative rights: writes PendingFileRenameOperations in HKLM (VM only)"]
    fn pending_exact_removal_of_a_registered_boot_move() {
        let s = Scratch::new("bootexact");
        let f = s.path("locked.dll");
        std::fs::write(&f, b"x").unwrap();
        let before = pending_renames().unwrap();
        let reg = move_delay_until_reboot(&f, &s.path("q.dll")).unwrap();
        assert!(reg.confirmed, "{reg:?}");
        let during = pending_renames().unwrap();

        // A wrong count changes nothing.
        assert_eq!(
            remove_pending_pairs_exactly(&reg.pair, 2),
            Err(FsError::PendingCountMismatch { found: 1 })
        );
        assert_eq!(pending_renames().unwrap(), during);

        assert_eq!(remove_pending_pairs_exactly(&reg.pair, 1), Ok(1));
        assert_eq!(pending_renames().unwrap(), before);
        assert_eq!(remove_pending_pairs_exactly(&reg.pair, 0), Ok(0));
    }
}
