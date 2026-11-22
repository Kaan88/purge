//! Opening, creating, renaming and deleting objects of the store relative to a directory handle,
//! and reading the facts of a handle (wave 2 review S1, M1, M3).
//!
//! `purge-win` opens files by path only. The store must act on the object it checked, so every file
//! it creates or opens below a checked directory is opened with `NtCreateFile` and that directory's
//! handle as `RootDirectory`, with a single name component and `FILE_OPEN_REPARSE_POINT`: nothing
//! between the checked directory and the file is resolved by name again, and a reparse point at the
//! name is opened itself, never followed. Declared here because purge-exec has no `windows-sys`
//! dependency.

use std::ffi::c_void;
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use purge_win::fs::FileId;
use purge_win::fs_write::FsError;
use purge_win::os::Win32Error;

type Handle = *mut c_void;

/// `DELETE`.
pub(crate) const DELETE: u32 = 0x0001_0000;
/// `READ_CONTROL`.
pub(crate) const READ_CONTROL: u32 = 0x0002_0000;
/// `SYNCHRONIZE`.
pub(crate) const SYNCHRONIZE: u32 = 0x0010_0000;
/// `GENERIC_READ`.
pub(crate) const GENERIC_READ: u32 = 0x8000_0000;
/// `GENERIC_WRITE`.
pub(crate) const GENERIC_WRITE: u32 = 0x4000_0000;
/// `FILE_READ_ATTRIBUTES`.
pub(crate) const FILE_READ_ATTRIBUTES: u32 = 0x80;
/// `FILE_LIST_DIRECTORY`: what [`list_names`] needs on a directory handle.
pub(crate) const FILE_LIST_DIRECTORY: u32 = 0x1;
/// `FILE_ADD_FILE`: what `FlushFileBuffers` on a directory needs.
const FILE_ADD_FILE: u32 = 0x2;

/// No sharing: while the handle is open, every other open that asks for data or delete access fails
/// with a sharing violation.
pub(crate) const SHARE_NONE: u32 = 0;
/// `FILE_SHARE_READ`.
pub(crate) const SHARE_READ: u32 = 0x1;
/// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`.
pub(crate) const SHARE_ALL: u32 = 0x7;

/// `FILE_OPEN`.
const FILE_OPEN: u32 = 1;
/// `FILE_CREATE`: fails if anything has the name.
const FILE_CREATE: u32 = 2;
/// `FILE_DIRECTORY_FILE`.
const FILE_DIRECTORY_FILE: u32 = 0x1;
/// `FILE_SYNCHRONOUS_IO_NONALERT`: ordinary synchronous reads and writes on the handle.
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
/// `FILE_NON_DIRECTORY_FILE`.
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
/// `FILE_OPEN_REPARSE_POINT`: a reparse point is opened itself, never followed.
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// `FILE_ATTRIBUTE_NORMAL`.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
/// `FILE_ATTRIBUTE_DIRECTORY`.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// `OBJ_CASE_INSENSITIVE`, as Win32 opens names.
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
/// `SDDL_REVISION_1`.
const SDDL_REVISION_1: u32 = 1;

/// `FileBasicInfo` (`FILE_INFO_BY_HANDLE_CLASS`).
const FILE_BASIC_INFO_CLASS: i32 = 0;
/// `FileStandardInfo`.
const FILE_STANDARD_INFO_CLASS: i32 = 1;
/// `FileDispositionInfo`.
const FILE_DISPOSITION_INFO_CLASS: i32 = 4;
/// `FileAttributeTagInfo`.
const FILE_ATTRIBUTE_TAG_INFO_CLASS: i32 = 9;
/// `FileIdInfo`.
const FILE_ID_INFO_CLASS: i32 = 18;
/// `FileFullDirectoryInfo`: the next entries of a directory listing.
const FILE_FULL_DIRECTORY_INFO_CLASS: i32 = 14;
/// `FileFullDirectoryRestartInfo`: the first entries of a directory listing.
const FILE_FULL_DIRECTORY_RESTART_INFO_CLASS: i32 = 15;
/// `ERROR_NO_MORE_FILES`: the end of a listing.
const ERROR_NO_MORE_FILES: u32 = 18;
/// Offset of `FileNameLength` in `FILE_FULL_DIR_INFO`.
const DIR_INFO_NAME_LENGTH: usize = 60;
/// Offset of `FileName` in `FILE_FULL_DIR_INFO`.
const DIR_INFO_NAME: usize = 68;
/// `FileRenameInformation` (`FILE_INFORMATION_CLASS`).
const NT_FILE_RENAME_INFORMATION: i32 = 10;
/// `FileRenameInformationEx`.
const NT_FILE_RENAME_INFORMATION_EX: i32 = 65;
/// `FILE_RENAME_REPLACE_IF_EXISTS`.
const FILE_RENAME_REPLACE_IF_EXISTS: u32 = 0x1;
/// `FILE_RENAME_POSIX_SEMANTICS`: a replaced name goes away even while readers that share delete
/// hold it open.
const FILE_RENAME_POSIX_SEMANTICS: u32 = 0x2;
/// Offset of `FileName` in `FILE_RENAME_INFORMATION` on 64-bit Windows.
const RENAME_NAME_OFFSET: usize = 20;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: Handle,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: *const c_void,
    security_quality_of_service: *const c_void,
}

#[repr(C)]
#[derive(Default)]
struct IoStatusBlock {
    status: usize,
    information: usize,
}

#[repr(C)]
#[derive(Default)]
struct BasicInfo {
    creation: i64,
    last_access: i64,
    last_write: i64,
    change: i64,
    attributes: u32,
}

#[repr(C)]
#[derive(Default)]
struct StandardInfo {
    allocation_size: i64,
    end_of_file: i64,
    number_of_links: u32,
    delete_pending: u8,
    directory: u8,
}

#[repr(C)]
#[derive(Default)]
struct AttributeTagInfo {
    attributes: u32,
    reparse_tag: u32,
}

#[repr(C)]
#[derive(Default)]
struct IdInfo {
    volume_serial: u64,
    file_id: [u8; 16],
}

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    /// `NtCreateFile`: the only call that opens a name relative to a directory handle.
    fn NtCreateFile(
        file: *mut Handle,
        access: u32,
        attributes: *const ObjectAttributes,
        io_status: *mut IoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
        ea: *const c_void,
        ea_length: u32,
    ) -> i32;
    /// `NtSetInformationFile`, for a rename relative to a directory handle.
    fn NtSetInformationFile(
        file: Handle,
        io_status: *mut IoStatusBlock,
        info: *const c_void,
        length: u32,
        class: i32,
    ) -> i32;
    /// `RtlNtStatusToDosError`.
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn GetFileInformationByHandleEx(file: Handle, class: i32, info: *mut c_void, size: u32) -> i32;
    fn SetFileInformationByHandle(file: Handle, class: i32, info: *const c_void, size: u32) -> i32;
    fn GetFinalPathNameByHandleW(file: Handle, path: *mut u16, len: u32, flags: u32) -> u32;
    fn GetLastError() -> u32;
    fn LocalFree(mem: *mut c_void) -> *mut c_void;
}

#[link(name = "advapi32", kind = "raw-dylib")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
}

fn last_error() -> FsError {
    // SAFETY: reads the calling thread's last-error value; no preconditions.
    FsError::from(Win32Error(unsafe { GetLastError() }))
}

fn status_error(status: i32) -> FsError {
    // SAFETY: a pure status-to-code mapping.
    FsError::from(Win32Error(unsafe { RtlNtStatusToDosError(status) }))
}

/// A security descriptor built from an SDDL string, freed on drop.
struct Descriptor(*mut c_void);

impl Descriptor {
    fn parse(sddl: &str) -> Result<Descriptor, FsError> {
        let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        if text[..text.len() - 1].contains(&0) {
            return Err(FsError::Other(87));
        }
        let mut sd = ptr::null_mut();
        // SAFETY: `text` is NUL-terminated; `sd` receives a LocalAlloc block; no size is asked for.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(Descriptor(sd))
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: the block came from ConvertStringSecurityDescriptorToSecurityDescriptorW, which
        // documents LocalFree as its deallocator; freed exactly once.
        unsafe { LocalFree(self.0) };
    }
}

/// Whether the object to open is a file or a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Only a non-directory file is created; opening an existing object of any kind works, so that
    /// a planted directory is seen and refused by the integrity check.
    File,
    /// A directory.
    Dir,
}

/// One relative open.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Open<'a> {
    /// Requested access.
    pub access: u32,
    /// Share mode.
    pub share: u32,
    /// `Some(sddl)`: create new with this descriptor, failing if anything has the name. `None`:
    /// open an existing object.
    pub create: Option<&'a str>,
    /// What to create (and, for [`Kind::Dir`], what to open).
    pub kind: Kind,
}

/// Whether `leaf` is one plain name component the store may open below a directory handle.
pub(crate) fn plain_leaf(leaf: &str) -> bool {
    !leaf.is_empty() && leaf != "." && leaf != ".." && !leaf.contains(['\\', '/', ':', '\0'])
}

/// Opens or creates `leaf` in the directory behind `dir` (a reparse point at the name is opened
/// itself). An empty `leaf` reopens the directory itself with the requested access.
pub(crate) fn open_at(
    dir: &impl AsHandle,
    leaf: &str,
    how: Open<'_>,
) -> Result<OwnedHandle, FsError> {
    if !leaf.is_empty() && !plain_leaf(leaf) {
        return Err(FsError::Other(87));
    }
    let name: Vec<u16> = leaf.encode_utf16().collect();
    let Ok(bytes) = u16::try_from(name.len() * 2) else {
        return Err(FsError::Other(87));
    };
    let descriptor = how.create.map(Descriptor::parse).transpose()?;
    let unicode = UnicodeString {
        length: bytes,
        maximum_length: bytes,
        buffer: if name.is_empty() {
            ptr::null()
        } else {
            name.as_ptr()
        },
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: dir.as_handle().as_raw_handle(),
        object_name: &unicode,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: descriptor
            .as_ref()
            .map_or(ptr::null(), |d| d.0.cast_const()),
        security_quality_of_service: ptr::null(),
    };
    let mut options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT;
    let (disposition, file_attributes) = match (how.create, how.kind) {
        (Some(_), Kind::File) => {
            options |= FILE_NON_DIRECTORY_FILE;
            (FILE_CREATE, FILE_ATTRIBUTE_NORMAL)
        }
        (Some(_), Kind::Dir) => {
            options |= FILE_DIRECTORY_FILE;
            (FILE_CREATE, FILE_ATTRIBUTE_NORMAL)
        }
        (None, _) => (FILE_OPEN, 0),
    };
    let mut handle: Handle = ptr::null_mut();
    let mut io = IoStatusBlock::default();
    // SAFETY: `attributes` points to live locals (`unicode`, whose buffer `name` outlives the
    // call, and the descriptor kept alive by `descriptor`); the root handle is borrowed for the
    // call; `handle` and `io` are writable; no allocation size and no extended attributes.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            how.access | SYNCHRONIZE,
            &attributes,
            &mut io,
            ptr::null(),
            file_attributes,
            how.share,
            disposition,
            options,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(status_error(status));
    }
    // SAFETY: a successful NtCreateFile returned a fresh handle that nobody else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// Flushes the directory behind `dir` through a second handle on the same directory (an empty
/// relative name), opened with the access `FlushFileBuffers` needs.
pub(crate) fn flush_dir_at(dir: &impl AsHandle) -> Result<(), FsError> {
    let reopened = open_at(
        dir,
        "",
        Open {
            access: FILE_ADD_FILE | FILE_READ_ATTRIBUTES,
            share: SHARE_ALL,
            create: None,
            kind: Kind::Dir,
        },
    )?;
    purge_win::fs_write::flush(&reopened)
}

fn info<T: Default>(h: &impl AsHandle, class: i32) -> Result<T, FsError> {
    let mut out = T::default();
    // SAFETY: the handle is live for the call; `out` is a writable, aligned value of exactly the
    // size passed, of the layout the class documents.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            h.as_handle().as_raw_handle(),
            class,
            (&mut out as *mut T).cast(),
            size_of::<T>() as u32,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(out)
}

/// The names in the directory behind `dir` (opened with [`FILE_LIST_DIRECTORY`] and synchronous I/O,
/// as [`open_at`] opens), `.` and `..` left out, read through that handle with
/// `GetFileInformationByHandleEx(FileFullDirectoryRestartInfo, FileFullDirectoryInfo)`: no path is
/// resolved, so the listing is of the very directory the handle is on.
pub(crate) fn list_names(dir: &impl AsHandle) -> Result<Vec<String>, FsError> {
    // u64 storage keeps the buffer aligned for the records the call writes.
    let mut buf = vec![0u64; 8 * 1024];
    let size = u32::try_from(buf.len() * 8).unwrap_or(u32::MAX);
    let mut names = Vec::new();
    let mut class = FILE_FULL_DIRECTORY_RESTART_INFO_CLASS;
    loop {
        // SAFETY: the handle is live for the call; `buf` is writable and holds `size` bytes.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                dir.as_handle().as_raw_handle(),
                class,
                buf.as_mut_ptr().cast(),
                size,
            )
        };
        if ok == 0 {
            // SAFETY: reads the calling thread's last-error value; no preconditions.
            let code = unsafe { GetLastError() };
            if code == ERROR_NO_MORE_FILES {
                return Ok(names);
            }
            return Err(FsError::from(Win32Error(code)));
        }
        class = FILE_FULL_DIRECTORY_INFO_CLASS;
        // SAFETY: the bytes of `buf` are initialised (zeroed, then written by the call) and stay
        // borrowed only while `buf` is not touched.
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len() * 8) };
        let mut at = 0usize;
        loop {
            let field = |offset: usize| -> Option<u32> {
                let start = at.checked_add(offset)?;
                let raw = bytes.get(start..start.checked_add(4)?)?;
                Some(u32::from_le_bytes(raw.try_into().ok()?))
            };
            let (Some(next), Some(name_len)) = (field(0), field(DIR_INFO_NAME_LENGTH)) else {
                return Err(FsError::Other(ERROR_INVALID_DATA));
            };
            let start = at + DIR_INFO_NAME;
            let Some(raw) = bytes.get(start..start + name_len as usize) else {
                return Err(FsError::Other(ERROR_INVALID_DATA));
            };
            let units: Vec<u16> = raw
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            let name = String::from_utf16_lossy(&units);
            if name != "." && name != ".." {
                names.push(name);
            }
            if next == 0 {
                break;
            }
            at += next as usize;
        }
    }
}

/// `ERROR_INVALID_DATA`: a listing record that does not fit its buffer.
const ERROR_INVALID_DATA: u32 = 13;

/// What the store reads from one handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Facts {
    /// `FILE_ATTRIBUTE_*` bits.
    pub attributes: u32,
    /// Reparse tag, 0 unless a reparse point.
    pub reparse_tag: u32,
    /// Directory flag.
    pub is_dir: bool,
    /// Hard link count.
    pub n_links: u32,
    /// End of file in bytes.
    pub size: u64,
    /// Volume serial and file id.
    pub file_id: FileId,
}

/// The facts of the object behind `h`.
pub(crate) fn facts(h: &impl AsHandle) -> Result<Facts, FsError> {
    let basic: BasicInfo = info(h, FILE_BASIC_INFO_CLASS)?;
    let standard: StandardInfo = info(h, FILE_STANDARD_INFO_CLASS)?;
    let tag: AttributeTagInfo = info(h, FILE_ATTRIBUTE_TAG_INFO_CLASS)?;
    let id: IdInfo = info(h, FILE_ID_INFO_CLASS)?;
    Ok(Facts {
        attributes: basic.attributes,
        reparse_tag: if tag.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            tag.reparse_tag
        } else {
            0
        },
        is_dir: standard.directory != 0 || basic.attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        n_links: standard.number_of_links,
        size: u64::try_from(standard.end_of_file).unwrap_or(0),
        file_id: FileId {
            volume_serial: id.volume_serial,
            id: id.file_id,
        },
    })
}

/// `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)`, in `\\?\C:\...` form.
pub(crate) fn final_path(h: &impl AsHandle) -> Result<String, FsError> {
    let mut buf = vec![0u16; 512];
    loop {
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: the handle is live; `buf` has `len` writable units.
        let n = unsafe {
            GetFinalPathNameByHandleW(h.as_handle().as_raw_handle(), buf.as_mut_ptr(), len, 0)
        };
        if n == 0 {
            return Err(last_error());
        }
        let n = n as usize;
        if n < buf.len() {
            return Ok(String::from_utf16_lossy(&buf[..n]));
        }
        if buf.len() >= 1 << 16 {
            return Err(FsError::Other(122));
        }
        buf.resize(n + 1, 0);
    }
}

/// Renames the object behind `h` (opened with `DELETE`) into the directory behind `dir` as `leaf`.
/// With `replace`, an existing file of that name is replaced (POSIX semantics where supported);
/// without, [`FsError::AlreadyExists`] when the name is taken.
pub(crate) fn rename_at(
    h: &impl AsHandle,
    dir: &impl AsHandle,
    leaf: &str,
    replace: bool,
) -> Result<(), FsError> {
    if !plain_leaf(leaf) {
        return Err(FsError::Other(87));
    }
    let name: Vec<u16> = leaf.encode_utf16().collect();
    let Ok(name_bytes) = u32::try_from(name.len() * 2) else {
        return Err(FsError::Other(87));
    };
    let bytes = RENAME_NAME_OFFSET + (name.len() + 1) * 2;
    let mut last = FsError::Other(87);
    let attempts: [(i32, u32); 2] = if replace {
        [
            (
                NT_FILE_RENAME_INFORMATION_EX,
                FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
            ),
            (NT_FILE_RENAME_INFORMATION, 1),
        ]
    } else {
        [
            (NT_FILE_RENAME_INFORMATION_EX, 0),
            (NT_FILE_RENAME_INFORMATION, 0),
        ]
    };
    for (class, flags) in attempts {
        // u64 storage keeps the buffer aligned; zeroed, so the name is NUL-terminated.
        let mut buf = vec![0u64; bytes.div_ceil(8).max(3)];
        let base = buf.as_mut_ptr().cast::<u8>();
        // SAFETY: `buf` holds at least `bytes` bytes (and at least the 24-byte fixed part); the
        // flags word sits at 0, the root handle at 8, the name length at 16 and the name at 20,
        // the FILE_RENAME_INFORMATION layout on 64-bit Windows; `name.len()` units fit at 20.
        unsafe {
            base.cast::<u32>().write(flags);
            base.add(8)
                .cast::<Handle>()
                .write(dir.as_handle().as_raw_handle());
            base.add(16).cast::<u32>().write(name_bytes);
            ptr::copy_nonoverlapping(
                name.as_ptr(),
                base.add(RENAME_NAME_OFFSET).cast::<u16>(),
                name.len(),
            );
        }
        let mut io = IoStatusBlock::default();
        // SAFETY: live handles; `io` is writable; `buf` holds a complete FILE_RENAME_INFORMATION
        // of `bytes` bytes.
        let status = unsafe {
            NtSetInformationFile(
                h.as_handle().as_raw_handle(),
                &mut io,
                buf.as_ptr().cast(),
                bytes as u32,
                class,
            )
        };
        if status >= 0 {
            return Ok(());
        }
        last = status_error(status);
        // Only an unknown information class falls back to the older one.
        if !matches!(last, FsError::Other(1 | 50 | 87)) {
            break;
        }
    }
    Err(last)
}

/// Marks the object behind `h` (opened with `DELETE`) for deletion when its last handle closes.
pub(crate) fn dispose(h: &impl AsHandle) -> Result<(), FsError> {
    let delete: u8 = 1;
    // SAFETY: the handle is live; FILE_DISPOSITION_INFO is a single BOOLEAN, passed by pointer
    // with its size.
    let ok = unsafe {
        SetFileInformationByHandle(
            h.as_handle().as_raw_handle(),
            FILE_DISPOSITION_INFO_CLASS,
            (&delete as *const u8).cast(),
            1,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "purge-at-{tag}-{}-{:016x}",
            std::process::id(),
            super::super::sys::random_u64()
        ));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    fn dir_handle(path: &std::path::Path) -> purge_win::fs::FileHandle {
        purge_win::secure::open_for_security(path).unwrap()
    }

    #[test]
    fn relative_create_open_rename_and_delete() {
        let root = scratch("ops");
        let dir = dir_handle(&root);
        let create = Open {
            access: GENERIC_READ | GENERIC_WRITE | DELETE,
            share: SHARE_READ,
            create: Some("D:P(A;;FA;;;OW)(A;;FA;;;SY)"),
            kind: Kind::File,
        };
        let mut file = std::fs::File::from(open_at(&dir, "a.txt", create).unwrap());
        file.write_all(b"hello").unwrap();
        assert!(matches!(
            open_at(&dir, "a.txt", create),
            Err(FsError::AlreadyExists)
        ));
        let f = facts(&file).unwrap();
        assert!(!f.is_dir && f.n_links == 1 && f.reparse_tag == 0 && f.size == 5);
        assert!(final_path(&file).unwrap().ends_with(r"\a.txt"));
        drop(file);

        let read = Open {
            access: GENERIC_READ,
            share: SHARE_ALL,
            create: None,
            kind: Kind::File,
        };
        let mut back = String::new();
        std::fs::File::from(open_at(&dir, "a.txt", read).unwrap())
            .read_to_string(&mut back)
            .unwrap();
        assert_eq!(back, "hello");
        assert!(matches!(
            open_at(&dir, "missing", read),
            Err(FsError::NotFound)
        ));
        for bad in [r"..\x", "a/b", "x:s", ".", ".."] {
            assert!(open_at(&dir, bad, read).is_err(), "{bad}");
        }

        // A directory created relative to the handle, and a rename into it, never replacing.
        let sub = open_at(
            &dir,
            "sub",
            Open {
                access: FILE_READ_ATTRIBUTES,
                share: SHARE_ALL,
                create: Some("D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)"),
                kind: Kind::Dir,
            },
        )
        .unwrap();
        assert!(facts(&sub).unwrap().is_dir);
        flush_dir_at(&sub).unwrap();
        let mover = open_at(
            &dir,
            "a.txt",
            Open {
                access: DELETE | FILE_READ_ATTRIBUTES,
                share: SHARE_ALL,
                create: None,
                kind: Kind::File,
            },
        )
        .unwrap();
        rename_at(&mover, &sub, "b.txt", false).unwrap();
        assert!(root.join(r"sub\b.txt").exists() && !root.join("a.txt").exists());
        std::fs::write(root.join("c.txt"), b"c").unwrap();
        assert!(matches!(
            rename_at(&mover, &dir, "c.txt", false),
            Err(FsError::AlreadyExists)
        ));
        rename_at(&mover, &dir, "c.txt", true).unwrap();
        assert_eq!(std::fs::read(root.join("c.txt")).unwrap(), b"hello");
        dispose(&mover).unwrap();
        drop(mover);
        assert!(!root.join("c.txt").exists());
        drop((sub, dir));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn listing_through_a_directory_handle() {
        let root = scratch("list");
        let list = Open {
            access: FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            share: SHARE_ALL,
            create: None,
            kind: Kind::Dir,
        };
        let dir = dir_handle(&root);
        let listing = open_at(&dir, "", list).unwrap();
        assert_eq!(list_names(&listing).unwrap(), Vec::<String>::new());
        let mut expected: Vec<String> = (0..300).map(|n| format!("entry-{n:03}-ü")).collect();
        for name in &expected {
            std::fs::write(root.join(name), b"x").unwrap();
        }
        std::fs::create_dir(root.join("sub")).unwrap();
        expected.push("sub".to_owned());
        let mut names = list_names(&listing).unwrap();
        names.sort();
        expected.sort();
        assert_eq!(names, expected);
        // A handle without FILE_LIST_DIRECTORY cannot list.
        assert!(list_names(&dir).is_err());
        drop((listing, dir));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
