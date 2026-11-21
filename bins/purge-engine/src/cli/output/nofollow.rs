//! Writing a file without following a reparse point anywhere on its path (review M2 S7).
//!
//! The path is made absolute, then opened one component at a time: the root (`X:\` or `\\server\share\`)
//! by path, every directory below it with `NtCreateFile` relative to the handle of the one above, with
//! `FILE_OPEN_REPARSE_POINT`, so a link is opened itself and never followed. A component whose reparse
//! tag is a name surrogate (a junction, a symbolic link, a mount point) is refused. The temporary file
//! is created new (`FILE_CREATE`) relative to the handle of the verified directory, and renamed to the
//! final name relative to that same handle: nothing between the checked directories and the file is
//! resolved by name again. Declared here because the engine has no `windows-sys` dependency and its
//! default build does not enable `purge-win/write`.

use std::ffi::{OsStr, c_void};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr;

type Handle = *mut c_void;

/// `DELETE`.
const DELETE: u32 = 0x0001_0000;
/// `SYNCHRONIZE`.
const SYNCHRONIZE: u32 = 0x0010_0000;
/// `FILE_WRITE_DATA`.
const FILE_WRITE_DATA: u32 = 0x2;
/// `FILE_APPEND_DATA`.
const FILE_APPEND_DATA: u32 = 0x4;
/// `FILE_TRAVERSE`.
const FILE_TRAVERSE: u32 = 0x20;
/// `FILE_READ_ATTRIBUTES`.
const FILE_READ_ATTRIBUTES: u32 = 0x80;
/// `FILE_WRITE_ATTRIBUTES`.
const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
/// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`.
const SHARE_ALL: u32 = 0x7;
/// `FILE_OPEN`.
const FILE_OPEN: u32 = 1;
/// `FILE_CREATE`: fails if anything has the name.
const FILE_CREATE: u32 = 2;
/// `FILE_DIRECTORY_FILE`.
const FILE_DIRECTORY_FILE: u32 = 0x1;
/// `FILE_SYNCHRONOUS_IO_NONALERT`.
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
/// `FILE_NON_DIRECTORY_FILE`.
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
/// `FILE_OPEN_REPARSE_POINT`.
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// `FILE_FLAG_BACKUP_SEMANTICS`: what opening a directory by path needs.
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// `FILE_FLAG_OPEN_REPARSE_POINT`.
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// `FILE_ATTRIBUTE_NORMAL`.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
/// `FILE_ATTRIBUTE_DIRECTORY`.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// The name-surrogate bit of a reparse tag: the object stands for another name (a link).
const REPARSE_TAG_NAME_SURROGATE: u32 = 0x2000_0000;
/// `OBJ_CASE_INSENSITIVE`, as Win32 opens names.
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
/// `FileAttributeTagInfo` (`FILE_INFO_BY_HANDLE_CLASS`).
const FILE_ATTRIBUTE_TAG_INFO_CLASS: i32 = 9;
/// `FileRenameInformation` (`FILE_INFORMATION_CLASS`).
const NT_FILE_RENAME_INFORMATION: i32 = 10;
/// `FileDispositionInformation`.
const NT_FILE_DISPOSITION_INFORMATION: i32 = 13;
/// Offset of `FileName` in `FILE_RENAME_INFORMATION` on 64-bit Windows.
const RENAME_NAME_OFFSET: usize = 20;

// The offset above and the hand-written `FILE_RENAME_INFORMATION` hold for 64-bit Windows only (F10 of
// the M2 fix-round review).
#[cfg(not(target_pointer_width = "64"))]
compile_error!(
    "the no-follow writer's FILE_RENAME_INFORMATION layout is written for 64-bit Windows"
);

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
struct AttributeTagInfo {
    attributes: u32,
    reparse_tag: u32,
}

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
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
    fn NtSetInformationFile(
        file: Handle,
        io_status: *mut IoStatusBlock,
        info: *const c_void,
        length: u32,
        class: i32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn GetFileInformationByHandleEx(file: Handle, class: i32, info: *mut c_void, size: u32) -> i32;
}

fn status_error(status: i32) -> io::Error {
    // SAFETY: a pure status-to-code mapping.
    let code = unsafe { RtlNtStatusToDosError(status) };
    io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX))
}

fn invalid(text: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, text.to_owned())
}

/// An absolute path split for the handle walk: the root to open by path, the directory names below
/// it, and the file name, each a plain name in UTF-16.
#[derive(Debug, PartialEq, Eq)]
struct Walk {
    root: PathBuf,
    dirs: Vec<Vec<u16>>,
    leaf: Vec<u16>,
}

/// A plain name component: not empty, no separator, no stream (`:`), no NUL.
fn plain(name: &OsStr) -> Option<Vec<u16>> {
    let wide: Vec<u16> = name.encode_wide().collect();
    let bad = [u16::from(b'\\'), u16::from(b'/'), u16::from(b':'), 0];
    (!wide.is_empty() && !wide.iter().any(|unit| bad.contains(unit))).then_some(wide)
}

/// Splits `path` (made absolute against the current directory) into a [`Walk`]. Only a drive
/// (`C:\`, `\\?\C:\`) or a share (`\\server\share\`, `\\?\UNC\server\share\`) root is accepted, and
/// every component below it must be a plain name (`.` and `..` are resolved by the absolute form or
/// refused).
fn split(path: &Path) -> io::Result<Walk> {
    let absolute = std::path::absolute(path)?;
    let mut components = absolute.components();
    let root = match (components.next(), components.next()) {
        (Some(Component::Prefix(prefix)), Some(Component::RootDir))
            if matches!(
                prefix.kind(),
                Prefix::Disk(_)
                    | Prefix::VerbatimDisk(_)
                    | Prefix::UNC(..)
                    | Prefix::VerbatimUNC(..)
            ) =>
        {
            let mut root = PathBuf::from(prefix.as_os_str());
            root.push(std::path::MAIN_SEPARATOR_STR);
            root
        }
        _ => return Err(invalid("the output path is not on a drive or a share")),
    };
    let mut names = Vec::new();
    for component in components {
        match component {
            Component::Normal(name) => names.push(
                plain(name)
                    .ok_or_else(|| invalid("the output path has a name that is not plain"))?,
            ),
            _ => return Err(invalid("the output path has a `.` or `..` component")),
        }
    }
    let leaf = names
        .pop()
        .ok_or_else(|| invalid("the path names no file"))?;
    Ok(Walk {
        root,
        dirs: names,
        leaf,
    })
}

/// Opens `name` relative to `dir`, never following a reparse point at the name.
fn open_at(
    dir: &impl AsRawHandle,
    name: &[u16],
    access: u32,
    disposition: u32,
    options: u32,
) -> io::Result<OwnedHandle> {
    let bytes = u16::try_from(name.len() * 2).map_err(|_| invalid("a name is too long"))?;
    let unicode = UnicodeString {
        length: bytes,
        maximum_length: bytes,
        buffer: name.as_ptr(),
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: dir.as_raw_handle(),
        object_name: &unicode,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: ptr::null(),
        security_quality_of_service: ptr::null(),
    };
    let mut handle: Handle = ptr::null_mut();
    let mut io = IoStatusBlock::default();
    // SAFETY: `attributes` points to live locals (`unicode`, whose buffer `name` outlives the call);
    // the root handle is borrowed for the call; `handle` and `io` are writable; no allocation size
    // and no extended attributes.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes,
            &mut io,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            SHARE_ALL,
            disposition,
            options | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
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

/// The attributes and reparse tag (0 unless a reparse point) of the object behind `h`.
fn attributes(h: &impl AsRawHandle) -> io::Result<AttributeTagInfo> {
    let mut out = AttributeTagInfo::default();
    // SAFETY: the handle is live for the call; `out` is a writable value of exactly the size passed,
    // of the layout the class documents.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            h.as_raw_handle(),
            FILE_ATTRIBUTE_TAG_INFO_CLASS,
            (&mut out as *mut AttributeTagInfo).cast(),
            size_of::<AttributeTagInfo>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(out)
}

/// Refuses a directory handle that is a link (a name-surrogate reparse point) or not a directory.
fn check_dir(h: &impl AsRawHandle) -> io::Result<()> {
    let info = attributes(h)?;
    if info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        && info.reparse_tag & REPARSE_TAG_NAME_SURROGATE != 0
    {
        return Err(invalid(
            "a directory on the output path is a link or junction; it is not followed",
        ));
    }
    if info.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(invalid("a component of the output path is not a directory"));
    }
    Ok(())
}

/// One `NtSetInformationFile` call with a buffer of `bytes` bytes at `info`.
fn set_info(h: &impl AsRawHandle, info: *const c_void, bytes: usize, class: i32) -> io::Result<()> {
    let mut io = IoStatusBlock::default();
    // SAFETY: the handle is live; `io` is writable; the caller passes a buffer of `bytes` bytes of
    // the layout `class` documents.
    let status = unsafe {
        NtSetInformationFile(
            h.as_raw_handle(),
            &mut io,
            info,
            u32::try_from(bytes).unwrap_or(u32::MAX),
            class,
        )
    };
    if status < 0 {
        return Err(status_error(status));
    }
    Ok(())
}

/// Renames the file behind `h` (opened with `DELETE`) to `leaf` in the directory behind `dir`,
/// replacing a file of that name.
fn rename_at(h: &impl AsRawHandle, dir: &impl AsRawHandle, leaf: &[u16]) -> io::Result<()> {
    let name_bytes = u32::try_from(leaf.len() * 2).map_err(|_| invalid("a name is too long"))?;
    let bytes = RENAME_NAME_OFFSET + (leaf.len() + 1) * 2;
    // u64 storage keeps the buffer aligned; zeroed, so the name is NUL-terminated.
    let mut buf = vec![0u64; bytes.div_ceil(8).max(3)];
    let base = buf.as_mut_ptr().cast::<u8>();
    // SAFETY: `buf` holds at least `bytes` bytes; ReplaceIfExists sits at 0, the root handle at 8,
    // the name length at 16 and the name at 20, the FILE_RENAME_INFORMATION layout on 64-bit Windows.
    unsafe {
        base.write(1);
        base.add(8).cast::<Handle>().write(dir.as_raw_handle());
        base.add(16).cast::<u32>().write(name_bytes);
        ptr::copy_nonoverlapping(
            leaf.as_ptr(),
            base.add(RENAME_NAME_OFFSET).cast::<u16>(),
            leaf.len(),
        );
    }
    set_info(h, buf.as_ptr().cast(), bytes, NT_FILE_RENAME_INFORMATION)
}

/// Marks the file behind `h` (opened with `DELETE`) for deletion when its handle closes.
fn dispose(h: &impl AsRawHandle) -> io::Result<()> {
    let delete: u8 = 1;
    set_info(
        h,
        (&delete as *const u8).cast(),
        1,
        NT_FILE_DISPOSITION_INFORMATION,
    )
}

/// Writes `bytes` to `path` through a temporary file in the verified directory, then renames it over
/// `path` relative to that directory's handle. A reparse point at `path` itself, or a directory
/// there, is refused and left alone.
pub(super) fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let walk = split(path)?;
    let mut dir: File = OpenOptions::new()
        .access_mode(FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&walk.root)?;
    check_dir(&dir)?;
    for name in &walk.dirs {
        let next = open_at(
            &dir,
            name,
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
        )
        .map(File::from)?;
        check_dir(&next)?;
        dir = next;
    }
    match open_at(&dir, &walk.leaf, FILE_READ_ATTRIBUTES, FILE_OPEN, 0) {
        Ok(existing) => {
            let info = attributes(&existing)?;
            if info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(invalid(
                    "a reparse point (link or junction) is at the output path; it is not followed or replaced",
                ));
            }
            if info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                return Err(invalid("a directory is at the output path"));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut tmp_name = vec![u16::from(b'.')];
    tmp_name.extend_from_slice(&walk.leaf);
    tmp_name.extend(format!(".{}.{nanos:x}.tmp", std::process::id()).encode_utf16());
    let mut tmp = open_at(
        &dir,
        &tmp_name,
        FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | DELETE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    )
    .map(File::from)?;
    // Only the file this call created is ever removed again, through its own handle.
    let result = tmp
        .write_all(bytes)
        .and_then(|()| tmp.sync_all())
        .and_then(|()| rename_at(&tmp, &dir, &walk.leaf));
    if result.is_err() {
        let _ = dispose(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn paths_split_into_a_root_and_plain_names() {
        assert_eq!(
            split(Path::new(r"C:\run\out\plan.json")).unwrap(),
            Walk {
                root: PathBuf::from(r"C:\"),
                dirs: vec![wide("run"), wide("out")],
                leaf: wide("plan.json"),
            }
        );
        // `..` is resolved lexically by the absolute form of a plain path.
        assert_eq!(
            split(Path::new(r"C:\run\x\..\plan.json")).unwrap().dirs,
            [wide("run")]
        );
        assert_eq!(
            split(Path::new(r"\\server\share\d\p.json")).unwrap(),
            Walk {
                root: PathBuf::from(r"\\server\share\"),
                dirs: vec![wide("d")],
                leaf: wide("p.json"),
            }
        );
        assert_eq!(
            split(Path::new(r"\\?\C:\d\p.json")).unwrap().root,
            PathBuf::from(r"\\?\C:\")
        );
        for bad in [
            r"\\?\C:\d\..\p.json",
            r"\\.\C:\p.json",
            r"\\?\GLOBALROOT\Device\x\p.json",
            r"C:\d\p.json:stream",
            r"C:\",
        ] {
            assert!(split(Path::new(bad)).is_err(), "{bad}");
        }
        // A relative path is taken against the current directory.
        let here = split(Path::new("p.json")).unwrap();
        assert_eq!(here.leaf, wide("p.json"));
    }
}
