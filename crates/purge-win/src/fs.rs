//! Read-only filesystem access that never traverses reparse points.
//!
//! ENGINE_PLAN.md §3.2 / §5.10 (G1):
//! - [`list_dir`] uses `FindFirstFileExW(FindExInfoBasic, FIND_FIRST_EX_LARGE_FETCH)` and reports each
//!   entry's attributes, size, times and reparse tag. [`walk`] recurses with it but never descends
//!   into a reparse point (junction, symlink, mount point, cloud placeholder directory): such entries
//!   are reported, with their tag, and skipped.
//! - [`FileHandle`] opens a path with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`, so
//!   the handle is on the reparse point itself, and answers metadata, `FileIdInfo`
//!   ([`FileHandle::file_id`]) and `GetFinalPathNameByHandleW` ([`FileHandle::final_path`]) from it.
//!   `purge-guard` compares the final path with the lexical path (ReparseMismatch) and the FileId with
//!   the scan.
//! - [`long_path`] (`GetLongPathNameW`), [`volume_info`] (serial, drive type, filesystem name) and
//!   [`read_bytes`], a bounded read that refuses name-surrogate reparse points.
//!
//! Times are FILETIME tick counts (100 ns since 1601-01-01 UTC) as `u64`, the unit the rig snapshot
//! uses. All `unsafe` FFI is confined here with `SAFETY` comments.
#![cfg(feature = "read")]

use std::io::Read;
use std::mem::{MaybeUninit, size_of};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_INFO_BY_HANDLE_CLASS, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO,
    FIND_FIRST_EX_LARGE_FETCH, FileAttributeTagInfo, FileBasicInfo, FileIdInfo, FileStandardInfo,
    FindClose, FindExInfoBasic, FindExSearchNameMatch, FindFirstFileExW, FindNextFileW,
    GetDriveTypeW, GetFileInformationByHandleEx, GetFinalPathNameByHandleW, GetLongPathNameW,
    GetVolumeInformationW, GetVolumePathNameW, OPEN_EXISTING, SYNCHRONIZE, VOLUME_NAME_DOS,
    WIN32_FIND_DATAW,
};

use crate::os::{Win32Error, from_wide, wide};
use crate::reg::filetime_u64;

/// `FILE_ATTRIBUTE_DIRECTORY`.
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// `IO_REPARSE_TAG_MOUNT_POINT` (junctions and volume mount points).
pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
/// `IO_REPARSE_TAG_SYMLINK`.
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
/// `DRIVE_FIXED` from `GetDriveTypeW`.
pub const DRIVE_FIXED: u32 = 3;

/// Whether a reparse tag is a name surrogate (it names another file or directory: symlink,
/// junction, mount point), the `IsReparseTagNameSurrogate` test.
pub fn is_name_surrogate(tag: u32) -> bool {
    tag & 0x2000_0000 != 0
}

/// One directory entry from `FindFirstFileExW` / `FindNextFileW`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// File name (one component).
    pub name: String,
    /// `FILE_ATTRIBUTE_*` bits.
    pub attributes: u32,
    /// Size in bytes (0 for directories).
    pub size: u64,
    /// Creation time (FILETIME ticks).
    pub creation_time: u64,
    /// Last access time (FILETIME ticks).
    pub last_access_time: u64,
    /// Last write time (FILETIME ticks).
    pub last_write_time: u64,
    /// Reparse tag, `0` unless the entry is a reparse point.
    pub reparse_tag: u32,
}

impl DirEntry {
    /// Directory attribute set (a junction is a directory and a reparse point).
    pub fn is_dir(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    /// Reparse-point attribute set.
    pub fn is_reparse_point(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    fn from_find(fd: &WIN32_FIND_DATAW) -> DirEntry {
        let reparse = fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        DirEntry {
            name: from_wide(&fd.cFileName),
            attributes: fd.dwFileAttributes,
            size: (u64::from(fd.nFileSizeHigh) << 32) | u64::from(fd.nFileSizeLow),
            creation_time: filetime_u64(fd.ftCreationTime),
            last_access_time: filetime_u64(fd.ftLastAccessTime),
            last_write_time: filetime_u64(fd.ftLastWriteTime),
            reparse_tag: if reparse { fd.dwReserved0 } else { 0 },
        }
    }
}

/// Closes a find handle on drop.
struct FindHandle(windows_sys::Win32::Foundation::HANDLE);

impl Drop for FindHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful FindFirstFileExW and is closed exactly once.
        unsafe { FindClose(self.0) };
    }
}

/// The entries directly inside `dir` (without `.` and `..`). Never follows anything: a reparse
/// point inside `dir` is returned as an entry with its tag. If `dir` itself is a junction, the
/// listing is of its target (as with any path the caller passes); use [`FileHandle`] first to tell.
pub fn list_dir(dir: &Path) -> Result<Vec<DirEntry>, Win32Error> {
    let mut pattern = dir.as_os_str().to_owned();
    if !pattern.to_string_lossy().ends_with('\\') {
        pattern.push("\\");
    }
    pattern.push("*");
    let pattern = wide(&pattern);
    let mut fd = MaybeUninit::<WIN32_FIND_DATAW>::zeroed();
    // SAFETY: `pattern` is NUL-terminated; `fd` is a writable WIN32_FIND_DATAW (the layout used by
    // FindExInfoBasic); no search filter.
    let h = unsafe {
        FindFirstFileExW(
            pattern.as_ptr(),
            FindExInfoBasic,
            fd.as_mut_ptr().cast(),
            FindExSearchNameMatch,
            ptr::null(),
            FIND_FIRST_EX_LARGE_FETCH,
        )
    };
    if h == INVALID_HANDLE_VALUE {
        let e = Win32Error::last();
        // No match at all (only possible for an empty volume root) is an empty listing.
        return if e == Win32Error::FILE_NOT_FOUND {
            Ok(Vec::new())
        } else {
            Err(e)
        };
    }
    let h = FindHandle(h);
    let mut out = Vec::new();
    loop {
        // SAFETY: the previous FindFirstFileExW/FindNextFileW call succeeded and filled `fd`.
        let entry = DirEntry::from_find(unsafe { fd.assume_init_ref() });
        if entry.name != "." && entry.name != ".." {
            out.push(entry);
        }
        // SAFETY: `h.0` is a live find handle; `fd` is writable.
        if unsafe { FindNextFileW(h.0, fd.as_mut_ptr()) } == 0 {
            let e = Win32Error::last();
            return if e == Win32Error::NO_MORE_FILES {
                Ok(out)
            } else {
                Err(e)
            };
        }
    }
}

/// Recursive listing below `root` that never descends into a reparse point.
///
/// `visit(path, entry)` is called for every entry (pre-order); returning `false` for a directory
/// skips its contents. `max_depth` limits recursion (`Some(1)`: only the entries of `root`).
/// Directories that cannot be listed are collected and returned instead of aborting the walk.
pub fn walk(
    root: &Path,
    max_depth: Option<u32>,
    mut visit: impl FnMut(&Path, &DirEntry) -> bool,
) -> Vec<(PathBuf, Win32Error)> {
    let mut errors = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 1u32)];
    while let Some((dir, depth)) = stack.pop() {
        let entries = match list_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                errors.push((dir, e));
                continue;
            }
        };
        // Push in reverse so siblings are visited in listing order.
        let mut subdirs = Vec::new();
        for entry in &entries {
            let path = dir.join(&entry.name);
            let descend = visit(&path, entry);
            if descend
                && entry.is_dir()
                && !entry.is_reparse_point()
                && max_depth.is_none_or(|m| depth < m)
            {
                subdirs.push((path, depth + 1));
            }
        }
        stack.extend(subdirs.into_iter().rev());
    }
    errors
}

/// Volume serial number and 128-bit file id (`FILE_ID_INFO`): stable identity of a file on a volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    /// 64-bit volume serial number.
    pub volume_serial: u64,
    /// 128-bit file identifier.
    pub id: [u8; 16],
}

/// Metadata read from a [`FileHandle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMeta {
    /// `FILE_ATTRIBUTE_*` bits.
    pub attributes: u32,
    /// Reparse tag, `0` unless a reparse point.
    pub reparse_tag: u32,
    /// End of file in bytes.
    pub size: u64,
    /// Allocated size in bytes.
    pub allocation_size: u64,
    /// Hard link count.
    pub n_links: u32,
    /// Directory flag from `FILE_STANDARD_INFO`.
    pub is_dir: bool,
    /// Creation time (FILETIME ticks).
    pub creation_time: u64,
    /// Last access time (FILETIME ticks).
    pub last_access_time: u64,
    /// Last write time (FILETIME ticks).
    pub last_write_time: u64,
    /// Change time (FILETIME ticks).
    pub change_time: u64,
    /// Volume serial and file id.
    pub file_id: FileId,
}

impl FileMeta {
    /// Reparse-point attribute set.
    pub fn is_reparse_point(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
}

/// A handle opened on the path itself, never through a reparse point at its final component
/// (`FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`, attribute-read access, full sharing).
#[derive(Debug)]
pub struct FileHandle(pub(crate) OwnedHandle);

impl FileHandle {
    /// Opens `path` for attribute reads without following a final reparse point.
    pub fn open(path: &Path) -> Result<FileHandle, Win32Error> {
        open_no_follow(path, FILE_READ_ATTRIBUTES | SYNCHRONIZE).map(FileHandle)
    }

    /// Attributes, sizes, times, reparse tag and file id.
    pub fn metadata(&self) -> Result<FileMeta, Win32Error> {
        let basic: FILE_BASIC_INFO = info_by_handle(&self.0, FileBasicInfo)?;
        let std_info: FILE_STANDARD_INFO = info_by_handle(&self.0, FileStandardInfo)?;
        let tag: FILE_ATTRIBUTE_TAG_INFO = info_by_handle(&self.0, FileAttributeTagInfo)?;
        Ok(FileMeta {
            attributes: basic.FileAttributes,
            reparse_tag: if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                tag.ReparseTag
            } else {
                0
            },
            size: std_info.EndOfFile as u64,
            allocation_size: std_info.AllocationSize as u64,
            n_links: std_info.NumberOfLinks,
            is_dir: std_info.Directory,
            creation_time: basic.CreationTime as u64,
            last_access_time: basic.LastAccessTime as u64,
            last_write_time: basic.LastWriteTime as u64,
            change_time: basic.ChangeTime as u64,
            file_id: self.file_id()?,
        })
    }

    /// `FileIdInfo`.
    pub fn file_id(&self) -> Result<FileId, Win32Error> {
        let info: FILE_ID_INFO = info_by_handle(&self.0, FileIdInfo)?;
        Ok(FileId {
            volume_serial: info.VolumeSerialNumber,
            id: info.FileId.Identifier,
        })
    }

    /// Reparse tag of the opened object (`0` if it is not a reparse point).
    pub fn reparse_tag(&self) -> Result<u32, Win32Error> {
        reparse_tag_of(&self.0)
    }

    /// `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)`, in `\\?\C:\...` form.
    /// For a handle on a reparse point this is the reparse point's own path.
    pub fn final_path(&self) -> Result<String, Win32Error> {
        let mut buf = vec![0u16; 512];
        loop {
            // SAFETY: the handle is live; `buf` has `buf.len()` writable units.
            let n = unsafe {
                GetFinalPathNameByHandleW(
                    self.0.as_raw_handle(),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    VOLUME_NAME_DOS,
                )
            } as usize;
            if n == 0 {
                return Err(Win32Error::last());
            }
            if n < buf.len() {
                return Ok(String::from_utf16_lossy(&buf[..n]));
            }
            buf.resize(n + 1, 0);
        }
    }
}

/// `CreateFileW(OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)`.
fn open_no_follow(path: &Path, access: u32) -> Result<OwnedHandle, Win32Error> {
    let p = wide(path);
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
    // SAFETY: `h` is a freshly opened valid handle owned by nobody else.
    Ok(unsafe { OwnedHandle::from_raw_handle(h) })
}

/// `GetFileInformationByHandleEx` for a fixed-size, plain-data info class `T`.
fn info_by_handle<T>(h: &OwnedHandle, class: FILE_INFO_BY_HANDLE_CLASS) -> Result<T, Win32Error> {
    let mut out = MaybeUninit::<T>::zeroed();
    // SAFETY: `out` provides `size_of::<T>()` writable bytes; callers pair each class with its
    // documented struct (FileBasicInfo/FILE_BASIC_INFO, etc.).
    let ok = unsafe {
        GetFileInformationByHandleEx(
            h.as_raw_handle(),
            class,
            out.as_mut_ptr().cast(),
            size_of::<T>() as u32,
        )
    };
    if ok == 0 {
        return Err(Win32Error::last());
    }
    // SAFETY: the call succeeded and filled the struct; every field type is plain data valid for
    // any bit pattern written by the OS (the two `bool` fields are written as 0/1 BOOLEANs).
    Ok(unsafe { out.assume_init() })
}

/// Reparse tag of an open handle (`0` when not a reparse point).
pub(crate) fn reparse_tag_of(h: &OwnedHandle) -> Result<u32, Win32Error> {
    let tag: FILE_ATTRIBUTE_TAG_INFO = info_by_handle(h, FileAttributeTagInfo)?;
    Ok(if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        tag.ReparseTag
    } else {
        0
    })
}

/// [`FileHandle::metadata`] for a path (the final component is not followed).
pub fn metadata(path: &Path) -> Result<FileMeta, Win32Error> {
    FileHandle::open(path)?.metadata()
}

/// [`FileHandle::file_id`] for a path.
pub fn file_id(path: &Path) -> Result<FileId, Win32Error> {
    FileHandle::open(path)?.file_id()
}

/// [`FileHandle::final_path`] for a path.
pub fn final_path(path: &Path) -> Result<String, Win32Error> {
    FileHandle::open(path)?.final_path()
}

/// `GetLongPathNameW`: expands 8.3 components. The path must exist.
pub fn long_path(path: &Path) -> Result<String, Win32Error> {
    let p = wide(path);
    let mut buf = vec![0u16; p.len().max(260)];
    loop {
        // SAFETY: `p` is NUL-terminated and `buf` has `buf.len()` writable units.
        let n =
            unsafe { GetLongPathNameW(p.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if n == 0 {
            return Err(Win32Error::last());
        }
        if n < buf.len() {
            return Ok(String::from_utf16_lossy(&buf[..n]));
        }
        buf.resize(n + 1, 0);
    }
}

/// Facts about the volume holding a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    /// Volume mount path from `GetVolumePathNameW`, e.g. `C:\`.
    pub root: String,
    /// 32-bit volume serial number from `GetVolumeInformationW`.
    pub serial: u32,
    /// `GetDriveTypeW` result (`DRIVE_FIXED` = 3, removable = 2, remote = 4, ...).
    pub drive_type: u32,
    /// Filesystem name, e.g. `NTFS` or `ReFS`.
    pub fs_name: String,
}

impl VolumeInfo {
    /// A fixed (non-removable, local) drive.
    pub fn is_fixed(&self) -> bool {
        self.drive_type == DRIVE_FIXED
    }
}

/// Volume root, serial, drive type and filesystem name for the volume holding `path`.
pub fn volume_info(path: &Path) -> Result<VolumeInfo, Win32Error> {
    let p = wide(path);
    let mut root = vec![0u16; p.len().max(261)];
    // SAFETY: `p` is NUL-terminated and `root` has `root.len()` writable units.
    if unsafe { GetVolumePathNameW(p.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
        return Err(Win32Error::last());
    }
    let root_str = from_wide(&root);
    let root_w = wide(&root_str);
    let mut serial = 0u32;
    let mut fs_name = [0u16; 64];
    // SAFETY: `root_w` is NUL-terminated; `fs_name` has 64 writable units; the volume label,
    // maximum component length and flags are not requested (null).
    let ok = unsafe {
        GetVolumeInformationW(
            root_w.as_ptr(),
            ptr::null_mut(),
            0,
            &mut serial,
            ptr::null_mut(),
            ptr::null_mut(),
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        )
    };
    if ok == 0 {
        return Err(Win32Error::last());
    }
    // SAFETY: `root_w` is NUL-terminated.
    let drive_type = unsafe { GetDriveTypeW(root_w.as_ptr()) };
    Ok(VolumeInfo {
        root: root_str,
        serial,
        drive_type,
        fs_name: from_wide(&fs_name),
    })
}

/// Reads at most `max` bytes from the start of a file. A name-surrogate reparse point (symlink,
/// junction) is refused with `ERROR_CANT_ACCESS_FILE` instead of being followed; other reparse
/// points (e.g. cloud placeholders) are read through the handle as opened, without a recall request.
pub fn read_bytes(path: &Path, max: usize) -> Result<Vec<u8>, Win32Error> {
    let h = open_no_follow(path, GENERIC_READ | SYNCHRONIZE)?;
    if is_name_surrogate(reparse_tag_of(&h)?) {
        return Err(Win32Error::CANT_ACCESS_FILE);
    }
    let mut out = Vec::new();
    std::fs::File::from(h)
        .take(max as u64)
        .read_to_end(&mut out)
        .map_err(|e| {
            e.raw_os_error()
                .map_or(Win32Error::INVALID_DATA, |c| Win32Error(c as u32))
        })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
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
                .join(format!("purge-win-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            // Remove junctions first (remove_dir on a junction deletes the link, not the target).
            if let Ok(entries) = list_dir(&self.0) {
                for e in entries.iter().filter(|e| e.is_reparse_point()) {
                    let _ = std::fs::remove_dir(self.0.join(&e.name));
                }
            }
            let _ = std::fs::remove_dir_all(&self.0);
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

    #[test]
    fn junction_is_listed_with_tag_and_not_traversed() {
        let s = Scratch::new("junction");
        let target = s.0.join("real");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("inside.txt"), b"x").unwrap();
        std::fs::write(s.0.join("plain.bin"), [0u8; 1234]).unwrap();
        let link = s.0.join("link");
        mklink_junction(&link, &target);

        let entries = list_dir(&s.0).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(entries.len(), 3, "{names:?}");
        let l = entries.iter().find(|e| e.name == "link").unwrap();
        assert!(l.is_dir() && l.is_reparse_point());
        assert_eq!(l.reparse_tag, IO_REPARSE_TAG_MOUNT_POINT);
        assert!(is_name_surrogate(l.reparse_tag));
        let p = entries.iter().find(|e| e.name == "plain.bin").unwrap();
        assert_eq!((p.size, p.reparse_tag, p.is_dir()), (1234, 0, false));
        assert!(p.last_write_time > 0 && p.creation_time > 0);

        let mut seen = Vec::new();
        let errors = walk(&s.0, None, |path, _| {
            seen.push(path.strip_prefix(&s.0).unwrap().to_path_buf());
            true
        });
        assert!(errors.is_empty(), "{errors:?}");
        seen.sort();
        let expect: Vec<PathBuf> = ["link", "plain.bin", "real", r"real\inside.txt"]
            .iter()
            .map(PathBuf::from)
            .collect();
        assert_eq!(seen, expect, "walk must not descend into the junction");

        // Depth limit.
        let mut shallow = 0;
        walk(&s.0, Some(1), |_, _| {
            shallow += 1;
            true
        });
        assert_eq!(shallow, 3);

        // Handle metadata is the junction's own, and its final path is the link path.
        let h = FileHandle::open(&link).unwrap();
        let m = h.metadata().unwrap();
        assert!(m.is_reparse_point() && m.is_dir);
        assert_eq!(m.reparse_tag, IO_REPARSE_TAG_MOUNT_POINT);
        let canon_dir = std::fs::canonicalize(&s.0).unwrap();
        assert!(
            h.final_path()
                .unwrap()
                .eq_ignore_ascii_case(&canon_dir.join("link").to_string_lossy())
        );
        assert_ne!(h.file_id().unwrap(), file_id(&target).unwrap());

        // Bounded read refuses the junction instead of following it.
        assert_eq!(read_bytes(&link, 10), Err(Win32Error::CANT_ACCESS_FILE));
    }

    #[test]
    fn file_id_stable_and_final_path() {
        let s = Scratch::new("fileid");
        let a = s.0.join("a.txt");
        let b = s.0.join("b.txt");
        std::fs::write(&a, b"hello").unwrap();
        std::fs::write(&b, b"world").unwrap();
        let id1 = file_id(&a).unwrap();
        let id2 = FileHandle::open(&a).unwrap().file_id().unwrap();
        assert_eq!(id1, id2);
        assert_ne!(id1, file_id(&b).unwrap());
        assert_ne!(id1.volume_serial, 0);

        let m = metadata(&a).unwrap();
        assert_eq!(
            (m.size, m.is_dir, m.reparse_tag, m.n_links),
            (5, false, 0, 1)
        );
        assert_eq!(m.file_id, id1);
        let canon = std::fs::canonicalize(&a).unwrap();
        assert!(
            final_path(&a)
                .unwrap()
                .eq_ignore_ascii_case(&canon.to_string_lossy())
        );
        assert!(metadata(&s.0.join("missing")).unwrap_err().is_not_found());
    }

    #[test]
    fn long_path_and_volume() {
        let s = Scratch::new("longpath");
        let f = s.0.join("a rather long file name for 8dot3.txt");
        std::fs::write(&f, b"").unwrap();
        let canon = std::fs::canonicalize(&f).unwrap();
        assert!(
            long_path(&canon)
                .unwrap()
                .eq_ignore_ascii_case(&canon.to_string_lossy())
        );
        // If 8.3 names exist on this volume, the short form expands back to the long one.
        let out = Command::new("cmd")
            .arg("/c")
            .arg(format!("for %I in (\"{}\") do @echo %~sI", f.display()))
            .output();
        if let Ok(out) = out {
            let short = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !short.is_empty() && short != f.to_string_lossy() && Path::new(&short).exists() {
                assert!(
                    long_path(Path::new(&short))
                        .unwrap()
                        .eq_ignore_ascii_case(&f.to_string_lossy()),
                    "{short}"
                );
            }
        }

        let v = volume_info(&s.0).unwrap();
        assert!(v.root.ends_with('\\'), "{v:?}");
        assert!(v.fs_name == "NTFS" || v.fs_name == "ReFS", "{v:?}");
        assert!(v.is_fixed());
        assert_ne!(v.serial, 0);
        let vv = volume_info(&std::fs::canonicalize(&s.0).unwrap()).unwrap();
        assert_eq!(
            (vv.serial, vv.drive_type, vv.fs_name.as_str()),
            (v.serial, v.drive_type, v.fs_name.as_str())
        );
    }

    #[test]
    fn bounded_read() {
        let s = Scratch::new("read");
        let f = s.0.join("data.bin");
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        std::fs::write(&f, &data).unwrap();
        assert_eq!(read_bytes(&f, 10).unwrap(), data[..10]);
        assert_eq!(read_bytes(&f, 5000).unwrap(), data);
        assert_eq!(read_bytes(&f, 0).unwrap(), Vec::<u8>::new());
        assert!(
            read_bytes(&s.0.join("missing"), 1)
                .unwrap_err()
                .is_not_found()
        );
    }

    #[test]
    fn list_errors() {
        assert!(
            list_dir(Path::new(r"C:\purge-test-no-such-dir-5d1e"))
                .unwrap_err()
                .is_not_found()
        );
        let root = list_dir(Path::new(r"C:\")).unwrap();
        assert!(
            root.iter()
                .any(|e| e.name.eq_ignore_ascii_case("Windows") && e.is_dir())
        );
    }
}
