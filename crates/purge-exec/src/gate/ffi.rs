//! The system calls the gate needs that `purge-win` does not wrap: the names of a file's hard links
//! (`FindFirstFileNameW`), a directory listing that stops at a limit (`FindFirstFileExW`; `purge-win`'s
//! `list_dir` always reads the whole directory) and the process placeholder mode
//! (`RtlSetProcessPlaceholderCompatibilityMode`). Local declarations, so that no other crate changes.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use purge_win::fs::DirEntry;
use purge_win::os::Win32Error;

/// `ERROR_FILE_NOT_FOUND`: a listing matched nothing.
const ERROR_FILE_NOT_FOUND: u32 = 2;
/// `ERROR_NO_MORE_FILES`: the end of a listing.
const ERROR_NO_MORE_FILES: u32 = 18;
/// `ERROR_HANDLE_EOF`: no more names.
const ERROR_HANDLE_EOF: u32 = 38;
/// `ERROR_MORE_DATA`: the name buffer is too small.
const ERROR_MORE_DATA: u32 = 234;
/// Longest name buffer tried (a path is at most 32,767 units).
const MAX_NAME_UNITS: usize = 32_768;
/// `PHCM_EXPOSE_PLACEHOLDERS`: placeholders are shown as what they are.
const PHCM_EXPOSE_PLACEHOLDERS: i8 = 2;
/// `FindExInfoBasic`: no short name.
const FIND_EX_INFO_BASIC: i32 = 1;
/// `FindExSearchNameMatch`.
const FIND_EX_SEARCH_NAME_MATCH: i32 = 0;
/// `FIND_FIRST_EX_LARGE_FETCH`.
const FIND_FIRST_EX_LARGE_FETCH: u32 = 2;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// `WIN32_FIND_DATAW` (`FILETIME` is two `u32`, low part first).
#[repr(C)]
struct FindData {
    attributes: u32,
    creation_time: [u32; 2],
    last_access_time: [u32; 2],
    last_write_time: [u32; 2],
    size_high: u32,
    size_low: u32,
    reserved0: u32,
    _reserved1: u32,
    file_name: [u16; 260],
    _alternate_file_name: [u16; 14],
}

impl FindData {
    fn zeroed() -> FindData {
        FindData {
            attributes: 0,
            creation_time: [0; 2],
            last_access_time: [0; 2],
            last_write_time: [0; 2],
            size_high: 0,
            size_low: 0,
            reserved0: 0,
            _reserved1: 0,
            file_name: [0; 260],
            _alternate_file_name: [0; 14],
        }
    }
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn FindFirstFileNameW(
        file_name: *const u16,
        flags: u32,
        string_length: *mut u32,
        link_name: *mut u16,
    ) -> *mut c_void;
    fn FindNextFileNameW(find: *mut c_void, string_length: *mut u32, link_name: *mut u16) -> i32;
    fn FindFirstFileExW(
        file_name: *const u16,
        info_level: i32,
        find_data: *mut FindData,
        search_op: i32,
        search_filter: *const c_void,
        additional_flags: u32,
    ) -> *mut c_void;
    fn FindNextFileW(find: *mut c_void, find_data: *mut FindData) -> i32;
    fn FindClose(find: *mut c_void) -> i32;
}

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn RtlSetProcessPlaceholderCompatibilityMode(mode: i8) -> i8;
    fn RtlQueryProcessPlaceholderCompatibilityMode() -> i8;
}

/// `INVALID_HANDLE_VALUE`.
fn invalid_handle() -> *mut c_void {
    usize::MAX as *mut c_void
}

/// Closes a find handle (from `FindFirstFileNameW` or `FindFirstFileExW`) on drop.
struct Find(*mut c_void);

impl Drop for Find {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful FindFirstFileNameW or FindFirstFileExW call and is
        // closed exactly once.
        unsafe { FindClose(self.0) };
    }
}

/// One listed entry, its name strictly decoded.
fn dir_entry(fd: &FindData) -> Result<DirEntry, Win32Error> {
    let end = fd
        .file_name
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(fd.file_name.len());
    let name = String::from_utf16(&fd.file_name[..end]).map_err(|_| Win32Error::INVALID_DATA)?;
    let time = |t: [u32; 2]| (u64::from(t[1]) << 32) | u64::from(t[0]);
    let reparse = fd.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    Ok(DirEntry {
        name,
        attributes: fd.attributes,
        size: (u64::from(fd.size_high) << 32) | u64::from(fd.size_low),
        creation_time: time(fd.creation_time),
        last_access_time: time(fd.last_access_time),
        last_write_time: time(fd.last_write_time),
        reparse_tag: if reparse { fd.reserved0 } else { 0 },
    })
}

/// The entries directly inside `dir` (without `.` and `..`), as `purge-win`'s `list_dir` lists them
/// (nothing followed; a reparse point is an entry with its tag), but `Ok(None)` as soon as there are
/// more than `cap` of them: at most `cap` entries are ever held. A name that is not valid UTF-16 fails
/// the whole call.
pub(super) fn list_dir_capped(dir: &Path, cap: u64) -> Result<Option<Vec<DirEntry>>, Win32Error> {
    let mut pattern: Vec<u16> = dir.as_os_str().encode_wide().collect();
    if pattern.contains(&0) {
        return Err(Win32Error::INVALID_PARAMETER);
    }
    if pattern.last() != Some(&u16::from(b'\\')) {
        pattern.push(u16::from(b'\\'));
    }
    pattern.extend([u16::from(b'*'), 0]);
    let mut fd = FindData::zeroed();
    // SAFETY: `pattern` is NUL-terminated; `fd` is a writable WIN32_FIND_DATAW (the layout
    // FindExInfoBasic fills); no search filter.
    let h = unsafe {
        FindFirstFileExW(
            pattern.as_ptr(),
            FIND_EX_INFO_BASIC,
            &mut fd,
            FIND_EX_SEARCH_NAME_MATCH,
            std::ptr::null(),
            FIND_FIRST_EX_LARGE_FETCH,
        )
    };
    if h == invalid_handle() || h.is_null() {
        let e = Win32Error::last();
        // No match at all (only possible for an empty volume root) is an empty listing.
        return if e.0 == ERROR_FILE_NOT_FOUND {
            Ok(Some(Vec::new()))
        } else {
            Err(e)
        };
    }
    let find = Find(h);
    let mut out = Vec::new();
    loop {
        let entry = dir_entry(&fd)?;
        if entry.name != "." && entry.name != ".." {
            if out.len() as u64 >= cap {
                return Ok(None);
            }
            out.push(entry);
        }
        // SAFETY: `find.0` is a live find handle; `fd` is writable.
        if unsafe { FindNextFileW(find.0, &mut fd) } == 0 {
            let e = Win32Error::last();
            return if e.0 == ERROR_NO_MORE_FILES {
                Ok(Some(out))
            } else {
                Err(e)
            };
        }
    }
}

/// The name in `buf` up to its terminator, strictly decoded.
fn take_name(buf: &[u16], len: u32) -> Result<String, Win32Error> {
    let filled = &buf[..(len as usize).min(buf.len())];
    let end = filled.iter().position(|&c| c == 0).unwrap_or(filled.len());
    String::from_utf16(&filled[..end]).map_err(|_| Win32Error::INVALID_DATA)
}

/// Every name of the file at `path` (absolute, any form `CreateFileW` takes), relative to the root of its
/// volume (`\dir\file`), as `FindFirstFileNameW` / `FindNextFileNameW` list them. A name that is not valid
/// UTF-16 fails the whole call.
pub(super) fn file_names(path: &Path) -> Result<Vec<String>, Win32Error> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(Win32Error::INVALID_PARAMETER);
    }
    wide.push(0);
    let mut buf = vec![0u16; 1024];
    let find = loop {
        let mut len = buf.len() as u32;
        // SAFETY: `wide` is NUL-terminated; `buf` has `len` writable units; `len` is a valid local.
        let h = unsafe { FindFirstFileNameW(wide.as_ptr(), 0, &mut len, buf.as_mut_ptr()) };
        if h != invalid_handle() && !h.is_null() {
            let find = Find(h);
            break (find, len);
        }
        let e = Win32Error::last();
        if e.0 == ERROR_MORE_DATA && (len as usize) > buf.len() && (len as usize) <= MAX_NAME_UNITS
        {
            buf.resize(len as usize, 0);
            continue;
        }
        return Err(e);
    };
    let (find, len) = find;
    let mut names = vec![take_name(&buf, len)?];
    loop {
        let mut len = buf.len() as u32;
        // SAFETY: `find.0` is a live enumeration handle; `buf` has `len` writable units.
        let ok = unsafe { FindNextFileNameW(find.0, &mut len, buf.as_mut_ptr()) };
        if ok != 0 {
            names.push(take_name(&buf, len)?);
            continue;
        }
        let e = Win32Error::last();
        match e.0 {
            ERROR_HANDLE_EOF => return Ok(names),
            ERROR_MORE_DATA if (len as usize) > buf.len() && (len as usize) <= MAX_NAME_UNITS => {
                buf.resize(len as usize, 0);
            }
            _ => return Err(e),
        }
    }
}

/// Sets `PHCM_EXPOSE_PLACEHOLDERS` for the whole process and reads the mode back. `Err` carries the mode
/// or error code the system reported instead.
pub(super) fn expose_placeholders() -> Result<(), i8> {
    // SAFETY: plain value call without pointers.
    let previous = unsafe { RtlSetProcessPlaceholderCompatibilityMode(PHCM_EXPOSE_PLACEHOLDERS) };
    if previous < 0 {
        return Err(previous);
    }
    // SAFETY: plain call without arguments.
    let now = unsafe { RtlQueryProcessPlaceholderCompatibilityMode() };
    if now == PHCM_EXPOSE_PLACEHOLDERS {
        Ok(())
    } else {
        Err(now)
    }
}
