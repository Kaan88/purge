//! The two system calls the gate needs that `purge-win` does not wrap: the names of a file's hard links
//! (`FindFirstFileNameW`) and the process placeholder mode (`RtlSetProcessPlaceholderCompatibilityMode`).
//! Local declarations, so that no other crate changes.

use std::ffi::c_void;
use std::path::Path;

use purge_win::os::Win32Error;

/// `ERROR_HANDLE_EOF`: no more names.
const ERROR_HANDLE_EOF: u32 = 38;
/// `ERROR_MORE_DATA`: the name buffer is too small.
const ERROR_MORE_DATA: u32 = 234;
/// Longest name buffer tried (a path is at most 32,767 units).
const MAX_NAME_UNITS: usize = 32_768;
/// `PHCM_EXPOSE_PLACEHOLDERS`: placeholders are shown as what they are.
const PHCM_EXPOSE_PLACEHOLDERS: i8 = 2;

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn FindFirstFileNameW(
        file_name: *const u16,
        flags: u32,
        string_length: *mut u32,
        link_name: *mut u16,
    ) -> *mut c_void;
    fn FindNextFileNameW(find: *mut c_void, string_length: *mut u32, link_name: *mut u16) -> i32;
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

/// Closes a name-enumeration handle on drop.
struct NameFind(*mut c_void);

impl Drop for NameFind {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful FindFirstFileNameW and is closed exactly once.
        unsafe { FindClose(self.0) };
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
    use std::os::windows::ffi::OsStrExt;
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
            let find = NameFind(h);
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
