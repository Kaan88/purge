//! Operating-system facts and the shared Win32 error type.
//!
//! - [`Win32Error`]: the error every read wrapper in `reg`, `fs`, `sid`, `known_folders` and `env`
//!   returns, a thin newtype over a `GetLastError` / `WIN32_ERROR` code.
//! - [`os_version`]: `EditionID`, `CurrentBuildNumber` and `UBR` read from
//!   `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` in the 64-bit view, the same three facts the
//!   rig snapshot header records (`vm/RIG.md` §2) and the baseline filter keys on (ENGINE_PLAN.md §5.5).
//!
//! The crate-private helpers here convert between Rust strings and NUL-terminated UTF-16.
#![cfg(feature = "read")]

use std::ffi::OsStr;
use std::fmt;
use std::os::windows::ffi::OsStrExt;

use crate::reg::{Key, RegRoot, RegView};

/// A Win32 error code (`WIN32_ERROR`, as returned by the registry API or `GetLastError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Win32Error(pub u32);

impl Win32Error {
    /// `ERROR_FILE_NOT_FOUND`.
    pub const FILE_NOT_FOUND: Win32Error = Win32Error(2);
    /// `ERROR_PATH_NOT_FOUND`.
    pub const PATH_NOT_FOUND: Win32Error = Win32Error(3);
    /// `ERROR_ACCESS_DENIED`.
    pub const ACCESS_DENIED: Win32Error = Win32Error(5);
    /// `ERROR_NO_MORE_FILES`.
    pub const NO_MORE_FILES: Win32Error = Win32Error(18);
    /// `ERROR_INVALID_DATA`: returned by the wrappers for malformed data (bad SID, bad ACL, bad path).
    pub const INVALID_DATA: Win32Error = Win32Error(13);
    /// `ERROR_INVALID_PARAMETER`.
    pub const INVALID_PARAMETER: Win32Error = Win32Error(87);
    /// `ERROR_INSUFFICIENT_BUFFER`.
    pub const INSUFFICIENT_BUFFER: Win32Error = Win32Error(122);
    /// `ERROR_MORE_DATA`.
    pub const MORE_DATA: Win32Error = Win32Error(234);
    /// `ERROR_NO_MORE_ITEMS`.
    pub const NO_MORE_ITEMS: Win32Error = Win32Error(259);
    /// `ERROR_CANT_RESOLVE_FILENAME`: returned by `reg` when a registry path would have to pass
    /// through a symbolic link key, which is never followed.
    pub const LINK_ON_PATH: Win32Error = Win32Error(1921);
    /// `ERROR_CANT_ACCESS_FILE`: returned when a path names a reparse point the caller asked not to
    /// follow (for example a bounded read of a symbolic link).
    pub const CANT_ACCESS_FILE: Win32Error = Win32Error(1920);

    /// The calling thread's last error (`GetLastError`).
    pub fn last() -> Win32Error {
        Win32Error(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32)
    }

    /// The raw code.
    pub fn code(self) -> u32 {
        self.0
    }

    /// `ERROR_FILE_NOT_FOUND` or `ERROR_PATH_NOT_FOUND`.
    pub fn is_not_found(self) -> bool {
        self == Self::FILE_NOT_FOUND || self == Self::PATH_NOT_FOUND
    }

    /// `ERROR_ACCESS_DENIED`.
    pub fn is_access_denied(self) -> bool {
        self == Self::ACCESS_DENIED
    }

    /// Converts a `WIN32_ERROR` return value: `0` is success.
    pub(crate) fn check(code: u32) -> Result<(), Win32Error> {
        if code == 0 {
            Ok(())
        } else {
            Err(Win32Error(code))
        }
    }
}

impl fmt::Display for Win32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = std::io::Error::from_raw_os_error(self.0 as i32);
        write!(f, "Win32 error {}: {msg}", self.0)
    }
}

impl std::error::Error for Win32Error {}

impl From<Win32Error> for std::io::Error {
    fn from(e: Win32Error) -> Self {
        std::io::Error::from_raw_os_error(e.0 as i32)
    }
}

/// NUL-terminated UTF-16 for a Win32 `PCWSTR` argument.
pub(crate) fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// Lossy UTF-16 to `String`, stopping at the first NUL if there is one.
pub(crate) fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Reads a NUL-terminated UTF-16 string from a raw pointer.
///
/// # Safety
/// `p` must be null or point to a readable, NUL-terminated UTF-16 string.
pub(crate) unsafe fn from_wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: the caller guarantees `p` is NUL-terminated, so every index up to and including the
    // terminator is readable.
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

/// Windows version facts from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsVersion {
    /// `EditionID`, e.g. `Professional`.
    pub edition_id: String,
    /// `CurrentBuildNumber` parsed as a number, e.g. `26100`.
    pub build: u32,
    /// `UBR` (update build revision), `0` when the value is absent.
    pub ubr: u32,
    /// `DisplayVersion`, e.g. `24H2`, when present.
    pub display_version: Option<String>,
}

impl OsVersion {
    /// `<build>.<ubr>`, the form the rig snapshot header and the baseline ids use.
    pub fn build_ubr(&self) -> String {
        format!("{}.{}", self.build, self.ubr)
    }
}

/// Registry path of the version facts (relative to HKLM).
const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

/// Reads [`OsVersion`] from the registry (64-bit view).
pub fn os_version() -> Result<OsVersion, Win32Error> {
    let key = Key::open(RegRoot::Hklm, CURRENT_VERSION, RegView::K64)?;
    let edition_id = key
        .value("EditionID")?
        .and_then(|v| v.as_string())
        .ok_or(Win32Error::FILE_NOT_FOUND)?;
    let build = key
        .value("CurrentBuildNumber")?
        .and_then(|v| v.as_string())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .ok_or(Win32Error::FILE_NOT_FOUND)?;
    let ubr = key.value("UBR")?.and_then(|v| v.as_u32()).unwrap_or(0);
    let display_version = key
        .value("DisplayVersion")?
        .and_then(|v| v.as_string())
        .filter(|s| !s.is_empty());
    Ok(OsVersion {
        edition_id,
        build,
        ubr,
        display_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_round_trip() {
        let w = wide("C:\\Temp\\ä");
        assert_eq!(*w.last().unwrap(), 0);
        assert_eq!(from_wide(&w), "C:\\Temp\\ä");
        // SAFETY: `w` is NUL-terminated.
        assert_eq!(unsafe { from_wide_ptr(w.as_ptr()) }, "C:\\Temp\\ä");
        assert_eq!(unsafe { from_wide_ptr(std::ptr::null()) }, "");
    }

    #[test]
    fn error_display_and_classes() {
        assert!(Win32Error(2).is_not_found());
        assert!(Win32Error(3).is_not_found());
        assert!(Win32Error(5).is_access_denied());
        assert!(Win32Error::check(0).is_ok());
        assert_eq!(Win32Error::check(5), Err(Win32Error::ACCESS_DENIED));
        assert!(Win32Error(5).to_string().starts_with("Win32 error 5"));
    }

    #[test]
    fn os_version_non_empty() {
        let v = os_version().expect("os version");
        assert!(!v.edition_id.is_empty());
        assert!(v.build >= 10240, "build {}", v.build);
        assert!(v.build_ubr().starts_with(&v.build.to_string()));
    }
}
