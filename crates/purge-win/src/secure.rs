//! Security-descriptor facts of files and directories, read side (M2-WIN-FS).
//!
//! ENGINE_PLAN.md §7.4 requires that every session and quarantine directory is opened with
//! `FILE_FLAG_OPEN_REPARSE_POINT` and checked on each use: not a reparse point, owner Administrators
//! or SYSTEM, protected DACL. This module supplies the facts for that check and nothing else; the
//! verdict belongs to `purge-exec`.
//!
//! - [`open_for_security`] opens a path without following a final reparse point, with
//!   `READ_CONTROL`, and returns an ordinary [`FileHandle`], so the reparse tag, the file id, the
//!   final path and the security descriptor are all read from one handle.
//! - [`handle_security`] reads owner, group, control bits, DACL and the SDDL string from any handle
//!   that carries `READ_CONTROL` (`GetSecurityInfo` on the handle, never on a path).
//! - [`extended_path`] turns an absolute path into its `\\?\` form without normalising it, so long
//!   paths work and names that end in a dot or a space keep their exact spelling.
//!
//! Nothing here changes anything: no ownership change, no ACL edit, no privilege is enabled.
#![cfg(feature = "read")]

use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorControl,
    GetSecurityDescriptorGroup, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
};

use crate::fs::FileHandle;
use crate::os::Win32Error;
use crate::sid::{sd_facts, sid_bytes_to_string};

/// `INHERIT_ONLY_ACE`: the entry applies to children only, not to the object that carries it.
pub const ACE_FLAG_INHERIT_ONLY: u8 = 0x08;
/// `INHERITED_ACE`: the entry was inherited from a parent.
pub const ACE_FLAG_INHERITED: u8 = 0x10;

/// One entry of a DACL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// `ACE_HEADER.AceType` (0 allow, 1 deny, 5/6 object forms, 9/10 callback forms, ...).
    pub ace_type: u8,
    /// `ACE_HEADER.AceFlags`.
    pub flags: u8,
    /// Access mask.
    pub mask: u32,
    /// Trustee SID in string form; `None` for an entry type without a decodable SID.
    pub sid: Option<String>,
}

impl Ace {
    /// An allow entry (plain, object or callback form).
    pub fn is_allow(&self) -> bool {
        matches!(self.ace_type, 0x00 | 0x05 | 0x09 | 0x0B)
    }

    /// A deny entry (plain, object or callback form).
    pub fn is_deny(&self) -> bool {
        matches!(self.ace_type, 0x01 | 0x06 | 0x0A | 0x0C)
    }

    /// The entry applies to the object itself, not only to its children.
    pub fn is_effective(&self) -> bool {
        self.flags & ACE_FLAG_INHERIT_ONLY == 0
    }

    /// The entry was inherited from a parent.
    pub fn is_inherited(&self) -> bool {
        self.flags & ACE_FLAG_INHERITED != 0
    }
}

/// Owner, group and DACL of an object, as read from an open handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Security {
    /// Owner SID in string form.
    pub owner: Option<String>,
    /// Primary group SID in string form.
    pub group: Option<String>,
    /// Raw `SECURITY_DESCRIPTOR_CONTROL` bits.
    pub control: u16,
    /// `SE_DACL_PROTECTED`: the DACL does not inherit from the parent.
    pub dacl_protected: bool,
    /// The DACL entries in order. `None` for an absent or NULL DACL, which grants everyone full
    /// access.
    pub dacl: Option<Vec<Ace>>,
    /// The owner, group and DACL in SDDL form (`O:..G:..D:..`), as Windows prints them.
    pub sddl: String,
}

impl Security {
    /// The DACL entries (empty for an absent or NULL DACL; check [`Security::dacl`] to tell the
    /// two apart).
    pub fn aces(&self) -> &[Ace] {
        self.dacl.as_deref().unwrap_or(&[])
    }
}

impl AsHandle for FileHandle {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.0.as_handle()
    }
}

/// The `\\?\` form of an absolute path, as UTF-16 units without a terminator.
///
/// - `X:\dir\name` becomes `\\?\X:\dir\name`, `\\server\share\x` becomes `\\?\UNC\server\share\x`.
/// - A path that already starts with `\\?\` is returned unchanged.
/// - `/` is turned into `\`. Nothing else is normalised: trailing dots and spaces stay.
/// - Relative paths, drive-relative paths (`C:x`), device paths (`\\.\`) and paths with a `.` or
///   `..` component are refused with `ERROR_INVALID_PARAMETER`, because the `\\?\` form would
///   take such a component as a literal name.
pub(crate) fn extended_units(path: &Path) -> Result<Vec<u16>, Win32Error> {
    const BS: u16 = b'\\' as u16;
    const DOT: u16 = b'.' as u16;
    let raw: Vec<u16> = path.as_os_str().encode_wide().collect();
    if raw.contains(&0) {
        return Err(Win32Error::INVALID_PARAMETER);
    }
    let verbatim: Vec<u16> = r"\\?\".encode_utf16().collect();
    if raw.starts_with(&verbatim) {
        return Ok(raw);
    }
    let units: Vec<u16> = raw
        .into_iter()
        .map(|c| if c == b'/' as u16 { BS } else { c })
        .collect();
    let (prefix, rest): (&str, &[u16]) = if units.starts_with(&[BS, BS]) {
        match units.get(2) {
            Some(&c) if c != DOT && c != b'?' as u16 && c != BS => (r"\\?\UNC\", &units[2..]),
            _ => return Err(Win32Error::INVALID_PARAMETER),
        }
    } else if units.len() >= 3
        && u8::try_from(units[0]).is_ok_and(|c| c.is_ascii_alphabetic())
        && units[1] == b':' as u16
        && units[2] == BS
    {
        (r"\\?\", &units[..])
    } else {
        return Err(Win32Error::INVALID_PARAMETER);
    };
    if rest
        .split(|&c| c == BS)
        .any(|part| part == [DOT] || part == [DOT, DOT])
    {
        return Err(Win32Error::INVALID_PARAMETER);
    }
    let mut out: Vec<u16> = prefix.encode_utf16().collect();
    out.extend_from_slice(rest);
    Ok(out)
}

/// The `\\?\` form of an absolute path: long paths work and a name ending in a dot or a space keeps
/// its exact spelling, because Windows does not normalise this form.
///
/// A path already in `\\?\` form is returned unchanged; `/` becomes `\`. Relative paths, device
/// paths (`\\.\`) and paths with a `.` or `..` component are refused with
/// `ERROR_INVALID_PARAMETER`. The path does not have to exist.
pub fn extended_path(path: &Path) -> Result<PathBuf, Win32Error> {
    Ok(PathBuf::from(OsString::from_wide(&extended_units(path)?)))
}

/// Opens `path` (absolute) without following a final reparse point, with
/// `READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE` and full sharing. The returned handle answers
/// [`FileHandle::metadata`], [`FileHandle::file_id`], [`FileHandle::final_path`],
/// [`FileHandle::reparse_tag`] and [`handle_security`], all about the same object.
pub fn open_for_security(path: &Path) -> Result<FileHandle, Win32Error> {
    let mut p = extended_units(path)?;
    p.push(0);
    // SAFETY: `p` is NUL-terminated; no security attributes or template handle.
    let h = unsafe {
        CreateFileW(
            p.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
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
    Ok(FileHandle(unsafe { OwnedHandle::from_raw_handle(h) }))
}

/// Frees a `LocalAlloc` block on drop.
struct LocalMem(*mut core::ffi::c_void);

impl Drop for LocalMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API that documents LocalFree as its deallocator
            // and is freed exactly once.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// Reads the SID at `psid`.
///
/// # Safety
/// `psid` must be null or point to a valid binary SID.
unsafe fn sid_string(psid: PSID) -> Option<String> {
    if psid.is_null() {
        return None;
    }
    let p = psid as *const u8;
    // SAFETY: a valid SID has an 8-byte header whose second byte is the sub-authority count,
    // which fixes the total length 8 + 4 * count; all of it is readable per the caller.
    unsafe {
        let len = 8 + 4 * *p.add(1) as usize;
        sid_bytes_to_string(std::slice::from_raw_parts(p, len))
    }
}

/// Owner, group, control bits, DACL and SDDL string of the file or directory behind `handle`
/// (`GetSecurityInfo` on the handle). The handle needs `READ_CONTROL`: one from
/// [`open_for_security`], or a `fs_write::MoveHandle` that reports `has_read_control()`.
///
/// For a handle on a reparse point this is the descriptor of the reparse point itself.
pub fn handle_security(handle: &impl AsHandle) -> Result<Security, Win32Error> {
    let info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut psd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the borrowed handle is live for the call; only the descriptor out-pointer is
    // requested.
    let rc = unsafe {
        GetSecurityInfo(
            handle.as_handle().as_raw_handle(),
            SE_FILE_OBJECT,
            info,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut psd,
        )
    };
    Win32Error::check(rc)?;
    let sd = LocalMem(psd);

    // SAFETY: `sd.0` is a valid descriptor allocated by GetSecurityInfo and alive until `sd` drops.
    let facts = unsafe { sd_facts(sd.0)? };

    let mut group: PSID = ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: valid descriptor; out-pointers are locals.
    if unsafe { GetSecurityDescriptorGroup(sd.0, &mut group, &mut defaulted) } == 0 {
        return Err(Win32Error::last());
    }
    // SAFETY: `group` is null or points into the live descriptor.
    let group = unsafe { sid_string(group) };

    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: valid descriptor; out-pointers are locals.
    if unsafe { GetSecurityDescriptorControl(sd.0, &mut control, &mut revision) } == 0 {
        return Err(Win32Error::last());
    }

    let mut text: *mut u16 = ptr::null_mut();
    let mut text_len = 0u32;
    // SAFETY: valid descriptor; `text` receives a LocalAlloc string of `text_len` units.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd.0,
            SDDL_REVISION_1,
            info,
            &mut text,
            &mut text_len,
        )
    };
    if ok == 0 {
        return Err(Win32Error::last());
    }
    let text_mem = LocalMem(text.cast());
    // SAFETY: on success `text` points to `text_len` readable UTF-16 units (terminator included),
    // alive until `text_mem` drops.
    let units = unsafe { std::slice::from_raw_parts(text_mem.0 as *const u16, text_len as usize) };
    let sddl = crate::os::from_wide(units);

    Ok(Security {
        owner: facts.owner,
        group,
        control,
        dacl_protected: control & SE_DACL_PROTECTED != 0,
        dacl: facts.dacl.map(|aces| {
            aces.into_iter()
                .map(|a| Ace {
                    ace_type: a.ace_type,
                    flags: a.flags,
                    mask: a.mask,
                    sid: a.sid,
                })
                .collect()
        }),
        sddl,
    })
}

/// The SDDL string (`O:..G:..D:..`) of the object behind `handle`; see [`handle_security`].
pub fn handle_sddl(handle: &impl AsHandle) -> Result<String, Win32Error> {
    handle_security(handle).map(|s| s.sddl)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(s: &str) -> Result<String, Win32Error> {
        extended_path(Path::new(s)).map(|p| p.to_string_lossy().into_owned())
    }

    #[test]
    fn extended_path_forms() {
        assert_eq!(ext(r"C:\a\b.txt").unwrap(), r"\\?\C:\a\b.txt");
        assert_eq!(ext(r"c:/a/b").unwrap(), r"\\?\c:\a\b");
        assert_eq!(ext(r"C:\").unwrap(), r"\\?\C:\");
        assert_eq!(ext(r"C:\a\name. ").unwrap(), r"\\?\C:\a\name. ");
        assert_eq!(ext(r"C:\a\...\b").unwrap(), r"\\?\C:\a\...\b");
        assert_eq!(ext(r"\\srv\share\x").unwrap(), r"\\?\UNC\srv\share\x");
        assert_eq!(ext(r"\\?\C:\a\..\b").unwrap(), r"\\?\C:\a\..\b");
        for bad in [
            r"a\b",
            r"C:a",
            r"\a\b",
            r"C:\a\..\b",
            r"C:\a\.\b",
            r"C:\a\..",
            r"\\.\C:\a",
            r"\\",
            "",
        ] {
            assert_eq!(ext(bad), Err(Win32Error::INVALID_PARAMETER), "{bad:?}");
        }
    }

    #[test]
    fn security_of_windows_dir_and_temp() {
        let windir =
            crate::known_folders::known_folder(crate::known_folders::KnownFolder::Windows).unwrap();
        let h = open_for_security(&windir).unwrap();
        assert_eq!(h.reparse_tag().unwrap(), 0);
        let s = handle_security(&h).unwrap();
        assert_eq!(s.owner.as_deref(), Some(crate::sid::TRUSTED_INSTALLER_SID));
        assert!(s.group.is_some());
        assert!(s.dacl_protected, "{}", s.sddl);
        assert!(
            s.sddl.starts_with("O:") && s.sddl.contains("D:P"),
            "{}",
            s.sddl
        );
        assert!(s.aces().iter().any(|a| a.is_allow() && a.is_effective()));
        assert_eq!(handle_sddl(&h).unwrap(), s.sddl);

        // A directory created below the temp directory inherits its DACL.
        let dir = std::env::temp_dir().join(format!("purge-win-secure-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let t = open_for_security(&dir).and_then(|h| handle_security(&h));
        std::fs::remove_dir(&dir).unwrap();
        let t = t.unwrap();
        assert!(!t.dacl_protected, "{}", t.sddl);
        assert!(t.aces().iter().any(Ace::is_inherited));
        assert!(t.aces().iter().all(|a| !a.is_deny()));

        // A handle without READ_CONTROL is refused, not answered from the path.
        let plain = FileHandle::open(&windir).unwrap();
        assert_eq!(handle_security(&plain), Err(Win32Error::ACCESS_DENIED));

        assert!(
            open_for_security(&windir.join("purge-test-no-such-dir-4b7e"))
                .unwrap_err()
                .is_not_found()
        );
        assert_eq!(
            open_for_security(Path::new(r"relative\x")).unwrap_err(),
            Win32Error::INVALID_PARAMETER
        );
    }
}
