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
//!
//! # Directories an elevated process trusts (M3 design 3.4, BL-R1 S4)
//!
//! - [`system_volume`] is the volume of the running Windows directory
//!   (`known_folders::system_windows_dir`), named by its volume GUID path (`\\?\Volume{…}\`). The
//!   GUID path is the mount manager's name of a volume mounted on this machine, read from an open
//!   handle ([`handle_volume`]): a disk prepared elsewhere, a share, a `subst` drive or a mapped
//!   letter cannot answer with the system volume's name, whatever its serial number or descriptors
//!   say.
//! - [`trusted_install_dir`] is the start check of the broker's own directory and data root: a
//!   plain drive spelling, no reparse point on any component, on the system volume, and the
//!   directory and every ancestor writable by administrators only (`sid::is_admin_only_writable`).
//! - [`restrict_dll_search`] is the first call of each `main`: `LoadLibrary` searches System32 only.
#![cfg(feature = "read")]

use std::ffi::OsString;
use std::fmt;
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
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFinalPathNameByHandleW, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE, VOLUME_NAME_GUID,
};
use windows_sys::Win32::System::Environment::SetCurrentDirectoryW;
use windows_sys::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
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
/// - A `:` anywhere after the drive (`X:`) is refused with `ERROR_INVALID_PARAMETER`, in the
///   `\\?\` form as well: it is stream syntax (`name::$DATA`, `name:stream`,
///   `dir::$INDEX_ALLOCATION`), which names a stream of an object or the object itself under
///   another spelling, never a plain file or directory.
pub(crate) fn extended_units(path: &Path) -> Result<Vec<u16>, Win32Error> {
    const BS: u16 = b'\\' as u16;
    const DOT: u16 = b'.' as u16;
    let raw: Vec<u16> = path.as_os_str().encode_wide().collect();
    if raw.contains(&0) {
        return Err(Win32Error::INVALID_PARAMETER);
    }
    let verbatim: Vec<u16> = r"\\?\".encode_utf16().collect();
    if raw.starts_with(&verbatim) {
        if has_stream_colon(&raw[verbatim.len()..]) {
            return Err(Win32Error::INVALID_PARAMETER);
        }
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
        || has_stream_colon(rest)
    {
        return Err(Win32Error::INVALID_PARAMETER);
    }
    let mut out: Vec<u16> = prefix.encode_utf16().collect();
    out.extend_from_slice(rest);
    Ok(out)
}

/// Whether `rest` (a path without its `\\?\` or `\\` prefix: `X:\...`, `UNC\server\...`,
/// `server\share\...`, `Volume{...}\...`) holds a `:` other than the one of a leading drive
/// letter.
fn has_stream_colon(rest: &[u16]) -> bool {
    const COLON: u16 = b':' as u16;
    let after_drive = match rest {
        [letter, COLON, ..] if u8::try_from(*letter).is_ok_and(|c| c.is_ascii_alphabetic()) => {
            &rest[2..]
        }
        _ => rest,
    };
    after_drive.contains(&COLON)
}

/// The `\\?\` form of an absolute path: long paths work and a name ending in a dot or a space keeps
/// its exact spelling, because Windows does not normalise this form.
///
/// A path already in `\\?\` form is returned unchanged; `/` becomes `\`. Relative paths, device
/// paths (`\\.\`), paths with a `.` or `..` component and paths with stream syntax (a `:` after
/// the drive) are refused with `ERROR_INVALID_PARAMETER`. The path does not have to exist.
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

/// The volume of the object behind `handle`, as its volume GUID path in lower case
/// (`\\?\volume{…}\`): `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED | VOLUME_NAME_GUID)` cut after
/// the volume name. A file on a share, or on a volume the mount manager gave no GUID name, is an
/// error, never a volume.
pub fn handle_volume(handle: &impl AsHandle) -> Result<String, Win32Error> {
    let mut buf = vec![0u16; 512];
    loop {
        // SAFETY: the borrowed handle is live for the call; `buf` has `buf.len()` writable units.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                handle.as_handle().as_raw_handle(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_GUID,
            )
        } as usize;
        if n == 0 {
            return Err(Win32Error::last());
        }
        if n < buf.len() {
            return volume_of_guid_path(&String::from_utf16_lossy(&buf[..n]))
                .ok_or(Win32Error::INVALID_DATA);
        }
        // Too small: `n` is the size needed, terminator included.
        buf.resize(n + 1, 0);
    }
}

/// `\\?\volume{<guid>}\` (lower case) of a path in volume GUID form (`\\?\Volume{<guid>}\rest`);
/// `None` for any other form.
fn volume_of_guid_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix(r"\\?\")?;
    let name = rest.split('\\').next()?.to_ascii_lowercase();
    let guid = name.strip_prefix("volume{")?.strip_suffix('}')?;
    let well_formed = guid.len() == 36
        && guid.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        });
    well_formed.then(|| format!(r"\\?\{name}\"))
}

/// The volume of `path` ([`handle_volume`] of [`open_for_security`]: a final reparse point is not
/// followed, so this is the volume the name itself is on).
pub fn volume_of(path: &Path) -> Result<String, Win32Error> {
    handle_volume(&open_for_security(path)?)
}

/// The system volume: the volume of the running Windows directory
/// (`known_folders::system_windows_dir`, not `%SystemRoot%`), as [`handle_volume`] names it.
pub fn system_volume() -> Result<String, Win32Error> {
    volume_of(&crate::known_folders::system_windows_dir()?)
}

/// Why [`trusted_install_dir`] refused a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UntrustedDir {
    /// Not a plain absolute drive path (`X:\a\b`): relative, UNC, device or `\\?\GLOBALROOT` form,
    /// a `.` or `..` component, an empty component, stream syntax, a character Windows does not
    /// allow in a name, or a name ending in a dot or a space (which the Win32 form drops, so it
    /// would name another object than the `\\?\` form).
    Spelling(String),
    /// A component of the path is a reparse point (any tag, not only links).
    ReparsePoint {
        /// The component.
        path: PathBuf,
        /// Its reparse tag.
        tag: u32,
    },
    /// The directory is not on the system volume.
    OtherVolume {
        /// The directory's volume, or the reason it has none.
        volume: String,
        /// The system volume.
        system: String,
    },
    /// The directory or an ancestor can be changed by a principal that is not SYSTEM,
    /// Administrators or TrustedInstaller (`sid::is_admin_only_writable`).
    UserWritable,
    /// A component, or the system volume, could not be opened or read.
    Unreadable {
        /// What could not be read.
        path: PathBuf,
        /// The error.
        error: Win32Error,
    },
}

impl fmt::Display for UntrustedDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UntrustedDir::Spelling(why) => write!(f, "not a plain drive path: {why}"),
            UntrustedDir::ReparsePoint { path, tag } => {
                write!(f, "{} is a reparse point (tag {tag:#x})", path.display())
            }
            UntrustedDir::OtherVolume { volume, system } => {
                write!(f, "on volume {volume}, not on the system volume {system}")
            }
            UntrustedDir::UserWritable => {
                f.write_str("it or an ancestor can be written by a non-administrator")
            }
            UntrustedDir::Unreadable { path, error } => {
                write!(f, "{} could not be read: {error}", path.display())
            }
        }
    }
}

impl std::error::Error for UntrustedDir {}

/// `path` when it is a plain absolute drive path (`X:\a\b`, or `X:\`); a leading `\\?\` is accepted
/// and dropped, because with the rules below both forms name the same object. See
/// [`UntrustedDir::Spelling`] for what is refused.
fn plain_drive_path(path: &Path) -> Result<PathBuf, String> {
    let s = path.to_str().ok_or("not valid Unicode")?;
    let s = s.strip_prefix(r"\\?\").unwrap_or(s);
    let b = s.as_bytes();
    if !(b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\') {
        return Err(format!("{s:?} is not an absolute drive path"));
    }
    let rest = &s[3..];
    if !rest.is_empty() {
        for c in rest.split('\\') {
            let bad_char = c
                .chars()
                .any(|ch| ch < ' ' || matches!(ch, '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|'));
            if c.is_empty()
                || c == "."
                || c == ".."
                || bad_char
                || c.ends_with('.')
                || c.ends_with(' ')
            {
                return Err(format!("{s:?} has the component {c:?}"));
            }
        }
    }
    Ok(PathBuf::from(s))
}

/// Whether an elevated Purge may trust `dir` as its own directory or its data root (M3 design 3.4,
/// BL-R1 S4): `Ok(())` when
///
/// 1. it is a plain absolute drive path ([`UntrustedDir::Spelling`]);
/// 2. no component, from the drive root down, is a reparse point of any kind, each opened without
///    following it ([`UntrustedDir::ReparsePoint`]);
/// 3. the path is the directory's own name: its final path (`GetFinalPathNameByHandleW`) is the
///    same string up to ASCII case, so no `subst` or mapped letter and no short name stands in
///    for it ([`UntrustedDir::Spelling`]);
/// 4. it is on the [`system_volume`] ([`UntrustedDir::OtherVolume`]): a volume written on another
///    machine has administrator-only descriptors as easily as this one, but it is not the volume
///    the running Windows is on;
/// 5. the directory and every ancestor are writable by administrators only
///    (`sid::is_admin_only_writable`, [`UntrustedDir::UserWritable`]).
///
/// The checks run in this order and the first failure is the answer. Once they pass, no standard
/// user and no medium-integrity process can rename, re-ACL or replace any component, so a later
/// open of the same path reaches the same objects (as long as the drive letter itself still names
/// the same volume: the check cannot rule out a redefinition of the letter in the process's own
/// DOS device directory after it ran).
pub fn trusted_install_dir(dir: &Path) -> Result<(), UntrustedDir> {
    let plain = plain_drive_path(dir).map_err(UntrustedDir::Spelling)?;
    let unreadable = |path: &Path, error| UntrustedDir::Unreadable {
        path: path.to_path_buf(),
        error,
    };
    let components: Vec<&Path> = plain.ancestors().collect();
    let mut leaf = None;
    for component in components.into_iter().rev() {
        let handle = open_for_security(component).map_err(|e| unreadable(component, e))?;
        let tag = handle.reparse_tag().map_err(|e| unreadable(component, e))?;
        if tag != 0 {
            return Err(UntrustedDir::ReparsePoint {
                path: component.to_path_buf(),
                tag,
            });
        }
        leaf = Some(handle);
    }
    let leaf = leaf.ok_or_else(|| UntrustedDir::Spelling("no component".into()))?;
    // The name must be the object's own: a `subst` or mapped letter, or a short (8.3) spelling,
    // names the same object under another path, and the checks below would judge that path.
    let resolved = leaf.final_path().map_err(|e| unreadable(&plain, e))?;
    let resolved = resolved.strip_prefix(r"\\?\").unwrap_or(&resolved);
    let given = plain.to_string_lossy();
    if !resolved
        .trim_end_matches('\\')
        .eq_ignore_ascii_case(given.trim_end_matches('\\'))
    {
        return Err(UntrustedDir::Spelling(format!(
            "{given:?} is the object {resolved:?}"
        )));
    }
    let system = system_volume().map_err(|e| unreadable(Path::new("the system volume"), e))?;
    let volume = handle_volume(&leaf).unwrap_or_else(|e| format!("none ({e})"));
    if volume != system {
        return Err(UntrustedDir::OtherVolume { volume, system });
    }
    match crate::sid::is_admin_only_writable(&plain) {
        Ok(true) => Ok(()),
        Ok(false) => Err(UntrustedDir::UserWritable),
        Err(e) => Err(unreadable(&plain, e)),
    }
}

/// `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`: from now on `LoadLibrary` without a
/// full path, and the dependencies it pulls in, are searched in System32 only, never in the
/// executable's directory, the current directory or `PATH`. The first call of each `main`
/// (M3 design 3.4). It does not cover the imports the loader resolved before `main` ran; for
/// those the broker relies on its directory passing [`trusted_install_dir`].
pub fn restrict_dll_search() -> Result<(), Win32Error> {
    // SAFETY: takes a flag value only.
    if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
        return Err(Win32Error::last());
    }
    Ok(())
}

/// `SetCurrentDirectoryW(dir)`: the process's working directory. The broker runs elevated and would
/// otherwise keep the directory its `runas` caller passed (review M3-R2 S4).
pub fn set_current_directory(dir: &Path) -> Result<(), Win32Error> {
    let dir: Vec<u16> = dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `dir` is a NUL-terminated wide string.
    if unsafe { SetCurrentDirectoryW(dir.as_ptr()) } == 0 {
        return Err(Win32Error::last());
    }
    Ok(())
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
    fn stream_syntax_is_refused() {
        for bad in [
            r"C:\a\host.txt::$DATA",
            r"C:\a\host.txt:second",
            r"C:\a\host.txt:second:$DATA",
            r"C:\a\dir::$INDEX_ALLOCATION",
            r"C:\a\dir:$I30:$INDEX_ALLOCATION\b",
            r"C:\a:b\c",
            r"C:/a/host.txt::$DATA",
            r"C::",
            r"\\srv\share\x:y",
            r"\\srv\share:x",
            r"\\?\C:\a\host.txt::$DATA",
            r"\\?\C:\a\host.txt:s",
            r"\\?\UNC\srv\share\x:y",
            r"\\?\Volume{0}\x::$DATA",
        ] {
            assert_eq!(ext(bad), Err(Win32Error::INVALID_PARAMETER), "{bad:?}");
        }
        // The drive colon is not stream syntax, in either form.
        assert_eq!(ext(r"z:\a").unwrap(), r"\\?\z:\a");
        assert_eq!(ext(r"\\?\C:\a\b").unwrap(), r"\\?\C:\a\b");
        assert_eq!(ext(r"\\?\UNC\srv\share").unwrap(), r"\\?\UNC\srv\share");

        // open_for_security cannot be pointed at a stream or a stream spelling of a directory.
        let dir = std::env::temp_dir().join(format!("purge-win-ads-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("host.txt"), b"x").unwrap();
        let spelled = |s: &str| PathBuf::from(format!("{}{s}", dir.display()));
        let results = [
            open_for_security(&spelled(r"\host.txt::$DATA")).map(|_| ()),
            open_for_security(&spelled("::$INDEX_ALLOCATION")).map(|_| ()),
        ];
        std::fs::remove_dir_all(&dir).unwrap();
        for r in results {
            assert_eq!(r, Err(Win32Error::INVALID_PARAMETER));
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

    #[test]
    fn volume_guid_paths() {
        let g = "{0a1B2c3d-0000-1111-2222-333344445555}";
        let want = r"\\?\volume{0a1b2c3d-0000-1111-2222-333344445555}\";
        for path in [
            format!(r"\\?\Volume{g}\Windows\System32"),
            format!(r"\\?\Volume{g}\"),
            format!(r"\\?\VOLUME{g}"),
        ] {
            assert_eq!(volume_of_guid_path(&path).as_deref(), Some(want), "{path}");
        }
        for bad in [
            r"\\?\C:\Windows",
            r"\\?\UNC\srv\share\x",
            r"C:\Windows",
            r"\\?\Volume{}\x",
            r"\\?\Volume{0a1b2c3d-0000-1111-2222-33334444555}\x",
            r"\\?\Volume{0a1b2c3d-0000-1111-2222-3333444455555}\x",
            r"\\?\Volume{0a1b2c3d_0000-1111-2222-333344445555}\x",
            r"\\?\Volume{0a1b2c3d-0000-1111-2222-33334444555g}\x",
            r"\\?\Volume0a1b2c3d-0000-1111-2222-333344445555\x",
            "",
        ] {
            assert_eq!(volume_of_guid_path(bad), None, "{bad}");
        }
    }

    #[test]
    fn plain_drive_spellings() {
        let ok = |s: &str| plain_drive_path(Path::new(s)).map(|p| p.to_string_lossy().into_owned());
        assert_eq!(
            ok(r"C:\Program Files\Purge").unwrap(),
            r"C:\Program Files\Purge"
        );
        assert_eq!(
            ok(r"\\?\C:\Program Files\Purge").unwrap(),
            r"C:\Program Files\Purge"
        );
        assert_eq!(ok(r"C:\").unwrap(), r"C:\");
        assert_eq!(ok(r"C:\a.b\c d\...x").unwrap(), r"C:\a.b\c d\...x");
        for bad in [
            r"Program Files\Purge",
            r"C:Purge",
            r"C:",
            r"\Purge",
            r"\\srv\share\Purge",
            r"\\?\UNC\srv\share\Purge",
            r"\\.\C:\Purge",
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\Purge",
            r"\\?\Volume{0a1b2c3d-0000-1111-2222-333344445555}\Purge",
            r"C:\a\..\Purge",
            r"C:\a\.\Purge",
            r"C:\a\\Purge",
            r"C:\Purge\",
            r"C:\Windows.",
            r"C:\Windows. ",
            r"C:\Windows \x",
            r"\\?\C:\Windows.\System32",
            r"C:\a:b",
            r"C:\a\b::$DATA",
            r"C:\a/b",
            "C:\\a\u{1}b",
            r"C:\a*",
            r"C:\a?",
            "",
        ] {
            assert!(ok(bad).is_err(), "{bad:?}");
            assert!(
                matches!(
                    trusted_install_dir(Path::new(bad)),
                    Err(UntrustedDir::Spelling(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_system_directories_are_trusted() {
        let windir = crate::known_folders::system_windows_dir().unwrap();
        let system = system_volume().unwrap();
        assert!(system.starts_with(r"\\?\volume{"), "{system}");
        let root = PathBuf::from(&windir.to_string_lossy()[..3]);
        assert_eq!(volume_of(&root).unwrap(), system);
        assert_eq!(trusted_install_dir(&windir), Ok(()));
        assert_eq!(trusted_install_dir(&windir.join("System32")), Ok(()));
        // The same directory in the `\\?\` form, and in another letter case.
        let verbatim = PathBuf::from(format!(r"\\?\{}", windir.display()));
        assert_eq!(trusted_install_dir(&verbatim), Ok(()));
        let upper = PathBuf::from(windir.to_string_lossy().to_uppercase());
        assert_eq!(trusted_install_dir(&upper), Ok(()));
        // Missing: unreadable, not trusted.
        assert!(matches!(
            trusted_install_dir(&windir.join("purge-test-no-such-dir-4b7e")),
            Err(UntrustedDir::Unreadable { error, .. }) if error.is_not_found()
        ));
    }

    /// A scratch directory below the temp directory, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let dir =
                std::env::temp_dir().join(format!("purge-win-trust-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// M3-HARDEN win-unit: a user-writable ancestor. The temp directory is the user's; a directory
    /// below it is refused whatever its own descriptor says.
    #[test]
    fn a_user_writable_ancestor_is_refused() {
        let s = Scratch::new("ancestor");
        let dir = s.0.join("Purge");
        std::fs::create_dir(&dir).unwrap();
        let on_system = volume_of(&s.0).unwrap() == system_volume().unwrap();
        for d in [&s.0, &dir] {
            let verdict = trusted_install_dir(d);
            if on_system {
                assert_eq!(verdict, Err(UntrustedDir::UserWritable), "{}", d.display());
            } else {
                assert!(
                    matches!(verdict, Err(UntrustedDir::OtherVolume { .. })),
                    "{verdict:?}"
                );
            }
        }
    }

    /// M3-HARDEN win-unit: a junction on the path. A junction to the Windows directory is refused
    /// itself and as an ancestor, although everything it reaches is trusted.
    #[test]
    fn a_junction_on_the_path_is_refused() {
        let s = Scratch::new("junction");
        let windir = crate::known_folders::system_windows_dir().unwrap();
        let link = s.0.join("win");
        let st = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&windir)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "mklink /J failed");
        for d in [link.clone(), link.join("System32")] {
            assert_eq!(
                trusted_install_dir(&d),
                Err(UntrustedDir::ReparsePoint {
                    path: link.clone(),
                    tag: 0xA000_0003
                }),
                "{}",
                d.display()
            );
        }
    }

    /// A short (8.3) name of a trusted directory names the same object under another path: refused.
    /// Skipped where the system volume makes no short names.
    #[test]
    fn a_short_name_is_refused() {
        let windir = crate::known_folders::system_windows_dir().unwrap();
        let program_files =
            PathBuf::from(format!(r"{}\Program Files", &windir.to_string_lossy()[..2]));
        use std::os::windows::process::CommandExt;
        let out = std::process::Command::new("cmd")
            .raw_arg(format!(
                r#"/c for %I in ("{}") do @echo %~sI"#,
                program_files.display()
            ))
            .output()
            .unwrap();
        let short = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if short.is_empty() || short.eq_ignore_ascii_case(&program_files.to_string_lossy()) {
            eprintln!("no short name for {}: skipped", program_files.display());
            return;
        }
        assert_eq!(trusted_install_dir(&program_files), Ok(()));
        assert!(
            matches!(
                trusted_install_dir(Path::new(&short)),
                Err(UntrustedDir::Spelling(ref why)) if why.contains("is the object")
            ),
            "{short}"
        );
    }

    /// M3-HARDEN win-unit: another volume. Any directory there is refused as `OtherVolume` before
    /// its descriptors are looked at.
    #[test]
    #[ignore = "needs a second volume: set PURGE_TEST_OTHER_VOLUME_DIR to a directory on it (VM only)"]
    fn another_volume_is_refused() {
        let other = PathBuf::from(
            std::env::var_os("PURGE_TEST_OTHER_VOLUME_DIR")
                .expect("PURGE_TEST_OTHER_VOLUME_DIR is not set"),
        );
        let system = system_volume().unwrap();
        assert_ne!(volume_of(&other).unwrap(), system);
        let root = PathBuf::from(&other.to_string_lossy()[..3]);
        for d in [&other, &root] {
            assert!(
                matches!(
                    trusted_install_dir(d),
                    Err(UntrustedDir::OtherVolume { system: ref s, .. }) if *s == system
                ),
                "{}",
                d.display()
            );
        }
    }

    /// Set by [`dll_search_skips_the_current_directory_after_restrict`] for its child.
    const DLL_CHILD_VAR: &str = "PURGE_TEST_DLL_SEARCH_CHILD";

    /// The child half: loads a DLL by bare name from its current directory, then restricts the
    /// search and tries again. Does nothing when run normally.
    #[test]
    fn dll_search_child() {
        use windows_sys::Win32::Foundation::FreeLibrary;
        use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;
        let Some(name) = std::env::var_os(DLL_CHILD_VAR) else {
            return;
        };
        let load = || {
            let w: Vec<u16> = name.encode_wide().chain(std::iter::once(0)).collect();
            // SAFETY: NUL-terminated name; the module is freed right away.
            let m = unsafe { LoadLibraryW(w.as_ptr()) };
            if m.is_null() {
                Err(Win32Error::last().code())
            } else {
                // SAFETY: `m` was just loaded by this thread and is freed once.
                unsafe { FreeLibrary(m) };
                Ok(())
            }
        };
        println!("BEFORE={:?}", load());
        restrict_dll_search().unwrap();
        println!("AFTER={:?}", load());
    }

    /// M3 design 3.4, T6: after [`restrict_dll_search`] a DLL planted in the current directory is not
    /// found by its bare name (it was before). Run in a child process, so this test process keeps
    /// its search order.
    #[test]
    fn dll_search_skips_the_current_directory_after_restrict() {
        let s = Scratch::new("dllsearch");
        let windir = crate::known_folders::system_windows_dir().unwrap();
        let name = format!("purge-plant-{}.dll", std::process::id());
        std::fs::copy(windir.join(r"System32\version.dll"), s.0.join(&name)).unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "secure::tests::dll_search_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .current_dir(&s.0)
            .env(DLL_CHILD_VAR, &name)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(out.status.success(), "{text}");
        assert!(text.contains("BEFORE=Ok(())"), "{text}");
        assert!(text.contains("AFTER=Err(126)"), "{text}");
    }
}
