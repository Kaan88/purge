//! Tokens, SIDs, `ProfileList` and the admin-only-writable check behind `SourceTrust`.
//!
//! - [`current_user_sid`] and [`is_elevated`] read the process token (`TokenUser`, `TokenElevation`).
//! - [`profiles`] lists `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` as
//!   `SID -> profile path` (expanded).
//! - [`is_admin_only_writable`] decides ENGINE_PLAN.md §5.2 `SourceTrust::AdminOnly`: the path and every
//!   ancestor are owned by an administrative principal and no effective allow ACE grants a
//!   non-administrative principal the right to change the path (or, for an ancestor, to delete,
//!   rename or re-ACL what lies below it).
//! - [`is_admin_only_executable`] is the stricter rule for a file that is about to be *run*
//!   elevated: on top of the above, no non-administrative principal may add a file or a
//!   subdirectory to its directory, which the loader searches first for the DLLs the program
//!   imports (review M3-R2 H3).
//!
//! Security descriptors are read through the Win32 API; the SIDs and ACLs inside them are decoded by
//! pure byte parsers here ([`sid_bytes_to_string`], `parse_acl`), which keeps the `unsafe` surface to
//! the pointer-to-slice steps.
#![cfg(feature = "read")]

use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_ELEVATION,
    TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetDriveTypeW, OPEN_EXISTING,
    QueryDosDeviceW, READ_CONTROL,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::os::{Win32Error, wide};
use crate::reg::{Key, RegRoot, RegView};

/// `NT SERVICE\TrustedInstaller`.
pub const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
/// `NT AUTHORITY\SYSTEM`.
pub const LOCAL_SYSTEM_SID: &str = "S-1-5-18";
/// `BUILTIN\Administrators`.
pub const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// `CREATOR OWNER`, `CREATOR GROUP`, `OWNER RIGHTS`: placeholders that grant nothing on the object
/// itself (the first two) or apply to the owner, which is checked separately (the third).
const PLACEHOLDER_SIDS: [&str; 3] = ["S-1-3-0", "S-1-3-1", "S-1-3-4"];

/// The principals [`is_admin_only_writable`] accepts as owners and writers.
const ADMIN_SIDS: [&str; 3] = [LOCAL_SYSTEM_SID, ADMINISTRATORS_SID, TRUSTED_INSTALLER_SID];

const INHERIT_ONLY_ACE: u8 = 0x08;

// File access rights (winnt.h). On a directory `FILE_WRITE_DATA` is `FILE_ADD_FILE` and
// `FILE_APPEND_DATA` is `FILE_ADD_SUBDIRECTORY`.
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;
const FILE_ADD_FILE: u32 = FILE_WRITE_DATA;
const FILE_ADD_SUBDIRECTORY: u32 = FILE_APPEND_DATA;
const FILE_DELETE_CHILD: u32 = 0x0040;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

/// Rights that let a principal change the object itself (data, children, deletion, ACL, owner).
const LEAF_WRITE_MASK: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_ALL
    | GENERIC_WRITE;
/// Rights on an ancestor that let a principal delete, rename or re-ACL what lies below it, and so
/// replace a component of the path. `FILE_ADD_FILE` and `FILE_ADD_SUBDIRECTORY` are left out: they
/// only create new names beside the path (Authenticated Users may add a subdirectory to `C:\`;
/// BUILTIN\Users may add files and folders to `C:\ProgramData` and, by inheritance, to the vendor
/// folders below it). That keeps the path's own content admin-only, not the directory around it: a
/// file a user adds there can be loaded by a program run from that directory, which
/// [`PARENT_RUN_MASK`] covers for [`is_admin_only_executable`].
const ANCESTOR_WRITE_MASK: u32 = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
/// Rights on the directory of a file about to be run that let a principal place something the
/// loader picks up before the system copy: a DLL beside the executable (the application directory
/// is searched first), an `<exe>.local` redirection folder, an `<exe>.manifest` (review M3-R2 H3).
const PARENT_RUN_MASK: u32 = ANCESTOR_WRITE_MASK | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY;

/// One ACE from a DACL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AceFact {
    /// `ACE_HEADER.AceType`.
    pub ace_type: u8,
    /// `ACE_HEADER.AceFlags`.
    pub flags: u8,
    /// Access mask.
    pub mask: u32,
    /// Trustee SID in string form; `None` for ACE types without a decodable SID.
    pub sid: Option<String>,
}

impl AceFact {
    /// An allow ACE (plain, object or callback form).
    fn is_allow(&self) -> bool {
        matches!(self.ace_type, 0x00 | 0x05 | 0x09 | 0x0B)
    }

    /// Applies to the object itself (not only inherited by children).
    fn is_effective(&self) -> bool {
        self.flags & INHERIT_ONLY_ACE == 0
    }
}

/// Owner and DACL of a security descriptor. `dacl` is `None` for an absent or NULL DACL, which
/// grants everyone full access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SdFacts {
    pub owner: Option<String>,
    pub dacl: Option<Vec<AceFact>>,
}

impl SdFacts {
    /// The DACL entries (empty for an absent/NULL DACL).
    pub fn aces(&self) -> &[AceFact] {
        self.dacl.as_deref().unwrap_or(&[])
    }
}

/// Decodes a binary SID (`Revision`, `SubAuthorityCount`, 6-byte big-endian authority, little-endian
/// sub-authorities) into `S-R-A-S1-...` form. `None` if the bytes are too short. Trailing bytes are
/// ignored.
pub fn sid_bytes_to_string(bytes: &[u8]) -> Option<String> {
    let (&rev, rest) = bytes.split_first()?;
    let (&count, rest) = rest.split_first()?;
    let auth_bytes = rest.get(..6)?;
    let subs = rest.get(6..6 + 4 * count as usize)?;
    let authority = auth_bytes
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    let mut s = if authority >> 32 == 0 {
        format!("S-{rev}-{authority}")
    } else {
        format!("S-{rev}-0x{authority:012X}")
    };
    for c in subs.chunks_exact(4) {
        s.push('-');
        s.push_str(&u32::from_le_bytes([c[0], c[1], c[2], c[3]]).to_string());
    }
    Some(s)
}

/// Byte length of the binary SID at the start of `bytes`, if the header is present.
fn sid_len(bytes: &[u8]) -> Option<usize> {
    Some(8 + 4 * *bytes.get(1)? as usize)
}

/// Decodes the ACEs of a binary ACL (`ACL` header followed by `AceCount` entries).
pub(crate) fn parse_acl(acl: &[u8]) -> Result<Vec<AceFact>, Win32Error> {
    let bad = Win32Error::INVALID_DATA;
    let hdr = acl.get(..8).ok_or(bad)?;
    let size = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
    let count = u16::from_le_bytes([hdr[4], hdr[5]]) as usize;
    let acl = acl.get(..size).ok_or(bad)?;
    let mut out = Vec::with_capacity(count);
    let mut off = 8usize;
    for _ in 0..count {
        let h = acl.get(off..off + 4).ok_or(bad)?;
        let (ace_type, flags) = (h[0], h[1]);
        let ace_size = u16::from_le_bytes([h[2], h[3]]) as usize;
        if ace_size < 8 {
            return Err(bad);
        }
        let ace = acl.get(off..off + ace_size).ok_or(bad)?;
        let mask = u32::from_le_bytes([ace[4], ace[5], ace[6], ace[7]]);
        let sid_off = match ace_type {
            // Object ACEs: Flags, then optional ObjectType / InheritedObjectType GUIDs.
            0x05..=0x08 | 0x0B | 0x0C | 0x0F | 0x10 => ace.get(8..12).map(|f| {
                let f = u32::from_le_bytes([f[0], f[1], f[2], f[3]]);
                12 + if f & 1 != 0 { 16 } else { 0 } + if f & 2 != 0 { 16 } else { 0 }
            }),
            // Compound ACEs carry more than one SID; not used on file or key DACLs.
            0x04 => None,
            _ => Some(8),
        };
        let sid = sid_off.and_then(|o| {
            let rest = ace.get(o..)?;
            rest.get(..sid_len(rest)?).and_then(sid_bytes_to_string)
        });
        out.push(AceFact {
            ace_type,
            flags,
            mask,
            sid,
        });
        off += ace_size;
    }
    Ok(out)
}

/// Reads the SID at `psid`.
///
/// # Safety
/// `psid` must be null or point to a valid binary SID.
unsafe fn sid_from_ptr(psid: PSID) -> Option<String> {
    if psid.is_null() {
        return None;
    }
    let p = psid as *const u8;
    // SAFETY: a valid SID has at least its 8-byte header; byte 1 is the sub-authority count, which
    // fixes the total length 8 + 4 * count, all readable by the caller's guarantee.
    unsafe {
        let len = 8 + 4 * *p.add(1) as usize;
        sid_bytes_to_string(std::slice::from_raw_parts(p, len))
    }
}

/// Owner and DACL facts of a security descriptor (self-relative or absolute).
///
/// # Safety
/// `psd` must point to a valid security descriptor that stays alive for the call.
pub(crate) unsafe fn sd_facts(psd: PSECURITY_DESCRIPTOR) -> Result<SdFacts, Win32Error> {
    let mut owner: PSID = ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: `psd` is valid per the caller; out-pointers are locals.
    if unsafe { GetSecurityDescriptorOwner(psd, &mut owner, &mut defaulted) } == 0 {
        return Err(Win32Error::last());
    }
    // SAFETY: `owner` is null or points into the descriptor, which the caller keeps alive.
    let owner = unsafe { sid_from_ptr(owner) };

    let mut present = 0;
    let mut pacl: *mut ACL = ptr::null_mut();
    // SAFETY: as above.
    if unsafe { GetSecurityDescriptorDacl(psd, &mut present, &mut pacl, &mut defaulted) } == 0 {
        return Err(Win32Error::last());
    }
    let dacl = if present == 0 || pacl.is_null() {
        None
    } else {
        // SAFETY: `pacl` points to an ACL inside the live descriptor; its header is 8 bytes and
        // `AclSize` is the total byte length of the ACL including the header.
        let bytes = unsafe {
            let size = (*pacl).AclSize as usize;
            std::slice::from_raw_parts(pacl as *const u8, size.max(8))
        };
        Some(parse_acl(bytes)?)
    };
    Ok(SdFacts { owner, dacl })
}

/// The current process token, opened for query.
fn process_token() -> Result<OwnedHandle, Win32Error> {
    let mut h: HANDLE = ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no closing; `h` is a valid
    // out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h) } == 0 {
        return Err(Win32Error::last());
    }
    // SAFETY: `h` is a freshly opened token handle owned by nobody else.
    Ok(unsafe { OwnedHandle::from_raw_handle(h) })
}

/// `GetTokenInformation` into an 8-byte-aligned buffer, retried with the reported size.
fn token_info(token: &OwnedHandle, class: i32) -> Result<Vec<u64>, Win32Error> {
    let mut buf = vec![0u64; 16];
    loop {
        let mut needed = 0u32;
        // SAFETY: `buf` has `buf.len() * 8` writable bytes; `needed` is a valid local.
        let ok = unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                class,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                &mut needed,
            )
        };
        if ok != 0 {
            return Ok(buf);
        }
        let e = Win32Error::last();
        if e != Win32Error::INSUFFICIENT_BUFFER || (needed as usize) <= buf.len() * 8 {
            return Err(e);
        }
        buf.resize((needed as usize).div_ceil(8), 0);
    }
}

/// SID of the user the current process runs as (`S-1-5-21-...`).
pub fn current_user_sid() -> Result<String, Win32Error> {
    let token = process_token()?;
    let buf = token_info(&token, TokenUser)?;
    // SAFETY: on success the buffer starts with a TOKEN_USER whose `User.Sid` points into the same
    // buffer, which is alive and 8-byte aligned.
    let sid = unsafe {
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        sid_from_ptr(tu.User.Sid)
    };
    sid.ok_or(Win32Error::INVALID_DATA)
}

/// Whether the current process token is elevated (`TokenElevation`).
pub fn is_elevated() -> Result<bool, Win32Error> {
    let token = process_token()?;
    let mut te = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut needed = 0u32;
    // SAFETY: `te` is a writable TOKEN_ELEVATION; this fixed-size class requires the exact size.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut te as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(Win32Error::last());
    }
    Ok(te.TokenIsElevated != 0)
}

/// One `ProfileList` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The subkey name: a SID, possibly with a `.bak` suffix left by a broken profile.
    pub sid: String,
    /// `ProfileImagePath` as stored (often `%SystemDrive%\Users\...`).
    pub raw_path: String,
    /// `ProfileImagePath` expanded against the engine's own environment.
    pub path: PathBuf,
}

const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

/// All `ProfileList` entries that have a `ProfileImagePath`, including service profiles
/// (`S-1-5-18/19/20`). Entries that cannot be read are skipped.
pub fn profiles() -> Result<Vec<Profile>, Win32Error> {
    let list = Key::open(RegRoot::Hklm, PROFILE_LIST, RegView::K64)?;
    let mut out = Vec::new();
    for sid in list.subkey_names()? {
        let Ok(key) = list.open_subkey(&sid) else {
            continue;
        };
        let Some(raw) = key
            .value("ProfileImagePath")
            .ok()
            .flatten()
            .and_then(|v| v.as_string())
        else {
            continue;
        };
        let path = PathBuf::from(crate::env::expand(&raw).unwrap_or_else(|_| raw.clone()));
        out.push(Profile {
            sid,
            raw_path: raw,
            path,
        });
    }
    Ok(out)
}

/// Owner and DACL of a file or directory, opened without following a reparse point. Returns
/// `Ok(None)` when the object is itself a name-surrogate reparse point (symlink, junction, mount
/// point), whose real location is elsewhere.
fn file_sd_facts(path: &Path) -> Result<Option<SdFacts>, Win32Error> {
    let p = wide(path);
    // SAFETY: `p` is NUL-terminated; no security attributes or template handle.
    let h = unsafe {
        CreateFileW(
            p.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES,
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
    let h = unsafe { OwnedHandle::from_raw_handle(h) };
    let tag = crate::fs::reparse_tag_of(&h)?;
    if crate::fs::is_name_surrogate(tag) {
        return Ok(None);
    }
    let mut psd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `h` is a live handle opened with READ_CONTROL; only the descriptor out-pointer is
    // requested (the owner/DACL pointers point into it).
    let rc = unsafe {
        GetSecurityInfo(
            h.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut psd,
        )
    };
    Win32Error::check(rc)?;
    // SAFETY: `psd` was allocated by GetSecurityInfo and is valid until the LocalFree below.
    let facts = unsafe { sd_facts(psd) };
    // SAFETY: `psd` came from GetSecurityInfo, which documents LocalFree as its deallocator.
    unsafe { LocalFree(psd) };
    facts.map(Some)
}

/// Whether the facts of one path component keep it admin-only under `mask`: an administrative owner,
/// a DACL, and no effective allow ACE that grants a right in `mask` to anyone else.
fn admin_only(facts: &SdFacts, mask: u32) -> bool {
    let Some(owner) = facts.owner.as_deref() else {
        return false;
    };
    if !ADMIN_SIDS.contains(&owner) {
        return false;
    }
    let Some(dacl) = facts.dacl.as_deref() else {
        return false;
    };
    !dacl.iter().any(|ace| {
        ace.is_allow()
            && ace.is_effective()
            && ace.mask & mask != 0
            && match ace.sid.as_deref() {
                Some(s) => !ADMIN_SIDS.contains(&s) && !PLACEHOLDER_SIDS.contains(&s),
                None => true,
            }
    })
}

/// Whether `path` (absolute) can be changed only by administrative principals (SYSTEM,
/// Administrators, TrustedInstaller): checked on the path and every ancestor up to the volume root.
///
/// Conservative: a path that is not on a local fixed drive (UNC, mapped, `subst`, removable;
/// [`on_local_fixed_drive`]), or a non-admin owner, an absent/NULL DACL, an undecodable allow ACE or
/// a reparse point anywhere on the chain makes the answer `false`. Deny ACEs are ignored (they can only narrow
/// access, and ignoring them errs towards `UserWritable`). Errors opening a component are returned.
pub fn is_admin_only_writable(path: &Path) -> Result<bool, Win32Error> {
    chain_admin_only(path, ANCESTOR_WRITE_MASK)
}

/// [`is_admin_only_writable`] for a file that is about to be run elevated (an uninstaller, or the
/// script, DLL or package a host loads): in addition, its immediate parent directory grants no
/// non-administrative principal `FILE_ADD_FILE` or `FILE_ADD_SUBDIRECTORY` ([`PARENT_RUN_MASK`]).
///
/// `C:\ProgramData` grants BUILTIN\Users `(CI)(WD,AD,WEA,WA)`, so a vendor folder below it usually
/// inherits "add file" while the uninstaller in it is admin-only: a medium process can then put a
/// `version.dll` beside `unins000.exe`, and the elevated run loads it (review M3-R2 H3). Ancestors
/// above the parent keep the plain ancestor rule: the loader searches the application's own
/// directory, not the ones above it, and a name added to an ancestor cannot replace or redirect a
/// component that already exists (that takes `DELETE`, `FILE_DELETE_CHILD`, `WRITE_DAC` or
/// `WRITE_OWNER`, which every ancestor is checked for).
///
/// Data trust (scan sources, baseline and cache directories, the store and data root, the boot-move
/// chain) stays with [`is_admin_only_writable`]: a file added beside data changes nothing, and
/// `C:\ProgramData\Purge` itself would fail this rule.
pub fn is_admin_only_executable(path: &Path) -> Result<bool, Win32Error> {
    chain_admin_only(path, PARENT_RUN_MASK)
}

/// The chain walk behind both rules: the path with [`LEAF_WRITE_MASK`], its parent with
/// `parent_mask`, every ancestor above it with [`ANCESTOR_WRITE_MASK`]. A path that is not on a
/// local fixed drive ([`on_local_fixed_drive`]) is never admin-only.
fn chain_admin_only(path: &Path, parent_mask: u32) -> Result<bool, Win32Error> {
    if !path.is_absolute() {
        return Err(Win32Error::INVALID_PARAMETER);
    }
    if !on_local_fixed_drive(path) {
        return Ok(false);
    }
    for (depth, p) in path.ancestors().enumerate() {
        let Some(facts) = file_sd_facts(p)? else {
            return Ok(false);
        };
        if !admin_only(&facts, chain_mask(depth, parent_mask)) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The drive letter `path` starts at, after a `\\?\`, `\\.\` or `\??\` prefix: `X:\` or `X:/`.
/// `None` for a UNC path (`\\server\share`, `\\?\UNC\...`), a volume GUID path or anything else.
fn drive_letter(path: &str) -> Option<char> {
    let rest = [r"\\?\", r"\\.\", r"\??\"]
        .iter()
        .find_map(|prefix| path.strip_prefix(prefix))
        .unwrap_or(path);
    let b = rest.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'\\' | b'/'))
        .then(|| char::from(b[0]))
}

/// Whether `path` is on a local fixed volume reached through a plain drive letter (review M3-R2 M6).
///
/// A remote path is judged by the server's ACL, whose SYSTEM and BUILTIN\Administrators are the
/// server's, and the share permissions are not judged at all; so every UNC path (`\\server`,
/// `\\?\UNC\...`, `\\localhost\c$` included, which goes through SMB) is refused. A drive letter must
/// be `DRIVE_FIXED` (a mapped network drive is `DRIVE_REMOTE`; removable media and optical drives
/// are refused too) and name a device itself, not a `subst` of a folder (`QueryDosDeviceW` gives
/// `\??\C:\...` for that) or a redirector.
fn on_local_fixed_drive(path: &Path) -> bool {
    let Some(letter) = drive_letter(&path.to_string_lossy()) else {
        return false;
    };
    let root = wide(format!(r"{letter}:\"));
    // SAFETY: `root` is NUL-terminated.
    if unsafe { GetDriveTypeW(root.as_ptr()) } != crate::fs::DRIVE_FIXED {
        return false;
    }
    let device = wide(format!("{letter}:"));
    let mut target = [0u16; 1024];
    // SAFETY: `device` is NUL-terminated; `target` has `target.len()` writable units.
    let n = unsafe { QueryDosDeviceW(device.as_ptr(), target.as_mut_ptr(), target.len() as u32) };
    if n == 0 {
        return false;
    }
    let end = target.iter().position(|&c| c == 0).unwrap_or(target.len());
    let target = String::from_utf16_lossy(&target[..end]);
    let lower = target.to_ascii_lowercase();
    lower.starts_with(r"\device\")
        && !lower.starts_with(r"\device\mup")
        && !lower.starts_with(r"\device\lanmanredirector")
}

/// The mask for the component `depth` levels above the judged path (0 is the path itself).
fn chain_mask(depth: usize, parent_mask: u32) -> u32 {
    match depth {
        0 => LEAF_WRITE_MASK,
        1 => parent_mask,
        _ => ANCESTOR_WRITE_MASK,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid_bytes(auth: u64, subs: &[u32]) -> Vec<u8> {
        let mut b = vec![1, subs.len() as u8];
        b.extend_from_slice(&auth.to_be_bytes()[2..]);
        for s in subs {
            b.extend_from_slice(&s.to_le_bytes());
        }
        b
    }

    fn ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
        let size = (8 + sid.len()) as u16;
        let mut b = vec![ace_type, flags];
        b.extend_from_slice(&size.to_le_bytes());
        b.extend_from_slice(&mask.to_le_bytes());
        b.extend_from_slice(sid);
        b
    }

    fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = aces.concat();
        let mut b = vec![2, 0];
        b.extend_from_slice(&((8 + body.len()) as u16).to_le_bytes());
        b.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend(body);
        b
    }

    #[test]
    fn sid_decoding() {
        assert_eq!(
            sid_bytes_to_string(&sid_bytes(5, &[18])).unwrap(),
            "S-1-5-18"
        );
        assert_eq!(
            sid_bytes_to_string(&sid_bytes(5, &[32, 544])).unwrap(),
            ADMINISTRATORS_SID
        );
        let ti = sid_bytes(
            5,
            &[
                80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464,
            ],
        );
        assert_eq!(sid_bytes_to_string(&ti).unwrap(), TRUSTED_INSTALLER_SID);
        assert_eq!(sid_bytes_to_string(&sid_bytes(1, &[0])).unwrap(), "S-1-1-0");
        assert_eq!(
            sid_bytes_to_string(&sid_bytes(0x1_0000_0000, &[])).unwrap(),
            "S-1-0x000100000000"
        );
        assert!(sid_bytes_to_string(&sid_bytes(5, &[18])[..9]).is_none());
    }

    #[test]
    fn acl_parsing_and_admin_rule() {
        let system = sid_bytes(5, &[18]);
        let users = sid_bytes(5, &[32, 545]);
        let creator = sid_bytes(3, &[0]);
        let read_exec = 0x0012_00A9;
        let full = 0x001F_01FF;
        let good = acl(&[
            ace(0, 0, full, &system),
            ace(0, 0, read_exec, &users),
            ace(0, INHERIT_ONLY_ACE, GENERIC_ALL, &creator),
            ace(0, INHERIT_ONLY_ACE, full, &users), // inherit-only: children, not this object
        ]);
        let aces = parse_acl(&good).unwrap();
        assert_eq!(aces.len(), 4);
        assert_eq!(aces[1].sid.as_deref(), Some("S-1-5-32-545"));
        let facts = SdFacts {
            owner: Some(LOCAL_SYSTEM_SID.into()),
            dacl: Some(aces),
        };
        assert!(admin_only(&facts, LEAF_WRITE_MASK));

        // Users may add a subdirectory: fine on an ancestor, not on the leaf.
        let add_sub = acl(&[
            ace(0, 0, full, &system),
            ace(0, 0, FILE_APPEND_DATA, &users),
        ]);
        let facts = SdFacts {
            owner: Some(TRUSTED_INSTALLER_SID.into()),
            dacl: Some(parse_acl(&add_sub).unwrap()),
        };
        assert!(admin_only(&facts, ANCESTOR_WRITE_MASK));
        assert!(!admin_only(&facts, LEAF_WRITE_MASK));

        // Deny ACEs never make something writable; allow DELETE for users does.
        let del = acl(&[ace(1, 0, full, &users), ace(0, 0, DELETE, &users)]);
        let facts = SdFacts {
            owner: Some(ADMINISTRATORS_SID.into()),
            dacl: Some(parse_acl(&del).unwrap()),
        };
        assert!(!admin_only(&facts, ANCESTOR_WRITE_MASK));

        // Non-admin owner, NULL DACL.
        let facts = SdFacts {
            owner: Some("S-1-5-21-1-2-3-1001".into()),
            dacl: Some(vec![]),
        };
        assert!(!admin_only(&facts, LEAF_WRITE_MASK));
        let facts = SdFacts {
            owner: Some(LOCAL_SYSTEM_SID.into()),
            dacl: None,
        };
        assert!(!admin_only(&facts, LEAF_WRITE_MASK));

        // Malformed ACLs are rejected, not misread.
        let mut broken = good.clone();
        broken[4] = 9; // claims 9 ACEs
        assert_eq!(parse_acl(&broken), Err(Win32Error::INVALID_DATA));
        assert_eq!(parse_acl(&[2, 0]), Err(Win32Error::INVALID_DATA));
    }

    #[test]
    fn object_ace_sid_offset() {
        let users = sid_bytes(5, &[32, 545]);
        // ACCESS_ALLOWED_OBJECT_ACE with ObjectType present (flag 1): 12 + 16 bytes before the SID.
        let mut body = vec![0u8; 0];
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&[0xAB; 16]);
        body.extend_from_slice(&users);
        let size = (8 + body.len()) as u16;
        let mut a = vec![0x05, 0];
        a.extend_from_slice(&size.to_le_bytes());
        a.extend_from_slice(&0x10u32.to_le_bytes());
        a.extend(body);
        let aces = parse_acl(&acl(&[a])).unwrap();
        assert_eq!(aces[0].sid.as_deref(), Some("S-1-5-32-545"));
    }

    #[test]
    fn token_facts() {
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
        let _ = is_elevated().unwrap();
    }

    #[test]
    fn profile_list_has_current_user() {
        let sid = current_user_sid().unwrap();
        let profiles = profiles().unwrap();
        let me = profiles
            .iter()
            .find(|p| p.sid == sid)
            .expect("current user in ProfileList");
        assert!(me.path.is_dir(), "{:?}", me.path);
        assert!(!me.path.to_string_lossy().contains('%'));
        assert!(profiles.iter().any(|p| p.sid == LOCAL_SYSTEM_SID));
    }

    #[test]
    fn admin_only_writable_on_host() {
        let windir =
            crate::known_folders::known_folder(crate::known_folders::KnownFolder::Windows).unwrap();
        assert!(is_admin_only_writable(&windir).unwrap(), "{windir:?}");
        assert!(!is_admin_only_writable(&std::env::temp_dir()).unwrap());
        assert_eq!(
            is_admin_only_writable(Path::new(r"relative\path")),
            Err(Win32Error::INVALID_PARAMETER)
        );
        let missing = windir.join("purge-test-no-such-dir-91c2");
        assert!(is_admin_only_writable(&missing).unwrap_err().is_not_found());
    }

    #[test]
    fn a_parent_users_may_add_to_is_not_admin_only_for_a_run() {
        // `C:\ProgramData` as Windows ships it (review M3-R2 H3).
        let system = sid_bytes(5, &[18]);
        let admins = sid_bytes(5, &[32, 544]);
        let users = sid_bytes(5, &[32, 545]);
        let creator = sid_bytes(3, &[0]);
        let (oi, ci) = (0x01, 0x02);
        let full = 0x001F_01FF;
        let read_exec = 0x0012_00A9;
        let wd_ad_wea_wa = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | 0x0010 | 0x0100;
        let program_data = |users_add: u32| SdFacts {
            owner: Some(LOCAL_SYSTEM_SID.into()),
            dacl: Some(
                parse_acl(&acl(&[
                    ace(0, oi | ci, full, &system),
                    ace(0, oi | ci, full, &admins),
                    ace(0, oi | ci | INHERIT_ONLY_ACE, full, &creator),
                    ace(0, oi | ci, read_exec, &users),
                    ace(0, ci, users_add, &users),
                ]))
                .unwrap(),
            ),
        };
        let facts = program_data(wd_ad_wea_wa);
        assert!(
            admin_only(&facts, ANCESTOR_WRITE_MASK),
            "fine above the parent"
        );
        assert!(
            !admin_only(&facts, PARENT_RUN_MASK),
            "not as the parent of a run"
        );
        for add in [FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY] {
            assert!(!admin_only(&program_data(add), PARENT_RUN_MASK), "{add:#x}");
        }
        // Without the add rights (`Program Files`: Users read and execute only) the parent passes.
        assert!(admin_only(&program_data(read_exec), PARENT_RUN_MASK));
        // Inherit-only add rights reach only new children, and CREATOR OWNER is a placeholder.
        let inherit_only = SdFacts {
            owner: Some(TRUSTED_INSTALLER_SID.into()),
            dacl: Some(
                parse_acl(&acl(&[
                    ace(0, oi | ci, full, &system),
                    ace(0, oi | ci | INHERIT_ONLY_ACE, wd_ad_wea_wa, &users),
                    ace(0, ci, FILE_ADD_FILE, &creator),
                ]))
                .unwrap(),
            ),
        };
        assert!(admin_only(&inherit_only, PARENT_RUN_MASK));

        // The walk: the path with the leaf mask, its parent with the given one, the rest as ancestors.
        assert_eq!(chain_mask(0, PARENT_RUN_MASK), LEAF_WRITE_MASK);
        assert_eq!(chain_mask(1, PARENT_RUN_MASK), PARENT_RUN_MASK);
        assert_eq!(chain_mask(1, ANCESTOR_WRITE_MASK), ANCESTOR_WRITE_MASK);
        assert_eq!(chain_mask(2, PARENT_RUN_MASK), ANCESTOR_WRITE_MASK);
        assert_eq!(chain_mask(7, PARENT_RUN_MASK), ANCESTOR_WRITE_MASK);
    }

    #[test]
    fn admin_only_executable_on_host() {
        use crate::known_folders::{KnownFolder, known_folder};
        // System32 grants Users read and execute only.
        let cmd = known_folder(KnownFolder::System).unwrap().join("cmd.exe");
        assert!(is_admin_only_writable(&cmd).unwrap(), "{cmd:?}");
        assert!(is_admin_only_executable(&cmd).unwrap(), "{cmd:?}");
        // `ProgramData\Microsoft` is admin-only itself, but its parent `ProgramData` lets Users add
        // files and folders: data trust holds, a run from there does not.
        let microsoft = known_folder(KnownFolder::ProgramData)
            .unwrap()
            .join("Microsoft");
        assert!(is_admin_only_writable(&microsoft).unwrap(), "{microsoft:?}");
        assert!(
            !is_admin_only_executable(&microsoft).unwrap(),
            "{microsoft:?}"
        );
        assert!(!is_admin_only_executable(&std::env::temp_dir()).unwrap());
        assert_eq!(
            is_admin_only_executable(Path::new(r"relative\path")),
            Err(Win32Error::INVALID_PARAMETER)
        );
    }

    #[test]
    fn drive_letter_spellings() {
        assert_eq!(drive_letter(r"C:\Windows"), Some('C'));
        assert_eq!(drive_letter("d:/x"), Some('d'));
        assert_eq!(drive_letter(r"\\?\C:\Windows"), Some('C'));
        assert_eq!(drive_letter(r"\\.\C:\Windows"), Some('C'));
        assert_eq!(drive_letter(r"\??\C:\Windows"), Some('C'));
        for remote in [
            r"\\nas\deploy\App\uninstall.exe",
            r"\\?\UNC\nas\deploy\App\uninstall.exe",
            r"\\localhost\c$\Windows",
            "//nas/deploy/App/uninstall.exe",
            r"\\?\Volume{11111111-1111-1111-1111-111111111111}\x",
            "C:relative",
            "1:\\x",
        ] {
            assert_eq!(drive_letter(remote), None, "{remote}");
        }
    }

    #[test]
    fn remote_paths_are_never_admin_only() {
        // Review M3-R2 M6: refused before any I/O, so no share has to exist.
        for remote in [
            r"\\nas\deploy\App\uninstall.exe",
            r"\\?\UNC\nas\deploy\App\uninstall.exe",
            r"\\localhost\c$\Windows\System32\cmd.exe",
            r"\\?\UNC\localhost\c$\Windows\System32\cmd.exe",
        ] {
            let path = Path::new(remote);
            assert_eq!(is_admin_only_writable(path), Ok(false), "{remote}");
            assert_eq!(is_admin_only_executable(path), Ok(false), "{remote}");
        }
        // The local fixed system drive, plain and in the extended spelling.
        let cmd = crate::known_folders::known_folder(crate::known_folders::KnownFolder::System)
            .unwrap()
            .join("cmd.exe");
        assert!(on_local_fixed_drive(&cmd), "{cmd:?}");
        let extended = PathBuf::from(format!(r"\\?\{}", cmd.display()));
        assert!(on_local_fixed_drive(&extended), "{extended:?}");
        assert_eq!(
            is_admin_only_executable(&extended),
            Ok(true),
            "{extended:?}"
        );
    }

    #[test]
    #[ignore = "needs Purge installed in %ProgramFiles%\\Purge"]
    fn the_installed_purge_passes_the_run_rule() {
        let dir =
            crate::known_folders::known_folder(crate::known_folders::KnownFolder::ProgramFiles)
                .unwrap()
                .join("Purge");
        let mut exes = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
            {
                assert!(is_admin_only_executable(&path).unwrap(), "{path:?}");
                exes += 1;
            }
        }
        assert!(exes > 0, "no .exe in {dir:?}");
    }
}
