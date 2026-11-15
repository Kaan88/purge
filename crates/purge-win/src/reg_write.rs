//! Link-refusing registry write primitives (`write` feature) (M2-WIN-REG).
//!
//! ENGINE_PLAN.md §5.10 (G1), §7.4, §7.5, §7.8. This module is the only place in the workspace that
//! changes the registry. Its rules:
//!
//! - **One handle type, [`WKey`].** Every open passes `REG_OPTION_OPEN_LINK` and an explicit
//!   `KEY_WOW64_64KEY` / `KEY_WOW64_32KEY` view, and walks the path one component at a time, so a
//!   registry symbolic link is opened as the link key itself and is never traversed. A link before
//!   the last component fails the open with [`Win32Error::LINK_ON_PATH`]; a link as the last
//!   component is returned with [`WKey::is_link`] `== true`.
//! - **Only `HKLM` and `HKU`** ([`RegRoot`]); the hive roots themselves cannot be opened for writing.
//! - **Every mutation runs on the handle the caller inspected** and refuses a link key. A key is
//!   deleted with `NtDeleteKey` on its own handle: `RegDeleteKeyExW` re-opens the child by name
//!   without `REG_OPTION_OPEN_LINK`, so it would act on the *target* of a link planted between the
//!   check and the delete. For the same reason [`WKey::create_subkey`] passes `REG_OPTION_OPEN_LINK`
//!   to `RegCreateKeyExW`, which otherwise creates the missing target of a dangling link.
//! - **Single keys only.** There is no tree delete (`RegDeleteTree`), no `RegSaveKey`, no link
//!   creation. A key with subkeys is not deleted ([`HAS_SUBKEYS`]); the caller walks deepest first.
//! - **Purge never raises its own access.** No privilege is enabled, no ownership is taken, and
//!   [`KeyAccess`] cannot request `WRITE_DAC` or `WRITE_OWNER`. The only security write is
//!   [`CreatedKey::set_security`], reachable solely through the value returned by
//!   [`WKey::create_subkey`], that is, on a key this process created a moment ago (undo).
//! - **Exact data.** Values are read and written as raw type and raw bytes through
//!   `NtQueryValueKey`, `NtEnumerateValueKey` and `NtSetValueKey`: `RegSetValueExW` may append a
//!   terminator to string types, and the Win32 reads may zero the last byte of an odd-length
//!   string. Names are strict: a key, value or class name that is not valid UTF-16, or holds a NUL,
//!   is an error ([`NAME_NOT_REPRESENTABLE`]) instead of being converted lossily, since a lossy
//!   name would make a later call address a different object.
//! - **Security on the handle.** The descriptor is read and written with `NtQuerySecurityObject`
//!   and `NtSetSecurityObject`; `RegGetKeySecurity` and `RegSetKeySecurity` open the key again.
//!
//! All `unsafe` FFI is confined to this module and carries `SAFETY` comments.

use std::ffi::c_void;
use std::ops::{BitOr, Deref};
use std::ptr;

use windows_sys::Win32::Foundation::{FILETIME, LocalFree, RtlNtStatusToDosError, UNICODE_STRING};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetSecurityDescriptorGroup, GetSecurityDescriptorOwner,
    GetSecurityDescriptorSacl, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_CREATE_SUB_KEY, KEY_QUERY_VALUE, KEY_READ,
    KEY_SET_VALUE, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_CREATED_NEW_KEY, REG_OPTION_NON_VOLATILE,
    REG_OPTION_OPEN_LINK, REG_OPTION_VOLATILE, RegCloseKey, RegCreateKeyExW, RegDeleteValueW,
    RegEnumKeyExW, RegFlushKey, RegOpenKeyExW, RegQueryInfoKeyW,
};

use crate::os::{Win32Error, from_wide_ptr, wide};
use crate::reg::{KeySecurity, REG_LINK, RegRoot, RegValue, RegView, filetime_u64};
use crate::sid::{TRUSTED_INSTALLER_SID, sd_facts};

/// `ERROR_DIR_NOT_EMPTY`: [`WKey::delete`] and [`WKey::delete_subkey`] return it for a key that
/// still has subkeys. Nothing is deleted.
pub const HAS_SUBKEYS: Win32Error = Win32Error(145);
/// `ERROR_ALREADY_EXISTS`: [`WKey::create_subkey`] returns it when the name is taken, whether by a
/// key or by a link. Nothing is created or changed.
pub const ALREADY_EXISTS: Win32Error = Win32Error(183);
/// `ERROR_NO_UNICODE_TRANSLATION`: a key name, value name or class string is not valid UTF-16 or
/// holds a NUL, so it cannot be addressed exactly through this module.
pub const NAME_NOT_REPRESENTABLE: Win32Error = Win32Error(1113);

/// Name of the value that holds a link key's target.
const SYMBOLIC_LINK_VALUE: &str = "SymbolicLinkValue";

/// Standard right `DELETE`.
const DELETE: u32 = 0x0001_0000;
/// Standard right `WRITE_DAC`.
const WRITE_DAC: u32 = 0x0004_0000;
/// Standard right `WRITE_OWNER`.
const WRITE_OWNER: u32 = 0x0008_0000;

/// Upper bound for name buffers (registry names are at most 16,383 units).
const MAX_NAME_UNITS: usize = 16_384;
/// Upper bound for class buffers.
const MAX_CLASS_UNITS: usize = 65_536;
/// Upper bound for one NT query buffer: a value's data plus its name (guards runaway growth).
const MAX_QUERY_BYTES: usize = 64 * 1024 * 1024 + 64 * 1024;

/// `KEY_INFORMATION_CLASS::KeyFlagsInformation`.
const KEY_FLAGS_INFORMATION_CLASS: i32 = 5;
/// `KEY_FLAGS_INFORMATION.KeyFlags`: the key lives in volatile storage.
const KEY_FLAG_VOLATILE: u32 = 0x1;
/// `KEY_FLAGS_INFORMATION.KeyFlags`: the key is a symbolic link.
const KEY_FLAG_LINK: u32 = 0x2;

/// `KEY_FLAGS_INFORMATION` (wdm.h).
#[repr(C)]
#[derive(Default)]
struct KeyFlagsInformation {
    wow64_flags: u32,
    key_flags: u32,
    control_flags: u32,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    /// Deletes the key the handle refers to (it must have no subkeys; needs `DELETE`).
    fn NtDeleteKey(key: HKEY) -> i32;
    /// Queries facts of an open key.
    fn NtQueryKey(key: HKEY, class: i32, info: *mut c_void, len: u32, result_len: *mut u32) -> i32;
    /// Sets a value with the given raw type and exactly `size` bytes of data.
    fn NtSetValueKey(
        key: HKEY,
        name: *const UNICODE_STRING,
        title_index: u32,
        ty: u32,
        data: *const c_void,
        size: u32,
    ) -> i32;
    /// Reads one value by name, with its stored type and bytes.
    fn NtQueryValueKey(
        key: HKEY,
        name: *const UNICODE_STRING,
        class: i32,
        info: *mut c_void,
        len: u32,
        result_len: *mut u32,
    ) -> i32;
    /// Reads the value at `index`, with its stored name, type and bytes.
    fn NtEnumerateValueKey(
        key: HKEY,
        index: u32,
        class: i32,
        info: *mut c_void,
        len: u32,
        result_len: *mut u32,
    ) -> i32;
    /// Reads the security descriptor of the object behind the handle (needs `READ_CONTROL`).
    fn NtQuerySecurityObject(
        handle: HKEY,
        info: u32,
        sd: PSECURITY_DESCRIPTOR,
        len: u32,
        needed: *mut u32,
    ) -> i32;
    /// Writes parts of the security descriptor of the object behind the handle (needs `WRITE_DAC`
    /// and/or `WRITE_OWNER` on that handle).
    fn NtSetSecurityObject(handle: HKEY, info: u32, sd: PSECURITY_DESCRIPTOR) -> i32;
}

/// `KEY_VALUE_INFORMATION_CLASS::KeyValueFullInformation`: title index, type, data offset, data
/// length, name length (bytes), name; five `u32` and then the name.
const KEY_VALUE_FULL_INFORMATION_CLASS: i32 = 1;
/// `KEY_VALUE_INFORMATION_CLASS::KeyValuePartialInformation`: title index, type, data length,
/// data; three `u32` and then the data.
const KEY_VALUE_PARTIAL_INFORMATION_CLASS: i32 = 2;
/// `STATUS_BUFFER_OVERFLOW`: the buffer holds the fixed part only; the needed size is returned.
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005_u32 as i32;
/// `STATUS_BUFFER_TOO_SMALL`: nothing was written; the needed size is returned.
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32 as i32;
/// `STATUS_NO_MORE_ENTRIES`: the enumeration index is past the end.
const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001A_u32 as i32;
/// `STATUS_OBJECT_NAME_NOT_FOUND`: no value of that name.
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;

/// Runs a size-probing NT query (`buffer, byte length, needed length -> NTSTATUS`) into an 8-byte
/// aligned buffer, growing it while the call reports it as too small. Returns the filled buffer as
/// bytes, or the failing status.
fn nt_query(mut call: impl FnMut(*mut c_void, u32, *mut u32) -> i32) -> Result<Vec<u8>, i32> {
    let mut buf = vec![0u64; 64];
    loop {
        let mut needed = 0u32;
        let status = call(buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut needed);
        if status >= 0 {
            return Ok(buf.iter().flat_map(|w| w.to_ne_bytes()).collect());
        }
        let too_small = status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL;
        if !too_small || buf.len() * 8 >= MAX_QUERY_BYTES {
            return Err(status);
        }
        let want = (needed as usize).max(buf.len() * 16).min(MAX_QUERY_BYTES);
        buf.resize(want.div_ceil(8), 0);
    }
}

/// The `u32` at byte offset `at` of an NT information buffer.
fn u32_at(buf: &[u8], at: usize) -> Result<u32, Win32Error> {
    let b = buf.get(at..at + 4).ok_or(Win32Error::INVALID_DATA)?;
    Ok(u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

/// The `len` bytes at byte offset `at` of an NT information buffer.
fn bytes_at(buf: &[u8], at: u32, len: u32) -> Result<&[u8], Win32Error> {
    let (at, len) = (at as usize, len as usize);
    buf.get(at..at.checked_add(len).ok_or(Win32Error::INVALID_DATA)?)
        .ok_or(Win32Error::INVALID_DATA)
}

/// A counted string over `name_w` (NUL-terminated; the terminator is not counted).
fn unicode_string(name_w: &[u16]) -> Result<UNICODE_STRING, Win32Error> {
    let bytes = (name_w.len() - 1) * 2;
    let (Ok(len), Ok(max_len)) = (u16::try_from(bytes), u16::try_from(bytes + 2)) else {
        return Err(Win32Error::INVALID_PARAMETER);
    };
    Ok(UNICODE_STRING {
        Length: len,
        MaximumLength: max_len,
        Buffer: name_w.as_ptr().cast_mut(),
    })
}

/// Converts an `NTSTATUS`: success and informational codes are `Ok`.
fn nt(status: i32) -> Result<(), Win32Error> {
    if status >= 0 {
        Ok(())
    } else {
        // SAFETY: a pure conversion function without pointer arguments.
        Err(Win32Error(unsafe { RtlNtStatusToDosError(status) }))
    }
}

fn root_hkey(root: RegRoot) -> HKEY {
    match root {
        RegRoot::Hklm => HKEY_LOCAL_MACHINE,
        RegRoot::Hku => HKEY_USERS,
    }
}

fn view_sam(view: RegView) -> u32 {
    match view {
        RegView::K64 => KEY_WOW64_64KEY,
        RegView::K32 => KEY_WOW64_32KEY,
    }
}

/// A single key, value or class name as NUL-terminated UTF-16; a name with an interior NUL would
/// be cut short by the Win32 API and address something else.
fn name_w(name: &str) -> Result<Vec<u16>, Win32Error> {
    if name.contains('\0') {
        return Err(NAME_NOT_REPRESENTABLE);
    }
    Ok(wide(name))
}

/// As [`name_w`], for exactly one key path component.
fn component_w(name: &str) -> Result<Vec<u16>, Win32Error> {
    if name.is_empty() || name.contains('\\') {
        return Err(Win32Error::INVALID_PARAMETER);
    }
    name_w(name)
}

/// Strict UTF-16 decoding of a name the registry returned.
fn strict_name(units: &[u16]) -> Result<String, Win32Error> {
    if units.contains(&0) {
        return Err(NAME_NOT_REPRESENTABLE);
    }
    String::from_utf16(units).map_err(|_| NAME_NOT_REPRESENTABLE)
}

/// The access rights a [`WKey`] is opened with. Combine with `|`.
///
/// Read access ([`KeyAccess::READ`]) is part of every open, so that each handle can be inspected
/// (link flag, counts, values, security descriptor) before it is used. `WRITE_DAC` and
/// `WRITE_OWNER` cannot be requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyAccess(u32);

impl KeyAccess {
    /// `KEY_READ`: query values, enumerate subkeys, read the security descriptor.
    pub const READ: KeyAccess = KeyAccess(KEY_READ);
    /// `KEY_SET_VALUE`: set and delete values of this key.
    pub const SET_VALUE: KeyAccess = KeyAccess(KEY_READ | KEY_SET_VALUE);
    /// `KEY_CREATE_SUB_KEY`: create direct subkeys. Opening with it proves the right early; the
    /// kernel checks it again, against the key's security descriptor, when a subkey is created.
    pub const CREATE_SUB_KEY: KeyAccess = KeyAccess(KEY_READ | KEY_CREATE_SUB_KEY);
    /// `DELETE`: delete this key itself ([`WKey::delete`]).
    pub const DELETE: KeyAccess = KeyAccess(KEY_READ | DELETE);
}

impl BitOr for KeyAccess {
    type Output = KeyAccess;

    fn bitor(self, rhs: KeyAccess) -> KeyAccess {
        KeyAccess(self.0 | rhs.0)
    }
}

/// Storage facts of a key, read from its handle (`NtQueryKey`, `KeyFlagsInformation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyFlags {
    /// The key is a registry symbolic link.
    pub link: bool,
    /// The key is volatile (gone at the next hive unload or reboot).
    pub volatile: bool,
}

/// Counts, class and timestamp of a key (`RegQueryInfoKeyW`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WKeyInfo {
    /// Number of direct subkeys.
    pub n_subkeys: u32,
    /// Number of values (the default value counts when it is set).
    pub n_values: u32,
    /// The key's class string; empty when it has none.
    pub class: String,
    /// Last write time as a FILETIME (100 ns ticks since 1601-01-01 UTC).
    pub last_write_time: u64,
}

/// A security descriptor allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
struct ParsedSd {
    psd: PSECURITY_DESCRIPTOR,
    /// The `SECURITY_INFORMATION` bits for the parts the SDDL string holds.
    info: u32,
}

impl Drop for ParsedSd {
    fn drop(&mut self) {
        // SAFETY: `psd` was allocated with `LocalAlloc` by the conversion call, is owned by this
        // value and is freed exactly once here.
        unsafe { LocalFree(self.psd) };
    }
}

impl ParsedSd {
    /// Parses `sddl` (owner, group and DACL parts; any subset). A string with a SACL part is
    /// refused: writing one needs a privilege, and Purge enables none.
    fn parse(sddl: &str) -> Result<ParsedSd, Win32Error> {
        let sddl_w = name_w(sddl)?;
        let mut psd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `sddl_w` is NUL-terminated and outlives the call; `psd` is a valid out-pointer;
        // the size out-pointer is optional and null.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(Win32Error::last());
        }
        let mut sd = ParsedSd { psd, info: 0 };

        let (mut sid, mut defaulted): (PSID, i32) = (ptr::null_mut(), 0);
        // SAFETY: `psd` is the valid descriptor allocated above; out-pointers are locals.
        if unsafe { GetSecurityDescriptorOwner(psd, &mut sid, &mut defaulted) } == 0 {
            return Err(Win32Error::last());
        }
        if !sid.is_null() {
            sd.info |= OWNER_SECURITY_INFORMATION;
        }
        sid = ptr::null_mut();
        // SAFETY: as above.
        if unsafe { GetSecurityDescriptorGroup(psd, &mut sid, &mut defaulted) } == 0 {
            return Err(Win32Error::last());
        }
        if !sid.is_null() {
            sd.info |= GROUP_SECURITY_INFORMATION;
        }

        let (mut present, mut acl): (i32, *mut ACL) = (0, ptr::null_mut());
        // SAFETY: as above.
        if unsafe { GetSecurityDescriptorSacl(psd, &mut present, &mut acl, &mut defaulted) } == 0 {
            return Err(Win32Error::last());
        }
        if present != 0 {
            return Err(Win32Error::INVALID_PARAMETER);
        }
        // SAFETY: as above.
        if unsafe { GetSecurityDescriptorDacl(psd, &mut present, &mut acl, &mut defaulted) } == 0 {
            return Err(Win32Error::last());
        }
        if present != 0 {
            let (mut control, mut revision) = (0u16, 0u32);
            // SAFETY: as above.
            if unsafe { GetSecurityDescriptorControl(psd, &mut control, &mut revision) } == 0 {
                return Err(Win32Error::last());
            }
            sd.info |= DACL_SECURITY_INFORMATION
                | if control & SE_DACL_PROTECTED != 0 {
                    PROTECTED_DACL_SECURITY_INFORMATION
                } else {
                    UNPROTECTED_DACL_SECURITY_INFORMATION
                };
        }
        if sd.info == 0 {
            return Err(Win32Error::INVALID_PARAMETER);
        }
        Ok(sd)
    }
}

/// An open registry key for the executor: explicit view, opened with `REG_OPTION_OPEN_LINK`, never
/// a predefined root. Closed on drop.
///
/// Reads report what the handle refers to; writes act on that same key object and refuse a link.
#[derive(Debug)]
pub struct WKey {
    hkey: HKEY,
    view: RegView,
}

// SAFETY: a registry key handle is a kernel handle, not tied to the thread that opened it.
unsafe impl Send for WKey {}
// SAFETY: the type has no interior state; the registry serialises concurrent calls on one handle.
unsafe impl Sync for WKey {}

impl Drop for WKey {
    fn drop(&mut self) {
        // SAFETY: `hkey` came from `RegOpenKeyExW` / `RegCreateKeyExW`, is owned by this value and
        // is closed exactly once here.
        unsafe { RegCloseKey(self.hkey) };
    }
}

impl WKey {
    /// Opens `path` (backslash-separated, relative to `root`, at least one component) in `view`
    /// with `access`, one component at a time with `REG_OPTION_OPEN_LINK`.
    ///
    /// A link as the last component is opened as the link key itself ([`WKey::is_link`]), never as
    /// its target. A link before the last component fails with [`Win32Error::LINK_ON_PATH`]. An
    /// empty path (a hive root) fails with [`Win32Error::INVALID_PARAMETER`].
    pub fn open(
        root: RegRoot,
        path: &str,
        view: RegView,
        access: KeyAccess,
    ) -> Result<WKey, Win32Error> {
        open_path(root_hkey(root), None, path, view, access)
    }

    /// Opens `path` below this key in this key's view (component-wise, see [`WKey::open`]). Fails
    /// with [`Win32Error::LINK_ON_PATH`] when this key or an intermediate key is a link.
    pub fn open_subkey(&self, path: &str, access: KeyAccess) -> Result<WKey, Win32Error> {
        open_path(self.hkey, Some(self), path, self.view, access)
    }

    /// The view this key was opened in.
    pub fn view(&self) -> RegView {
        self.view
    }

    /// Link and volatility flags of the key object behind the handle.
    pub fn flags(&self) -> Result<KeyFlags, Win32Error> {
        let mut info = KeyFlagsInformation::default();
        let mut len = 0u32;
        // SAFETY: `info` is a writable `KEY_FLAGS_INFORMATION` of the size passed; `len` is a valid
        // out-pointer; `hkey` is live for the borrow.
        let status = unsafe {
            NtQueryKey(
                self.hkey,
                KEY_FLAGS_INFORMATION_CLASS,
                (&raw mut info).cast(),
                size_of::<KeyFlagsInformation>() as u32,
                &mut len,
            )
        };
        nt(status)?;
        if (len as usize) < size_of::<KeyFlagsInformation>() {
            return Err(Win32Error::INVALID_DATA);
        }
        Ok(KeyFlags {
            link: info.key_flags & KEY_FLAG_LINK != 0,
            volatile: info.key_flags & KEY_FLAG_VOLATILE != 0,
        })
    }

    /// The target of a registry symbolic link: the `REG_LINK` data of `SymbolicLinkValue` (an NT
    /// path such as `\REGISTRY\USER\S-1-5-21-..._Classes`). `None` when the value is absent. The
    /// link is never followed.
    pub fn link_target(&self) -> Result<Option<String>, Win32Error> {
        Ok(self
            .value(SYMBOLIC_LINK_VALUE)?
            .filter(|v| v.ty == REG_LINK)
            .and_then(|v| v.as_string()))
    }

    /// Whether this key is a registry symbolic link: the kernel's link flag is set, or the key
    /// carries a `REG_LINK` `SymbolicLinkValue`. Either sign is enough.
    pub fn is_link(&self) -> Result<bool, Win32Error> {
        Ok(self.flags()?.link || self.link_target()?.is_some())
    }

    /// Every mutation starts here.
    fn refuse_link(&self) -> Result<(), Win32Error> {
        if self.is_link()? {
            Err(Win32Error::LINK_ON_PATH)
        } else {
            Ok(())
        }
    }

    /// Subkey and value counts, class string and last write time.
    pub fn info(&self) -> Result<WKeyInfo, Win32Error> {
        let mut class = vec![0u16; 64];
        loop {
            let mut class_len = class.len() as u32;
            let (mut n_sub, mut n_val) = (0u32, 0u32);
            let mut ft = FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            };
            // SAFETY: `class` has `class_len` writable units; every other non-null pointer refers
            // to a local that outlives the call; reserved, the maximum lengths and the security
            // descriptor size are null (not requested).
            let rc = unsafe {
                RegQueryInfoKeyW(
                    self.hkey,
                    class.as_mut_ptr(),
                    &mut class_len,
                    ptr::null(),
                    &mut n_sub,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut n_val,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut ft,
                )
            };
            match Win32Error::check(rc) {
                Ok(()) => {
                    return Ok(WKeyInfo {
                        n_subkeys: n_sub,
                        n_values: n_val,
                        class: strict_name(&class[..(class_len as usize).min(class.len())])?,
                        last_write_time: filetime_u64(ft),
                    });
                }
                Err(Win32Error::MORE_DATA) if class.len() < MAX_CLASS_UNITS => {
                    let want = (class_len as usize + 1).max(class.len() * 2);
                    class.resize(want.min(MAX_CLASS_UNITS), 0);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Names of the direct subkeys, in registry order. A name that is not valid UTF-16 fails the
    /// whole call with [`NAME_NOT_REPRESENTABLE`].
    pub fn subkey_names(&self) -> Result<Vec<String>, Win32Error> {
        let mut name = vec![0u16; 256];
        let mut out = Vec::new();
        let mut index = 0u32;
        loop {
            let mut len = name.len() as u32;
            // SAFETY: `name` has `len` writable units; reserved, class and time pointers are null
            // (not requested); `len` is a valid local.
            let rc = unsafe {
                RegEnumKeyExW(
                    self.hkey,
                    index,
                    name.as_mut_ptr(),
                    &mut len,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            match Win32Error::check(rc) {
                Ok(()) => {
                    out.push(strict_name(&name[..len as usize])?);
                    index += 1;
                }
                Err(Win32Error::NO_MORE_ITEMS) => return Ok(out),
                Err(Win32Error::MORE_DATA) if name.len() < MAX_NAME_UNITS => {
                    name.resize((name.len() * 2).min(MAX_NAME_UNITS), 0);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// All values with raw type and raw bytes, in registry order. The default value has the empty
    /// name. A name that is not valid UTF-16 fails the whole call with [`NAME_NOT_REPRESENTABLE`].
    pub fn values(&self) -> Result<Vec<RegValue>, Win32Error> {
        let mut out = Vec::new();
        for index in 0u32.. {
            // SAFETY: the closure passes on a writable buffer of the stated byte length and a
            // valid out-pointer; `hkey` is live for the borrow.
            let buf = match nt_query(|buf, len, needed| unsafe {
                NtEnumerateValueKey(
                    self.hkey,
                    index,
                    KEY_VALUE_FULL_INFORMATION_CLASS,
                    buf,
                    len,
                    needed,
                )
            }) {
                Ok(buf) => buf,
                Err(STATUS_NO_MORE_ENTRIES) => break,
                Err(status) => return nt(status).map(|()| out),
            };
            let ty = u32_at(&buf, 4)?;
            // The data offset of an empty value need not lie inside the buffer.
            let data = match u32_at(&buf, 12)? {
                0 => &[][..],
                len => bytes_at(&buf, u32_at(&buf, 8)?, len)?,
            };
            let name: Vec<u16> = bytes_at(&buf, 20, u32_at(&buf, 16)?)?
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            out.push(RegValue {
                name: strict_name(&name)?,
                ty,
                data: data.to_vec(),
            });
        }
        Ok(out)
    }

    /// One value by name (`""` for the default value) with raw type and raw bytes; `Ok(None)` when
    /// it does not exist.
    pub fn value(&self, name: &str) -> Result<Option<RegValue>, Win32Error> {
        let name_w = name_w(name)?;
        let us = unicode_string(&name_w)?;
        // SAFETY: `us` describes `name_w`, which outlives the call and is only read; the closure
        // passes on a writable buffer of the stated byte length and a valid out-pointer.
        let buf = match nt_query(|buf, len, needed| unsafe {
            NtQueryValueKey(
                self.hkey,
                &us,
                KEY_VALUE_PARTIAL_INFORMATION_CLASS,
                buf,
                len,
                needed,
            )
        }) {
            Ok(buf) => buf,
            Err(STATUS_OBJECT_NAME_NOT_FOUND) => return Ok(None),
            Err(status) => return nt(status).map(|()| None),
        };
        Ok(Some(RegValue {
            name: name.to_owned(),
            ty: u32_at(&buf, 4)?,
            data: bytes_at(&buf, 12, u32_at(&buf, 8)?)?.to_vec(),
        }))
    }

    /// The key's self-relative security descriptor (owner, group, DACL), 8-byte aligned. Read from
    /// the handle itself (`NtQuerySecurityObject`); the Win32 call opens the key a second time.
    fn read_sd(&self) -> Result<Vec<u64>, Win32Error> {
        let info =
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        // SAFETY: the closure passes on a writable buffer of the stated byte length and a valid
        // out-pointer; `hkey` is live for the borrow.
        let bytes = nt_query(|buf, len, needed| unsafe {
            NtQuerySecurityObject(self.hkey, info, buf, len, needed)
        })
        .or_else(|status| nt(status).map(|()| Vec::new()))?;
        Ok(bytes
            .chunks_exact(8)
            .map(|c| u64::from_ne_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
            .collect())
    }

    /// Owner SID and TrustedInstaller DACL flag of this handle's key (the guard's ownership facts).
    pub fn security(&self) -> Result<KeySecurity, Win32Error> {
        let mut buf = self.read_sd()?;
        // SAFETY: `buf` holds a valid self-relative security descriptor written by
        // `NtQuerySecurityObject` and stays alive, unmoved, for the parse.
        let facts = unsafe { sd_facts(buf.as_mut_ptr().cast())? };
        let dacl_names_trusted_installer = facts
            .aces()
            .iter()
            .any(|a| a.sid.as_deref() == Some(TRUSTED_INSTALLER_SID));
        Ok(KeySecurity {
            owner_sid: facts.owner,
            dacl_names_trusted_installer,
        })
    }

    /// Owner, group and DACL of the key as one SDDL string (`O:...G:...D:...`), the form
    /// [`WKey::create_subkey`] and [`CreatedKey::set_security`] accept. The SACL is not read.
    pub fn security_sddl(&self) -> Result<String, Win32Error> {
        let mut buf = self.read_sd()?;
        let info =
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut out: *mut u16 = ptr::null_mut();
        // SAFETY: `buf` holds a valid self-relative security descriptor and outlives the call;
        // `out` is a valid out-pointer; the length out-pointer is optional and null.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                buf.as_mut_ptr().cast(),
                SDDL_REVISION_1,
                info,
                &mut out,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(Win32Error::last());
        }
        // SAFETY: on success `out` is a NUL-terminated string allocated with `LocalAlloc`; it is
        // read once and freed once.
        unsafe {
            let s = from_wide_ptr(out);
            LocalFree(out.cast());
            Ok(s)
        }
    }

    /// Sets value `name` (`""` for the default value) to raw type `ty` and exactly `data`: no
    /// terminator is added or removed, any length and any type number is stored as given. Needs
    /// [`KeyAccess::SET_VALUE`]. Refuses a link key and the type `REG_LINK`.
    pub fn set_value_raw(&self, name: &str, ty: u32, data: &[u8]) -> Result<(), Win32Error> {
        if ty == REG_LINK {
            return Err(Win32Error::INVALID_PARAMETER);
        }
        let name_w = name_w(name)?;
        let us = unicode_string(&name_w)?;
        let size = u32::try_from(data.len()).map_err(|_| Win32Error::INVALID_PARAMETER)?;
        self.refuse_link()?;
        // SAFETY: `us` describes `name_w`, which outlives the call and is only read; `data` has
        // `size` readable bytes; `hkey` is live.
        nt(unsafe { NtSetValueKey(self.hkey, &us, 0, ty, data.as_ptr().cast(), size) })
    }

    /// Deletes value `name` (`""` for the default value). Needs [`KeyAccess::SET_VALUE`]. A missing
    /// value is an error for which [`Win32Error::is_not_found`] holds. Refuses a link key.
    pub fn delete_value(&self, name: &str) -> Result<(), Win32Error> {
        let name_w = name_w(name)?;
        self.refuse_link()?;
        // SAFETY: `name_w` is NUL-terminated and outlives the call; `hkey` is live.
        Win32Error::check(unsafe { RegDeleteValueW(self.hkey, name_w.as_ptr()) })
    }

    /// Deletes the key this handle refers to: this exact key object, whatever its name resolves to
    /// by now. Needs [`KeyAccess::DELETE`]. Refuses a link key ([`Win32Error::LINK_ON_PATH`]) and a
    /// key with subkeys ([`HAS_SUBKEYS`]); the kernel enforces the latter as well. Values go with
    /// the key. Afterwards the handle only reports `ERROR_KEY_DELETED`.
    pub fn delete(&self) -> Result<(), Win32Error> {
        self.refuse_link()?;
        if self.info()?.n_subkeys > 0 {
            return Err(HAS_SUBKEYS);
        }
        // SAFETY: `hkey` is a live key handle; the call takes no pointers.
        nt(unsafe { NtDeleteKey(self.hkey) })
    }

    /// Deletes the direct subkey `name` (one component) in this key's view: opens it with
    /// `REG_OPTION_OPEN_LINK` and [`KeyAccess::DELETE`], then [`WKey::delete`] on that handle. Same
    /// refusals; a missing subkey is an error for which [`Win32Error::is_not_found`] holds.
    pub fn delete_subkey(&self, name: &str) -> Result<(), Win32Error> {
        let name_w = component_w(name)?;
        self.refuse_link()?;
        open_one(self.hkey, &name_w, KeyAccess::DELETE.0, self.view)?.delete()
    }

    /// Creates the direct subkey `name` (one component) in this key's view and returns it opened
    /// for reading, writing values, creating subkeys, deleting and setting its security.
    ///
    /// - Fails with [`ALREADY_EXISTS`] when the name is taken by a key or a link; nothing is
    ///   changed then, and a dangling link's target is not created.
    /// - `class` is the key's class string (`""` for none).
    /// - `sddl` (owner, group, DACL; any subset) is applied atomically at creation; `None` leaves
    ///   the inherited default. An owner the caller's token may not assign fails with
    ///   `ERROR_INVALID_OWNER` (1307), because no privilege is enabled. Compare
    ///   [`WKey::security_sddl`] afterwards and use [`CreatedKey::set_security`] for a difference.
    /// - `volatile` selects `REG_OPTION_VOLATILE`; the executor passes `false` except when a
    ///   backup recorded a volatile key.
    ///
    /// The kernel checks the right to create a subkey against this key's security descriptor at
    /// the time of the call, not against the rights this handle was opened with. Refuses when this
    /// key is a link.
    pub fn create_subkey(
        &self,
        name: &str,
        class: &str,
        sddl: Option<&str>,
        volatile: bool,
    ) -> Result<CreatedKey, Win32Error> {
        let name_w = component_w(name)?;
        let class_w = name_w_opt(class)?;
        let sd = sddl.map(ParsedSd::parse).transpose()?;
        self.refuse_link()?;
        match open_one(self.hkey, &name_w, KEY_QUERY_VALUE, self.view) {
            Ok(_) => return Err(ALREADY_EXISTS),
            Err(e) if e.is_not_found() => {}
            Err(e) => return Err(e),
        }
        let sa = sd.as_ref().map(|sd| SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.psd,
            bInheritHandle: 0,
        });
        let storage = if volatile {
            REG_OPTION_VOLATILE
        } else {
            REG_OPTION_NON_VOLATILE
        };
        let access =
            KEY_READ | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE | WRITE_DAC | WRITE_OWNER;
        let mut out: HKEY = ptr::null_mut();
        let mut disposition = 0u32;
        // SAFETY: `name_w` and `class_w` are NUL-terminated and outlive the call; `sa`, when
        // present, points to a descriptor kept alive by `sd`; `out` and `disposition` are valid
        // out-pointers; `hkey` is live for the borrow.
        let rc = unsafe {
            RegCreateKeyExW(
                self.hkey,
                name_w.as_ptr(),
                0,
                class_w.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                storage | REG_OPTION_OPEN_LINK,
                access | view_sam(self.view),
                sa.as_ref().map_or(ptr::null(), ptr::from_ref),
                &mut out,
                &mut disposition,
            )
        };
        Win32Error::check(rc)?;
        let key = WKey {
            hkey: out,
            view: self.view,
        };
        if disposition != REG_CREATED_NEW_KEY {
            // Lost a race: the name appeared after the probe. The handle is closed unused.
            return Err(ALREADY_EXISTS);
        }
        Ok(CreatedKey(key))
    }

    /// Writes the key's pending changes to disk (`RegFlushKey`).
    pub fn flush_key(&self) -> Result<(), Win32Error> {
        // SAFETY: `hkey` is a live key handle; the call takes no pointers.
        Win32Error::check(unsafe { RegFlushKey(self.hkey) })
    }
}

/// A class string for `RegCreateKeyExW`: `None` for the empty class.
fn name_w_opt(class: &str) -> Result<Option<Vec<u16>>, Win32Error> {
    if class.is_empty() {
        Ok(None)
    } else {
        name_w(class).map(Some)
    }
}

/// Opens one path component below `parent` with `REG_OPTION_OPEN_LINK`.
fn open_one(parent: HKEY, name_w: &[u16], access: u32, view: RegView) -> Result<WKey, Win32Error> {
    let mut out: HKEY = ptr::null_mut();
    // SAFETY: `parent` is a predefined root or a handle the caller keeps alive; `name_w` is
    // NUL-terminated and outlives the call; `out` is a valid out-pointer written only on success.
    let rc = unsafe {
        RegOpenKeyExW(
            parent,
            name_w.as_ptr(),
            REG_OPTION_OPEN_LINK,
            access | view_sam(view),
            &mut out,
        )
    };
    Win32Error::check(rc)?;
    Ok(WKey { hkey: out, view })
}

/// Component-wise open below `start` (a predefined root, or the handle of `start_key`).
fn open_path(
    start: HKEY,
    start_key: Option<&WKey>,
    path: &str,
    view: RegView,
    access: KeyAccess,
) -> Result<WKey, Win32Error> {
    let comps: Vec<&str> = path.split('\\').filter(|c| !c.is_empty()).collect();
    if comps.is_empty() {
        return Err(Win32Error::INVALID_PARAMETER);
    }
    let mut current: Option<WKey> = None;
    for (i, comp) in comps.iter().enumerate() {
        let name_w = component_w(comp)?;
        // Never descend below a link: the kernel would resolve the relative open in its target.
        if let Some(parent) = current.as_ref().or(start_key) {
            parent.refuse_link()?;
        }
        let acc = if i + 1 == comps.len() {
            access.0
        } else {
            KEY_QUERY_VALUE
        };
        let parent = current.as_ref().map_or(start, |k| k.hkey);
        current = Some(open_one(parent, &name_w, acc, view)?);
    }
    Ok(current.expect("at least one component"))
}

/// A key this process created a moment ago with [`WKey::create_subkey`].
///
/// It dereferences to [`WKey`] and adds the one security write Purge performs: putting a recorded
/// owner, group and DACL back on a key it re-creates during undo. No other key can reach
/// [`CreatedKey::set_security`].
#[derive(Debug)]
pub struct CreatedKey(WKey);

impl Deref for CreatedKey {
    type Target = WKey;

    fn deref(&self) -> &WKey {
        &self.0
    }
}

impl CreatedKey {
    /// Sets the parts present in `sddl` (owner `O:`, group `G:`, DACL `D:`; any subset, at least
    /// one) on this key, through this handle (`NtSetSecurityObject`; the Win32 call opens the key
    /// a second time). The DACL is stored as given, including its protected flag and
    /// inherited-ACE flags; nothing is recomputed from the parent. A SACL part is refused. An owner
    /// the caller's token may not assign fails with `ERROR_INVALID_OWNER`.
    ///
    /// Put all parts into one call (or give them to [`WKey::create_subkey`]): the kernel checks an
    /// owner or group change against the DACL in force, so after a restrictive DACL has been set a
    /// separate owner call fails with `ERROR_ACCESS_DENIED`.
    pub fn set_security(&self, sddl: &str) -> Result<(), Win32Error> {
        let sd = ParsedSd::parse(sddl)?;
        self.0.refuse_link()?;
        // SAFETY: `sd.psd` is a valid descriptor kept alive by `sd`; `hkey` is live.
        nt(unsafe { NtSetSecurityObject(self.0.hkey, sd.info, sd.psd) })
    }

    /// Gives up the security write and keeps the plain key handle.
    pub fn into_key(self) -> WKey {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reg::{Key, REG_MULTI_SZ, REG_NONE, REG_SZ};
    use crate::sid::current_user_sid;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use windows_sys::Win32::System::Registry::{
        KEY_ALL_ACCESS, REG_OPTION_CREATE_LINK, RegRenameKey, RegSetValueExW,
    };

    const RW: KeyAccess = KeyAccess(KEY_READ | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE);
    const ACCESS_DENIED: Win32Error = Win32Error::ACCESS_DENIED;

    /// Deletes `name` below `parent` with everything in it, links included (links are deleted as
    /// keys, never followed). Test cleanup only.
    fn nuke(parent: &WKey, name: &str) -> Result<(), Win32Error> {
        let name_w = component_w(name)?;
        let child = open_one(parent.hkey, &name_w, KEY_READ | DELETE, parent.view)?;
        if !child.is_link()? {
            for sub in child.subkey_names()? {
                nuke(&child, &sub)?;
            }
        }
        // SAFETY: `child.hkey` is a live handle opened with DELETE.
        nt(unsafe { NtDeleteKey(child.hkey) })
    }

    /// A fresh `HKU\<SID>\Software\PurgeTest-<random>` key, removed again on drop (also on panic).
    struct TestRoot {
        software: WKey,
        name: String,
        /// `<SID>\Software\PurgeTest-<random>`, relative to `HKU`.
        path: String,
        key: WKey,
    }

    impl TestRoot {
        fn new() -> TestRoot {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let name = format!(
                "PurgeTest-{:x}-{:x}-{}",
                std::process::id(),
                nanos,
                COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            let sid = current_user_sid().unwrap();
            let software = WKey::open(
                RegRoot::Hku,
                &format!(r"{sid}\Software"),
                RegView::K64,
                KeyAccess::CREATE_SUB_KEY,
            )
            .unwrap();
            let key = software
                .create_subkey(&name, "", None, false)
                .unwrap()
                .into_key();
            TestRoot {
                software,
                path: format!(r"{sid}\Software\{name}"),
                name,
                key,
            }
        }

        /// The NT path of `rel` below this root, as a link target.
        fn nt_path(&self, rel: &str) -> String {
            format!(r"\REGISTRY\USER\{}\{rel}", self.path)
        }

        fn open(&self, rel: &str, access: KeyAccess) -> Result<WKey, Win32Error> {
            WKey::open(
                RegRoot::Hku,
                &format!(r"{}\{rel}", self.path),
                RegView::K64,
                access,
            )
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let r = nuke(&self.software, &self.name);
            if !std::thread::panicking() {
                r.expect("test key removed");
            }
        }
    }

    /// Creates the registry symbolic link `name` below `parent`, pointing at NT path `target`.
    fn make_link(parent: &WKey, name: &str, target: &str) {
        let name_w = wide(name);
        let mut out: HKEY = ptr::null_mut();
        // SAFETY: `name_w` is NUL-terminated; class, security attributes and disposition are null;
        // `out` is a valid out-pointer.
        let rc = unsafe {
            RegCreateKeyExW(
                parent.hkey,
                name_w.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_CREATE_LINK,
                KEY_ALL_ACCESS | view_sam(parent.view),
                ptr::null(),
                &mut out,
                ptr::null_mut(),
            )
        };
        Win32Error::check(rc).expect("create link key");
        let link = WKey {
            hkey: out,
            view: parent.view,
        };
        let data: Vec<u8> = target.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let value_w = wide(SYMBOLIC_LINK_VALUE);
        // SAFETY: `value_w` is NUL-terminated; `data` has the stated number of readable bytes.
        let rc = unsafe {
            RegSetValueExW(
                link.hkey,
                value_w.as_ptr(),
                0,
                REG_LINK,
                data.as_ptr(),
                data.len() as u32,
            )
        };
        Win32Error::check(rc).expect("set link target");
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn link_is_opened_as_itself_and_never_followed_or_changed() {
        let root = TestRoot::new();
        let target = root.key.create_subkey("target", "", None, false).unwrap();
        target.set_value_raw("v", REG_SZ, &utf16("keep")).unwrap();
        target.create_subkey("child", "", None, false).unwrap();
        make_link(&root.key, "link", &root.nt_path("target"));

        let link = root.open("link", RW).unwrap();
        assert!(link.is_link().unwrap());
        assert!(link.flags().unwrap().link);
        assert_eq!(
            link.link_target().unwrap().as_deref(),
            Some(root.nt_path("target").as_str())
        );
        // The link key itself: no subkeys, and not the target's value.
        assert_eq!(link.info().unwrap().n_subkeys, 0);
        assert_eq!(link.value("v").unwrap(), None);
        assert!(!target.is_link().unwrap());
        assert!(!target.flags().unwrap().link);
        // The read-only wrapper agrees.
        assert!(
            Key::open(RegRoot::Hku, &format!(r"{}\link", root.path), RegView::K64)
                .unwrap()
                .is_link()
                .unwrap()
        );

        // Nothing descends through it.
        let lop = Win32Error::LINK_ON_PATH;
        assert_eq!(root.open(r"link\child", RW).unwrap_err(), lop);
        assert_eq!(link.open_subkey("child", RW).unwrap_err(), lop);

        // Every mutation refuses the link key.
        assert_eq!(link.set_value_raw("x", REG_SZ, b"ab").unwrap_err(), lop);
        assert_eq!(link.delete_value(SYMBOLIC_LINK_VALUE).unwrap_err(), lop);
        assert_eq!(link.delete_value("v").unwrap_err(), lop);
        assert_eq!(link.delete().unwrap_err(), lop);
        assert_eq!(root.key.delete_subkey("link").unwrap_err(), lop);
        assert_eq!(link.create_subkey("new", "", None, false).unwrap_err(), lop);
        assert_eq!(link.delete_subkey("child").unwrap_err(), lop);

        // Link and target are untouched.
        assert!(
            root.open("link", KeyAccess::READ)
                .unwrap()
                .is_link()
                .unwrap()
        );
        let t = root.open("target", KeyAccess::READ).unwrap();
        assert_eq!(t.value("v").unwrap().unwrap().data, utf16("keep"));
        assert_eq!(t.subkey_names().unwrap(), vec!["child"]);
        assert_eq!(t.info().unwrap().n_values, 1);
    }

    #[test]
    fn create_over_a_dangling_link_fails_and_does_not_create_the_target() {
        let root = TestRoot::new();
        make_link(&root.key, "dangling", &root.nt_path("absent"));
        assert_eq!(
            root.key
                .create_subkey("dangling", "", None, false)
                .unwrap_err(),
            ALREADY_EXISTS
        );
        assert!(
            root.open("absent", KeyAccess::READ)
                .unwrap_err()
                .is_not_found()
        );
        assert_eq!(root.key.subkey_names().unwrap(), vec!["dangling"]);
        // The dangling link is still a link, still reported, still refused.
        let link = root.open("dangling", KeyAccess::DELETE).unwrap();
        assert!(link.is_link().unwrap());
        assert_eq!(link.delete().unwrap_err(), Win32Error::LINK_ON_PATH);
    }

    #[test]
    fn link_key_without_a_target_value_is_still_a_link() {
        let root = TestRoot::new();
        make_link(&root.key, "bare", &root.nt_path("x"));
        let bare = root.open("bare", KeyAccess::READ).unwrap();
        // Remove the target value behind the module's back: the kernel flag still says link.
        let value_w = wide(SYMBOLIC_LINK_VALUE);
        let raw = open_one(root.key.hkey, &wide("bare"), KEY_ALL_ACCESS, RegView::K64).unwrap();
        // SAFETY: `value_w` is NUL-terminated; `raw.hkey` is live.
        Win32Error::check(unsafe { RegDeleteValueW(raw.hkey, value_w.as_ptr()) }).unwrap();
        assert_eq!(bare.link_target().unwrap(), None);
        assert!(bare.flags().unwrap().link);
        assert!(bare.is_link().unwrap());
        assert_eq!(
            root.key.delete_subkey("bare").unwrap_err(),
            Win32Error::LINK_ON_PATH
        );
    }

    #[test]
    fn delete_refuses_a_key_with_subkeys() {
        let root = TestRoot::new();
        let a = root.key.create_subkey("a", "", None, false).unwrap();
        a.set_value_raw("v", REG_SZ, &utf16("x\0")).unwrap();
        a.create_subkey("b", "", None, false).unwrap();

        assert_eq!(root.key.delete_subkey("a").unwrap_err(), HAS_SUBKEYS);
        assert_eq!(a.delete().unwrap_err(), HAS_SUBKEYS);
        assert_eq!(a.subkey_names().unwrap(), vec!["b"]);
        assert_eq!(a.info().unwrap().n_values, 1);
        // The kernel refuses as well, without the count check in front.
        // SAFETY: `a` is a live handle with DELETE access.
        assert!(nt(unsafe { NtDeleteKey(a.hkey) }).is_err());
        assert!(root.open("a", KeyAccess::READ).is_ok());

        // Deepest first works; a key with values but no subkeys goes in one call.
        a.delete_subkey("b").unwrap();
        root.key.delete_subkey("a").unwrap();
        assert!(root.open("a", KeyAccess::READ).unwrap_err().is_not_found());
        assert!(root.key.delete_subkey("a").unwrap_err().is_not_found());
        // The stale handle reports the deletion and nothing else.
        assert_eq!(a.info().unwrap_err(), Win32Error(1018));
    }

    #[test]
    fn delete_acts_on_the_inspected_handle() {
        let root = TestRoot::new();
        root.key.create_subkey("k", "", None, false).unwrap();
        let k = root.open("k", KeyAccess::DELETE).unwrap();
        assert!(!k.is_link().unwrap());
        k.delete().unwrap();
        assert!(root.open("k", KeyAccess::READ).unwrap_err().is_not_found());
        // Without DELETE on the handle there is no delete.
        root.key.create_subkey("ro", "", None, false).unwrap();
        let ro = root.open("ro", KeyAccess::READ).unwrap();
        assert_eq!(ro.delete().unwrap_err(), ACCESS_DENIED);
        assert!(root.open("ro", KeyAccess::READ).is_ok());
    }

    #[test]
    fn a_link_swapped_in_after_the_check_is_not_followed() {
        let root = TestRoot::new();
        let precious = root.key.create_subkey("precious", "", None, false).unwrap();
        precious.set_value_raw("v", REG_SZ, &utf16("keep")).unwrap();
        root.key.create_subkey("victim", "", None, false).unwrap();

        // The executor opens and inspects its key ...
        let checked = root.open("victim", KeyAccess::DELETE).unwrap();
        assert!(!checked.is_link().unwrap());
        // ... then the name is taken over by a link to something else.
        let (old_w, new_w) = (wide("victim"), wide("moved"));
        // SAFETY: both names are NUL-terminated and outlive the call; the handle is live.
        let rc = unsafe { RegRenameKey(root.key.hkey, old_w.as_ptr(), new_w.as_ptr()) };
        Win32Error::check(rc).expect("rename");
        make_link(&root.key, "victim", &root.nt_path("precious"));

        // By name: refused, because the name is a link now.
        assert_eq!(
            root.key.delete_subkey("victim").unwrap_err(),
            Win32Error::LINK_ON_PATH
        );
        // By handle: the inspected key goes, wherever it lives now; link and target stay.
        checked.delete().unwrap();
        assert!(
            root.open("moved", KeyAccess::READ)
                .unwrap_err()
                .is_not_found()
        );
        assert!(
            root.open("victim", KeyAccess::READ)
                .unwrap()
                .is_link()
                .unwrap()
        );
        let p = root.open("precious", KeyAccess::READ).unwrap();
        assert_eq!(p.value("v").unwrap().unwrap().data, utf16("keep"));
    }

    #[test]
    fn create_fails_on_an_existing_key_and_leaves_it_alone() {
        let root = TestRoot::new();
        let first = root
            .key
            .create_subkey("k", "FirstClass", None, false)
            .unwrap();
        first.set_value_raw("v", 4, &[1, 0, 0, 0]).unwrap();
        let before = first.security_sddl().unwrap();

        let sid = current_user_sid().unwrap();
        let other_sddl = format!("D:P(A;;KR;;;{sid})");
        assert_eq!(
            root.key
                .create_subkey("k", "SecondClass", Some(&other_sddl), true)
                .unwrap_err(),
            ALREADY_EXISTS
        );
        let k = root.open("K", KeyAccess::READ).unwrap();
        assert_eq!(k.info().unwrap().class, "FirstClass");
        assert_eq!(k.value("v").unwrap().unwrap().data, [1, 0, 0, 0]);
        assert_eq!(k.security_sddl().unwrap(), before);
        assert!(!k.flags().unwrap().volatile);
    }

    #[test]
    fn names_are_single_components_without_nul() {
        let root = TestRoot::new();
        let inv = Win32Error::INVALID_PARAMETER;
        assert_eq!(
            root.key.create_subkey(r"a\b", "", None, false).unwrap_err(),
            inv
        );
        assert_eq!(
            root.key.create_subkey("", "", None, false).unwrap_err(),
            inv
        );
        assert_eq!(root.key.delete_subkey(r"a\b").unwrap_err(), inv);
        assert_eq!(root.key.delete_subkey("").unwrap_err(), inv);
        assert_eq!(
            root.key.create_subkey("a\0b", "", None, false).unwrap_err(),
            NAME_NOT_REPRESENTABLE
        );
        assert_eq!(
            root.key
                .create_subkey("a", "c\0d", None, false)
                .unwrap_err(),
            NAME_NOT_REPRESENTABLE
        );
        assert_eq!(
            root.key.set_value_raw("v\0w", REG_SZ, b"").unwrap_err(),
            NAME_NOT_REPRESENTABLE
        );
        assert_eq!(
            root.key.delete_value("v\0w").unwrap_err(),
            NAME_NOT_REPRESENTABLE
        );
        assert_eq!(root.key.value("v\0w").unwrap_err(), NAME_NOT_REPRESENTABLE);
        assert_eq!(root.open("a\0b", RW).unwrap_err(), NAME_NOT_REPRESENTABLE);
        assert_eq!(root.key.info().unwrap().n_subkeys, 0);
        assert_eq!(root.key.info().unwrap().n_values, 0);
        // A hive root is not a write target.
        for root_id in [RegRoot::Hku, RegRoot::Hklm] {
            assert_eq!(
                WKey::open(root_id, "", RegView::K64, KeyAccess::READ).unwrap_err(),
                inv
            );
        }
        assert_eq!(
            strict_name(&[0x61, 0xD800]).unwrap_err(),
            NAME_NOT_REPRESENTABLE
        );
        assert_eq!(
            strict_name(&[0x61, 0, 0x62]).unwrap_err(),
            NAME_NOT_REPRESENTABLE
        );
    }

    #[test]
    fn raw_values_round_trip_exactly() {
        let root = TestRoot::new();
        let k = &root.key;
        // "abcd" as REG_SZ without terminator, with zero bytes right behind the slice: the case
        // in which the Win32 setter would extend the data by a terminator.
        let mut padded = utf16("abcd");
        padded.extend_from_slice(&[0, 0, 0, 0]);
        let unterminated = &padded[..8];
        let big: Vec<u8> = (0..70_001u32).map(|i| (i % 251) as u8).collect();
        let cases: Vec<(&str, u32, &[u8])> = vec![
            ("sz-unterminated", REG_SZ, unterminated),
            ("sz-odd", REG_SZ, &[0x61, 0x00, 0x62]),
            ("sz-empty", REG_SZ, &[]),
            ("sz-double-nul", REG_SZ, &[0x61, 0, 0, 0, 0, 0]),
            ("expand-odd", 2, &[1, 2, 3, 4, 5]),
            ("none-with-data", REG_NONE, &[9, 8, 7]),
            ("none-empty", REG_NONE, &[]),
            ("dword-short", 4, &[1, 2]),
            ("dword-long", 4, &[1, 2, 3, 4, 5, 6, 7]),
            ("qword-odd", 11, &[1, 2, 3]),
            ("multi-unterminated", REG_MULTI_SZ, unterminated),
            ("type-12", 12, &[0xAA]),
            ("type-high", 0xFFFF_0007, &[1, 2, 3, 4, 5]),
            ("type-max", u32::MAX, &[0]),
            ("binary-big", 3, &big),
            ("", REG_SZ, &[0x7A, 0x00]),
            ("Ünï cödé \u{1F600} name", 3, &[0]),
        ];
        for (name, ty, data) in &cases {
            k.set_value_raw(name, *ty, data).unwrap();
        }
        for (name, ty, data) in &cases {
            let v = k.value(name).unwrap().unwrap_or_else(|| panic!("{name}"));
            assert_eq!((v.ty, v.data.as_slice()), (*ty, *data), "{name}");
        }
        let all = k.values().unwrap();
        assert_eq!(all.len(), cases.len());
        assert_eq!(k.info().unwrap().n_values as usize, cases.len());
        for (name, ty, data) in &cases {
            let v = all.iter().find(|v| v.name == *name).expect(name);
            assert_eq!((v.ty, v.data.as_slice()), (*ty, *data), "{name}");
        }
        // The read-only wrapper lists the same values. Its Win32 reads may zero the last byte of
        // an odd-length string, which is one reason this module reads through the NT calls.
        let ro = Key::open(RegRoot::Hku, &root.path, RegView::K64).unwrap();
        let win32 = ro.values().unwrap();
        assert_eq!(win32.len(), all.len());
        for (w, e) in win32.iter().zip(&all) {
            assert_eq!((&w.name, w.ty, w.data.len()), (&e.name, e.ty, e.data.len()));
            if e.data.len() % 2 == 0 {
                assert_eq!(w.data, e.data, "{}", e.name);
            }
        }

        // Overwrite changes type and bytes; value names are case-insensitive.
        k.set_value_raw("SZ-ODD", 0x1234, &[5]).unwrap();
        let v = k.value("sz-odd").unwrap().unwrap();
        assert_eq!((v.ty, v.data.as_slice()), (0x1234, &[5u8][..]));
        assert_eq!(k.values().unwrap().len(), cases.len());

        // REG_LINK data is never written.
        assert_eq!(
            k.set_value_raw("l", REG_LINK, &utf16("x")).unwrap_err(),
            Win32Error::INVALID_PARAMETER
        );
        assert_eq!(
            k.set_value_raw(SYMBOLIC_LINK_VALUE, REG_LINK, &utf16("x"))
                .unwrap_err(),
            Win32Error::INVALID_PARAMETER
        );
        assert_eq!(k.value("l").unwrap(), None);
        assert!(!k.is_link().unwrap());
    }

    #[test]
    fn delete_value_and_flush() {
        let root = TestRoot::new();
        let k = &root.key;
        k.set_value_raw("a", REG_SZ, &utf16("1\0")).unwrap();
        k.set_value_raw("", REG_SZ, &utf16("d\0")).unwrap();
        k.flush_key().unwrap();
        k.delete_value("A").unwrap();
        assert_eq!(k.value("a").unwrap(), None);
        assert!(k.delete_value("a").unwrap_err().is_not_found());
        k.delete_value("").unwrap();
        assert!(k.delete_value("").unwrap_err().is_not_found());
        assert_eq!(k.info().unwrap().n_values, 0);

        // A handle opened for reading cannot write: access is never raised.
        root.key.create_subkey("k", "", None, false).unwrap();
        let ro = root.open("k", KeyAccess::READ).unwrap();
        assert_eq!(
            ro.set_value_raw("a", REG_SZ, b"").unwrap_err(),
            ACCESS_DENIED
        );
        assert_eq!(ro.delete_value("a").unwrap_err(), ACCESS_DENIED);
        assert_eq!(ro.info().unwrap().n_subkeys, 0);
        let set_only = root.open("k", KeyAccess::SET_VALUE).unwrap();
        set_only.set_value_raw("a", REG_SZ, b"").unwrap();
        assert_eq!(set_only.delete().unwrap_err(), ACCESS_DENIED);
    }

    #[test]
    fn class_strings_round_trip() {
        let root = TestRoot::new();
        let long = "C".repeat(300);
        for (name, class) in [
            ("plain", "PurgeClass"),
            ("none", ""),
            ("unicode", "Klasse \u{00FC}\u{4E2D} \u{1F600}"),
            ("long", long.as_str()),
        ] {
            let created = root.key.create_subkey(name, class, None, false).unwrap();
            assert_eq!(created.info().unwrap().class, class, "{name}");
            let info = root.open(name, KeyAccess::READ).unwrap().info().unwrap();
            assert_eq!(info.class, class, "{name}");
            assert_eq!((info.n_subkeys, info.n_values), (0, 0));
            assert!(info.last_write_time > 0);
        }
        let mut names = root.key.subkey_names().unwrap();
        names.sort();
        assert_eq!(names, vec!["long", "none", "plain", "unicode"]);
        assert_eq!(root.key.info().unwrap().n_subkeys, 4);
    }

    #[test]
    fn both_views_open_create_and_delete() {
        // Below HKU\<SID>\Software the two views name the same key; the redirected case needs
        // HKLM and runs in `views_are_separate_under_hklm_software`.
        let root = TestRoot::new();
        let sid_path = &root.path;
        let k32 = WKey::open(RegRoot::Hku, sid_path, RegView::K32, RW).unwrap();
        assert_eq!(k32.view(), RegView::K32);
        let made = k32.create_subkey("from32", "c32", None, false).unwrap();
        assert_eq!(made.view(), RegView::K32);
        made.set_value_raw("v", REG_SZ, &utf16("x")).unwrap();
        let sub = k32.open_subkey("from32", KeyAccess::READ).unwrap();
        assert_eq!(sub.view(), RegView::K32);

        let k64 = root.open("from32", RW).unwrap();
        assert_eq!(k64.view(), RegView::K64);
        assert_eq!(k64.info().unwrap().class, "c32");
        assert_eq!(k64.value("v").unwrap().unwrap().data, utf16("x"));
        k32.delete_subkey("from32").unwrap();
        assert_eq!(k64.info().unwrap_err(), Win32Error(1018));
    }

    #[test]
    #[ignore = "needs admin rights: writes HKLM\\SOFTWARE\\PurgeTest-<random> (runs in the VM)"]
    fn views_are_separate_under_hklm_software() {
        let name = format!("PurgeTest-{:x}", std::process::id());
        let open_sw = |view| WKey::open(RegRoot::Hklm, "SOFTWARE", view, KeyAccess::CREATE_SUB_KEY);
        let (sw32, sw64) = (
            open_sw(RegView::K32).unwrap(),
            open_sw(RegView::K64).unwrap(),
        );
        let made = sw32.create_subkey(&name, "", None, false).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            made.set_value_raw("v", 4, &[1, 0, 0, 0]).unwrap();
            // Present in the 32-bit view and below WOW6432Node, absent from the 64-bit view.
            assert!(sw32.open_subkey(&name, KeyAccess::READ).is_ok());
            assert!(
                sw64.open_subkey(&format!(r"WOW6432Node\{name}"), KeyAccess::READ)
                    .is_ok()
            );
            assert!(
                sw64.open_subkey(&name, KeyAccess::READ)
                    .unwrap_err()
                    .is_not_found()
            );
            assert!(sw64.delete_subkey(&name).unwrap_err().is_not_found());
        }));
        let removed = sw32.delete_subkey(&name);
        result.unwrap();
        removed.unwrap();
        assert!(
            sw32.open_subkey(&name, KeyAccess::READ)
                .unwrap_err()
                .is_not_found()
        );
    }

    #[test]
    fn volatile_flag_is_reported() {
        let root = TestRoot::new();
        let v = root.key.create_subkey("vol", "", None, true).unwrap();
        assert_eq!(
            v.flags().unwrap(),
            KeyFlags {
                link: false,
                volatile: true
            }
        );
        let n = root.key.create_subkey("nonvol", "", None, false).unwrap();
        assert_eq!(
            n.flags().unwrap(),
            KeyFlags {
                link: false,
                volatile: false
            }
        );
        // A stable key cannot live below a volatile one.
        assert!(v.create_subkey("stable", "", None, false).is_err());
        assert!(v.create_subkey("vol2", "", None, true).is_ok());
    }

    /// Puts a permissive DACL back when dropped, so the test key can be removed after a failure.
    struct RestoreDacl<'a>(&'a CreatedKey, String);

    impl Drop for RestoreDacl<'_> {
        fn drop(&mut self) {
            let _ = self.0.set_security(&self.1);
        }
    }

    #[test]
    fn security_round_trip_and_restricted_dacl() {
        let root = TestRoot::new();
        let sid = current_user_sid().unwrap();
        let open_sddl = format!("D:P(A;CI;KA;;;{sid})");

        // Default security: inherited, owned by a SID, readable as SDDL with all three parts.
        let plain = root.key.create_subkey("plain", "", None, false).unwrap();
        let inherited = plain.security_sddl().unwrap();
        assert!(inherited.starts_with("O:"), "{inherited}");
        assert!(
            inherited.contains("G:") && inherited.contains("D:"),
            "{inherited}"
        );
        let facts = plain.security().unwrap();
        assert!(facts.owner_sid.is_some());
        assert!(!facts.trusted_installer());

        // A protected, read-only DACL given at creation is on the key from the start.
        let restricted_sddl = format!("D:P(A;;KR;;;{sid})(A;;KA;;;SY)");
        let locked = root
            .key
            .create_subkey("locked", "", Some(&restricted_sddl), false)
            .unwrap();
        let _restore = RestoreDacl(&locked, open_sddl.clone());
        let got = locked.security_sddl().unwrap();
        let dacl = &got[got.find("D:").unwrap()..];
        assert_eq!(dacl, restricted_sddl, "{got}");

        // Purge does not raise its access: a fresh open for writing is denied, reading works.
        assert_eq!(
            root.open("locked", KeyAccess::SET_VALUE).unwrap_err(),
            ACCESS_DENIED
        );
        assert_eq!(
            root.open("locked", KeyAccess::DELETE).unwrap_err(),
            ACCESS_DENIED
        );
        assert_eq!(
            root.open("locked", KeyAccess::CREATE_SUB_KEY).unwrap_err(),
            ACCESS_DENIED
        );
        assert_eq!(root.key.delete_subkey("locked").unwrap_err(), ACCESS_DENIED);
        let ro = root.open("locked", KeyAccess::READ).unwrap();
        assert_eq!(ro.security_sddl().unwrap(), got);
        assert_eq!(ro.info().unwrap().n_values, 0);
        // The creating handle keeps the rights it was created with.
        locked.set_value_raw("v", REG_SZ, &utf16("x")).unwrap();

        // set_security: a full descriptor read from one key is stored exactly on another.
        let copy = root.key.create_subkey("copy", "", None, false).unwrap();
        let _restore_copy = RestoreDacl(&copy, open_sddl.clone());
        copy.set_security(&got).unwrap();
        assert_eq!(copy.security_sddl().unwrap(), got);
        // So is one given at creation, in a single step.
        let full = root
            .key
            .create_subkey("full", "", Some(&got), false)
            .unwrap();
        let _restore_full = RestoreDacl(&full, open_sddl.clone());
        assert_eq!(full.security_sddl().unwrap(), got);
        // Back to the unprotected default: the DACL first (the kernel checks an owner or group
        // change against the DACL in force), then the whole descriptor.
        copy.set_security(&inherited[inherited.find("D:").unwrap()..])
            .unwrap();
        copy.set_security(&inherited).unwrap();
        assert_eq!(copy.security_sddl().unwrap(), inherited);
        // Owner alone (the caller's own SID is always assignable) leaves the DACL alone.
        copy.set_security(&format!("O:{sid}")).unwrap();
        let after = copy.security_sddl().unwrap();
        assert!(after.starts_with(&format!("O:{sid}")), "{after}");
        assert_eq!(
            &after[after.find("D:").unwrap()..],
            &inherited[inherited.find("D:").unwrap()..]
        );

        // Refused inputs change nothing.
        let inv = Win32Error::INVALID_PARAMETER;
        assert_eq!(copy.set_security("S:(AU;SA;KA;;;WD)").unwrap_err(), inv);
        assert_eq!(
            copy.set_security(&format!("{open_sddl}S:(AU;SA;KA;;;WD)"))
                .unwrap_err(),
            inv
        );
        assert!(copy.set_security("not sddl").is_err());
        assert!(copy.set_security("").is_err());
        assert!(
            root.key
                .create_subkey("bad", "", Some("not sddl"), false)
                .is_err()
        );
        assert!(
            root.open("bad", KeyAccess::READ)
                .unwrap_err()
                .is_not_found()
        );
        assert_eq!(copy.security_sddl().unwrap(), after);

        // An owner the token may not assign is an error, not a privilege request.
        let foreign = copy.set_security(&format!("O:{TRUSTED_INSTALLER_SID}"));
        assert_eq!(foreign.unwrap_err(), Win32Error(1307));
        assert_eq!(copy.security_sddl().unwrap(), after);
    }
}
