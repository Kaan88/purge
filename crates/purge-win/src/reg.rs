//! Read-only registry access with an explicit WOW64 view that never follows registry links.
//!
//! ENGINE_PLAN.md §3.2 / §5.10 (G1):
//! - Only the two physical roots the engine reasons about are exposed: `HKLM` and `HKU` ([`RegRoot`]).
//!   `HKCR` and `HKCU` are merged/aliased views and are deliberately absent.
//! - Every open passes an explicit `KEY_WOW64_64KEY` or `KEY_WOW64_32KEY` ([`RegView`]) and
//!   `REG_OPTION_OPEN_LINK`. [`Key::open`] opens a path **one component at a time**, so a registry
//!   symbolic link is opened as the link key itself and never traversed: as the last component the
//!   caller sees it through [`Key::link_target`]; before the last component the open fails with
//!   [`Win32Error::LINK_ON_PATH`]. Consequently `HKLM\SYSTEM\CurrentControlSet\...` does not
//!   resolve; map it to `ControlSet00N` first with [`current_control_set`], and read
//!   `HKU\<SID>_Classes` instead of `HKU\<SID>\Software\Classes` (both are `purge-guard`
//!   canonicalisation duties).
//! - Subkeys are enumerated with `RegQueryInfoKeyW` for sizes and `RegEnumKeyExW`, growing the buffer on
//!   `ERROR_MORE_DATA`.
//! - Values are read with their stored type and exactly their stored bytes through `NtEnumerateValueKey`
//!   and `NtQueryValueKey`. The Win32 reads (`RegEnumValueW`, `RegQueryValueExW`) zero the last byte of
//!   a string value (`REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`) whose data has an odd length (seen
//!   when the caller's buffer has room beyond the data and the data does not already end in a NUL
//!   character), so the bytes they report are not what is stored. Data of even length reads the same
//!   either way. The
//!   predefined roots ([`Key::root`]) are pseudo-handles the NT calls do not take; their values (the
//!   hive roots hold none in practice) are still read through the Win32 calls.
//! - [`Key::security`] reports the owner SID and whether any DACL entry names TrustedInstaller, the
//!   subtree-baseline facts of ENGINE_PLAN.md §5.2.
//!
//! All `unsafe` FFI is confined to this module and carries `SAFETY` comments.
#![cfg(feature = "read")]

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::{FILETIME, RtlNtStatusToDosError, UNICODE_STRING};
use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_QUERY_VALUE, KEY_READ, KEY_WOW64_32KEY,
    KEY_WOW64_64KEY, REG_OPTION_OPEN_LINK, RegCloseKey, RegEnumKeyExW, RegEnumValueW,
    RegGetKeySecurity, RegOpenKeyExW, RegQueryInfoKeyW, RegQueryValueExW,
};

use crate::os::{Win32Error, from_wide, wide};
use crate::sid::{TRUSTED_INSTALLER_SID, sd_facts};

/// `REG_NONE`.
pub const REG_NONE: u32 = 0;
/// `REG_SZ`.
pub const REG_SZ: u32 = 1;
/// `REG_EXPAND_SZ`.
pub const REG_EXPAND_SZ: u32 = 2;
/// `REG_BINARY`.
pub const REG_BINARY: u32 = 3;
/// `REG_DWORD` (little-endian).
pub const REG_DWORD: u32 = 4;
/// `REG_DWORD_BIG_ENDIAN`.
pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
/// `REG_LINK`: the target of a registry symbolic link (stored in `SymbolicLinkValue`).
pub const REG_LINK: u32 = 6;
/// `REG_MULTI_SZ`.
pub const REG_MULTI_SZ: u32 = 7;
/// `REG_QWORD` (little-endian).
pub const REG_QWORD: u32 = 11;

/// Name of the value that holds a link key's target.
const SYMBOLIC_LINK_VALUE: &str = "SymbolicLinkValue";

#[link(name = "ntdll")]
unsafe extern "system" {
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
/// Upper bound for one NT value read: the largest data plus a name (guards runaway growth).
const MAX_QUERY_BYTES: usize = MAX_DATA_BYTES + 64 * 1024;

/// The 8-byte words an NT value read is first offered: 512 bytes.
const NT_FIRST_WORDS: usize = 64;

/// Runs a size-probing NT query (`buffer, byte length, needed length -> NTSTATUS`) into an 8-byte
/// aligned buffer, growing it while the call reports it as too small. Returns the filled buffer as
/// bytes, or the failing status.
fn nt_query(mut call: impl FnMut(*mut c_void, u32, *mut u32) -> i32) -> Result<Vec<u8>, i32> {
    let mut buf = vec![0u64; NT_FIRST_WORDS];
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

/// The Win32 error of a failed `NTSTATUS`.
fn nt_error(status: i32) -> Win32Error {
    // SAFETY: a pure conversion function without pointer arguments.
    Win32Error(unsafe { RtlNtStatusToDosError(status) })
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

/// A physical registry root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegRoot {
    /// `HKEY_LOCAL_MACHINE`.
    Hklm,
    /// `HKEY_USERS` (loaded user hives, `<SID>` and `<SID>_Classes`).
    Hku,
}

impl RegRoot {
    fn hkey(self) -> HKEY {
        match self {
            RegRoot::Hklm => HKEY_LOCAL_MACHINE,
            RegRoot::Hku => HKEY_USERS,
        }
    }
}

/// The WOW64 registry view passed explicitly on every open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegView {
    /// `KEY_WOW64_64KEY`: the native view; `WOW6432Node` appears as an ordinary subkey.
    K64,
    /// `KEY_WOW64_32KEY`: the redirected 32-bit view.
    K32,
}

impl RegView {
    fn sam(self) -> u32 {
        match self {
            RegView::K64 => KEY_WOW64_64KEY,
            RegView::K32 => KEY_WOW64_32KEY,
        }
    }
}

/// Sizes and timestamp from `RegQueryInfoKeyW`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyInfo {
    /// Number of direct subkeys.
    pub n_subkeys: u32,
    /// Longest subkey name, in UTF-16 units, without the terminator.
    pub max_subkey_name_len: u32,
    /// Number of values (the default value counts when it is set).
    pub n_values: u32,
    /// Longest value name, in UTF-16 units, without the terminator.
    pub max_value_name_len: u32,
    /// Largest value data, in bytes.
    pub max_value_len: u32,
    /// Last write time as a FILETIME (100 ns ticks since 1601-01-01 UTC).
    pub last_write_time: u64,
}

/// One subkey from `RegEnumKeyExW`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubkeyEntry {
    /// Subkey name (one path component).
    pub name: String,
    /// Its last write time as a FILETIME.
    pub last_write_time: u64,
}

/// One registry value: name, raw type and raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegValue {
    /// Value name; empty for the default value.
    pub name: String,
    /// Raw `REG_*` type.
    pub ty: u32,
    /// Raw data bytes exactly as stored.
    pub data: Vec<u8>,
}

impl RegValue {
    /// The data as UTF-16 units (an odd trailing byte is dropped).
    fn utf16(&self) -> Vec<u16> {
        self.data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect()
    }

    /// `REG_SZ`, `REG_EXPAND_SZ` or `REG_LINK` data as a string, cut at the first NUL. `None` for
    /// other types. Expansion is not performed (see `env`).
    pub fn as_string(&self) -> Option<String> {
        matches!(self.ty, REG_SZ | REG_EXPAND_SZ | REG_LINK).then(|| from_wide(&self.utf16()))
    }

    /// `REG_MULTI_SZ` segments, in order, without the empty terminator segment. Empty segments in
    /// the middle are kept (they are real data a segment index refers to).
    pub fn as_multi_sz(&self) -> Option<Vec<String>> {
        if self.ty != REG_MULTI_SZ {
            return None;
        }
        let mut units = self.utf16();
        // Strip the terminator(s): "a\0b\0\0" -> "a\0b".
        while units.last() == Some(&0) {
            units.pop();
        }
        if units.is_empty() {
            return Some(Vec::new());
        }
        Some(
            units
                .split(|&c| c == 0)
                .map(String::from_utf16_lossy)
                .collect(),
        )
    }

    /// `REG_DWORD` / `REG_DWORD_BIG_ENDIAN` data. `None` for other types or short data.
    pub fn as_u32(&self) -> Option<u32> {
        let b: [u8; 4] = self.data.get(..4)?.try_into().ok()?;
        match self.ty {
            REG_DWORD => Some(u32::from_le_bytes(b)),
            REG_DWORD_BIG_ENDIAN => Some(u32::from_be_bytes(b)),
            _ => None,
        }
    }

    /// `REG_QWORD` data (or a `REG_DWORD` widened). `None` for other types or short data.
    pub fn as_u64(&self) -> Option<u64> {
        match self.ty {
            REG_QWORD => Some(u64::from_le_bytes(self.data.get(..8)?.try_into().ok()?)),
            REG_DWORD | REG_DWORD_BIG_ENDIAN => self.as_u32().map(u64::from),
            _ => None,
        }
    }
}

/// Owner and TrustedInstaller facts of a key's security descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySecurity {
    /// Owner SID in string form (`S-1-5-...`), if the descriptor has an owner.
    pub owner_sid: Option<String>,
    /// Whether any DACL entry names `NT SERVICE\TrustedInstaller`.
    pub dacl_names_trusted_installer: bool,
}

impl KeySecurity {
    /// Whether the owner is `NT SERVICE\TrustedInstaller`.
    pub fn owner_is_trusted_installer(&self) -> bool {
        self.owner_sid.as_deref() == Some(TRUSTED_INSTALLER_SID)
    }

    /// Owner or any ACE is TrustedInstaller: the "TI-owned" flag of the subtree baseline.
    pub fn trusted_installer(&self) -> bool {
        self.owner_is_trusted_installer() || self.dacl_names_trusted_installer
    }
}

/// An open registry key (read access, explicit view, opened with `REG_OPTION_OPEN_LINK`).
///
/// Closed on drop. Predefined roots from [`Key::root`] are not closed.
#[derive(Debug)]
pub struct Key {
    hkey: HKEY,
    owned: bool,
    view: RegView,
    /// Set once this key is proven not to be a symbolic link for as long as the handle lives (see
    /// [`Key::link_target_with_info`]); opens below it then skip the link check. Never reset.
    not_link: AtomicBool,
}

// SAFETY: a registry key handle is a kernel handle, not tied to the thread that opened it; the
// registry API is safe to call concurrently on one handle.
unsafe impl Send for Key {}
// SAFETY: every method takes `&self` and only issues read calls, which the registry serialises;
// the only interior state is an `AtomicBool`, which is itself `Sync`.
unsafe impl Sync for Key {}

impl Drop for Key {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: `hkey` was returned by `RegOpenKeyExW`, is owned by this value and is closed
            // exactly once here.
            unsafe { RegCloseKey(self.hkey) };
        }
    }
}

impl Key {
    fn new(hkey: HKEY, owned: bool, view: RegView) -> Key {
        Key {
            hkey,
            owned,
            view,
            not_link: AtomicBool::new(false),
        }
    }

    /// The predefined root handle in `view` (not opened, never closed).
    pub fn root(root: RegRoot, view: RegView) -> Key {
        Key::new(root.hkey(), false, view)
    }

    /// Opens `path` (backslash-separated, relative to `root`) in `view`, one component at a time
    /// with `REG_OPTION_OPEN_LINK`. An empty path returns the root.
    ///
    /// A link as the last component is opened as the link key itself (see [`Key::link_target`]).
    /// A link before the last component fails the open with [`Win32Error::LINK_ON_PATH`]: the
    /// kernel would otherwise reparse relative opens below a link key into its target. Every
    /// intermediate key must therefore allow `KEY_QUERY_VALUE` so it can be checked.
    pub fn open(root: RegRoot, path: &str, view: RegView) -> Result<Key, Win32Error> {
        Key::root(root, view).open_subkey(path)
    }

    /// Opens `path` below this key in this key's view (component-wise, see [`Key::open`]). Fails
    /// with [`Win32Error::LINK_ON_PATH`] when this key, or any intermediate key, is a link.
    pub fn open_subkey(&self, path: &str) -> Result<Key, Win32Error> {
        let mut comps = path.split('\\').filter(|c| !c.is_empty()).peekable();
        if comps.peek().is_none() {
            return self.reopen();
        }
        let mut current: Option<Key> = None;
        while let Some(comp) = comps.next() {
            let parent = current.as_ref().unwrap_or(self);
            current = Some(parent.open_component(comp, comps.peek().is_none())?);
        }
        current.ok_or(Win32Error::INVALID_PARAMETER)
    }

    /// One step of [`Key::open_subkey`]: refuses to descend when this key is a link
    /// ([`Win32Error::LINK_ON_PATH`]), then opens the direct subkey `name` with `REG_OPTION_OPEN_LINK`
    /// in this key's view, for reading when it is the `last` component of a path and for
    /// `KEY_QUERY_VALUE` (enough to descend further) otherwise.
    ///
    /// A caller that keeps the keys of a path open and opens further paths below them step by step
    /// (`purge-source`'s registry walker) opens exactly what [`Key::open`] of the whole path opens:
    /// whether this key is a link is asked on every call, unless [`Key::link_target_with_info`]
    /// proved through this handle that it is none and stays none.
    pub fn open_component(&self, name: &str, last: bool) -> Result<Key, Win32Error> {
        self.ensure_not_link()?;
        let access = if last { KEY_READ } else { KEY_QUERY_VALUE };
        self.open_one(name, access)
    }

    /// Refuses to descend below a link key (predefined roots are never links).
    fn ensure_not_link(&self) -> Result<(), Win32Error> {
        if !self.owned || self.not_link.load(Ordering::Relaxed) {
            return Ok(());
        }
        if self.is_link()? {
            Err(Win32Error::LINK_ON_PATH)
        } else {
            Ok(())
        }
    }

    /// A new owned handle to the same key (or the root itself for a predefined key).
    fn reopen(&self) -> Result<Key, Win32Error> {
        if !self.owned {
            return Ok(Key::new(self.hkey, false, self.view));
        }
        let empty = wide("");
        let mut out: HKEY = ptr::null_mut();
        // SAFETY: `self.hkey` is a live key handle, `empty` is NUL-terminated and outlives the call,
        // `out` is a valid out-pointer. An empty subkey on a non-predefined key opens a new handle.
        let rc = unsafe {
            RegOpenKeyExW(
                self.hkey,
                empty.as_ptr(),
                REG_OPTION_OPEN_LINK,
                KEY_READ | self.view.sam(),
                &mut out,
            )
        };
        Win32Error::check(rc)?;
        Ok(Key::new(out, true, self.view))
    }

    /// Opens a single path component.
    fn open_one(&self, name: &str, access: u32) -> Result<Key, Win32Error> {
        let name_w = wide(name);
        let mut out: HKEY = ptr::null_mut();
        // SAFETY: `self.hkey` is live for the borrow, `name_w` is NUL-terminated and outlives the
        // call, `out` is a valid out-pointer written only on success.
        let rc = unsafe {
            RegOpenKeyExW(
                self.hkey,
                name_w.as_ptr(),
                REG_OPTION_OPEN_LINK,
                access | self.view.sam(),
                &mut out,
            )
        };
        Win32Error::check(rc)?;
        Ok(Key::new(out, true, self.view))
    }

    /// The view this key was opened in.
    pub fn view(&self) -> RegView {
        self.view
    }

    /// Counts, maximum sizes and last write time (`RegQueryInfoKeyW`).
    pub fn info(&self) -> Result<KeyInfo, Win32Error> {
        let (mut n_sub, mut max_sub, mut n_val, mut max_vname, mut max_vlen) =
            (0u32, 0u32, 0u32, 0u32, 0u32);
        let mut ft = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        // SAFETY: every non-null pointer refers to a local that outlives the call; the class buffer,
        // reserved, max class length and security descriptor size are null (not requested).
        let rc = unsafe {
            RegQueryInfoKeyW(
                self.hkey,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
                &mut n_sub,
                &mut max_sub,
                ptr::null_mut(),
                &mut n_val,
                &mut max_vname,
                &mut max_vlen,
                ptr::null_mut(),
                &mut ft,
            )
        };
        Win32Error::check(rc)?;
        Ok(KeyInfo {
            n_subkeys: n_sub,
            max_subkey_name_len: max_sub,
            n_values: n_val,
            max_value_name_len: max_vname,
            max_value_len: max_vlen,
            last_write_time: filetime_u64(ft),
        })
    }

    /// Direct subkeys with their last write times (`RegEnumKeyExW`), in registry order.
    pub fn subkeys(&self) -> Result<Vec<SubkeyEntry>, Win32Error> {
        let info = self.info()?;
        self.subkeys_with_capacity(info.max_subkey_name_len as usize + 1, info.n_subkeys)
    }

    /// Direct subkey names.
    pub fn subkey_names(&self) -> Result<Vec<String>, Win32Error> {
        Ok(self.subkeys()?.into_iter().map(|e| e.name).collect())
    }

    /// [`Key::subkey_names`] for a caller that already holds this key's [`Key::info`]: `info` gives the
    /// size of the name buffer (which grows if a longer name turns up) and the room to reserve for
    /// the list, nothing else, so the names are the same. The enumeration always runs until the
    /// registry reports the end of the list. The count in `info` must not end it: subkeys are
    /// enumerated sorted by name, so a subkey created after `info` was taken moves every later one up
    /// by an index, and a read that stopped at the count would lose the last subkey that was there
    /// all along, with everything below it. (Values are enumerated in the order they were added,
    /// which is why [`Key::values_counted`] may stop at its count.)
    pub fn subkey_names_after(&self, info: &KeyInfo) -> Result<Vec<String>, Win32Error> {
        Ok(self
            .subkeys_with_capacity(info.max_subkey_name_len as usize + 1, info.n_subkeys)?
            .into_iter()
            .map(|e| e.name)
            .collect())
    }

    /// Enumeration with an explicit starting name buffer (in UTF-16 units), which grows on
    /// `ERROR_MORE_DATA`. `expected` only reserves room for the result; the enumeration ends when the
    /// registry says there are no more subkeys.
    fn subkeys_with_capacity(
        &self,
        name_cap: usize,
        expected: u32,
    ) -> Result<Vec<SubkeyEntry>, Win32Error> {
        let mut name = vec![0u16; name_cap.max(1)];
        let mut out = Vec::with_capacity(expected.min(1024) as usize);
        let mut index = 0u32;
        loop {
            let mut len = name.len() as u32;
            let mut ft = FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            };
            // SAFETY: `name` has `len` writable units; class/reserved are null; `ft` and `len` are
            // valid locals.
            let rc = unsafe {
                RegEnumKeyExW(
                    self.hkey,
                    index,
                    name.as_mut_ptr(),
                    &mut len,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut ft,
                )
            };
            match Win32Error::check(rc) {
                Ok(()) => {
                    out.push(SubkeyEntry {
                        name: String::from_utf16_lossy(&name[..len as usize]),
                        last_write_time: filetime_u64(ft),
                    });
                    index += 1;
                }
                Err(Win32Error::NO_MORE_ITEMS) => return Ok(out),
                Err(Win32Error::MORE_DATA) => {
                    if name.len() >= MAX_NAME_UNITS {
                        return Err(Win32Error::MORE_DATA);
                    }
                    name.resize((name.len() * 2).min(MAX_NAME_UNITS), 0);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// All values with their stored type and exactly their stored bytes (`NtEnumerateValueKey`), in
    /// registry order. The default value has the empty name. Names are converted lossily, as the Win32
    /// enumeration reported them.
    pub fn values(&self) -> Result<Vec<RegValue>, Win32Error> {
        self.values_limited(None)
    }

    /// [`Key::values`] for a caller that holds `info`, this key's [`Key::info`]: reads the
    /// `info.n_values` values `info` counted and stops there, one call per value, without the last
    /// call that only reports the end of the list. On a key nobody changes between [`Key::info`] and
    /// this call the values are the same; a value added in between is not read (it was not there
    /// when the key was counted), and a list that got shorter ends where it ends. Stopping at the
    /// count loses no value that was counted, because a key's values are enumerated in the order
    /// they were added: a new value goes to the end of the list and moves no other. Subkeys are
    /// enumerated sorted by name, so they are never read up to a count ([`Key::subkey_names_after`]).
    pub fn values_counted(&self, info: &KeyInfo) -> Result<Vec<RegValue>, Win32Error> {
        self.values_limited(Some(info.n_values))
    }

    /// The values in registry order, at most `limit` of them when one is given.
    fn values_limited(&self, limit: Option<u32>) -> Result<Vec<RegValue>, Win32Error> {
        if !self.owned {
            // A predefined root is a pseudo-handle, which only the Win32 calls accept.
            let info = self.info()?;
            return self.values_with_capacity(
                info.max_value_name_len as usize + 1,
                info.max_value_len as usize,
            );
        }
        let mut out = Vec::with_capacity(limit.map_or(0, |n| n.min(1024) as usize));
        // One 8-byte aligned buffer for every value of the key. Each value is first asked for with
        // the small length `nt_query` starts with (the kernel's work grows with the length it is
        // offered), and only a value that needs more is asked for again with a longer one.
        let mut buf = vec![0u64; NT_FIRST_WORDS];
        for index in 0u32.. {
            if limit.is_some_and(|n| index >= n) {
                break;
            }
            let mut offered = NT_FIRST_WORDS;
            let filled = loop {
                let mut needed = 0u32;
                // SAFETY: `buf` has at least `offered` writable 8-byte words, `needed` is a valid
                // out-pointer, and `hkey` is a live handle for the borrow.
                let status = unsafe {
                    NtEnumerateValueKey(
                        self.hkey,
                        index,
                        KEY_VALUE_FULL_INFORMATION_CLASS,
                        buf.as_mut_ptr().cast(),
                        (offered * 8) as u32,
                        &mut needed,
                    )
                };
                if status >= 0 {
                    break Ok(());
                }
                let too_small =
                    status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL;
                if !too_small || offered * 8 >= MAX_QUERY_BYTES {
                    break Err(status);
                }
                // As `nt_query` grows: to what the call asks for, and at least to twice the bytes
                // offered (`offered` counts 8-byte words, so twice the bytes are `offered * 16`).
                let want = (needed as usize).max(offered * 16).min(MAX_QUERY_BYTES);
                offered = want.div_ceil(8);
                if buf.len() < offered {
                    buf.resize(offered, 0);
                }
            };
            match filled {
                Ok(()) => {}
                Err(STATUS_NO_MORE_ENTRIES) => break,
                Err(status) => return Err(nt_error(status)),
            }
            // SAFETY: `buf` holds at least `offered` initialised `u64` words; any bit pattern is a
            // valid `u8`, the byte view covers exactly those words and is not used after `buf` is
            // next written.
            let bytes: &[u8] =
                unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), offered * 8) };
            let ty = u32_at(bytes, 4)?;
            // The data offset of an empty value need not lie inside the buffer.
            let data = match u32_at(bytes, 12)? {
                0 => &[][..],
                len => bytes_at(bytes, u32_at(bytes, 8)?, len)?,
            };
            let name: Vec<u16> = bytes_at(bytes, 20, u32_at(bytes, 16)?)?
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            out.push(RegValue {
                name: String::from_utf16_lossy(&name),
                ty,
                data: data.to_vec(),
            });
        }
        Ok(out)
    }

    /// Win32 enumeration (`RegEnumValueW`) with explicit starting buffers; both grow on
    /// `ERROR_MORE_DATA`. May zero the last byte of odd-length string data (see the module docs); used
    /// only for the predefined
    /// roots.
    fn values_with_capacity(
        &self,
        name_cap: usize,
        data_cap: usize,
    ) -> Result<Vec<RegValue>, Win32Error> {
        let mut name = vec![0u16; name_cap.max(1)];
        let mut data = vec![0u8; data_cap.max(1)];
        let mut out = Vec::new();
        let mut index = 0u32;
        loop {
            let mut name_len = name.len() as u32;
            let mut data_len = data.len() as u32;
            let mut ty = 0u32;
            // SAFETY: `name` has `name_len` writable units and `data` has `data_len` writable bytes;
            // `ty`, `name_len` and `data_len` are valid locals; reserved is null.
            let rc = unsafe {
                RegEnumValueW(
                    self.hkey,
                    index,
                    name.as_mut_ptr(),
                    &mut name_len,
                    ptr::null(),
                    &mut ty,
                    data.as_mut_ptr(),
                    &mut data_len,
                )
            };
            match Win32Error::check(rc) {
                Ok(()) => {
                    out.push(RegValue {
                        name: String::from_utf16_lossy(&name[..name_len as usize]),
                        ty,
                        data: data[..data_len as usize].to_vec(),
                    });
                    index += 1;
                }
                Err(Win32Error::NO_MORE_ITEMS) => return Ok(out),
                Err(Win32Error::MORE_DATA) => {
                    // Either buffer may be the short one; `data_len` holds the required size when the
                    // data was too small. Grow both and retry the same index.
                    if name.len() >= MAX_NAME_UNITS && data.len() >= MAX_DATA_BYTES {
                        return Err(Win32Error::MORE_DATA);
                    }
                    name.resize((name.len() * 2).min(MAX_NAME_UNITS), 0);
                    let want = (data_len as usize).max(data.len() * 2);
                    data.resize(want.min(MAX_DATA_BYTES), 0);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// One value by name (`""` for the default value) with its stored type and exactly its stored bytes
    /// (`NtQueryValueKey`); `Ok(None)` when it does not exist. As with the Win32 call, the name ends at
    /// its first NUL.
    pub fn value(&self, name: &str) -> Result<Option<RegValue>, Win32Error> {
        if !self.owned {
            // A predefined root is a pseudo-handle, which only the Win32 calls accept.
            return self.value_with_capacity(name, 256);
        }
        let mut units: Vec<u16> = name.encode_utf16().collect();
        if let Some(nul) = units.iter().position(|&u| u == 0) {
            units.truncate(nul);
        }
        let byte_len = u16::try_from(units.len() * 2).map_err(|_| Win32Error::INVALID_PARAMETER)?;
        let uname = UNICODE_STRING {
            Length: byte_len,
            MaximumLength: byte_len,
            Buffer: units.as_mut_ptr(),
        };
        // SAFETY: `uname` points into `units`, which outlives the call and is only read; the closure
        // passes on a writable buffer of the stated byte length and a valid out-pointer; `hkey` is a
        // live handle for the borrow.
        let buf = match nt_query(|buf, len, needed| unsafe {
            NtQueryValueKey(
                self.hkey,
                &uname,
                KEY_VALUE_PARTIAL_INFORMATION_CLASS,
                buf,
                len,
                needed,
            )
        }) {
            Ok(buf) => buf,
            Err(STATUS_OBJECT_NAME_NOT_FOUND) => return Ok(None),
            Err(status) => return Err(nt_error(status)),
        };
        let ty = u32_at(&buf, 4)?;
        let data = bytes_at(&buf, 12, u32_at(&buf, 8)?)?.to_vec();
        Ok(Some(RegValue {
            name: name.to_owned(),
            ty,
            data,
        }))
    }

    /// Win32 query (`RegQueryValueExW`) with an explicit starting buffer; grows on `ERROR_MORE_DATA`.
    /// May zero the last byte of odd-length string data (see the module docs); used only for the
    /// predefined roots.
    fn value_with_capacity(
        &self,
        name: &str,
        data_cap: usize,
    ) -> Result<Option<RegValue>, Win32Error> {
        let name_w = wide(name);
        let mut data = vec![0u8; data_cap.max(1)];
        loop {
            let mut ty = 0u32;
            let mut len = data.len() as u32;
            // SAFETY: `name_w` is NUL-terminated, `data` has `len` writable bytes, `ty` and `len` are
            // valid locals; reserved is null.
            let rc = unsafe {
                RegQueryValueExW(
                    self.hkey,
                    name_w.as_ptr(),
                    ptr::null(),
                    &mut ty,
                    data.as_mut_ptr(),
                    &mut len,
                )
            };
            match Win32Error::check(rc) {
                Ok(()) => {
                    data.truncate(len as usize);
                    return Ok(Some(RegValue {
                        name: name.to_owned(),
                        ty,
                        data,
                    }));
                }
                Err(e) if e.is_not_found() => return Ok(None),
                Err(Win32Error::MORE_DATA) => {
                    if data.len() >= MAX_DATA_BYTES {
                        return Err(Win32Error::MORE_DATA);
                    }
                    let want = (len as usize).max(data.len() * 2);
                    data.resize(want.min(MAX_DATA_BYTES), 0);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// The target of a registry symbolic link, if this key is one: the `REG_LINK` data of its
    /// `SymbolicLinkValue` (an NT path such as `\REGISTRY\USER\S-1-5-21-..._Classes`). The link is
    /// never followed. The answer is not remembered: a later open below this handle asks again.
    pub fn link_target(&self) -> Result<Option<String>, Win32Error> {
        Ok(self
            .value(SYMBOLIC_LINK_VALUE)?
            .filter(|v| v.ty == REG_LINK)
            .and_then(|v| v.as_string()))
    }

    /// [`Key::link_target`] for a caller that holds `info`, this key's [`Key::info`] read through this
    /// handle: a key without values has no `SymbolicLinkValue`, so it is not asked.
    ///
    /// When the key has subkeys of its own and no link target, the answer "no link" is remembered on
    /// this handle and later opens below it ([`Key::open_component`]) skip the check. That answer
    /// cannot go stale: a link key never holds subkeys (opens and creates below it resolve in its
    /// target), and a key made without `REG_OPTION_CREATE_LINK` never becomes a link. A key without
    /// subkeys proves nothing (a link key exists without its target for a moment each time a link is
    /// made), so nothing is remembered for it.
    ///
    /// One case the remembered answer reads differently from a fresh [`Key::open`]: an ordinary key
    /// that gets a `REG_LINK` `SymbolicLinkValue` after this call. The kernel does not treat it as a
    /// link and opens below this handle read its real subkeys; a fresh open refuses them as below a
    /// link.
    pub fn link_target_with_info(&self, info: &KeyInfo) -> Result<Option<String>, Win32Error> {
        let target = if info.n_values == 0 {
            Ok(None)
        } else {
            self.link_target()
        };
        if self.owned && info.n_subkeys > 0 && matches!(target, Ok(None)) {
            self.not_link.store(true, Ordering::Relaxed);
        }
        target
    }

    /// [`Key::link_target_with_info`] for a caller that has also read this key's values through this
    /// handle (`values`: [`Key::values`] or [`Key::values_counted`]): the same answer, and the same
    /// "no link" remembered on the handle, without asking for `SymbolicLinkValue` by name when the
    /// values already show what the lookup finds.
    ///
    /// The lookup by name is case-insensitive in the kernel's own upper-casing. Among values whose
    /// names are all ASCII, it finds exactly the one that equals `SymbolicLinkValue` ignoring ASCII
    /// case, so that value (or its absence) is the answer. When no such value is there and some
    /// name is not ASCII, the kernel's folding could still match one of them: the key is then asked
    /// by name, as [`Key::link_target_with_info`] asks.
    pub fn link_target_with_values(
        &self,
        info: &KeyInfo,
        values: &[RegValue],
    ) -> Result<Option<String>, Win32Error> {
        let named = values
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case(SYMBOLIC_LINK_VALUE));
        let target = match named {
            Some(v) => Ok(Some(v)
                .filter(|v| v.ty == REG_LINK)
                .and_then(|v| v.as_string())),
            None if values.iter().all(|v| v.name.is_ascii()) => Ok(None),
            None => self.link_target(),
        };
        if self.owned && info.n_subkeys > 0 && matches!(target, Ok(None)) {
            self.not_link.store(true, Ordering::Relaxed);
        }
        target
    }

    /// Whether this key is a registry symbolic link.
    pub fn is_link(&self) -> Result<bool, Win32Error> {
        Ok(self.link_target()?.is_some())
    }

    /// Owner SID and TrustedInstaller DACL flag (`RegGetKeySecurity`).
    pub fn security(&self) -> Result<KeySecurity, Win32Error> {
        let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        // u64 storage keeps the self-relative descriptor suitably aligned for the parsers.
        let mut buf = vec![0u64; 64];
        loop {
            let mut len = (buf.len() * 8) as u32;
            // SAFETY: `buf` has `len` writable bytes and `len` is a valid local.
            let rc =
                unsafe { RegGetKeySecurity(self.hkey, info, buf.as_mut_ptr().cast(), &mut len) };
            match Win32Error::check(rc) {
                Ok(()) => break,
                Err(Win32Error::INSUFFICIENT_BUFFER) => {
                    buf.resize((len as usize).div_ceil(8).max(buf.len() * 2), 0)
                }
                Err(e) => return Err(e),
            }
        }
        // SAFETY: `buf` now holds a valid self-relative security descriptor written by the call
        // above, and stays alive (unmoved) for the duration of the parse.
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
}

/// Upper bound for name buffers (registry names are at most 16,383 units).
const MAX_NAME_UNITS: usize = 16_384;
/// Upper bound for value data reads (well above any value the engine needs; guards runaway growth).
const MAX_DATA_BYTES: usize = 64 * 1024 * 1024;

/// FILETIME as a single u64 tick count.
pub(crate) fn filetime_u64(ft: FILETIME) -> u64 {
    (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)
}

/// `ControlSet00N`, the set `HKLM\SYSTEM\CurrentControlSet` links to, from `HKLM\SYSTEM\Select\Current`.
pub fn current_control_set() -> Result<String, Win32Error> {
    let key = Key::open(RegRoot::Hklm, r"SYSTEM\Select", RegView::K64)?;
    let n = key
        .value("Current")?
        .and_then(|v| v.as_u32())
        .ok_or(Win32Error::FILE_NOT_FOUND)?;
    Ok(format!("ControlSet{n:03}"))
}

/// SIDs of the user hives loaded under `HKU` (`S-1-...` names, without `<SID>_Classes` and `.DEFAULT`).
/// Includes service accounts (`S-1-5-18/19/20`) when loaded.
pub fn loaded_user_sids() -> Result<Vec<String>, Win32Error> {
    let names = Key::root(RegRoot::Hku, RegView::K64).subkey_names()?;
    Ok(names
        .into_iter()
        .filter(|n| {
            n.len() > 2
                && n[..2].eq_ignore_ascii_case("S-")
                && !ends_with_ignore_case(n, "_Classes")
        })
        .collect())
}

fn ends_with_ignore_case(s: &str, suffix: &str) -> bool {
    s.len() >= suffix.len()
        && s.is_char_boundary(s.len() - suffix.len())
        && s[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::process::Command;

    const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    /// Subkey names of an HKLM key per `reg query`, the second enumeration method.
    fn reg_query_subkeys(path: &str, view_flag: &str) -> BTreeSet<String> {
        let full = format!(r"HKLM\{path}");
        let out = Command::new("reg")
            .args(["query", &full, view_flag])
            .output()
            .expect("run reg.exe");
        assert!(out.status.success(), "reg query failed");
        let text = String::from_utf8_lossy(&out.stdout);
        let prefix = format!(r"HKEY_LOCAL_MACHINE\{path}\").to_lowercase();
        text.lines()
            .map(str::trim_end)
            .filter(|l| l.to_lowercase().starts_with(&prefix))
            .map(|l| l[prefix.len()..].to_string())
            .collect()
    }

    #[test]
    fn uninstall_parity_with_reg_query_both_views() {
        for (view, flag) in [(RegView::K64, "/reg:64"), (RegView::K32, "/reg:32")] {
            let ours: BTreeSet<String> = Key::open(RegRoot::Hklm, UNINSTALL, view)
                .unwrap()
                .subkey_names()
                .unwrap()
                .into_iter()
                .collect();
            let theirs = reg_query_subkeys(UNINSTALL, flag);
            // reg.exe prints names through a best-fit OEM conversion (e.g. a registered-trademark
            // sign becomes `r`), so non-ASCII names cannot be compared verbatim: every ASCII name of
            // ours must appear in its output, and the leftovers must pair up one to one.
            assert_eq!(ours.len(), theirs.len(), "{view:?} count");
            let ours_ascii: BTreeSet<String> =
                ours.iter().filter(|n| n.is_ascii()).cloned().collect();
            let missing: Vec<&String> = ours_ascii.difference(&theirs).collect();
            assert!(
                missing.is_empty(),
                "{view:?} names missing from reg query: {missing:?}"
            );
            assert_eq!(
                theirs.difference(&ours_ascii).count(),
                ours.len() - ours_ascii.len(),
                "{view:?}"
            );
        }
    }

    #[test]
    fn views_differ_and_wow6432node_is_plain_subkey_in_64() {
        let k64 = Key::open(RegRoot::Hklm, "SOFTWARE", RegView::K64)
            .unwrap()
            .subkey_names()
            .unwrap();
        assert!(k64.iter().any(|n| n.eq_ignore_ascii_case("WOW6432Node")));
        let via_node = Key::open(
            RegRoot::Hklm,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            RegView::K64,
        )
        .unwrap()
        .subkey_names()
        .unwrap();
        let k32 = Key::open(RegRoot::Hklm, UNINSTALL, RegView::K32)
            .unwrap()
            .subkey_names()
            .unwrap();
        assert_eq!(via_node, k32);
    }

    #[test]
    fn value_types_multi_sz_binary_dword_default() {
        let ccs = current_control_set().unwrap();
        assert!(
            ccs.starts_with("ControlSet") && ccs.len() == "ControlSet001".len(),
            "{ccs}"
        );
        let sgo = Key::open(
            RegRoot::Hklm,
            &format!(r"SYSTEM\{ccs}\Control\ServiceGroupOrder"),
            RegView::K64,
        )
        .unwrap();
        let list = sgo.value("List").unwrap().expect("List");
        assert_eq!(list.ty, REG_MULTI_SZ);
        let segs = list.as_multi_sz().unwrap();
        assert!(
            segs.len() > 3 && segs.iter().all(|s| !s.is_empty()),
            "{segs:?}"
        );
        assert!(list.as_string().is_none());

        let cv = Key::open(
            RegRoot::Hklm,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            RegView::K64,
        )
        .unwrap();
        let all = cv.values().unwrap();
        assert!(
            all.iter().any(|v| v.ty == REG_BINARY && !v.data.is_empty()),
            "no REG_BINARY under CurrentVersion"
        );
        let dw = all.iter().find(|v| v.ty == REG_DWORD).expect("a DWORD");
        assert_eq!(dw.data.len(), 4);
        assert!(dw.as_u32().is_some() && dw.as_u64().is_some());
        // Enumerated and queried data agree.
        for v in all.iter().take(20) {
            assert_eq!(cv.value(&v.name).unwrap().as_ref(), Some(v));
        }

        let txt = Key::open(RegRoot::Hklm, r"SOFTWARE\Classes\.txt", RegView::K64).unwrap();
        let def = txt.value("").unwrap().expect("default value of .txt");
        assert_eq!(def.ty, REG_SZ);
        assert!(!def.as_string().unwrap().is_empty());
        assert!(
            txt.values().unwrap().iter().any(|v| v.name.is_empty()),
            "default value enumerated with empty name"
        );
        assert_eq!(txt.value("NoSuchValue-purge-test").unwrap(), None);
    }

    #[test]
    fn long_value_retry_with_tiny_buffers() {
        let cv = Key::open(
            RegRoot::Hklm,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            RegView::K64,
        )
        .unwrap();
        let normal = cv.values().unwrap();
        assert_eq!(cv.values_with_capacity(1, 1).unwrap(), normal);
        let longest = normal.iter().max_by_key(|v| v.data.len()).unwrap();
        assert!(longest.data.len() > 1);
        assert_eq!(
            cv.value_with_capacity(&longest.name, 1).unwrap().as_ref(),
            Some(longest)
        );

        let un = Key::open(RegRoot::Hklm, UNINSTALL, RegView::K64).unwrap();
        assert_eq!(
            un.subkeys_with_capacity(1, 0).unwrap(),
            un.subkeys().unwrap()
        );
    }

    /// Whether a value is string-typed with an odd byte length: the only data the Win32 reads report
    /// differently from what is stored.
    fn odd_string(v: &RegValue) -> bool {
        matches!(v.ty, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ) && v.data.len() % 2 == 1
    }

    /// Why [`compare_reads`] did not confirm a key.
    #[derive(Debug)]
    enum ReadDiff {
        /// The key was deleted while it was read.
        Gone,
        /// The reads differ (or the key changed between them).
        Differs(String),
    }

    /// `ERROR_KEY_DELETED`: a read through the handle of a key deleted meanwhile.
    const KEY_DELETED: Win32Error = Win32Error(1018);

    fn os(what: &str) -> impl Fn(Win32Error) -> ReadDiff + '_ {
        move |e| {
            if e == KEY_DELETED {
                ReadDiff::Gone
            } else {
                panic!("{what}: {e}")
            }
        }
    }

    /// Reads the values of `k` through the NT calls and through the Win32 calls (with the buffers the
    /// reader passed before the NT reads) and compares them: equal for well-formed data; a value of
    /// odd-length string data differs at most in its last byte, which the Win32 read zeroed. Returns the
    /// number of values compared and of odd-length strings among them.
    fn compare_reads(k: &Key) -> Result<(usize, usize), ReadDiff> {
        let nt = k.values().map_err(os("NT enumeration"))?;
        let info = k.info().map_err(os("info"))?;
        let win32 = k
            .values_with_capacity(
                info.max_value_name_len as usize + 1,
                info.max_value_len as usize,
            )
            .map_err(os("Win32 enumeration"))?;
        if nt.len() != win32.len() {
            return Err(ReadDiff::Differs(format!(
                "{} values by NT, {} by Win32",
                nt.len(),
                win32.len()
            )));
        }
        let mut odd = 0;
        for (n, w) in nt.iter().zip(&win32) {
            let differs = |what: &str| Err(ReadDiff::Differs(format!("{:?}: {what}", n.name)));
            let Some(q) = k
                .value_with_capacity(&n.name, 256)
                .map_err(os("Win32 query"))?
            else {
                return differs("gone for the Win32 query");
            };
            if k.value(&n.name).map_err(os("NT query"))?.as_ref() != Some(n) {
                return differs("NT query differs from NT enumeration");
            }
            for old in [w, &q] {
                if (&n.name, n.ty, n.data.len()) != (&old.name, old.ty, old.data.len()) {
                    return differs("name, type or length differ");
                }
                let same = if odd_string(n) {
                    let last = n.data.len() - 1;
                    n.data[..last] == old.data[..last]
                        && (old.data[last] == 0 || old.data[last] == n.data[last])
                } else {
                    n == old
                };
                if !same {
                    return differs("data differ");
                }
            }
            if odd_string(n) {
                odd += 1;
            }
        }
        Ok((nt.len(), odd))
    }

    /// The NT reads report what the Win32 reads reported for every well-formed value (the scan output
    /// for such data cannot change): exactly, on the first read, under a scratch key the test writes;
    /// and over the uninstall keys of both views and the keys below them, `CurrentVersion` and the
    /// current user's `Software` subkeys. Those are live keys other processes write: a key whose reads
    /// differ is read again (up to five times), since a difference of the reads themselves repeats on
    /// unchanging data while a concurrent write does not; a key deleted meanwhile is skipped.
    #[test]
    fn nt_reads_equal_win32_reads_for_well_formed_data() {
        let scratch = Scratch::new();
        let k = scratch.create("Values");
        let utf16z = |s: &str| -> Vec<u8> {
            s.encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect()
        };
        let big: Vec<u8> = (0..100_000u32).map(|i| (i * 7) as u8).collect();
        let cases: Vec<(&str, u32, Vec<u8>)> = vec![
            ("", REG_SZ, utf16z("default")),
            ("sz", REG_SZ, utf16z(r"C:\Program Files\Purge test\a.exe")),
            ("sz-empty", REG_SZ, Vec::new()),
            ("expand", REG_EXPAND_SZ, utf16z(r"%ProgramFiles%\x")),
            ("multi", REG_MULTI_SZ, utf16z("a\0\0bc\0")),
            ("binary", REG_BINARY, vec![1, 2, 3]),
            ("binary-big", REG_BINARY, big),
            ("dword", REG_DWORD, 7u32.to_le_bytes().to_vec()),
            ("dword-be", REG_DWORD_BIG_ENDIAN, vec![0, 0, 1, 2]),
            ("qword", REG_QWORD, 9u64.to_le_bytes().to_vec()),
            ("none", REG_NONE, vec![9; 5]),
            ("n\u{e4}me \u{263a}", REG_SZ, utf16z("non-ASCII name")),
        ];
        for (name, ty, data) in &cases {
            k.set(name, *ty, data);
        }
        let ro = Key::open(RegRoot::Hku, &scratch.path("Values"), RegView::K64).unwrap();
        assert_eq!(compare_reads(&ro).unwrap(), (cases.len(), 0));

        let sid = crate::sid::current_user_sid().unwrap();
        let mut keys: Vec<Key> = Vec::new();
        for view in [RegView::K64, RegView::K32] {
            let un = Key::open(RegRoot::Hklm, UNINSTALL, view).unwrap();
            for name in un.subkey_names().unwrap() {
                if let Ok(k) = un.open_subkey(&name) {
                    keys.push(k);
                }
            }
            keys.push(un);
        }
        keys.push(
            Key::open(
                RegRoot::Hklm,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                RegView::K64,
            )
            .unwrap(),
        );
        let software = Key::open(RegRoot::Hku, &format!(r"{sid}\Software"), RegView::K64).unwrap();
        for name in software.subkey_names().unwrap() {
            if let Ok(k) = software.open_subkey(&name) {
                keys.push(k);
            }
        }
        let (mut compared, mut odd, mut retried, mut gone) = (0usize, 0usize, 0usize, 0usize);
        for (i, k) in keys.iter().enumerate() {
            let mut tries = 0;
            loop {
                tries += 1;
                match compare_reads(k) {
                    Ok((values, odd_strings)) => {
                        compared += values;
                        odd += odd_strings;
                        break;
                    }
                    Err(ReadDiff::Gone) => {
                        gone += 1;
                        break;
                    }
                    Err(ReadDiff::Differs(why)) if tries < 5 => {
                        eprintln!("key {i}: {why}; reading it again");
                        retried += 1;
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    Err(ReadDiff::Differs(why)) => panic!("key {i}: {why} on {tries} reads"),
                }
            }
        }
        assert!(compared > 100, "only {compared} values compared");
        eprintln!(
            "compared {compared} values in {} keys, {odd} odd-length strings; {retried} reads \
             repeated, {gone} keys deleted meanwhile",
            keys.len()
        );
    }

    // The scratch trees below are written with raw calls: links included, which the `write`
    // feature's API does not make, and without that feature.
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtDeleteKey(key: HKEY) -> i32;
    }

    /// `DELETE` access.
    const DELETE_ACCESS: u32 = 0x1_0000;

    /// A key handle from `RegCreateKeyExW` with all access, closed on drop.
    struct RawKey(HKEY);

    impl Drop for RawKey {
        fn drop(&mut self) {
            // SAFETY: the handle came from `RegCreateKeyExW` and is closed once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    impl RawKey {
        /// Sets value `name` to `ty` and exactly `data`.
        fn set(&self, name: &str, ty: u32, data: &[u8]) {
            let name = wide(name);
            // SAFETY: live handle; `name` is NUL-terminated; `data` has the stated length.
            let rc = unsafe {
                windows_sys::Win32::System::Registry::RegSetValueExW(
                    self.0,
                    name.as_ptr(),
                    0,
                    ty,
                    data.as_ptr(),
                    data.len() as u32,
                )
            };
            assert_eq!(rc, 0, "set value");
        }

        /// Writes a link target: a `REG_LINK` `SymbolicLinkValue` with the NT path `target`.
        fn set_link_target(&self, target: &str) {
            let data: Vec<u8> = target.encode_utf16().flat_map(u16::to_le_bytes).collect();
            self.set(SYMBOLIC_LINK_VALUE, REG_LINK, &data);
        }
    }

    /// A fresh `HKU\<SID>\Software\PurgeTest-<random>` key written with raw calls, removed on drop
    /// (also on panic): link keys first, as links, then the tree.
    struct Scratch {
        /// `<SID>\Software\PurgeTest-…`, relative to `HKU`.
        rel: String,
        links: Vec<String>,
    }

    impl Scratch {
        fn new() -> Scratch {
            use std::sync::atomic::AtomicU32;
            use std::time::{SystemTime, UNIX_EPOCH};
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let sid = crate::sid::current_user_sid().unwrap();
            let s = Scratch {
                rel: format!(
                    r"{sid}\Software\PurgeTest-{:x}-{nanos:x}-{}",
                    std::process::id(),
                    COUNTER.fetch_add(1, Ordering::Relaxed)
                ),
                links: Vec::new(),
            };
            drop(s.raw_create("", 0));
            s
        }

        /// `sub` below the scratch root, relative to `HKU`.
        fn path(&self, sub: &str) -> String {
            if sub.is_empty() {
                self.rel.clone()
            } else {
                format!(r"{}\{sub}", self.rel)
            }
        }

        /// The NT path of `sub`, as a link target.
        fn nt_path(&self, sub: &str) -> String {
            format!(r"\REGISTRY\USER\{}", self.path(sub))
        }

        fn raw_create(&self, sub: &str, options: u32) -> RawKey {
            use windows_sys::Win32::System::Registry::{KEY_ALL_ACCESS, RegCreateKeyExW};
            let name = wide(self.path(sub));
            let mut out: HKEY = ptr::null_mut();
            // SAFETY: `name` is NUL-terminated; class, security attributes and disposition are
            // null; `out` is a valid out-pointer.
            let rc = unsafe {
                RegCreateKeyExW(
                    HKEY_USERS,
                    name.as_ptr(),
                    0,
                    ptr::null(),
                    options,
                    KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                    ptr::null(),
                    &mut out,
                    ptr::null_mut(),
                )
            };
            assert_eq!(rc, 0, "create {sub}");
            RawKey(out)
        }

        /// Creates the ordinary key `sub` (and the keys above it).
        fn create(&self, sub: &str) -> RawKey {
            self.raw_create(sub, 0)
        }

        /// Creates `sub` as a link key without its target: the first of the two steps of making a
        /// link.
        fn link(&mut self, sub: &str) -> RawKey {
            use windows_sys::Win32::System::Registry::REG_OPTION_CREATE_LINK;
            self.links.push(sub.to_owned());
            self.raw_create(sub, REG_OPTION_CREATE_LINK)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            for link in self.links.iter().rev() {
                let name = wide(self.path(link));
                let mut key: HKEY = ptr::null_mut();
                // SAFETY: `name` is NUL-terminated; `key` is a valid out-pointer.
                let rc = unsafe {
                    RegOpenKeyExW(
                        HKEY_USERS,
                        name.as_ptr(),
                        REG_OPTION_OPEN_LINK,
                        DELETE_ACCESS | KEY_WOW64_64KEY,
                        &mut key,
                    )
                };
                if rc == 0 {
                    let key = RawKey(key);
                    // SAFETY: a live handle opened with DELETE; the link key itself is deleted.
                    unsafe { NtDeleteKey(key.0) };
                }
            }
            let name = wide(&self.rel);
            // SAFETY: `name` is NUL-terminated; with a subkey name the call deletes that key too.
            let rc = unsafe {
                windows_sys::Win32::System::Registry::RegDeleteTreeW(HKEY_USERS, name.as_ptr())
            };
            if !std::thread::panicking() {
                assert_eq!(rc, 0, "scratch key removed");
            }
        }
    }

    /// `Key::link_target` remembers nothing, and "no link" is remembered on a handle only for a key
    /// with subkeys of its own: a link key read before its target was written (a link is made in two
    /// steps) is asked again before an open below it, never resolved into its target (review S1).
    #[test]
    fn link_status_is_remembered_only_for_a_key_with_subkeys_of_its_own() {
        let mut s = Scratch::new();
        s.create("T").set(SYMBOLIC_LINK_VALUE, REG_SZ, &[0x41, 0]);
        drop(s.create(r"T\Sub"));
        let plain_raw = s.create("Plain");
        drop(s.create(r"Plain\Sub"));
        let link = s.link("L");

        let l = Key::open(RegRoot::Hku, &s.path("L"), RegView::K64).unwrap();
        assert_eq!(l.link_target().unwrap(), None);
        let info = l.info().unwrap();
        assert_eq!((info.n_values, info.n_subkeys), (0, 0));
        assert_eq!(l.link_target_with_info(&info).unwrap(), None);
        link.set_link_target(&s.nt_path("T"));
        // The handle read "no link" twice; an open below it still asks and refuses.
        assert_eq!(
            l.open_component("Sub", true).unwrap_err(),
            Win32Error::LINK_ON_PATH
        );
        assert_eq!(l.open_subkey("Sub").unwrap_err(), Win32Error::LINK_ON_PATH);
        assert_eq!(l.link_target().unwrap(), Some(s.nt_path("T")));
        // A `SymbolicLinkValue` of another type makes no link.
        let t = Key::open(RegRoot::Hku, &s.path("T"), RegView::K64).unwrap();
        assert!(t.open_component("Sub", true).is_ok());

        // An ordinary key with subkeys is remembered as no link. The one case where that reads
        // differently from a fresh open (review M2): a `REG_LINK` `SymbolicLinkValue` written on it
        // afterwards. The kernel does not follow it and the handle reads the real subkey; a fresh open
        // refuses it as a path through a link.
        let plain = Key::open(RegRoot::Hku, &s.path("Plain"), RegView::K64).unwrap();
        let info = plain.info().unwrap();
        assert_eq!((info.n_values, info.n_subkeys), (0, 1));
        assert_eq!(plain.link_target_with_info(&info).unwrap(), None);
        plain_raw.set_link_target(&s.nt_path("T"));
        let sub = plain.open_component("Sub", true).unwrap();
        assert_eq!(sub.info().unwrap().n_values, 0, "the real Plain\\Sub");
        assert_eq!(
            Key::open(RegRoot::Hku, &s.path(r"Plain\Sub"), RegView::K64).unwrap_err(),
            Win32Error::LINK_ON_PATH
        );
    }

    /// The reads a walk makes with a key's counts in hand give what the plain reads give: the same
    /// values and subkey names, and from the values the same link answer as the lookup by name (a
    /// link key, a `SymbolicLinkValue` of another type, no such value, a name the lookup must judge).
    #[test]
    fn counted_reads_and_link_facts_from_values_equal_the_plain_reads() {
        let mut s = Scratch::new();
        s.create("T").set(SYMBOLIC_LINK_VALUE, REG_SZ, &[0x41, 0]);
        drop(s.create(r"T\Sub"));
        drop(s.create(r"T\Other"));
        let plain = s.create("Plain");
        plain.set("", REG_SZ, &[0x41, 0, 0, 0]);
        plain.set("Second", REG_BINARY, &[1, 2, 3]);
        plain.set("symboliclinkVALUE", REG_DWORD, &[1, 0, 0, 0]);
        drop(s.create(r"Plain\Sub"));
        drop(s.create("Empty"));
        // A name that equals `SymbolicLinkValue` only if the registry folds the dotless i to `I`.
        s.create("Odd")
            .set("Symbol\u{131}cLinkValue", REG_SZ, &[0x41, 0]);
        let link = s.link("L");
        link.set_link_target(&s.nt_path("T"));

        for name in ["T", "Plain", "Empty", "Odd", "L"] {
            let open = || Key::open(RegRoot::Hku, &s.path(name), RegView::K64).unwrap();
            let k = open();
            let info = k.info().unwrap();
            let values = k.values_counted(&info).unwrap();
            assert_eq!(values, k.values().unwrap(), "{name}");
            assert_eq!(values.len(), info.n_values as usize, "{name}");
            assert_eq!(
                k.subkey_names_after(&info).unwrap(),
                k.subkey_names().unwrap(),
                "{name}"
            );
            // Asked of a handle of its own: what one answer remembers must not shape the other.
            let by_name = open().link_target_with_info(&info).unwrap();
            assert_eq!(
                k.link_target_with_values(&info, &values).unwrap(),
                by_name,
                "{name}"
            );
            assert_eq!(by_name.is_some(), name == "L", "{name}");
            // "No link" is remembered exactly where the lookup by name remembers it.
            assert_eq!(
                k.not_link.load(Ordering::Relaxed),
                info.n_subkeys > 0 && by_name.is_none(),
                "{name}"
            );
        }

        // A value count that is too small ends the read early; one that is too large ends where the
        // list ends. The subkey count ends nothing, too small or too large.
        let k = Key::open(RegRoot::Hku, &s.path("Plain"), RegView::K64).unwrap();
        let mut info = k.info().unwrap();
        let all = k.values().unwrap();
        info.n_values = 2;
        info.n_subkeys = 0;
        assert_eq!(k.values_counted(&info).unwrap(), all[..2]);
        assert_eq!(k.subkey_names_after(&info).unwrap(), ["Sub"]);
        info.n_values = 50;
        info.n_subkeys = 50;
        assert_eq!(k.values_counted(&info).unwrap(), all);
        assert_eq!(k.subkey_names_after(&info).unwrap(), ["Sub"]);
    }

    /// A subkey created between a key's count and the read of its subkeys costs no subkey that was
    /// there before. Subkeys are enumerated sorted by name, so one that sorts first moves the others
    /// up by an index: a read that stopped at the old count would return `a`, `m` and lose `z`.
    /// A value added after the count is the other case: values keep the order they were added in,
    /// so the counted read returns exactly the values that were counted.
    #[test]
    fn a_subkey_added_after_the_count_costs_no_earlier_subkey() {
        let s = Scratch::new();
        let parent = s.create("P");
        parent.set("first", REG_SZ, &[0x41, 0]);
        parent.set("second", REG_SZ, &[0x42, 0]);
        drop(s.create(r"P\m"));
        drop(s.create(r"P\z"));
        let k = Key::open(RegRoot::Hku, &s.path("P"), RegView::K64).unwrap();
        let info = k.info().unwrap();
        assert_eq!((info.n_subkeys, info.n_values), (2, 2));
        let counted_values = k.values().unwrap();

        // After the count: a subkey that sorts before both, and a value.
        drop(s.create(r"P\a"));
        parent.set("added", REG_SZ, &[0x43, 0]);

        let names = k.subkey_names_after(&info).unwrap();
        for original in ["m", "z"] {
            assert!(
                names.iter().any(|n| n == original),
                "{original} in {names:?}"
            );
        }
        assert_eq!(names, ["a", "m", "z"]);
        assert_eq!(names, k.subkey_names().unwrap());
        assert_eq!(k.values_counted(&info).unwrap(), counted_values);
    }

    /// The predefined roots are pseudo-handles that the NT calls refuse; their values are still read
    /// through the Win32 calls.
    #[test]
    fn root_values_use_the_win32_reads() {
        for root in [RegRoot::Hklm, RegRoot::Hku] {
            let k = Key::root(root, RegView::K64);
            let all = k.values().unwrap();
            assert_eq!(all.len(), k.info().unwrap().n_values as usize);
            assert_eq!(k.value("NoSuchValue-purge-test").unwrap(), None);
        }
    }

    /// The reported bytes are exactly the stored ones for odd-length string data, which the Win32 reads
    /// get wrong. Written raw below `HKU\<SID>\Software\PurgeTest-<random>`, removed afterwards.
    #[cfg(feature = "write")]
    #[test]
    fn odd_length_strings_read_exactly_as_stored() {
        use crate::reg_write::{KeyAccess, WKey};
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        /// Removes the test key, also when an assertion fails.
        struct Cleanup {
            software: WKey,
            name: String,
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let r = self.software.delete_subkey(&self.name);
                if !std::thread::panicking() {
                    r.expect("test key removed");
                }
            }
        }

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
        let sid = crate::sid::current_user_sid().unwrap();
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
        let cleanup = Cleanup { software, name };

        let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let even_sz = utf16("ab\0");
        let even_multi = utf16("a\0bc\0\0");
        let mut odd_multi = utf16("a\0b\0\0");
        odd_multi.push(0x63);
        let cases: Vec<(&str, u32, &[u8])> = vec![
            ("sz-odd", REG_SZ, &[0x61, 0x00, 0x62]),
            ("sz-one", REG_SZ, &[0x41]),
            ("expand-odd", REG_EXPAND_SZ, &[1, 2, 3, 4, 5]),
            ("multi-odd", REG_MULTI_SZ, &odd_multi),
            ("", REG_SZ, &[0x7A, 0x00, 0x7B]),
            ("sz-even", REG_SZ, &even_sz),
            ("multi-even", REG_MULTI_SZ, &even_multi),
            ("binary-odd", REG_BINARY, &[1, 2, 3]),
        ];
        for (name, ty, data) in &cases {
            key.set_value_raw(name, *ty, data).unwrap();
        }

        let ro = Key::open(
            RegRoot::Hku,
            &format!(r"{sid}\Software\{}", cleanup.name),
            RegView::K64,
        )
        .unwrap();
        // The flaw, reproduced with the buffers the reader passed before the fix: the Win32 reads zero
        // the last byte of odd-length string data whenever the buffer has room beyond the data (an
        // exact-size buffer happens to escape it).
        let info = ro.info().unwrap();
        let win32 = ro
            .values_with_capacity(
                info.max_value_name_len as usize + 1,
                info.max_value_len as usize,
            )
            .unwrap();
        assert_eq!(win32.len(), cases.len());
        let (mut zeroed_enum, mut zeroed_query) = (Vec::new(), Vec::new());
        for (name, ty, data) in &cases {
            let w = win32.iter().find(|v| v.name == *name).expect(name);
            let q = ro.value_with_capacity(name, 256).unwrap().expect(name);
            let odd = matches!(*ty, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ) && data.len() % 2 == 1;
            for (old, zeroed) in [(w, &mut zeroed_enum), (&q, &mut zeroed_query)] {
                assert_eq!((old.ty, old.data.len()), (*ty, data.len()), "{name}");
                if old.data.as_slice() == *data {
                    continue;
                }
                // The only difference ever seen: the last byte of an odd-length string is zero.
                assert!(odd, "{name}");
                let last = data.len() - 1;
                assert_eq!(
                    (&old.data[..last], old.data[last]),
                    (&data[..last], 0),
                    "{name}"
                );
                zeroed.push(*name);
            }
        }
        // Which odd-length values are hit depends on the buffer slack (a one-byte string escapes it
        // here); these are hit with the buffers above.
        for name in ["sz-odd", "expand-odd", ""] {
            assert!(zeroed_enum.contains(&name), "{name}: {zeroed_enum:?}");
            assert!(zeroed_query.contains(&name), "{name}: {zeroed_query:?}");
        }
        eprintln!("zeroed by enumeration: {zeroed_enum:?}; by query: {zeroed_query:?}");
        // With an exact-size buffer the Win32 reads happen to return the stored bytes.
        let exact = ro.value_with_capacity("sz-odd", 1).unwrap().unwrap();
        assert_eq!(exact.data, [0x61, 0x00, 0x62]);
        // The fix: enumeration and lookup report exactly the stored type and bytes.
        let all = ro.values().unwrap();
        assert_eq!(all.len(), cases.len());
        for (name, ty, data) in &cases {
            let v = all.iter().find(|v| v.name == *name).expect(name);
            assert_eq!((v.ty, v.data.as_slice()), (*ty, *data), "{name}");
            let q = ro.value(name).unwrap().expect(name);
            assert_eq!(&q, v, "{name}");
        }
        // Lookup is case-insensitive and stops at an embedded NUL, as the Win32 call did.
        assert_eq!(
            ro.value("SZ-ODD").unwrap().unwrap().data,
            [0x61, 0x00, 0x62]
        );
        assert_eq!(
            ro.value("sz-odd\0tail").unwrap().unwrap().data,
            [0x61, 0x00, 0x62]
        );
        assert_eq!(ro.value("sz-missing").unwrap(), None);
        drop(ro);
        drop(key);
        drop(cleanup);
    }

    #[test]
    fn info_counts_match_enumeration() {
        let un = Key::open(RegRoot::Hklm, UNINSTALL, RegView::K64).unwrap();
        let info = un.info().unwrap();
        assert_eq!(info.n_subkeys as usize, un.subkeys().unwrap().len());
        assert_eq!(info.n_values as usize, un.values().unwrap().len());
        assert!(info.last_write_time > 0);
    }

    #[test]
    fn user_classes_is_reported_as_link_and_not_followed() {
        let sid = crate::sid::current_user_sid().unwrap();
        assert!(loaded_user_sids().unwrap().contains(&sid));
        let classes = Key::open(
            RegRoot::Hku,
            &format!(r"{sid}\Software\Classes"),
            RegView::K64,
        )
        .unwrap();
        let target = classes
            .link_target()
            .unwrap()
            .expect("Software\\Classes is a link");
        assert!(
            target
                .to_ascii_lowercase()
                .ends_with(&format!("{sid}_classes").to_ascii_lowercase()),
            "{target}"
        );
        assert!(classes.is_link().unwrap());
        // Not followed: the link key has no subkeys of its own, while the real hive has many.
        assert_eq!(classes.info().unwrap().n_subkeys, 0);
        let real = Key::open(RegRoot::Hku, &format!("{sid}_Classes"), RegView::K64).unwrap();
        assert!(!real.is_link().unwrap());
        // A path through the link does not resolve, neither in one open nor from the link key.
        let through = Key::open(
            RegRoot::Hku,
            &format!(r"{sid}\Software\Classes\CLSID"),
            RegView::K64,
        );
        assert_eq!(through.unwrap_err(), Win32Error::LINK_ON_PATH);
        assert_eq!(
            classes.open_subkey("CLSID").unwrap_err(),
            Win32Error::LINK_ON_PATH
        );
        assert!(real.open_subkey("CLSID").is_ok());
    }

    #[test]
    fn current_control_set_is_a_link() {
        let ccs = Key::open(RegRoot::Hklm, r"SYSTEM\CurrentControlSet", RegView::K64).unwrap();
        let target = ccs
            .link_target()
            .unwrap()
            .expect("CurrentControlSet is a link");
        assert!(
            target.ends_with(&current_control_set().unwrap()),
            "{target}"
        );
        let through = Key::open(
            RegRoot::Hklm,
            r"SYSTEM\CurrentControlSet\Control",
            RegView::K64,
        );
        assert_eq!(through.unwrap_err(), Win32Error::LINK_ON_PATH);
    }

    #[test]
    fn key_security_owner_and_trusted_installer() {
        let sec = Key::open(
            RegRoot::Hklm,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            RegView::K64,
        )
        .unwrap()
        .security()
        .unwrap();
        assert!(
            sec.owner_sid
                .as_deref()
                .is_some_and(|s| s.starts_with("S-1-")),
            "{sec:?}"
        );
        let un = Key::open(RegRoot::Hklm, UNINSTALL, RegView::K64)
            .unwrap()
            .security()
            .unwrap();
        assert!(un.owner_sid.is_some());
    }

    #[test]
    fn missing_key_is_not_found() {
        let e = Key::open(
            RegRoot::Hklm,
            r"SOFTWARE\purge-test-no-such-key-7f3a",
            RegView::K64,
        )
        .unwrap_err();
        assert!(e.is_not_found(), "{e}");
    }

    #[test]
    fn reg_value_accessors() {
        let utf16 = |s: &str| {
            s.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>()
        };
        let ms = RegValue {
            name: "m".into(),
            ty: REG_MULTI_SZ,
            data: utf16("a\0\0b\0\0"),
        };
        assert_eq!(ms.as_multi_sz().unwrap(), vec!["a", "", "b"]);
        let empty = RegValue {
            name: "m".into(),
            ty: REG_MULTI_SZ,
            data: utf16("\0"),
        };
        assert_eq!(empty.as_multi_sz().unwrap(), Vec::<String>::new());
        let sz = RegValue {
            name: String::new(),
            ty: REG_EXPAND_SZ,
            data: utf16("%X%\\y\0junk"),
        };
        assert_eq!(sz.as_string().unwrap(), "%X%\\y");
        let be = RegValue {
            name: String::new(),
            ty: REG_DWORD_BIG_ENDIAN,
            data: vec![0, 0, 1, 2],
        };
        assert_eq!(be.as_u32(), Some(0x0102));
        let qw = RegValue {
            name: String::new(),
            ty: REG_QWORD,
            data: 5u64.to_le_bytes().to_vec(),
        };
        assert_eq!(qw.as_u64(), Some(5));
        assert_eq!(qw.as_u32(), None);
        let short = RegValue {
            name: String::new(),
            ty: REG_DWORD,
            data: vec![1],
        };
        assert_eq!(short.as_u32(), None);
        assert!(ends_with_ignore_case("S-1-5-21-1_CLASSES", "_Classes"));
        assert!(!ends_with_ignore_case("S-1", "_Classes"));
    }
}
