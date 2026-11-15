//! Raw registry calls for the tests, for what `WKey` deliberately cannot do: create and delete
//! registry links, set values with names that are not representable. Declared once for the whole
//! crate, so every test module calls the functions with the same signatures.

use std::ffi::c_void;

/// A raw registry key handle (`HKEY`).
pub type Hkey = *mut c_void;

/// `REG_OPTION_CREATE_LINK`.
pub const REG_OPTION_CREATE_LINK: u32 = 0x2;
/// `REG_OPTION_OPEN_LINK`.
pub const REG_OPTION_OPEN_LINK: u32 = 0x8;
/// `KEY_ALL_ACCESS`.
pub const KEY_ALL_ACCESS: u32 = 0xF_003F;
/// `KEY_SET_VALUE`.
pub const KEY_SET_VALUE: u32 = 0x2;
/// `DELETE`.
pub const DELETE_ACCESS: u32 = 0x1_0000;
/// `KEY_WOW64_64KEY`.
pub const KEY_WOW64_64KEY: u32 = 0x100;

#[link(name = "advapi32", kind = "raw-dylib")]
unsafe extern "system" {
    /// `RegOpenKeyExW`.
    pub fn RegOpenKeyExW(key: Hkey, sub: *const u16, options: u32, sam: u32, out: *mut Hkey)
    -> u32;
    /// `RegCreateKeyExW`.
    pub fn RegCreateKeyExW(
        key: Hkey,
        sub: *const u16,
        reserved: u32,
        class: *const u16,
        options: u32,
        sam: u32,
        sa: *const c_void,
        out: *mut Hkey,
        disposition: *mut u32,
    ) -> u32;
    /// `RegSetValueExW`.
    pub fn RegSetValueExW(
        key: Hkey,
        name: *const u16,
        reserved: u32,
        ty: u32,
        data: *const u8,
        len: u32,
    ) -> u32;
    /// `RegCloseKey`.
    pub fn RegCloseKey(key: Hkey) -> u32;
}

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    /// `NtDeleteKey`: deletes the key behind the handle itself (a link as the link).
    pub fn NtDeleteKey(key: Hkey) -> i32;
}

/// `HKEY_USERS` (sign-extended predefined handle).
pub fn hkey_users() -> Hkey {
    0x8000_0003_u32 as i32 as isize as Hkey
}

/// `text` as NUL-terminated UTF-16.
pub fn wz(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}
