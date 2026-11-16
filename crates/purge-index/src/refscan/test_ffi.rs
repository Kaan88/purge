//! Raw registry writes for the live reference-scan test: a scratch tree under
//! `HKU\<SID>\Software\PurgeTest-<random>` with a link key and keys whose DACL refuses reading, all
//! removed again on drop. `purge-source` reads the registry only; test code only.

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

type Hkey = *mut c_void;

const REG_OPTION_NON_VOLATILE: u32 = 0;
const REG_OPTION_CREATE_LINK: u32 = 0x2;
const REG_OPTION_OPEN_LINK: u32 = 0x8;
const KEY_ALL_ACCESS: u32 = 0xF_003F;
const DELETE: u32 = 0x1_0000;
const WRITE_DAC: u32 = 0x4_0000;
const KEY_WOW64_64KEY: u32 = 0x100;
const REG_SZ: u32 = 1;
const REG_LINK: u32 = 6;
const DACL_SECURITY_INFORMATION: u32 = 4;
const SDDL_REVISION_1: u32 = 1;

#[link(name = "advapi32", kind = "raw-dylib")]
unsafe extern "system" {
    fn RegOpenKeyExW(key: Hkey, sub: *const u16, options: u32, sam: u32, out: *mut Hkey) -> u32;
    fn RegCreateKeyExW(
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
    fn RegSetValueExW(
        key: Hkey,
        name: *const u16,
        reserved: u32,
        ty: u32,
        data: *const u8,
        len: u32,
    ) -> u32;
    fn RegSetKeySecurity(key: Hkey, info: u32, sd: *mut c_void) -> u32;
    fn RegDeleteTreeW(key: Hkey, sub: *const u16) -> u32;
    fn RegCloseKey(key: Hkey) -> u32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl: *const u16,
        revision: u32,
        sd: *mut *mut c_void,
        len: *mut u32,
    ) -> i32;
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn LocalFree(mem: *mut c_void) -> *mut c_void;
}

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    /// Deletes the key behind the handle itself (a link as the link).
    fn NtDeleteKey(key: Hkey) -> i32;
}

/// `HKEY_USERS` (sign-extended predefined handle).
fn hkey_users() -> Hkey {
    0x8000_0003_u32 as i32 as isize as Hkey
}

/// `text` as NUL-terminated UTF-16.
fn wz(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// An open key handle, closed on drop.
pub(super) struct RawKey(Hkey);

impl Drop for RawKey {
    fn drop(&mut self) {
        // SAFETY: the handle came from `RegCreateKeyExW` / `RegOpenKeyExW` and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

impl RawKey {
    fn set(&self, name: &str, ty: u32, data: &[u8]) {
        let name = wz(name);
        // SAFETY: live handle; `name` is NUL-terminated; `data` has the stated length.
        let rc = unsafe {
            RegSetValueExW(
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

    /// Sets the `REG_SZ` value `name` (with its terminator).
    pub(super) fn set_sz(&self, name: &str, text: &str) -> &Self {
        let data: Vec<u8> = wz(text).iter().flat_map(|u| u.to_le_bytes()).collect();
        self.set(name, REG_SZ, &data);
        self
    }

    /// Sets the DACL of the key to the one of `sddl` (`D:...`).
    fn set_dacl(&self, sddl: &str) {
        let text = wz(sddl);
        let mut sd: *mut c_void = std::ptr::null_mut();
        // SAFETY: `text` is NUL-terminated; `sd` is a valid out-pointer; the length is not wanted.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "parse {sddl}");
        // SAFETY: live handle opened with WRITE_DAC; `sd` is the descriptor just made.
        let rc = unsafe { RegSetKeySecurity(self.0, DACL_SECURITY_INFORMATION, sd) };
        // SAFETY: `sd` was allocated by the conversion with `LocalAlloc` and is freed once.
        unsafe { LocalFree(sd) };
        assert_eq!(rc, 0, "set DACL {sddl}");
    }
}

/// A fresh `HKU\<SID>\Software\PurgeTest-<random>` tree, removed on drop (also on panic).
pub(super) struct Scratch {
    sid: String,
    /// `<SID>\Software\PurgeTest-…`, relative to `HKU`.
    rel: String,
    /// Link keys made, relative to the root; deleted as links before the tree.
    links: Vec<String>,
    /// Keys whose DACL was narrowed, relative to the root; opened up again before the tree goes.
    restricted: Vec<String>,
}

impl Scratch {
    pub(super) fn new(sid: &str) -> Scratch {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let rel = format!(
            r"{sid}\Software\PurgeTest-{:x}-{nanos:x}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let scratch = Scratch {
            sid: sid.to_owned(),
            rel,
            links: Vec::new(),
            restricted: Vec::new(),
        };
        drop(scratch.create(""));
        scratch
    }

    fn full(&self, sub: &str) -> String {
        if sub.is_empty() {
            self.rel.clone()
        } else {
            format!(r"{}\{sub}", self.rel)
        }
    }

    /// The canonical path of `sub` below the root (`HKU\<SID>\Software\PurgeTest-…\<sub>`).
    pub(super) fn canon(&self, sub: &str) -> String {
        format!(r"HKU\{}", self.full(sub))
    }

    fn raw_create(&self, sub: &str, options: u32) -> RawKey {
        let name = wz(&self.full(sub));
        let mut key: Hkey = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated; class, security and disposition are null; `key` is a valid
        // out-pointer.
        let rc = unsafe {
            RegCreateKeyExW(
                hkey_users(),
                name.as_ptr(),
                0,
                std::ptr::null(),
                options,
                KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                std::ptr::null(),
                &mut key,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "create {sub}");
        RawKey(key)
    }

    /// Creates `sub` (and the keys above it) as an ordinary key.
    pub(super) fn create(&self, sub: &str) -> RawKey {
        self.raw_create(sub, REG_OPTION_NON_VOLATILE)
    }

    /// Creates the link `sub` with its target `target` (relative to the root).
    pub(super) fn link(&mut self, sub: &str, target: &str) {
        self.links.push(sub.to_owned());
        let key = self.raw_create(sub, REG_OPTION_CREATE_LINK);
        let nt = format!(r"\REGISTRY\USER\{}", self.full(target));
        let data: Vec<u8> = nt.encode_utf16().flat_map(u16::to_le_bytes).collect();
        key.set("SymbolicLinkValue", REG_LINK, &data);
    }

    /// Narrows the DACL of the existing key `sub` to the access mask `rights` (SDDL rights, such as
    /// `0x10001` for `DELETE | KEY_QUERY_VALUE`) for the current user alone, protected from
    /// inheritance.
    pub(super) fn restrict(&mut self, sub: &str, rights: &str) {
        self.restricted.push(sub.to_owned());
        let key = self.open(sub, WRITE_DAC).expect("open for WRITE_DAC");
        key.set_dacl(&format!("D:P(A;;{rights};;;{})", self.sid));
    }

    fn open(&self, sub: &str, access: u32) -> Result<RawKey, u32> {
        let name = wz(&self.full(sub));
        let mut key: Hkey = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated; `key` is a valid out-pointer.
        let rc = unsafe {
            RegOpenKeyExW(
                hkey_users(),
                name.as_ptr(),
                REG_OPTION_OPEN_LINK,
                access | KEY_WOW64_64KEY,
                &mut key,
            )
        };
        if rc == 0 { Ok(RawKey(key)) } else { Err(rc) }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // The owner may always rewrite the DACL; open the narrowed keys up again.
        for sub in self.restricted.iter().rev() {
            if let Ok(key) = self.open(sub, WRITE_DAC) {
                key.set_dacl(&format!("D:P(A;;KA;;;{})", self.sid));
            }
        }
        // Links as links: `RegDeleteTreeW` would follow them.
        for link in self.links.iter().rev() {
            if let Ok(key) = self.open(link, DELETE) {
                // SAFETY: a live handle opened with DELETE; the link key itself is deleted.
                unsafe { NtDeleteKey(key.0) };
            }
        }
        let name = wz(&self.rel);
        // SAFETY: `name` is NUL-terminated; with a subkey name the call deletes that key too.
        let rc = unsafe { RegDeleteTreeW(hkey_users(), name.as_ptr()) };
        if !std::thread::panicking() {
            assert_eq!(rc, 0, "scratch key {} removed", self.rel);
        }
    }
}
