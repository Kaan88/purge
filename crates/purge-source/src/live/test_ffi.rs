//! Raw registry writes for the host tests, for what the read-only `purge-win` API cannot do: a scratch
//! tree under `HKU\<SID>\Software\PurgeTest-<random>` with link keys (made in two steps, as the registry
//! makes every link) and keys deleted, all removed again on drop. Test code only.

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

type Hkey = *mut c_void;

const REG_OPTION_NON_VOLATILE: u32 = 0;
const REG_OPTION_CREATE_LINK: u32 = 0x2;
const REG_OPTION_OPEN_LINK: u32 = 0x8;
const KEY_ALL_ACCESS: u32 = 0xF_003F;
const DELETE: u32 = 0x1_0000;
const KEY_WOW64_64KEY: u32 = 0x100;
const REG_SZ: u32 = 1;
const REG_LINK: u32 = 6;

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
    fn RegDeleteTreeW(key: Hkey, sub: *const u16) -> u32;
    fn RegCloseKey(key: Hkey) -> u32;
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

/// An open key handle with all access, closed on drop.
pub(crate) struct RawKey(Hkey);

impl Drop for RawKey {
    fn drop(&mut self) {
        // SAFETY: the handle came from `RegCreateKeyExW` and is closed once.
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
    pub(crate) fn set_sz(&self, name: &str, text: &str) {
        let data: Vec<u8> = wz(text).iter().flat_map(|u| u.to_le_bytes()).collect();
        self.set(name, REG_SZ, &data);
    }

    /// Writes the target of a link key (`SymbolicLinkValue`, an NT path, no terminator).
    pub(crate) fn set_link_target(&self, nt_path: &str) {
        let data: Vec<u8> = nt_path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        self.set("SymbolicLinkValue", REG_LINK, &data);
    }
}

/// A fresh `HKU\<SID>\Software\PurgeTest-<random>` tree, removed on drop (also on panic).
pub(crate) struct Scratch {
    /// `<SID>\Software\PurgeTest-…`, relative to `HKU`.
    rel: String,
    /// Link keys made, relative to the scratch root; deleted as links before the tree.
    links: Vec<String>,
}

impl Scratch {
    pub(crate) fn new(sid: &str) -> Scratch {
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
            rel,
            links: Vec::new(),
        };
        drop(scratch.raw_create("", REG_OPTION_NON_VOLATILE));
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
    pub(crate) fn canon(&self, sub: &str) -> String {
        format!(r"HKU\{}", self.full(sub))
    }

    /// The NT path of `sub` below the root, as a link target.
    pub(crate) fn nt_path(&self, sub: &str) -> String {
        format!(r"\REGISTRY\USER\{}", self.full(sub))
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
    pub(crate) fn create(&self, sub: &str) -> RawKey {
        self.raw_create(sub, REG_OPTION_NON_VOLATILE)
    }

    /// Creates `sub` as a link key without its target: the first of the two steps of making a link.
    pub(crate) fn link(&mut self, sub: &str) -> RawKey {
        self.links.push(sub.to_owned());
        self.raw_create(sub, REG_OPTION_CREATE_LINK)
    }

    /// Deletes the key `sub` itself (a link as the link); it must have no subkeys.
    pub(crate) fn delete(&self, sub: &str) -> Result<(), u32> {
        let name = wz(&self.full(sub));
        let mut key: Hkey = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated; `key` is a valid out-pointer.
        let rc = unsafe {
            RegOpenKeyExW(
                hkey_users(),
                name.as_ptr(),
                REG_OPTION_OPEN_LINK,
                DELETE | KEY_WOW64_64KEY,
                &mut key,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        let key = RawKey(key);
        // SAFETY: a live handle opened with DELETE.
        let status = unsafe { NtDeleteKey(key.0) };
        if status < 0 {
            Err(status as u32)
        } else {
            Ok(())
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Links first, as links: `RegDeleteTreeW` would follow them.
        for link in self.links.iter().rev() {
            let _ = self.delete(link);
        }
        let name = wz(&self.rel);
        // SAFETY: `name` is NUL-terminated. With a subkey name the call deletes that key too.
        let rc = unsafe { RegDeleteTreeW(hkey_users(), name.as_ptr()) };
        if !std::thread::panicking() {
            assert_eq!(rc, 0, "scratch key {} removed", self.rel);
        }
    }
}
