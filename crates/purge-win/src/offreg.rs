//! Read-only walk of an offline registry hive file through `offreg.dll`.
//!
//! BASELINE_LOCAL_DESIGN.md §3.2 (source S2, the default user hive `C:\Users\Default\NTUSER.DAT`).
//! [`OfflineHive::open`] opens the file itself with `GENERIC_READ` and `FILE_SHARE_READ` and hands that
//! handle to `OROpenHiveByHandle`, so the hive is parsed by `offreg.dll` in the calling process and is
//! never mounted into the live registry. [`OfflineHive::walk`] then yields every key path and every
//! value name and type, depth-first, within [`HiveLimits`] (depth 64, 2,000,000 keys by default).
//!
//! Read-only by construction:
//! - `offreg.dll` is loaded once from `System32` by its full path (`LoadLibraryExW` with
//!   `LOAD_LIBRARY_SEARCH_SYSTEM32` for its own dependencies), never from the search path.
//! - Only the reading exports are bound: open hive by handle, close hive, open key, close key, enumerate
//!   keys, enumerate values. No call that saves, flushes, creates, deletes, renames, merges or sets is
//!   bound, and no registry call that mounts a hive file (key load, app-key load) is used;
//!   `cargo xtask check-deps` forbids all of those names in purge-win.
//! - The file handle has no write access, so nothing `offreg.dll` does can change the file.
//! - Value data is never read (`OREnumValue` gets a null data buffer): names and types only.
//!
//! **Transaction logs are not replayed.** `NTUSER.DAT.LOG1`/`LOG2` beside the hive are ignored, so the
//! walk sees the primary file as last flushed. For the default profile's hive, which changes only with
//! servicing, that is the state every new profile is copied from.
//!
//! Errors are Win32 codes as `offreg.dll` returns them; a file that is not a hive fails in
//! [`OfflineHive::open`] (typically `ERROR_BADDB` or `ERROR_REGISTRY_CORRUPT`).
#![cfg(feature = "read")]

use std::ffi::c_void;
use std::path::Path;
use std::ptr;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, HANDLE, HMODULE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::core::{PCSTR, PCWSTR, PWSTR};

use crate::os::{Win32Error, from_wide, wide};

/// Default depth cap: keys this many components below the root are yielded but not descended into.
pub const MAX_DEPTH: u32 = 64;
/// Default key cap: the walk stops after yielding this many keys (the root included).
pub const MAX_KEYS: u64 = 2_000_000;

/// Caps of one [`OfflineHive::walk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HiveLimits {
    /// Deepest key yielded, in path components below the root (the root is depth 0). Subkeys of a key at
    /// this depth are counted in [`WalkSummary::depth_capped`] and not visited.
    pub max_depth: u32,
    /// Most keys yielded; reaching it ends the walk with [`WalkSummary::key_cap_hit`].
    pub max_keys: u64,
}

impl Default for HiveLimits {
    fn default() -> Self {
        HiveLimits {
            max_depth: MAX_DEPTH,
            max_keys: MAX_KEYS,
        }
    }
}

/// One item of a walk. Paths are relative to the hive root, `\`-separated, without a leading `\`, with
/// names as stored in the hive (case kept); the root key itself is the empty path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HiveItem<'a> {
    /// A key, yielded before its values and subkeys.
    Key {
        /// Its path.
        path: &'a str,
    },
    /// A value of the key yielded last (the default value has the empty name).
    Value {
        /// Path of the key that holds it.
        key: &'a str,
        /// The value name.
        name: &'a str,
        /// Its `REG_*` type.
        kind: u32,
    },
}

/// What one walk saw. A walk with `depth_capped == 0` and `!key_cap_hit` is complete.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalkSummary {
    /// Keys yielded, the root included.
    pub keys: u64,
    /// Values yielded.
    pub values: u64,
    /// Subkeys not visited because their parent was at [`HiveLimits::max_depth`].
    pub depth_capped: u64,
    /// The walk stopped at [`HiveLimits::max_keys`].
    pub key_cap_hit: bool,
}

impl WalkSummary {
    /// No cap was reached: every key and value of the hive was yielded.
    pub fn is_complete(&self) -> bool {
        self.depth_capped == 0 && !self.key_cap_hit
    }
}

/// Why an offline hive could not be opened or walked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OffregError {
    /// `offreg.dll` or one of its reading exports is missing.
    #[error("offreg.dll unavailable: {0}")]
    Unavailable(Win32Error),
    /// The file could not be opened for reading, or `offreg.dll` refused it as a hive.
    #[error("cannot open hive file: {0}")]
    Open(Win32Error),
    /// A key inside the hive could not be opened or enumerated; the walk stopped there.
    #[error("cannot read hive key `{path}`: {error}")]
    Read {
        /// Path of the key, relative to the hive root.
        path: String,
        /// The code `offreg.dll` returned.
        error: Win32Error,
    },
}

/// `ORHKEY`.
type OrHkey = *mut c_void;

type OpenHiveByHandle = unsafe extern "system" fn(HANDLE, *mut OrHkey) -> u32;
type CloseHandleFn = unsafe extern "system" fn(OrHkey) -> u32;
type OpenKey = unsafe extern "system" fn(OrHkey, PCWSTR, *mut OrHkey) -> u32;
type EnumKey =
    unsafe extern "system" fn(OrHkey, u32, PWSTR, *mut u32, PWSTR, *mut u32, *mut c_void) -> u32;
type EnumValue =
    unsafe extern "system" fn(OrHkey, u32, PWSTR, *mut u32, *mut u32, *mut u8, *mut u32) -> u32;

/// The reading exports of `offreg.dll`, the only ones bound.
struct Api {
    open_hive_by_handle: OpenHiveByHandle,
    close_hive: CloseHandleFn,
    open_key: OpenKey,
    close_key: CloseHandleFn,
    enum_key: EnumKey,
    enum_value: EnumValue,
}

/// `LOAD_LIBRARY_SEARCH_SYSTEM32`.
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
/// `ERROR_MORE_DATA`.
const ERROR_MORE_DATA: u32 = 234;
/// `ERROR_NO_MORE_ITEMS`.
const ERROR_NO_MORE_ITEMS: u32 = 259;

// The `Win32_System_LibraryLoader` feature of windows-sys is not enabled for this crate; these two
// kernel32 functions are declared here instead (as in `sr`).
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(name: PCWSTR, file: HANDLE, flags: u32) -> HMODULE;
    fn GetProcAddress(module: HMODULE, name: PCSTR)
    -> Option<unsafe extern "system" fn() -> isize>;
}

/// The bound exports, loaded once and kept for the life of the process.
fn api() -> Result<&'static Api, OffregError> {
    static API: OnceLock<Result<Api, Win32Error>> = OnceLock::new();
    API.get_or_init(load_api)
        .as_ref()
        .map_err(|&e| OffregError::Unavailable(e))
}

/// `<GetSystemDirectoryW>\offreg.dll` loaded by full path, then the six reading exports.
fn load_api() -> Result<Api, Win32Error> {
    let mut dir = [0u16; 260];
    // SAFETY: the buffer is writable for its stated length.
    let n = unsafe { GetSystemDirectoryW(dir.as_mut_ptr(), dir.len() as u32) } as usize;
    if n == 0 || n >= dir.len() {
        return Err(Win32Error::last());
    }
    let path = wide(format!(r"{}\offreg.dll", from_wide(&dir[..n])));
    // SAFETY: NUL-terminated absolute path; dependencies are searched in System32 only.
    let module =
        unsafe { LoadLibraryExW(path.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if module.is_null() {
        return Err(Win32Error::last());
    }
    let proc = |name: &std::ffi::CStr| -> Result<usize, Win32Error> {
        // SAFETY: `module` is a loaded module that is never freed; NUL-terminated ANSI export name.
        match unsafe { GetProcAddress(module, name.as_ptr().cast()) } {
            Some(f) => Ok(f as usize),
            None => Err(Win32Error::last()),
        }
    };
    let open_hive_by_handle = proc(c"OROpenHiveByHandle")?;
    let close_hive = proc(c"ORCloseHive")?;
    let open_key = proc(c"OROpenKey")?;
    let close_key = proc(c"ORCloseKey")?;
    let enum_key = proc(c"OREnumKey")?;
    let enum_value = proc(c"OREnumValue")?;
    // SAFETY: each address is the export of that name in a module that stays loaded, and each type is
    // the documented signature in offreg.h (all `DWORD` results, `ORHKEY` handles).
    unsafe {
        Ok(Api {
            open_hive_by_handle: std::mem::transmute::<usize, OpenHiveByHandle>(
                open_hive_by_handle,
            ),
            close_hive: std::mem::transmute::<usize, CloseHandleFn>(close_hive),
            open_key: std::mem::transmute::<usize, OpenKey>(open_key),
            close_key: std::mem::transmute::<usize, CloseHandleFn>(close_key),
            enum_key: std::mem::transmute::<usize, EnumKey>(enum_key),
            enum_value: std::mem::transmute::<usize, EnumValue>(enum_value),
        })
    }
}

/// An open subkey; closed on drop.
struct SubKey {
    api: &'static Api,
    key: OrHkey,
}

impl Drop for SubKey {
    fn drop(&mut self) {
        // SAFETY: `key` was returned by `OROpenKey` and is closed once.
        unsafe { (self.api.close_key)(self.key) };
    }
}

/// An offline hive file opened read-only. Closing (drop) releases the hive, then the file handle.
pub struct OfflineHive {
    api: &'static Api,
    hive: OrHkey,
    file: HANDLE,
}

// SAFETY: the handles are owned exclusively; `walk` borrows `&self` and offreg handles carry no thread
// affinity. Not `Sync`: concurrent walks of one hive are not promised by offreg.
unsafe impl Send for OfflineHive {}

impl std::fmt::Debug for OfflineHive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OfflineHive").finish_non_exhaustive()
    }
}

impl Drop for OfflineHive {
    fn drop(&mut self) {
        // SAFETY: `hive` came from `OROpenHiveByHandle` and `file` from `CreateFileW`; each is closed
        // once, the hive before the file it reads.
        unsafe {
            (self.api.close_hive)(self.hive);
            CloseHandle(self.file);
        }
    }
}

impl OfflineHive {
    /// Opens the hive file at `path` with `GENERIC_READ` and `FILE_SHARE_READ` and parses it with
    /// `offreg.dll`. Fails with [`OffregError::Open`] for a missing file, a file another process holds
    /// open for writing (a mounted hive), or a file that is not a hive. Needs no elevation for a file the
    /// caller can read.
    pub fn open(path: &Path) -> Result<OfflineHive, OffregError> {
        let api = api()?;
        let name = wide(path.as_os_str());
        // SAFETY: NUL-terminated path; no security attributes or template.
        let file = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if file == INVALID_HANDLE_VALUE {
            return Err(OffregError::Open(Win32Error::last()));
        }
        let mut hive: OrHkey = ptr::null_mut();
        // SAFETY: `file` is an open handle with read access; `hive` receives the root handle.
        let rc = unsafe { (api.open_hive_by_handle)(file, &mut hive) };
        if rc != 0 {
            // SAFETY: `file` came from `CreateFileW` and is closed once.
            unsafe { CloseHandle(file) };
            return Err(OffregError::Open(Win32Error(rc)));
        }
        Ok(OfflineHive { api, hive, file })
    }

    /// Walks the hive depth-first (pre-order): each key is passed to `visit` as [`HiveItem::Key`], then
    /// its values as [`HiveItem::Value`] in stored order, then its subkeys in stored order. The root is
    /// the first key, with the empty path. Stops at the caps in `limits` and says so in the summary; any
    /// offreg error ends the walk with [`OffregError::Read`].
    pub fn walk(
        &self,
        limits: HiveLimits,
        mut visit: impl FnMut(HiveItem<'_>),
    ) -> Result<WalkSummary, OffregError> {
        let mut summary = WalkSummary::default();
        let mut path = String::new();
        let mut names = Names::default();
        // Each frame: the open subkey (none for the root), the length of `path` before its name was
        // appended, and the index of the next subkey to enumerate.
        let mut stack: Vec<(Option<SubKey>, usize, u32)> = Vec::new();

        self.enter(self.hive, &path, &mut names, &mut summary, &mut visit)?;
        if summary.keys >= limits.max_keys {
            summary.key_cap_hit = true;
            return Ok(summary);
        }
        stack.push((None, 0, 0));

        while let Some(frame) = stack.last_mut() {
            let key = frame.0.as_ref().map_or(self.hive, |k| k.key);
            let index = frame.2;
            let Some(child) = names
                .key(self.api, key, index)
                .map_err(|error| read_error(&path, error))?
            else {
                let (_, parent_len, _) = stack.pop().expect("non-empty stack");
                path.truncate(parent_len);
                continue;
            };
            frame.2 += 1;
            let depth = stack.len() as u32; // depth of `child`
            if depth > limits.max_depth {
                summary.depth_capped += 1;
                continue;
            }
            let parent_len = path.len();
            if !path.is_empty() {
                path.push('\\');
            }
            path.push_str(&child);
            let wname = wide(&child);
            let mut sub: OrHkey = ptr::null_mut();
            // SAFETY: `key` is an open handle of this hive; NUL-terminated name of one of its subkeys.
            let rc = unsafe { (self.api.open_key)(key, wname.as_ptr(), &mut sub) };
            if rc != 0 {
                return Err(read_error(&path, Win32Error(rc)));
            }
            let sub = SubKey {
                api: self.api,
                key: sub,
            };
            self.enter(sub.key, &path, &mut names, &mut summary, &mut visit)?;
            if summary.keys >= limits.max_keys {
                summary.key_cap_hit = true;
                return Ok(summary);
            }
            stack.push((Some(sub), parent_len, 0));
        }
        Ok(summary)
    }

    /// Yields the key at `path` and its values.
    fn enter(
        &self,
        key: OrHkey,
        path: &str,
        names: &mut Names,
        summary: &mut WalkSummary,
        visit: &mut impl FnMut(HiveItem<'_>),
    ) -> Result<(), OffregError> {
        visit(HiveItem::Key { path });
        summary.keys += 1;
        let mut index = 0;
        while let Some((name, kind)) = names
            .value(self.api, key, index)
            .map_err(|error| read_error(path, error))?
        {
            visit(HiveItem::Value {
                key: path,
                name: &name,
                kind,
            });
            summary.values += 1;
            index += 1;
        }
        Ok(())
    }
}

fn read_error(path: &str, error: Win32Error) -> OffregError {
    OffregError::Read {
        path: path.to_owned(),
        error,
    }
}

/// Reused name buffers for `OREnumKey` / `OREnumValue` (key names are at most 255 characters, value
/// names at most 16,383; both grow on `ERROR_MORE_DATA`).
struct Names {
    key: Vec<u16>,
    value: Vec<u16>,
}

impl Default for Names {
    fn default() -> Self {
        Names {
            key: vec![0; 256],
            value: vec![0; 16_384],
        }
    }
}

impl Names {
    /// Name of subkey `index` of `key`, `None` past the last.
    fn key(&mut self, api: &Api, key: OrHkey, index: u32) -> Result<Option<String>, Win32Error> {
        loop {
            let mut len = self.key.len() as u32;
            // SAFETY: `key` is an open handle; the buffer holds `len` characters; class and time are
            // optional and passed as null.
            let rc = unsafe {
                (api.enum_key)(
                    key,
                    index,
                    self.key.as_mut_ptr(),
                    &mut len,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            match rc {
                0 => return Ok(Some(String::from_utf16_lossy(&self.key[..len as usize]))),
                ERROR_NO_MORE_ITEMS => return Ok(None),
                ERROR_MORE_DATA if self.key.len() < 1 << 16 => {
                    let n = self.key.len() * 2;
                    self.key.resize(n, 0);
                }
                code => return Err(Win32Error(code)),
            }
        }
    }

    /// Name and type of value `index` of `key`, `None` past the last. The data is never read.
    fn value(
        &mut self,
        api: &Api,
        key: OrHkey,
        index: u32,
    ) -> Result<Option<(String, u32)>, Win32Error> {
        loop {
            let mut len = self.value.len() as u32;
            let mut kind = 0u32;
            // SAFETY: `key` is an open handle; the buffer holds `len` characters; a null data buffer
            // and size ask for no data.
            let rc = unsafe {
                (api.enum_value)(
                    key,
                    index,
                    self.value.as_mut_ptr(),
                    &mut len,
                    &mut kind,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            match rc {
                0 => {
                    let name = String::from_utf16_lossy(&self.value[..len as usize]);
                    return Ok(Some((name, kind)));
                }
                ERROR_NO_MORE_ITEMS => return Ok(None),
                ERROR_MORE_DATA if self.value.len() < 1 << 17 => {
                    let n = self.value.len() * 2;
                    self.value.resize(n, 0);
                }
                code => return Err(Win32Error(code)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// `%SystemDrive%\Users\Default\NTUSER.DAT`.
    fn default_hive() -> PathBuf {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        PathBuf::from(format!(r"{drive}\Users\Default\NTUSER.DAT"))
    }

    fn temp_file(tag: &str, bytes: &[u8]) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "purge-offreg-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&p, bytes).expect("write temp file");
        p
    }

    /// The default user hive opens (no elevation needed) and yields the `Run` key or its parent; the
    /// file is byte-for-byte unchanged afterwards.
    #[test]
    fn default_user_hive_walk() {
        let path = default_hive();
        let before = std::fs::read(&path).expect("read default hive");
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();

        let hive = OfflineHive::open(&path).expect("open default hive");
        let mut keys = Vec::new();
        let mut values = 0u64;
        let mut first = None;
        let summary = hive
            .walk(HiveLimits::default(), |item| match item {
                HiveItem::Key { path } => {
                    first.get_or_insert_with(|| path.to_owned());
                    keys.push(path.to_ascii_lowercase());
                }
                HiveItem::Value { key, .. } => {
                    assert!(keys.last().is_some_and(|k| *k == key.to_ascii_lowercase()));
                    values += 1;
                }
            })
            .expect("walk default hive");
        drop(hive);

        assert_eq!(first.as_deref(), Some(""));
        assert!(summary.is_complete(), "{summary:?}");
        assert_eq!(summary.keys, keys.len() as u64);
        assert_eq!(summary.values, values);
        assert!(
            keys.iter()
                .any(|k| k == r"software\microsoft\windows\currentversion\run"
                    || k == r"software\microsoft\windows\currentversion"),
            "{} keys",
            keys.len()
        );
        eprintln!(
            "default hive: {} keys, {} values, {} bytes",
            summary.keys,
            summary.values,
            before.len()
        );

        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            modified
        );
    }

    /// Both caps stop the walk and are reported.
    #[test]
    fn caps() {
        let hive = OfflineHive::open(&default_hive()).expect("open default hive");
        let mut deepest = 0;
        let s = hive
            .walk(
                HiveLimits {
                    max_depth: 1,
                    max_keys: MAX_KEYS,
                },
                |item| {
                    if let HiveItem::Key { path } = item {
                        let depth = if path.is_empty() {
                            0
                        } else {
                            path.matches('\\').count() + 1
                        };
                        deepest = deepest.max(depth);
                    }
                },
            )
            .unwrap();
        assert_eq!(deepest, 1);
        assert!(
            s.depth_capped > 0 && !s.key_cap_hit && !s.is_complete(),
            "{s:?}"
        );

        let mut n = 0;
        let s = hive
            .walk(
                HiveLimits {
                    max_depth: MAX_DEPTH,
                    max_keys: 5,
                },
                |item| n += matches!(item, HiveItem::Key { .. }) as u64,
            )
            .unwrap();
        assert_eq!((n, s.keys, s.key_cap_hit), (5, 5, true));
    }

    #[test]
    fn missing_file_is_an_error() {
        let p = std::env::temp_dir().join("purge-offreg-does-not-exist.dat");
        match OfflineHive::open(&p) {
            Err(OffregError::Open(e)) => assert!(e.is_not_found(), "{e}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn non_hive_file_is_an_error() {
        for (tag, bytes) in [
            ("text", b"not a registry hive\r\n".repeat(400)),
            ("empty", Vec::new()),
            ("zeros", vec![0u8; 8192]),
        ] {
            let p = temp_file(tag, &bytes);
            let r = OfflineHive::open(&p);
            std::fs::remove_file(&p).ok();
            assert!(matches!(r, Err(OffregError::Open(_))), "{tag}: {r:?}");
        }
    }
}
