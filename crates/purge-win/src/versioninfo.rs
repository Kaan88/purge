//! VersionInfo strings of a PE file: CompanyName, ProductName, FileDescription, OriginalFilename.
//!
//! ENGINE_PLAN.md §3.2 and §5.4 (vendor tokens; the generic `company_name` idea is reused, the code is
//! new). `GetFileVersionInfoW` loads the resource, `\VarFileInfo\Translation` gives the language and code
//! page pairs, and the strings are read from the **first** translation's `\StringFileInfo\<lang><cp>`
//! block. When a file has no translation table, the common `040904B0` / `040904E4` / `000004B0` blocks are
//! tried instead.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};

/// The VersionInfo strings the engine reads. Empty or whitespace-only values are `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VersionInfo {
    /// `CompanyName`.
    pub company_name: Option<String>,
    /// `ProductName`.
    pub product_name: Option<String>,
    /// `FileDescription`.
    pub file_description: Option<String>,
    /// `OriginalFilename`.
    pub original_filename: Option<String>,
}

impl VersionInfo {
    /// True when no string was found.
    pub fn is_empty(&self) -> bool {
        self.company_name.is_none()
            && self.product_name.is_none()
            && self.file_description.is_none()
            && self.original_filename.is_none()
    }
}

/// Fallback `<lang><codepage>` blocks when the file has no translation table.
const FALLBACK_TRANSLATIONS: [&str; 3] = ["040904B0", "040904E4", "000004B0"];

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Reads the VersionInfo strings of `path`.
///
/// `Ok(None)` when the file has no version resource. `Err` when the file cannot be opened.
pub fn read_version_info(path: &Path) -> io::Result<Option<VersionInfo>> {
    // Distinguish "cannot open" from "no resource".
    std::fs::metadata(path)?;
    let path_w: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut handle = 0u32;
    // SAFETY: `path_w` is NUL-terminated.
    let size = unsafe { GetFileVersionInfoSizeW(path_w.as_ptr(), &mut handle) };
    if size == 0 {
        return Ok(None);
    }
    let mut block = vec![0u8; size as usize];
    // SAFETY: `block` holds `size` bytes.
    if unsafe { GetFileVersionInfoW(path_w.as_ptr(), 0, size, block.as_mut_ptr().cast()) } == 0 {
        return Ok(None);
    }

    let translation = first_translation(&block);
    let prefixes: Vec<String> = match translation {
        Some((lang, cp)) => vec![format!("{lang:04X}{cp:04X}")],
        None => FALLBACK_TRANSLATIONS
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
    };

    let mut info = VersionInfo::default();
    for prefix in &prefixes {
        let get = |name: &str| query_string(&block, &format!(r"\StringFileInfo\{prefix}\{name}"));
        info = VersionInfo {
            company_name: get("CompanyName"),
            product_name: get("ProductName"),
            file_description: get("FileDescription"),
            original_filename: get("OriginalFilename"),
        };
        if !info.is_empty() {
            break;
        }
    }
    Ok(Some(info))
}

/// The first `(language, code page)` pair of `\VarFileInfo\Translation`.
fn first_translation(block: &[u8]) -> Option<(u16, u16)> {
    let sub = wide(r"\VarFileInfo\Translation");
    let mut value: *mut c_void = ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: `block` is a version-info block from GetFileVersionInfoW; the returned pointer points into it.
    let ok = unsafe { VerQueryValueW(block.as_ptr().cast(), sub.as_ptr(), &mut value, &mut len) };
    if ok == 0 || value.is_null() || len < 4 {
        return None;
    }
    // SAFETY: at least 4 bytes are available; read unaligned to be safe.
    let pair = unsafe { ptr::read_unaligned(value as *const [u16; 2]) };
    Some((pair[0], pair[1]))
}

/// A string value from the block; `None` when absent or blank.
fn query_string(block: &[u8], sub_block: &str) -> Option<String> {
    let sub = wide(sub_block);
    let mut value: *mut c_void = ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: as in `first_translation`.
    let ok = unsafe { VerQueryValueW(block.as_ptr().cast(), sub.as_ptr(), &mut value, &mut len) };
    if ok == 0 || value.is_null() || len == 0 {
        return None;
    }
    // `len` counts characters for string values. Clamp it to the block so a malformed resource cannot
    // make us read past the buffer.
    let start = value as usize;
    let block_start = block.as_ptr() as usize;
    let block_end = block_start + block.len();
    if start < block_start || start >= block_end {
        return None;
    }
    let max_chars = (block_end - start) / 2;
    let n = (len as usize).min(max_chars);
    let mut chars = Vec::with_capacity(n);
    for i in 0..n {
        // SAFETY: `i < max_chars`, so the read stays inside `block`; unaligned read is used.
        let c = unsafe { ptr::read_unaligned((value as *const u16).add(i)) };
        if c == 0 {
            break;
        }
        chars.push(c);
    }
    let s = String::from_utf16_lossy(&chars).trim().to_owned();
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn notepad_has_microsoft_company() {
        let root =
            PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into()));
        let notepad = root.join(r"System32\notepad.exe");
        if !notepad.exists() {
            return;
        }
        let info = read_version_info(&notepad)
            .unwrap()
            .expect("notepad has a version resource");
        println!("{info:?}");
        assert!(
            info.company_name
                .as_deref()
                .unwrap_or("")
                .contains("Microsoft"),
            "{info:?}"
        );
        assert!(
            info.original_filename
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase()
                .starts_with("notepad"),
            "{info:?}"
        );
    }

    #[test]
    fn kernel32_dll_has_description() {
        let root =
            PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into()));
        let info = read_version_info(&root.join(r"System32\kernel32.dll"))
            .unwrap()
            .expect("resource");
        assert!(info.file_description.is_some(), "{info:?}");
    }

    #[test]
    fn file_without_resource_is_none() {
        let dir = std::env::temp_dir().join(format!("purge-win-verinfo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let txt = dir.join("plain.txt");
        std::fs::write(&txt, b"no resource").unwrap();
        assert_eq!(read_version_info(&txt).unwrap(), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_file_is_error() {
        assert!(read_version_info(Path::new(r"C:\definitely\not\here.dll")).is_err());
    }
}
