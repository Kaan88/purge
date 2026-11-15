//! The few Win32 calls the store needs that `purge-win` does not wrap: the system random source and
//! the size of a volume. Declared here because purge-exec has no `windows-sys` dependency.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use purge_model::FileTime;
use purge_win::fs_write::FsError;

#[link(name = "bcryptprimitives", kind = "raw-dylib")]
unsafe extern "system" {
    /// `ProcessPrng`: fills a buffer from the process's cryptographic random generator. Documented to
    /// always succeed and return TRUE.
    fn ProcessPrng(data: *mut u8, len: usize) -> i32;
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    /// `GetDiskFreeSpaceExW`; the three out-parameters are `ULARGE_INTEGER`, laid out as `u64`.
    fn GetDiskFreeSpaceExW(
        directory: *const u16,
        free_to_caller: *mut u64,
        total: *mut u64,
        total_free: *mut u64,
    ) -> i32;
    /// `GetLastError`.
    fn GetLastError() -> u32;
}

/// 64 bits from the system's cryptographic random source.
pub(crate) fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    // SAFETY: `bytes` is a writable buffer of exactly the length passed.
    unsafe { ProcessPrng(bytes.as_mut_ptr(), bytes.len()) };
    u64::from_le_bytes(bytes)
}

/// The current UTC time.
pub(crate) fn now() -> FileTime {
    /// 100 ns ticks between 1601-01-01 and 1970-01-01.
    const EPOCH_TICKS: u64 = 116_444_736_000_000_000;
    let since_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ticks = u64::try_from(since_unix.as_nanos() / 100).unwrap_or(u64::MAX);
    FileTime(ticks.saturating_add(EPOCH_TICKS))
}

/// Total size in bytes of the volume mounted at `root` (a volume root such as `C:\`).
pub(crate) fn volume_total_bytes(root: &Path) -> Result<u64, FsError> {
    let mut wide: Vec<u16> = root.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(FsError::Other(87));
    }
    wide.push(0);
    let (mut free_to_caller, mut total, mut total_free) = (0u64, 0u64, 0u64);
    // SAFETY: `wide` is NUL-terminated; the three out-pointers are live, aligned u64 locals.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free_to_caller,
            &mut total,
            &mut total_free,
        )
    };
    if ok == 0 {
        // SAFETY: reads the calling thread's last-error value; no preconditions.
        let code = unsafe { GetLastError() };
        return Err(FsError::from(purge_win::os::Win32Error(code)));
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bits_differ() {
        let draws: std::collections::BTreeSet<u64> = (0..16).map(|_| random_u64()).collect();
        assert_eq!(draws.len(), 16);
    }

    #[test]
    fn clock_is_after_2025() {
        assert!(now().to_unix_secs() > 1_735_689_600);
    }

    #[test]
    fn temp_volume_has_a_size() {
        let temp = std::env::temp_dir();
        let root = purge_win::fs::volume_info(&temp).unwrap().root;
        assert!(volume_total_bytes(Path::new(&root)).unwrap() > 1 << 30);
        assert!(volume_total_bytes(&temp.join("purge-store-no-such-dir-7c1e\\")).is_err());
    }
}
