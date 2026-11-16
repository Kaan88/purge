//! Win32 error codes to [`SourceError`], and the tri-state existence rule (ENGINE_PLAN.md §3.2, §5.10).
//!
//! Everything here is pure, so the mapping is tested over a code table without touching the host.

use purge_win::os::Win32Error;

use crate::types::{ExistsState, SourceError, VolumeInfo};

/// `ERROR_FILE_NOT_FOUND`.
pub(crate) const ERROR_FILE_NOT_FOUND: u32 = 2;
/// `ERROR_PATH_NOT_FOUND`.
pub(crate) const ERROR_PATH_NOT_FOUND: u32 = 3;
/// `ERROR_ACCESS_DENIED`.
pub(crate) const ERROR_ACCESS_DENIED: u32 = 5;
/// `ERROR_DIRECTORY`: the directory name is invalid (a file where a directory is needed).
pub(crate) const ERROR_DIRECTORY: u32 = 267;
/// `ERROR_CANT_ACCESS_FILE`: `purge-win` refuses to read through a name-surrogate reparse point.
pub(crate) const ERROR_CANT_ACCESS_FILE: u32 = 1920;
/// `ERROR_CANT_RESOLVE_FILENAME`: `purge-win` refuses to open a registry path through a link key.
pub(crate) const ERROR_LINK_ON_PATH: u32 = 1921;
/// `ERROR_PROCESS_ABORTED`: the shortcut worker thread is gone.
pub(crate) const ERROR_WORKER_GONE: u32 = 1067;
/// `ERROR_KEY_DELETED`: a read through a handle whose registry key was deleted meanwhile.
pub(crate) const ERROR_KEY_DELETED: u32 = 1018;

/// Maps a Win32 error code to a [`SourceError`].
///
/// - `ERROR_FILE_NOT_FOUND` / `ERROR_PATH_NOT_FOUND` → [`SourceError::NotFound`];
/// - `ERROR_KEY_DELETED` → [`SourceError::NotFound`]: the key was deleted after it was opened, so it
///   is gone just as when the open itself had found nothing;
/// - `ERROR_ACCESS_DENIED` → [`SourceError::AccessDenied`];
/// - a registry path through a link key (`ERROR_CANT_RESOLVE_FILENAME`) and a refused name-surrogate
///   reparse point (`ERROR_CANT_ACCESS_FILE`) → [`SourceError::ReparsePoint`]: something the sources never
///   traverse, never "not found";
/// - `ERROR_DIRECTORY` → [`SourceError::WrongKind`];
/// - anything else, including sharing violations and "device not ready" → [`SourceError::Other`] with the
///   code.
pub(crate) fn map_code(code: u32) -> SourceError {
    match code {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_KEY_DELETED => SourceError::NotFound,
        ERROR_ACCESS_DENIED => SourceError::AccessDenied,
        ERROR_LINK_ON_PATH | ERROR_CANT_ACCESS_FILE => SourceError::ReparsePoint,
        ERROR_DIRECTORY => SourceError::WrongKind,
        other => SourceError::Other(other),
    }
}

/// [`map_code`] for a `purge-win` error.
pub(crate) fn map_win32(e: Win32Error) -> SourceError {
    map_code(e.code())
}

/// The Win32 code inside an `HRESULT`: `HRESULT_FROM_WIN32` values (`0x8007xxxx`) unwrap to `xxxx`, other
/// failure codes are kept whole.
pub(crate) fn hresult_code(hr: i32) -> u32 {
    let u = hr as u32;
    if u & 0xFFFF_0000 == 0x8007_0000 {
        u & 0xFFFF
    } else {
        u
    }
}

/// Maps an `io::Error` from the `purge-win` modules that return one (MSI, signer, version info, shell
/// links). Negative raw codes are `HRESULT`s.
pub(crate) fn map_io(e: &std::io::Error) -> SourceError {
    match e.raw_os_error() {
        Some(c) if c < 0 => map_code(hresult_code(c)),
        Some(c) => map_code(c as u32),
        None => match e.kind() {
            std::io::ErrorKind::NotFound => SourceError::NotFound,
            std::io::ErrorKind::PermissionDenied => SourceError::AccessDenied,
            _ => SourceError::Other(0),
        },
    }
}

/// The tri-state existence verdict.
///
/// - `open_error`: `None` when opening the path succeeded, otherwise the Win32 code of the failure.
/// - `volume`: the volume the path lives on, `None` when it could not be read (unmounted, no such drive).
/// - `reparse_on_path`: an existing ancestor of the path is a reparse point (junction, mount point,
///   symlink, cloud placeholder), so "not found" describes some other location.
///
/// `Present` when the open succeeded. `Absent` only for `ERROR_FILE_NOT_FOUND` / `ERROR_PATH_NOT_FOUND` on
/// a volume that [proves absence](VolumeInfo::proves_absence) (mounted, fixed, NTFS or ReFS) with no
/// reparse point on the path. Everything else (access denied, sharing violation, device not ready,
/// removable, network or unknown volume) is `Unknown`.
pub(crate) fn exists_verdict(
    open_error: Option<u32>,
    volume: Option<&VolumeInfo>,
    reparse_on_path: bool,
) -> ExistsState {
    match open_error {
        None => ExistsState::Present,
        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
            if !reparse_on_path && volume.is_some_and(VolumeInfo::proves_absence) =>
        {
            ExistsState::Absent
        }
        Some(_) => ExistsState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_table() {
        let table: &[(u32, SourceError)] = &[
            (2, SourceError::NotFound),
            (3, SourceError::NotFound),
            (1018, SourceError::NotFound), // key deleted under an open handle
            (5, SourceError::AccessDenied),
            (1921, SourceError::ReparsePoint),
            (1920, SourceError::ReparsePoint),
            (267, SourceError::WrongKind),
            (32, SourceError::Other(32)),     // sharing violation
            (21, SourceError::Other(21)),     // device not ready
            (53, SourceError::Other(53)),     // bad network path
            (1605, SourceError::Other(1605)), // unknown MSI product
            (0x8000_4005, SourceError::Other(0x8000_4005)),
        ];
        for (code, want) in table {
            assert_eq!(&map_code(*code), want, "code {code}");
            assert_eq!(&map_win32(Win32Error(*code)), want, "code {code}");
        }
    }

    #[test]
    fn io_and_hresult_mapping() {
        assert_eq!(hresult_code(0x8007_0005_u32 as i32), 5);
        assert_eq!(hresult_code(0x8000_4005_u32 as i32), 0x8000_4005);
        assert_eq!(
            map_io(&std::io::Error::from_raw_os_error(0x8007_0002_u32 as i32)),
            SourceError::NotFound
        );
        assert_eq!(
            map_io(&std::io::Error::from_raw_os_error(5)),
            SourceError::AccessDenied
        );
        assert_eq!(
            map_io(&std::io::Error::from_raw_os_error(0x8000_4005_u32 as i32)),
            SourceError::Other(0x8000_4005)
        );
        assert_eq!(
            map_io(&std::io::Error::new(std::io::ErrorKind::NotFound, "x")),
            SourceError::NotFound
        );
        assert_eq!(map_io(&std::io::Error::other("x")), SourceError::Other(0));
    }

    #[test]
    fn exists_table() {
        let vol = |fixed: bool, fs: &str| VolumeInfo {
            serial: Some(1),
            fixed,
            fs: fs.into(),
        };
        let ntfs = vol(true, "NTFS");
        let refs = vol(true, "ReFS");
        let fat = vol(true, "FAT32");
        let removable = vol(false, "NTFS");
        use ExistsState::{Absent, Present, Unknown};
        let table: &[(Option<u32>, Option<&VolumeInfo>, bool, ExistsState)] = &[
            (None, Some(&ntfs), false, Present),
            (None, None, true, Present),
            (Some(2), Some(&ntfs), false, Absent),
            (Some(3), Some(&ntfs), false, Absent),
            (Some(2), Some(&refs), false, Absent),
            (Some(2), Some(&ntfs), true, Unknown), // behind a junction / mount point
            (Some(2), Some(&fat), false, Unknown),
            (Some(2), Some(&removable), false, Unknown), // removable or network
            (Some(3), None, false, Unknown),             // unmounted / no such drive
            (Some(5), Some(&ntfs), false, Unknown),      // access denied
            (Some(32), Some(&ntfs), false, Unknown),     // sharing violation
            (Some(21), Some(&ntfs), false, Unknown),     // device not ready
            (Some(1920), Some(&ntfs), false, Unknown),
            (Some(123), Some(&ntfs), false, Unknown), // invalid name
        ];
        for (err, v, rp, want) in table {
            assert_eq!(exists_verdict(*err, *v, *rp), *want, "{err:?} {v:?} {rp}");
        }
    }
}
