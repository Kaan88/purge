//! [`LiveFileSystem`]: [`FileSystemSource`] over `purge_win::{fs, sid, versioninfo, signer, shelllink}`
//! (ENGINE_PLAN.md §3.2, §5.10 "the index never traverses reparse points").
//!
//! - Paths are absolute Win32 paths (`C:\…`, `\\server\share\…`; a `\\?\` prefix is accepted). A path longer
//!   than the classic `MAX_PATH` limit is opened through its `\\?\` form.
//! - Metadata is read from a handle opened with `FILE_FLAG_OPEN_REPARSE_POINT`, so a reparse point is
//!   described, not followed. Listing a directory that is itself a reparse point is refused with
//!   [`SourceError::ReparsePoint`]; entries inside a listing carry their reparse tag. Intermediate
//!   components of a path are resolved by Windows as usual: the guard's final-path check (G1) is what
//!   catches a path that moved behind a junction.
//! - [`exists`](FileSystemSource::exists) is tri-state (see [`super::errors::exists_verdict`]): `Absent`
//!   needs "not found" on a mounted fixed NTFS/ReFS volume and no reparse point on the existing part of
//!   the path.

use std::path::PathBuf;

use purge_model::FileTime;
use purge_win::{fs, sid, signer, versioninfo};

use super::errors::{exists_verdict, map_io, map_win32};
use super::shortcut::ShortcutWorker;
use crate::filesystem::{FileSystemSource, join_file_path, split_file_path};
use crate::types::{
    DirEntry, ExistsState, FILE_ATTRIBUTE_DIRECTORY, FileMeta, FileTimes, ShortcutInfo,
    SourceError, SourceResult, VersionInfo, VolumeInfo,
};

/// Paths at least this long are opened through their `\\?\` form.
const LONG_PATH_FROM: usize = 248;

/// The live filesystem, read only.
#[derive(Debug, Default)]
pub struct LiveFileSystem {
    shortcuts: ShortcutWorker,
}

/// A path ready for a Win32 call, with the form it was written in.
struct Win32Path {
    /// The path segments (drive or UNC host first).
    segs: Vec<String>,
    /// The path as passed to Win32.
    path: PathBuf,
    /// Whether `path` got a `\\?\` prefix.
    verbatim: bool,
}

/// Parses an absolute path and picks the form passed to Win32.
fn win32_path(input: &str) -> SourceResult<Win32Path> {
    let segs = split_file_path(input).ok_or_else(|| SourceError::InvalidPath(input.to_string()))?;
    let plain = join_file_path(&segs);
    // `\\?\` turns off `.`/`..` processing, so only paths without those segments get it.
    let dotted = segs.iter().any(|s| s == "." || s == "..");
    let (path, verbatim) = if plain.len() >= LONG_PATH_FROM && !dotted {
        match plain.strip_prefix("\\\\") {
            Some(unc) => (format!("\\\\?\\UNC\\{unc}"), true),
            None => (format!("\\\\?\\{plain}"), true),
        }
    } else {
        (plain, false)
    };
    Ok(Win32Path {
        segs,
        path: PathBuf::from(path),
        verbatim,
    })
}

/// Strips the `\\?\` (or `\\?\UNC\`) prefix Win32 echoes back for a verbatim path.
fn strip_verbatim(s: String) -> String {
    if let Some(unc) = s.strip_prefix("\\\\?\\UNC\\") {
        format!("\\\\{unc}")
    } else if let Some(rest) = s.strip_prefix("\\\\?\\") {
        rest.to_string()
    } else {
        s
    }
}

fn time(ticks: u64) -> Option<FileTime> {
    (ticks != 0).then_some(FileTime(ticks))
}

/// `purge-win` handle metadata to the source type. Directories always carry the directory attribute and
/// size 0; the file id is the 128-bit `FileIdInfo` identifier read little-endian, and the volume serial
/// the 64-bit serial of the same `FileIdInfo` read (no extra call).
pub(crate) fn to_file_meta(m: &fs::FileMeta) -> FileMeta {
    let attrs = if m.is_dir {
        m.attributes | FILE_ATTRIBUTE_DIRECTORY
    } else {
        m.attributes
    };
    FileMeta {
        size: if m.is_dir { 0 } else { m.size },
        attrs,
        times: FileTimes {
            created: time(m.creation_time),
            modified: time(m.last_write_time),
            accessed: time(m.last_access_time),
        },
        reparse_tag: m.reparse_tag,
        file_id: Some(u128::from_le_bytes(m.file_id.id)),
        volume_serial: Some(m.file_id.volume_serial),
    }
}

/// A `purge-win` listing entry to the source type (listings carry no file id).
pub(crate) fn to_dir_entry(e: fs::DirEntry) -> DirEntry {
    let is_dir = e.is_dir();
    DirEntry {
        meta: FileMeta {
            size: if is_dir { 0 } else { e.size },
            attrs: e.attributes,
            times: FileTimes {
                created: time(e.creation_time),
                modified: time(e.last_write_time),
                accessed: time(e.last_access_time),
            },
            reparse_tag: e.reparse_tag,
            file_id: None,
            volume_serial: None,
        },
        name: e.name,
    }
}

/// `purge-win` volume facts to the source type.
pub(crate) fn to_volume_info(v: &fs::VolumeInfo) -> VolumeInfo {
    VolumeInfo {
        serial: Some(v.serial),
        fixed: v.is_fixed(),
        fs: v.fs_name.clone(),
    }
}

impl LiveFileSystem {
    /// A live filesystem source.
    pub fn new() -> Self {
        Self::default()
    }

    fn meta_of(p: &Win32Path) -> SourceResult<FileMeta> {
        fs::metadata(&p.path)
            .map(|m| to_file_meta(&m))
            .map_err(map_win32)
    }

    /// Refuses directories where a file is needed.
    fn require_file(p: &Win32Path) -> SourceResult<()> {
        if Self::meta_of(p)?.is_dir() {
            Err(SourceError::WrongKind)
        } else {
            Ok(())
        }
    }

    /// Whether an existing proper ancestor of the path is a reparse point; `None` when an ancestor could
    /// not be examined (the answer is then unknown).
    fn reparse_on_path(p: &Win32Path) -> Option<bool> {
        for depth in 2..p.segs.len() {
            let Ok(anc) = win32_path(&join_file_path(&p.segs[..depth])) else {
                return None;
            };
            match fs::metadata(&anc.path) {
                Ok(m) if m.is_reparse_point() || m.reparse_tag != 0 => return Some(true),
                Ok(_) => {}
                // Nothing deeper exists either.
                Err(e) if e.is_not_found() => return Some(false),
                Err(_) => return None,
            }
        }
        Some(false)
    }
}

impl FileSystemSource for LiveFileSystem {
    fn metadata(&self, path: &str) -> SourceResult<FileMeta> {
        Self::meta_of(&win32_path(path)?)
    }

    fn list_dir(&self, path: &str) -> SourceResult<Vec<DirEntry>> {
        let p = win32_path(path)?;
        let meta = Self::meta_of(&p)?;
        if meta.is_reparse_point() {
            return Err(SourceError::ReparsePoint);
        }
        if !meta.is_dir() {
            return Err(SourceError::WrongKind);
        }
        Ok(fs::list_dir(&p.path)
            .map_err(map_win32)?
            .into_iter()
            .map(to_dir_entry)
            .collect())
    }

    fn exists(&self, path: &str) -> ExistsState {
        let Ok(p) = win32_path(path) else {
            return ExistsState::Unknown;
        };
        let err = match fs::metadata(&p.path) {
            Ok(_) => return ExistsState::Present,
            Err(e) if !e.is_not_found() => return exists_verdict(Some(e.code()), None, false),
            Err(e) => e.code(),
        };
        let Some(reparse) = Self::reparse_on_path(&p) else {
            return ExistsState::Unknown;
        };
        let volume = fs::volume_info(&p.path).ok().map(|v| to_volume_info(&v));
        exists_verdict(Some(err), volume.as_ref(), reparse)
    }

    fn read_bytes(&self, path: &str, max: usize) -> SourceResult<Vec<u8>> {
        let p = win32_path(path)?;
        Self::require_file(&p)?;
        fs::read_bytes(&p.path, max).map_err(map_win32)
    }

    fn long_path(&self, path: &str) -> SourceResult<String> {
        let p = win32_path(path)?;
        let long = fs::long_path(&p.path).map_err(map_win32)?;
        Ok(if p.verbatim {
            strip_verbatim(long)
        } else {
            long
        })
    }

    fn volume_info(&self, path: &str) -> SourceResult<VolumeInfo> {
        let p = win32_path(path)?;
        fs::volume_info(&p.path)
            .map(|v| to_volume_info(&v))
            .map_err(map_win32)
    }

    fn version_info(&self, path: &str) -> SourceResult<Option<VersionInfo>> {
        let p = win32_path(path)?;
        Self::require_file(&p)?;
        let info = versioninfo::read_version_info(&p.path).map_err(|e| map_io(&e))?;
        Ok(info.map(|v| VersionInfo {
            company_name: v.company_name,
            product_name: v.product_name,
            file_description: v.file_description,
            original_filename: v.original_filename,
            // `purge-win` reads the four identity strings only.
            file_version: None,
            product_version: None,
        }))
    }

    fn signer_cn(&self, path: &str) -> SourceResult<Option<String>> {
        let p = win32_path(path)?;
        Self::require_file(&p)?;
        signer::signer_subject_cn(&p.path).map_err(|e| map_io(&e))
    }

    /// Reads the link on the shortcut thread. A file that is not a shell link (the load fails with a COM
    /// error rather than a Win32 one) is [`SourceError::WrongKind`].
    fn read_shortcut(&self, path: &str) -> SourceResult<ShortcutInfo> {
        let p = win32_path(path)?;
        Self::require_file(&p)?;
        match self.shortcuts.read(p.path) {
            Ok(l) => Ok(ShortcutInfo {
                raw_path: l.raw_path,
                args: l.arguments,
                workdir: l.working_directory,
                aumid: l.aumid,
            }),
            Err(SourceError::Other(code)) if code >= 0x8000_0000 => Err(SourceError::WrongKind),
            Err(e) => Err(e),
        }
    }

    fn is_admin_only_writable(&self, path: &str) -> SourceResult<bool> {
        let p = win32_path(path)?;
        sid::is_admin_only_writable(&p.path).map_err(map_win32)
    }

    fn is_admin_only_executable(&self, path: &str) -> SourceResult<bool> {
        let p = win32_path(path)?;
        sid::is_admin_only_executable(&p.path).map_err(map_win32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_forms() {
        let p = win32_path("c:\\Program Files\\App\\").unwrap();
        assert_eq!(p.path, PathBuf::from("C:\\Program Files\\App"));
        assert!(!p.verbatim);
        assert_eq!(win32_path("C:").unwrap().path, PathBuf::from("C:\\"));
        let long = format!("C:\\{}", "a".repeat(300));
        let p = win32_path(&long).unwrap();
        assert!(p.verbatim);
        assert_eq!(p.path, PathBuf::from(format!("\\\\?\\{long}")));
        let unc = format!("\\\\srv\\share\\{}", "b".repeat(300));
        let p = win32_path(&unc).unwrap();
        assert_eq!(
            p.path,
            PathBuf::from(format!("\\\\?\\UNC\\srv\\share\\{}", "b".repeat(300)))
        );
        assert_eq!(strip_verbatim(p.path.to_string_lossy().into_owned()), unc);
        assert!(matches!(
            win32_path("relative\\x"),
            Err(SourceError::InvalidPath(_))
        ));
    }
}
