//! The [`FileSystemSource`] trait: read-only filesystem access for every scanner (ENGINE_PLAN.md §3.2,
//! §5.6, §5.10 "the index never traverses reparse points").
//!
//! Paths are absolute Win32 paths as `purge-guard` canonicalises them (`C:\Program Files\App`, no `\\?\`
//! prefix needed; a `\\?\` prefix is accepted). Lookups are case-insensitive. Nothing here follows a reparse
//! point: [`FileSystemSource::list_dir`] reports reparse entries with their tag and the caller decides
//! whether to descend, and listing a reparse point itself is refused with
//! [`SourceError::ReparsePoint`](crate::types::SourceError::ReparsePoint).

use crate::types::{
    DirEntry, ExistsState, FileMeta, ShortcutInfo, SourceResult, VersionInfo, VolumeInfo,
};

/// Read-only filesystem access. Object safe; implementations are shared across scanner threads.
pub trait FileSystemSource: Send + Sync {
    /// Metadata of a file or directory, without following a reparse point.
    fn metadata(&self, path: &str) -> SourceResult<FileMeta>;

    /// The direct entries of a directory (non-traversing), in a stable order.
    fn list_dir(&self, path: &str) -> SourceResult<Vec<DirEntry>>;

    /// Tri-state existence for dangling checks. `Absent` only when absence is proven (not found on a
    /// mounted fixed NTFS/ReFS volume, inside what the source can see); access denied, sharing violations,
    /// removable/network/unmounted volumes and uncaptured locations give `Unknown`.
    fn exists(&self, path: &str) -> ExistsState;

    /// The first `max` bytes of a file.
    fn read_bytes(&self, path: &str, max: usize) -> SourceResult<Vec<u8>>;

    /// The long form of a path (8.3 segments expanded, case as stored on disk).
    fn long_path(&self, path: &str) -> SourceResult<String>;

    /// The volume a path lives on.
    fn volume_info(&self, path: &str) -> SourceResult<VolumeInfo>;

    /// The version resource of an executable; `Ok(None)` when it has none.
    fn version_info(&self, path: &str) -> SourceResult<Option<VersionInfo>>;

    /// The subject CN of the file's Authenticode signer; `Ok(None)` when unsigned.
    fn signer_cn(&self, path: &str) -> SourceResult<Option<String>>;

    /// What a `.lnk` file says, without resolving it.
    fn read_shortcut(&self, path: &str) -> SourceResult<ShortcutInfo>;

    /// Whether only administrators (and the system) can write the path and every ancestor; feeds
    /// `SourceTrust` (ENGINE_PLAN.md §5.2 Rule T).
    fn is_admin_only_writable(&self, path: &str) -> SourceResult<bool>;
}

/// The segments of an absolute file path: the drive (`C:`) or UNC host (`\\server`) first, then each
/// component. `None` for a relative or empty path. A `\\?\` or `\??\` prefix is stripped; `/` is accepted
/// as a separator.
pub(crate) fn split_file_path(path: &str) -> Option<Vec<String>> {
    let p = path.trim();
    let p = p
        .strip_prefix("\\\\?\\")
        .or_else(|| p.strip_prefix("\\??\\"))
        .unwrap_or(p);
    let p = p.replace('/', "\\");
    if let Some(rest) = p.strip_prefix("\\\\") {
        let mut parts = rest.split('\\').filter(|s| !s.is_empty());
        let host = parts.next()?;
        let mut segs = vec![format!("\\\\{host}")];
        segs.extend(parts.map(String::from));
        return Some(segs);
    }
    let bytes = p.as_bytes();
    if bytes.len() < 2 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
        return None;
    }
    if bytes.len() > 2 && bytes[2] != b'\\' {
        return None; // drive-relative (`C:foo`)
    }
    let mut segs = vec![p[..2].to_ascii_uppercase()];
    segs.extend(
        p[2..]
            .split('\\')
            .filter(|s| !s.is_empty())
            .map(String::from),
    );
    Some(segs)
}

/// Joins file-path segments back into a path; a lone drive becomes `C:\`.
pub(crate) fn join_file_path(segs: &[String]) -> String {
    match segs {
        [] => String::new(),
        [drive] if drive.ends_with(':') => format!("{drive}\\"),
        _ => segs.join("\\"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_forms() {
        assert_eq!(
            split_file_path("C:\\Program Files\\App\\").unwrap(),
            vec!["C:", "Program Files", "App"]
        );
        assert_eq!(split_file_path("c:\\").unwrap(), vec!["C:"]);
        assert_eq!(
            split_file_path("\\\\?\\C:\\x/y").unwrap(),
            vec!["C:", "x", "y"]
        );
        assert_eq!(
            split_file_path("\\\\srv\\share\\a").unwrap(),
            vec!["\\\\srv", "share", "a"]
        );
        assert_eq!(split_file_path("relative\\x"), None);
        assert_eq!(split_file_path("C:foo"), None);
        assert_eq!(split_file_path(""), None);
        assert_eq!(join_file_path(&["C:".into()]), "C:\\");
        assert_eq!(join_file_path(&["C:".into(), "a".into()]), "C:\\a");
    }
}
