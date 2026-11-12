//! Main-exe selection for identity resolution (ENGINE_PLAN §5.4 "main exe names").
//!
//! This is a deliberately small heuristic. It looks only at
//!
//! - the `DisplayIcon` target, when that is an `.exe`, and
//! - the `.exe` files in `InstallLocation` and in its direct subfolders (path depth 2 at most),
//!
//! and never at uninstallers (the `UninstallString` executable, `unins*.exe`). The complete exe set of an
//! app, and the validation of its roots, belong to the harvest.
//!
//! # Which candidates are main exes
//!
//! Each candidate gets a [`MainExeBasis`], strongest first:
//!
//! 1. [`MainExeBasis::DisplayIcon`]: the app's own Uninstall key points at it.
//! 2. [`MainExeBasis::FileName`]: its file name shares a token with the app's registry names
//!    (`firefox.exe` for `Mozilla Firefox`).
//! 3. [`MainExeBasis::VersionInfo`]: its `ProductName` or `FileDescription` does.
//! 4. [`MainExeBasis::LargestOnly`]: nothing relates any candidate to the app, so the largest one is
//!    reported. It is a main exe for verify-gone purposes only and contributes no name and no vendor.
//!
//! Candidates with one of the first three bases are sorted by basis, then size (largest first), then path,
//! and the first [`MAX_MAIN_EXES`] are kept. A bundled third-party tool (`node.exe`, `ffmpeg.exe`) is
//! unrelated to the app's names and is therefore never a main exe while a related one exists.
//!
//! # Paths
//!
//! `InstallLocation` and `DisplayIcon` are used as written in the key, after trimming quotes, an icon
//! index and expanding environment variables with the caller's map. A path that still holds a `%`, holds a
//! `..` segment or is not an absolute drive path is ignored. `InstallLocation` is also ignored when it is
//! lexically a shared system location (a drive root, the Windows tree, `Program Files` itself, a profile
//! folder, …): listing those would only produce unrelated executables. Reparse points are never listed.
//!
//! A path with a segment that Win32 would rewrite (a trailing dot or space, so also `.`), or with a
//! character that is not valid in a file name, is ignored as well: the lexical checks here would look at a
//! different string than the file system does (`C:\Windows.` is `C:\Windows`).
//!
//! # Other apps' folders
//!
//! A `DisplayIcon` target that lies in the `InstallLocation` of **another** installed entry, and not in
//! this entry's own, is not a candidate: an add-on or component that borrows its host's icon must not take
//! the host's exe, signer or company as its own identity.

use std::collections::BTreeSet;

use purge_source::filesystem::FileSystemSource;
use purge_source::types::{SourceError, VersionInfo};
use purge_win::env::{EnvMap, expand_with};

/// Most main exes reported for one app.
pub const MAX_MAIN_EXES: usize = 4;
/// Most subfolders of `InstallLocation` that are listed.
const MAX_SUBDIRS: usize = 64;
/// Most candidates whose version resource is read.
const MAX_CANDIDATES: usize = 64;

/// Why an executable counts as a main exe; see the module documentation. Ordered strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MainExeBasis {
    /// The `DisplayIcon` value of the Uninstall key names it.
    DisplayIcon,
    /// Its file name shares a token with the app's registry names.
    FileName,
    /// Its `ProductName` or `FileDescription` shares a token with the app's registry names.
    VersionInfo,
    /// Only the largest candidate; nothing relates it to the app's names.
    LargestOnly,
}

impl MainExeBasis {
    /// Whether names and vendors may be read from an exe selected on this basis.
    pub fn is_related(self) -> bool {
        self != MainExeBasis::LargestOnly
    }
}

/// One main exe of an app.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MainExe {
    /// Absolute path, as built from the key's values and the directory listing.
    pub path: String,
    /// Why it was selected.
    pub basis: MainExeBasis,
    /// File size in bytes; 0 when unknown.
    pub size: u64,
    /// The file name without `.exe`.
    pub stem: String,
    /// Its version resource, when it has one and the source could read it.
    pub version_info: Option<VersionInfo>,
    /// The subject CN of its Authenticode signer, when signed and readable.
    pub signer_cn: Option<String>,
}

/// What the selection needs from the Uninstall key.
pub(crate) struct ExeQuery<'a> {
    pub install_location: Option<&'a str>,
    pub display_icon: Option<&'a str>,
    pub uninstaller_exe: Option<&'a str>,
    /// Cleaned, non-shared `InstallLocation`s of the other installed entries; see [`foreign_roots`].
    pub foreign_roots: &'a [String],
    pub env: &'a EnvMap,
}

/// The usable `InstallLocation`s among `locations` (raw values of other entries): cleaned, not shared.
pub(crate) fn foreign_roots<'a>(
    locations: impl Iterator<Item = &'a str>,
    env: &EnvMap,
) -> Vec<String> {
    locations
        .filter_map(|l| clean_path(l, env))
        .filter(|l| !is_shared_location(l))
        .collect()
}

/// Whether `path` is `root` or lies below it (both cleaned; separator-aware, case-insensitive).
fn is_under(path: &str, root: &str) -> bool {
    let (path, root) = (path.to_lowercase(), root.to_lowercase());
    path.strip_prefix(root.as_str())
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('\\'))
}

/// An absolute drive path from a raw key value: quotes trimmed, environment variables expanded, `/`
/// turned into `\`, trailing separators removed. `None` when the result is not `X:\…`, is a bare drive
/// root, still holds a `%`, or has a segment that Win32 would rewrite or reject (ending in a dot or a
/// space, which covers `.` and `..`, or holding one of `: * ? " < > |` or a control character).
pub(crate) fn clean_path(raw: &str, env: &EnvMap) -> Option<String> {
    let s = raw.trim().trim_matches('"').trim();
    if s.is_empty() {
        return None;
    }
    let s = if s.contains('%') && !env.is_empty() {
        expand_with(s, env)
    } else {
        s.to_owned()
    };
    if s.contains('%') {
        return None;
    }
    // One separator style and no doubled separators (sloppy installers write `C:\Dir\\App`).
    let mut s = s.replace('/', "\\");
    while s.contains("\\\\") {
        s = s.replace("\\\\", "\\");
    }
    let s = s.trim_end_matches('\\');
    let b = s.as_bytes();
    if b.len() < 4 || !b[0].is_ascii_alphabetic() || b[1] != b':' || b[2] != b'\\' {
        return None;
    }
    let bad_segment = |seg: &str| {
        seg.ends_with(['.', ' '])
            || seg.contains([':', '*', '?', '"', '<', '>', '|'])
            || seg.chars().any(char::is_control)
    };
    if s[3..].split('\\').any(bad_segment) {
        return None;
    }
    Some(s.to_owned())
}

/// The file a `DisplayIcon` value names: the value without a trailing `,<index>`.
pub(crate) fn icon_target(raw: &str, env: &EnvMap) -> Option<String> {
    let s = raw.trim();
    let s = match s.rfind(',') {
        Some(i) if s[i + 1..].trim().parse::<i64>().is_ok() => &s[..i],
        _ => s,
    };
    clean_path(s, env)
}

fn eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Whether a cleaned path is, lexically, a location shared by many programs, whose executables say nothing
/// about one app. The harvest's `validate_root` is the real check; this only keeps identity resolution from
/// reading names out of such a folder.
pub(crate) fn is_shared_location(path: &str) -> bool {
    let segs: Vec<&str> = path.split('\\').filter(|s| !s.is_empty()).collect();
    match segs.as_slice() {
        [] | [_] => true,
        [_, top, rest @ ..] => {
            if eq(top, "Windows") {
                return true;
            }
            // `PROGRA~1`, `PROGRA~2`: the 8.3 names of the Program Files folders.
            let short_program_files =
                top.len() > 7 && top.get(..7).is_some_and(|p| eq(p, "PROGRA~"));
            if eq(top, "Program Files") || eq(top, "Program Files (x86)") || short_program_files {
                return rest.is_empty() || (rest.len() == 1 && eq(rest[0], "Common Files"));
            }
            if eq(top, "ProgramData") {
                return rest.is_empty()
                    || (rest.len() == 1
                        && (eq(rest[0], "Microsoft") || eq(rest[0], "Package Cache")));
            }
            if eq(top, "Users") || eq(top, "Documents and Settings") {
                return match rest {
                    // `Users`, `Users\<name>`, `Users\<name>\<known folder>`
                    [] | [_] | [_, _] => true,
                    [_, appdata, _] if eq(appdata, "AppData") => true,
                    // `AppData\Local\Programs`, the temp folder and the folders every program shares.
                    [_, appdata, _, last] => {
                        eq(appdata, "AppData")
                            && ["Programs", "Temp", "Microsoft", "Packages"]
                                .iter()
                                .any(|k| eq(last, k))
                    }
                    _ => false,
                };
            }
            false
        }
    }
}

/// Whether a cleaned path lies in the Windows directory tree (lexically).
fn in_windows_tree(path: &str) -> bool {
    path.split('\\').nth(1).is_some_and(|s| eq(s, "Windows"))
}

fn exe_stem(name: &str) -> Option<&str> {
    let n = name.len();
    (n > 4 && name.is_char_boundary(n - 4) && eq(&name[n - 4..], ".exe")).then(|| &name[..n - 4])
}

fn file_name(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

fn is_uninstaller(path: &str, uninstaller: Option<&str>) -> bool {
    if uninstaller.is_some_and(|u| eq(u, path)) {
        return true;
    }
    file_name(path).get(..5).is_some_and(|p| eq(p, "unins"))
}

struct Candidate {
    path: String,
    size: u64,
    stem: String,
    icon: bool,
}

/// Collects candidates without duplicates (case-insensitive path) and without uninstallers.
struct Candidates<'a> {
    uninstaller: Option<&'a str>,
    seen: BTreeSet<String>,
    list: Vec<Candidate>,
}

impl Candidates<'_> {
    fn push(&mut self, path: String, size: u64, icon: bool) {
        let Some(stem) = exe_stem(file_name(&path)).map(str::to_owned) else {
            return;
        };
        if is_uninstaller(&path, self.uninstaller) || !self.seen.insert(path.to_lowercase()) {
            return;
        }
        self.list.push(Candidate {
            path,
            size,
            stem,
            icon,
        });
    }
}

fn warn(warnings: &mut Vec<String>, what: &str, path: &str, error: &SourceError) {
    if *error != SourceError::NotFound {
        warnings.push(format!("identity: cannot read {what} of {path}: {error}"));
    }
}

/// Selects the main exes; see the module documentation. `related` says whether a string shares a token
/// with the app's registry names. Read problems are appended to `warnings` and never fail the selection.
pub(crate) fn select(
    fs: &dyn FileSystemSource,
    query: &ExeQuery<'_>,
    related: &dyn Fn(&str) -> bool,
    warnings: &mut Vec<String>,
) -> Vec<MainExe> {
    let uninstaller = query.uninstaller_exe.and_then(|u| clean_path(u, query.env));
    let mut found = Candidates {
        uninstaller: uninstaller.as_deref(),
        seen: BTreeSet::new(),
        list: Vec::new(),
    };

    let own = query
        .install_location
        .and_then(|l| clean_path(l, query.env));
    let foreign = |path: &str| {
        query.foreign_roots.iter().any(|r| is_under(path, r))
            && !own.as_deref().is_some_and(|o| is_under(path, o))
    };

    // The DisplayIcon target first, so that it wins the de-duplication against the directory listing.
    if let Some(icon) = query.display_icon.and_then(|i| icon_target(i, query.env))
        && exe_stem(file_name(&icon)).is_some()
        && !in_windows_tree(&icon)
        && !foreign(&icon)
    {
        match fs.metadata(&icon) {
            Ok(meta) if !meta.is_dir() => found.push(icon, meta.size, true),
            Ok(_) => {}
            Err(e) => warn(warnings, "the DisplayIcon target", &icon, &e),
        }
    }

    let root = own.clone().filter(|l| !is_shared_location(l));
    if let Some(root) = root {
        match fs.list_dir(&root) {
            Ok(entries) => {
                let mut subdirs = Vec::new();
                for e in entries {
                    if e.meta.is_reparse_point() {
                        continue;
                    }
                    let path = format!("{root}\\{}", e.name);
                    if e.meta.is_dir() {
                        subdirs.push(path);
                    } else {
                        found.push(path, e.meta.size, false);
                    }
                }
                for dir in subdirs.into_iter().take(MAX_SUBDIRS) {
                    match fs.list_dir(&dir) {
                        Ok(entries) => {
                            for e in entries {
                                if !e.meta.is_dir() && !e.meta.is_reparse_point() {
                                    found.push(format!("{dir}\\{}", e.name), e.meta.size, false);
                                }
                            }
                        }
                        Err(e) => warn(warnings, "the listing", &dir, &e),
                    }
                }
            }
            Err(e) => warn(warnings, "the listing", &root, &e),
        }
    }

    // Facts are read for the most promising candidates only: the icon target, then related file names,
    // then by size.
    let mut candidates = found.list;
    candidates.sort_by(|a, b| {
        let key = |c: &Candidate| (!c.icon, !related(&c.stem));
        key(a)
            .cmp(&key(b))
            .then(b.size.cmp(&a.size))
            .then_with(|| a.path.to_lowercase().cmp(&b.path.to_lowercase()))
    });
    candidates.truncate(MAX_CANDIDATES);

    let mut picked: Vec<MainExe> = Vec::new();
    let mut largest: Option<&Candidate> = None;
    for c in &candidates {
        let version_info = match fs.version_info(&c.path) {
            Ok(v) => v,
            Err(e) => {
                warn(warnings, "the version resource", &c.path, &e);
                None
            }
        };
        let vi_related = version_info.as_ref().is_some_and(|v| {
            [&v.product_name, &v.file_description]
                .into_iter()
                .flatten()
                .any(|s| related(s))
        });
        let basis = if c.icon {
            MainExeBasis::DisplayIcon
        } else if related(&c.stem) {
            MainExeBasis::FileName
        } else if vi_related {
            MainExeBasis::VersionInfo
        } else {
            if largest.is_none_or(|l| c.size > l.size) {
                largest = Some(c);
            }
            continue;
        };
        picked.push(MainExe {
            path: c.path.clone(),
            basis,
            size: c.size,
            stem: c.stem.clone(),
            version_info,
            signer_cn: None,
        });
    }
    picked.sort_by(|a, b| {
        a.basis
            .cmp(&b.basis)
            .then(b.size.cmp(&a.size))
            .then_with(|| a.path.to_lowercase().cmp(&b.path.to_lowercase()))
    });
    picked.truncate(MAX_MAIN_EXES);
    for exe in &mut picked {
        match fs.signer_cn(&exe.path) {
            Ok(cn) => exe.signer_cn = cn.filter(|s| !s.trim().is_empty()),
            Err(e) => warn(warnings, "the signer", &exe.path, &e),
        }
    }
    if picked.is_empty()
        && let Some(c) = largest
    {
        picked.push(MainExe {
            path: c.path.clone(),
            basis: MainExeBasis::LargestOnly,
            size: c.size,
            stem: c.stem.clone(),
            version_info: None,
            signer_cn: None,
        });
    }
    picked
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> EnvMap {
        let mut e = EnvMap::new();
        e.insert("LOCALAPPDATA", "C:\\Users\\kaan\\AppData\\Local");
        e
    }

    #[test]
    fn clean_path_forms() {
        let none = EnvMap::new();
        assert_eq!(
            clean_path(" \"C:\\Program Files\\App\\\" ", &none).as_deref(),
            Some("C:\\Program Files\\App")
        );
        assert_eq!(
            clean_path("C:/Apps/Tool/", &none).as_deref(),
            Some("C:\\Apps\\Tool")
        );
        assert_eq!(
            clean_path("%LocalAppData%\\Programs\\X", &env()).as_deref(),
            Some("C:\\Users\\kaan\\AppData\\Local\\Programs\\X")
        );
        assert_eq!(clean_path("%LocalAppData%\\Programs\\X", &none), None);
        assert_eq!(clean_path("%UNKNOWN%\\X", &env()), None);
        assert_eq!(clean_path("", &none), None);
        assert_eq!(clean_path("C:\\", &none), None);
        assert_eq!(clean_path("C:", &none), None);
        assert_eq!(clean_path("relative\\x", &none), None);
        assert_eq!(clean_path("\\\\server\\share\\x", &none), None);
        assert_eq!(clean_path("C:\\a\\..\\Windows", &none), None);
        // Win32 would rewrite or reject these; the lexical checks must not see a different path.
        for p in [
            "C:\\Windows.\\System32",
            "C:\\Program Files \\App",
            "C:\\Program Files.",
            "C:\\a\\.\\b",
            "C:\\a\\b:stream",
            "C:\\a\\*",
            "C:\\a\\b\tc",
        ] {
            assert_eq!(clean_path(p, &none), None, "{p}");
        }
        assert_eq!(
            clean_path("C:\\a\\\\\\b//c\\\\", &none).as_deref(),
            Some("C:\\a\\b\\c")
        );
        assert_eq!(
            clean_path("C:\\PROGRA~1\\App v1.2", &none).as_deref(),
            Some("C:\\PROGRA~1\\App v1.2")
        );
    }

    #[test]
    fn icon_target_forms() {
        let none = EnvMap::new();
        assert_eq!(
            icon_target("C:\\Program Files\\Mozilla Firefox\\firefox.exe,0", &none).as_deref(),
            Some("C:\\Program Files\\Mozilla Firefox\\firefox.exe")
        );
        assert_eq!(
            icon_target("\"C:\\A B\\x.exe\",-101", &none).as_deref(),
            Some("C:\\A B\\x.exe")
        );
        assert_eq!(
            icon_target("C:\\A\\x.exe", &none).as_deref(),
            Some("C:\\A\\x.exe")
        );
        // A comma inside the path is not an icon index.
        assert_eq!(
            icon_target("C:\\A, B\\x.exe", &none).as_deref(),
            Some("C:\\A, B\\x.exe")
        );
    }

    #[test]
    fn shared_locations() {
        for p in [
            "C:\\Windows",
            "C:\\Windows\\System32",
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "C:\\Program Files\\Common Files",
            "C:\\ProgramData",
            "C:\\ProgramData\\Package Cache",
            "C:\\Users",
            "C:\\Users\\kaan",
            "C:\\Users\\kaan\\Desktop",
            "C:\\Users\\kaan\\AppData\\Local",
            "C:\\Users\\kaan\\AppData\\Local\\Programs",
            "C:\\Users\\kaan\\AppData\\Local\\Temp",
            "C:\\Users\\kaan\\AppData\\Roaming\\Microsoft",
            "C:\\PROGRA~1",
            "C:\\progra~2\\Common Files",
        ] {
            assert!(is_shared_location(p), "{p}");
        }
        for p in [
            "C:\\Git",
            "C:\\Program Files\\Git",
            "C:\\Program Files\\Common Files\\Vendor",
            "C:\\ProgramData\\Vendor",
            "C:\\Users\\kaan\\AppData\\Local\\Programs\\Microsoft VS Code",
            "C:\\Users\\kaan\\AppData\\Local\\Vendor",
            "D:\\Tools\\App",
            "C:\\PROGRA~1\\App",
            "C:\\Users\\kaan\\AppData\\Local\\Temp\\App",
        ] {
            assert!(!is_shared_location(p), "{p}");
        }
    }

    #[test]
    fn under_is_separator_aware() {
        assert!(is_under("C:\\Apps\\Host\\host.exe", "c:\\apps\\HOST"));
        assert!(is_under("C:\\Apps\\Host", "C:\\Apps\\Host"));
        assert!(!is_under("C:\\Apps\\Host2\\x.exe", "C:\\Apps\\Host"));
        assert!(!is_under("C:\\Apps", "C:\\Apps\\Host"));
        let none = EnvMap::new();
        assert_eq!(
            foreign_roots(
                ["C:\\Program Files", "\"C:\\Apps\\Host\\\"", "%X%\\y", ""].into_iter(),
                &none
            ),
            ["C:\\Apps\\Host"]
        );
    }

    #[test]
    fn uninstallers_and_stems() {
        assert!(is_uninstaller("C:\\A\\unins000.exe", None));
        assert!(is_uninstaller("C:\\A\\Uninstall.exe", None));
        assert!(is_uninstaller(
            "C:\\A\\helper.exe",
            Some("c:\\a\\HELPER.exe")
        ));
        assert!(!is_uninstaller("C:\\A\\app.exe", Some("C:\\A\\helper.exe")));
        assert_eq!(exe_stem("Code.EXE"), Some("Code"));
        assert_eq!(exe_stem("notepad++.exe"), Some("notepad++"));
        assert_eq!(exe_stem(".exe"), None);
        assert_eq!(exe_stem("readme.txt"), None);
    }
}
