//! FS-INSTALLDIR (ENGINE_PLAN.md §5.6): what is left of a validated InstallRoot (`InsideInstallRoot`,
//! needs verify-gone).
//!
//! # What the scanner offers
//!
//! - **An InstallRoot that still exists** is offered whole (quarantine the directory). The evidence is
//!   `InsideInstallRoot`; the candidate is `NotGone` unless the uninstall was observed and passed
//!   verify-gone, and also when a running process has its image inside the root (or the process list
//!   cannot be read). Another app's uninstaller or icon inside the root gives `ContainsOtherApp` through
//!   the common blockers. A file created or written after the uninstall ended gives the
//!   `ModifiedAfterUninstall` negative and the `UnmatchedChildren` soft blocker: something is still
//!   writing there.
//! - **An InferredRoot is never offered whole** (§5.2 "Root kinds"). Only descendants the Inno uninstall
//!   log names are offered, each with its own `InstallerManifest` evidence.
//! - A referenced data directory is not this scanner's business.
//!
//! The file also holds the helpers the file-system scanners of this crate share: known locations
//! ([`Places`]), bounded directory reads ([`list`], [`measure`]) and small path utilities.

use std::collections::BTreeMap;

use purge_guard::prefix;
use purge_model::{
    Action, Blocker, Candidate, Category, EvidenceKind, Facts, FileTime, InnoRecordKind, Root,
    RootKind, Target,
};
use purge_source::types::{DirEntry, FileMeta, KnownFolder, ProcessInfo, SourceResult};

use crate::framework::{AppIdentityView, CandidateBuilder, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "FS-INSTALLDIR";

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[
    RootSpec::fs(r"%ProgramFiles%", None),
    RootSpec::fs(r"%ProgramData%", None),
    RootSpec::fs(r"%USERPROFILE%", None),
];

/// The FS-INSTALLDIR scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsInstallDir;

impl Scanner for FsInstallDir {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
        let mut out = Vec::new();
        let processes = ctx.sys.processes();
        for root in &ctx.fp.roots {
            match root.kind {
                RootKind::InstallRoot => whole_root(ctx, root, &processes, &mut out),
                RootKind::InferredRoot => owned_descendants(ctx, root, &processes, &mut out),
                RootKind::ReferencedDataDir => {}
            }
        }
        out
    }
}

/// Offers a still existing InstallRoot as one directory.
fn whole_root(
    ctx: &ScanCtx<'_>,
    root: &Root,
    processes: &SourceResult<Vec<ProcessInfo>>,
    out: &mut Vec<Candidate>,
) {
    let Ok(meta) = ctx.fs.metadata(&root.path) else {
        return;
    };
    if !meta.is_dir() {
        return;
    }
    let mut b = ctx.candidate(
        ID,
        Target::Path {
            path: root.path.clone(),
        },
        Action::Quarantine,
        Category::AppFiles,
    );
    if !b.inside_install_root() {
        return;
    }
    b.require_verify_gone().common_blockers();
    live_blockers(ctx, &mut b, &root.path, processes);
    if meta.is_reparse_point() {
        // The directory the installer named is now a link to somewhere else: nothing behind it is
        // proven to be the app's.
        b.blocker(Blocker::ReparseMismatch);
    }
    let measured = measure(ctx, &root.path, &meta);
    sized(&mut b, &measured);
    if measured.modified_after > 0 {
        let mut detail = Facts::new().with("root", root.path.clone());
        if let Some(path) = &measured.first_modified_after {
            detail = detail.with("path", path.clone());
        }
        b.negative(EvidenceKind::ModifiedAfterUninstall, detail);
        b.blocker(Blocker::UnmatchedChildren {
            n: measured.modified_after,
        });
    }
    emit(out, b);
}

/// Offers what the Inno log names under an InferredRoot; the root itself is never a target.
fn owned_descendants(
    ctx: &ScanCtx<'_>,
    root: &Root,
    processes: &SourceResult<Vec<ProcessInfo>>,
    out: &mut Vec<Candidate>,
) {
    for record in &ctx.fp.inno {
        let Target::Path { path } = &record.target else {
            continue;
        };
        let is_file_record = match record.kind {
            InnoRecordKind::DeleteFile => true,
            InnoRecordKind::DeleteDirOrFiles => false,
            _ => continue,
        };
        if record.existed_before
            || record.shared
            || has_dot_segment(path)
            || !prefix::is_inside(path, &root.path)
            || ctx.inside_install_root(path).is_some()
        {
            continue;
        }
        let Ok(meta) = ctx.fs.metadata(path) else {
            continue;
        };
        // A file record on what is a directory: the uninstaller would not have removed the tree.
        if meta.is_reparse_point() || (is_file_record && meta.is_dir()) {
            continue;
        }
        let mut b = ctx.candidate(
            ID,
            Target::Path { path: path.clone() },
            Action::Quarantine,
            Category::AppFiles,
        );
        if !b.installer_manifest() {
            continue;
        }
        b.require_verify_gone().common_blockers();
        live_blockers(ctx, &mut b, path, processes);
        sized(&mut b, &measure(ctx, path, &meta));
        // Carry-over rule (§5.5): the record on a directory says nothing about files in it that the log
        // does not name itself (a `[Dirs]` entry is only removed when empty), and an InferredRoot gives
        // them no cover either. Such a directory is offered unchecked.
        if meta.is_dir() {
            let undeclared = undeclared_files(ctx, path);
            if undeclared > 0 {
                b.blocker(Blocker::UnmatchedChildren { n: undeclared });
            }
        }
        emit(out, b);
    }
}

/// The number of files under `dir` that no file record of the Inno log names. Files in directories the
/// bounded walk could not read are not counted here; [`sized`] flags such a walk as `TooLarge`.
fn undeclared_files(ctx: &ScanCtx<'_>, dir: &str) -> u32 {
    let declared = |file: &str| {
        ctx.fp.inno.iter().any(|r| {
            r.kind == InnoRecordKind::DeleteFile
                && !r.existed_before
                && !r.shared
                && matches!(&r.target, Target::Path { path } if prefix::is_same(path, file))
        })
    };
    let mut count = 0u32;
    let mut visited = 0usize;
    let mut stack = vec![(dir.trim_end_matches(prefix::SEP).to_owned(), 0u32)];
    while let Some((dir, depth)) = stack.pop() {
        let Some(entries) = list(ctx, &dir) else {
            continue;
        };
        for entry in entries {
            visited += 1;
            if visited > ctx.limits.max_walk_entries {
                return count;
            }
            let child = join(&dir, &entry.name);
            if is_plain_dir(&entry.meta) {
                if depth + 1 < ctx.limits.max_depth {
                    stack.push((child, depth + 1));
                }
            } else if !declared(&child) {
                count = count.saturating_add(1);
            }
        }
    }
    count
}

/// `NotGone` and `InUse` when a running process has its image at or under `path`, or when the process
/// list cannot be read (the precondition "nothing of the app runs" is then unproven).
fn live_blockers(
    ctx: &ScanCtx<'_>,
    b: &mut CandidateBuilder<'_>,
    path: &str,
    processes: &SourceResult<Vec<ProcessInfo>>,
) {
    match processes {
        Ok(list) => {
            if list.iter().any(|p| runs_inside(ctx, p, path)) {
                b.blocker(Blocker::InUse).blocker(Blocker::NotGone);
            }
        }
        Err(_) => {
            b.blocker(Blocker::NotGone);
        }
    }
}

/// Whether a process image lies at or under `path`. A process whose image path could not be read counts
/// when its image name is the name of a file of the app's exe set under `path`.
fn runs_inside(ctx: &ScanCtx<'_>, process: &ProcessInfo, path: &str) -> bool {
    match &process.path {
        Some(image) => prefix::is_same_or_inside(image, path),
        None => ctx.fp.exes.iter().any(|exe| {
            prefix::is_same_or_inside(&exe.path, path)
                && prefix::leaf(&exe.path).is_some_and(|name| prefix::eq_ci(name, &process.name))
        }),
    }
}

// ---------------------------------------------------------------------------------------------------------
// Shared helpers of the file-system scanners
// ---------------------------------------------------------------------------------------------------------

/// Finishes a candidate and adds it to `out`.
///
/// A candidate that lies inside another app's root or key is dropped rather than listed as protected:
/// nothing of another installed app is shown among this app's leftovers (§1.4). A target that an earlier
/// candidate of the same scanner already covers is not added twice.
pub(crate) fn emit(out: &mut Vec<Candidate>, builder: CandidateBuilder<'_>) -> bool {
    let candidate = builder.build();
    let foreign = candidate
        .blockers
        .iter()
        .any(|b| matches!(b, Blocker::InsideOtherApp { .. }));
    if foreign || out.iter().any(|c| c.id == candidate.id) {
        return false;
    }
    out.push(candidate);
    true
}

/// `dir\name`.
pub(crate) fn join(dir: &str, name: &str) -> String {
    format!("{}{}{name}", dir.trim_end_matches(prefix::SEP), prefix::SEP)
}

/// The extension of a file name, without the dot; `None` for a name without one or a dot-file.
pub(crate) fn extension(name: &str) -> Option<&str> {
    match name.rfind('.') {
        Some(at) if at > 0 && at + 1 < name.len() => Some(&name[at + 1..]),
        _ => None,
    }
}

/// A file name without its extension.
pub(crate) fn stem(name: &str) -> &str {
    match extension(name) {
        Some(ext) => &name[..name.len() - ext.len() - 1],
        None => name,
    }
}

/// Whether `name` has one of the extensions `exts` (lower case, without dot).
pub(crate) fn has_extension(name: &str, exts: &[&str]) -> bool {
    extension(name).is_some_and(|ext| exts.iter().any(|want| ext.eq_ignore_ascii_case(want)))
}

/// Whether `token` occurs in `name` as a delimited part: not directly preceded or followed by a letter
/// or digit. Case-insensitive.
pub(crate) fn contains_delimited(name: &str, token: &str) -> bool {
    let (name, token) = (prefix::fold(name), prefix::fold(token));
    if token.is_empty() {
        return false;
    }
    name.match_indices(&token).any(|(at, hit)| {
        let before = name[..at].chars().next_back();
        let after = name[at + hit.len()..].chars().next();
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    })
}

/// An absolute drive path without a trailing separator, or `None` when `path` is not one (relative, UNC,
/// a device path, still holding an unexpanded `%NAME%`, or with a `.`/`..` segment).
pub(crate) fn clean_path(path: &str) -> Option<String> {
    let p = path.trim().trim_matches('"').trim().replace('/', "\\");
    let p = p.trim_end_matches(prefix::SEP);
    let bytes = p.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if !drive || (bytes.len() > 2 && bytes[2] != b'\\') || p.contains('%') || has_dot_segment(p) {
        return None;
    }
    Some(p.to_owned())
}

/// Whether a path has a segment made of dots only (`.`, `..`, `...`). Prefix tests are lexical, so such
/// a path can read as "inside" a directory it leaves; it is never accepted as a location (the guard's
/// canonicaliser refuses it as well).
pub(crate) fn has_dot_segment(path: &str) -> bool {
    path.split(['\\', '/'])
        .any(|segment| !segment.is_empty() && segment.bytes().all(|b| b == b'.'))
}

/// Expands `%NAME%` references from `env` (names upper-cased, as in [`ScanCtx::env`]). An unknown name
/// is left as written.
pub(crate) fn expand_env(s: &str, env: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => match env.get(&after[..end].to_uppercase()) {
                Some(value) if end > 0 => {
                    out.push_str(value);
                    rest = &after[end + 1..];
                }
                _ => {
                    out.push('%');
                    rest = after;
                }
            },
            None => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The direct entries of a directory, or `None` when it cannot be read completely (an error, a reparse
/// point, or more entries than [`ScanLimits::max_dir_entries`](crate::framework::ScanLimits)).
pub(crate) fn list(ctx: &ScanCtx<'_>, dir: &str) -> Option<Vec<DirEntry>> {
    let entries = ctx.fs.list_dir(dir).ok()?;
    (entries.len() <= ctx.limits.max_dir_entries).then_some(entries)
}

/// Whether a directory entry is a real directory (not a reparse point).
pub(crate) fn is_plain_dir(meta: &FileMeta) -> bool {
    meta.is_dir() && !meta.is_reparse_point()
}

/// File extensions that make a directory "hold executables" (`ExecutablesPresent`).
const EXECUTABLE_EXTS: &[&str] = &["exe", "dll", "sys", "com", "scr", "ocx", "cpl", "msi"];

/// What a bounded walk of a file or directory found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Measure {
    /// Files (and reparse points, which are not followed) at or under the path.
    pub(crate) files: u32,
    /// Their total size.
    pub(crate) bytes: u64,
    /// Files with an executable extension.
    pub(crate) executables: u32,
    /// Files created or written after the uninstall ended (`t_end` of the fingerprint's window).
    pub(crate) modified_after: u32,
    /// The first such file.
    pub(crate) first_modified_after: Option<String>,
    /// Whether everything was read: no unreadable directory and no limit reached.
    pub(crate) complete: bool,
}

impl Measure {
    fn note_file(&mut self, path: &str, name: &str, meta: &FileMeta, t_end: Option<FileTime>) {
        self.files = self.files.saturating_add(1);
        self.bytes = self.bytes.saturating_add(meta.size);
        if has_extension(name, EXECUTABLE_EXTS) {
            self.executables = self.executables.saturating_add(1);
        }
        let after = |t: Option<FileTime>| matches!((t, t_end), (Some(t), Some(end)) if t > end);
        if after(meta.times.modified) || after(meta.times.created) {
            self.modified_after = self.modified_after.saturating_add(1);
            self.first_modified_after
                .get_or_insert_with(|| path.to_owned());
        }
    }
}

/// Counts and sizes `path` (whose metadata is `meta`) without following reparse points, within the
/// context's read limits.
pub(crate) fn measure(ctx: &ScanCtx<'_>, path: &str, meta: &FileMeta) -> Measure {
    let t_end = ctx.fp.window.t_end;
    let mut m = Measure {
        complete: true,
        ..Measure::default()
    };
    if !is_plain_dir(meta) {
        m.note_file(path, prefix::leaf(path).unwrap_or(""), meta, t_end);
        return m;
    }
    let mut stack = vec![(path.trim_end_matches(prefix::SEP).to_owned(), 0u32)];
    let mut visited = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let Some(entries) = list(ctx, &dir) else {
            m.complete = false;
            continue;
        };
        for entry in entries {
            visited += 1;
            if visited > ctx.limits.max_walk_entries {
                m.complete = false;
                return m;
            }
            let child = join(&dir, &entry.name);
            if is_plain_dir(&entry.meta) {
                if depth + 1 >= ctx.limits.max_depth {
                    m.complete = false;
                } else {
                    stack.push((child, depth + 1));
                }
            } else {
                m.note_file(&child, &entry.name, &entry.meta, t_end);
            }
        }
    }
    m
}

/// Records the measured size and file count on a candidate. A walk that could not finish gives the
/// `TooLarge` soft blocker, because the blast-radius limits of `purge-plan` would otherwise see too small
/// a number.
pub(crate) fn sized(b: &mut CandidateBuilder<'_>, measured: &Measure) {
    b.size_bytes(measured.bytes).child_count(measured.files);
    if !measured.complete {
        b.blocker(Blocker::TooLarge);
    }
}

/// The directories the file-system scanners look in, for the interactive user and the machine.
///
/// Each comes from the source's known folders, then from the interactive user's environment, then from
/// the guard's machine layout; a location none of them knows is `None` and is not scanned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Places {
    /// `%USERPROFILE%`.
    pub(crate) profile: Option<String>,
    /// `%APPDATA%`.
    pub(crate) roaming: Option<String>,
    /// `%LOCALAPPDATA%`.
    pub(crate) local: Option<String>,
    /// `%USERPROFILE%\AppData\LocalLow`.
    pub(crate) local_low: Option<String>,
    /// `%ProgramData%`.
    pub(crate) program_data: Option<String>,
    /// The Program Files directories, native first.
    pub(crate) program_files: Vec<String>,
    /// The user's Start Menu.
    pub(crate) start_menu: Option<String>,
    /// The all-users Start Menu.
    pub(crate) common_start_menu: Option<String>,
    /// The user's `Start Menu\Programs`.
    pub(crate) programs: Option<String>,
    /// The all-users `Start Menu\Programs`.
    pub(crate) common_programs: Option<String>,
    /// The user's Startup folder.
    pub(crate) startup: Option<String>,
    /// The all-users Startup folder.
    pub(crate) common_startup: Option<String>,
    /// The user's desktop.
    pub(crate) desktop: Option<String>,
    /// The public desktop.
    pub(crate) public_desktop: Option<String>,
    /// `%APPDATA%\Microsoft\Internet Explorer\Quick Launch` (holds `User Pinned\TaskBar` and
    /// `ImplicitAppShortcuts`).
    pub(crate) quick_launch: Option<String>,
}

impl Places {
    /// Resolves the locations for the context's interactive user.
    pub(crate) fn of(ctx: &ScanCtx<'_>) -> Self {
        let known = ctx.sys.known_folders().unwrap_or_default();
        let folder = |k: KnownFolder| known.get(&k).and_then(|p| clean_path(p));
        let env = |name: &str| ctx.env.get(name).and_then(|p| clean_path(p));
        let user = ctx.guard.profile(&ctx.fp.user_sid);
        let guard_path = |p: &str| clean_path(p);
        let under = |base: &Option<String>, rest: &str| base.as_deref().map(|b| join(b, rest));

        let profile = folder(KnownFolder::Profile)
            .or_else(|| env("USERPROFILE"))
            .or_else(|| user.and_then(|u| guard_path(&u.root)));
        let roaming = folder(KnownFolder::RoamingAppData)
            .or_else(|| env("APPDATA"))
            .or_else(|| user.and_then(|u| guard_path(&u.appdata)));
        let local = folder(KnownFolder::LocalAppData)
            .or_else(|| env("LOCALAPPDATA"))
            .or_else(|| user.and_then(|u| guard_path(&u.local_appdata)));
        let local_low =
            folder(KnownFolder::LocalAppDataLow).or_else(|| under(&profile, r"AppData\LocalLow"));
        let program_data = folder(KnownFolder::ProgramData)
            .or_else(|| env("PROGRAMDATA"))
            .or_else(|| guard_path(&ctx.guard.program_data));

        let mut program_files: Vec<String> = Vec::new();
        let candidates = [
            folder(KnownFolder::ProgramFiles),
            folder(KnownFolder::ProgramFilesX86),
        ]
        .into_iter()
        .flatten()
        .chain(ctx.guard.program_files_dirs().filter_map(guard_path));
        for dir in candidates {
            if !program_files.iter().any(|d| prefix::is_same(d, &dir)) {
                program_files.push(dir);
            }
        }

        let start_menu = folder(KnownFolder::StartMenu)
            .or_else(|| under(&roaming, r"Microsoft\Windows\Start Menu"));
        let common_start_menu = folder(KnownFolder::CommonStartMenu)
            .or_else(|| under(&program_data, r"Microsoft\Windows\Start Menu"));
        let programs = folder(KnownFolder::Programs).or_else(|| under(&start_menu, "Programs"));
        let common_programs =
            folder(KnownFolder::CommonPrograms).or_else(|| under(&common_start_menu, "Programs"));
        let startup = folder(KnownFolder::Startup).or_else(|| under(&programs, "Startup"));
        let common_startup =
            folder(KnownFolder::CommonStartup).or_else(|| under(&common_programs, "Startup"));
        let desktop = folder(KnownFolder::Desktop).or_else(|| under(&profile, "Desktop"));
        let public = folder(KnownFolder::Public)
            .or_else(|| env("PUBLIC"))
            .or_else(|| guard_path(&ctx.guard.profiles_dir).map(|d| join(&d, "Public")));
        let public_desktop =
            folder(KnownFolder::PublicDesktop).or_else(|| under(&public, "Desktop"));
        let quick_launch = under(&roaming, r"Microsoft\Internet Explorer\Quick Launch");

        Self {
            profile,
            roaming,
            local,
            local_low,
            program_data,
            program_files,
            start_menu,
            common_start_menu,
            programs,
            common_programs,
            startup,
            common_startup,
            desktop,
            public_desktop,
            quick_launch,
        }
    }

    /// The application-data bases FS-APPDATA and FS-VENDORPARENT read: roaming, local, LocalLow and
    /// ProgramData, without duplicates.
    pub(crate) fn appdata_bases(&self) -> Vec<&str> {
        distinct([
            &self.roaming,
            &self.local,
            &self.local_low,
            &self.program_data,
        ])
    }

    /// Every directory FS-SHORTCUTS reads, with whether it is read recursively: the Start Menus, the
    /// desktops, Quick Launch and the Startup folders.
    pub(crate) fn shortcut_dirs(&self) -> Vec<(&str, bool)> {
        let recursive = distinct([
            &self.start_menu,
            &self.common_start_menu,
            &self.programs,
            &self.common_programs,
            &self.startup,
            &self.common_startup,
            &self.quick_launch,
        ]);
        let flat = distinct([&self.desktop, &self.public_desktop]);
        // A directory inside another recursive one is read with it.
        let mut out: Vec<(&str, bool)> = Vec::new();
        for dir in &recursive {
            if !recursive.iter().any(|other| prefix::is_inside(dir, other)) {
                out.push((dir, true));
            }
        }
        for dir in flat {
            if !recursive
                .iter()
                .any(|other| prefix::is_same_or_inside(dir, other))
            {
                out.push((dir, false));
            }
        }
        out
    }

    /// Whether `path` is one of the shortcut directories or lies in one.
    pub(crate) fn in_shortcut_dir(&self, path: &str) -> bool {
        self.shortcut_dirs()
            .iter()
            .any(|(dir, _)| prefix::is_same_or_inside(path, dir))
    }

    /// Whether `path` is one of the Startup folders or lies in one.
    pub(crate) fn in_startup(&self, path: &str) -> bool {
        [&self.startup, &self.common_startup]
            .into_iter()
            .flatten()
            .any(|dir| prefix::is_same_or_inside(path, dir))
    }
}

/// The known ones of `dirs`, each once.
fn distinct<const N: usize>(dirs: [&Option<String>; N]) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    for dir in dirs.into_iter().flatten() {
        if !out.iter().any(|d| prefix::is_same(d, dir)) {
            out.push(dir);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::testkit::World;
    use purge_source::fixture::Fixture;

    #[test]
    fn names_and_extensions() {
        assert_eq!(extension("unins000.exe"), Some("exe"));
        assert_eq!(extension(".gitconfig"), None);
        assert_eq!(extension("name."), None);
        assert_eq!(extension("README"), None);
        assert_eq!(stem("Git Bash.lnk"), "Git Bash");
        assert_eq!(stem("a.tar.gz"), "a.tar");
        assert_eq!(stem("README"), "README");
        assert!(has_extension("App.EXE", &["exe"]));
        assert!(!has_extension("App.exe.txt", &["exe"]));
        assert_eq!(join(r"C:\A\", "b"), r"C:\A\b");
        assert!(contains_delimited("Mozilla-1de4eec8", "mozilla"));
        assert!(!contains_delimited("MozillaPlugins", "mozilla"));
        assert!(!contains_delimited("anything", ""));
    }

    #[test]
    fn clean_path_accepts_only_absolute_drive_paths() {
        assert_eq!(clean_path(r#" "C:\A\b\" "#).as_deref(), Some(r"C:\A\b"));
        assert_eq!(clean_path("C:/A/b").as_deref(), Some(r"C:\A\b"));
        assert_eq!(clean_path(r"C:\").as_deref(), Some("C:"));
        assert_eq!(clean_path(r"\\server\share\x"), None);
        assert_eq!(clean_path(r"relative\x"), None);
        assert_eq!(clean_path("C:relative"), None);
        assert_eq!(clean_path(r"%UNKNOWN%\x"), None);
        assert_eq!(clean_path(""), None);
        // Lexically inside `C:\Program Files\App`, really Windows' Notepad.
        assert_eq!(
            clean_path(r"C:\Program Files\App\..\..\Windows\System32\notepad.exe"),
            None
        );
        assert_eq!(clean_path(r"C:\A\.\b"), None);
        assert_eq!(clean_path("C:/A/../b"), None);
        assert_eq!(
            clean_path(r"C:\A\.config\b..c").as_deref(),
            Some(r"C:\A\.config\b..c")
        );
        assert!(has_dot_segment(r"C:\a\...\b"));
        assert!(!has_dot_segment(r"C:\a\.b\c."));
    }

    #[test]
    fn env_expansion() {
        let env: BTreeMap<String, String> = [
            ("WINDIR".to_owned(), r"C:\Windows".to_owned()),
            (
                "APPDATA".to_owned(),
                r"C:\Users\t\AppData\Roaming".to_owned(),
            ),
        ]
        .into();
        assert_eq!(
            expand_env(r"%windir%\system32\notepad.exe", &env),
            r"C:\Windows\system32\notepad.exe"
        );
        assert_eq!(
            expand_env(r"%AppData%\X;%APPDATA%", &env),
            r"C:\Users\t\AppData\Roaming\X;C:\Users\t\AppData\Roaming"
        );
        assert_eq!(expand_env(r"%NOPE%\x", &env), r"%NOPE%\x");
        assert_eq!(expand_env("100% sure", &env), "100% sure");
        assert_eq!(expand_env("%%", &env), "%%");
        assert_eq!(expand_env(r"50%WINDIR%", &env), r"50C:\Windows");
    }

    #[test]
    fn places_fall_back_to_the_guard_layout() {
        let world = World::new(Fixture::new());
        let places = Places::of(&world.ctx());
        assert_eq!(places.profile.as_deref(), Some(r"C:\Users\tester"));
        assert_eq!(
            places.roaming.as_deref(),
            Some(r"C:\Users\tester\AppData\Roaming")
        );
        assert_eq!(
            places.local_low.as_deref(),
            Some(r"C:\Users\tester\AppData\LocalLow")
        );
        assert_eq!(places.program_data.as_deref(), Some(r"C:\ProgramData"));
        assert_eq!(
            places.program_files,
            [r"C:\Program Files", r"C:\Program Files (x86)"]
        );
        assert_eq!(
            places.common_programs.as_deref(),
            Some(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs")
        );
        assert_eq!(
            places.public_desktop.as_deref(),
            Some(r"C:\Users\Public\Desktop")
        );
        let dirs = places.shortcut_dirs();
        assert!(dirs.contains(&(
            r"C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu",
            true
        )));
        assert!(dirs.contains(&(r"C:\Users\tester\Desktop", false)));
        // Programs and Startup are read with the Start Menu they lie in.
        assert!(!dirs.iter().any(|(d, _)| d.ends_with("Programs")));
        assert!(
            places
                .in_startup(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk")
        );
        assert!(places.in_shortcut_dir(r"C:\Users\Public\Desktop\x.lnk"));
        assert!(!places.in_shortcut_dir(r"C:\Users\tester\AppData\Roaming\App"));
    }

    #[test]
    fn measure_counts_without_following_reparse_points() {
        let fixture = Fixture::builder()
            .file(r"C:\Program Files\Git\git.exe", 100)
            .file(r"C:\Program Files\Git\doc\a.txt", 7)
            .reparse_dir(r"C:\Program Files\Git\link", 0xA000_0003)
            .file(r"C:\Program Files\Git\link\hidden.txt", 1_000)
            .build();
        let world = World::new(fixture);
        let ctx = world.ctx();
        let meta = ctx.fs.metadata(r"C:\Program Files\Git").unwrap();
        let m = measure(&ctx, r"C:\Program Files\Git", &meta);
        assert!(m.complete);
        assert_eq!((m.files, m.bytes, m.executables), (3, 107, 1));
        assert_eq!(m.modified_after, 0);

        let mut tight = ctx;
        tight.limits.max_walk_entries = 1;
        assert!(!measure(&tight, r"C:\Program Files\Git", &meta).complete);
    }
}
