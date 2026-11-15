//! Shared install directories (ENGINE_PLAN.md §5.2 "Root kinds"): an app installed into a folder that
//! already held other things.
//!
//! An InstallRoot stands for "everything in here is the app's": a file in it is an anchor, a reference
//! into it is Tier A, and what is left of it is offered whole. That holds for a directory the installer
//! made for the app. It does not hold for `C:\Users\<user>\Tools` that the user pointed the installer
//! at: the user's other programs and notes live there too.
//!
//! # The test
//!
//! Only the installer's own record can tell the two apart, so the test needs an Inno Setup uninstall
//! log with file records under the root. A root is *shared* when both of these hold:
//!
//! 1. **No install run of the log created the directory.** Inno Setup logs every directory it makes
//!    (`LogRecord::created_dir`) and logs nothing for one that was already there. The rig shows it:
//!    Git installed into a fresh `C:\Program Files\Git` has the record, the same installer pointed at
//!    an existing `C:\Users\tester\Tools` does not.
//! 2. **The directory holds a file from before the install that the log does not name.** The
//!    *install start* is the earliest creation time of a file the log names under the root as
//!    installed by it; a file that no record names and that was created before that was there before
//!    the app.
//!
//! Neither is enough alone. An upgrade that starts a new log (`unins001.dat`) finds the directory in
//! place and logs no creation; an empty folder the user made for the app is not shared with anything.
//! And a file the log does not name is not foreign by that alone: installers generate files in their
//! post-install steps and apps write into their own directory (Git for Windows has dozens, VS Code
//! two); those are created after the install start.
//!
//! A file the log names but flags "existed before the install" or "shared" is neither: it does not
//! set the install start (it is older by definition) and it is not counted as foreign (on an upgrade
//! these are the app's own files of the earlier version). The same goes for the single items of
//! `[UninstallDelete]`. The uninstaller's own files (`unins000.exe`, `.dat`, `.msg`) are never in the
//! log and are left out.
//!
//! # When the test cannot be made
//!
//! A root the installer did not create is the app's alone only when the walk shows it. Where the
//! walk gives no verdict the root is **unjudged** and handled like a shared one: a directory under it
//! that cannot be listed (the stranger's files may be in there), a tree beyond the walk's limits, a
//! file the log does not name that has no creation time (it cannot be shown to be younger than the
//! install), or no named file with a creation time (no install start). Nothing is lost where the
//! installer created the folder: such a root is never walked.
//!
//! Left as they are: a root of an app without an Inno log, and a root under which the log names no
//! file (the test has nothing to start from; no time stamp tells an upgraded app's own older files
//! from a stranger's).
//!
//! Not seen by the test: an installer that overwrote an older copy of the same program in the folder
//! (the user's portable copy). The overwritten files keep their old creation times, the install
//! start comes out too early, and the user's files from between look younger than the install.
//!
//! # The consequence
//!
//! A shared root is demoted to [`RootKind::InferredRoot`], the kind the engine already has for "a
//! directory that is not the app's alone": no file is an anchor because of where it lies, nothing is
//! Tier A for pointing into it, and it is never offered whole (FS-INSTALLDIR offers only what the log
//! names). So that references to the app's own programs keep their weight, the code files the log
//! names under the root join the exe set ([`declared_code_files`]): they are the app's by the
//! installer's record, not by their location.

use std::collections::HashSet;

use purge_guard::prefix;
use purge_model::{FileTime, InnoRecord, InnoRecordKind, Root, RootKind, Target};
use purge_source::filesystem::FileSystemSource;

/// Most directory entries one root's walk visits. A larger tree is not judged.
const MAX_ENTRIES: usize = 400_000;
/// Deepest directory level below the root that is listed.
const MAX_DEPTH: usize = 32;

/// A root found to be shared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedRoot {
    /// The root.
    pub path: String,
    /// The install start: the earliest creation time of a file the log names under the root.
    pub install_start: FileTime,
    /// How many files under the root the log does not name and that are older than the install.
    pub foreign: u32,
    /// The first such file, in walk order.
    pub first: String,
}

/// A root the installer did not create and that could not be judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnjudgedRoot {
    /// The root.
    pub path: String,
    /// Why the walk gave no verdict.
    pub why: String,
}

/// What [`demote`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Demoted {
    /// The roots shown to be shared.
    pub shared: Vec<SharedRoot>,
    /// The roots that could not be judged.
    pub unjudged: Vec<UnjudgedRoot>,
    /// The install start of the roots the installer did not create and that were judged to be
    /// the app's alone: the earliest creation time of a file the log names under one of them.
    pub own_start: Option<FileTime>,
}

impl Demoted {
    /// The paths of every demoted root.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.shared
            .iter()
            .map(|s| s.path.as_str())
            .chain(self.unjudged.iter().map(|u| u.path.as_str()))
    }
}

/// The verdict on one root.
enum Verdict {
    /// Nothing older than the install that the log does not name (with the install start), or the
    /// test does not apply (without one).
    Own(Option<FileTime>),
    Shared(SharedRoot),
    /// No verdict, and why.
    Unknown(String),
}

/// Whether a file directly in the root is one of the Inno uninstaller's own (`unins000.exe`,
/// `unins000.dat`, `unins000.msg`): the log never names them.
fn is_uninstaller_file(root: &str, path: &str) -> bool {
    let direct = prefix::parent(path).is_some_and(|dir| prefix::is_same(dir, root));
    let name = prefix::leaf(path).unwrap_or_default().to_ascii_lowercase();
    direct
        && name.starts_with("unins")
        && [".exe", ".dat", ".msg"]
            .iter()
            .any(|ext| name.ends_with(ext))
}

/// The files and single items the log names under `root`, folded: those it installed itself (`.0`),
/// and those it only removes or flags as older than the install or shared (`.1`).
fn named_under(root: &str, records: &[InnoRecord]) -> (HashSet<String>, HashSet<String>) {
    let mut installed = HashSet::new();
    let mut other = HashSet::new();
    for record in records {
        let Target::Path { path } = &record.target else {
            continue;
        };
        let names_item = matches!(
            record.kind,
            InnoRecordKind::DeleteFile | InnoRecordKind::DeleteDirOrFiles
        );
        if !names_item || !prefix::is_inside(path, root) {
            continue;
        }
        if record.kind == InnoRecordKind::DeleteFile && !record.existed_before && !record.shared {
            installed.insert(prefix::fold(path));
        } else {
            // Flagged as older or shared, or an `[UninstallDelete]` item (made after the install).
            other.insert(prefix::fold(path));
        }
    }
    (installed, other)
}

/// Judges one root.
fn judge(fs: &dyn FileSystemSource, root: &str, records: &[InnoRecord]) -> Verdict {
    let (declared, named_otherwise) = named_under(root, records);
    if declared.is_empty() {
        return Verdict::Own(None);
    }
    let mut install_start: Option<FileTime> = None;
    // (creation time, path) of every file the log does not name.
    let mut undeclared: Vec<(FileTime, String)> = Vec::new();
    // The first file the log does not name that has no creation time.
    let mut timeless: Option<String> = None;
    let mut visited = 0usize;
    let mut stack: Vec<(String, usize)> = vec![(root.trim_end_matches(prefix::SEP).to_owned(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        // A directory that cannot be read may hold the earliest file of the install, or the
        // stranger's files: no verdict.
        let Ok(entries) = fs.list_dir(&dir) else {
            return Verdict::Unknown(format!("{dir} could not be listed"));
        };
        for entry in entries {
            visited += 1;
            if visited > MAX_ENTRIES {
                return Verdict::Unknown(format!("it holds more than {MAX_ENTRIES} entries"));
            }
            let path = format!("{dir}\\{}", entry.name);
            if entry.meta.is_reparse_point() {
                continue;
            }
            if entry.meta.is_dir() {
                if depth >= MAX_DEPTH {
                    return Verdict::Unknown(format!("it is more than {MAX_DEPTH} levels deep"));
                }
                stack.push((path, depth + 1));
                continue;
            }
            let created = entry.meta.times.created.filter(|t| t.0 != 0);
            if declared.contains(&prefix::fold(&path)) {
                if let Some(created) = created {
                    install_start = Some(install_start.map_or(created, |t| t.min(created)));
                }
            } else if !named_otherwise.contains(&prefix::fold(&path))
                && !is_uninstaller_file(root, &path)
            {
                match created {
                    Some(created) => undeclared.push((created, path)),
                    None => {
                        timeless.get_or_insert(path);
                    }
                }
            }
        }
    }
    let Some(install_start) = install_start else {
        return Verdict::Unknown(
            "no file the uninstall log names in it has a creation time".to_owned(),
        );
    };
    let mut foreign = undeclared
        .into_iter()
        .filter(|(created, _)| *created < install_start)
        .map(|(_, path)| path);
    let Some(first) = foreign.next() else {
        // Nothing shown to be older; a file without a time may still be.
        return match timeless {
            Some(path) => Verdict::Unknown(format!("{path} has no creation time")),
            None => Verdict::Own(Some(install_start)),
        };
    };
    Verdict::Shared(SharedRoot {
        path: root.to_owned(),
        install_start,
        foreign: u32::try_from(foreign.count() + 1).unwrap_or(u32::MAX),
        first,
    })
}

/// Demotes every InstallRoot of `roots` that is shown to be shared, or that the installer did not
/// create and that cannot be judged, to an InferredRoot and reports them. `created_dirs` are the directories the log shows the installer to have created
/// (`InnoHarvest::created_dirs`). See the module documentation.
pub fn demote(
    fs: &dyn FileSystemSource,
    roots: &mut [Root],
    records: &[InnoRecord],
    created_dirs: &[String],
) -> Demoted {
    let mut out = Demoted::default();
    for root in roots.iter_mut().filter(|r| r.kind == RootKind::InstallRoot) {
        if created_dirs.iter().any(|d| prefix::is_same(d, &root.path)) {
            continue;
        }
        match judge(fs, &root.path, records) {
            Verdict::Own(start) => {
                out.own_start = match (out.own_start, start) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
            }
            Verdict::Shared(shared) => {
                root.kind = RootKind::InferredRoot;
                out.shared.push(shared);
            }
            Verdict::Unknown(why) => {
                root.kind = RootKind::InferredRoot;
                out.unjudged.push(UnjudgedRoot {
                    path: root.path.clone(),
                    why,
                });
            }
        }
    }
    out
}

/// The `.exe` and `.dll` files the log names under the demoted roots and that are there now: the app's
/// programs by the installer's record. Sorted by folded path, each once.
pub fn declared_code_files(
    fs: &dyn FileSystemSource,
    demoted: &Demoted,
    records: &[InnoRecord],
) -> Vec<String> {
    let is_code = |path: &str| {
        path.rsplit_once('.').is_some_and(|(_, ext)| {
            ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("dll")
        })
    };
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for record in records {
        let Target::Path { path } = &record.target else {
            continue;
        };
        if record.kind != InnoRecordKind::DeleteFile
            || record.existed_before
            || record.shared
            || !is_code(path)
            || !demoted.paths().any(|root| prefix::is_inside(path, root))
        {
            continue;
        }
        if seen.insert(prefix::fold(path)) && fs.exists(path).is_present() {
            out.push(path.clone());
        }
    }
    out.sort_by_key(|p| prefix::fold(p));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_model::{RootSource, SourceTrust};
    use purge_source::fixture::Fixture;
    use purge_source::types::FileTimes;

    const TOOLS: &str = r"C:\Users\tester\Tools";

    fn root(path: &str) -> Root {
        Root {
            path: path.into(),
            kind: RootKind::InstallRoot,
            source: RootSource::ArpInstallLocation,
            trust: SourceTrust::UserWritable,
            volume_serial: None,
            parent_existed: true,
        }
    }

    fn file_record(path: &str) -> InnoRecord {
        InnoRecord {
            kind: InnoRecordKind::DeleteFile,
            target: Target::Path { path: path.into() },
            view: None,
            user_hive: false,
            existed_before: false,
            shared: false,
            key_create: false,
        }
    }

    fn created(t: u64) -> FileTimes {
        FileTimes {
            created: Some(FileTime(t)),
            modified: Some(FileTime(t)),
            accessed: None,
        }
    }

    fn records() -> Vec<InnoRecord> {
        vec![
            file_record(r"C:\Users\tester\Tools\git-bash.exe"),
            file_record(r"C:\Users\tester\Tools\cmd\git.exe"),
            file_record(r"C:\Users\tester\Tools\LICENSE.txt"),
        ]
    }

    /// The Git install of the `git-toolsdir` run: installed at 1000 into a folder that held the user's
    /// ripgrep and notes since 100; the installer generated `etc\gitconfig` at 1005.
    fn tools(user_files_at: u64) -> Fixture {
        Fixture::builder()
            .file(r"C:\Users\tester\Tools\git-bash.exe", 10)
            .times(r"C:\Users\tester\Tools\git-bash.exe", created(1_001))
            .file(r"C:\Users\tester\Tools\cmd\git.exe", 10)
            .times(r"C:\Users\tester\Tools\cmd\git.exe", created(1_000))
            .file(r"C:\Users\tester\Tools\LICENSE.txt", 10)
            .times(r"C:\Users\tester\Tools\LICENSE.txt", created(1_002))
            .file(r"C:\Users\tester\Tools\etc\gitconfig", 10)
            .times(r"C:\Users\tester\Tools\etc\gitconfig", created(1_005))
            .file(r"C:\Users\tester\Tools\unins000.exe", 10)
            .times(r"C:\Users\tester\Tools\unins000.exe", created(999))
            .file(r"C:\Users\tester\Tools\ripgrep\rg.exe", 10)
            .times(
                r"C:\Users\tester\Tools\ripgrep\rg.exe",
                created(user_files_at),
            )
            .file(r"C:\Users\tester\Tools\notes.txt", 10)
            .times(r"C:\Users\tester\Tools\notes.txt", created(user_files_at))
            .build()
    }

    #[test]
    fn a_folder_that_held_files_before_the_install_is_shared() {
        let fixture = tools(100);
        let mut roots = [root(TOOLS)];
        let demoted = demote(&fixture, &mut roots, &records(), &[]);
        assert!(demoted.unjudged.is_empty());
        let shared = &demoted.shared;
        assert_eq!(roots[0].kind, RootKind::InferredRoot);
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].install_start, FileTime(1_000));
        assert_eq!(shared[0].foreign, 2);
        // Only what the log names is the app's program; the user's `rg.exe` is not.
        assert_eq!(
            declared_code_files(&fixture, &demoted, &records()),
            [
                r"C:\Users\tester\Tools\cmd\git.exe",
                r"C:\Users\tester\Tools\git-bash.exe"
            ]
        );
    }

    #[test]
    fn files_made_after_the_install_started_do_not_make_a_root_shared() {
        // The same tree, the unnamed files created during or after the install: generated files, an
        // app's own data, a user's later additions. None of them shows that the folder pre-existed.
        let fixture = tools(1_003);
        let mut roots = [root(TOOLS)];
        // The walk's install start is reported: the folder may be older than the install.
        assert_eq!(
            demote(&fixture, &mut roots, &records(), &[]),
            Demoted {
                own_start: Some(FileTime(1_000)),
                ..Demoted::default()
            }
        );
        assert_eq!(roots[0].kind, RootKind::InstallRoot);
    }

    #[test]
    fn a_directory_the_installer_created_is_never_shared() {
        // The log shows the installer made the directory: whatever is in it came later.
        let fixture = tools(100);
        let mut roots = [root(TOOLS)];
        assert_eq!(
            demote(&fixture, &mut roots, &records(), &[TOOLS.to_owned()]),
            Demoted::default()
        );
        assert_eq!(roots[0].kind, RootKind::InstallRoot);
    }

    #[test]
    fn nothing_is_concluded_without_file_records() {
        let fixture = tools(100);
        let mut roots = [root(TOOLS)];
        assert_eq!(demote(&fixture, &mut roots, &[], &[]), Demoted::default());
        assert_eq!(roots[0].kind, RootKind::InstallRoot);
    }

    /// A directory under the root that cannot be listed may hold the stranger's files.
    #[test]
    fn a_root_with_an_unlistable_directory_is_unjudged() {
        let mut fixture = tools(1_003);
        fixture.add_denied(r"C:\Users\tester\Tools\ripgrep");
        let mut roots = [root(TOOLS)];
        let demoted = demote(&fixture, &mut roots, &records(), &[]);
        assert!(demoted.shared.is_empty(), "{demoted:?}");
        assert_eq!(demoted.unjudged.len(), 1, "{demoted:?}");
        assert!(demoted.unjudged[0].why.contains("ripgrep"));
        assert_eq!(demoted.own_start, None);
        assert_eq!(roots[0].kind, RootKind::InferredRoot);
    }

    /// A root the installer did not create is the app's alone only when the walk shows it.
    #[test]
    fn a_root_that_cannot_be_judged_is_not_the_apps_alone() {
        // No creation times at all (a rig snapshot): no install start.
        let bare = Fixture::builder()
            .file(r"C:\Users\tester\Tools\git-bash.exe", 10)
            .file(r"C:\Users\tester\Tools\ripgrep\rg.exe", 10)
            .build();
        let mut roots = [root(TOOLS)];
        let demoted = demote(&bare, &mut roots, &records(), &[]);
        assert!(demoted.shared.is_empty());
        assert_eq!(demoted.unjudged.len(), 1, "{demoted:?}");
        assert_eq!(roots[0].kind, RootKind::InferredRoot);

        // The installer's files have times, a file nobody names has none: it may be older.
        let timeless = Fixture::builder()
            .file(r"C:\Users\tester\Tools\git-bash.exe", 10)
            .times(r"C:\Users\tester\Tools\git-bash.exe", created(1_001))
            .file(r"C:\Users\tester\Tools\ripgrep\rg.exe", 10)
            .build();
        let mut roots = [root(TOOLS)];
        let demoted = demote(&timeless, &mut roots, &records(), &[]);
        assert_eq!(demoted.unjudged.len(), 1, "{demoted:?}");
        assert!(demoted.unjudged[0].why.contains("rg.exe"));
        assert_eq!(roots[0].kind, RootKind::InferredRoot);
        // The code files the log names are still the app's programs.
        assert_eq!(
            declared_code_files(&timeless, &demoted, &records()),
            [r"C:\Users\tester\Tools\git-bash.exe"]
        );

        // The same root when the log shows the installer created it: never walked, never demoted.
        let mut roots = [root(TOOLS)];
        assert_eq!(
            demote(&timeless, &mut roots, &records(), &[TOOLS.to_owned()]),
            Demoted::default()
        );
        assert_eq!(roots[0].kind, RootKind::InstallRoot);
    }

    #[test]
    fn a_file_the_log_flags_as_older_does_not_set_the_install_start() {
        // The installer overwrote the user's own `LICENSE.txt`: the record says it existed before, so
        // its (old) creation time is not the start of the install.
        let fixture = Fixture::builder()
            .file(r"C:\Users\tester\Tools\git-bash.exe", 10)
            .times(r"C:\Users\tester\Tools\git-bash.exe", created(1_001))
            .file(r"C:\Users\tester\Tools\LICENSE.txt", 10)
            .times(r"C:\Users\tester\Tools\LICENSE.txt", created(50))
            .file(r"C:\Users\tester\Tools\notes.txt", 10)
            .times(r"C:\Users\tester\Tools\notes.txt", created(100))
            .build();
        let mut records = records();
        records[2].existed_before = true;
        let mut roots = [root(TOOLS)];
        let shared = demote(&fixture, &mut roots, &records, &[]).shared;
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].install_start, FileTime(1_001));
        // The overwritten file is named by the log and so is not counted; the user's note is.
        assert_eq!(shared[0].foreign, 1);
    }
}
