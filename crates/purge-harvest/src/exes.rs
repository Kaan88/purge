//! The exe/dll set of an app (ENGINE_PLAN.md §5.2 "Fingerprint": "the exe/dll set", §5.4 "Anchors").
//!
//! Every `.exe` and `.dll` under the app's **InstallRoots**, found by a bounded walk that never enters a
//! reparse point. The set serves two purposes: its full paths are reference anchors (a registry value
//! naming one of them points at the app), and its main exes are what verify-gone checks after the
//! uninstall.
//!
//! # Main exes
//!
//! The identity resolution (`purge-identity`) proposes main exes; this module decides which of them the
//! fingerprint trusts:
//!
//! - an exe related to the app's names (named by `DisplayIcon`, or sharing a name token) is main when it
//!   lies under any validated root, inferred ones included: an app without an `InstallLocation` still
//!   needs its verify-gone check;
//! - an exe selected only because it is the largest is main only when it lies under an InstallRoot and
//!   no related exe was found, because nothing ties it to the app but the directory.
//!
//! An inferred root is not walked: it is a guess, and its files are not the app's by that alone.

use purge_guard::prefix;
use purge_identity::identity::MainExe;
use purge_model::{ExeFile, Root, RootKind};
use purge_source::filesystem::FileSystemSource;

/// Bounds of the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExeLimits {
    /// Deepest directory level below a root that is listed (the root itself is level 0).
    pub max_depth: usize,
    /// Most directories listed, over all roots.
    pub max_dirs: usize,
    /// Most files recorded, over all roots.
    pub max_files: usize,
}

impl Default for ExeLimits {
    fn default() -> Self {
        Self {
            max_depth: 16,
            max_dirs: 20_000,
            max_files: 8_192,
        }
    }
}

/// The exe set and how complete it is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExeSet {
    /// The files, sorted by case-folded path, each once.
    pub files: Vec<ExeFile>,
    /// A limit of [`ExeLimits`] stopped the walk; the set is incomplete.
    pub truncated: bool,
    /// What could not be read, for the fingerprint's warnings.
    pub warnings: Vec<String>,
}

impl ExeSet {
    /// The file names of the set (last path segment), in the order of [`ExeSet::files`].
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.files.iter().filter_map(|f| prefix::leaf(&f.path))
    }
}

fn is_code_file(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(stem, ext)| {
        !stem.is_empty() && (ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("dll"))
    })
}

/// Collects the exe set of `roots` and marks the main exes among `main_exes` (as proposed by the
/// identity resolution); see the module documentation.
pub fn collect(
    fs: &dyn FileSystemSource,
    roots: &[Root],
    main_exes: &[MainExe],
    limits: ExeLimits,
) -> ExeSet {
    let mut set = ExeSet::default();
    let mut paths: Vec<String> = Vec::new();
    let mut dirs_listed = 0usize;
    let mut unreadable = 0usize;

    for root in roots.iter().filter(|r| r.kind == RootKind::InstallRoot) {
        // Depth-first, children in the source's (stable) order.
        let mut stack: Vec<(String, usize)> = vec![(root.path.clone(), 0)];
        while let Some((dir, depth)) = stack.pop() {
            if dirs_listed >= limits.max_dirs {
                set.truncated = true;
                break;
            }
            dirs_listed += 1;
            let entries = match fs.list_dir(&dir) {
                Ok(entries) => entries,
                Err(_) => {
                    unreadable += 1;
                    continue;
                }
            };
            for entry in entries {
                // Never through a junction, symbolic link or mount point.
                if entry.meta.is_reparse_point() {
                    continue;
                }
                let path = format!("{dir}\\{}", entry.name);
                if entry.meta.is_dir() {
                    if depth < limits.max_depth {
                        stack.push((path, depth + 1));
                    } else {
                        set.truncated = true;
                    }
                } else if is_code_file(&entry.name) {
                    if paths.len() >= limits.max_files {
                        set.truncated = true;
                    } else {
                        paths.push(path);
                    }
                }
            }
        }
    }
    if unreadable > 0 {
        set.warnings.push(format!(
            "exes: {unreadable} director(y/ies) under the install roots could not be listed"
        ));
    }
    if set.truncated {
        set.warnings.push(format!(
            "exes: the walk of the install roots stopped at a limit ({} files recorded)",
            paths.len()
        ));
    }

    // The main exes.
    let under = |path: &str, install_only: bool| {
        roots.iter().any(|r| {
            (!install_only || r.kind == RootKind::InstallRoot)
                && r.kind != RootKind::ReferencedDataDir
                && prefix::is_inside(path, &r.path)
        })
    };
    // A proposed exe must be there: one that is already gone would make verify-gone pass for nothing.
    let present =
        |path: &str| paths.iter().any(|p| prefix::is_same(p, path)) || fs.exists(path).is_present();
    let mut main: Vec<String> = main_exes
        .iter()
        .filter(|m| m.basis.is_related() && under(&m.path, false) && present(&m.path))
        .map(|m| m.path.clone())
        .collect();
    if main.is_empty() {
        main.extend(
            main_exes
                .iter()
                .filter(|m| !m.basis.is_related() && under(&m.path, true) && present(&m.path))
                .map(|m| m.path.clone()),
        );
    }

    for path in main.iter().chain(&paths) {
        if !set.files.iter().any(|f| prefix::is_same(&f.path, path)) {
            set.files.push(ExeFile {
                // Prefer the spelling of the walk (as stored on disk) over the registry's.
                path: paths
                    .iter()
                    .find(|p| prefix::is_same(p, path))
                    .unwrap_or(path)
                    .clone(),
                main: false,
            });
        }
    }
    for file in &mut set.files {
        file.main = main.iter().any(|m| prefix::is_same(m, &file.path));
    }
    set.files.sort_by_key(|f| prefix::fold(&f.path));
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_identity::identity::MainExeBasis;
    use purge_model::{RootSource, SourceTrust};
    use purge_source::fixture::Fixture;

    fn root(path: &str, source: RootSource) -> Root {
        Root {
            path: path.into(),
            kind: source.root_kind(),
            source,
            trust: SourceTrust::AdminOnly,
            volume_serial: None,
            parent_existed: true,
        }
    }

    fn main_exe(path: &str, basis: MainExeBasis) -> MainExe {
        MainExe {
            path: path.into(),
            basis,
            size: 1,
            stem: String::new(),
            version_info: None,
            signer_cn: None,
        }
    }

    fn app() -> Fixture {
        Fixture::builder()
            .file(r"C:\Program Files\App\App.exe", 100)
            .file(r"C:\Program Files\App\readme.txt", 1)
            .file(r"C:\Program Files\App\.dll", 1)
            .file(r"C:\Program Files\App\bin\helper.EXE", 5)
            .file(r"C:\Program Files\App\bin\core.dll", 5)
            .file(r"C:\Program Files\App\bin\deep\er\plugin.dll", 5)
            .reparse_dir(r"C:\Program Files\App\link", 0xA000_0003)
            .file(r"C:\Program Files\Other\other.exe", 5)
            .file(r"C:\Tools\Portable\tool.exe", 5)
            .file(r"C:\Tools\Portable\big.dll", 500)
            .build()
    }

    fn paths(set: &ExeSet) -> Vec<(&str, bool)> {
        set.files
            .iter()
            .map(|f| (f.path.as_str(), f.main))
            .collect()
    }

    #[test]
    fn walks_install_roots_only_and_marks_related_main_exes() {
        let mut f = app();
        // A file behind the junction must not be seen.
        f.add_file(r"C:\Program Files\Other\via-link.exe", 1);
        let roots = [
            root(r"C:\Program Files\App", RootSource::ArpInstallLocation),
            root(r"C:\Tools\Portable", RootSource::DisplayIcon),
        ];
        let mains = [
            main_exe(r"c:\program files\app\app.exe", MainExeBasis::DisplayIcon),
            main_exe(r"C:\Tools\Portable\tool.exe", MainExeBasis::FileName),
            main_exe(r"C:\Program Files\Other\other.exe", MainExeBasis::FileName),
            main_exe(
                r"C:\Program Files\App\bin\core.dll",
                MainExeBasis::LargestOnly,
            ),
        ];
        let set = collect(&f, &roots, &mains, ExeLimits::default());
        assert!(
            !set.truncated && set.warnings.is_empty(),
            "{:?}",
            set.warnings
        );
        assert_eq!(
            paths(&set),
            [
                (r"C:\Program Files\App\App.exe", true),
                (r"C:\Program Files\App\bin\core.dll", false),
                (r"C:\Program Files\App\bin\deep\er\plugin.dll", false),
                (r"C:\Program Files\App\bin\helper.EXE", false),
                // Under an inferred root: not walked, but a related main exe is kept for verify-gone.
                (r"C:\Tools\Portable\tool.exe", true),
            ]
        );
        assert_eq!(
            set.names().collect::<Vec<_>>(),
            [
                "App.exe",
                "core.dll",
                "plugin.dll",
                "helper.EXE",
                "tool.exe"
            ]
        );
        // Deterministic.
        assert_eq!(collect(&f, &roots, &mains, ExeLimits::default()), set);
    }

    #[test]
    fn largest_only_exe_is_main_only_under_an_install_root_and_without_a_related_one() {
        let f = app();
        let install = [root(r"C:\Program Files\App", RootSource::InnoApp)];
        let largest = [main_exe(
            r"C:\Program Files\App\App.exe",
            MainExeBasis::LargestOnly,
        )];
        let set = collect(&f, &install, &largest, ExeLimits::default());
        assert_eq!(
            set.files
                .iter()
                .filter(|f| f.main)
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            [r"C:\Program Files\App\App.exe"]
        );
        // Under an inferred root nothing ties it to the app.
        let inferred = [root(r"C:\Tools\Portable", RootSource::UninstallerDir)];
        let largest = [main_exe(
            r"C:\Tools\Portable\big.dll",
            MainExeBasis::LargestOnly,
        )];
        assert!(
            collect(&f, &inferred, &largest, ExeLimits::default())
                .files
                .is_empty()
        );
        // No roots, no exes: a proposed main exe outside every root is ignored.
        let stray = [main_exe(
            r"C:\Program Files\Other\other.exe",
            MainExeBasis::DisplayIcon,
        )];
        assert!(
            collect(&f, &[], &stray, ExeLimits::default())
                .files
                .is_empty()
        );
        // So is one that does not exist.
        let gone = [main_exe(
            r"C:\Program Files\App\gone.exe",
            MainExeBasis::DisplayIcon,
        )];
        let set = collect(&f, &install, &gone, ExeLimits::default());
        assert!(set.files.iter().all(|f| !f.main), "{:?}", set.files);
    }

    #[test]
    fn limits_truncate_and_are_reported() {
        let f = app();
        let roots = [root(r"C:\Program Files\App", RootSource::InnoApp)];
        let shallow = ExeLimits {
            max_depth: 1,
            ..ExeLimits::default()
        };
        let set = collect(&f, &roots, &[], shallow);
        assert!(set.truncated);
        assert_eq!(set.files.len(), 3, "{:?}", set.files);
        assert!(set.warnings.iter().any(|w| w.contains("limit")));

        let few = ExeLimits {
            max_files: 1,
            ..ExeLimits::default()
        };
        let set = collect(&f, &roots, &[], few);
        assert!(set.truncated && set.files.len() == 1);

        let one_dir = ExeLimits {
            max_dirs: 1,
            ..ExeLimits::default()
        };
        let set = collect(&f, &roots, &[], one_dir);
        assert!(set.truncated);
        assert_eq!(paths(&set), [(r"C:\Program Files\App\App.exe", false)]);

        // An unreadable directory is a warning, not a failure.
        let mut f = app();
        f.add_denied(r"C:\Program Files\App\bin");
        let set = collect(&f, &roots, &[], ExeLimits::default());
        assert_eq!(paths(&set), [(r"C:\Program Files\App\App.exe", false)]);
        assert!(
            set.warnings
                .iter()
                .any(|w| w.contains("could not be listed"))
        );
    }
}
