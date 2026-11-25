//! The broker's start checks (M3 design 3.4, package M3-HARDEN; BL-R1 S4), run before the pipe or
//! the store is touched.
//!
//! | Order | Check | Failure |
//! |---|---|---|
//! | 0 | [`restrict_dll_search`] is the first call of `main`; a failure is [`StartFailure::InstallUntrusted`] | [`StartFailure::InstallUntrusted`] |
//! | 1 | The process token is elevated | [`StartFailure::NotElevated`] |
//! | 2 | Own directory (of the running executable): plain drive path, no reparse point on it, on the system volume, every ancestor writable by administrators only (`purge_win::secure::trusted_install_dir`); the executable itself admin-only writable; `<own directory>\kb` passes the directory rule too | [`StartFailure::InstallUntrusted`] |
//! | 3 | Data root `<ProgramData>\Purge`, `ProgramData` from the machine (`purge_win::known_folders::machine_program_data`), passes the same directory rule, and `StorageRoots::check` passes on it | [`StartFailure::StoreIntegrity`] |
//! | 2b | The client image `<own directory>\Purge.exe` (what the pipe peer check compares with, design 3.3) is admin-only writable, and so is every file directly in `<own directory>\kb\baselines` (review M3-R1 S7: a file moved into a checked directory keeps its own descriptor) | [`StartFailure::InstallUntrusted`] |
//! | 4 | KB and baselines are `<own directory>\kb`; `PURGE_KB_DIR` is not read | (none) |
//!
//! No directory comes from the environment: the own directory is the running image's path, and
//! `ProgramData` is read from `ProfileList` with `%SystemDrive%` taken from the running Windows
//! directory, because the known-folder API itself expands `%SystemDrive%` of the process, which the
//! caller of `ShellExecuteExW("runas")` chooses (`purge_win::known_folders`, "The environment").
//!
//! A failure is one line in the Application event log (source [`EVENT_SOURCE`], event id = exit
//! code) and on stderr, and the process exit code of [`StartFailure::exit_code`]; the UI shows
//! "The administrator part could not start" with [`StartFailure::code`].
//!
//! The checks read the machine through [`StartFacts`], so their order and the "nothing after a
//! failure" rule are tested on fakes; [`LiveFacts`] is the machine.

use std::path::{Path, PathBuf};

use purge_engine::pipeline::{Settings, VolumeRule};
use purge_exec::storage::StorageRoots;

use crate::store_caches::{StoreLocalCaches, StoreTableCaches};

/// The event source of the broker's start failures in the Application log.
pub const EVENT_SOURCE: &str = "Purge";

/// Why the broker refused to start. Each variant carries the reason in words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartFailure {
    /// The process token is not elevated, or its elevation could not be read.
    NotElevated(String),
    /// The broker's own directory, executable or `kb` directory fails the directory rule, its path could
    /// not be read, or the DLL search could not be restricted to System32.
    InstallUntrusted(String),
    /// The data root could not be located, fails the directory rule, or the store's own check
    /// (`StorageRoots::check`) fails.
    StoreIntegrity(String),
}

impl StartFailure {
    /// The error kind of M3 design 6.4 (`not_elevated`, `install_untrusted`, `store_integrity`).
    pub fn code(&self) -> &'static str {
        match self {
            StartFailure::NotElevated(_) => "not_elevated",
            StartFailure::InstallUntrusted(_) => "install_untrusted",
            StartFailure::StoreIntegrity(_) => "store_integrity",
        }
    }

    /// The process exit code, one per kind so the UI can name it from the process handle alone:
    /// 20 `not_elevated`, 21 `install_untrusted`, 22 `store_integrity`. (1 is the stub's "not
    /// implemented"; the CLI's codes 2 to 12 are not reused.)
    pub fn exit_code(&self) -> u8 {
        match self {
            StartFailure::NotElevated(_) => 20,
            StartFailure::InstallUntrusted(_) => 21,
            StartFailure::StoreIntegrity(_) => 22,
        }
    }

    /// The reason in words.
    pub fn reason(&self) -> &str {
        match self {
            StartFailure::NotElevated(r)
            | StartFailure::InstallUntrusted(r)
            | StartFailure::StoreIntegrity(r) => r,
        }
    }

    /// The one line that goes to the event log and stderr.
    pub fn line(&self) -> String {
        format!(
            "purge-broker did not start: {} (exit code {}): {}",
            self.code(),
            self.exit_code(),
            self.reason()
        )
    }

    /// Writes [`StartFailure::line`] to the Application event log and to stderr. Failures to
    /// write are ignored: the exit code still says it.
    pub fn report(&self) {
        let line = self.line();
        let _ = purge_win::eventlog::report_error(EVENT_SOURCE, u32::from(self.exit_code()), &line);
        eprintln!("{line}");
    }
}

/// Writes `line` to the Application event log (event id = `code`) and to stderr: the report of an
/// exit that is not a [`StartFailure`] (`lifetime::codes`). Failures to write are ignored.
pub fn report_exit(code: u8, line: &str) {
    let _ = purge_win::eventlog::report_error(EVENT_SOURCE, u32::from(code), line);
    eprintln!("{line}");
}

/// What the start checks established; everything the broker later reads from disk is below these
/// directories.
#[derive(Debug, Clone)]
pub struct Started<S> {
    /// The broker's own directory (checked).
    pub install_dir: PathBuf,
    /// `<install_dir>\kb`, the knowledge base; its `baselines` subdirectory holds the baselines.
    pub kb_dir: PathBuf,
    /// `<install_dir>\Purge.exe`, the only image the pipe client may have (checked admin-only writable).
    pub client_image: PathBuf,
    /// `<ProgramData>\Purge` (checked).
    pub data_root: PathBuf,
    /// The system volume (`\\?\volume{…}\`) the checks compared against.
    pub system_volume: String,
    /// The store over the data root, checked once.
    pub store: S,
}

impl<S> Started<S> {
    /// The engine settings of the broker's pipeline steps: baselines from `<install_dir>\kb\baselines`
    /// (never `PURGE_KB_DIR`), the MSI table cache and the local baseline cache under the checked
    /// data root, the shipped-directory check on and the system-volume rule of the checks.
    pub fn engine_settings(&self) -> Settings {
        let path = |p: &Path| p.to_string_lossy().into_owned();
        Settings {
            baseline_dir: Some(self.kb_dir.join("baselines")),
            purge_dirs: vec![path(&self.install_dir), path(&self.data_root)],
            // The two cache directories name the caches in messages only: the broker's caches are
            // its store's checked `fp\msitables` and `baseline` ([`Started::broker_settings`]),
            // never opened by path.
            msi_table_dir: Some(self.data_root.join("fp").join("msitables")),
            msi_table_source: None,
            local_baseline_dir: Some(self.data_root.join("baseline")),
            local_baseline_source: None,
            data_root: Some(self.data_root.clone()),
            check_shipped_dir: true,
            volume_rule: VolumeRule::On(self.system_volume.clone()),
            local_build: None,
        }
    }
}

impl Started<StorageRoots> {
    /// [`Started::engine_settings`] with the MSI table cache and the local baseline cache in the
    /// checked store (`store_caches`; DECISIONS 2026-11-22, "fp checked" and "baseline checked"):
    /// what the broker's pipeline steps and its background build run with.
    pub fn broker_settings(&self) -> Settings {
        Settings {
            msi_table_source: Some(StoreTableCaches::shared(self.store.clone())),
            local_baseline_source: Some(StoreLocalCaches::shared(self.store.clone())),
            ..self.engine_settings()
        }
    }
}

/// The facts the start checks read. Every error is a reason in words.
pub trait StartFacts {
    /// The store a checked data root opens to.
    type Store;
    /// Whether the process token is elevated.
    fn elevated(&self) -> Result<bool, String>;
    /// The path of the running executable.
    fn exe_path(&self) -> Result<PathBuf, String>;
    /// The directory rule (`purge_win::secure::trusted_install_dir`).
    fn trusted_dir(&self, dir: &Path) -> Result<(), String>;
    /// Whether only administrators can write the file and every ancestor, and add to its directory
    /// (`is_admin_only_executable`; each caller has already checked that directory with `trusted_dir`).
    fn trusted_file(&self, file: &Path) -> Result<(), String>;
    /// The files directly in `<kb>\baselines`, or none when that directory does not exist.
    fn kb_files(&self, kb_dir: &Path) -> Result<Vec<PathBuf>, String>;
    /// The machine's `ProgramData`, not from the environment.
    fn program_data(&self) -> Result<PathBuf, String>;
    /// The system volume.
    fn system_volume(&self) -> Result<String, String>;
    /// Opens and checks the store at `data_root`.
    fn open_store(&self, data_root: &Path) -> Result<Self::Store, String>;
}

/// The live machine.
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveFacts;

impl StartFacts for LiveFacts {
    type Store = StorageRoots;

    fn elevated(&self) -> Result<bool, String> {
        purge_win::sid::is_elevated().map_err(|e| format!("the token's elevation: {e}"))
    }

    fn exe_path(&self) -> Result<PathBuf, String> {
        std::env::current_exe().map_err(|e| format!("the executable's path: {e}"))
    }

    fn trusted_dir(&self, dir: &Path) -> Result<(), String> {
        purge_win::secure::trusted_install_dir(dir).map_err(|e| e.to_string())
    }

    fn trusted_file(&self, file: &Path) -> Result<(), String> {
        match purge_win::sid::is_admin_only_executable(file) {
            Ok(true) => Ok(()),
            Ok(false) => Err("a non-administrator can write it".into()),
            Err(e) => Err(format!("its protection could not be read: {e}")),
        }
    }

    fn kb_files(&self, kb_dir: &Path) -> Result<Vec<PathBuf>, String> {
        let dir = kb_dir.join("baselines");
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("{}: {e}", dir.display())),
        };
        let mut files = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
            files.push(entry.path());
        }
        Ok(files)
    }

    fn program_data(&self) -> Result<PathBuf, String> {
        purge_win::known_folders::machine_program_data()
            .map_err(|e| format!("the machine's ProgramData: {e}"))
    }

    fn system_volume(&self) -> Result<String, String> {
        purge_win::secure::system_volume().map_err(|e| format!("the system volume: {e}"))
    }

    fn open_store(&self, data_root: &Path) -> Result<StorageRoots, String> {
        let roots = StorageRoots::new(data_root).map_err(|e| e.to_string())?;
        roots.check().map_err(|e| e.to_string())?;
        // What `fp`, `fp\msitables` and `baseline` renamed aside more than 30 days ago goes
        // (DECISIONS 2026-11-22, "fp checked" review follow-ups); failures change nothing.
        roots.prune_rejected(REJECTED_KEPT);
        Ok(roots)
    }
}

/// How long the broker keeps what its document directories renamed aside.
pub const REJECTED_KEPT: std::time::Duration = std::time::Duration::from_secs(30 * 24 * 60 * 60);

/// `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`: the first call of the broker's
/// `main`. A failure is a start failure (review M3-R1 S4): without it the elevated process keeps the
/// default search order, in which the application directory comes before System32. The imports
/// resolved before `main` are covered by the static-import load flag and the directory check, not by
/// this.
pub fn restrict_dll_search() -> Result<(), StartFailure> {
    purge_win::secure::restrict_dll_search().map_err(|e| {
        StartFailure::InstallUntrusted(format!(
            "the DLL search could not be restricted to System32: {e}"
        ))
    })
}

/// Sets the process's working directory to the broker's own install directory, so an elevated start
/// does not keep the directory the `runas` caller chose (review M3-R2 S4).
pub fn restrict_working_directory() -> Result<(), StartFailure> {
    let exe = std::env::current_exe().map_err(|e| {
        StartFailure::InstallUntrusted(format!("the own image path could not be read: {e}"))
    })?;
    let dir = exe
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or_else(|| {
            StartFailure::InstallUntrusted(format!("{} has no directory", exe.display()))
        })?;
    purge_win::secure::set_current_directory(dir).map_err(|e| {
        StartFailure::InstallUntrusted(format!(
            "the working directory {} could not be set: {e}",
            dir.display()
        ))
    })
}

/// The machine-wide variables the broker resets at start, before anything else reads the environment
/// (M3_DESIGN 3.4, threat T7). An elevated process gets the caller's environment, including values from
/// `HKCU\Environment`, so a caller could point `ProgramData` and the others at a tree it writes. Purge's
/// own paths never read them (known folders and the registry); this also covers Windows components
/// loaded into the broker and the uninstallers it starts (m3-broker 2026-11-25: `env-planted` found the
/// shell's `Caches` databases written into a planted `ProgramData`).
pub fn pin_machine_environment() -> Result<(), StartFailure> {
    use purge_win::env::set_process_var;
    use purge_win::known_folders::{machine_program_data, system_windows_dir};

    let fail = |what: &str, e: purge_win::os::Win32Error| {
        StartFailure::StoreIntegrity(format!(
            "the machine environment could not be set ({what}): {e}"
        ))
    };
    let windows = system_windows_dir().map_err(|e| fail("the Windows directory", e))?;
    let program_data = machine_program_data().map_err(|e| fail("ProgramData", e))?;
    let windows_s = windows.to_string_lossy().trim_end_matches('\\').to_string();
    let program_data_s = program_data
        .to_string_lossy()
        .trim_end_matches('\\')
        .to_string();
    let drive = windows_s.get(..2).unwrap_or("C:").to_string();
    let pins: [(&str, Option<&str>); 6] = [
        ("SystemDrive", Some(&drive)),
        ("SystemRoot", Some(&windows_s)),
        ("windir", Some(&windows_s)),
        ("ProgramData", Some(&program_data_s)),
        ("ALLUSERSPROFILE", Some(&program_data_s)),
        ("PURGE_KB_DIR", None),
    ];
    for (name, value) in pins {
        set_process_var(name, value).map_err(|e| fail(name, e))?;
    }
    Ok(())
}

/// The start checks on the live machine ([`check_with`] of [`LiveFacts`]).
pub fn check() -> Result<Started<StorageRoots>, StartFailure> {
    check_with(&LiveFacts)
}

/// The start checks in the order of the module table. The first failure is returned and nothing
/// after it is read: a broker that is not elevated looks at no directory, and one whose own
/// directory fails never locates or opens the store.
pub fn check_with<F: StartFacts>(facts: &F) -> Result<Started<F::Store>, StartFailure> {
    match facts.elevated() {
        Ok(true) => {}
        Ok(false) => {
            return Err(StartFailure::NotElevated(
                "the process token is not elevated".into(),
            ));
        }
        Err(e) => return Err(StartFailure::NotElevated(e)),
    }

    let untrusted = |what: &Path, why: String| {
        StartFailure::InstallUntrusted(format!("{}: {why}", what.display()))
    };
    let exe = facts.exe_path().map_err(StartFailure::InstallUntrusted)?;
    let install_dir = exe
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .ok_or_else(|| untrusted(&exe, "has no directory".into()))?;
    facts
        .trusted_dir(&install_dir)
        .map_err(|why| untrusted(&install_dir, why))?;
    facts
        .trusted_file(&exe)
        .map_err(|why| untrusted(&exe, why))?;
    // The KB sits below the checked directory. The directory rule covers its ancestors, not `kb`
    // itself (a file or directory moved in keeps its own descriptor), so it is checked too, and so
    // are the client image and each file the broker will load from it (review M3-R1 S7).
    let kb_dir = install_dir.join("kb");
    facts
        .trusted_dir(&kb_dir)
        .map_err(|why| untrusted(&kb_dir, why))?;
    let client_image = install_dir.join("Purge.exe");
    facts
        .trusted_file(&client_image)
        .map_err(|why| untrusted(&client_image, why))?;
    let baselines = kb_dir.join("baselines");
    let files = facts
        .kb_files(&kb_dir)
        .map_err(StartFailure::InstallUntrusted)?;
    if !files.is_empty() {
        facts
            .trusted_dir(&baselines)
            .map_err(|why| untrusted(&baselines, why))?;
    }
    for file in &files {
        facts
            .trusted_file(file)
            .map_err(|why| untrusted(file, why))?;
    }

    let store = |what: &Path, why: String| {
        StartFailure::StoreIntegrity(format!("{}: {why}", what.display()))
    };
    let program_data = facts.program_data().map_err(StartFailure::StoreIntegrity)?;
    let data_root = program_data.join("Purge");
    facts
        .trusted_dir(&data_root)
        .map_err(|why| store(&data_root, why))?;
    let system_volume = facts
        .system_volume()
        .map_err(StartFailure::StoreIntegrity)?;
    let opened = facts
        .open_store(&data_root)
        .map_err(|why| store(&data_root, why))?;

    Ok(Started {
        kb_dir,
        client_image,
        install_dir,
        data_root,
        system_volume,
        store: opened,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Facts from a table; every call is recorded.
    struct Fake {
        elevated: Result<bool, String>,
        exe: PathBuf,
        untrusted_dirs: Vec<PathBuf>,
        untrusted_files: Vec<PathBuf>,
        kb_files: Result<Vec<PathBuf>, String>,
        program_data: Result<PathBuf, String>,
        store: Result<(), String>,
        calls: RefCell<Vec<String>>,
    }

    impl Fake {
        fn passing() -> Fake {
            Fake {
                elevated: Ok(true),
                exe: PathBuf::from(r"C:\Program Files\Purge\purge-broker.exe"),
                untrusted_dirs: Vec::new(),
                untrusted_files: Vec::new(),
                kb_files: Ok(Vec::new()),
                program_data: Ok(PathBuf::from(r"C:\ProgramData")),
                store: Ok(()),
                calls: RefCell::new(Vec::new()),
            }
        }

        fn note(&self, call: String) {
            self.calls.borrow_mut().push(call);
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl StartFacts for Fake {
        type Store = PathBuf;

        fn elevated(&self) -> Result<bool, String> {
            self.note("elevated".into());
            self.elevated.clone()
        }

        fn exe_path(&self) -> Result<PathBuf, String> {
            self.note("exe".into());
            Ok(self.exe.clone())
        }

        fn trusted_dir(&self, dir: &Path) -> Result<(), String> {
            self.note(format!("dir {}", dir.display()));
            if self.untrusted_dirs.iter().any(|d| d == dir) {
                Err("refused by the fake".into())
            } else {
                Ok(())
            }
        }

        fn trusted_file(&self, file: &Path) -> Result<(), String> {
            self.note(format!("file {}", file.display()));
            if self.untrusted_files.iter().any(|f| f == file) {
                Err("refused by the fake".into())
            } else {
                Ok(())
            }
        }

        fn kb_files(&self, kb_dir: &Path) -> Result<Vec<PathBuf>, String> {
            self.note(format!("kb_files {}", kb_dir.display()));
            self.kb_files.clone()
        }

        fn program_data(&self) -> Result<PathBuf, String> {
            self.note("program_data".into());
            self.program_data.clone()
        }

        fn system_volume(&self) -> Result<String, String> {
            self.note("system_volume".into());
            Ok(r"\\?\volume{1}\".into())
        }

        fn open_store(&self, data_root: &Path) -> Result<PathBuf, String> {
            self.note(format!("store {}", data_root.display()));
            self.store.clone().map(|()| data_root.to_path_buf())
        }
    }

    const INSTALL: &str = r"C:\Program Files\Purge";
    const EXE: &str = r"C:\Program Files\Purge\purge-broker.exe";
    const ROOT: &str = r"C:\ProgramData\Purge";

    #[test]
    fn all_checks_pass_in_order() {
        let f = Fake::passing();
        let started = check_with(&f).unwrap();
        assert_eq!(
            f.calls(),
            [
                "elevated".to_owned(),
                "exe".into(),
                format!("dir {INSTALL}"),
                format!("file {EXE}"),
                format!("dir {INSTALL}\\kb"),
                format!("file {INSTALL}\\Purge.exe"),
                format!("kb_files {INSTALL}\\kb"),
                "program_data".into(),
                format!("dir {ROOT}"),
                "system_volume".into(),
                format!("store {ROOT}"),
            ]
        );
        assert_eq!(started.install_dir, Path::new(INSTALL));
        assert_eq!(started.kb_dir, Path::new(r"C:\Program Files\Purge\kb"));
        assert_eq!(
            started.client_image,
            Path::new(r"C:\Program Files\Purge\Purge.exe")
        );
        assert_eq!(started.data_root, Path::new(ROOT));
        assert_eq!(started.store, Path::new(ROOT));

        let s = started.engine_settings();
        assert_eq!(
            s.baseline_dir.as_deref(),
            Some(Path::new(r"C:\Program Files\Purge\kb\baselines"))
        );
        assert_eq!(s.purge_dirs, [INSTALL, ROOT]);
        assert_eq!(
            s.msi_table_dir.as_deref(),
            Some(Path::new(r"C:\ProgramData\Purge\fp\msitables"))
        );
        assert_eq!(
            s.local_baseline_dir.as_deref(),
            Some(Path::new(r"C:\ProgramData\Purge\baseline"))
        );
        assert!(s.check_shipped_dir);
        assert_eq!(s.volume_rule, VolumeRule::On(r"\\?\volume{1}\".into()));
    }

    #[test]
    fn not_elevated_reads_no_directory() {
        for elevated in [Ok(false), Err("no token".to_owned())] {
            let f = Fake {
                elevated,
                ..Fake::passing()
            };
            let e = check_with(&f).unwrap_err();
            assert_eq!((e.code(), e.exit_code()), ("not_elevated", 20));
            assert_eq!(f.calls(), ["elevated"]);
        }
    }

    #[test]
    fn an_untrusted_install_never_reaches_the_store() {
        let dir = Fake {
            untrusted_dirs: vec![PathBuf::from(INSTALL)],
            ..Fake::passing()
        };
        let file = Fake {
            untrusted_files: vec![PathBuf::from(EXE)],
            ..Fake::passing()
        };
        let bare = Fake {
            exe: PathBuf::from("purge-broker.exe"),
            ..Fake::passing()
        };
        let kb = Fake {
            untrusted_dirs: vec![PathBuf::from(format!(r"{INSTALL}\kb"))],
            ..Fake::passing()
        };
        for f in [&dir, &file, &bare, &kb] {
            let e = check_with(f).unwrap_err();
            assert_eq!(
                (e.code(), e.exit_code()),
                ("install_untrusted", 21),
                "{e:?}"
            );
            assert!(
                !f.calls()
                    .iter()
                    .any(|c| c == "program_data" || c.starts_with("store")),
                "{:?}",
                f.calls()
            );
        }
        assert!(dir.calls().last().unwrap().starts_with("dir "));
        assert!(file.calls().last().unwrap().starts_with("file "));
        assert!(kb.calls().last().unwrap().starts_with("dir "));
        assert!(
            check_with(&dir)
                .unwrap_err()
                .line()
                .contains(r"C:\Program Files\Purge: refused by the fake")
        );
        assert!(
            check_with(&kb)
                .unwrap_err()
                .line()
                .contains(r"C:\Program Files\Purge\kb: refused by the fake")
        );
    }

    /// S7: the client image and every KB file are judged on their own, and a user-writable one
    /// refuses the start before the store is located.
    #[test]
    fn the_client_image_and_every_kb_file_are_judged() {
        let baselines = format!(r"{INSTALL}\kb\baselines");
        let a = PathBuf::from(format!(r"{baselines}\a.tsv.gz"));
        let b = PathBuf::from(format!(r"{baselines}\b.tsv.gz"));
        let image = PathBuf::from(format!(r"{INSTALL}\Purge.exe"));
        let image_bad = Fake {
            untrusted_files: vec![image.clone()],
            ..Fake::passing()
        };
        let file_bad = Fake {
            kb_files: Ok(vec![a.clone(), b.clone()]),
            untrusted_files: vec![b.clone()],
            ..Fake::passing()
        };
        let dir_bad = Fake {
            kb_files: Ok(vec![a.clone()]),
            untrusted_dirs: vec![PathBuf::from(&baselines)],
            ..Fake::passing()
        };
        let unreadable = Fake {
            kb_files: Err("access denied".into()),
            ..Fake::passing()
        };
        for (f, what) in [
            (&image_bad, "Purge.exe"),
            (&file_bad, "b.tsv.gz"),
            (&dir_bad, "baselines"),
            (&unreadable, "access denied"),
        ] {
            let e = check_with(f).unwrap_err();
            assert_eq!(e.code(), "install_untrusted", "{what}: {e:?}");
            assert!(e.line().contains(what), "{what}: {}", e.line());
            assert!(!f.calls().iter().any(|c| c == "program_data"));
        }
        // Both files are looked at, in order, when the first passes.
        let ok = Fake {
            kb_files: Ok(vec![a.clone(), b.clone()]),
            ..Fake::passing()
        };
        check_with(&ok).unwrap();
        let calls = ok.calls();
        let at = |s: String| calls.iter().position(|c| *c == s).unwrap();
        assert!(at(format!("file {}", a.display())) < at(format!("file {}", b.display())));
        assert!(at(format!("dir {baselines}")) < at(format!("file {}", a.display())));
    }

    #[test]
    fn an_untrusted_data_root_is_never_opened() {
        let root = Fake {
            untrusted_dirs: vec![PathBuf::from(ROOT)],
            ..Fake::passing()
        };
        let located = Fake {
            program_data: Err("no ProgramData".into()),
            ..Fake::passing()
        };
        for f in [&root, &located] {
            let e = check_with(f).unwrap_err();
            assert_eq!((e.code(), e.exit_code()), ("store_integrity", 22), "{e:?}");
            assert!(
                !f.calls().iter().any(|c| c.starts_with("store")),
                "{:?}",
                f.calls()
            );
        }
        let failing = Fake {
            store: Err("index.json is user-writable".into()),
            ..Fake::passing()
        };
        let e = check_with(&failing).unwrap_err();
        assert_eq!(e.code(), "store_integrity");
        assert!(
            e.line().contains("index.json is user-writable"),
            "{}",
            e.line()
        );
    }

    #[test]
    fn failure_lines_name_code_and_exit_code() {
        let e = StartFailure::InstallUntrusted(r"D:\x: on volume a".into());
        assert_eq!(
            e.line(),
            r"purge-broker did not start: install_untrusted (exit code 21): D:\x: on volume a"
        );
        assert_eq!(e.reason(), r"D:\x: on volume a");
    }
}
