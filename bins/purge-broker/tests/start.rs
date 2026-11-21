//! The broker's start checks on the real binary (M3 design 3.4, T6, T7; package M3-HARDEN).
//!
//! Each run is started with a planted environment: `PURGE_KB_DIR`, `ProgramData`,
//! `ALLUSERSPROFILE` and `SystemDrive` point at a planted tree. Whatever the verdict, the broker
//! names no path of that tree. A failure also writes one line to the Application event log.
//!
//! The elevated cases are `#[ignore]`d and run in the elevated pass of `vm/win-unit.ps1`. A
//! win-unit bundle holds test binaries only: there `PURGE_TEST_BROKER_EXE` names the broker binary;
//! without it and without the build's own binary the unelevated test is skipped.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The broker binary: `PURGE_TEST_BROKER_EXE`, else the one cargo built; `None` when neither exists.
fn broker() -> Option<PathBuf> {
    let exe = std::env::var_os("PURGE_TEST_BROKER_EXE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_purge-broker")));
    exe.is_file().then_some(exe)
}

/// A scratch directory below the temp directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir =
            std::env::temp_dir().join(format!("purge-broker-start-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A planted tree that looks like a KB and a data root.
fn planted() -> Scratch {
    let s = Scratch::new("planted");
    for d in [
        r"kb\baselines",
        r"ProgramData\Purge\sessions",
        r"ProgramData\Purge\Quarantine",
    ] {
        std::fs::create_dir_all(s.0.join(d)).unwrap();
    }
    std::fs::write(s.0.join(r"ProgramData\Purge\sessions\index.json"), b"{}").unwrap();
    s
}

/// Runs `exe` with the planted environment. `SystemDrive` is the planted directory itself: the
/// known folder `ProgramData` is then `<plant>\ProgramData` (see `purge_win::known_folders`).
fn run(exe: &Path, plant: &Path) -> Output {
    Command::new(exe)
        .env("PURGE_KB_DIR", plant.join("kb"))
        .env("ProgramData", plant.join("ProgramData"))
        .env("ALLUSERSPROFILE", plant.join("ProgramData"))
        .env("SystemDrive", plant)
        .output()
        .unwrap()
}

fn elevated() -> bool {
    purge_win::sid::is_elevated().unwrap()
}

/// The stderr of `out`, after checking that it names nothing of the planted tree.
fn stderr_without(out: &Output, plant: &Path) -> String {
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    let planted = plant.to_string_lossy().to_ascii_lowercase();
    assert!(
        !err.to_ascii_lowercase().contains(&planted),
        "the broker named the planted tree: {err}"
    );
    err
}

/// A copy in the user's temp directory: refused as `install_untrusted` (21) when elevated, and
/// before that as `not_elevated` (20) when not.
#[test]
fn from_a_user_directory_it_refuses_to_start() {
    let Some(broker) = broker() else {
        eprintln!("no broker binary (set PURGE_TEST_BROKER_EXE): skipped");
        return;
    };
    let plant = planted();
    let user = Scratch::new("usercopy0");
    let copy = user.0.join("purge-broker.exe");
    std::fs::copy(&broker, &copy).unwrap();
    let out = run(&copy, &plant.0);
    let err = stderr_without(&out, &plant.0);
    if elevated() {
        assert_eq!(out.status.code(), Some(21), "{err}");
        assert!(err.contains("install_untrusted"), "{err}");
    } else {
        assert_eq!(out.status.code(), Some(20), "{err}");
        assert!(err.contains("not_elevated"), "{err}");
    }
}

/// M3-HARDEN win-unit (elevated): a copy in a user-writable directory is refused; a copy in an
/// admin-only directory on the system volume passes the install check and then judges the
/// machine's data root, never the planted one.
#[test]
#[ignore = "needs an elevated administrator: writes a directory below Program Files"]
fn elevated_copies_are_judged_by_their_directory() {
    assert!(elevated(), "run elevated");
    let broker = broker().expect("no broker binary: set PURGE_TEST_BROKER_EXE");
    let plant = planted();

    let user = Scratch::new("usercopy");
    let copy = user.0.join("purge-broker.exe");
    std::fs::copy(&broker, &copy).unwrap();
    let out = run(&copy, &plant.0);
    let err = stderr_without(&out, &plant.0);
    assert_eq!(out.status.code(), Some(21), "{err}");
    assert!(err.contains("install_untrusted"), "{err}");

    let program_files =
        purge_win::known_folders::known_folder(purge_win::known_folders::KnownFolder::ProgramFiles)
            .unwrap();
    let dir = program_files.join(format!("purge-m3-harden-test-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("kb")).unwrap();
    let copy = dir.join("purge-broker.exe");
    std::fs::copy(&broker, &copy).unwrap();
    // No `Purge.exe` beside it: the client image cannot be judged, so the start is refused (M3-R1 S7).
    let out = run(&copy, &plant.0);
    let err = stderr_without(&out, &plant.0);
    assert_eq!(out.status.code(), Some(21), "{err}");
    assert!(err.contains("Purge.exe"), "{err}");
    std::fs::write(dir.join("Purge.exe"), b"not a UI").unwrap();
    let out = run(&copy, &plant.0);
    let _ = std::fs::remove_dir_all(&dir);
    let err = stderr_without(&out, &plant.0);
    match out.status.code() {
        // Every start check passed; the command line (none was given) is refused.
        Some(23) => assert!(err.contains("--pipe is missing"), "{err}"),
        // No install.ps1 data root on this machine: the machine's one was judged.
        Some(22) => {
            let root = purge_win::known_folders::machine_program_data()
                .unwrap()
                .join("Purge");
            assert!(
                err.to_ascii_lowercase()
                    .contains(&root.to_string_lossy().to_ascii_lowercase()),
                "{err}"
            );
        }
        other => panic!("exit {other:?}: {err}"),
    }
}
