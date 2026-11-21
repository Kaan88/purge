//! BL-R1 S4, M3 design 3.4 (package M3-HARDEN): the real `purge-engine` binary started with a
//! planted environment. `PURGE_KB_DIR` names a planted KB that holds a baseline of exactly this
//! Windows, and `SystemDrive`, `ProgramData` and `ALLUSERSPROFILE` point at the planted tree.
//!
//! - Not elevated, `PURGE_KB_DIR` is honoured (its answers decide nothing a standard user could
//!   not do): `hello` reports the planted baseline as Exact. This shows the plant is a real one.
//! - Elevated, a release build reads nothing from the planted tree: no Exact trust from it, no path
//!   of it in any warning, no directory made in it. That case runs in the elevated pass of
//!   `vm/win-unit.ps1` (`--include-ignored`). A win-unit bundle holds test binaries only: there
//!   `PURGE_TEST_ENGINE_EXE` names the engine binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The engine binary: `PURGE_TEST_ENGINE_EXE`, else the one cargo built; `None` when neither exists.
fn engine() -> Option<PathBuf> {
    let exe = std::env::var_os("PURGE_TEST_ENGINE_EXE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_purge-engine")));
    exe.is_file().then_some(exe)
}

/// A planted tree below the temp directory, removed on drop.
struct Plant(PathBuf);

impl Plant {
    /// `<plant>\kb\baselines\<this Windows>.tsv.gz` and an empty `<plant>\ProgramData\Purge`.
    fn new(name: &str) -> Plant {
        let dir = std::env::temp_dir().join(format!(
            "purge-engine-planted-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let baselines = dir.join(r"kb\baselines");
        std::fs::create_dir_all(&baselines).unwrap();
        std::fs::create_dir_all(dir.join(r"ProgramData\Purge")).unwrap();
        let os = purge_win::os::os_version().unwrap();
        let file = purge_index::baseline::Baseline::file_name(&os.edition_id, os.build, os.ubr);
        std::fs::write(
            baselines.join(file),
            format!(
                "#purge-baseline 1\tT\tPC\t{}\t{}.{}\nK\thklm\\\\software\\\\purgeplantedkey\n",
                os.edition_id, os.build, os.ubr
            ),
        )
        .unwrap();
        Plant(dir)
    }

    fn run_hello(&self, engine: &Path) -> Output {
        Command::new(engine)
            .arg("hello")
            .env("PURGE_KB_DIR", self.0.join("kb"))
            .env("SystemDrive", &self.0)
            .env("ProgramData", self.0.join("ProgramData"))
            .env("ALLUSERSPROFILE", self.0.join("ProgramData"))
            .output()
            .unwrap()
    }

    /// Every directory below the plant, sorted.
    fn listing(&self) -> Vec<PathBuf> {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    out.push(p.clone());
                    walk(&p, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.0, &mut out);
        out.sort();
        out
    }
}

impl Drop for Plant {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn trust(out: &Output) -> String {
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "hello failed: {err}");
    let hello: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    hello["baseline_trust"]
        .as_str()
        .unwrap_or_else(|| panic!("no baseline_trust in {hello}"))
        .to_ascii_lowercase()
}

/// The baseline fields of `hello` (flattened into it).
fn baseline(out: &Output) -> Vec<serde_json::Value> {
    let hello: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    [
        "baseline_available",
        "baseline_trust",
        "baseline_view",
        "baseline_build",
    ]
    .iter()
    .map(|k| hello[*k].clone())
    .collect()
}

#[test]
fn an_unelevated_engine_honours_purge_kb_dir() {
    if purge_win::sid::is_elevated().unwrap() {
        return; // The elevated case is the ignored test below.
    }
    let Some(engine) = engine() else {
        eprintln!("no engine binary (set PURGE_TEST_ENGINE_EXE): skipped");
        return;
    };
    let plant = Plant::new("unelevated");
    let out = plant.run_hello(&engine);
    assert_eq!(
        trust(&out),
        "exact",
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[ignore = "needs an elevated administrator (M3-HARDEN win-unit: planted ProgramData and PURGE_KB_DIR)"]
fn an_elevated_engine_reads_nothing_from_a_planted_environment() {
    assert!(purge_win::sid::is_elevated().unwrap(), "run elevated");
    let engine = engine().expect("no engine binary: set PURGE_TEST_ENGINE_EXE");
    let plant = Plant::new("elevated");
    let before = plant.listing();
    let out = plant.run_hello(&engine);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        plant.listing(),
        before,
        "the engine made a directory in the plant"
    );
    if cfg!(feature = "rig-exec") {
        // A rig build honours PURGE_KB_DIR; the directory rule refuses the plant below the user's
        // temp directory, so the planted baseline is still unused.
        assert_ne!(trust(&out), "exact", "{err}");
        return;
    }
    // A release build does not read the plant at all: no path of it in any line, and the baseline
    // answer is the one the engine gives without the planted environment.
    let planted = plant.0.to_string_lossy().to_ascii_lowercase();
    assert!(
        !err.to_ascii_lowercase().contains(&planted),
        "a warning names the planted tree: {err}"
    );
    let clean = Command::new(&engine).arg("hello").output().unwrap();
    assert!(clean.status.success());
    assert_eq!(baseline(&out), baseline(&clean), "{err}");
}
