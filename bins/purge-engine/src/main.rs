//! `purge-engine`: one executable, two roles (ENGINE_PLAN.md §3.1, §3.4).
//!
//! - `--stdio`: medium-integrity server for the UI (inventory, sizes, per-user work);
//! - CLI verbs for the VM rig and power users. Headless `exec` exists only with the `rig-exec` feature.
//!   (The elevated broker is its own binary, `purge-broker`; the engine has no broker mode.)
//!
//! Milestone: the CLI verbs `inventory`, `harvest`, `uninstall`, `scan` and `plan show` in M1a;
//! `exec`/`undo`/`journal`/`quarantine` in M2, `--stdio` in M3 (§11.1). The M2 executor verbs run only
//! in a `rig-exec` build (the VM rig); a normal build refuses them with exit code 5 because they need
//! the consent dialog. `kb lint` reports "not implemented" with exit code 1.
//!
//! This file only wires the live machine into [`purge_engine::cli::run`]: the `Live` sources, the live
//! process host, and the settings taken from the process (see [`settings`]).

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("purge-engine supports x86_64 Windows only (ENGINE_PLAN.md §3.2)");

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use purge_engine::cli::{self, Env};
use purge_engine::pipeline::{Settings, Sources, VolumeRule};
use purge_inventory::runner::{LiveHost, RunOptions};
use purge_source::live::Live;
use purge_source::metered::{self, Meter, MeteredFileSystem, MeteredRegistry, MeteredSystem};

/// Overrides the knowledge-base directory; its `baselines` subdirectory holds the baselines. Read
/// only by an engine that is not elevated, or by a `rig-exec` build ([`kb_override_allowed`]).
const KB_DIR_VAR: &str = "PURGE_KB_DIR";

/// What [`settings_from`] is made of, read from the process by [`settings`].
struct ProcessFacts {
    /// The directory of the running executable.
    exe_dir: Option<PathBuf>,
    /// `%PURGE_KB_DIR%`, when the variable may be read at all ([`kb_override_allowed`]).
    kb_dir_var: Option<OsString>,
    /// The machine's `ProgramData` (`purge_win::known_folders::machine_program_data`): from the
    /// registry and the running Windows directory, never from the environment.
    program_data: Option<PathBuf>,
    /// The volume rule (`VolumeRule::live`).
    volume_rule: VolumeRule,
}

/// Whether `PURGE_KB_DIR` is honoured (BL-R1 S4, M3 design 3.4): by an engine that is not elevated,
/// whose baseline answers decide nothing a standard user could not do, and by a `rig-exec` build
/// for the VM rig. A release engine that is elevated never reads it. An engine that cannot tell
/// whether it is elevated counts as elevated.
fn kb_override_allowed(elevated: Option<bool>, rig: bool) -> bool {
    rig || elevated == Some(false)
}

/// The engine's settings from the process (see [`settings_from`]).
fn settings() -> Settings {
    let elevated = purge_win::sid::is_elevated().ok();
    let kb_dir_var = kb_override_allowed(elevated, cfg!(feature = "rig-exec"))
        .then(|| std::env::var_os(KB_DIR_VAR))
        .flatten();
    settings_from(ProcessFacts {
        exe_dir: std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(PathBuf::from)),
        kb_dir_var,
        program_data: purge_win::known_folders::machine_program_data().ok(),
        volume_rule: VolumeRule::live(),
    })
}

/// The engine's settings: baselines from `%PURGE_KB_DIR%\baselines` where that variable is honoured
/// ([`kb_override_allowed`]), else from `<exe dir>\kb\baselines`; Purge's own directories are the
/// exe's directory and the data root `<ProgramData>\Purge`, with `ProgramData` taken from the machine
/// and not from the environment (`%ProgramData%` and `%SystemDrive%` are the caller's to choose);
/// the MSI table cache is `<data root>\fp\msitables` (`pipeline::table_cache` decides whether it is
/// used) and the local baseline cache is `<data root>\baseline` (`pipeline::local_cache` decides).
/// The sources are the live machine, so an elevated engine uses the baseline directory only when it
/// is admin-only writable (`Settings::check_shipped_dir`), and the baseline directory and both
/// caches only on the system volume (`Settings::volume_rule`), also when the baselines come from
/// `PURGE_KB_DIR`.
fn settings_from(facts: ProcessFacts) -> Settings {
    let ProcessFacts {
        exe_dir,
        kb_dir_var,
        program_data,
        volume_rule,
    } = facts;
    let baseline_dir = kb_dir_var
        .filter(|v| !v.is_empty())
        .map(|kb| PathBuf::from(kb).join("baselines"))
        .or_else(|| exe_dir.as_ref().map(|d| d.join("kb").join("baselines")));
    let mut purge_dirs: Vec<String> = Vec::new();
    if let Some(dir) = exe_dir.as_ref().and_then(|d| d.to_str()) {
        purge_dirs.push(dir.to_owned());
    }
    let mut msi_table_dir = None;
    let mut local_baseline_dir = None;
    let mut data_root = None;
    if let Some(data) = program_data.as_ref().and_then(|p| p.to_str()) {
        let root = format!("{}\\Purge", data.trim_end_matches('\\'));
        data_root = Some(PathBuf::from(&root));
        msi_table_dir = Some(PathBuf::from(format!("{root}\\fp\\msitables")));
        local_baseline_dir = Some(PathBuf::from(format!("{root}\\baseline")));
        purge_dirs.push(root);
    }
    Settings {
        baseline_dir,
        purge_dirs,
        msi_table_dir,
        // By path, as `pipeline::table_cache` decides: the engine has no checked store.
        msi_table_source: None,
        local_baseline_dir,
        data_root,
        check_shipped_dir: true,
        volume_rule,
        local_build: None,
    }
}

/// When set (to anything but empty), every source call is counted and timed, and the counters of each
/// step go to stderr after its progress line ([`purge_source::metered`]). Off by default; it changes
/// nothing the engine reads or writes.
const TIMING_VAR: &str = "PURGE_TIMING";

fn main() -> ExitCode {
    // First, before anything can load a library by name (M3 design 3.4). A failure leaves the
    // default search order, which is what the engine had before; there is nothing better to do.
    let _ = purge_win::secure::restrict_dll_search();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let live = Live::new();
    let timing = std::env::var_os(TIMING_VAR).is_some_and(|v| !v.is_empty());
    let meter: Option<&'static Meter> = timing.then(|| &*Box::leak(Box::new(Meter::new())));
    let metered = meter.map(|meter| {
        metered::install(meter);
        (
            MeteredRegistry::new(&live.registry, meter),
            MeteredFileSystem::new(&live.fs, meter),
            MeteredSystem::new(&live.system, meter),
        )
    });
    let sources = match &metered {
        Some((reg, fs, sys)) => Sources { reg, fs, sys },
        None => Sources {
            reg: &live.registry,
            fs: &live.fs,
            sys: &live.system,
        },
    };
    let mut host = LiveHost::new();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let (mut out, mut err) = (stdout.lock(), stderr.lock());
    let exit = cli::run(
        &args,
        &mut Env {
            sources,
            host: &mut host,
            settings: settings(),
            run_options: RunOptions::default(),
            stdout: &mut out,
            stderr: &mut err,
        },
    );
    if let Some(meter) = meter {
        let _ = writeln!(err, "timing: total: {}", meter.snapshot().summary());
    }
    let _ = out.flush();
    ExitCode::from(exit.code())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn purge_kb_dir_is_honoured_only_unelevated_or_in_a_rig_build() {
        assert!(kb_override_allowed(Some(false), false));
        assert!(!kb_override_allowed(Some(true), false));
        assert!(
            !kb_override_allowed(None, false),
            "unknown counts as elevated"
        );
        for elevated in [Some(true), Some(false), None] {
            assert!(kb_override_allowed(elevated, true));
        }
    }

    fn facts(kb: Option<&str>, program_data: Option<&str>) -> ProcessFacts {
        ProcessFacts {
            exe_dir: Some(PathBuf::from(r"C:\Program Files\Purge")),
            kb_dir_var: kb.map(OsString::from),
            program_data: program_data.map(PathBuf::from),
            volume_rule: VolumeRule::On(r"\\?\volume{0}\".into()),
        }
    }

    #[test]
    fn settings_take_the_data_root_from_the_machine_and_the_kb_from_the_exe() {
        let s = settings_from(facts(None, Some(r"C:\ProgramData\")));
        assert_eq!(
            s.baseline_dir.as_deref(),
            Some(Path::new(r"C:\Program Files\Purge\kb\baselines"))
        );
        assert_eq!(
            s.purge_dirs,
            [r"C:\Program Files\Purge", r"C:\ProgramData\Purge"]
        );
        assert_eq!(
            s.msi_table_dir.as_deref(),
            Some(Path::new(r"C:\ProgramData\Purge\fp\msitables"))
        );
        assert_eq!(
            s.local_baseline_dir.as_deref(),
            Some(Path::new(r"C:\ProgramData\Purge\baseline"))
        );
        assert_eq!(
            s.data_root.as_deref(),
            Some(Path::new(r"C:\ProgramData\Purge"))
        );
        assert!(s.check_shipped_dir);
        assert_eq!(s.volume_rule, VolumeRule::On(r"\\?\volume{0}\".into()));

        // An honoured PURGE_KB_DIR replaces the baseline directory only; an empty one is ignored.
        let s = settings_from(facts(Some(r"D:\kb"), Some(r"C:\ProgramData")));
        assert_eq!(
            s.baseline_dir.as_deref(),
            Some(Path::new(r"D:\kb\baselines"))
        );
        let s = settings_from(facts(Some(""), Some(r"C:\ProgramData")));
        assert_eq!(
            s.baseline_dir.as_deref(),
            Some(Path::new(r"C:\Program Files\Purge\kb\baselines"))
        );

        // No machine ProgramData: no data root and no caches; the environment is not asked instead.
        let s = settings_from(facts(None, None));
        assert_eq!(s.purge_dirs, [r"C:\Program Files\Purge"]);
        assert!(s.msi_table_dir.is_none() && s.local_baseline_dir.is_none());
    }
}
