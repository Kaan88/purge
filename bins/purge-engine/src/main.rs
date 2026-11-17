//! `purge-engine`: one executable, three roles (ENGINE_PLAN.md §3.1, §3.4).
//!
//! - `--stdio`: medium-integrity server for the UI (inventory, icons, sizes, per-user work);
//! - `--broker`: the elevated broker (harvest, uninstall, scan, plan, consent, execute, undo);
//! - CLI verbs for the VM rig and power users. Headless `exec` exists only with the `rig-exec` feature.
//!
//! Milestone: the CLI verbs `inventory`, `harvest`, `uninstall`, `scan` and `plan show` in M1a;
//! `exec`/`undo`/`journal`/`quarantine` in M2, `--stdio` and `--broker` in M3 (§11.1). The M2 executor
//! verbs run only in a `rig-exec` build (the VM rig); a normal build refuses them with exit code 5
//! because they need the consent dialog. `--stdio`, `--broker` and `kb lint` report "not implemented"
//! with exit code 1.
//!
//! This file only wires the live machine into [`purge_engine::cli::run`]: the `Live` sources, the live
//! process host, and the settings taken from the process (see [`settings`]).

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("purge-engine supports x86_64 Windows only (ENGINE_PLAN.md §3.2)");

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use purge_engine::cli::{self, Env};
use purge_engine::pipeline::{Settings, Sources};
use purge_inventory::runner::{LiveHost, RunOptions};
use purge_source::live::Live;
use purge_source::metered::{self, Meter, MeteredFileSystem, MeteredRegistry, MeteredSystem};

/// Overrides the knowledge-base directory; its `baselines` subdirectory holds the baselines.
const KB_DIR_VAR: &str = "PURGE_KB_DIR";

/// The engine's settings from the process: baselines from `%PURGE_KB_DIR%\baselines`, else from
/// `<exe dir>\kb\baselines`; Purge's own directories are the exe's directory and
/// `%ProgramData%\Purge`; the MSI table cache is `%ProgramData%\Purge\fp\msitables`
/// (`pipeline::table_cache` decides whether it is used).
fn settings() -> Settings {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from));
    let baseline_dir = std::env::var_os(KB_DIR_VAR)
        .filter(|v| !v.is_empty())
        .map(|kb| PathBuf::from(kb).join("baselines"))
        .or_else(|| exe_dir.as_ref().map(|d| d.join("kb").join("baselines")));
    let mut purge_dirs: Vec<String> = Vec::new();
    if let Some(dir) = exe_dir.as_ref().and_then(|d| d.to_str()) {
        purge_dirs.push(dir.to_owned());
    }
    let mut msi_table_dir = None;
    if let Some(data) = std::env::var_os("ProgramData").and_then(|v| v.into_string().ok()) {
        let root = format!("{}\\Purge", data.trim_end_matches('\\'));
        msi_table_dir = Some(PathBuf::from(format!("{root}\\fp\\msitables")));
        purge_dirs.push(root);
    }
    Settings {
        baseline_dir,
        purge_dirs,
        msi_table_dir,
    }
}

/// When set (to anything but empty), every source call is counted and timed, and the counters of each
/// step go to stderr after its progress line ([`purge_source::metered`]). Off by default; it changes
/// nothing the engine reads or writes.
const TIMING_VAR: &str = "PURGE_TIMING";

fn main() -> ExitCode {
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
