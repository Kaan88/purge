//! `purge-engine`: one executable, three roles (ENGINE_PLAN.md §3.1, §3.4).
//!
//! - `--stdio`: medium-integrity server for the UI (inventory, icons, sizes, per-user work);
//! - `--broker`: the elevated broker (harvest, uninstall, scan, plan, consent, execute, undo);
//! - CLI verbs for the VM rig and power users. Headless `exec` exists only with the `rig-exec` feature.
//!
//! Milestone: the CLI verbs `inventory`, `harvest`, `uninstall`, `scan` and `plan show` in M1a;
//! `exec`/`undo`/`journal` in M2, `--stdio` and `--broker` in M3 (§11.1). Those report "not implemented"
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

/// Overrides the knowledge-base directory; its `baselines` subdirectory holds the baselines.
const KB_DIR_VAR: &str = "PURGE_KB_DIR";

/// The engine's settings from the process: baselines from `%PURGE_KB_DIR%\baselines`, else from
/// `<exe dir>\kb\baselines`; Purge's own directories are the exe's directory and
/// `%ProgramData%\Purge`.
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
    if let Some(data) = std::env::var_os("ProgramData").and_then(|v| v.into_string().ok()) {
        purge_dirs.push(format!("{}\\Purge", data.trim_end_matches('\\')));
    }
    Settings {
        baseline_dir,
        purge_dirs,
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let live = Live::new();
    let mut host = LiveHost::new();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let (mut out, mut err) = (stdout.lock(), stderr.lock());
    let exit = cli::run(
        &args,
        &mut Env {
            sources: Sources {
                reg: &live.registry,
                fs: &live.fs,
                sys: &live.system,
            },
            host: &mut host,
            settings: settings(),
            run_options: RunOptions::default(),
            stdout: &mut out,
            stderr: &mut err,
        },
    );
    let _ = out.flush();
    ExitCode::from(exit.code())
}
