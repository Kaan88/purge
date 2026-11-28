//! Repository automation for Purge (ENGINE_PLAN.md §3.2, §11.4). Run as `cargo xtask <command>`.
//!
//! - `ui-strings`: fail if any 12+ character string literal of ours equals a string of the reference
//!   product's English language file (path in `PURGE_UT_STRINGS`, never committed).
//! - `check-deps`: fail if `purge-mcp` depends on any Purge crate other than `purge-model` and
//!   `purge-rpc`, in its own tree or under workspace feature unification (so never the executor); also
//!   fail if purge-win's code names a forbidden service, MSI or firewall API, `netsh` or PowerShell.
//! - `no-new-walks`: fail if a file of `purge-scan/src` outside `ref_any.rs`, `framework.rs` and
//!   `framework/m1b.rs` calls `.walker(` or `refscan::scan` (the scan makes one reference walk).
//! - `baseline-sites`: fail if the scan or the harvest uses the baseline view at a place that is not a
//!   listed site with a class (presence or absence), asks the view for absence outside the capped
//!   path, or negates a presence answer (BASELINE_LOCAL_DESIGN.md §4.3).
//! - `scanner-coverage`: fail if a scanner declares a root the VM rig does not capture, or if the
//!   scanners' value containers differ from the guard's table (ENGINE_PLAN.md §5.6, §5.10).
//! - `replay`: run the engine pipeline offline over one frozen rig run (harvest at snap-1, scan at
//!   snap-2) and write its `purge.plan/0`; `replay-all` does so for the M0 runs and scores them with
//!   rigtool when it is built; `replay-diff` replays the M0 runs and compares the plans with the
//!   committed m1a.6 plans, every difference with an allowed reason (see replay.rs).
//! - `bench-launch`: the launch bench of the WinUI shell against the bare-WinUI control (not part of `ci`; see
//!   bench_launch.rs).
//! - `gen-dto`: JSON Schemas of the engine API's types and the C# source-generation glue, under
//!   `ui/Purge.Client/` (see gen_dto.rs). `--check` fails on a difference.
//! - `notices`: write `THIRD-PARTY-NOTICES.txt`, the licences of the crates the shipped binaries link,
//!   from `Cargo.lock` (see notices.rs); `--check` fails when the committed file is out of date.
//! - `broker-timings`: the broker's timing lines of a run (collected by `vm/guest/broker-timings.ps1`) as
//!   the numbers of gate G12 (see broker_timings.rs; not part of `ci`).
//! - `ci`: fmt check, clippy, tests, a standalone clippy of `purge-mcp`, clippy and the feature-gated
//!   tests of the rig-exec build (engine CLI), every purge-exec test target with its `fault-inject` and
//!   `test-support` features (crash matrix, object ops), check-deps, notices --check, no-new-walks, ui-strings,
//!   scanner-coverage, `gen-dto --check`, and the UI (`dotnet build` and `dotnet test`; skipped when no
//!   .NET SDK is installed unless `--require-ui` is given).

mod baseline_sites;
mod bench_launch;
mod broker_timings;
mod check_deps;
mod gen_dto;
mod lex;
mod no_new_walks;
mod notices;
mod replay;
mod replay_diff;
mod scanner_coverage;
mod ui_strings;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail};

const USAGE: &str = "usage: cargo xtask <ui-strings | check-deps | no-new-walks | baseline-sites | \
                     scanner-coverage | replay | replay-all | replay-diff | bench-launch | gen-dto | \
                     broker-timings | ci>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("ui-strings") => ui_strings::run(&workspace_root()),
        Some("check-deps") => check_deps::run(&workspace_root()),
        Some("no-new-walks") => no_new_walks::run(&workspace_root()),
        Some("baseline-sites") => baseline_sites::run(&workspace_root()),
        Some("scanner-coverage") => scanner_coverage::run(),
        Some("replay") => replay::run_one(&workspace_root(), &args[1..]),
        Some("replay-all") => replay::run_all(&workspace_root(), &args[1..]),
        Some("replay-diff") => replay_diff::run(&workspace_root(), &args[1..]),
        Some("bench-launch") => bench_launch::run(&workspace_root(), &args[1..]),
        Some("gen-dto") => gen_dto::run(&workspace_root(), &args[1..]),
        Some("notices") => notices::run(&workspace_root(), &args[1..]),
        Some("broker-timings") => broker_timings::run(&args[1..]),
        Some("ci") => ci(&workspace_root(), &args[1..]),
        Some("-h" | "--help") => {
            println!("{USAGE}");
            Ok(true)
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("xtask: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// The workspace root (two levels above this crate's manifest).
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("tools/xtask has a grandparent")
        .to_path_buf()
}

/// The cargo that launched us, so `ci` uses the same toolchain.
pub(crate) fn cargo() -> Command {
    Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
}

fn cargo_step(root: &Path, args: &[&str]) -> Result<bool> {
    println!("xtask ci: cargo {}", args.join(" "));
    let status = cargo()
        .args(args)
        .current_dir(root)
        .status()
        .with_context(|| format!("running cargo {}", args.join(" ")))?;
    Ok(status.success())
}

/// The features of the rig's executor build, for the `ci` steps that compile it.
const RIG_FEATURES: &str = "purge-engine/rig-exec,purge-exec/test-support";

/// The features every purge-exec test target needs: the same `fault-inject` and `test-support` the rig
/// build unifies in (`rig-exec` enables `fault-inject`), named on purge-exec alone.
const EXEC_TEST_FEATURES: &str = "purge-exec/fault-inject,purge-exec/test-support";

/// The broker's one feature, which no default build turns on (check-deps rules 4b and 6): the consent
/// dialog drawn with the toolkit. The `ci` steps that name it are the only ones that compile
/// `consent::toolkit`, its tests and the preview example.
const BROKER_TOOLKIT_FEATURE: &str = "toolkit-consent";

fn ci(root: &Path, args: &[String]) -> Result<bool> {
    let mut require_ui = false;
    for arg in args {
        match arg.as_str() {
            "--require-ui" => require_ui = true,
            other => bail!("ci: unknown argument {other}"),
        }
    }
    let cargo_steps: [&[&str]; 9] = [
        &["fmt", "--all", "--", "--check"],
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        &["test", "--workspace"],
        // purge-mcp on its own, with only the features its own tree enables: code that compiles only
        // because another member unified a feature in fails here (see check_deps.rs).
        &[
            "clippy",
            "-p",
            "purge-mcp",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        // The executor CLI and every purge-exec test target, which only a rig-exec build and
        // purge-exec's `fault-inject` and `test-support` features compile (review M2 M23, M1b R2b S1:
        // `act_service`, `act_task`, `act_firewall`, `m1b_found`, `roundtrip` and `crash` are empty
        // without them). purge-engine's library and CLI tests, and its engine tests, whose `m1b_exec`
        // module (M1B-X-INTEG) only a rig-exec build compiles; its other targets do not depend on the
        // features and ran in the workspace step.
        &[
            "clippy",
            "-p",
            "purge-engine",
            "-p",
            "purge-exec",
            "--features",
            RIG_FEATURES,
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        &[
            "test",
            "-p",
            "purge-engine",
            "--features",
            RIG_FEATURES,
            "--lib",
            "--test",
            "exec_cli",
            "--test",
            "engine",
        ],
        &["test", "-p", "purge-exec", "--features", EXEC_TEST_FEATURES],
        // The broker with its toolkit consent dialog, which the workspace steps above do not compile
        // (review of BROKER-CONSENT-UI, B2): the dialog's own modules and tests, and the preview.
        &[
            "clippy",
            "-p",
            "purge-broker",
            "--features",
            BROKER_TOOLKIT_FEATURE,
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        &[
            "test",
            "-p",
            "purge-broker",
            "--features",
            BROKER_TOOLKIT_FEATURE,
        ],
    ];
    for step in cargo_steps {
        if !cargo_step(root, step)? {
            bail!("step failed: cargo {}", step.join(" "));
        }
    }
    println!("xtask ci: check-deps");
    if !check_deps::run(root)? {
        bail!("step failed: check-deps");
    }
    println!("xtask ci: notices --check");
    if !notices::run(root, &["--check".to_owned()])? {
        bail!("step failed: notices --check");
    }
    println!("xtask ci: no-new-walks");
    if !no_new_walks::run(root)? {
        bail!("step failed: no-new-walks");
    }
    println!("xtask ci: baseline-sites");
    if !baseline_sites::run(root)? {
        bail!("step failed: baseline-sites");
    }
    println!("xtask ci: ui-strings");
    if !ui_strings::run(root)? {
        bail!("step failed: ui-strings");
    }
    println!("xtask ci: scanner-coverage");
    if !scanner_coverage::run()? {
        bail!("step failed: scanner-coverage");
    }
    println!("xtask ci: gen-dto --check");
    if !gen_dto::run(root, &["--check".to_owned()])? {
        bail!("step failed: gen-dto --check");
    }
    println!("xtask ci: ui");
    if !ui_step(root, require_ui)? {
        bail!("step failed: ui");
    }
    println!("xtask ci: all steps passed");
    Ok(true)
}

/// The .NET SDK: `dotnet` on PATH first, then the SDK's default directory. `None` when neither runs.
fn dotnet() -> Option<PathBuf> {
    for candidate in [
        PathBuf::from("dotnet"),
        PathBuf::from(r"C:\Program Files\dotnet\dotnet.exe"),
    ] {
        let runs = Command::new(&candidate)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if runs.is_ok_and(|s| s.success()) {
            return Some(candidate);
        }
    }
    None
}

/// `dotnet build` of the solution, then `dotnet test` of the client tests. Without an SDK the step is
/// skipped, unless `--require-ui` asks for it (M3_DESIGN.md §6.5, package M3-GEN-DTO).
fn ui_step(root: &Path, require: bool) -> Result<bool> {
    let Some(dotnet) = dotnet() else {
        if require {
            bail!("no .NET SDK found (looked on PATH and in C:\\Program Files\\dotnet)");
        }
        println!("xtask ci: no .NET SDK; ui skipped (pass --require-ui to require it)");
        return Ok(true);
    };
    let solution = root.join("ui").join("Purge.slnx");
    println!(
        "xtask ci: {} build {}",
        dotnet.display(),
        solution.display()
    );
    let status = Command::new(&dotnet)
        .arg("build")
        .arg(&solution)
        .arg("--nologo")
        .current_dir(root)
        .status()
        .with_context(|| format!("running {} build", dotnet.display()))?;
    if !status.success() {
        return Ok(false);
    }
    let tests = root
        .join("ui")
        .join("Purge.Client.Tests")
        .join("Purge.Client.Tests.csproj");
    println!("xtask ci: {} test {}", dotnet.display(), tests.display());
    let status = Command::new(&dotnet)
        .arg("test")
        .arg(&tests)
        .args(["--no-build", "--nologo"])
        .current_dir(root)
        .status()
        .with_context(|| format!("running {} test", dotnet.display()))?;
    Ok(status.success())
}
