//! Repository automation for Purge (ENGINE_PLAN.md §3.2, §11.4). Run as `cargo xtask <command>`.
//!
//! - `ui-strings`: fail if any 12+ character string literal of ours equals a string of the reference
//!   product's English language file (path in `PURGE_UT_STRINGS`, never committed).
//! - `check-deps`: fail if `purge-mcp` depends on any Purge crate other than `purge-model` and
//!   `purge-rpc`, in its own tree or under workspace feature unification (so never the executor).
//! - `ci`: fmt check, clippy, tests, a standalone clippy of `purge-mcp`, check-deps, ui-strings.

mod check_deps;
mod lex;
mod ui_strings;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail};

const USAGE: &str = "usage: cargo xtask <ui-strings | check-deps | ci>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("ui-strings") => ui_strings::run(&workspace_root()),
        Some("check-deps") => check_deps::run(&workspace_root()),
        Some("ci") => ci(&workspace_root()),
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

fn ci(root: &Path) -> Result<bool> {
    let cargo_steps: [&[&str]; 4] = [
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
    println!("xtask ci: ui-strings");
    if !ui_strings::run(root)? {
        bail!("step failed: ui-strings");
    }
    println!("xtask ci: all steps passed");
    Ok(true)
}
