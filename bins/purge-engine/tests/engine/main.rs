//! Pipeline and CLI integration tests on committed mini-fixtures (ENGINE_PLAN.md §3.4, §10.1).
//!
//! Each machine is a `purge.fixture/1` JSON (`tests/fixtures/<name>.before.json`) plus what its
//! uninstaller removes (`<name>.uninstall.json`). The fake process host "runs" the uninstaller by
//! switching the machine to its "after" state; no test starts a real process.
//!
//! - `inno`: an Inno Setup app with an uninstall log, end to end through the CLI (inventory, harvest,
//!   uninstall, scan, plan show), with golden plan and table;
//! - `nsis`: an NSIS app that takes a co-product with it while a sibling product of the same vendor
//!   stays, through the pipeline functions, with a golden plan;
//! - `exit_codes`: failed, cancelled and timed-out uninstalls, broken preconditions, write errors and
//!   `scan --path`;
//! - `m1b_exec` (`rig-exec` builds): `exec --fp` and `undo` of a service, a scheduled task and a
//!   firewall rule over in-memory object backends, and their exit codes.

mod common;
mod exit_codes;
mod inno;
#[cfg(feature = "rig-exec")]
mod m1b_exec;
mod nsis;
