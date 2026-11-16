//! The executor: the only crate that changes the system.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §7): validate a plan, move files to a same-volume quarantine,
//! write a lossless JSON registry backup, apply actions with a hashed journal and typed inverses, handle
//! locked files and reboot-time operations, create restore points, and run undo, recovery and expiry.
//! Depends on `purge-win` with the `write` feature; must never be linked into `purge-mcp`.
//!
//! Milestone: M2 (§11.1).

pub mod act_fs;
pub mod act_reg;
pub mod act_typed;
pub mod durable;
pub mod execute;
pub mod expiry;
pub mod fault;
pub mod gate;
pub mod journal;
pub mod locked;
pub mod plan_in;
pub mod prepare;
pub mod recover;
pub mod regbackup;
pub mod regfile;
pub mod report;
pub mod storage;
#[cfg(test)]
mod test_ffi;
pub mod undo;
