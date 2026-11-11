//! The executor: the only crate that changes the system.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §7): validate a plan, move files to a same-volume quarantine,
//! write a lossless JSON registry backup, apply actions with a hashed journal and typed inverses, handle
//! locked files and reboot-time operations, create restore points, and run undo, recovery and expiry.
//! Depends on `purge-win` with the `write` feature; must never be linked into `purge-mcp`.
//!
//! Milestone: M2 (§11.1).
