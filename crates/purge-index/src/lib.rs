//! Reference and ownership indexes.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §5.5): a reference index over registry names and data (including
//! `REG_MULTI_SZ` and UTF-16 inside binary values), an ownership index that includes MSI component rows,
//! the clean-Windows baseline filter keyed by (edition, build) from `kb/baselines/`, and the targeted
//! queries scanners run from harvested anchors.
//!
//! Milestone: targeted queries in M1a, MSI ownership rows in M1b (§11.1).

pub mod baseline;
pub mod matcher;
pub mod queries;
pub mod refscan;
