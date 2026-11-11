//! Plan building.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §7.1): collapse nested selections (only Safe parents absorb
//! children), derive `EmptyAfterPlan` containers, order actions, and compute the plan hash the consent
//! dialog shows and the executor checks.
//!
//! Milestone: dry-run plans in M1a, hash binding to execution in M2 (§11.1).
