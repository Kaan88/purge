//! Knowledge packs.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §5.9): load the declarative JSON packs and data files under `kb/`,
//! lint them (nothing may resolve into a deny-list rule or a secrets store), and, later, track the pack
//! lifecycle for local and agent-proposed packs.
//!
//! Milestone: static packs and lint in M4, lifecycle states in M6 (§11.1).
