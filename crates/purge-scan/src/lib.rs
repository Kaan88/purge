//! Leftover scanners.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §5.6): the `Scanner` trait and the scanner catalog. Each scanner
//! turns harvested anchors and index queries into candidates carrying typed evidence and blockers; it never
//! decides a band and never touches the system directly (all reads go through `purge-source`).
//!
//! Milestone: first scanners in M1a, MSI/COM/system scanners in M1b, the rest in M4 (§11.1).
