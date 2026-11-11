//! Canonicalisation, the hard deny-list and safety gates. Pure: no I/O.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §5.10): canonicalise paths and registry keys, match them against
//! the deny-list (Windows, shared components, other apps' anchors, secrets stores), and expose the gates
//! that block a candidate regardless of its evidence.
//!
//! Milestone: read-side gates in M1a, executor-time re-checks in M2 (§11.1).
