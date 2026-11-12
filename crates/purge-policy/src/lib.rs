//! Policy: bands, preselection and explanations. Pure and versioned.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §5.8): turn a candidate's evidence and blockers into a band
//! (`Safe`, `Likely`, `Weak`, `Blocked`), decide preselection per scan mode, and render the explanation
//! shown to the user. Every change bumps the policy version reported by `engine.hello`.
//!
//! Milestone: M1a (§11.1).

pub mod band;
pub mod bcu_map;
pub mod explain;
pub mod harm;
pub mod score;
