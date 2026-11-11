//! The shared vocabulary of the Purge engine.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §5.2): the types every other crate, the UI (through generated
//! DTOs) and the VM rig agree on: `Target`, `Scope`, `AppRef`, `Evidence`, `Blocker`, `Candidate`,
//! `Plan`, `Journal`, `Inverse`. All of them are `serde`-serialisable and derive `schemars::JsonSchema`, so
//! the JSON Schema the C# client is generated from comes straight from this crate.
//!
//! Milestone: M0 lands the subset the rig already uses (vm/RIG.md §7): [`Target`], [`Band`] and the minimal
//! plan document [`Plan`] (`purge.plan/0`). The rest of the §5.2 entities land in M1a (§11.1).

mod plan;
mod target;

pub use plan::{Band, Category, Plan, PlanItem, PlanSchema, ScanMode, Tool};
pub use target::Target;
