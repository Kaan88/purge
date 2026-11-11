//! Data-source abstraction between the scanners and the machine.
//!
//! Responsibility (ENGINE_PLAN.md §3.2): the `RegistrySource` and `FileSystemSource` traits, with a `Live`
//! implementation over `purge-win` (read only) and a `Fixture` implementation over JSON and offline hives
//! (offreg), so every scanner can be tested without touching the host.
//!
//! Milestone: M1a (§11.1).
