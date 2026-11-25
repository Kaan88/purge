//! The Rust UI's view models (docs/UI_RUST_PLAN.md, packages UI-MODEL-*): plain state machines that
//! take engine and broker results in and give requests and view state out. No I/O, no toolkit.

mod casefold;
pub mod pipeline;
pub mod programs;
pub mod registry_label;
