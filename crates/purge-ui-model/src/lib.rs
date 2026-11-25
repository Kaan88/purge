//! The Rust UI's view models (docs/UI_RUST_PLAN.md, packages UI-MODEL-*): plain state machines that
//! take engine and broker results in and give requests and view state out. No I/O, no toolkit.

pub mod broker_link;
mod casefold;
pub mod history;
pub mod info_bar;
pub mod leftovers;
pub mod local_time;
pub mod pipeline;
pub mod programs;
pub mod registry_label;
pub mod vault;
