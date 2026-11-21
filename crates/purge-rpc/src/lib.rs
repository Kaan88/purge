//! The engine API: newline-delimited JSON-RPC 2.0.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §3.3): request, response and notification framing, the method
//! table, and the capability sets `Read`, `Propose` and `Execute` that each transport (stdio, broker pipe,
//! CLI, MCP) is allowed to use. Holds no executor code, so `purge-mcp` can depend on it.
//!
//! Milestone: M3 with the UI and broker; agent `Propose` methods in M6 (§11.1).

pub mod error;
pub mod frame;
pub mod methods;
pub mod sets;
pub mod table;
