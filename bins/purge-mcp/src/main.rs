//! `purge-mcp`: the MCP server AI agents talk to (ENGINE_PLAN.md §8).
//!
//! It exposes the `Read` and `Propose` capability sets of `purge-rpc` with paths redacted, and links no
//! executor: it depends only on `purge-model` and `purge-rpc`, which `cargo xtask check-deps` enforces.
//!
//! Milestone: M6 (§11.1). This is a stub until then.

fn main() {
    eprintln!(
        "purge-mcp {}: not implemented in M0",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(1);
}
