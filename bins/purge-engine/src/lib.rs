//! `purge-engine` library: the pipeline and CLI logic behind the binary (ENGINE_PLAN.md §3.1, §3.4).
//!
//! - [`pipeline`]: the steps of §3.6 (inventory, harvest, uninstall, scan, plan emission), generic over
//!   the three `purge-source` traits so the live machine and fixtures share one code path;
//! - [`stdio`]: the medium engine's JSON-RPC server over stdin/stdout (M3-STDIO);
//! - [`cli`]: argument parsing per verb, the verbs themselves, output files and exit codes.
//!
//! The binary (`main.rs`) only wires the live sources, the live process host and the process
//! environment into [`cli::run`].

pub mod cli;
pub mod pipeline;
pub mod stdio;
