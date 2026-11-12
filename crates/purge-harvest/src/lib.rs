//! Pre-uninstall harvest: everything an app registered, captured before its uninstaller runs.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §5.2, §6): validated roots (`validate_root`), the Inno Setup
//! uninstall-log parser (written from the published format), MSI tables, Burn dependencies, AppX links,
//! the reference snapshot, subtree baselines of harvested keys, co-removed products, harvested tokens,
//! and the pre-harvest cache used for external uninstalls. The result is the per-app fingerprint.
//!
//! Milestone: Inno log, reference snapshot, tokens and co-products in M1a; MSI tables and Burn in M1b;
//! pre-harvest cache in M4 (§11.1).

pub mod anchors;
pub mod appx_link;
pub mod assoc;
pub mod coproducts;
pub mod exes;
pub mod harvest;
pub mod inno;
pub mod inno_map;
pub mod refsnap;
pub mod roots;
pub mod subtree;
pub mod tokens;
