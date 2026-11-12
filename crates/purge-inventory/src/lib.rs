//! Program inventory: what is installed and how to remove it.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §4): enumerate ARP entries (HKLM 64/32-bit views and every user
//! hive), MSI products in all contexts, Burn bundles and their child packages, and AppX packages; generate
//! quiet uninstall strings per installer kind. Written fresh from BCU (Apache-2.0, attributed per file)
//! and Microsoft documentation; the clone's list builder is not reused.
//!
//! Milestone: ARP and the minimal uninstall runner in M1a, MSI/Burn/AppX depth in M1b (§11.1).

pub mod arp;
pub mod kind;
pub mod msi_merge;
pub mod quiet;
pub mod runner;
pub mod verify_gone;
