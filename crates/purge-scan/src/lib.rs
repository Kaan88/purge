//! Leftover scanners.
//!
//! Responsibility (ENGINE_PLAN.md §3.2, §5.6): the `Scanner` trait and the scanner catalog. Each scanner
//! turns harvested anchors and index queries into candidates carrying typed evidence and blockers; it never
//! decides a band and never touches the system directly (all reads go through `purge-source`).
//!
//! Milestone: first scanners in M1a, MSI/COM/system scanners in M1b, the rest in M4 (§11.1).

pub mod catalog;
pub mod cls_assoc;
pub mod cls_aumid;
pub mod cls_fileexts;
pub mod cls_progid;
pub mod cls_protocol;
pub mod cls_regapps;
pub mod cls_toasts;
pub mod cls_verbs;
pub mod framework;
pub mod fs_appdata;
pub mod fs_installdir;
pub mod fs_shortcuts;
pub mod fs_uninstaller;
pub mod fs_vendorparent;
pub mod ref_any;
pub mod reg_apppaths;
pub mod reg_env;
pub mod reg_run;
pub mod reg_software;
pub mod skeleton;
pub mod sys_appx;
