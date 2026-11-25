//! Thin, safe wrappers over the Win32 APIs the engine needs, and nothing else.
//!
//! Responsibility (ENGINE_PLAN.md §3.2):
//! - `reg`: raw `RegEnumKeyExW` / `RegQueryInfoKeyW` with an explicit registry view, a walk that opens
//!   symbolic links with `REG_OPTION_OPEN_LINK` instead of following them, `CurrentControlSet` →
//!   `ControlSet00N` and `HKU\<SID>\Software\Classes` → `HKU\<SID>_Classes` mapping;
//! - `fs`: `FindFirstFileExW` with `FIND_FIRST_EX_LARGE_FETCH` that never traverses reparse points,
//!   handle-based operations, `FileIdInfo`;
//! - tokens, SIDs, Known Folders, `ProfileList`, offline hives (offreg), MSI (`msi.dll`), AppX (WinRT),
//!   SCM, Task Scheduler, firewall rules (WMI), shell links (`SLGP_RAWPATH`), signer and version info,
//!   Restart Manager, System Restore, and the broker consent `TaskDialog`.
//!
//! Features: `read` (default) exposes read-only access. `write` adds mutating calls and is enabled only by
//! `purge-exec`; `cargo xtask check-deps` proves it never reaches `purge-mcp`.
//!
//! Milestone: read side in M1a/M1b, `write` in M2, consent dialog in M3 (§11.1).

#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("purge-win supports x86_64 Windows only (ENGINE_PLAN.md §3.2)");

pub mod appx;
#[cfg(feature = "write")]
pub mod appx_write;
pub mod cmdline;
pub mod env;
pub mod eventlog;
#[cfg(feature = "write")]
pub mod firewall;
pub mod fs;
#[cfg(feature = "write")]
pub mod fs_write;
#[cfg(feature = "read")]
pub mod icons;
pub mod known_folders;
#[cfg(feature = "run")]
pub mod launch;
pub mod msi;
pub mod msi_db;
pub mod offreg;
pub mod os;
pub mod pipe;
pub mod pipe_client;
pub mod privilege;
pub mod process;
pub mod reg;
#[cfg(feature = "write")]
pub mod reg_write;
#[cfg(feature = "write")]
pub mod rm;
pub mod scm;
pub mod secure;
pub mod shelllink;
pub mod sid;
pub mod signer;
#[cfg(feature = "write")]
pub mod sr;
pub mod sxs;
pub mod taskdialog;
pub mod taskschd;
pub mod token;
pub mod versioninfo;
