//! The [`SystemSource`] trait: machine and session facts the pipeline needs besides the registry and the
//! filesystem (ENGINE_PLAN.md §3.2, §4.1 MSI, §5.2 fingerprint `os`/`user_sid`, APPX-MIN packages).
//!
//! Facts are about the **interactive user** (the one whose apps are being cleaned), not necessarily the
//! account the engine runs as: the environment map, the known folders and `user_sid` all describe that
//! user.

use std::collections::BTreeMap;

use crate::sysobj::{MsiTables, TaskInfo};
use crate::types::{
    FileTime, KnownFolder, MsiContextState, MsiProduct, OsInfo, PackageInfo, ProcessInfo,
    ProfileInfo, SourceResult,
};

/// Read-only machine and session facts. Object safe; implementations are shared across threads.
pub trait SystemSource: Send + Sync {
    /// Windows edition, build and UBR (selects the `(edition, build)` baseline).
    fn os_info(&self) -> SourceResult<OsInfo>;

    /// The interactive user's SID.
    fn user_sid(&self) -> SourceResult<String>;

    /// Whether the engine runs with an elevated token.
    fn elevated(&self) -> bool;

    /// Every profile from `ProfileList`.
    fn profiles(&self) -> SourceResult<Vec<ProfileInfo>>;

    /// The known folders of the interactive user and the machine. A folder the source could not
    /// resolve is missing from the map.
    fn known_folders(&self) -> SourceResult<BTreeMap<KnownFolder, String>>;

    /// The interactive user's environment block (system + user + volatile), with variable **names
    /// upper-cased** and values expanded.
    fn env(&self) -> SourceResult<BTreeMap<String, String>>;

    /// The running processes.
    fn processes(&self) -> SourceResult<Vec<ProcessInfo>>;

    /// Every installed MSI product in every context visible to the engine.
    fn msi_products(&self) -> SourceResult<Vec<MsiProduct>>;

    /// The state of one ProductCode (`{GUID}`, case-insensitive) in each installation context.
    fn msi_product_state_all(&self, code: &str) -> SourceResult<Vec<MsiContextState>>;

    /// The registered AppX/MSIX packages (APPX-MIN).
    fn packages(&self) -> SourceResult<Vec<PackageInfo>>;

    /// The tables of one cached MSI package, by its `LocalPackage` path (compared case-insensitively).
    /// Within the [`crate::sysobj`] limits: a cut or dropped row sets [`MsiTables::truncated`]. A package
    /// that does not exist is [`SourceError::NotFound`](crate::types::SourceError::NotFound); a source
    /// that holds no tables is `NotCaptured`.
    fn msi_tables(&self, local_package: &str) -> SourceResult<MsiTables>;

    /// Every scheduled task the source can see; more than [`MAX_TASKS`](crate::sysobj::MAX_TASKS) is an
    /// error. A task the scanning user cannot read keeps an empty action list.
    fn tasks(&self) -> SourceResult<Vec<TaskInfo>>;

    /// The current time.
    fn now(&self) -> FileTime;
}
