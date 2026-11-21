//! The `Live` sources: [`LiveRegistry`], [`LiveFileSystem`] and [`LiveSystem`] implement the three source
//! traits by calling `purge-win` (read side only) on the running machine (ENGINE_PLAN.md §3.2, §4.1, §5.10
//! G1).
//!
//! What the Live sources add on top of `purge-win`:
//!
//! - **Canonical key paths to physical opens** (`live/regpath.rs`): `HKLM\SYSTEM\CurrentControlSet` becomes the
//!   `ControlSet00N` that `HKLM\SYSTEM\Select\Current` names; a path strictly below
//!   `HKU\<SID>\Software\Classes` is read from the physical `HKU\<SID>_Classes` hive (the key itself is the
//!   link and is reported as one); a `WOW6432Node` segment where Windows redirects (`HKLM\SOFTWARE\WOW6432Node`,
//!   `HKU\<SID>_Classes\WOW6432Node`) becomes an open with `KEY_WOW64_32KEY` without that segment, so the
//!   redirector also resolves the shared and redirected parts of `SOFTWARE\Classes`. Anywhere else
//!   `WOW6432Node` is an ordinary key name read in the 64-bit view. These are the only links resolved; every
//!   other registry link is reported by [`KeyInfo::is_link`](crate::types::KeyInfo::is_link) and never
//!   followed, and a path that passes through one fails with
//!   [`SourceError::ReparsePoint`](crate::types::SourceError::ReparsePoint).
//! - **One error vocabulary** (`live/errors.rs`): Win32 codes map onto [`SourceError`](crate::types::SourceError)
//!   (`NotFound`, `AccessDenied`, `ReparsePoint`, `WrongKind`, `Other(code)`), and
//!   [`FileSystemSource::exists`](crate::filesystem::FileSystemSource::exists) only answers `Absent` when
//!   `ERROR_FILE_NOT_FOUND` / `ERROR_PATH_NOT_FOUND` comes from a mounted fixed NTFS/ReFS volume with no
//!   reparse point on the existing part of the path.
//! - **Shortcut reads on a dedicated thread** (`live/shortcut.rs`): `IShellLinkW` needs COM, so `.lnk` files are
//!   read on one worker thread that enters a COM apartment for each read, never on a scanner thread.
//! - **The interactive user's environment** (`live/system.rs`): built from the registry (the system block under
//!   `Session Manager\Environment`, the profile, `HKU\<SID>\Environment` and `HKU\<SID>\Volatile
//!   Environment`), not from the engine's own process environment.
//!
//! Only the `read` and `appx` features of `purge-win` are used; nothing here can write or start a process
//! (`write` and `run` stay off). [`LiveSystem::processes`] lists the Toolhelp32 snapshot with image paths;
//! [`LiveSystem::packages`] lists AppX/MSIX packages through WinRT `PackageManager` (see
//! `live/system.rs`).
//!
//! [`LiveSystem::packages`]: crate::system::SystemSource::packages
//! [`LiveSystem::processes`]: crate::system::SystemSource::processes

mod errors;
mod filesystem;
mod local_baseline;
mod registry;
mod regpath;
mod shortcut;
mod sysobj;
mod system;

#[cfg(test)]
mod test_ffi;
#[cfg(test)]
mod tests;

pub use filesystem::LiveFileSystem;
pub use local_baseline::LiveLocal;
pub use registry::LiveRegistry;
pub use system::LiveSystem;

/// The three Live sources together, for callers that want all of them.
#[derive(Debug, Default)]
pub struct Live {
    /// The registry.
    pub registry: LiveRegistry,
    /// The filesystem.
    pub fs: LiveFileSystem,
    /// Machine and session facts.
    pub system: LiveSystem,
}

impl Live {
    /// Live sources for the user the engine runs as.
    pub fn new() -> Self {
        Self::default()
    }

    /// Live sources whose session facts describe the user with `sid` (the interactive user when the
    /// engine runs as another account).
    pub fn for_user(sid: impl Into<String>) -> Self {
        Self {
            system: LiveSystem::for_user(sid),
            ..Self::default()
        }
    }
}
