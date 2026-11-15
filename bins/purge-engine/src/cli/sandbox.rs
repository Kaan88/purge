//! The `sandbox-dev` build: the executor verbs of a `rig-exec` build, for a developer trying Purge inside
//! Sandboxie (docs/SANDBOX_TEST.md). Never in releases.
//!
//! What changes against `rig-exec`:
//! - **Store.** A relaxed store (purge-exec's `test-support` roots: owned by the current user, no
//!   administrator ACLs) under [`ROOT_VAR`], or `%LOCALAPPDATA%\PurgeSandboxDev` when it is unset. `exec`
//!   creates it on first use; the other verbs need it to exist.
//! - **Elevation.** Not needed: [`crate::cli::exec::run_live`] answers "elevated" for this build.
//! - **Sandboxie only.** Every destructive verb (`exec`, `undo`, `journal resume` / `rollback`,
//!   `quarantine purge`) is refused with [`Exit::NotInSandbox`](crate::cli::Exit) unless the process runs
//!   inside Sandboxie, which this module tells by `SbieDll.dll` being loaded in it: Sandboxie injects that
//!   DLL into every sandboxed process (the x64 and the x86 DLL have the same name). The check runs before
//!   anything is read or created, so this build cannot change the real machine by accident.
//!
//! `uninstall` (the vendor's uninstaller, which removes things too) is refused outside Sandboxie the same
//! way. The read-only verbs (`inventory`, `harvest`, `scan`, `journal recover` / `show`, `quarantine
//! expiring`) work anywhere.

use std::cell::Cell;
use std::ffi::{OsStr, OsString, c_void};
use std::path::{Path, PathBuf};

use purge_exec::storage::{StorageError, StorageRoots};

/// Printed by `--version` of a `sandbox-dev` build, and shown by the UI's title bar and About.
pub const BUILD_MARKER: &str = "SANDBOX DEV BUILD: destructive verbs run only inside Sandboxie, on a relaxed \
                                store; not for real use";

/// Overrides the directory of the relaxed store (an absolute path).
pub const ROOT_VAR: &str = "PURGE_SANDBOX_DEV_ROOT";

/// The store's directory under `%LOCALAPPDATA%` when [`ROOT_VAR`] is unset.
pub const DEFAULT_DIR: &str = "PurgeSandboxDev";

/// The DLL Sandboxie injects into every process it runs.
pub const SBIE_DLL: &str = "SbieDll.dll";

/// What a refused destructive verb prints after its name.
pub const REFUSAL: &str = "this is a SANDBOX DEV BUILD and the process is not running inside Sandboxie \
                           (SbieDll.dll is not loaded); start it in a Sandboxie box. Nothing was done.";

thread_local! {
    static INSIDE_OVERRIDE: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Test hook: answers [`inside_sandboxie`] with `value` on the calling thread (`None` goes back to the
/// real check). Only the tests call it; the binary never does.
#[doc(hidden)]
pub fn set_inside_for_tests(value: Option<bool>) {
    INSIDE_OVERRIDE.with(|cell| cell.set(value));
}

/// Whether the process runs inside Sandboxie: [`SBIE_DLL`] is loaded in it.
pub fn inside_sandboxie() -> bool {
    INSIDE_OVERRIDE
        .with(Cell::get)
        .unwrap_or_else(|| module_loaded(SBIE_DLL))
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
}

/// Whether a module of this name is loaded in the process (`GetModuleHandleW`, which never loads one).
fn module_loaded(name: &str) -> bool {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call; the returned handle is
    // only compared with null, never used or freed.
    let handle = unsafe { GetModuleHandleW(wide.as_ptr()) };
    !handle.is_null()
}

/// The store's directory: [`ROOT_VAR`] when set and not empty, else `<local_app_data>\PurgeSandboxDev`.
///
/// # Errors
///
/// A one-line message when the variable is not an absolute path, or when neither value is there.
pub fn data_root(var: Option<&OsStr>, local_app_data: Option<&OsStr>) -> Result<PathBuf, String> {
    if let Some(var) = var.filter(|v| !v.is_empty()) {
        let path = PathBuf::from(var);
        if !path.is_absolute() {
            return Err(format!(
                "{ROOT_VAR}={} is not an absolute path",
                path.display()
            ));
        }
        return Ok(path);
    }
    match local_app_data.filter(|v| !v.is_empty()) {
        Some(base) => Ok(PathBuf::from(base).join(DEFAULT_DIR)),
        None => Err(format!("neither {ROOT_VAR} nor LOCALAPPDATA is set")),
    }
}

/// The relaxed store at `root`. When nothing is there it is created only with `create` (its parent too);
/// otherwise the answer is [`StorageError::NotInstalled`].
///
/// # Errors
///
/// What the store reports, or the creation of the parent directory failing.
pub fn store_at(root: &Path, create: bool) -> Result<StorageRoots, StorageError> {
    if std::fs::symlink_metadata(root).is_ok() {
        return StorageRoots::relaxed(root);
    }
    if !create {
        return Err(StorageError::NotInstalled(root.to_path_buf()));
    }
    if let Some(parent) = root.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| StorageError::InvalidPath(format!("{}: {e}", parent.display())))?;
    }
    StorageRoots::install_relaxed(root)
}

/// The store of a live run: the directory of [`data_root`] from the process environment, created only when
/// `create` is set.
pub fn live_store(create: bool) -> Result<StorageRoots, StorageError> {
    let var: Option<OsString> = std::env::var_os(ROOT_VAR);
    let local: Option<OsString> = std::env::var_os("LOCALAPPDATA");
    let root = data_root(var.as_deref(), local.as_deref()).map_err(StorageError::InvalidPath)?;
    store_at(&root, create)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_store_directory_comes_from_the_variable_or_local_app_data() {
        let local = OsStr::new(r"C:\Users\u\AppData\Local");
        assert_eq!(
            data_root(None, Some(local)).unwrap(),
            Path::new(r"C:\Users\u\AppData\Local\PurgeSandboxDev")
        );
        assert_eq!(
            data_root(Some(OsStr::new("")), Some(local)).unwrap(),
            Path::new(r"C:\Users\u\AppData\Local\PurgeSandboxDev")
        );
        assert_eq!(
            data_root(Some(OsStr::new(r"D:\sbx\store")), Some(local)).unwrap(),
            Path::new(r"D:\sbx\store")
        );
        assert!(
            data_root(Some(OsStr::new(r"rel\store")), Some(local))
                .unwrap_err()
                .contains("not an absolute path")
        );
        assert!(data_root(None, None).is_err());
    }

    #[test]
    fn the_store_is_created_only_when_asked() {
        let base = std::env::temp_dir().join(format!(
            "purge-sbx-store-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let root = base.join("nested").join("store");
        assert!(matches!(
            store_at(&root, false),
            Err(StorageError::NotInstalled(_))
        ));
        assert!(!base.exists(), "nothing is created without create");
        let roots = store_at(&root, true).unwrap();
        roots.check().unwrap();
        assert!(roots.read_index().unwrap().sessions.is_empty());
        // A second use opens the same store.
        store_at(&root, false).unwrap().check().unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_override_is_per_thread_and_the_real_check_answers_no_here() {
        set_inside_for_tests(Some(true));
        assert!(inside_sandboxie());
        set_inside_for_tests(Some(false));
        assert!(!inside_sandboxie());
        set_inside_for_tests(None);
        // The test runner itself does not run in Sandboxie (when it does, this says so).
        assert_eq!(inside_sandboxie(), module_loaded(SBIE_DLL));
        assert!(module_loaded("kernel32.dll"));
        assert!(!module_loaded("no-such-module-purge.dll"));
    }
}
