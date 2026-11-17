//! Scanner REG-INSTFOLDERS (ENGINE_PLAN.md §5.6, C-PATHSTORES): the app's entries in Windows
//! Installer's list of the directories it created, `...\CurrentVersion\Installer\Folders`.
//!
//! The key is a path-keyed store: each value is named after a directory (usually with a trailing
//! backslash) and the key itself is a structural container, never offered. A value is the app's only when
//! its name, decoded as the store requires ([`ScanCtx::path_from_value_name`]: environment references
//! expanded, the trailing separator dropped, canonical form), is a directory at or inside an InstallRoot
//! of the fingerprint. The value's data never counts, and a directory outside every root is never a
//! candidate, whatever its name holds.
//!
//! - Directory proven absent: `path_named_value(file_missing = true)`: `PointsIntoInstallRoot` plus
//!   `DanglingRef` when the whole root is gone on the recorded volume (P-PATH-1: can be Safe).
//! - Directory present (or its state unknown): `PointsIntoInstallRoot` only: Likely.
//! - [`ScanCtx::msi_blockers`] on the directory: a component of another product (installed or a stale
//!   client) with its key path in the directory blocks; so does one of the app's products that Windows
//!   still lists.
//! - Another app's root at, around or inside the directory, or a file of another app in it, blocks.
//!
//! Reads: one `values()` of the store.

use purge_model::{Action, Blocker, Candidate, Category, RootKind, Target};
use purge_source::types::SourceError;

use crate::framework::{AppIdentityView, PathStore, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "REG-INSTFOLDERS";

/// The store.
const FOLDERS: &str = purge_index::ownership::INSTALLER_FOLDERS;

/// What the scanner reads: the values of the store.
const ROOTS: &[RootSpec] = &[RootSpec::reg(
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders",
    Some(0),
)];

/// The store as the guard spells it (`purge_guard::containers::M1B_VALUE_CONTAINERS`).
const VALUE_CONTAINERS: &[&str] =
    &[r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders"];

/// The REG-INSTFOLDERS scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegInstFolders;

impl Scanner for RegInstFolders {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn value_containers(&self) -> &[&'static str] {
        VALUE_CONTAINERS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
        // Without an InstallRoot no name can be the app's: nothing is read.
        if !ctx.fp.roots.iter().any(|r| r.kind == RootKind::InstallRoot) {
            return Vec::new();
        }
        // Missing, or unknown: nothing (unknown is said).
        let values = match ctx.reg.values(FOLDERS) {
            Ok(values) => values,
            Err(SourceError::NotFound) => return Vec::new(),
            Err(e) => {
                ctx.ext.warn(
                    ID,
                    format!("{FOLDERS}: not read ({e}); nothing is offered from it"),
                );
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for value in values {
            let Some(dir) = ctx.path_from_value_name(PathStore::InstallerFolders, &value.name)
            else {
                continue;
            };
            if ctx.inside_install_root(&dir).is_none() {
                continue;
            }
            let missing = ctx.fs.exists(&dir).is_absent();
            let mut b = ctx.candidate(
                ID,
                Target::RegValue {
                    path: FOLDERS.to_owned(),
                    name: value.name.clone(),
                },
                Action::DeleteValue,
                Category::Registration,
            );
            b = b.path_named_value(PathStore::InstallerFolders, missing);
            if !b.has_positive_evidence() {
                continue;
            }
            for blocker in ctx.msi_blockers(&Target::Path { path: dir.clone() }) {
                b.blocker(blocker);
            }
            for blocker in ctx.other_apps.path_blockers(&dir) {
                if matches!(
                    blocker,
                    Blocker::InsideOtherApp { .. }
                        | Blocker::ContainsOtherApp { .. }
                        | Blocker::ReferencedByOtherApp { .. }
                ) {
                    b.blocker(blocker);
                }
            }
            b.baseline_blocker()
                .existed_before_blocker()
                .other_app_blockers();
            out.push(b.build());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_are_well_formed_and_the_store_is_a_guard_container() {
        assert!(ROOTS.iter().all(RootSpec::is_well_formed));
        for container in VALUE_CONTAINERS {
            assert!(purge_guard::containers::M1B_VALUE_CONTAINERS.contains(container));
            assert!(ROOTS.iter().any(|r| r.pattern == *container));
        }
        assert!(FOLDERS.eq_ignore_ascii_case(VALUE_CONTAINERS[0]));
    }
}
