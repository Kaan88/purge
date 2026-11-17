//! Scanner REG-SHAREDDLLS (ENGINE_PLAN.md §5.6, C-PATHSTORES): the app's reference counters in
//! `...\CurrentVersion\SharedDLLs`, both registry views.
//!
//! The keys are path-keyed stores: each value is named after a file and holds the number of installs
//! that use it. The keys themselves are structural (guard rule `reg.shareddlls`), never offered. A value
//! is looked at only when its name, decoded as the store requires ([`ScanCtx::path_from_value_name`]), is
//! a file inside an InstallRoot of the fingerprint; a file outside every root is never a candidate,
//! whatever its name holds, and a match on the value's data never counts. Each value of each view is its
//! own candidate.
//!
//! - The count must be accounted for by the app, by the framework's rule
//!   ([`ScanCtx::shared_count_unexplained`], the one `msi_blockers` applies to paths): the file's count
//!   summed over **both views** (the two views are two keys, not one: WOW64 redirects `SharedDLLs`; an
//!   install counted in either still uses the file), against the app's MSI components keyed on the
//!   file that the fresh index still lists one of its products as a client of, or 1 for an app without
//!   MSI products when the file is proven gone. A greater count means other installs still use the
//!   file: hard `SharedRefcount`. Data that is not a complete `REG_DWORD` is an unknown count:
//!   `SharedRefcount` too.
//! - File proven absent: `path_named_value(file_missing = true)` (can be Safe when the whole root is
//!   gone); file present or unknown: Likely.
//! - [`ScanCtx::msi_blockers`] on the file, without its own `SharedRefcount` (the same rule for a file
//!   that is there; the counter's verdict above knows whether it is): another product's component keyed
//!   on the file blocks.
//! - Another app's root around the file, or a reference of another app to it, blocks.
//!
//! Reads: one `values()` of each view's store. A view that cannot be read (any error but "not there")
//! gives nothing from that view and one scan warning.

use purge_index::ownership::{SHARED_DLL_UNKNOWN, area};
use purge_model::{Action, Blocker, Candidate, Category, RootKind, Target};
use purge_source::types::{REG_DWORD, RegValue, SourceError};

use crate::framework::{AppIdentityView, PathStore, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "REG-SHAREDDLLS";

/// What the scanner reads: the values of the store (the pattern covers both views).
const ROOTS: &[RootSpec] = &[RootSpec::reg(
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs",
    Some(0),
)];

/// The store as the guard spells it (`purge_guard::containers::M1B_VALUE_CONTAINERS`).
const VALUE_CONTAINERS: &[&str] = &[r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs"];

/// The REG-SHAREDDLLS scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegSharedDlls;

impl Scanner for RegSharedDlls {
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
        if !ctx.fp.roots.iter().any(|r| r.kind == RootKind::InstallRoot) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for key in purge_index::ownership::SHARED_DLLS {
            // Missing, or unknown: nothing from this view; unknown is said.
            let values = match ctx.reg.values(key) {
                Ok(values) => values,
                Err(SourceError::NotFound) => continue,
                Err(e) => {
                    ctx.ext.warn(
                        ID,
                        format!("{key}: not read ({e}); its counters are not offered"),
                    );
                    continue;
                }
            };
            for value in &values {
                if let Some(candidate) = counter_candidate(ctx, key, value) {
                    out.push(candidate);
                }
            }
        }
        out
    }
}

/// The candidate for one counter of the store `key`, or `None` when its name is not a file in a root.
fn counter_candidate(ctx: &ScanCtx<'_>, key: &str, value: &RegValue) -> Option<Candidate> {
    let file = ctx.path_from_value_name(PathStore::SharedDlls, &value.name)?;
    ctx.inside_install_root(&file)?;
    let missing = ctx.fs.exists(&file).is_absent();
    let mut b = ctx.candidate(
        ID,
        Target::RegValue {
            path: key.to_owned(),
            name: value.name.clone(),
        },
        Action::DeleteValue,
        Category::Registration,
    );
    b = b.path_named_value(PathStore::SharedDlls, missing);
    if !b.has_positive_evidence() {
        return None;
    }

    // This counter, then the file's count over both views (the views are two keys, and an install in
    // either still uses the file), judged by the framework's rule.
    let count = (value.data.ty == REG_DWORD && value.data.is_complete())
        .then(|| value.data.dword())
        .flatten();
    let held = match count {
        None => true,
        Some(count) => {
            let total = match ctx.ext.ownership.shared_dll_count(&file) {
                Some(total) => total.max(count),
                // The index did not see this counter: the other view is unknown unless it read both.
                None if !ctx.ext.ownership.stats().complete(area::SHARED_DLLS) => {
                    SHARED_DLL_UNKNOWN
                }
                None => count,
            };
            ctx.shared_count_unexplained(&file, total, missing)
        }
    };
    if held {
        b.blocker(Blocker::SharedRefcount);
    }
    // The file's other MSI owners. Their `SharedRefcount` is the same rule for a file that is there;
    // the counter's verdict above knows whether it is.
    for blocker in ctx.msi_blockers(&Target::Path { path: file.clone() }) {
        if blocker != Blocker::SharedRefcount {
            b.blocker(blocker);
        }
    }
    for blocker in ctx.other_apps.path_blockers(&file) {
        if matches!(
            blocker,
            Blocker::InsideOtherApp { .. } | Blocker::ReferencedByOtherApp { .. }
        ) {
            b.blocker(blocker);
        }
    }
    b.baseline_blocker()
        .existed_before_blocker()
        .other_app_blockers();
    Some(b.build())
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
    }
}
