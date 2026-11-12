//! SYS-APPX (ENGINE_PLAN.md §5.6): the sparse AppX/MSIX packages linked to the app (APPX-MIN).
//!
//! A Win32 app can register a *sparse* package: an identity-only package whose content stays in the
//! app's own directory (VS Code's and Notepad++'s context-menu packages). The uninstaller often leaves
//! the registration behind. The harvest links such a package to the app by its external location and
//! records its full name and family in the fingerprint; this scanner offers each linked package that is
//! still registered ([`SystemSource::packages`]).
//!
//! One candidate per package: `Target::AppxPackage`, `AppxExternalLocation` evidence,
//! `Category::Package`, `Action::RemovePackage`. Removing a package cannot be undone, so every candidate
//! carries the `ReversibilityNone` soft blocker and is at most Likely.
//!
//! Never offered: a framework or resource package, a Store- or System-signed package, a package installed
//! under `%WINDIR%` (an inbox app, whatever its signature field says: rig lists do not record the
//! signature), a package that is not sparse, and a package whose external location lies in another
//! installed app's root.
//!
//! [`SystemSource::packages`]: purge_source::system::SystemSource::packages

use purge_guard::prefix;
use purge_model::{Action, Blocker, Candidate, Category, Target};
use purge_source::types::{PackageInfo, PackageSignatureKind};

use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "SYS-APPX";

/// The scanner reads the package list of `SystemSource::packages` (the rig's structured lists, vm/RIG.md
/// §3), not a snapshot root.
const ROOTS: &[RootSpec] = &[];

/// The SYS-APPX scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SysAppx;

impl Scanner for SysAppx {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
        let anchors = &ctx.fp.anchors;
        if anchors.package_full_names.is_empty() && anchors.package_families.is_empty() {
            return Vec::new();
        }
        // An unreadable package list offers nothing: "still registered" cannot be shown.
        let Ok(packages) = ctx.sys.packages() else {
            return Vec::new();
        };
        let mut out: Vec<Candidate> = Vec::new();
        for package in &packages {
            if never_offered(ctx, package) {
                continue;
            }
            let mut b = ctx.candidate(
                ID,
                Target::AppxPackage {
                    full_name: package.full_name.clone(),
                },
                Action::RemovePackage,
                Category::Package,
            );
            // Holds only for a package the fingerprint links to the app.
            if !b.appx_external_location() {
                continue;
            }
            b.blocker(Blocker::ReversibilityNone).common_blockers();
            let candidate = b.build();
            if !out.iter().any(|c| c.id == candidate.id) {
                out.push(candidate);
            }
        }
        out
    }
}

/// The packages that are never a leftover of a Win32 app, whatever the fingerprint says.
fn never_offered(ctx: &ScanCtx<'_>, package: &PackageInfo) -> bool {
    if package.is_framework
        || package.is_resource
        || !package.is_sparse()
        || matches!(
            package.signature_kind,
            PackageSignatureKind::Store | PackageSignatureKind::System
        )
    {
        return true;
    }
    let under = |location: &Option<String>, dir: &str| {
        location
            .as_deref()
            .is_some_and(|l| prefix::is_same_or_inside(l, dir))
    };
    if under(&package.install_location, &ctx.guard.windir) {
        return true;
    }
    // Another app's directory holds the package's content: it is that app's package.
    package
        .external_location
        .as_deref()
        .is_some_and(|external| {
            ctx.other_apps
                .path_blockers(external)
                .iter()
                .any(|b| matches!(b, Blocker::InsideOtherApp { .. }))
        })
}
