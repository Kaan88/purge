//! SYS-APPX (ENGINE_PLAN.md §5.6): the sparse AppX/MSIX packages linked to the app (APPX-MIN).
//!
//! A Win32 app can register a *sparse* package: an identity-only package whose content stays in the
//! app's own directory (VS Code's and Notepad++'s context-menu packages). The uninstaller often leaves
//! the registration behind. The harvest links such a package to the app by its external location and
//! records its full name and family in the fingerprint; this scanner offers each linked package that is
//! still registered ([`SystemSource::packages`]).
//!
//! One candidate per package: `Target::AppxPackage`, `AppxExternalLocation` evidence,
//! `Category::Package`. Removing a package cannot be undone, so every candidate carries the
//! `ReversibilityNone` soft blocker and `Reversibility::None`, and is at most Likely (never preselected).
//!
//! # Which packages (M1b, M1B-S-APPX)
//!
//! Only a package whose `PackageFamilyName` is exactly (case-insensitively) one of the families the
//! harvest linked (`fp.anchors.package_families`), and whose full name belongs to that family. A full
//! name the harvest recorded is not enough on its own, and neither is a publisher id or a similar name.
//!
//! Never offered: a framework or resource package, a bundle (resource id `~` in the full name; the
//! source reports no bundle flag, so this also covers a bundle of frameworks), a Store- or System-signed
//! package, a package installed under `%WINDIR%` (an inbox app, whatever its signature field says: rig
//! lists do not record the signature), a package that is not sparse, and a package whose external
//! location lies in another installed app's root.
//!
//! # Which action (M1b)
//!
//! The executor removes a package for the calling user only. `Action::RemovePackage` is offered only
//! when the package is registered for the scanning user and for nobody else. A package registered for
//! any other user (SYSTEM included) is listed as `Action::ReportOnly`, and its `AppxExternalLocation`
//! evidence carries the fact `other_users = <n>`. When who it is registered for cannot be known (the
//! scanning user's SID cannot be read, the engine is not elevated so the listing shows the engine
//! account's own registrations only, or the listing names no user), it is `ReportOnly` too, with
//! `other_users = unknown`. Removal for all users and deprovisioning are not M1b's (M4).
//!
//! [`SystemSource::packages`]: purge_source::system::SystemSource::packages

use purge_guard::prefix;
use purge_model::{Action, Blocker, Candidate, Category, EvidenceKind, Reversibility, Target};
use purge_source::types::{PackageInfo, PackageSignatureKind};

use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "SYS-APPX";

/// The fact on the `AppxExternalLocation` evidence of a `ReportOnly` package: how many users other than
/// the scanning one it is registered for, or [`OTHER_USERS_UNKNOWN`].
pub const OTHER_USERS: &str = "other_users";

/// The value of [`OTHER_USERS`] when the registered users cannot be known.
pub const OTHER_USERS_UNKNOWN: &str = "unknown";

/// The resource id of a bundle in a package full name.
const BUNDLE_RESOURCE_ID: &str = "~";

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
        if anchors.package_families.is_empty() {
            return Vec::new();
        }
        // An unreadable package list offers nothing: "still registered" cannot be shown.
        let Ok(packages) = ctx.sys.packages() else {
            // warning: the registered packages could not be read; no linked package is checked.
            return Vec::new();
        };
        let registrations = Registrations::of(ctx);
        let mut out: Vec<Candidate> = Vec::new();
        for package in &packages {
            if !linked_family(ctx, package) || never_offered(ctx, package) {
                continue;
            }
            let others = registrations.others(package);
            let action = match others {
                Others::None => Action::RemovePackage,
                Others::Count(_) | Others::Unknown => Action::ReportOnly,
            };
            let mut b = ctx.candidate(
                ID,
                Target::AppxPackage {
                    full_name: package.full_name.clone(),
                },
                action,
                Category::Package,
            );
            // Holds only for a package the fingerprint links to the app.
            if !b.appx_external_location() {
                continue;
            }
            b.reversibility(Reversibility::None)
                .blocker(Blocker::ReversibilityNone)
                .common_blockers();
            if let Some(n) = others.fact() {
                b.evidence_fact(EvidenceKind::AppxExternalLocation, OTHER_USERS, n);
            }
            let candidate = b.build();
            if !out.iter().any(|c| c.id == candidate.id) {
                out.push(candidate);
            }
        }
        out
    }
}

/// Whether the package's family is exactly one the harvest linked, and its full name is of that family.
fn linked_family(ctx: &ScanCtx<'_>, package: &PackageInfo) -> bool {
    let Some(parts) = full_name_parts(&package.full_name) else {
        return false;
    };
    let own_family = format!("{}_{}", parts.name, parts.publisher_id);
    prefix::eq_ci(&own_family, &package.family)
        && ctx
            .fp
            .anchors
            .package_families
            .iter()
            .any(|f| prefix::eq_ci(f, &package.family))
}

/// The five fields of a package full name, `Name_Version_Architecture_ResourceId_PublisherId`.
struct FullNameParts<'a> {
    name: &'a str,
    resource_id: &'a str,
    publisher_id: &'a str,
}

/// Splits a package full name. A package name, version, architecture and publisher id never contain
/// `_`, so a full name has exactly five fields; anything else is not a full name.
fn full_name_parts(full_name: &str) -> Option<FullNameParts<'_>> {
    let fields: Vec<&str> = full_name.split('_').collect();
    let [name, version, arch, resource_id, publisher_id] = fields.as_slice() else {
        return None;
    };
    if name.is_empty() || version.is_empty() || arch.is_empty() || publisher_id.is_empty() {
        return None;
    }
    Some(FullNameParts {
        name,
        resource_id,
        publisher_id,
    })
}

/// The packages that are never a leftover of a Win32 app, whatever the fingerprint says.
fn never_offered(ctx: &ScanCtx<'_>, package: &PackageInfo) -> bool {
    let bundle = full_name_parts(&package.full_name)
        .is_none_or(|parts| parts.resource_id == BUNDLE_RESOURCE_ID);
    if bundle
        || package.is_framework
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

/// Who, besides the scanning user, a package is registered for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Others {
    /// Registered for the scanning user alone.
    None,
    /// Registered for this many other users (and maybe the scanning user).
    Count(usize),
    /// Cannot be known.
    Unknown,
}

impl Others {
    /// The [`OTHER_USERS`] fact, for a package that is not the scanning user's alone.
    fn fact(self) -> Option<String> {
        match self {
            Others::None => None,
            Others::Count(n) => Some(n.to_string()),
            Others::Unknown => Some(OTHER_USERS_UNKNOWN.to_owned()),
        }
    }
}

/// What the scan knows about whose registrations a package listing shows.
struct Registrations {
    /// The scanning user's SID, when the listing shows every user's registrations of a package.
    /// `None` when the SID cannot be read or the listing is the engine account's own (not elevated:
    /// another user's registration of the same package is not in it).
    scanning_user: Option<String>,
}

impl Registrations {
    fn of(ctx: &ScanCtx<'_>) -> Self {
        // warning: without elevation, or without the scanning user's SID, no package is shown to be the
        // scanning user's alone; every linked package is ReportOnly with `other_users = unknown`.
        let scanning_user = ctx
            .sys
            .elevated()
            .then(|| ctx.sys.user_sid().ok())
            .flatten()
            .filter(|sid| !sid.trim().is_empty());
        Self { scanning_user }
    }

    fn others(&self, package: &PackageInfo) -> Others {
        let Some(me) = self.scanning_user.as_deref() else {
            return Others::Unknown;
        };
        let mut users: Vec<&str> = Vec::new();
        for sid in package.users.iter().map(|s| s.trim()) {
            if sid.is_empty() {
                // warning: a registration whose user is not named; who it is cannot be known.
                return Others::Unknown;
            }
            if !users.iter().any(|u| u.eq_ignore_ascii_case(sid)) {
                users.push(sid);
            }
        }
        if users.is_empty() {
            // warning: the listing names no user for the package.
            return Others::Unknown;
        }
        let others = users.iter().filter(|u| !u.eq_ignore_ascii_case(me)).count();
        if others == 0 {
            Others::None
        } else {
            Others::Count(others)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_names_split_into_five_fields() {
        let p = full_name_parts("NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww").expect("parts");
        assert_eq!(
            (p.name, p.resource_id, p.publisher_id),
            ("NotepadPlusPlus", "", "2247w0b46hfww")
        );
        let b = full_name_parts("Vendor.App_1.0.0.0_neutral_~_abc").expect("parts");
        assert_eq!(b.resource_id, BUNDLE_RESOURCE_ID);
        for bad in [
            "",
            "Vendor.App_abc",
            "Vendor.App_1.0.0.0_x64_abc",
            "Vendor.App_1.0.0.0_x64___abc",
            "_1.0.0.0_x64__abc",
            "Vendor.App_1.0.0.0_x64__",
        ] {
            assert!(full_name_parts(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn others_fact() {
        assert_eq!(Others::None.fact(), None);
        assert_eq!(Others::Count(2).fact().as_deref(), Some("2"));
        assert_eq!(Others::Unknown.fact().as_deref(), Some(OTHER_USERS_UNKNOWN));
    }
}
