//! Read-only AppX/MSIX package enumeration through WinRT `PackageManager` (feature `appx`, APPX-MIN).
//!
//! ENGINE_PLAN.md §3.2 and the M1a APPX-MIN decision: enough to link a sparse package to a Win32 install
//! by its external location. [`list_packages`] with [`AppxScope::CurrentUser`] calls
//! `FindPackagesForUser("")` (works at medium integrity); [`AppxScope::AllUsers`] calls `FindPackages()`
//! and `FindUsers(fullName)` and needs elevation.
//!
//! [`list_packages_with`] with [`ListOptions::dependencies`] also reads each package's dependencies
//! (`Package.Dependencies`); the plain [`list_packages`] (the scanner's listing) does not. Whether a
//! package is marked non-removable is not in the public WinRT or Win32 projection, so it is not reported.
//!
//! Per-package properties that a given OS build or package cannot provide (for example
//! `EffectiveExternalPath` before Windows 10 2004, or `InstalledPath` of a staged package) come back as
//! `None` or the default rather than failing the whole listing. Nothing here changes system state.

#![cfg(feature = "appx")]

use std::io;

use windows::ApplicationModel::{Package, PackageSignatureKind};
use windows::Management::Deployment::{PackageInstallState, PackageManager};
use windows::core::HSTRING;

/// Whose packages [`list_packages`] returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppxScope {
    /// The calling user's packages (`FindPackagesForUser("")`). `users` stays empty.
    CurrentUser,
    /// Every package on the machine with the users it is registered for (`FindPackages` + `FindUsers`;
    /// requires administrator rights).
    AllUsers,
}

/// How a package is signed (`Windows.ApplicationModel.PackageSignatureKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureKind {
    /// Not signed.
    None,
    /// Signed with a developer certificate.
    Developer,
    /// Signed with an enterprise certificate.
    Enterprise,
    /// Signed by the Microsoft Store.
    Store,
    /// Part of Windows.
    System,
    /// A value this build does not know.
    Other(i32),
}

impl From<PackageSignatureKind> for SignatureKind {
    fn from(k: PackageSignatureKind) -> Self {
        match k {
            PackageSignatureKind::None => SignatureKind::None,
            PackageSignatureKind::Developer => SignatureKind::Developer,
            PackageSignatureKind::Enterprise => SignatureKind::Enterprise,
            PackageSignatureKind::Store => SignatureKind::Store,
            PackageSignatureKind::System => SignatureKind::System,
            other => SignatureKind::Other(other.0),
        }
    }
}

/// A package's install state for one user (`Windows.Management.Deployment.PackageInstallState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppxInstallState {
    /// Not installed.
    NotInstalled,
    /// Staged (on disk, not registered).
    Staged,
    /// Installed.
    Installed,
    /// Install paused.
    Paused,
    /// A value this build does not know.
    Other(i32),
}

impl From<PackageInstallState> for AppxInstallState {
    fn from(s: PackageInstallState) -> Self {
        match s {
            PackageInstallState::NotInstalled => AppxInstallState::NotInstalled,
            PackageInstallState::Staged => AppxInstallState::Staged,
            PackageInstallState::Installed => AppxInstallState::Installed,
            PackageInstallState::Paused => AppxInstallState::Paused,
            other => AppxInstallState::Other(other.0),
        }
    }
}

/// One user a package is registered for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppxUser {
    /// User SID string.
    pub sid: String,
    /// The package's state for that user.
    pub install_state: AppxInstallState,
}

/// One package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppxPackage {
    /// Package full name (`Name_Version_Arch_ResourceId_PublisherId`).
    pub full_name: String,
    /// Package family name (`Name_PublisherId`).
    pub family_name: String,
    /// Installed location (`Package.InstalledPath`).
    pub installed_location: Option<String>,
    /// External location of a sparse package (`Package.EffectiveExternalPath`); `None` otherwise.
    pub effective_external_path: Option<String>,
    /// Signature kind; `None` when the property is unavailable.
    pub signature_kind: Option<SignatureKind>,
    /// Framework package.
    pub is_framework: bool,
    /// Resource package.
    pub is_resource_package: bool,
    /// Users the package is registered for; filled only for [`AppxScope::AllUsers`].
    pub users: Vec<AppxUser>,
    /// Full names of the packages this package depends on (`Package.Dependencies`, each
    /// `Id().FullName()`), in the order Windows reports them. `None` when they were not requested
    /// ([`ListOptions::dependencies`]) or could not be read completely; never a partial list.
    pub dependencies: Option<Vec<String>>,
}

/// What [`list_packages_with`] reads besides the properties every listing has.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListOptions {
    /// Read each package's dependencies into [`AppxPackage::dependencies`]: one more WinRT collection
    /// per package. The executor needs it; the scanner does not.
    pub dependencies: bool,
}

fn non_empty(s: windows::core::Result<HSTRING>) -> Option<String> {
    s.ok()
        .map(|h| h.to_string_lossy())
        .filter(|s| !s.is_empty())
}

/// Lists packages for `scope`, without dependencies ([`AppxPackage::dependencies`] is `None`).
pub fn list_packages(scope: AppxScope) -> io::Result<Vec<AppxPackage>> {
    list_packages_with(scope, ListOptions::default())
}

/// Lists packages for `scope`, reading what `options` asks for as well.
pub fn list_packages_with(scope: AppxScope, options: ListOptions) -> io::Result<Vec<AppxPackage>> {
    let pm = PackageManager::new()?;
    let packages = match scope {
        AppxScope::CurrentUser => pm.FindPackagesByUserSecurityId(&HSTRING::new())?,
        AppxScope::AllUsers => pm.FindPackages()?,
    };
    let mut out = Vec::new();
    for package in packages {
        let Some(mut p) = read_package(&package) else {
            continue;
        };
        if options.dependencies {
            p.dependencies = read_dependencies(&package);
        }
        if scope == AppxScope::AllUsers
            && let Ok(users) = pm.FindUsers(&HSTRING::from(p.full_name.as_str()))
        {
            p.users = users
                .into_iter()
                .filter_map(|u| {
                    let sid = u.UserSecurityId().ok()?.to_string_lossy();
                    let install_state = u
                        .InstallState()
                        .map_or(AppxInstallState::Other(-1), AppxInstallState::from);
                    Some(AppxUser { sid, install_state })
                })
                .collect();
        }
        out.push(p);
    }
    Ok(out)
}

/// Reads one package's properties; `None` when even its identity cannot be read.
fn read_package(package: &Package) -> Option<AppxPackage> {
    let id = package.Id().ok()?;
    let full_name = non_empty(id.FullName())?;
    let family_name = non_empty(id.FamilyName()).unwrap_or_default();
    Some(AppxPackage {
        full_name,
        family_name,
        installed_location: non_empty(package.InstalledPath()),
        effective_external_path: non_empty(package.EffectiveExternalPath()),
        signature_kind: package.SignatureKind().ok().map(SignatureKind::from),
        is_framework: package.IsFramework().unwrap_or(false),
        is_resource_package: package.IsResourcePackage().unwrap_or(false),
        users: Vec::new(),
        dependencies: None,
    })
}

/// The full names of the packages `package` depends on; `None` when the list or the identity of any
/// entry cannot be read. Indexed reads rather than the collection iterator, which ends silently on an
/// error and would give a partial list.
fn read_dependencies(package: &Package) -> Option<Vec<String>> {
    let deps = package.Dependencies().ok()?;
    let count = deps.Size().ok()?;
    let mut out = Vec::with_capacity(usize::try_from(count).ok()?);
    for i in 0..count {
        let dep = deps.GetAt(i).ok()?;
        out.push(non_empty(dep.Id().ok()?.FullName())?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_user_listing() {
        let packages = list_packages(AppxScope::CurrentUser).expect("FindPackagesForUser");
        println!("{} packages for the current user", packages.len());
        for p in packages
            .iter()
            .filter(|p| p.effective_external_path.is_some())
        {
            println!("sparse: {} -> {:?}", p.full_name, p.effective_external_path);
        }
        // Any Windows 10/11 desktop has at least some registered packages for an interactive user.
        assert!(!packages.is_empty());
        assert!(
            packages
                .iter()
                .all(|p| !p.full_name.is_empty() && p.users.is_empty())
        );
        assert!(packages.iter().any(|p| p.is_framework));
        assert!(packages.iter().any(|p| p.installed_location.is_some()));
        assert!(packages.iter().all(|p| p.dependencies.is_none()));
    }

    /// Read-only, unelevated: the current user's packages with their dependencies. Every desktop has
    /// packages that depend on a framework (VCLibs, UI.Xaml, WindowsAppRuntime ...). The full-name check
    /// is `appx_write`'s, so this test needs the `write` feature too.
    #[cfg(feature = "write")]
    #[test]
    fn current_user_listing_with_dependencies() {
        use std::time::Instant;

        let start = Instant::now();
        let plain = list_packages(AppxScope::CurrentUser).expect("FindPackagesForUser");
        let plain_time = start.elapsed();
        let start = Instant::now();
        let packages =
            list_packages_with(AppxScope::CurrentUser, ListOptions { dependencies: true })
                .expect("FindPackagesForUser");
        let deps_time = start.elapsed();
        println!(
            "{} packages: {plain_time:?} without dependencies, {deps_time:?} with",
            packages.len()
        );
        assert!(!plain.is_empty());

        let unread: Vec<&str> = packages
            .iter()
            .filter(|p| p.dependencies.is_none())
            .map(|p| p.full_name.as_str())
            .collect();
        println!("dependencies not readable for: {unread:?}");
        let with_deps: Vec<&AppxPackage> = packages
            .iter()
            .filter(|p| p.dependencies.as_ref().is_some_and(|d| !d.is_empty()))
            .collect();
        println!("{} packages have dependencies", with_deps.len());
        assert!(!with_deps.is_empty(), "no package reports a dependency");
        for p in &packages {
            for dep in p.dependencies.iter().flatten() {
                crate::appx_write::validate_full_name(dep)
                    .unwrap_or_else(|e| panic!("{}: dependency {dep:?}: {e}", p.full_name));
            }
        }
    }

    #[test]
    fn all_users_listing_needs_elevation_or_works() {
        // At medium integrity FindPackages fails with access denied; elevated it lists users.
        match list_packages(AppxScope::AllUsers) {
            Ok(packages) => {
                println!("{} packages machine-wide", packages.len());
                assert!(packages.iter().any(|p| !p.users.is_empty()));
            }
            Err(e) => println!("AllUsers not available here: {e}"),
        }
    }
}
