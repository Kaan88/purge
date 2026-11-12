//! The sparse-package link, APPX-MIN (ENGINE_PLAN.md §4.1 "AppX / MSIX").
//!
//! A Win32 app can register a *sparse* package: an AppX identity whose content stays in the app's own
//! directory (its *external location*). VS Code and Notepad++ do so for their Explorer context-menu
//! entries. Such a package is the app's and is recorded in the fingerprint (full name and family), so
//! that the scan can offer it once the app is gone.
//!
//! # The linking rule
//!
//! A package is linked **only** when
//!
//! - it is sparse and its external location is known,
//! - that location, canonicalised, equals or lies under a validated root of the app that is an
//!   InstallRoot or an InferredRoot (see below),
//! - it is neither a framework nor a resource package, and
//! - it is not Store-signed or System-signed.
//!
//! Never by publisher, by name or by family alone: Edge's sparse package lives in Edge's directory and
//! must never be linked to anything else Microsoft ships.
//!
//! # Inferred roots
//!
//! §4.1 names the InstallRoot. An NSIS app without an `InstallLocation` value (Notepad++) has only an
//! InferredRoot, the directory of its uninstaller and icon, and its sparse package lies below it. The
//! link is a statement about the *package's own declaration* (it names a directory inside the app's
//! validated directory), not about the directory's content, so an InferredRoot carries it as well; a
//! ReferencedDataDir never does. The scan decides what the link is worth.

use purge_guard::canon::GuardEnv;
use purge_guard::prefix;
use purge_model::{Root, RootKind};
use purge_source::system::SystemSource;
use purge_source::types::{PackageInfo, PackageSignatureKind};

use crate::roots::canon_file;

/// A sparse package linked to the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedPackage {
    /// `PackageFullName`.
    pub full_name: String,
    /// `PackageFamilyName`.
    pub family: String,
    /// The canonical external location.
    pub external_location: String,
    /// The root the location is, or lies under.
    pub root: String,
}

/// The packages linked to one app.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppxLink {
    /// The linked packages, sorted by full name, each once.
    pub packages: Vec<LinkedPackage>,
    /// What could not be read, for the fingerprint's warnings.
    pub warnings: Vec<String>,
}

impl AppxLink {
    /// The full names, in order.
    pub fn full_names(&self) -> Vec<String> {
        self.packages.iter().map(|p| p.full_name.clone()).collect()
    }

    /// The family names, in order, each once.
    pub fn families(&self) -> Vec<String> {
        let mut families: Vec<String> = Vec::new();
        for package in &self.packages {
            if !families
                .iter()
                .any(|f| f.eq_ignore_ascii_case(&package.family))
            {
                families.push(package.family.clone());
            }
        }
        families
    }
}

/// Whether a package may be linked at all, whatever its location.
fn linkable(package: &PackageInfo) -> bool {
    package.is_sparse()
        && !package.is_framework
        && !package.is_resource
        && !matches!(
            package.signature_kind,
            PackageSignatureKind::Store | PackageSignatureKind::System
        )
}

/// The packages of `packages` that the linking rule gives to an app with these `roots`.
pub fn link_packages(
    packages: &[PackageInfo],
    roots: &[Root],
    guard: &GuardEnv,
) -> Vec<LinkedPackage> {
    let mut linked: Vec<LinkedPackage> = Vec::new();
    for package in packages.iter().filter(|p| linkable(p)) {
        let Some(location) = package
            .external_location
            .as_deref()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .and_then(|l| canon_file(l, guard))
        else {
            continue;
        };
        let Some(root) = roots.iter().find(|r| {
            r.kind != RootKind::ReferencedDataDir && prefix::is_same_or_inside(&location, &r.path)
        }) else {
            continue;
        };
        if linked
            .iter()
            .any(|l| l.full_name.eq_ignore_ascii_case(&package.full_name))
        {
            continue;
        }
        linked.push(LinkedPackage {
            full_name: package.full_name.clone(),
            family: package.family.clone(),
            external_location: location,
            root: root.path.clone(),
        });
    }
    linked.sort_by(|a, b| a.full_name.cmp(&b.full_name));
    linked
}

/// Reads the registered packages and links them to `roots`. A package list that cannot be read is a
/// warning: nothing is linked then.
pub fn link(sys: &dyn SystemSource, roots: &[Root], guard: &GuardEnv) -> AppxLink {
    if roots.is_empty() {
        return AppxLink::default();
    }
    match sys.packages() {
        Ok(packages) => AppxLink {
            packages: link_packages(&packages, roots, guard),
            warnings: Vec::new(),
        },
        Err(e) => AppxLink {
            packages: Vec::new(),
            warnings: vec![format!(
                "appx: the registered packages could not be read ({e}); no sparse package is linked"
            )],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_model::{RootSource, SourceTrust};

    fn root(path: &str, source: RootSource) -> Root {
        Root {
            path: path.into(),
            kind: source.root_kind(),
            source,
            trust: SourceTrust::AdminOnly,
            volume_serial: None,
            parent_existed: true,
        }
    }

    fn sparse(full_name: &str, family: &str, external: &str) -> PackageInfo {
        PackageInfo {
            full_name: full_name.into(),
            family: family.into(),
            install_location: None,
            external_location: Some(external.into()),
            sparse: true,
            users: Vec::new(),
            is_framework: false,
            is_resource: false,
            signature_kind: PackageSignatureKind::Developer,
        }
    }

    const CODE_FULL: &str = "Microsoft.VisualStudioCode_1.106.0.0_x64__8wekyb3d8bbwe";
    const CODE_FAMILY: &str = "Microsoft.VisualStudioCode_8wekyb3d8bbwe";
    const EDGE_FULL: &str = "Microsoft.MicrosoftEdge.Stable_142.0.3595.65_neutral__8wekyb3d8bbwe";
    const EDGE_FAMILY: &str = "Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe";

    fn packages() -> Vec<PackageInfo> {
        vec![
            sparse(
                EDGE_FULL,
                EDGE_FAMILY,
                r"C:\Program Files (x86)\Microsoft\Edge\Application",
            ),
            sparse(
                CODE_FULL,
                CODE_FAMILY,
                r"C:\Program Files\Microsoft VS Code\69047191fc\appx",
            ),
            sparse(
                "NotepadPlusPlus_1.0.0.0_neutral__7njy0v32s6xk6",
                "NotepadPlusPlus_7njy0v32s6xk6",
                r"C:\Program Files\Notepad++\contextMenu\",
            ),
        ]
    }

    #[test]
    fn links_by_external_location_under_a_root_and_never_by_publisher() {
        let guard = GuardEnv::sample();
        let code = [root(
            r"C:\Program Files\Microsoft VS Code",
            RootSource::InnoApp,
        )];
        let linked = link_packages(&packages(), &code, &guard);
        assert_eq!(linked.len(), 1, "{linked:?}");
        assert_eq!(linked[0].full_name, CODE_FULL);
        assert_eq!(linked[0].family, CODE_FAMILY);
        assert_eq!(
            linked[0].external_location,
            r"C:\Program Files\Microsoft VS Code\69047191fc\appx"
        );
        assert_eq!(linked[0].root, r"C:\Program Files\Microsoft VS Code");

        // Edge's package has the same publisher id as VS Code's: it is still not VS Code's.
        assert!(linked.iter().all(|l| l.full_name != EDGE_FULL));

        // The location equal to the root, in another case and with a trailing separator.
        let exact = [root(
            r"c:\program files\notepad++\contextmenu",
            RootSource::ArpInstallLocation,
        )];
        let linked = link_packages(&packages(), &exact, &guard);
        assert_eq!(linked.len(), 1);
        assert!(linked[0].full_name.starts_with("NotepadPlusPlus_"));

        // A root *inside* the external location does not link: the package is not under the root.
        let inside = [root(
            r"C:\Program Files\Microsoft VS Code\69047191fc\appx\assets",
            RootSource::ArpInstallLocation,
        )];
        assert!(link_packages(&packages(), &inside, &guard).is_empty());
        // A sibling directory with the root as a name prefix does not link either.
        let sibling = [root(
            r"C:\Program Files\Microsoft VS",
            RootSource::ArpInstallLocation,
        )];
        assert!(link_packages(&packages(), &sibling, &guard).is_empty());
        assert!(link_packages(&packages(), &[], &guard).is_empty());
    }

    #[test]
    fn inferred_roots_link_and_referenced_data_dirs_do_not() {
        let guard = GuardEnv::sample();
        let inferred = [root(
            r"C:\Program Files\Notepad++",
            RootSource::UninstallerDir,
        )];
        assert_eq!(inferred[0].kind, RootKind::InferredRoot);
        let linked = link_packages(&packages(), &inferred, &guard);
        assert_eq!(linked.len(), 1);
        assert_eq!(linked[0].family, "NotepadPlusPlus_7njy0v32s6xk6");

        let mut data = inferred.clone();
        data[0].kind = RootKind::ReferencedDataDir;
        assert!(link_packages(&packages(), &data, &guard).is_empty());
    }

    #[test]
    fn frameworks_resources_store_and_system_packages_are_never_linked() {
        let guard = GuardEnv::sample();
        let roots = [root(
            r"C:\Program Files\App",
            RootSource::ArpInstallLocation,
        )];
        let base = sparse(
            "App_1.0.0.0_x64__abc",
            "App_abc",
            r"C:\Program Files\App\appx",
        );
        assert_eq!(
            link_packages(std::slice::from_ref(&base), &roots, &guard).len(),
            1
        );

        let variants: [fn(&mut PackageInfo); 6] = [
            |p| p.is_framework = true,
            |p| p.is_resource = true,
            |p| p.signature_kind = PackageSignatureKind::Store,
            |p| p.signature_kind = PackageSignatureKind::System,
            // Not sparse at all: a packaged app that merely installs under the root.
            |p| {
                p.sparse = false;
                p.install_location = p.external_location.take();
            },
            // Sparse, but the external location was not read.
            |p| p.external_location = None,
        ];
        for (i, change) in variants.iter().enumerate() {
            let mut package = base.clone();
            change(&mut package);
            assert!(
                link_packages(&[package], &roots, &guard).is_empty(),
                "variant {i} must not link"
            );
        }
        // An unknown or enterprise signature does not block the link; a relative location does.
        let mut unknown = base.clone();
        unknown.signature_kind = PackageSignatureKind::Unknown;
        assert_eq!(link_packages(&[unknown], &roots, &guard).len(), 1);
        let mut relative = base.clone();
        relative.external_location = Some(r"App\appx".into());
        assert!(link_packages(&[relative], &roots, &guard).is_empty());
    }

    #[test]
    fn output_is_sorted_and_deduplicated() {
        let guard = GuardEnv::sample();
        let roots = [root(
            r"C:\Program Files\App",
            RootSource::ArpInstallLocation,
        )];
        let list = [
            sparse("B_1.0.0.0_x64__abc", "B_abc", r"C:\Program Files\App\b"),
            sparse("A_1.0.0.0_x64__abc", "A_abc", r"C:\Program Files\App\a"),
            sparse("A_2.0.0.0_x64__abc", "A_abc", r"C:\Program Files\App\a"),
            sparse("B_1.0.0.0_x64__abc", "B_abc", r"C:\Program Files\App\b"),
        ];
        let link = AppxLink {
            packages: link_packages(&list, &roots, &guard),
            warnings: Vec::new(),
        };
        assert_eq!(
            link.full_names(),
            [
                "A_1.0.0.0_x64__abc",
                "A_2.0.0.0_x64__abc",
                "B_1.0.0.0_x64__abc"
            ]
        );
        assert_eq!(link.families(), ["A_abc", "B_abc"]);
    }
}
