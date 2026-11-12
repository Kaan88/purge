//! The scanner catalog (ENGINE_PLAN.md §5.6): every scanner the engine runs, in a fixed order.
//!
//! [`all_scanners`] is what the pipeline iterates. [`metadata`] is the same list as plain data for
//! `xtask scanner-coverage`, which checks each scanner's [`RootSpec`]s against the capture roots of the
//! VM rig (vm/RIG.md §2) and the union of the scanners' value containers against
//! `purge_guard::containers::VALUE_CONTAINERS` (§5.10 "derived structural containers").
//!
//! M1a ships the seventeen scanners of §11.1 plus SYS-APPX in its minimal form (APPX-MIN, decision of
//! 2026-11-12). The MSI, COM and system scanners join in M1b, the rest in M4.

use crate::framework::{RootSpec, Scanner};
use crate::{
    cls_assoc, cls_aumid, cls_fileexts, cls_progid, cls_protocol, cls_regapps, cls_toasts,
    cls_verbs, fs_appdata, fs_installdir, fs_shortcuts, fs_uninstaller, fs_vendorparent, ref_any,
    reg_apppaths, reg_env, reg_run, reg_software, sys_appx,
};

/// The ids of [`all_scanners`], in catalog order.
pub const SCANNER_IDS: [&str; 19] = [
    fs_installdir::ID,
    fs_uninstaller::ID,
    fs_appdata::ID,
    fs_vendorparent::ID,
    fs_shortcuts::ID,
    reg_software::ID,
    reg_apppaths::ID,
    reg_run::ID,
    reg_env::ID,
    ref_any::ID,
    cls_progid::ID,
    cls_assoc::ID,
    cls_fileexts::ID,
    cls_toasts::ID,
    cls_aumid::ID,
    cls_verbs::ID,
    cls_protocol::ID,
    cls_regapps::ID,
    sys_appx::ID,
];

/// Every scanner of this milestone, in catalog order: files, application keys, classes, packages.
pub fn all_scanners() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(fs_installdir::FsInstallDir),
        Box::new(fs_uninstaller::FsUninstaller),
        Box::new(fs_appdata::FsAppData),
        Box::new(fs_vendorparent::FsVendorParent),
        Box::new(fs_shortcuts::FsShortcuts),
        Box::new(reg_software::RegSoftware),
        Box::new(reg_apppaths::RegAppPaths),
        Box::new(reg_run::RegRun),
        Box::new(reg_env::RegEnv),
        Box::new(ref_any::RefAny),
        Box::new(cls_progid::ClsProgId),
        Box::new(cls_assoc::ClsAssoc),
        Box::new(cls_fileexts::ClsFileExts),
        Box::new(cls_toasts::ClsToasts),
        Box::new(cls_aumid::ClsAumid),
        Box::new(cls_verbs::ClsVerbs),
        Box::new(cls_protocol::ClsProtocol),
        Box::new(cls_regapps::ClsRegApps),
        Box::new(sys_appx::SysAppx),
    ]
}

/// The scanner with this catalog id (compared case-insensitively).
pub fn scanner(id: &str) -> Option<Box<dyn Scanner>> {
    all_scanners()
        .into_iter()
        .find(|s| s.id().eq_ignore_ascii_case(id))
}

/// What one scanner declares about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerMeta {
    /// The catalog id.
    pub id: &'static str,
    /// The locations it reads.
    pub captured_roots: Vec<RootSpec>,
    /// The keys it reads single values from.
    pub value_containers: Vec<&'static str>,
}

/// The declarations of every scanner of [`all_scanners`], in the same order.
pub fn metadata() -> Vec<ScannerMeta> {
    all_scanners()
        .iter()
        .map(|s| ScannerMeta {
            id: s.id(),
            captured_roots: s.captured_roots().to_vec(),
            value_containers: s.value_containers().to_vec(),
        })
        .collect()
}

/// The union of every scanner's value containers, without duplicates, in catalog order.
pub fn value_containers() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for meta in metadata() {
        for container in meta.value_containers {
            if !out.contains(&container) {
                out.push(container);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::testkit::World;
    use crate::framework::{AppIdentityView, RootSpecKind};
    use purge_guard::containers::VALUE_CONTAINERS;
    use purge_source::fixture::Fixture;

    #[test]
    fn catalog_lists_exactly_the_m1a_scanners() {
        let expected = [
            "FS-INSTALLDIR",
            "FS-UNINSTALLER",
            "FS-APPDATA",
            "FS-VENDORPARENT",
            "FS-SHORTCUTS",
            "REG-SOFTWARE",
            "REG-APPPATHS",
            "REG-RUN",
            "REG-ENV",
            "REF-ANY",
            "CLS-PROGID",
            "CLS-ASSOC",
            "CLS-FILEEXTS",
            "CLS-TOASTS",
            "CLS-AUMID",
            "CLS-VERBS",
            "CLS-PROTOCOL",
            "CLS-REGAPPS",
            "SYS-APPX",
        ];
        let ids: Vec<&str> = all_scanners().iter().map(|s| s.id()).collect();
        assert_eq!(ids, expected);
        assert_eq!(SCANNER_IDS, expected);
        assert_eq!(
            metadata().iter().map(|m| m.id).collect::<Vec<_>>(),
            expected
        );
        for id in expected {
            assert_eq!(scanner(&id.to_lowercase()).map(|s| s.id()), Some(id));
        }
        assert!(scanner("COM-CLASS").is_none());
    }

    /// The acceptance rule: no scanner declares a container the guard does not treat as structural.
    #[test]
    fn value_containers_are_a_subset_of_the_guard_table() {
        for meta in metadata() {
            for container in &meta.value_containers {
                assert!(
                    VALUE_CONTAINERS.contains(container),
                    "{}: {container} is not in purge_guard::containers::VALUE_CONTAINERS",
                    meta.id
                );
            }
        }
    }

    /// The other direction, which `xtask scanner-coverage` also checks: every container of the guard
    /// table is declared by a scanner, so the table holds nothing that no scanner reads.
    #[test]
    fn value_containers_cover_the_guard_table() {
        let declared = value_containers();
        for container in VALUE_CONTAINERS {
            assert!(
                declared.contains(container),
                "no scanner declares {container}"
            );
        }
        assert_eq!(declared.len(), VALUE_CONTAINERS.len());
    }

    #[test]
    fn root_specs_are_well_formed() {
        for meta in metadata() {
            for (i, spec) in meta.captured_roots.iter().enumerate() {
                assert!(spec.is_well_formed(), "{}: {spec:?}", meta.id);
                assert!(
                    !meta.captured_roots[..i].contains(spec),
                    "{}: {spec:?} is listed twice",
                    meta.id
                );
            }
            // Every scanner but the package scanner reads a snapshot location.
            assert_eq!(
                meta.captured_roots.is_empty(),
                meta.id == sys_appx::ID,
                "{}",
                meta.id
            );
            // File scanners read files, the others the registry.
            let kind = if meta.id.starts_with("FS-") {
                RootSpecKind::Fs
            } else {
                RootSpecKind::Reg
            };
            assert!(
                meta.captured_roots.iter().all(|r| r.kind == kind),
                "{}",
                meta.id
            );
        }
    }

    /// A value container is read at the key itself, so each one lies at or under a declared root of the
    /// scanner that declares it.
    #[test]
    fn value_containers_lie_under_the_scanners_roots() {
        let fold = |s: &str| s.to_ascii_lowercase();
        for meta in metadata() {
            for container in &meta.value_containers {
                let covered = meta.captured_roots.iter().any(|root| {
                    let (root, container) = (fold(root.pattern), fold(container));
                    container == root || container.starts_with(&format!("{root}\\"))
                });
                assert!(covered, "{}: {container}", meta.id);
            }
        }
    }

    /// The scanners are object safe, and until their packages land they find nothing.
    #[test]
    fn stub_scanners_run_and_find_nothing() {
        let world = World::new(Fixture::new());
        let ctx = world.ctx();
        let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
        for scanner in all_scanners() {
            assert!(scanner.scan(&ctx, &app).is_empty(), "{}", scanner.id());
        }
    }
}
