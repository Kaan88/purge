//! The scanner catalog (ENGINE_PLAN.md §5.6): every scanner the engine runs, in a fixed order.
//!
//! [`all_scanners`] is what the pipeline iterates. [`metadata`] is the same list as plain data for
//! `xtask scanner-coverage`, which checks each scanner's [`RootSpec`]s against the capture roots of the
//! VM rig (vm/RIG.md §2) and the union of the scanners' value containers against the guard's tables
//! (`purge_guard::containers::all_value_containers`: `VALUE_CONTAINERS`, then `M1B_VALUE_CONTAINERS`;
//! §5.10 "derived structural containers").
//!
//! M1a ships the seventeen scanners of §11.1 plus SYS-APPX in its minimal form (APPX-MIN, decision of
//! 2026-11-12). M1b appends the fourteen COM, system-object, Burn, MSI, privacy and diagnostics
//! scanners (M1B-SCAN-INTEG), after the M1a ones and in the design's order; the rest join in M4.

use crate::framework::{RootSpec, Scanner};
use crate::{
    cls_assoc, cls_aumid, cls_fileexts, cls_progid, cls_protocol, cls_regapps, cls_toasts,
    cls_verbs, com_class, com_interface, com_shellex, fs_appdata, fs_installdir, fs_pkgcache,
    fs_shortcuts, fs_uninstaller, fs_vendorparent, fs_wer, ref_any, reg_apppaths, reg_arp_msi,
    reg_diag, reg_env, reg_instfolders, reg_privacy, reg_run, reg_shareddlls, reg_software,
    sys_appx, sys_burndeps, sys_firewall, sys_service, sys_task,
};

/// The ids of [`all_scanners`], in catalog order.
pub const SCANNER_IDS: [&str; 33] = [
    // M1a.
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
    // M1b.
    com_class::ID,
    com_interface::ID,
    com_shellex::ID,
    sys_service::ID,
    sys_task::ID,
    sys_firewall::ID,
    sys_burndeps::ID,
    fs_pkgcache::ID,
    fs_wer::ID,
    reg_arp_msi::ID,
    reg_shareddlls::ID,
    reg_instfolders::ID,
    reg_privacy::ID,
    reg_diag::ID,
];

/// Every scanner of this milestone, in catalog order: files, application keys, classes, packages (M1a),
/// then COM, system objects, Burn and MSI records, privacy traces and diagnostics (M1b).
pub fn all_scanners() -> Vec<Box<dyn Scanner>> {
    vec![
        // M1a.
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
        // M1b.
        Box::new(com_class::ComClass),
        Box::new(com_interface::ComInterface),
        Box::new(com_shellex::ComShellex),
        Box::new(sys_service::SysService),
        Box::new(sys_task::SysTask),
        Box::new(sys_firewall::SysFirewall::default()),
        Box::new(sys_burndeps::SysBurnDeps),
        Box::new(fs_pkgcache::FsPkgCache),
        Box::new(fs_wer::FsWer),
        Box::new(reg_arp_msi::RegArpMsi),
        Box::new(reg_shareddlls::RegSharedDlls),
        Box::new(reg_instfolders::RegInstFolders),
        Box::new(reg_privacy::RegPrivacy),
        Box::new(reg_diag::RegDiag),
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
    use std::collections::BTreeSet;

    use super::*;
    use crate::framework::testkit::World;
    use crate::framework::{AppIdentityView, RootSpecKind};
    use purge_guard::containers::{M1B_VALUE_CONTAINERS, VALUE_CONTAINERS, all_value_containers};
    use purge_source::fixture::Fixture;

    const M1A: [&str; 19] = [
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

    const M1B: [&str; 14] = [
        "COM-CLASS",
        "COM-INTERFACE",
        "COM-SHELLEX",
        "SYS-SERVICE",
        "SYS-TASK",
        "SYS-FIREWALL",
        "SYS-BURNDEPS",
        "FS-PKGCACHE",
        "FS-WER",
        "REG-ARP-MSI",
        "REG-SHAREDDLLS",
        "REG-INSTFOLDERS",
        "REG-PRIVACY",
        "REG-DIAG",
    ];

    /// The M1a nineteen first, unchanged, then the fourteen M1b scanners in the design's order.
    #[test]
    fn catalog_lists_exactly_the_m1b_scanners() {
        let expected: Vec<&str> = M1A.iter().chain(&M1B).copied().collect();
        let ids: Vec<&str> = all_scanners().iter().map(|s| s.id()).collect();
        assert_eq!(ids, expected);
        assert_eq!(SCANNER_IDS.as_slice(), expected.as_slice());
        assert_eq!(
            metadata().iter().map(|m| m.id).collect::<Vec<_>>(),
            expected
        );
        for id in &expected {
            assert_eq!(scanner(&id.to_lowercase()).map(|s| s.id()), Some(*id));
        }
        assert!(scanner("FS-NOSUCH").is_none());
    }

    /// The scanners' value containers are exactly the guard's two tables (C-GUARD, R2a note): every
    /// container a scanner reads is structural to the guard, and the guard holds nothing that no scanner
    /// reads. `xtask scanner-coverage` checks the same two lists.
    #[test]
    fn catalog_value_containers_equal_guard() {
        let declared = value_containers();
        let guard: Vec<&str> = all_value_containers().collect();
        assert_eq!(
            guard.len(),
            VALUE_CONTAINERS.len() + M1B_VALUE_CONTAINERS.len()
        );
        let declared_set: BTreeSet<&str> = declared.iter().copied().collect();
        let guard_set: BTreeSet<&str> = guard.iter().copied().collect();
        assert_eq!(
            guard_set.len(),
            guard.len(),
            "the guard lists a container twice"
        );
        if let Some(container) = declared_set.difference(&guard_set).next() {
            panic!("a scanner declares {container}, which the guard does not list");
        }
        if let Some(container) = guard_set.difference(&declared_set).next() {
            panic!("the guard lists {container}, which no scanner declares");
        }
        assert_eq!(declared.len(), guard.len());
        // The M1a scanners still declare exactly the M1a table.
        let m1a: BTreeSet<&str> = metadata()
            .iter()
            .filter(|m| M1A.contains(&m.id))
            .flat_map(|m| m.value_containers.iter().copied())
            .collect();
        assert_eq!(m1a, VALUE_CONTAINERS.iter().copied().collect());
        // The shell-extension lists of R3a M10 are among them.
        for leaf in [
            r"Shell Extensions\Cached",
            r"Explorer\ShellExecuteHooks",
            r"Explorer\SharedTaskScheduler",
        ] {
            assert!(
                declared.iter().any(|c| c.ends_with(leaf)),
                "{leaf} is not a declared container"
            );
        }
    }

    /// Root specs: well formed, none twice; every scanner but SYS-APPX declares at least one (the
    /// system-object scanners declare the keys their objects come from, so `scanner-coverage` counts
    /// them); file scanners read files, the others the registry; a value container lies at or under a
    /// declared root of the scanner that declares it.
    #[test]
    fn catalog_root_specs_consistent() {
        let fold = |s: &str| s.to_ascii_lowercase();
        for meta in metadata() {
            for (i, spec) in meta.captured_roots.iter().enumerate() {
                assert!(spec.is_well_formed(), "{}: {spec:?}", meta.id);
                assert!(
                    !meta.captured_roots[..i].contains(spec),
                    "{}: {spec:?} is listed twice",
                    meta.id
                );
            }
            assert_eq!(
                meta.captured_roots.is_empty(),
                meta.id == sys_appx::ID,
                "{}",
                meta.id
            );
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
            for container in &meta.value_containers {
                let covered = meta.captured_roots.iter().any(|root| {
                    let (root, container) = (fold(root.pattern), fold(container));
                    container == root || container.starts_with(&format!("{root}\\"))
                });
                assert!(covered, "{}: {container}", meta.id);
            }
        }
        // The places the system-object and Burn scanners are about.
        let declares = |id: &str, pattern: &str| {
            metadata().iter().find(|m| m.id == id).is_some_and(|m| {
                m.captured_roots
                    .iter()
                    .any(|r| r.pattern.eq_ignore_ascii_case(pattern))
            })
        };
        assert!(declares(
            sys_service::ID,
            r"HKLM\SYSTEM\CurrentControlSet\Services"
        ));
        assert!(declares(
            sys_task::ID,
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
        ));
        assert!(declares(
            sys_firewall::ID,
            r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        ));
        assert!(declares(
            sys_burndeps::ID,
            r"*\SOFTWARE\Classes\Installer\Dependencies"
        ));
    }

    /// Every scanner runs on an empty machine and finds nothing (the scanners are object safe, and none
    /// invents a candidate without data).
    #[test]
    fn scanners_run_on_an_empty_world_and_find_nothing() {
        let world = World::new(Fixture::new());
        let ctx = world.ctx();
        let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
        for scanner in all_scanners() {
            assert!(scanner.scan(&ctx, &app).is_empty(), "{}", scanner.id());
        }
    }
}
