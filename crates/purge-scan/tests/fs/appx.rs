//! SYS-APPX (APPX-MIN).

use std::path::PathBuf;

use purge_model::{Action, Blocker, Category, EvidenceKind, Reversibility, Target};
use purge_scan::sys_appx::SysAppx;
use purge_source::fixture::Fixture;
use purge_source::types::{PackageInfo, PackageSignatureKind};

use crate::{NPP_PACKAGE, SID, World, golden, machine, npp_fp, target_text};

/// The four AppX rows that matter of the Notepad++ run's post-uninstall lists (`lists-npp-2.json`): an
/// inbox app, the Edge DevTools client, Edge's own sparse package and Notepad++'s leftover one.
const LISTS: &str = include_str!("fixtures/lists-npp-2-appx.json");

fn lists_fixture(lists_json: &str) -> Fixture {
    Fixture::from_snap_parts(&b""[..], Some(lists_json), None).expect("the lists load")
}

fn package(full_name: &str, family: &str) -> PackageInfo {
    PackageInfo {
        full_name: full_name.to_owned(),
        family: family.to_owned(),
        install_location: Some(format!(r"C:\Program Files\WindowsApps\{full_name}")),
        external_location: Some(r"C:\Program Files\Notepad++\contextMenu".to_owned()),
        sparse: true,
        users: vec![SID.to_owned()],
        is_framework: false,
        is_resource: false,
        signature_kind: PackageSignatureKind::Developer,
    }
}

#[test]
fn leftover_sparse_package_is_offered_and_edge_never() {
    let world = World::new(lists_fixture(LISTS), npp_fp());
    let found = world.scan(&SysAppx);
    golden("appx_npp", &found);
    let [c] = found.as_slice() else {
        panic!("one package: {found:#?}");
    };
    assert_eq!(
        c.target,
        Target::AppxPackage {
            full_name: NPP_PACKAGE.into()
        }
    );
    assert_eq!(
        (c.action, c.category, c.reversibility),
        (
            Action::RemovePackage,
            Category::Package,
            Reversibility::None
        )
    );
    assert_eq!(c.blockers, [Blocker::ReversibilityNone]);
    assert!(
        c.evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::AppxExternalLocation)
    );
}

#[test]
fn real_npp_run_lists_when_present() {
    // The rig's run directory is not part of the repository; the committed excerpt above stands in.
    let lists =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vm/runs/npp/lists-npp-2.json");
    let Ok(text) = std::fs::read_to_string(&lists) else {
        return;
    };
    let mut fp = npp_fp();
    let fixture = lists_fixture(&text);
    fp.user_sid = purge_source::system::SystemSource::user_sid(&fixture).expect("a user sid");
    let found = World::new(fixture, fp).scan(&SysAppx);
    let names: Vec<String> = found.iter().map(|c| target_text(&c.target)).collect();
    assert_eq!(names, [format!("package:{NPP_PACKAGE}")]);
}

#[test]
fn package_that_is_no_longer_registered_yields_nothing() {
    let mut fixture = lists_fixture(LISTS);
    let mut packages = purge_source::system::SystemSource::packages(&fixture).expect("packages");
    packages.retain(|p| p.full_name != NPP_PACKAGE);
    assert_eq!(packages.len(), 3);
    fixture.set_packages(Some(packages));
    assert!(World::new(fixture, npp_fp()).scan(&SysAppx).is_empty());

    // An unreadable package list proves nothing either.
    let fixture = machine().with(|f| f.set_packages(None)).build();
    assert!(World::new(fixture, npp_fp()).scan(&SysAppx).is_empty());
}

#[test]
fn only_linked_packages_and_never_protected_kinds() {
    let family = "NotepadPlusPlus_2247w0b46hfww";
    let offered = |edit: &dyn Fn(&mut PackageInfo)| {
        let mut p = package(NPP_PACKAGE, family);
        edit(&mut p);
        let fixture = machine().package(p).build();
        World::new(fixture, npp_fp()).scan(&SysAppx).len()
    };
    assert_eq!(offered(&|_| {}), 1);
    assert_eq!(offered(&|p| p.is_framework = true), 0);
    assert_eq!(offered(&|p| p.is_resource = true), 0);
    assert_eq!(
        offered(&|p| p.signature_kind = PackageSignatureKind::Store),
        0
    );
    assert_eq!(
        offered(&|p| p.signature_kind = PackageSignatureKind::System),
        0
    );
    // Rig lists do not record the signature: unknown is not a reason to refuse.
    assert_eq!(
        offered(&|p| p.signature_kind = PackageSignatureKind::Unknown),
        1
    );
    // A full (non-sparse) package is an app of its own.
    assert_eq!(
        offered(&|p| {
            p.sparse = false;
            p.external_location = None;
        }),
        0
    );
    // An inbox package.
    assert_eq!(
        offered(&|p| p.install_location = Some(r"C:\Windows\SystemApps\X".into())),
        0
    );

    // A newer version of the linked family is the same leftover; an unlinked package is not.
    let fixture = machine()
        .package(package(
            "NotepadPlusPlus_1.0.1.0_neutral__2247w0b46hfww",
            family,
        ))
        .package(package(
            "Microsoft.MicrosoftEdge.Stable_157.0.4341.46_neutral__8wekyb3d8bbwe",
            "Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe",
        ))
        .build();
    let found = World::new(fixture, npp_fp()).scan(&SysAppx);
    assert_eq!(found.len(), 1);
    assert_eq!(
        target_text(&found[0].target),
        "package:NotepadPlusPlus_1.0.1.0_neutral__2247w0b46hfww"
    );

    // No link in the fingerprint: nothing, whatever is registered.
    let mut fp = npp_fp();
    fp.anchors.package_full_names.clear();
    fp.anchors.package_families.clear();
    let fixture = machine().package(package(NPP_PACKAGE, family)).build();
    assert!(World::new(fixture, fp).scan(&SysAppx).is_empty());
}

#[test]
fn package_living_in_another_apps_directory_is_not_offered() {
    let fixture = machine()
        .package(package(NPP_PACKAGE, "NotepadPlusPlus_2247w0b46hfww"))
        .build();
    let world = World::new(fixture, npp_fp()).with_other_app(
        "Notepad++ (32-bit x86)",
        &[r"C:\Program Files\Notepad++"],
        &[],
    );
    assert!(world.scan(&SysAppx).is_empty());
}
