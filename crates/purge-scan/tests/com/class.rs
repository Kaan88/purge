//! COM-CLASS: the app's `CLSID\{x}` keys, view by view.

use purge_model::{Band, Blocker, EvidenceKind, Tier};

use super::world::*;

/// A world where the app's class `CLS_A` is registered in `root` with `server` = `data`.
fn one_class(root: &str, server: &str, data: &str) -> World {
    let mut fx = machine();
    class(&mut fx, root, CLS_A, server, data);
    let mut world = World::new(fx);
    world.fp.anchors.clsids = vec![CLS_A.into()];
    world
}

#[test]
fn clsid_dangling_inproc_in_root_safe() {
    let world = one_class(HKLM_CLASSES, "InprocServer32", &app_file("a.dll")).ready(&[]);
    let found = world.classes();
    assert_eq!(found.len(), 1, "{found:#?}");
    let c = get(&found, &clsid_key(HKLM_CLASSES, CLS_A));
    assert!(has(c, EvidenceKind::ComKeyOwnership, Tier::A), "{c:#?}");
    assert!(has(c, EvidenceKind::DanglingRef, Tier::A), "{c:#?}");
    assert!(c.blockers.is_empty(), "{:?}", c.blockers);
    assert_eq!(c.category, purge_model::Category::ShellCom);
    assert_eq!(c.action, purge_model::Action::DeleteKey);
    assert_eq!(c.harm, purge_model::Harm::Low);
    assert_eq!(c.reversibility, purge_model::Reversibility::Full);
    assert_eq!(band(c), Band::Safe);
}

/// R3a S3: "no other class emulates it, no shared interface uses it" is read from the walk's hits; an
/// incomplete walk proves no "none": Likely, with one scan warning.
#[test]
fn clsid_incomplete_walk_likely() {
    let mut world = one_class(HKLM_CLASSES, "InprocServer32", &app_file("a.dll")).ready(&[]);
    let app = world.fp.app.program_id.clone();
    let hits = world.ext.ref_hits_for(&app).unwrap().to_vec();
    world.ext = purge_scan::framework::ScanExt::new(Default::default(), Default::default())
        .with_ref_walk(&app, hits, false);
    assert!(!world.ext.ref_walk_complete());
    let found = world.classes();
    let c = get(&found, &clsid_key(HKLM_CLASSES, CLS_A));
    assert!(!has(c, EvidenceKind::DanglingRef, Tier::A), "{c:#?}");
    assert_eq!(band(c), Band::Likely);
    let warnings = world.ext.take_warnings();
    assert_eq!(
        warnings
            .iter()
            .filter(|w| w.contains("did not read every key"))
            .count(),
        1,
        "{warnings:?}"
    );
}

/// R3a S3: a machine class while another user's hive is loaded but was not walked: a class there may
/// emulate it (`TreatAs`). Likely.
#[test]
fn clsid_machine_class_with_unwalked_user_hive_likely() {
    let mut fx = machine();
    class(
        &mut fx,
        HKLM_CLASSES,
        CLS_A,
        "InprocServer32",
        &app_file("a.dll"),
    );
    fx.add_key(r"HKU\S-1-5-21-1000000000-2000000000-3000000000-1002\Software");
    let mut world = World::new(fx);
    world.fp.anchors.clsids = vec![CLS_A.into()];
    let world = world.ready(&[]);
    let found = world.classes();
    let c = get(&found, &clsid_key(HKLM_CLASSES, CLS_A));
    assert_eq!(band(c), Band::Likely, "{c:#?}");
}

#[test]
fn clsid_server_present_likely() {
    let mut world = one_class(HKLM_CLASSES, "InprocServer32", &app_file("a.dll"));
    world.fixture.add_dir(ROOT);
    world.fixture.add_file(&app_file("a.dll"), 100);
    let world = world.ready(&[]);
    let found = world.classes();
    let c = get(&found, &clsid_key(HKLM_CLASSES, CLS_A));
    assert!(has(c, EvidenceKind::ComKeyOwnership, Tier::A));
    assert!(!has_kind(c, EvidenceKind::DanglingRef));
    assert_eq!(band(c), Band::Likely);
}

/// Hostile (trap `com-shared-class`): after the harvest another product re-points the app's class at
/// its own DLL. The class is listed, protected, with the product named.
#[test]
fn clsid_repointed_to_other_product_protected() {
    let world = one_class(
        HKLM_CLASSES,
        "InprocServer32",
        &format!(r"{OTHER_ROOT}\other.dll"),
    )
    .ready(&[]);
    let found = world.classes();
    assert_eq!(found.len(), 1);
    let c = get(&found, &clsid_key(HKLM_CLASSES, CLS_A));
    assert!(blocked_by(c, |b| matches!(
        b,
        Blocker::ReferencedByOtherApp { app } if app == OTHER
    )));
    assert!(!has_kind(c, EvidenceKind::ComKeyOwnership));
    assert_eq!(band(c), Band::Blocked);
}

#[test]
fn clsid_server_outside_root_missing_no_candidate() {
    let world = one_class(HKLM_CLASSES, "InprocServer32", r"C:\Tools\gone.dll").ready(&[]);
    assert!(world.classes().is_empty());
}

#[test]
fn clsid_no_server_subkey_no_candidate() {
    let mut fx = machine();
    sz(&mut fx, &clsid_key(HKLM_CLASSES, CLS_A), "a class");
    sz(
        &mut fx,
        &format!(r"{}\ProgID", clsid_key(HKLM_CLASSES, CLS_A)),
        "App.Thing",
    );
    let mut world = World::new(fx);
    world.fp.anchors.clsids = vec![CLS_A.into()];
    assert!(world.ready(&[]).classes().is_empty());
}

#[test]
fn clsid_in_baseline_no_candidate() {
    let mut world = one_class(HKLM_CLASSES, "InprocServer32", &app_file("a.dll"));
    let key = clsid_key(HKLM_CLASSES, CLS_A);
    world.baseline = Some(baseline(&[&key]));
    assert!(world.ready(&[]).classes().is_empty());
}

/// Without a baseline of this Windows the key is not proven not Windows' own: listed, never Safe.
#[test]
fn clsid_without_baseline_is_tier_b() {
    let mut world = one_class(HKLM_CLASSES, "InprocServer32", &app_file("a.dll"));
    world.baseline = None;
    let found = world.ready(&[]).classes();
    let c = get(&found, &clsid_key(HKLM_CLASSES, CLS_A));
    assert!(has(c, EvidenceKind::ComKeyOwnership, Tier::B));
    assert_eq!(band(c), Band::Likely);
}

/// A subkey COM does not define for a class (an `Instance` list others add to) keeps the key from Tier A.
#[test]
fn clsid_with_foreign_subkey_is_tier_b() {
    let mut world = one_class(HKLM_CLASSES, "InprocServer32", &app_file("a.dll"));
    let key = clsid_key(HKLM_CLASSES, CLS_A);
    sz(
        &mut world.fixture,
        &format!(r"{key}\Instance\{FOREIGN}"),
        "x",
    );
    let found = world.ready(&[]).classes();
    let c = get(&found, &key);
    assert!(has(c, EvidenceKind::ComKeyOwnership, Tier::B));
    assert_ne!(band(c), Band::Safe);
}

#[test]
fn clsid_mscoree_codebase_in_root() {
    let mut world = one_class(HKLM_CLASSES, "InprocServer32", "mscoree.dll");
    let server = format!(r"{}\InprocServer32", clsid_key(HKLM_CLASSES, CLS_A));
    world.fixture.set_value(
        &server,
        "CodeBase",
        purge_source::types::RegData::from_sz("file:///C:/Program%20Files/App/managed.dll"),
    );
    world.fixture.set_value(
        &server,
        "Assembly",
        purge_source::types::RegData::from_sz("App.Managed, Version=1.0.0.0"),
    );
    let found = world.ready(&[]).classes();
    let c = get(&found, &clsid_key(HKLM_CLASSES, CLS_A));
    assert!(has(c, EvidenceKind::DanglingRef, Tier::A));
    let dangling = c
        .evidence
        .iter()
        .find(|e| e.kind == EvidenceKind::DanglingRef)
        .unwrap();
    assert_eq!(
        dangling.detail.get("path"),
        Some(app_file("managed.dll").as_str())
    );
    assert_eq!(band(c), Band::Safe);
    // The CodeBase may also sit in a version subkey.
    let mut world = one_class(HKLM_CLASSES, "InprocServer32", "mscoree.dll");
    world.fixture.set_value(
        &format!(r"{server}\1.0.0.0"),
        "CodeBase",
        purge_source::types::RegData::from_sz("file:///C:/Program Files/App/managed.dll"),
    );
    let found = world.ready(&[]).classes();
    assert_eq!(
        band(get(&found, &clsid_key(HKLM_CLASSES, CLS_A))),
        Band::Safe
    );
}

#[test]
fn clsid_mscoree_without_codebase_no_candidate() {
    let mut world = one_class(HKLM_CLASSES, "InprocServer32", "mscoree.dll");
    let server = format!(r"{}\InprocServer32", clsid_key(HKLM_CLASSES, CLS_A));
    world.fixture.set_value(
        &server,
        "Assembly",
        purge_source::types::RegData::from_sz("App.Managed, Version=1.0.0.0"),
    );
    assert!(world.ready(&[]).classes().is_empty());
}

#[test]
fn clsid_localserver_command_line_with_args() {
    for command in [
        format!(r#""{}" /automation"#, app_file("app.exe")),
        format!(r"{} -Embedding", app_file("app.exe")),
    ] {
        let world = one_class(HKLM_CLASSES, "LocalServer32", &command).ready(&[]);
        let found = world.classes();
        let c = get(&found, &clsid_key(HKLM_CLASSES, CLS_A));
        assert_eq!(band(c), Band::Safe, "{command}: {c:#?}");
        let dangling = c
            .evidence
            .iter()
            .find(|e| e.kind == EvidenceKind::DanglingRef)
            .unwrap();
        assert_eq!(
            dangling.detail.get("path"),
            Some(app_file("app.exe").as_str()),
            "{command}"
        );
    }
}

/// Hostile: a host program (`rundll32`) with the app's DLL as an argument is not the app's server.
/// The harvest may have taken the class for the app's (the argument names its files); the scanner
/// offers nothing.
#[test]
fn clsid_localserver_interpreter_host_not_owned() {
    let command = format!(
        r#"C:\Windows\System32\rundll32.exe "{}",Serve"#,
        app_file("a.dll")
    );
    let world = one_class(HKLM_CLASSES, "LocalServer32", &command).ready(&[]);
    assert!(world.classes().is_empty());
}

#[test]
fn clsid_treatas_from_foreign_class_protects() {
    let mut world = one_class(HKLM_CLASSES, "InprocServer32", &app_file("a.dll"));
    // Another product's class emulated by the app's.
    class(
        &mut world.fixture,
        HKLM_CLASSES,
        FOREIGN,
        "InprocServer32",
        &format!(r"{OTHER_ROOT}\other.dll"),
    );
    sz(
        &mut world.fixture,
        &format!(r"{}\TreatAs", clsid_key(HKLM_CLASSES, FOREIGN)),
        CLS_A,
    );
    let found = world.ready(&[]).classes();
    let c = get(&found, &clsid_key(HKLM_CLASSES, CLS_A));
    assert!(blocked_by(c, |b| matches!(
        b,
        Blocker::ReferencedByOtherApp { .. }
    )));
    assert_eq!(band(c), Band::Blocked);
    // The app's own class naming it does not.
    let mut world = one_class(HKLM_CLASSES, "InprocServer32", &app_file("a.dll"));
    class(
        &mut world.fixture,
        HKLM_CLASSES,
        CLS_B,
        "InprocServer32",
        &app_file("b.dll"),
    );
    sz(
        &mut world.fixture,
        &format!(r"{}\TreatAs", clsid_key(HKLM_CLASSES, CLS_B)),
        CLS_A,
    );
    world.fp.anchors.clsids.push(CLS_B.into());
    let found = world.ready(&[]).classes();
    assert_eq!(
        band(get(&found, &clsid_key(HKLM_CLASSES, CLS_A))),
        Band::Safe
    );
}

/// The 64-bit class is the app's and dangling; the 32-bit one was registered again by another product.
#[test]
fn clsid_each_view_judged_separately() {
    let mut world = one_class(HKLM_CLASSES, "InprocServer32", &app_file("a.dll"));
    class(
        &mut world.fixture,
        HKLM_CLASSES32,
        CLS_A,
        "InprocServer32",
        &format!(r"{OTHER_ROOT}\other.dll"),
    );
    let found = world.ready(&[]).classes();
    assert_eq!(found.len(), 2);
    assert_eq!(
        band(get(&found, &clsid_key(HKLM_CLASSES, CLS_A))),
        Band::Safe
    );
    let c32 = get(&found, &clsid_key(HKLM_CLASSES32, CLS_A));
    assert_eq!(band(c32), Band::Blocked);
    assert!(blocked_by(c32, |b| matches!(
        b,
        Blocker::ReferencedByOtherApp { .. }
    )));
}

#[test]
fn clsid_per_user_view_found() {
    let world = one_class(&user_classes(), "InprocServer32", &app_file("a.dll")).ready(&[]);
    let found = world.classes();
    assert_eq!(found.len(), 1);
    let c = get(&found, &clsid_key(&user_classes(), CLS_A));
    assert_eq!(band(c), Band::Safe);
    // And the user's 32-bit view.
    let root32 = format!(r"{}\WOW6432Node", user_classes());
    let world = one_class(&root32, "InprocServer32", &app_file("a.dll")).ready(&[]);
    let found = world.classes();
    assert_eq!(band(get(&found, &clsid_key(&root32, CLS_A))), Band::Safe);
}

/// A shared proxy/stub class of `kb/shared-iids.json` (here `PSOAInterface`, pointed into the app's
/// folder by a broken installer) is never a candidate.
#[test]
fn shared_proxy_clsid_never_candidate() {
    let mut fx = machine();
    class(
        &mut fx,
        HKLM_CLASSES,
        PSOA,
        "InprocServer32",
        &app_file("a.dll"),
    );
    let mut world = World::new(fx);
    world.fp.anchors.clsids = vec![PSOA.into()];
    assert!(world.ready(&[]).classes().is_empty());
}

/// Without the pipeline's reference walk no referrer is known: nothing is offered.
#[test]
fn without_the_walk_nothing() {
    let world = one_class(HKLM_CLASSES, "InprocServer32", &app_file("a.dll"));
    assert!(world.classes().is_empty());
    assert!(world.interfaces().is_empty());
}

/// Hostile: another installed MSI product's `Registry` row writes the class's server value. The class
/// is protected with that product named.
#[test]
fn msi_foreign_row_blocks_clsid_value() {
    use purge_index::ownership::pack_guid;
    use purge_model::{
        InstallScope, InstallerKind, InventoryEntry, MsiContext, MsiInfo, RawFlags, View,
        WritableBy,
    };
    use purge_source::sysobj::{MsiComponentRow, MsiRegistryRaw, MsiTables};

    const PRODUCT: &str = "{22222222-2222-2222-2222-222222222222}";
    const COMPONENT: &str = "{C1C1C1C1-0000-0000-0000-000000000001}";
    const PACKAGE: &str = r"C:\Windows\Installer\other.msi";
    let mut world = one_class(HKLM_CLASSES, "InprocServer32", &app_file("a.dll"));
    world.fixture.set_msi_tables(
        PACKAGE,
        MsiTables {
            properties: vec![("ProductName".into(), OTHER.into())],
            components: vec![MsiComponentRow {
                component: "Main".into(),
                component_id: Some(COMPONENT.into()),
                attributes: 256,
                key_path: None,
            }],
            registry: vec![MsiRegistryRaw {
                row: "ClassServer".into(),
                root: 2,
                key: format!(r"Software\Classes\CLSID\{CLS_A}\InprocServer32"),
                name: None,
                value: Some(format!(r"{OTHER_ROOT}\other.dll")),
                component: "Main".into(),
            }],
            ..MsiTables::default()
        },
    );
    assert!(pack_guid(PRODUCT).is_some());
    let id = purge_model::ProgramId::machine(View::K64, PRODUCT).unwrap();
    let entry = InventoryEntry {
        key_path: id.key_path(),
        program_id: id,
        hive_sid: None,
        view: View::K64,
        display_name: OTHER.into(),
        version: None,
        publisher: None,
        flags: RawFlags::default(),
        installer_kind: InstallerKind::Msi,
        scope: InstallScope::Machine,
        product_code: Some(PRODUCT.into()),
        upgrade_code: None,
        inno_app_id: None,
        writable_by: WritableBy::Admin,
        install_location: None,
        uninstall_string: None,
        quiet_uninstall_string: None,
        display_icon: None,
        install_time_evidence: Vec::new(),
        msi: Some(MsiInfo {
            context: MsiContext::Machine,
            local_package: Some(PACKAGE.into()),
            install_date: None,
        }),
    };
    let world = world.ready(&[entry]);
    let found = world.classes();
    let c = get(&found, &clsid_key(HKLM_CLASSES, CLS_A));
    assert!(
        blocked_by(c, |b| matches!(
            b,
            Blocker::OwnedByInstalledMsi { product, row }
                if product == PRODUCT && row == "Registry:ClassServer"
        )),
        "{:?}",
        c.blockers
    );
    assert_eq!(band(c), Band::Blocked);
}
