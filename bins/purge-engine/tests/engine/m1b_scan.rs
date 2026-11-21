//! M1b scan tests of the engine (M1B-SCAN-INTEG): the M1b scanners through `pipeline::harvest` and
//! `pipeline::scan`, so the shared data (`ScanExt`), the MSI exemptions (`M1bDecide`), the other apps of
//! the fresh inventory, the policy and the plan are the engine's own.
//!
//! The machines are the scanners' and the harvest's test worlds, read from their crates' test sources
//! (one definition of each shape); every app the scanner tests describe by hand as an "other app" is
//! an Uninstall entry here, as the engine reads it.

use std::path::Path;

use purge_engine::pipeline::{self, Scanned, Sources};
use purge_identity::kbdata::Kb;
use purge_index::ownership::{MACHINE_SID, USERDATA, pack_guid};
use purge_model::{
    Band, Candidate, FileTime, Fingerprint, MsiContext, MsiFacts, MsiRegRow, Plan, PlanItem,
    ProgramId, ScanMode, Target, VerifyGone, View,
};
use purge_source::fixture::{Fixture, FixtureBuilder};
use purge_source::sysobj::{MsiComponentRow, MsiRegistryRaw, MsiTables};
use purge_source::types::{MsiProduct, RegData};

use crate::common::{BASE, shipped_baselines};

#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/purge-harvest/tests/m1b/shapes.rs"]
mod shapes;

#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/purge-scan/tests/msireg/world.rs"]
mod msireg;

#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/purge-scan/tests/com/world.rs"]
mod com;

#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/purge-scan/tests/burn/world.rs"]
mod burn;

#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/purge-scan/tests/diag/world.rs"]
mod diag;

/// Another user of the machine.
const SID2: &str = "S-1-5-21-1000000000-2000000000-3000000000-1002";

// ---------------------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------------------

/// The fingerprint after a completed, verified uninstall.
fn uninstalled(mut fp: Fingerprint) -> Fingerprint {
    fp.window.t_start = Some(FileTime(BASE));
    fp.window.t_end = Some(FileTime(BASE + 10_000_000));
    fp.verify_gone = Some(VerifyGone::new(true, true, true));
    fp
}

/// The machine facts the engine reads besides what a scanner world holds: the environment, the
/// interactive user's profile, an elevated process. What the world already sets stays.
fn engine_facts(mut fx: Fixture) -> Fixture {
    let sid = fx
        .system()
        .user_sid
        .clone()
        .unwrap_or_else(|| shapes::SID.to_owned());
    let facts = fx.system_mut();
    for (name, value) in [
        ("USERNAME", "tester"),
        ("SYSTEMDRIVE", "C:"),
        ("WINDIR", r"C:\Windows"),
        ("SYSTEMROOT", r"C:\Windows"),
        ("PROGRAMFILES", r"C:\Program Files"),
        ("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
        ("PROGRAMDATA", r"C:\ProgramData"),
        ("PUBLIC", r"C:\Users\Public"),
        ("APPDATA", r"C:\Users\tester\AppData\Roaming"),
        ("LOCALAPPDATA", r"C:\Users\tester\AppData\Local"),
    ] {
        facts
            .env
            .entry(name.to_owned())
            .or_insert_with(|| value.to_owned());
    }
    facts.elevated = true;
    if facts.profiles.as_ref().is_none_or(Vec::is_empty) {
        facts.profiles = Some(vec![purge_source::types::ProfileInfo {
            sid,
            path: r"C:\Users\tester".to_owned(),
        }]);
    }
    fx
}

/// `scan --mode post` over `machine` (with [`engine_facts`]), with the shipped baselines.
fn scan_post(machine: &Fixture, fp: &Fingerprint) -> Scanned {
    let machine = engine_facts(machine.clone());
    let scanned = pipeline::scan(
        Sources::of(&machine),
        fp,
        ScanMode::Post,
        None,
        &shipped_baselines(),
        &mut |_| {},
    )
    .expect("the scan runs");
    if std::env::var_os("PURGE_TEST_DUMP").is_some() {
        eprintln!("WARN {:#?}", scanned.warnings);
        for c in &scanned.candidates {
            eprintln!(
                "CAND {} {:?} {:?} {:?}",
                c.scanner, c.target, c.action, c.blockers
            );
        }
        for i in &scanned.built.plan.items {
            eprintln!(
                "ITEM {} {:?} {:?} {}",
                i.scanner, i.target, i.band, i.preselected
            );
        }
    }
    assert_eq!(
        scanned.per_scanner.len(),
        purge_scan::catalog::SCANNER_IDS.len()
    );
    assert_eq!(
        scanned.residue.scan_id, scanned.built.scan.plan_hash,
        "the residue binds to the scan's plan hash"
    );
    scanned.residue.validate().expect("the residue validates");
    assert!(scanned.residue.items.len() <= purge_model::MAX_RESIDUE_ITEMS);
    scanned
}

/// Harvests the Uninstall entry `key` of `machine`.
fn harvest(machine: &Fixture, key: &str) -> Fingerprint {
    pipeline::harvest(
        Sources::of(machine),
        key,
        Kb::shipped(),
        &pipeline::Settings::default(),
        &mut |_| {},
    )
    .unwrap_or_else(|e| panic!("harvest {key}: {e}"))
    .report
    .fingerprint
}

fn fold(t: &Target) -> String {
    format!("{t:?}").to_lowercase()
}

/// The plan's item on `target` (compared ignoring case).
fn item<'p>(plan: &'p Plan, target: &Target) -> Option<&'p PlanItem> {
    plan.items.iter().find(|i| fold(&i.target) == fold(target))
}

/// The scanners' candidate on `target` (compared ignoring case).
fn candidate<'s>(scanned: &'s Scanned, target: &Target) -> Option<&'s Candidate> {
    scanned
        .candidates
        .iter()
        .find(|c| fold(&c.target) == fold(target))
}

/// The plan's items whose target mentions `needle` (ignoring case).
fn mentioning<'p>(plan: &'p Plan, needle: &str) -> Vec<&'p PlanItem> {
    // The needle as `Debug` spells it inside the target (backslashes doubled).
    let quoted = format!("{needle:?}").to_lowercase();
    let needle = &quoted[1..quoted.len() - 1];
    plan.items
        .iter()
        .filter(|i| fold(&i.target).contains(needle))
        .collect()
}

fn key(path: impl Into<String>) -> Target {
    Target::RegKey { path: path.into() }
}

fn dir(path: impl Into<String>) -> Target {
    Target::Path { path: path.into() }
}

/// An Uninstall entry of an installed app in `C:\Program Files\<folder>`, its main exe there.
fn installed_app(fx: &mut Fixture, key_name: &str, name: &str, folder: &str, exe: &str) {
    let key = format!(r"{}\{key_name}", shapes::UNINSTALL);
    fx.set_value(&key, "DisplayName", RegData::from_sz(name));
    fx.set_value(&key, "InstallLocation", RegData::from_sz(folder));
    fx.set_value(
        &key,
        "DisplayIcon",
        RegData::from_sz(&format!(r"{folder}\{exe}")),
    );
    fx.set_value(
        &key,
        "UninstallString",
        RegData::from_sz(&format!(r#""{folder}\uninst.exe""#)),
    );
    fx.add_file(&format!(r"{folder}\{exe}"), 10);
    fx.add_file(&format!(r"{folder}\uninst.exe"), 10);
}

/// An Uninstall entry of an installed MSI product `code` (`WindowsInstaller` = 1) in the hive of `sid`
/// (`None`: the machine).
fn installed_msi_entry(fx: &mut Fixture, sid: Option<&str>, code: &str, name: &str) {
    let key = match sid {
        None => format!(r"{}\{code}", shapes::UNINSTALL),
        Some(sid) => {
            format!(r"HKU\{sid}\Software\Microsoft\Windows\CurrentVersion\Uninstall\{code}")
        }
    };
    fx.set_value(&key, "DisplayName", RegData::from_sz(name));
    fx.set_value(&key, "WindowsInstaller", RegData::from_dword(1));
    fx.set_value(
        &key,
        "UninstallString",
        RegData::from_expand_sz(&format!("MsiExec.exe /X{code}")),
    );
}

// ---------------------------------------------------------------------------------------------------------
// MSI
// ---------------------------------------------------------------------------------------------------------

/// The 7-Zip MSI.
const ZIP: &str = "{23170F69-40C1-2702-2408-000001000000}";
const ZIP_DIR: &str = r"C:\Program Files\7-Zip";
const ZIP_FILES: [&str; 3] = [
    r"C:\Program Files\7-Zip\7z.exe",
    r"C:\Program Files\7-Zip\7zFM.exe",
    r"C:\Program Files\7-Zip\7z.dll",
];

fn zip_component(n: usize) -> String {
    format!("{{C0C0C0C0-0000-0000-0000-{n:012X}}}")
}

fn zip_component_key(n: usize) -> String {
    format!(
        r"{USERDATA}\{MACHINE_SID}\Components\{}",
        pack_guid(&zip_component(n)).unwrap()
    )
}

fn zip_package() -> String {
    format!(
        r"C:\Windows\Installer\{}.msi",
        &pack_guid(ZIP).unwrap()[..8]
    )
}

/// 7-Zip as its MSI installs it: no `InstallLocation`, component key paths in `Program Files\7-Zip`,
/// and a `Registry` row writing `HKCU\Software\7-Zip\Path`, which the user's hive holds.
fn seven_zip(name: &str) -> FixtureBuilder {
    let key = format!(r"{}\{ZIP}", shapes::UNINSTALL);
    let mut b = shapes::machine()
        .os("Professional", 26340, 9882)
        .sz(&key, "DisplayName", name)
        .dword(&key, "WindowsInstaller", 1)
        .expand_sz(&key, "UninstallString", &format!("MsiExec.exe /I{ZIP}"))
        .sz(&key, "Publisher", "Igor Pavlov")
        .msi_product(MsiProduct {
            code: ZIP.to_owned(),
            context: MsiContext::Machine,
            user_sid: None,
            name: Some(name.to_owned()),
            version: None,
            publisher: Some("Igor Pavlov".to_owned()),
            install_location: None,
            local_package: Some(zip_package()),
            install_date: None,
        });
    for (n, path) in ZIP_FILES.iter().enumerate() {
        b = b
            .sz(&zip_component_key(n), &pack_guid(ZIP).unwrap(), path)
            .file(path, 100);
    }
    b.msi_tables(
        &zip_package(),
        MsiTables {
            properties: vec![("ProductCode".into(), ZIP.into())],
            components: vec![MsiComponentRow {
                component: "Main".into(),
                component_id: Some(zip_component(0)),
                attributes: 256,
                key_path: None,
            }],
            registry: vec![MsiRegistryRaw {
                row: "RegPath".into(),
                root: 1,
                key: r"Software\7-Zip".into(),
                name: Some("Path".into()),
                value: Some("[INSTALLDIR]".into()),
                component: "Main".into(),
            }],
            ..MsiTables::default()
        },
    )
    .sz(
        &format!(r"HKU\{}\Software\7-Zip", shapes::SID),
        "Path",
        r"C:\Program Files\7-Zip\",
    )
}

/// The 7-Zip MSI's uninstall leaves the user's `HKCU\Software\7-Zip` (a per-user `Registry` row the
/// machine uninstall cannot reach): the scan offers that key (M1b gate G1).
#[test]
fn e2e_7zip_msi_shape_offers_hkcu_software_key() {
    seven_zip_offers_hkcu_software_key("7-Zip 24.08 (x64)");
}

/// The same with the display name the 7-Zip MSI registers: the bracketed build qualifier
/// `(x64 edition)` is not part of the full name, so the key name `7-Zip` is the app's full name.
#[test]
fn e2e_7zip_msi_display_name_with_edition_offers_hkcu_software_key() {
    seven_zip_offers_hkcu_software_key("7-Zip 24.08 (x64 edition)");
}

fn seven_zip_offers_hkcu_software_key(name: &str) {
    let before = seven_zip(name).build();
    let fp = harvest(&before, ZIP);
    assert_eq!(fp.msi.len(), 1, "{:?} {:?}", fp.msi, fp.warnings);
    assert!(
        fp.msi[0]
            .registry_rows
            .iter()
            .any(|r| r.key.eq_ignore_ascii_case(r"HKU\*\Software\7-Zip")),
        "{:?}",
        fp.msi[0].registry_rows
    );

    // The uninstall: the entry, the product, its components and its folder go; the user's key stays.
    let mut after = before.clone();
    assert!(after.remove_key(&format!(r"{}\{ZIP}", shapes::UNINSTALL)));
    after.set_msi_products(Some(Vec::new()));
    for n in 0..ZIP_FILES.len() {
        assert!(after.remove_key(&zip_component_key(n)));
    }
    assert!(after.remove_path(ZIP_DIR));

    let scanned = scan_post(&after, &uninstalled(fp));
    let plan = &scanned.built.plan;
    let hkcu = key(format!(r"HKU\{}\Software\7-Zip", shapes::SID));
    let it = item(plan, &hkcu).unwrap_or_else(|| panic!("{hkcu:?} not offered: {plan:#?}"));
    assert_eq!(it.scanner, "REG-SOFTWARE");
    assert_ne!(it.band, Band::Blocked, "{it:?}");
    // Nothing of another user or of the machine's Software key itself.
    assert!(item(plan, &key(format!(r"HKU\{}\Software", shapes::SID))).is_none());
}

/// Trap msi-remnants through the engine: every registration of the gone product is offered by
/// REG-ARP-MSI, Safe and ticked (the exemptions of the run list the product as gone), except the
/// component value whose key path lies outside the app; nothing names the installed product.
#[test]
fn e2e_msi_remnants_gone_product() {
    let w = msireg::World::new();
    let scanned = scan_post(&w.fixture, &uninstalled(w.fp.clone()));
    let plan = &scanned.built.plan;
    let p = msireg::packed(msireg::OWN);
    let u = msireg::packed(msireg::UPGRADE);
    let keys = [
        key(format!(r"{USERDATA}\{MACHINE_SID}\Products\{p}")),
        key(format!(r"{}\Products\{p}", msireg::CLASSES)),
        key(format!(r"{}\Features\{p}", msireg::CLASSES)),
    ];
    let values = [
        Target::RegValue {
            path: format!(r"{}\{u}", msireg::UPGRADE_CODES),
            name: p.clone(),
        },
        Target::RegValue {
            path: format!(r"{}\UpgradeCodes\{u}", msireg::CLASSES),
            name: p.clone(),
        },
        Target::RegValue {
            path: msireg::component_key(MACHINE_SID, msireg::C1),
            name: p.clone(),
        },
    ];
    for target in keys.iter().chain(&values) {
        let it = item(plan, target).unwrap_or_else(|| panic!("{target:?}: {plan:#?}"));
        assert_eq!(it.scanner, "REG-ARP-MSI", "{target:?}");
        assert_eq!((it.band, it.preselected), (Band::Safe, true), "{target:?}");
    }
    let shared = Target::RegValue {
        path: msireg::component_key(MACHINE_SID, msireg::C2),
        name: p,
    };
    if let Some(it) = item(plan, &shared) {
        assert!(it.band != Band::Safe && !it.preselected, "{it:?}");
    }
    assert!(
        mentioning(plan, &msireg::packed(msireg::OTHER)).is_empty(),
        "the installed product: {plan:#?}"
    );
}

/// Hostile (R3a B1): the same ProductCode installed per-user by a second user. When the fresh
/// inventory lists it, the product is not gone and nothing of it is offered; when it does not (an
/// unelevated engine), the machine install is gone and still nothing under the second user's SID is
/// offered.
#[test]
fn e2e_hostile_same_msi_installed_for_second_user() {
    let p = msireg::packed(msireg::OWN);
    let second_user = |fx: &mut Fixture| {
        fx.add_key(&format!(
            r"{USERDATA}\{SID2}\Products\{p}\InstallProperties"
        ));
        fx.add_key(&format!(
            r"HKU\{SID2}\Software\Microsoft\Installer\Products\{p}"
        ));
        fx.set_value(
            &msireg::component_key(SID2, msireg::C1),
            &p,
            RegData::from_sz(&msireg::file("app.exe")),
        );
    };

    // 1. Listed for the second user by the inventory.
    let mut fx = msireg::machine();
    second_user(&mut fx);
    installed_msi_entry(&mut fx, Some(SID2), msireg::OWN, "App");
    // An elevated enumeration of Windows Installer lists every user's products.
    fx.add_msi_product(MsiProduct {
        code: msireg::OWN.into(),
        context: MsiContext::UserUnmanaged,
        user_sid: Some(SID2.into()),
        name: Some("App".into()),
        version: None,
        publisher: None,
        install_location: None,
        install_date: None,
        local_package: Some(r"C:\Windows\Installer\own2.msi".into()),
    });
    let fp = uninstalled(msireg::World::with(fx.clone()).fp);
    let plan = scan_post(&fx, &fp).built.plan;
    assert!(mentioning(&plan, &p).is_empty(), "{plan:#?}");

    // 2. Not listed: the machine registration goes, the second user's never.
    let mut fx = msireg::machine();
    second_user(&mut fx);
    let fp = uninstalled(msireg::World::with(fx.clone()).fp);
    let plan = scan_post(&fx, &fp).built.plan;
    assert!(!mentioning(&plan, &p).is_empty(), "{plan:#?}");
    assert!(mentioning(&plan, SID2).is_empty(), "{plan:#?}");
}

// ---------------------------------------------------------------------------------------------------------
// System objects
// ---------------------------------------------------------------------------------------------------------

const TOOL_DIR: &str = r"C:\Program Files\Tool";
const OUR_RULE: &str = "{0000BBBB-0000-0000-0000-000000000001}";
const SAME_NAME_RULE: &str = "{0000BBBB-0000-0000-0000-000000000002}";
const OTHER_RULE: &str = "{0000AAAA-0000-0000-0000-000000000001}";

/// Tool, a non-MSI app in [`TOOL_DIR`] with a service, a task and a firewall rule of its own, beside
/// the shapes' other app (its own service, task and rule) and a rule of the same name for another
/// program.
fn tool() -> Fixture {
    let key = format!(r"{}\Tool", shapes::UNINSTALL);
    let b = shapes::machine()
        .os("Professional", 26340, 9882)
        .sz(&key, "DisplayName", "Tool")
        .sz(&key, "InstallLocation", TOOL_DIR)
        .sz(
            &key,
            "UninstallString",
            &format!(r#""{TOOL_DIR}\uninstall.exe""#),
        )
        .file(&format!(r"{TOOL_DIR}\tool.exe"), 1_000)
        .file(&format!(r"{TOOL_DIR}\update.exe"), 1_000)
        .file(&format!(r"{TOOL_DIR}\uninstall.exe"), 1_000)
        .task(shapes::task(
            r"\Tool\Update",
            &[&format!(r"{TOOL_DIR}\update.exe")],
        ));
    let b = shapes::other_app(b);
    let b = shapes::service(
        b,
        "ToolUpdater",
        &format!(r#""{TOOL_DIR}\update.exe" --service"#),
    );
    let b = shapes::firewall_rule(b, OUR_RULE, "Tool", &format!(r"{TOOL_DIR}\tool.exe"));
    shapes::firewall_rule(
        b,
        SAME_NAME_RULE,
        "Tool",
        r"C:\Program Files\Other\tool.exe",
    )
    .build()
}

/// The service, the task and the firewall rule the uninstaller left are offered; the other app's own
/// objects and a rule that only shares the app's name are not.
#[test]
fn e2e_service_task_firewall_owned_and_traps() {
    let before = tool();
    let fp = harvest(&before, "Tool");
    assert_eq!(fp.sys.services.len(), 1, "{:?}", fp.sys.services);
    assert_eq!(fp.sys.tasks.len(), 1, "{:?}", fp.sys.tasks);
    assert_eq!(
        fp.sys.firewall_rules.len(),
        1,
        "{:?}",
        fp.sys.firewall_rules
    );

    let mut after = before.clone();
    assert!(after.remove_key(&format!(r"{}\Tool", shapes::UNINSTALL)));
    assert!(after.remove_path(TOOL_DIR));
    let scanned = scan_post(&after, &uninstalled(fp));
    let plan = &scanned.built.plan;

    for (needle, scanner) in [
        ("ToolUpdater", "SYS-SERVICE"),
        (r"\Tool\Update", "SYS-TASK"),
        (OUR_RULE, "SYS-FIREWALL"),
    ] {
        let found = mentioning(plan, needle);
        assert!(
            found.iter().any(|i| i.scanner == scanner),
            "{needle}: {found:#?}"
        );
    }
    for trap in ["OtherSvc", r"\Other\Update", OTHER_RULE, SAME_NAME_RULE] {
        assert!(mentioning(plan, trap).is_empty(), "{trap}: {plan:#?}");
    }
}

// ---------------------------------------------------------------------------------------------------------
// COM
// ---------------------------------------------------------------------------------------------------------

/// The COM world with the other product installed (an Uninstall entry in its folder).
fn com_machine() -> Fixture {
    let mut fx = com::machine();
    installed_app(&mut fx, "Other", com::OTHER, com::OTHER_ROOT, "other.exe");
    fx
}

/// An MSI record of the COM app with whole-key `Registry` rows on `keys`.
fn com_msi(keys: &[String]) -> MsiFacts {
    const CODE: &str = "{70707070-0000-0000-0000-0000000000C0}";
    MsiFacts {
        product_code: CODE.into(),
        packed_code: pack_guid(CODE).unwrap(),
        upgrade_code: None,
        context: MsiContext::Machine,
        user_sid: None,
        local_package: None,
        package_readable: true,
        components: Vec::new(),
        registry_rows: keys
            .iter()
            .enumerate()
            .map(|(i, key)| MsiRegRow {
                key: key.clone(),
                name: None,
                whole_key: true,
                component: "Main".into(),
                row: format!("Row{i}"),
            })
            .collect(),
        services: Vec::new(),
        source_dirs: Vec::new(),
        custom_actions: 0,
        unresolved_rows: 0,
    }
}

/// A class whose server was in the app's gone folder is offered; `ISimpleDOMNode`, which the app
/// registered with its own proxy, is shared by every accessibility client: never ticked, never Safe,
/// and neither is the proxy class.
#[test]
fn e2e_com_class_and_isimpledom() {
    let mut fx = com_machine();
    com::class(
        &mut fx,
        com::HKLM_CLASSES,
        com::CLS_A,
        "InprocServer32",
        &com::app_file("app.dll"),
    );
    for root in [com::HKLM_CLASSES, com::HKLM_CLASSES32] {
        com::class(
            &mut fx,
            root,
            com::PROXY,
            "InprocServer32",
            &com::app_file("proxy.dll"),
        );
        com::interface(&mut fx, root, com::ISIMPLEDOM, com::PROXY, None);
    }
    let mut fp = com::fingerprint();
    fp.anchors.clsids = vec![com::CLS_A.into(), com::PROXY.into()];
    let scanned = scan_post(&fx, &uninstalled(fp));
    let plan = &scanned.built.plan;

    let class = key(com::clsid_key(com::HKLM_CLASSES, com::CLS_A));
    let it = item(plan, &class).unwrap_or_else(|| panic!("{class:?}: {plan:#?}"));
    assert_eq!(it.scanner, "COM-CLASS");
    assert_ne!(it.band, Band::Blocked);

    for root in [com::HKLM_CLASSES, com::HKLM_CLASSES32] {
        for target in [
            key(com::iface_key(root, com::ISIMPLEDOM)),
            key(com::clsid_key(root, com::PROXY)),
        ] {
            if let Some(it) = item(plan, &target) {
                assert!(
                    it.band != Band::Safe && !it.preselected,
                    "{target:?}: {it:?}"
                );
            }
            if let Some(c) = candidate(&scanned, &target) {
                assert!(
                    c.blockers.contains(&purge_model::Blocker::SharedIid),
                    "{target:?}: {:?}",
                    c.blockers
                );
            }
        }
    }
}

/// Hostile (R3a S2): a sibling product registered the app's type library again, to its own file. An
/// interface marshalled by `oleaut32` through that library is the sibling's too: not offered. With
/// the app's own proxy it is listed, blocked, never ticked.
#[test]
fn e2e_hostile_typelib_reregistered_by_sibling() {
    let iface = com::iface_key(com::HKLM_CLASSES, com::IID_1);
    let world = |proxy: &str| {
        let mut fx = com_machine();
        for root in [com::HKLM_CLASSES, com::HKLM_CLASSES32] {
            com::class(
                &mut fx,
                root,
                com::PROXY,
                "InprocServer32",
                &com::app_file("proxy.dll"),
            );
        }
        com::interface(
            &mut fx,
            com::HKLM_CLASSES,
            com::IID_1,
            proxy,
            Some(com::TLB),
        );
        com::sz(
            &mut fx,
            &format!(r"{}\TypeLib\{}\1.0\0\win32", com::HKLM_CLASSES, com::TLB),
            &format!(r"{}\other.dll", com::OTHER_ROOT),
        );
        let mut fp = com::fingerprint();
        fp.anchors.clsids = vec![com::PROXY.into()];
        fp.anchors.typelibs = vec![com::TLB.into()];
        fp.msi.push(com_msi(std::slice::from_ref(&iface)));
        (fx, uninstalled(fp))
    };

    let (fx, fp) = world(com::PSOA);
    let plan = scan_post(&fx, &fp).built.plan;
    assert!(item(&plan, &key(iface.clone())).is_none(), "{plan:#?}");
    assert!(mentioning(&plan, com::TLB).is_empty(), "{plan:#?}");

    let (fx, fp) = world(com::PROXY);
    let scanned = scan_post(&fx, &fp);
    if let Some(it) = item(&scanned.built.plan, &key(iface.clone())) {
        assert_eq!((it.band, it.preselected), (Band::Blocked, false), "{it:?}");
    }
    let c = candidate(&scanned, &key(iface)).expect("the interface is listed");
    assert!(
        c.blockers
            .iter()
            .any(|b| matches!(b, purge_model::Blocker::ReferencedByOtherApp { .. })),
        "{:?}",
        c.blockers
    );
    assert!(mentioning(&scanned.built.plan, com::TLB).is_empty());
}

// ---------------------------------------------------------------------------------------------------------
// Burn
// ---------------------------------------------------------------------------------------------------------

/// The Burn world's machine (read from the scanner tests' data) with the two products that stay
/// installed as Uninstall entries: the Python Launcher and the VC++ runtime.
fn burn_machine() -> Fixture {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/purge-scan/tests/data/burn/machine.json");
    let mut fx = Fixture::from_json_file(&path).expect("machine.json loads");
    installed_msi_entry(&mut fx, None, burn::LAUNCHER, "Python Launcher");
    installed_msi_entry(
        &mut fx,
        None,
        burn::VC,
        "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.44.35211",
    );
    fx
}

fn dependents_entry(provider: &str) -> Target {
    key(format!(
        r"{}\{provider}\Dependents\{}",
        burn::DEPS,
        burn::BUNDLE
    ))
}

/// The Python shape: the bundle is gone, the Python Launcher it installed stays, kept by nothing else.
/// The bundle's own dependency entries go; the Launcher is suggested, report-only, never selectable.
#[test]
fn e2e_burn_python_launcher_pair() {
    let fx = burn_machine();
    let scanned = scan_post(&fx, &uninstalled(burn::fingerprint()));
    let plan = &scanned.built.plan;
    let launcher = dependents_entry(burn::LAUNCHER);
    let it = item(plan, &launcher).unwrap_or_else(|| panic!("{launcher:?}: {plan:#?}"));
    assert_eq!(it.scanner, "SYS-BURNDEPS");
    // The Launcher's provider key stays: the product is installed.
    assert!(item(plan, &key(format!(r"{}\{}", burn::DEPS, burn::LAUNCHER))).is_none());
    // The bundle's cache folder goes.
    let cache = dir(format!(r"{}\{}", burn::CACHE, burn::BUNDLE));
    assert!(item(plan, &cache).is_some(), "{plan:#?}");
    // The suggestion.
    let arp = key(format!(r"{}\{}", burn::UNINSTALL, burn::LAUNCHER));
    let c = candidate(&scanned, &arp).expect("the Launcher is suggested");
    assert_eq!(c.action, purge_model::Action::ReportOnly);
    burn_suggestions_are_never_selectable(&scanned);
}

/// A Burn suggestion (a related product's Uninstall entry) is never Safe and never ticked.
fn burn_suggestions_are_never_selectable(scanned: &Scanned) {
    let plan = &scanned.built.plan;
    let mut seen = 0;
    for c in &scanned.candidates {
        if c.scanner == "SYS-BURNDEPS" && c.action == purge_model::Action::ReportOnly {
            seen += 1;
            if let Some(it) = item(plan, &c.target) {
                assert!(it.band != Band::Safe && !it.preselected, "{it:?}");
            }
        }
    }
    assert!(seen > 0, "no suggestion to check");
}

#[test]
fn e2e_burn_suggestion_never_selectable() {
    // Also when the run is forced: no verify-gone, the same answer.
    let fx = burn_machine();
    let scanned = scan_post(&fx, &uninstalled(burn::fingerprint()));
    burn_suggestions_are_never_selectable(&scanned);
    let forced = pipeline::scan(
        Sources::of(&fx),
        &burn::fingerprint(),
        ScanMode::Forced,
        None,
        &shipped_baselines(),
        &mut |_| {},
    )
    .unwrap();
    for it in &forced.built.plan.items {
        assert!(!it.preselected, "forced: {it:?}");
    }
}

/// The VC++ redistributable shape: a bundle whose one package is the shared VC++ runtime, which
/// stays installed. Nothing of the runtime is ticked or Safe, and it is never suggested.
#[test]
fn e2e_vcredist_shape_offers_nothing_preselected() {
    // The redistributable's uninstall removes its own Package Cache folder.
    let mut fx = burn_machine();
    assert!(fx.remove_path(&format!(r"{}\{}", burn::CACHE, burn::BUNDLE)));
    let mut fp = burn::fingerprint();
    fp.app.display_name = "Microsoft Visual C++ 2015-2022 Redistributable (x64)".into();
    if let Some(b) = fp.burn.as_mut() {
        b.packages.retain(|p| p.provider_key == burn::VC_PROVIDER);
    }
    let scanned = scan_post(&fx, &uninstalled(fp));
    let plan = &scanned.built.plan;
    assert!(
        !plan.items.is_empty(),
        "the bundle's dependency records are listed"
    );
    for it in &plan.items {
        assert!(!it.preselected, "{it:?}");
    }
    for needle in [burn::VC, burn::VC_PROVIDER] {
        for it in mentioning(plan, needle) {
            assert_ne!(it.band, Band::Safe, "{it:?}");
        }
    }
    assert!(
        candidate(&scanned, &key(format!(r"{}\{}", burn::UNINSTALL, burn::VC))).is_none(),
        "the runtime is never suggested"
    );
    assert!(item(plan, &key(format!(r"{}\{}", burn::DEPS, burn::VC_PROVIDER))).is_none());
    assert!(
        mentioning(plan, &format!(r"{}v14", burn::VC)).is_empty(),
        "the runtime's package cache: {plan:#?}"
    );
}

/// Hostile (R3a S4): a per-user bundle installed by two users. The scan of the first user's offers its
/// own records and cache only; the second user's install and the machine's Package Cache stay.
#[test]
fn e2e_hostile_per_user_bundle_of_two_users() {
    let mut fx = burn_machine();
    let second_cache = format!(
        r"C:\Users\second\AppData\Local\Package Cache\{}v1.0.0.0",
        burn::USER_PART
    );
    fx.add_key(&format!(
        r"HKU\{SID2}_Classes\Installer\Dependencies\{}\Dependents\{}",
        burn::USER_PROVIDER,
        burn::BUNDLE
    ));
    fx.add_key(&format!(r"HKU\{SID2}\Software\Microsoft"));
    fx.add_file(&format!(r"{second_cache}\user.msi"), 200);
    let mut fp = burn::fingerprint();
    fp.app.program_id = ProgramId::user(burn::SID, View::K64, burn::BUNDLE).unwrap();
    let scanned = scan_post(&fx, &uninstalled(fp));
    let plan = &scanned.built.plan;

    let own = dir(format!(r"{}\{}v1.0.0.0", burn::USER_CACHE, burn::USER_PART));
    assert!(item(plan, &own).is_some(), "{plan:#?}");
    assert!(mentioning(plan, SID2).is_empty(), "{plan:#?}");
    assert!(mentioning(plan, r"Users\second").is_empty(), "{plan:#?}");
    for machine in [
        dir(format!(r"{}\{}", burn::CACHE, burn::BUNDLE)),
        dir(format!(r"{}\{}v1.0.0.0", burn::CACHE, burn::CORE)),
    ] {
        assert!(item(plan, &machine).is_none(), "{machine:?}");
    }
}

// ---------------------------------------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------------------------------------

/// Hostile: a tracing key named after the app's main exe, whose stem an installed app's exe shares. The
/// key is that app's too: not offered; the app's own stem still is.
#[test]
fn e2e_hostile_tracing_stem_shared_with_installed_app() {
    let shared = format!(r"{}\{}_RASAPI32", diag::TRACING, diag::MAIN_STEM);
    let mut fx = diag::machine();
    fx.add_key(&shared);
    let scanned = |fx: &Fixture| scan_post(fx, &uninstalled(diag::fingerprint()));

    // Without the other app in the inventory, the key is the app's.
    let plan = scanned(&fx).built.plan;
    let it = item(&plan, &key(shared.clone())).unwrap_or_else(|| panic!("{plan:#?}"));
    assert_eq!(it.scanner, "REG-DIAG");
    assert!(it.band != Band::Safe && !it.preselected, "{it:?}");

    // With it: not offered.
    installed_app(
        &mut fx,
        "Other",
        diag::OTHER,
        diag::OTHER_ROOT,
        diag::MAIN_EXE,
    );
    let plan = scanned(&fx).built.plan;
    assert!(item(&plan, &key(shared)).is_none(), "{plan:#?}");
}
