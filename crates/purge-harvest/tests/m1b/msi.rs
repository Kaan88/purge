//! MSI facts and the install folder from component key paths (rule R-MSI).

use purge_harvest::msi::{self, ComponentRootInput, MAX_COMPONENTS};
use purge_harvest::roots::RootEnv;
use purge_index::ownership::{OwnershipIndex, OwnershipInput, PERMANENT_CLIENT};
use purge_model::{MsiKeyPath, RootKind, RootSource, SourceTrust};
use purge_source::fixture::FixtureBuilder;
use purge_source::sysobj::{MsiClassRow, MsiComponentRow, MsiRegistryRaw, MsiTables};

use super::*;

/// The 7-Zip MSI.
pub const ZIP: &str = "{23170F69-40C1-2702-2408-000001000000}";
const ZIP_NAME: &str = "7-Zip 24.08 (x64 edition)";
const ZIP_DIR: &str = r"C:\Program Files\7-Zip";
/// A product.
pub const TOOL: &str = "{11111111-1111-1111-1111-111111111111}";
/// Another product.
pub const OTHER: &str = "{22222222-2222-2222-2222-222222222222}";
/// A product that is registered as a client but not installed.
pub const STALE: &str = "{33333333-3333-3333-3333-333333333333}";

/// A `Component` table row.
pub fn component_row(name: &str, id: &str) -> MsiComponentRow {
    MsiComponentRow {
        component: name.to_owned(),
        component_id: Some(id.to_owned()),
        attributes: 256,
        key_path: None,
    }
}

/// The 7-Zip MSI as it installs: no `InstallLocation`, no `DisplayIcon`, five components with file
/// key paths in `Program Files\7-Zip` and its `Lang` subfolder.
fn seven_zip() -> FixtureBuilder {
    let b = msi_app(machine(), ZIP, ZIP_NAME, None);
    let b = files(
        b,
        ZIP,
        1,
        &[
            r"C:\Program Files\7-Zip\7z.exe",
            r"C:\Program Files\7-Zip\7zFM.exe",
            r"C:\Program Files\7-Zip\7z.dll",
            r"C:\Program Files\7-Zip\7-zip.dll",
            r"C:\Program Files\7-Zip\Lang\de.txt",
        ],
    );
    with_tables(
        b,
        ZIP,
        MsiTables {
            properties: vec![(
                "UpgradeCode".into(),
                "{23170f69-40c1-2702-0000-000004000000}".into(),
            )],
            components: vec![component_row("Main", &comp(1))],
            registry: vec![MsiRegistryRaw {
                row: "RegPath".into(),
                root: 1,
                key: r"Software\7-Zip".into(),
                name: Some("Path".into()),
                value: Some("[INSTALLDIR]".into()),
                component: "Main".into(),
            }],
            custom_action_count: 2,
            ..MsiTables::default()
        },
    )
}

/// The 7-Zip machine, built.
pub fn seven_zip_fixture() -> Fixture {
    seven_zip().build()
}

#[test]
fn msi_root_from_component_key_paths_7zip_shape() {
    let f = seven_zip().build();
    let report = harvest_of(&f, ZIP_NAME);
    let fp = &report.fingerprint;

    // The M1a logic finds nothing (no InstallLocation, no DisplayIcon, msiexec uninstaller); the
    // component key paths give the install folder.
    assert_eq!(
        roots(&report),
        [(ZIP_DIR.to_owned(), RootSource::MsiComponent)]
    );
    assert_eq!(fp.roots[0].kind, RootKind::InstallRoot);
    assert_eq!(fp.roots[0].trust, SourceTrust::AdminOnly);
    assert!(
        !fp.warnings.iter().any(|w| w.contains("no validated root")),
        "{:?}",
        fp.warnings
    );
    // Everything is inside the root.
    assert!(
        fp.outside_root_files.is_empty(),
        "{:?}",
        fp.outside_root_files
    );
    assert!(fp.exes.iter().any(|e| e.path.ends_with(r"7-Zip\7zFM.exe")));

    // The MSI facts.
    assert_eq!(fp.msi.len(), 1);
    let m = &fp.msi[0];
    assert_eq!(m.product_code, ZIP);
    assert_eq!(m.packed_code, packed(ZIP));
    assert_eq!(
        m.upgrade_code.as_deref(),
        Some("{23170F69-40C1-2702-0000-000004000000}")
    );
    assert!(m.package_readable);
    assert_eq!(m.local_package.as_deref(), Some(package_of(ZIP).as_str()));
    assert_eq!(m.components.len(), 5);
    assert!(m.components.iter().all(|c| c.other_clients.is_empty()));
    assert_eq!(m.custom_actions, 2);
    assert_eq!(m.registry_rows.len(), 1);
    assert_eq!(m.registry_rows[0].key, r"HKU\*\Software\7-Zip");
    assert_eq!(m.registry_rows[0].name.as_deref(), Some("Path"));
    assert!(fp.burn.is_none());
    assert!(report.ownership.is_some());

    // The document is deterministic and parses back.
    let json = purge_harvest::harvest::to_json(fp);
    assert_eq!(
        json,
        purge_harvest::harvest::to_json(&harvest_of(&f, ZIP_NAME).fingerprint)
    );
    let back: purge_model::Fingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(&back, fp);
}

#[test]
fn msi_root_needs_two_key_paths_or_corroboration() {
    let dir = r"C:\Program Files\Tool";
    // One key-path file and nothing else: not a root; the file is the app's, outside every root.
    let f = files(
        msi_app(machine(), TOOL, "Tool", None),
        TOOL,
        1,
        &[r"C:\Program Files\Tool\tool.exe"],
    )
    .build();
    let report = harvest_of(&f, "Tool");
    assert!(
        report.fingerprint.roots.is_empty(),
        "{:?}",
        report.fingerprint.roots
    );
    assert_eq!(outside(&report), [r"C:\Program Files\Tool\tool.exe"]);
    assert_eq!(
        report.fingerprint.outside_root_files[0].source.0,
        format!("msi:{TOOL}")
    );
    assert!(
        report
            .fingerprint
            .warnings
            .iter()
            .any(|w| w.contains("nothing corroborates")),
        "{:?}",
        report.fingerprint.warnings
    );

    // Two key-path files: the lowest common ancestor is the root.
    let f = files(
        msi_app(machine(), TOOL, "Tool", None),
        TOOL,
        1,
        &[
            r"C:\Program Files\Tool\tool.exe",
            r"C:\Program Files\Tool\bin\helper.exe",
        ],
    )
    .build();
    let report = harvest_of(&f, "Tool");
    assert_eq!(roots(&report), [(dir.to_owned(), RootSource::MsiComponent)]);
    assert!(report.fingerprint.outside_root_files.is_empty());

    // One file, corroborated by the package's INSTALLDIR property.
    let b = files(
        msi_app(machine(), TOOL, "Tool", None),
        TOOL,
        1,
        &[r"C:\Program Files\Tool\tool.exe"],
    );
    let f = with_tables(
        b,
        TOOL,
        MsiTables {
            properties: vec![("INSTALLDIR".into(), r"C:\Program Files\Tool\".into())],
            ..MsiTables::default()
        },
    )
    .build();
    let report = harvest_of(&f, "Tool");
    assert_eq!(roots(&report), [(dir.to_owned(), RootSource::MsiComponent)]);

    // A property naming another folder corroborates nothing.
    let b = files(
        msi_app(machine(), TOOL, "Tool", None),
        TOOL,
        1,
        &[r"C:\Program Files\Tool\tool.exe"],
    );
    let f = with_tables(
        b,
        TOOL,
        MsiTables {
            properties: vec![("INSTALLDIR".into(), r"C:\Program Files\Elsewhere\".into())],
            ..MsiTables::default()
        },
    )
    .build();
    assert!(harvest_of(&f, "Tool").fingerprint.roots.is_empty());
}

/// The parts [`msi::component_roots`] needs, for the entry named `name` of `f`.
fn root_parts(
    f: &Fixture,
    name: &str,
) -> (RootEnv, OwnershipIndex, Vec<purge_model::MsiComponentFact>) {
    let doc = inventory_of(f);
    let entry = doc.entries.iter().find(|e| e.display_name == name).unwrap();
    let (env, _) = RootEnv::from_sources(f, f, entry, &doc);
    let ix = OwnershipIndex::build(&OwnershipInput {
        reg: f,
        fs: f,
        sys: f,
        products: &doc.entries,
        cache: None,
        threads: 1,
    });
    let packed_code = packed(entry.product_code.as_deref().unwrap());
    let comps = msi::components(&ix, &packed_code);
    (env, ix, comps)
}

#[test]
fn msi_root_single_file_with_matching_shortcut_target_accepted() {
    let f = files(
        msi_app(machine(), TOOL, "Tool", None),
        TOOL,
        1,
        &[r"C:\Program Files\Tool\tool.exe"],
    )
    .build();
    let (env, ix, comps) = root_parts(&f, "Tool");
    let own = [packed(TOOL)];
    let run = |corroboration: &[String]| {
        msi::component_roots(&ComponentRootInput {
            fs: &f,
            env: &env,
            ownership: &ix,
            own_codes: &own,
            components: &comps,
            corroboration,
            existing: &[],
            user_writable: false,
        })
    };
    // Without corroboration a single file is not enough.
    assert!(run(&[]).roots.is_empty());
    // A Start Menu shortcut whose target is the file: its directory corroborates the folder.
    let shortcut_target = r"C:\Program Files\Tool\tool.exe";
    let target_dir = shortcut_target.rsplit_once('\\').unwrap().0.to_owned();
    let found = run(&[target_dir]);
    assert_eq!(found.roots.len(), 1, "{found:?}");
    assert_eq!(found.roots[0].path, r"C:\Program Files\Tool");
    assert_eq!(found.roots[0].source, RootSource::MsiComponent);
    // A shortcut into another folder corroborates nothing.
    assert!(
        run(&[r"C:\Program Files\Elsewhere".to_owned()])
            .roots
            .is_empty()
    );
}

#[test]
fn msi_root_never_systemroot_or_common_files() {
    // Hostile: a package whose every key path is in System32, the Windows folder or Common Files.
    let paths = [
        r"C:\Windows\System32\evil1.dll",
        r"C:\Windows\System32\evil2.dll",
        r"C:\Windows\tool.exe",
        r"C:\Program Files\Common Files\microsoft shared\Vendor\a.dll",
        r"C:\Program Files\Common Files\microsoft shared\Vendor\b.dll",
        r"C:\Program Files\Common Files\Vendor\c.dll",
        r"C:\Program Files\Common Files\Vendor\d.dll",
        r"C:\Program Files (x86)\Common Files\Vendor\e.dll",
        r"C:\Program Files (x86)\Common Files\Vendor\f.dll",
    ];
    let f = files(msi_app(machine(), TOOL, "Tool", None), TOOL, 1, &paths).build();
    let report = harvest_of(&f, "Tool");
    assert!(
        report.fingerprint.roots.is_empty(),
        "{:?}",
        report.fingerprint.roots
    );
    assert!(
        !report
            .rejected_roots
            .iter()
            .any(|r| r.source == RootSource::MsiComponent)
    );
    // The files are the app's (no other client), recorded outside every root.
    let mut got = outside(&report);
    got.sort();
    let mut want: Vec<String> = paths.iter().map(|p| (*p).to_owned()).collect();
    want.sort();
    assert_eq!(got, want);
}

#[test]
fn msi_root_never_program_files_itself() {
    // Hostile: one key path in each of two vendor folders, and one directly in Program Files.
    let f = files(
        msi_app(machine(), TOOL, "Tool", None),
        TOOL,
        1,
        &[
            r"C:\Program Files\VendorA\a.exe",
            r"C:\Program Files\VendorB\b.exe",
            r"C:\Program Files\loose.exe",
        ],
    )
    .build();
    let report = harvest_of(&f, "Tool");
    assert!(
        report.fingerprint.roots.is_empty(),
        "{:?}",
        report.fingerprint.roots
    );

    // Two files in each vendor folder: two roots, never their common parent.
    let f = files(
        msi_app(machine(), TOOL, "Tool", None),
        TOOL,
        1,
        &[
            r"C:\Program Files\VendorA\a.exe",
            r"C:\Program Files\VendorA\a.dll",
            r"C:\Program Files\VendorB\b.exe",
            r"C:\Program Files\VendorB\sub\b.dll",
            r"C:\Program Files\loose.exe",
        ],
    )
    .build();
    let report = harvest_of(&f, "Tool");
    assert_eq!(
        roots(&report),
        [
            (
                r"C:\Program Files\VendorA".to_owned(),
                RootSource::MsiComponent
            ),
            (
                r"C:\Program Files\VendorB".to_owned(),
                RootSource::MsiComponent
            ),
        ]
    );
    assert!(
        report
            .fingerprint
            .roots
            .iter()
            .all(|r| !r.path.eq_ignore_ascii_case(r"C:\Program Files"))
    );
    assert_eq!(outside(&report), [r"C:\Program Files\loose.exe"]);
}

#[test]
fn msi_root_dropped_when_dir_has_foreign_component() {
    // Hostile: another product registered a component whose key path is in the same folder.
    let b = msi_app(seven_zip(), OTHER, "Other", None);
    let b = files(
        b,
        OTHER,
        100,
        &[r"C:\Program Files\7-Zip\plugin-of-other.dll"],
    );
    let f = b.build();
    let report = harvest_of(&f, ZIP_NAME);
    assert!(
        report.fingerprint.roots.is_empty(),
        "{:?}",
        report.fingerprint.roots
    );
    assert!(
        report
            .fingerprint
            .warnings
            .iter()
            .any(|w| w.contains("of another client")),
        "{:?}",
        report.fingerprint.warnings
    );
    // 7-Zip's own key paths are still the app's files.
    assert_eq!(report.fingerprint.outside_root_files.len(), 5);
    assert!(
        !outside(&report)
            .iter()
            .any(|p| p.contains("plugin-of-other"))
    );
}

#[test]
fn msi_root_dropped_when_stale_client_present() {
    // A component of the folder is also registered for a product that is not installed (a stale
    // client): it may be another user's install, so the folder is not 7-Zip's alone.
    let f = client(
        seven_zip(),
        &comp(3),
        STALE,
        r"C:\Program Files\7-Zip\7z.dll",
    )
    .build();
    let report = harvest_of(&f, ZIP_NAME);
    assert!(
        report.fingerprint.roots.is_empty(),
        "{:?}",
        report.fingerprint.roots
    );
    let m = &report.fingerprint.msi[0];
    let shared = m
        .components
        .iter()
        .find(|c| c.component_id == comp(3))
        .unwrap();
    assert_eq!(shared.other_clients, [packed(STALE)]);
    // The component with another client contributes no outside-root file either.
    assert!(!outside(&report).iter().any(|p| p.ends_with("7z.dll")));
    assert_eq!(report.fingerprint.outside_root_files.len(), 4);

    // The permanent marker counts as another client too.
    let f = seven_zip()
        .sz(
            &component_key(&comp(3)),
            PERMANENT_CLIENT,
            r"C:\Program Files\7-Zip\7z.dll",
        )
        .build();
    let report = harvest_of(&f, ZIP_NAME);
    assert!(
        report.fingerprint.roots.is_empty(),
        "{:?}",
        report.fingerprint.roots
    );

    // A component of a stale product alone, in the folder: dropped as well.
    let f = client(
        seven_zip(),
        &comp(50),
        STALE,
        r"C:\Program Files\7-Zip\left.dll",
    )
    .file(r"C:\Program Files\7-Zip\left.dll", 1)
    .build();
    assert!(harvest_of(&f, ZIP_NAME).fingerprint.roots.is_empty());
}

#[test]
fn msi_shared_component_contributes_nothing() {
    let shared_a = r"C:\Program Files\Shared\s1.dll";
    let shared_b = r"C:\Program Files\Shared\s2.dll";
    let b = msi_app(machine(), TOOL, "Tool", None);
    let b = files(
        b,
        TOOL,
        1,
        &[
            r"C:\Program Files\Tool\a.exe",
            r"C:\Program Files\Tool\b.exe",
        ],
    );
    // Two components Tool shares with Other, in a folder of their own.
    let b = files(b, TOOL, 10, &[shared_a, shared_b]);
    let b = client(b, &comp(10), OTHER, shared_a);
    let b = client(b, &comp(11), OTHER, shared_b);
    let b = with_tables(
        b,
        TOOL,
        MsiTables {
            components: vec![
                component_row("Shared", &comp(10)),
                component_row("Main", &comp(1)),
            ],
            classes: vec![MsiClassRow {
                clsid: "{5AAAAAAA-0000-0000-0000-000000000001}".into(),
                context: "InprocServer32".into(),
                component: "Shared".into(),
                progid: None,
                appid: None,
            }],
            ..MsiTables::default()
        },
    );
    let f = b.build();
    let report = harvest_of(&f, "Tool");
    let fp = &report.fingerprint;
    // No root, no outside-root file, no anchor from the shared components.
    assert_eq!(
        roots(&report),
        [(
            r"C:\Program Files\Tool".to_owned(),
            RootSource::MsiComponent
        )]
    );
    assert!(
        fp.outside_root_files.is_empty(),
        "{:?}",
        fp.outside_root_files
    );
    assert!(fp.anchors.clsids.is_empty(), "{:?}", fp.anchors.clsids);
    // The facts record the other client.
    let m = &fp.msi[0];
    for id in [comp(10), comp(11)] {
        let c = m.components.iter().find(|c| c.component_id == id).unwrap();
        assert_eq!(c.other_clients, [packed(OTHER)]);
    }
}

#[test]
fn msi_root_does_not_widen_m1a_root() {
    // The entry names `App\bin`; the key paths span `App\bin` and `App\lib`: their common folder
    // `App` would widen the M1a root, so it is not added.
    let b = msi_app(machine(), TOOL, "Tool", Some(r"C:\Program Files\App\bin"));
    let b = files(
        b,
        TOOL,
        1,
        &[
            r"C:\Program Files\App\bin\a.exe",
            r"C:\Program Files\App\lib\b.dll",
        ],
    );
    // A second folder of the product, disjoint from the M1a root: added.
    let b = files(
        b,
        TOOL,
        10,
        &[
            r"C:\Program Files\AppExtra\x.exe",
            r"C:\Program Files\AppExtra\y.dll",
        ],
    );
    let report = harvest_of(&b.build(), "Tool");
    assert_eq!(
        roots(&report),
        [
            (
                r"C:\Program Files\App\bin".to_owned(),
                RootSource::ArpInstallLocation
            ),
            (
                r"C:\Program Files\AppExtra".to_owned(),
                RootSource::MsiComponent
            ),
        ]
    );
    // `App\lib\b.dll` is in no root.
    assert_eq!(outside(&report), [r"C:\Program Files\App\lib\b.dll"]);

    // An inferred M1a root at the same folder is neither replaced nor duplicated.
    let key = format!(r"{UNINSTALL}\{TOOL}");
    let b = msi_app(machine(), TOOL, "Tool", None).sz(
        &key,
        "DisplayIcon",
        r"C:\Program Files\App2\app.exe",
    );
    let b = files(
        b,
        TOOL,
        1,
        &[
            r"C:\Program Files\App2\app.exe",
            r"C:\Program Files\App2\x.dll",
        ],
    );
    let report = harvest_of(&b.build(), "Tool");
    assert_eq!(
        roots(&report),
        [(r"C:\Program Files\App2".to_owned(), RootSource::DisplayIcon)]
    );
}

#[test]
fn msi_unreadable_package_warns_and_keeps_m1a_behaviour() {
    let dir = r"C:\Program Files\Tool";
    // The entry names its folder; the cached package cannot be read (not captured).
    let b = msi_app(machine(), TOOL, "Tool", Some(dir));
    let b = files(
        b,
        TOOL,
        1,
        &[
            r"C:\Program Files\Tool\tool.exe",
            r"C:\Program Files\Tool\x.dll",
        ],
    );
    let f = b.build();
    let report = harvest_of(&f, "Tool");
    let fp = &report.fingerprint;
    assert!(
        fp.warnings.iter().any(|w| w.contains(msi::UNREADABLE)),
        "{:?}",
        fp.warnings
    );
    let m = &fp.msi[0];
    assert!(!m.package_readable);
    assert!(m.registry_rows.is_empty() && m.services.is_empty());
    assert_eq!(m.components.len(), 2);
    // The roots are the M1a roots; nothing comes from the package.
    assert_eq!(
        roots(&report),
        [(dir.to_owned(), RootSource::ArpInstallLocation)]
    );
    assert!(fp.anchors.clsids.is_empty() && fp.anchors.progids.is_empty());
    assert!(fp.outside_root_files.is_empty());
}

#[test]
fn msi_anchors_from_class_progid_typelib_rows() {
    const CLSID: &str = "{5AAAAAAA-0000-0000-0000-000000000001}";
    const SHARED_CLSID: &str = "{5AAAAAAA-0000-0000-0000-000000000002}";
    const LIBID: &str = "{6BBBBBBB-0000-0000-0000-000000000001}";
    const APPID: &str = "{7CCCCCCC-0000-0000-0000-000000000001}";
    let b = msi_app(machine(), TOOL, "Tool", None);
    let b = files(
        b,
        TOOL,
        1,
        &[
            r"C:\Program Files\Tool\a.exe",
            r"C:\Program Files\Tool\b.dll",
        ],
    );
    let b = client(
        files(b, TOOL, 10, &[r"C:\Program Files\Shared\s.dll"]),
        &comp(10),
        OTHER,
        r"C:\Program Files\Shared\s.dll",
    );
    let class = |clsid: &str, component: &str| MsiClassRow {
        clsid: clsid.into(),
        context: "InprocServer32".into(),
        component: component.into(),
        progid: None,
        appid: None,
    };
    let b = with_tables(
        b,
        TOOL,
        MsiTables {
            components: vec![
                component_row("Main", &comp(1)),
                component_row("Shared", &comp(10)),
            ],
            classes: vec![class(CLSID, "Main"), class(SHARED_CLSID, "Shared")],
            progids: vec!["Tool.Document".into(), "txtfile".into(), "Other.Doc".into()],
            typelibs: vec![LIBID.into()],
            appids: vec![APPID.into(), "not-a-guid".into()],
            ..MsiTables::default()
        },
    );
    // Another installed product whose package writes under `Other.Doc`.
    let b = msi_app(b, OTHER, "Other", None);
    let b = with_tables(
        b,
        OTHER,
        MsiTables {
            components: vec![component_row("OtherMain", &comp(90))],
            registry: vec![MsiRegistryRaw {
                row: "Verb".into(),
                root: 0,
                key: r"Other.Doc\shell\open\command".into(),
                name: None,
                value: Some("other.exe".into()),
                component: "OtherMain".into(),
            }],
            ..MsiTables::default()
        },
    );
    let report = harvest_of(&b.build(), "Tool");
    let a = &report.fingerprint.anchors;
    assert_eq!(a.clsids, [CLSID]);
    assert_eq!(
        a.progids,
        ["Tool.Document"],
        "{:?}",
        report.fingerprint.warnings
    );
    assert_eq!(a.typelibs, [LIBID]);
    assert_eq!(a.appids, [APPID]);
}

#[test]
fn msi_component_cap_disables_root_rule() {
    let mut b = msi_app(machine(), TOOL, "Tool", None);
    let n = u32::try_from(MAX_COMPONENTS).unwrap() + 1;
    for i in 0..n {
        let path = format!(r"C:\Program Files\Big\f{i}.dll");
        b = client(b, &comp(i + 1), TOOL, &path);
    }
    let f = b.dir(r"C:\Program Files\Big").build();
    let report = harvest_of(&f, "Tool");
    let fp = &report.fingerprint;
    assert_eq!(fp.msi[0].components.len(), MAX_COMPONENTS);
    assert!(
        fp.warnings
            .iter()
            .any(|w| w.contains("components, more than 5000") && w.contains("not applied")),
        "{:?}",
        fp.warnings
    );
    assert!(fp.roots.is_empty(), "{:?}", fp.roots);
    // The facts kept are the first ones, in component-id order.
    assert!(matches!(
        &fp.msi[0].components[0].key_path,
        MsiKeyPath::File { .. }
    ));
}
