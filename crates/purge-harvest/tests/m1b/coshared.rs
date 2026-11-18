//! The harvest of a co-product candidate shares the engine call's indexes: one ownership index, one
//! system-object index and one MSI table cache per engine call (gate K14; HidHide with ViGEm measured
//! two `ownership.components` phases before). The candidate's fingerprint is the one a harvest of its
//! own gives, byte for byte.
//!
//! The shared ownership index is built from the whole inventory, `msi_only` included, while a
//! candidate's harvest used to build one from the entries alone (review R5 S4). A candidate now sees the
//! MSI products without an Uninstall key as a target harvest of the same product does: their package
//! rows, and `installed()` for them. Component clients do not depend on the inventory (they are read
//! from the `Components` keys), so `other_clients` is the same either way. The `msi_only` tests below
//! pin what a co-removed candidate then claims: exactly what a target harvest of the same product claims
//! in the same world, byte for byte, and never more than the entries-only harvest claimed.

use purge_harvest::harvest::{self, HarvestReport, SharedIndexes, to_json};
use purge_index::ownership::MemTableCache;
use purge_model::{Fingerprint, InventoryDoc, InventorySchema, MsiContext, MsiKeyPath};
use purge_source::fixture::FixtureBuilder;
use purge_source::metered::{Meter, MeteredFileSystem, MeteredRegistry, MeteredSystem, Op};
use purge_source::sysobj::{MsiRegistryRaw, MsiTables};
use purge_source::types::{FileTimes, MsiProduct};

use super::msi::{OTHER, TOOL, component_row};
use super::*;

const SUITE: &str = "Tool Suite";
const SUITE_DIR: &str = r"C:\Program Files\Acme\Tool Suite";
const HELPER: &str = "Tool Suite Helper";
const HELPER_DIR: &str = r"C:\Program Files\Acme\Helper";

/// An MSI product with its install folder, two key-path files there, and its cached package (on disk,
/// so that the table cache can key it) with its tables.
fn product(b: FixtureBuilder, code: &str, name: &str, dir: &str, first: u32) -> FixtureBuilder {
    product_with(b, code, name, dir, first, MsiTables::default())
}

/// The cached package of `code` on disk, so that the table cache can key it.
fn package_file(b: FixtureBuilder, code: &str) -> FixtureBuilder {
    b.file(&package_of(code), 40_960).times(
        &package_of(code),
        FileTimes {
            modified: Some(purge_model::FileTime(133_000_000_000_000_000)),
            ..FileTimes::default()
        },
    )
}

/// [`product`] with more rows in its package (the `Main` component row is added to `tables`).
fn product_with(
    b: FixtureBuilder,
    code: &str,
    name: &str,
    dir: &str,
    first: u32,
    tables: MsiTables,
) -> FixtureBuilder {
    let b = package_file(msi_app(b, code, name, Some(dir)), code);
    let b = files(
        b,
        code,
        first,
        &[
            &format!(r"{dir}\{first}.exe"),
            &format!(r"{dir}\{first}.dll"),
        ],
    );
    let mut tables = tables;
    tables.components.push(component_row("Main", &comp(first)));
    with_tables(b, code, tables)
}

/// The suite and its helper, an MSI of the same vendor installed beside it in the vendor's folder: a
/// co-product candidate of the suite.
fn suite() -> Fixture {
    let b = product(machine(), TOOL, SUITE, SUITE_DIR, 1);
    product(b, OTHER, HELPER, HELPER_DIR, 10).build()
}

fn entry<'d>(doc: &'d InventoryDoc, name: &str) -> &'d purge_model::InventoryEntry {
    doc.entries
        .iter()
        .find(|e| e.display_name == name)
        .unwrap_or_else(|| panic!("no entry {name:?}"))
}

#[test]
fn co_product_harvest_reuses_the_indexes() {
    let f = suite();
    let doc = inventory_of(&f);
    assert!(doc.msi_only.is_empty());
    let meter = Meter::new();
    let (reg, fs, sys) = (
        MeteredRegistry::new(&f, &meter),
        MeteredFileSystem::new(&f, &meter),
        MeteredSystem::new(&f, &meter),
    );
    let sources = Sources {
        reg: &reg,
        fs: &fs,
        sys: &sys,
    };
    let cache = MemTableCache::new();
    let report = harvest_report_with(
        entry(&doc, SUITE),
        &doc,
        sources,
        None,
        Kb::shipped(),
        &HarvestOpts {
            table_cache: Some(&cache),
            shared: None,
        },
    );
    assert_eq!(report.co_candidates.len(), 1, "{:?}", report.rejected_roots);
    assert_eq!(report.co_candidates[0].app.display_name, HELPER);
    let calls = meter.snapshot();
    // One system-object index (one task list) and one ownership index, whose package reads also serve
    // both products' own tables: each package is read once in the whole call.
    assert_eq!(calls.get(Op::SysTasks).calls, 1, "{}", calls.summary());
    assert_eq!(calls.get(Op::SysMsiTables).calls, 2, "{}", calls.summary());

    // The candidate's fingerprint is the one its own harvest gives, as the candidate harvest made it
    // before (the entries alone, no table cache, indexes of its own). This world has no `msi_only`
    // product, so that harvest and one from the whole inventory cannot differ here; the worlds that
    // have one are in the `co_product_*msi_only*` tests below.
    let co = report.co_candidates[0]
        .fingerprint
        .as_deref()
        .expect("the candidate was harvested");
    let alone = harvest::harvest(
        entry(&doc, HELPER),
        &InventoryDoc {
            schema: InventorySchema,
            entries: doc.entries.clone(),
            msi_only: Vec::new(),
        },
        Sources::of(&f),
        None,
        Kb::shipped(),
    );
    assert!(!co.msi.is_empty(), "the candidate's MSI facts were read");
    assert_eq!(to_json(co), to_json(&alone));
    // And the target's own fingerprint is the one a harvest without a cache gives.
    assert_eq!(
        to_json(&report.fingerprint),
        to_json(&harvest_of(&f, SUITE).fingerprint)
    );
}

/// Indexes the caller already has are used as they are: nothing of the machine is read again.
#[test]
fn harvest_uses_the_callers_indexes() {
    let f = suite();
    let doc = inventory_of(&f);
    let shared = SharedIndexes::new(Sources::of(&f), &doc, None);
    shared.ownership();
    shared.sysobj();
    let meter = Meter::new();
    let (reg, fs, sys) = (
        MeteredRegistry::new(&f, &meter),
        MeteredFileSystem::new(&f, &meter),
        MeteredSystem::new(&f, &meter),
    );
    let report = harvest_report_with(
        entry(&doc, SUITE),
        &doc,
        Sources {
            reg: &reg,
            fs: &fs,
            sys: &sys,
        },
        None,
        Kb::shipped(),
        &HarvestOpts {
            table_cache: None,
            shared: Some(&shared),
        },
    );
    let calls = meter.snapshot();
    assert_eq!(calls.get(Op::SysTasks).calls, 0, "{}", calls.summary());
    assert_eq!(
        to_json(&report.fingerprint),
        to_json(&harvest_of(&f, SUITE).fingerprint)
    );
}

// ---------------------------------------------------------------------------------------------------------
// MSI products without an Uninstall key (`msi_only`) beside a co-product candidate (review R5 S4)
// ---------------------------------------------------------------------------------------------------------

/// An MSI product Windows Installer lists without an Uninstall key: it is in `msi_only`, not an entry.
const LOOSE: &str = "{44444444-4444-4444-4444-444444444444}";
const LOOSE_NAME: &str = "Acme Loose Runtime";

/// Registers `code` with Windows Installer (machine context) with its cached package and `tables`, and
/// writes no Uninstall key for it.
fn msi_only(b: FixtureBuilder, code: &str, name: &str, tables: MsiTables) -> FixtureBuilder {
    let b = package_file(b, code).msi_product(MsiProduct {
        code: code.to_owned(),
        context: MsiContext::Machine,
        user_sid: None,
        name: Some(name.to_owned()),
        version: None,
        publisher: Some("Vendor".to_owned()),
        install_location: None,
        local_package: Some(package_of(code)),
        install_date: None,
    });
    with_tables(b, code, tables)
}

/// The fingerprint of the co-product candidate `name` of a report.
fn candidate_fp(report: &HarvestReport, name: &str) -> Fingerprint {
    report
        .co_candidates
        .iter()
        .find(|c| c.app.display_name == name)
        .and_then(|c| c.fingerprint.as_deref())
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "no harvested candidate {name:?}: {:?}",
                report.co_candidates
            )
        })
}

/// The harvest of `name` as a candidate's harvest made it before the shared index: indexes of its own,
/// built from the entries alone (`msi_only` empty).
fn entries_only(f: &Fixture, doc: &InventoryDoc, name: &str) -> Fingerprint {
    harvest::harvest(
        entry(doc, name),
        &InventoryDoc {
            schema: InventorySchema,
            entries: doc.entries.clone(),
            msi_only: Vec::new(),
        },
        Sources::of(f),
        None,
        Kb::shipped(),
    )
}

/// The world has exactly one `msi_only` product, [`LOOSE`], and no entry for it.
fn assert_loose_is_msi_only(f: &Fixture) -> InventoryDoc {
    let doc = inventory_of(f);
    assert_eq!(
        doc.msi_only
            .iter()
            .map(|r| r.product_code.as_str())
            .collect::<Vec<_>>(),
        [LOOSE]
    );
    assert!(doc.entries.iter().all(|e| e.display_name != LOOSE_NAME));
    doc
}

/// An `msi_only` product beside an MSI candidate: it is a client of one of the helper's components
/// (key path outside the helper's folder), and its package writes under the helper's ProgID.
///
/// What the co-removed helper claims with the shared index:
/// - the shared component is recorded with the `msi_only` product in `other_clients`, so it is neither
///   an outside-root file nor inside a root of the helper. This is the same without the shared index:
///   component clients come from the `Components` keys, not from the inventory;
/// - the ProgID is not an anchor of the helper: a row of another installed product claims its key
///   ("also a row of"). The entries-only harvest did not read the `msi_only` package and took it.
///
/// The candidate's fingerprint is byte for byte the one a target harvest of the helper gives in the same
/// world; against the entries-only harvest it only claims less (one anchor fewer).
#[test]
fn co_product_harvest_sees_msi_only_clients_and_rows() {
    const SHARED_DLL: &str = r"C:\Program Files\Common Files\Acme\shared.dll";
    const PROGID: &str = "Helper.Document";
    let b = product(machine(), TOOL, SUITE, SUITE_DIR, 1);
    let b = product_with(
        b,
        OTHER,
        HELPER,
        HELPER_DIR,
        10,
        MsiTables {
            progids: vec![PROGID.into()],
            ..MsiTables::default()
        },
    );
    let b = client(b, &comp(20), OTHER, SHARED_DLL).file(SHARED_DLL, 100);
    let b = client(b, &comp(20), LOOSE, SHARED_DLL);
    let b = msi_only(
        b,
        LOOSE,
        LOOSE_NAME,
        MsiTables {
            components: vec![component_row("LooseMain", &comp(20))],
            registry: vec![MsiRegistryRaw {
                row: "Verb".into(),
                root: 0,
                key: format!(r"{PROGID}\shell\open\command"),
                name: None,
                value: Some("loose.exe".into()),
                component: "LooseMain".into(),
            }],
            ..MsiTables::default()
        },
    );
    let f = b.build();
    let doc = assert_loose_is_msi_only(&f);

    let report = harvest_of(&f, SUITE);
    assert_eq!(
        report
            .co_candidates
            .iter()
            .map(|c| c.app.display_name.as_str())
            .collect::<Vec<_>>(),
        [HELPER],
        "{:?}",
        report.rejected_roots
    );
    let co = candidate_fp(&report, HELPER);

    // The shared component: kept, with the `msi_only` product as its other client.
    let shared_of = |fp: &Fingerprint| {
        fp.msi[0]
            .components
            .iter()
            .find(|c| c.component_id == comp(20))
            .cloned()
            .expect("the helper's shared component is recorded")
    };
    let shared = shared_of(&co);
    assert_eq!(shared.other_clients, [packed(LOOSE)]);
    assert_eq!(
        shared.key_path,
        MsiKeyPath::File {
            path: SHARED_DLL.to_owned()
        }
    );
    assert!(
        !co.outside_root_files.iter().any(|o| o.path == SHARED_DLL),
        "{:?}",
        co.outside_root_files
    );
    assert!(
        co.roots.iter().all(|r| !SHARED_DLL
            .to_ascii_lowercase()
            .starts_with(&r.path.to_ascii_lowercase())),
        "{:?}",
        co.roots
    );
    // The ProgID: another installed product's row claims its key.
    assert!(co.anchors.progids.is_empty(), "{:?}", co.anchors.progids);
    assert!(
        co.warnings
            .iter()
            .any(|w| w.contains(PROGID) && w.contains("also a row of")),
        "{:?}",
        co.warnings
    );

    // Exactly what a target harvest of the helper claims in the same world.
    assert_eq!(to_json(&co), to_json(&harvest_of(&f, HELPER).fingerprint));

    // The entries-only harvest differs: it took the ProgID. Roots, outside-root files and component
    // facts are the same.
    let before = entries_only(&f, &doc, HELPER);
    assert_ne!(to_json(&co), to_json(&before));
    assert_eq!(before.anchors.progids, [PROGID]);
    assert_eq!(shared_of(&before), shared);
    assert_eq!(before.msi, co.msi);
    assert_eq!(before.roots, co.roots);
    assert_eq!(before.outside_root_files, co.outside_root_files);
}

/// A bundle of the vendor, `InstallLocation` beside the suite: a co-product candidate.
const RUNTIME: &str = "Tool Suite Runtime";
const RUNTIME_BUNDLE: &str = "{B0000000-0000-0000-0000-0000000000A1}";
const RUNTIME_DIR: &str = r"C:\Program Files\Acme\Runtime";
const RUNTIME_PROVIDER: &str = "AcmeRuntime";
const DEPS: &str = r"HKLM\SOFTWARE\Classes\Installer\Dependencies";

/// The runtime bundle under the Uninstall key `uninstall`, with its cache and its own provider key.
fn runtime_bundle(b: FixtureBuilder, uninstall: &str) -> FixtureBuilder {
    let cache = format!(r"C:\ProgramData\Package Cache\{RUNTIME_BUNDLE}\setup.exe");
    let key = format!(r"{uninstall}\{RUNTIME_BUNDLE}");
    b.sz(&key, "DisplayName", RUNTIME)
        .sz(&key, "Publisher", "Vendor")
        .sz(&key, "InstallLocation", RUNTIME_DIR)
        .sz(&key, "BundleProviderKey", RUNTIME_PROVIDER)
        .sz(&key, "BundleCachePath", &cache)
        .sz(
            &key,
            "BundleUpgradeCode",
            "{B1111111-0000-0000-0000-0000000000A1}",
        )
        .sz(&key, "UninstallString", &format!(r#""{cache}" /uninstall"#))
        .file(&cache, 1_000)
        .key(&format!(r"{DEPS}\{RUNTIME_PROVIDER}\Dependents"))
}

/// The suite, the runtime bundle under `uninstall`, and the bundle's package [`LOOSE`]: an `msi_only`
/// product (installed for the machine, no Uninstall key) with two key-path files in the runtime's
/// folder, tied to the bundle by a dependency record under `deps`.
fn runtime_world(uninstall: &str, deps: &str) -> Fixture {
    let b = product(machine(), TOOL, SUITE, SUITE_DIR, 1);
    let b = runtime_bundle(b, uninstall);
    let b = files(
        b,
        LOOSE,
        30,
        &[
            &format!(r"{RUNTIME_DIR}\rt.exe"),
            &format!(r"{RUNTIME_DIR}\rt.dll"),
        ],
    );
    let b = msi_only(
        b,
        LOOSE,
        LOOSE_NAME,
        MsiTables {
            components: vec![component_row("RtMain", &comp(30))],
            ..MsiTables::default()
        },
    );
    b.key(&format!(r"{deps}\{LOOSE}\Dependents\{RUNTIME_BUNDLE}"))
        .build()
}

/// The co-removed runtime bundle's package is an `msi_only` product (review R5 S4: "a package product
/// without an Uninstall key can now become a child of a co-removed bundle").
///
/// What the co-removed bundle claims with the shared index: the package is installed (`ix.installed()`
/// knows it), so it becomes a child of the bundle, as it does when the bundle is the target. A child is
/// harvested through its inventory entry, and the `msi_only` product has none, so it contributes no MSI
/// facts, no root and no outside-root file ("has no inventory entry; it is not harvested"). The package
/// is listed in the bundle's facts with its product code, as it was before.
///
/// The candidate's fingerprint is byte for byte the one a target harvest of the bundle gives in the same
/// world. The entries-only harvest differs only in the warning ("is not an installed product"): the same
/// Burn facts, MSI facts, roots and outside-root files.
#[test]
fn co_product_bundle_with_msi_only_package() {
    let f = runtime_world(UNINSTALL, DEPS);
    let doc = assert_loose_is_msi_only(&f);

    let report = harvest_of(&f, SUITE);
    let co = candidate_fp(&report, RUNTIME);
    let burn = co.burn.as_ref().expect("the candidate is a Burn bundle");
    assert_eq!(
        burn.packages
            .iter()
            .map(|p| (p.provider_key.as_str(), p.product_code.as_deref()))
            .collect::<Vec<_>>(),
        [(LOOSE, Some(LOOSE))]
    );
    assert!(burn.packages[0].other_dependents.is_empty());
    // A child, but without an inventory entry: not harvested, nothing of it is claimed.
    let not_harvested = format!(
        "burn: the package {} has no inventory entry; it is not harvested",
        packed(LOOSE)
    );
    assert!(co.warnings.contains(&not_harvested), "{:?}", co.warnings);
    assert!(co.msi.is_empty(), "{:?}", co.msi);
    assert!(
        co.roots
            .iter()
            .all(|r| r.source != purge_model::RootSource::MsiComponent),
        "{:?}",
        co.roots
    );
    assert!(
        co.outside_root_files.is_empty(),
        "{:?}",
        co.outside_root_files
    );

    // Exactly what a target harvest of the bundle claims in the same world.
    assert_eq!(to_json(&co), to_json(&harvest_of(&f, RUNTIME).fingerprint));

    // The entries-only harvest: the package was not installed for it, so it was no child. The claims
    // are the same.
    let before = entries_only(&f, &doc, RUNTIME);
    assert!(!before.warnings.contains(&not_harvested));
    assert!(
        before
            .warnings
            .iter()
            .any(|w| w.contains(LOOSE) && w.contains("is not an installed product")),
        "{:?}",
        before.warnings
    );
    assert_eq!(before.burn, co.burn);
    assert_eq!(before.msi, co.msi);
    assert_eq!(before.roots, co.roots);
    assert_eq!(before.outside_root_files, co.outside_root_files);
}

/// The foreign-product check of a co-removed per-user bundle with an `msi_only` package (review R5 S4:
/// "the foreign-product check catches more"). The runtime bundle is installed for the user; only the
/// user's own dependency records name the package, which is installed for the machine.
///
/// With the shared index the co-removed bundle does not claim the package at all: a user's record cannot
/// tie a machine product to the bundle ("installed for the machine"), and the package is not in the
/// bundle's facts. That is byte for byte what a target harvest of the bundle gives. The entries-only
/// harvest did not know the package as installed and listed it among the bundle's packages: with the
/// shared index the candidate claims less.
#[test]
fn co_product_user_bundle_drops_msi_only_machine_package() {
    let uninstall = format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Uninstall");
    let deps = format!(r"HKU\{SID}_Classes\Installer\Dependencies");
    let f = runtime_world(&uninstall, &deps);
    let doc = assert_loose_is_msi_only(&f);
    assert_eq!(entry(&doc, RUNTIME).hive_sid.as_deref(), Some(SID));

    let report = harvest_of(&f, SUITE);
    let co = candidate_fp(&report, RUNTIME);
    let burn = co.burn.as_ref().expect("the candidate is a Burn bundle");
    assert!(burn.packages.is_empty(), "{:?}", burn.packages);
    assert!(co.msi.is_empty(), "{:?}", co.msi);
    assert!(
        co.warnings
            .iter()
            .any(|w| w.contains(LOOSE) && w.contains("installed for the machine")),
        "{:?}",
        co.warnings
    );

    // Exactly what a target harvest of the bundle claims in the same world.
    assert_eq!(to_json(&co), to_json(&harvest_of(&f, RUNTIME).fingerprint));

    // The entries-only harvest kept the package in the bundle's facts.
    let before = entries_only(&f, &doc, RUNTIME);
    assert_eq!(
        before
            .burn
            .as_ref()
            .expect("Burn facts")
            .packages
            .iter()
            .map(|p| p.product_code.as_deref())
            .collect::<Vec<_>>(),
        [Some(LOOSE)]
    );
    assert!(before.msi.is_empty(), "{:?}", before.msi);
    assert_eq!(before.roots, co.roots);
    assert_eq!(before.outside_root_files, co.outside_root_files);
}
