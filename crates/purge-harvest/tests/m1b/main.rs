//! Tests of the M1b harvest steps (M1B-HARVEST): MSI facts and the install folder from component key
//! paths, Burn bundle facts, and the system objects recorded before the uninstall. Every source is a
//! fixture built in code; the M1a golden documents are in `tests/data/m1b/`.

mod burn;
mod coshared;
mod golden;
mod msi;
mod shapes;
mod sys;
mod view_subset;
mod walks;

use purge_harvest::harvest::{HarvestOpts, HarvestReport, Sources, harvest_report_with};
use purge_identity::kbdata::Kb;
use purge_index::ownership::{MACHINE_SID, USERDATA, pack_guid};
use purge_model::{InventoryDoc, MsiContext};
use purge_source::fixture::{Fixture, FixtureBuilder};
use purge_source::sysobj::MsiTables;
use purge_source::types::MsiProduct;

pub use shapes::{SID, UNINSTALL, machine};

/// The packed form of a `{GUID}`.
pub fn packed(guid: &str) -> String {
    pack_guid(guid).expect("test GUID")
}

/// A component GUID numbered `n`.
pub fn comp(n: u32) -> String {
    format!("{{C0C0C0C0-0000-0000-0000-{n:012X}}}")
}

/// The machine's `Components\<packed component>` key.
pub fn component_key(component: &str) -> String {
    format!(
        "{USERDATA}\\{MACHINE_SID}\\Components\\{}",
        packed(component)
    )
}

/// Registers `product` as a client of `component` with key path `data` (machine context).
pub fn client(b: FixtureBuilder, component: &str, product: &str, data: &str) -> FixtureBuilder {
    b.sz(&component_key(component), &packed(product), data)
}

/// Registers `product` as the client of one component per file, numbered from `first`, each file
/// existing on disk.
pub fn files(b: FixtureBuilder, product: &str, first: u32, paths: &[&str]) -> FixtureBuilder {
    let mut b = b;
    for (i, path) in paths.iter().enumerate() {
        let n = first + u32::try_from(i).unwrap();
        b = client(b, &comp(n), product, path).file(path, 100);
    }
    b
}

/// The cached package path of a product.
pub fn package_of(code: &str) -> String {
    format!(r"C:\Windows\Installer\{}.msi", &packed(code)[..8])
}

/// An MSI product with an ARP entry (machine context, `WindowsInstaller` = 1), listed by Windows
/// Installer with its package. `install_location` goes into both.
pub fn msi_app(
    b: FixtureBuilder,
    code: &str,
    name: &str,
    install_location: Option<&str>,
) -> FixtureBuilder {
    let key = format!(r"{UNINSTALL}\{code}");
    let mut b = b
        .sz(&key, "DisplayName", name)
        .dword(&key, "WindowsInstaller", 1)
        .expand_sz(&key, "UninstallString", &format!("MsiExec.exe /I{code}"))
        .sz(&key, "Publisher", "Vendor");
    if let Some(dir) = install_location {
        b = b.sz(&key, "InstallLocation", dir);
    }
    b.msi_product(MsiProduct {
        code: code.to_owned(),
        context: MsiContext::Machine,
        user_sid: None,
        name: Some(name.to_owned()),
        version: None,
        publisher: Some("Vendor".to_owned()),
        install_location: install_location.map(str::to_owned),
        local_package: Some(package_of(code)),
        install_date: None,
    })
}

/// The tables of a product's package (the `ProductCode` property is filled in).
pub fn with_tables(b: FixtureBuilder, code: &str, tables: MsiTables) -> FixtureBuilder {
    let mut tables = tables;
    tables
        .properties
        .push(("ProductCode".to_owned(), code.to_owned()));
    b.msi_tables(&package_of(code), tables)
}

/// The inventory of a fixture.
pub fn inventory_of(f: &Fixture) -> InventoryDoc {
    purge_inventory::arp::inventory(f, f, f, 0).doc
}

/// Harvests the entry named `name`.
pub fn harvest_of(f: &Fixture, name: &str) -> HarvestReport {
    let doc = inventory_of(f);
    let entry = doc
        .entries
        .iter()
        .find(|e| e.display_name == name)
        .unwrap_or_else(|| panic!("no entry {name:?} in {:?}", doc.entries));
    harvest_report_with(
        entry,
        &doc,
        Sources::of(f),
        purge_index::baseline_view::BaselineView::empty(),
        Kb::shipped(),
        &HarvestOpts::default(),
    )
}

/// The roots of a report as (path, source).
pub fn roots(report: &HarvestReport) -> Vec<(String, purge_model::RootSource)> {
    report
        .fingerprint
        .roots
        .iter()
        .map(|r| (r.path.clone(), r.source))
        .collect()
}

/// The outside-root files of a report.
pub fn outside(report: &HarvestReport) -> Vec<String> {
    report
        .fingerprint
        .outside_root_files
        .iter()
        .map(|f| f.path.clone())
        .collect()
}
