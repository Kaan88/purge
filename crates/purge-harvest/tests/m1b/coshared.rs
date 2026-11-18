//! The harvest of a co-product candidate shares the engine call's indexes: one ownership index, one
//! system-object index and one MSI table cache per engine call (gate K14; HidHide with ViGEm measured
//! two `ownership.components` phases before). The candidate's fingerprint is the one a harvest of its
//! own gives, byte for byte.

use purge_harvest::harvest::{self, SharedIndexes, to_json};
use purge_index::ownership::MemTableCache;
use purge_model::{InventoryDoc, InventorySchema};
use purge_source::fixture::FixtureBuilder;
use purge_source::metered::{Meter, MeteredFileSystem, MeteredRegistry, MeteredSystem, Op};
use purge_source::sysobj::MsiTables;
use purge_source::types::FileTimes;

use super::msi::{OTHER, TOOL, component_row};
use super::*;

const SUITE: &str = "Tool Suite";
const SUITE_DIR: &str = r"C:\Program Files\Acme\Tool Suite";
const HELPER: &str = "Tool Suite Helper";
const HELPER_DIR: &str = r"C:\Program Files\Acme\Helper";

/// An MSI product with its install folder, two key-path files there, and its cached package (on disk,
/// so that the table cache can key it) with its tables.
fn product(b: FixtureBuilder, code: &str, name: &str, dir: &str, first: u32) -> FixtureBuilder {
    let b = msi_app(b, code, name, Some(dir))
        .file(&package_of(code), 40_960)
        .times(
            &package_of(code),
            FileTimes {
                modified: Some(purge_model::FileTime(133_000_000_000_000_000)),
                ..FileTimes::default()
            },
        );
    let b = files(
        b,
        code,
        first,
        &[
            &format!(r"{dir}\{first}.exe"),
            &format!(r"{dir}\{first}.dll"),
        ],
    );
    with_tables(
        b,
        code,
        MsiTables {
            components: vec![component_row("Main", &comp(first))],
            ..MsiTables::default()
        },
    )
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
    // before (the entries alone, no table cache, indexes of its own).
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
