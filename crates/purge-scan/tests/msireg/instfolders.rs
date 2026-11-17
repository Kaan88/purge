//! REG-INSTFOLDERS.

use purge_index::ownership::MACHINE_SID;
use purge_model::{Action, Band, Blocker, Candidate, Category, EvidenceKind, Target};
use purge_scan::framework::ScanCtx;
use purge_scan::reg_instfolders::RegInstFolders as Scanner;
use purge_source::fixture::Fixture;
use purge_source::metered::{Meter, MeteredFileSystem, MeteredRegistry, MeteredSystem, Op};
use purge_source::types::RegData;

use crate::world::*;

fn with_folders(names: &[&str]) -> Fixture {
    let mut fx = machine();
    for name in names {
        fx.set_value(FOLDERS, name, RegData::from_sz(""));
    }
    fx
}

fn folder(name: &str) -> Target {
    value(FOLDERS, name)
}

fn has(c: &Candidate, kind: EvidenceKind) -> bool {
    c.evidence.iter().any(|e| e.kind == kind)
}

#[test]
fn instfolders_missing_dir_safe() {
    let root = format!(r"{ROOT}\");
    let sub = format!(r"{ROOT}\bin\");
    let mut w = World::with(with_folders(&[&root, &sub]));
    w.remove_root();
    let gone = [packed(OWN)];
    for name in [&root, &sub] {
        let c = w.get(&Scanner, &folder(name));
        assert_eq!(c.scanner, "REG-INSTFOLDERS");
        assert_eq!(c.action, Action::DeleteValue);
        assert_eq!(c.category, Category::Registration);
        assert!(has(&c, EvidenceKind::PointsIntoInstallRoot));
        assert!(has(&c, EvidenceKind::DanglingRef), "{:?}", c.evidence);
        assert!(c.blockers.is_empty(), "{:?}", c.blockers);
        assert_eq!(band(&c), (Band::Safe, true), "{name}");
        assert_eq!(guard_check(&w, &c.target, &gone), None);
    }
}

#[test]
fn instfolders_present_dir_likely() {
    let root = format!(r"{ROOT}\");
    let w = World::with(with_folders(&[&root]));
    let c = w.get(&Scanner, &folder(&root));
    assert!(has(&c, EvidenceKind::PointsIntoInstallRoot));
    assert!(!has(&c, EvidenceKind::DanglingRef));
    assert_eq!(band(&c), (Band::Likely, false));

    // A directory missing inside a root that still exists proves nothing either.
    let sub = format!(r"{ROOT}\bin\");
    let w = World::with(with_folders(&[&sub]));
    let c = w.get(&Scanner, &folder(&sub));
    assert!(!has(&c, EvidenceKind::DanglingRef));
    assert_eq!(band(&c), (Band::Likely, false));
}

/// Another product's component keyed in the directory blocks the directory's entry.
#[test]
fn instfolders_foreign_component_in_dir_blocks() {
    let plugin = format!(r"{ROOT}\plugin\");
    let mut fx = with_folders(&[&plugin]);
    let dll = format!(r"{ROOT}\plugin\x.dll");
    fx.add_dir(&format!(r"{ROOT}\plugin"));
    fx.add_file(&dll, 10);
    fx.set_value(
        &component_key(MACHINE_SID, "{C3C3C3C3-0000-0000-0000-000000000003}"),
        &packed(OTHER),
        RegData::from_sz(&dll),
    );
    let w = World::with(fx);
    let c = w.get(&Scanner, &folder(&plugin));
    assert!(
        c.blockers.iter().any(|b| matches!(
            b,
            Blocker::OwnedByInstalledMsi { product, .. } if product == OTHER
        )),
        "{:?}",
        c.blockers
    );
    assert_eq!(band(&c).0, Band::Blocked);
}

/// Trap instfolders: a directory outside every root is never a candidate, whatever its name holds: the
/// root's parent, a sibling whose name starts like the root, another vendor's folder, a relative or UNC
/// name, a name that is no path.
#[test]
fn instfolders_dir_outside_root_never() {
    let names = [
        r"C:\Program Files\",
        r"C:\Program Files\AppData\",
        r"C:\Program Files\App Vendor\",
        r"C:\Program Files\Common\",
        r"C:\",
        r"App\",
        r"\\server\share\App\",
        "App",
        r"C:\Windows\Installer\",
    ];
    let mut w = World::with(with_folders(&names));
    assert!(w.run(&Scanner).is_empty());
    w.remove_root();
    assert!(w.run(&Scanner).is_empty());
}

#[test]
fn instfolders_trailing_backslash_and_case() {
    let names = [r"c:\PROGRAM FILES\app", r"C:\Program Files\App\Sub\\"];
    let mut w = World::with(with_folders(&names));
    w.remove_root();
    let all = w.run(&Scanner);
    assert_eq!(all.len(), 2, "{all:#?}");
    for name in names {
        // The value is named exactly as stored.
        let c = all
            .iter()
            .find(|c| matches!(&c.target, Target::RegValue { name: n, .. } if n == name))
            .unwrap_or_else(|| panic!("{name}"));
        assert_eq!(band(c), (Band::Safe, true), "{name}");
    }
}

/// REG-INSTFOLDERS reads one `values()` of its store and nothing else of the registry, apart from the
/// sealing's content reads (in `build` and in `run`) of each candidate.
#[test]
fn budget_key_opens() {
    let root = format!(r"{ROOT}\");
    let w = World::with(with_folders(&[&root, r"C:\Program Files\"]));
    let meter = Meter::new();
    let reg = MeteredRegistry::new(&w.fixture, &meter);
    let fs = MeteredFileSystem::new(&w.fixture, &meter);
    let sys = MeteredSystem::new(&w.fixture, &meter);
    let ctx = ScanCtx {
        reg: &reg,
        fs: &fs,
        sys: &sys,
        ..w.ctx()
    };
    let app = purge_scan::framework::AppIdentityView::from_fingerprint(&w.fp, &Default::default());
    let out = ctx.run(&Scanner, &app);
    assert_eq!(out.len(), 1);
    let calls = meter.snapshot();
    assert_eq!(calls.get(Op::RegValues).calls, 1, "{}", calls.summary());
    assert_eq!(calls.get(Op::RegSubkeys).calls, 0, "{}", calls.summary());
    assert_eq!(calls.get(Op::RegKeyInfo).calls, 0, "{}", calls.summary());
    assert!(
        calls.get(Op::RegValue).calls <= 2 * out.len() as u64,
        "{}",
        calls.summary()
    );
}
