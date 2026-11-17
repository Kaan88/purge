//! REG-SHAREDDLLS.

use purge_model::{Action, Band, Blocker, Category, EvidenceKind, Target};
use purge_scan::framework::ScanCtx;
use purge_scan::reg_shareddlls::RegSharedDlls as Scanner;
use purge_source::fixture::Fixture;
use purge_source::metered::{Meter, MeteredFileSystem, MeteredRegistry, MeteredSystem, Op};
use purge_source::types::RegData;

use crate::world::*;

fn with_counters(counters: &[(&str, &str, RegData)]) -> Fixture {
    let mut fx = machine();
    for (key, name, data) in counters {
        fx.set_value(key, name, data.clone());
    }
    fx
}

/// The app without an MSI product (an Inno or plain install).
fn non_msi(fx: Fixture) -> World {
    let mut w = World::with(fx);
    w.fp.msi.clear();
    w
}

#[test]
fn shareddlls_count_one_file_missing_safe() {
    let lib = file("lib.dll");
    let mut w = non_msi(with_counters(&[(SHARED, &lib, RegData::from_dword(1))]));
    w.remove_root();
    let c = w.get(&Scanner, &value(SHARED, &lib));
    assert_eq!(c.scanner, "REG-SHAREDDLLS");
    assert_eq!(c.action, Action::DeleteValue);
    assert_eq!(c.category, Category::Registration);
    assert!(
        c.evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::DanglingRef)
    );
    assert!(c.blockers.is_empty(), "{:?}", c.blockers);
    assert_eq!(band(&c), (Band::Safe, true));
    assert_eq!(guard_check(&w, &c.target, &[]), None);

    // An MSI app: one of its components is keyed on the file.
    let exe = file("app.exe");
    let mut w = World::with(with_counters(&[(SHARED, &exe, RegData::from_dword(1))]));
    w.remove_root();
    let c = w.get(&Scanner, &value(SHARED, &exe));
    assert!(c.blockers.is_empty(), "{:?}", c.blockers);
    assert_eq!(band(&c), (Band::Safe, true));

    // The file still there, and no component of the app explains the count (R2a S1: the framework
    // rule): someone else's reference, Blocked.
    let mut fx = with_counters(&[(SHARED, &lib, RegData::from_dword(1))]);
    fx.add_file(&lib, 10);
    let w = non_msi(fx);
    let c = w.get(&Scanner, &value(SHARED, &lib));
    assert!(
        c.blockers.contains(&Blocker::SharedRefcount),
        "{:?}",
        c.blockers
    );
    assert_eq!(band(&c), (Band::Blocked, false));

    // SharedDLLs is redirected by WOW64: a count in each view is two installs. The app's one
    // component explains one of them, so both values are Blocked.
    let w = World::with(with_counters(&[
        (SHARED, &exe, RegData::from_dword(1)),
        (SHARED32, &exe, RegData::from_dword(1)),
    ]));
    for key in [SHARED, SHARED32] {
        let c = w.get(&Scanner, &value(key, &exe));
        assert!(
            c.blockers.contains(&Blocker::SharedRefcount),
            "{key}: {:?}",
            c.blockers
        );
    }

    // A component of a product the app no longer records is keyed on the file: a stale client blocks.
    let w = non_msi(with_counters(&[(SHARED, &exe, RegData::from_dword(1))]));
    assert!(
        w.get(&Scanner, &value(SHARED, &exe))
            .blockers
            .iter()
            .any(|b| matches!(b, Blocker::OwnedByInstalledMsi { .. }))
    );
}

/// Trap shareddlls-count: a count the app does not account for means other installs use the file.
#[test]
fn shareddlls_count_two_blocks() {
    let lib = file("lib.dll");
    let mut w = non_msi(with_counters(&[(SHARED, &lib, RegData::from_dword(2))]));
    w.remove_root();
    let c = w.get(&Scanner, &value(SHARED, &lib));
    assert!(
        c.blockers.contains(&Blocker::SharedRefcount),
        "{:?}",
        c.blockers
    );
    assert_eq!(band(&c), (Band::Blocked, false));

    // An MSI app none of whose components is keyed on the file accounts for no count at all.
    let mut w = World::with(with_counters(&[(SHARED, &lib, RegData::from_dword(1))]));
    w.remove_root();
    let c = w.get(&Scanner, &value(SHARED, &lib));
    assert!(
        c.blockers.contains(&Blocker::SharedRefcount),
        "{:?}",
        c.blockers
    );
}

#[test]
fn shareddlls_system32_file_never() {
    let names = [
        r"C:\Windows\System32\msvcr120.dll",
        r"C:\Program Files\Common\shared.dll",
        r"C:\Program Files\AppData\lib.dll",
        "lib.dll",
        r"App\lib.dll",
    ];
    let counters: Vec<(&str, &str, RegData)> = names
        .iter()
        .map(|n| (SHARED, *n, RegData::from_dword(1)))
        .collect();
    let mut w = non_msi(with_counters(&counters));
    assert!(w.run(&Scanner).is_empty());
    w.remove_root();
    assert!(w.run(&Scanner).is_empty());
}

#[test]
fn shareddlls_non_dword_blocks() {
    let lib = file("lib.dll");
    for data in [
        RegData::from_sz("1"),
        RegData::from_qword(1),
        RegData::from_binary(vec![1, 0, 0, 0]),
    ] {
        let mut w = non_msi(with_counters(&[(SHARED, &lib, data.clone())]));
        w.remove_root();
        let c = w.get(&Scanner, &value(SHARED, &lib));
        assert!(
            c.blockers.contains(&Blocker::SharedRefcount),
            "{data:?}: {:?}",
            c.blockers
        );
        assert_eq!(band(&c).0, Band::Blocked);
    }
}

/// Both views are read; each value is its own candidate.
#[test]
fn shareddlls_wow64_view() {
    let lib = file("lib.dll");
    let x86 = file("x86.dll");
    let mut w = non_msi(with_counters(&[
        (SHARED, &lib, RegData::from_dword(1)),
        (SHARED32, &x86, RegData::from_dword(1)),
    ]));
    w.remove_root();
    let all = w.run(&Scanner);
    assert_eq!(all.len(), 2, "{all:#?}");
    for target in [value(SHARED, &lib), value(SHARED32, &x86)] {
        let c = w.get(&Scanner, &target);
        assert_eq!(band(&c), (Band::Safe, true), "{target:?}");
        assert_eq!(guard_check(&w, &target, &[]), None, "{target:?}");
    }
    // The keys themselves are never offered, and the guard refuses them.
    assert!(
        all.iter()
            .all(|c| matches!(c.target, Target::RegValue { .. }))
    );
    assert!(guard_check(&w, &key(SHARED), &[]).is_some());
}

/// REG-SHAREDDLLS reads one `values()` of each view's store and nothing else of the registry, apart
/// from the sealing's content reads (in `build` and in `run`) of each candidate.
#[test]
fn budget_key_opens() {
    let lib = file("lib.dll");
    let w = non_msi(with_counters(&[
        (SHARED, &lib, RegData::from_dword(1)),
        (SHARED, r"C:\Windows\System32\a.dll", RegData::from_dword(1)),
    ]));
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
    assert_eq!(calls.get(Op::RegValues).calls, 2, "{}", calls.summary());
    assert_eq!(calls.get(Op::RegSubkeys).calls, 0, "{}", calls.summary());
    assert_eq!(calls.get(Op::RegKeyInfo).calls, 0, "{}", calls.summary());
    assert!(
        calls.get(Op::RegValue).calls <= 2 * out.len() as u64,
        "{}",
        calls.summary()
    );
}
