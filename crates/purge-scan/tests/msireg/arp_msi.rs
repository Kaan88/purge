//! REG-ARP-MSI.

use purge_index::ownership::{MACHINE_SID, USERDATA};
use purge_model::{Action, Band, Candidate, Category, MsiContext, Target};
use purge_scan::framework::ScanCtx;
use purge_scan::reg_arp_msi::RegArpMsi as Scanner;
use purge_source::metered::{Meter, MeteredFileSystem, MeteredRegistry, MeteredSystem, Op};
use purge_source::types::{MsiProduct, MsiProductState, RegData};

use crate::world::*;

/// Every target the default world offers for `OWN`.
fn own_targets() -> Vec<Target> {
    let p = packed(OWN);
    let u = packed(UPGRADE);
    vec![
        key(&format!(r"{USERDATA}\{MACHINE_SID}\Products\{p}")),
        key(&format!(r"{CLASSES}\Products\{p}")),
        key(&format!(r"{CLASSES}\Features\{p}")),
        value(&format!(r"{UPGRADE_CODES}\{u}"), &p),
        value(&format!(r"{CLASSES}\UpgradeCodes\{u}"), &p),
        value(&component_key(MACHINE_SID, C1), &p),
        value(&component_key(MACHINE_SID, C2), &p),
    ]
}

fn targets(all: &[Candidate]) -> Vec<&Target> {
    all.iter().map(|c| &c.target).collect()
}

/// Nothing at all names `code` (as a key segment or a value name).
fn mentions(all: &[Candidate], code: &str) -> bool {
    let p = packed(code);
    all.iter().any(|c| match &c.target {
        Target::RegKey { path } => path.to_ascii_uppercase().contains(&p),
        Target::RegValue { path, name } => {
            path.to_ascii_uppercase().contains(&p) || name.eq_ignore_ascii_case(&p)
        }
        _ => false,
    })
}

/// Trap msi-remnants: every shape of a gone product's registration is offered, each Safe with the
/// installer's record, and each passes the guard exactly when the plan lists the product as gone.
#[test]
fn arp_msi_gone_product_all_shapes_safe() {
    let w = World::new();
    let all = w.run(&Scanner);
    let want = own_targets();
    assert_eq!(all.len(), want.len(), "{:#?}", targets(&all));
    let gone = [packed(OWN)];
    for target in &want {
        let c = w.get(&Scanner, target);
        assert_eq!(c.scanner, "REG-ARP-MSI");
        assert_eq!(c.category, Category::Registration);
        let action = match target {
            Target::RegKey { .. } => Action::DeleteKey,
            _ => Action::DeleteValue,
        };
        assert_eq!(c.action, action, "{target:?}");
        assert!(c.blockers.is_empty(), "{target:?}: {:?}", c.blockers);
        assert_eq!(guard_check(&w, target, &gone), None, "{target:?}");
        assert!(guard_check(&w, target, &[]).is_some(), "{target:?}");
        // The shared component's value holds a path outside the app: the content rule keeps it from
        // Safe (arp_msi_component_shared_with_installed_product_value_only_ours).
        if *target != value(&component_key(MACHINE_SID, C2), &gone[0]) {
            assert!(has_msi_manifest(&c), "{target:?}: {:?}", c.evidence);
            assert_eq!(band(&c), (Band::Safe, true), "{target:?}");
        }
    }
    assert!(!mentions(&all, OTHER));
}

#[test]
fn arp_msi_installed_product_nothing() {
    let mut w = World::new();
    w.fixture.add_msi_product(MsiProduct {
        code: OWN.into(),
        context: MsiContext::Machine,
        user_sid: None,
        name: Some("App".into()),
        version: None,
        publisher: None,
        install_location: None,
        install_date: None,
        local_package: None,
    });
    assert!(w.run(&Scanner).is_empty());
}

/// Hostile: the state source fails or answers with a known state: never "gone".
#[test]
fn arp_msi_state_unknown_nothing() {
    let mut w = World::new();
    w.fixture.set_msi_products(None);
    assert!(w.run(&Scanner).is_empty(), "source error");

    // Installed for another user only.
    let mut w = World::new();
    w.fixture
        .set_msi_state(OWN, MsiContext::Machine, MsiProductState::Absent);
    assert!(w.run(&Scanner).is_empty(), "absent is known");

    // Advertised in one context.
    let mut w = World::new();
    w.fixture
        .set_msi_state(OWN, MsiContext::Machine, MsiProductState::Unknown);
    w.fixture
        .set_msi_state(OWN, MsiContext::UserUnmanaged, MsiProductState::Advertised);
    assert!(w.run(&Scanner).is_empty(), "advertised is known");
}

/// Trap msi-remnants, second half: registration of a product the fingerprint does not record is never
/// offered, however its InstallProperties name the app; nor is a record whose packed code does not
/// belong to its ProductCode.
#[test]
fn arp_msi_fabricated_code_not_in_fingerprint_never() {
    let mut fx = machine();
    let f = packed(FAKE);
    let u = packed(UPGRADE);
    fx.set_value(
        &format!(r"{USERDATA}\{MACHINE_SID}\Products\{f}\InstallProperties"),
        "DisplayName",
        RegData::from_sz("App"),
    );
    fx.add_key(&format!(r"{CLASSES}\Products\{f}"));
    fx.add_key(&format!(r"{CLASSES}\Features\{f}"));
    fx.set_value(&format!(r"{UPGRADE_CODES}\{u}"), &f, RegData::from_sz(""));
    fx.set_value(
        &component_key(MACHINE_SID, C1),
        &f,
        RegData::from_sz(&file("app.exe")),
    );
    let w = World::with(fx);
    let all = w.run(&Scanner);
    assert!(!mentions(&all, FAKE), "{:#?}", targets(&all));
    assert_eq!(all.len(), own_targets().len());

    // A record whose packed code is another product's: nothing (the plan would not open the guard).
    let mut w = World::with(machine());
    w.fp.msi[0].packed_code = packed(FAKE);
    assert!(w.run(&Scanner).is_empty());
    let mut w = World::with(machine());
    w.fp.msi[0].product_code = FAKE.into();
    w.fp.msi[0].packed_code = packed(FAKE);
    assert!(w.run(&Scanner).is_empty(), "FAKE has no registration");
}

#[test]
fn arp_msi_upgradecode_value_only_never_key() {
    let mut fx = machine();
    // Another product shares the UpgradeCode; then the app's is the only value left.
    let u = packed(UPGRADE);
    fx.set_value(
        &format!(r"{UPGRADE_CODES}\{u}"),
        &packed(OTHER),
        RegData::from_sz(""),
    );
    for w in [World::with(fx), World::new()] {
        let all = w.run(&Scanner);
        for c in &all {
            if let Target::RegKey { path } = &c.target {
                assert!(
                    !path.to_ascii_lowercase().contains("upgradecodes"),
                    "{path}"
                );
            }
            if let Target::RegValue { path, name } = &c.target
                && path.to_ascii_lowercase().contains("upgradecodes")
            {
                assert_eq!(*name, packed(OWN));
            }
        }
        assert_eq!(
            all.iter()
                .filter(|c| matches!(&c.target, Target::RegValue { path, .. } if path.contains("UpgradeCodes")))
                .count(),
            2
        );
    }
}

#[test]
fn arp_msi_component_value_only_never_key() {
    let w = World::new();
    let all = w.run(&Scanner);
    assert!(all.iter().all(|c| match &c.target {
        Target::RegKey { path } => !path.to_ascii_lowercase().contains("components"),
        _ => true,
    }));
    // C1 has OWN as its only client, and still only the value is offered.
    let c = w.get(
        &Scanner,
        &value(&component_key(MACHINE_SID, C1), &packed(OWN)),
    );
    assert_eq!(c.action, Action::DeleteValue);
    assert!(
        w.find(&Scanner, &key(&component_key(MACHINE_SID, C1)))
            .is_none()
    );
}

/// Trap msi-shared-component: a component the gone product shares with an installed one loses only the
/// gone product's value; the installed product's value is never a target and the guard refuses it.
#[test]
fn arp_msi_component_shared_with_installed_product_value_only_ours() {
    let w = World::new();
    let p = packed(OWN);
    let o = packed(OTHER);
    let k = component_key(MACHINE_SID, C2);
    let ours = w.get(&Scanner, &value(&k, &p));
    assert!(
        ours.evidence.iter().any(|e| e.kind
            == purge_model::EvidenceKind::InstallerManifest(purge_model::ManifestKind::Msi)),
        "{:?}",
        ours.evidence
    );
    assert!(ours.blockers.is_empty(), "{:?}", ours.blockers);
    // Its data is the shared file outside the app: offered, never preselected.
    assert_eq!(band(&ours), (Band::Likely, false));
    assert!(w.find(&Scanner, &value(&k, &o)).is_none());
    assert!(w.find(&Scanner, &key(&k)).is_none());
    assert!(guard_check(&w, &value(&k, &o), std::slice::from_ref(&p)).is_some());
    assert!(guard_check(&w, &key(&k), &[p]).is_some());
}

#[test]
fn arp_msi_per_user_context_paths() {
    let mut fx = machine();
    let p = packed(OWN);
    // The per-user registration of the same product.
    fx.add_key(&format!(r"{USERDATA}\{SID}\Products\{p}\InstallProperties"));
    fx.add_key(&format!(
        r"HKU\{SID}\Software\Microsoft\Installer\Products\{p}"
    ));
    assert!(fx.remove_value(&component_key(MACHINE_SID, C1), &p));
    assert!(fx.remove_value(&component_key(MACHINE_SID, C2), &p));
    fx.set_value(
        &component_key(SID, C1),
        &p,
        RegData::from_sz(&file("app.exe")),
    );
    let mut w = World::with(fx);
    w.fp.msi[0].context = MsiContext::UserUnmanaged;
    w.fp.msi[0].user_sid = Some(SID.into());
    let gone = [p.clone()];
    for target in [
        key(&format!(r"{USERDATA}\{SID}\Products\{p}")),
        key(&format!(r"{USERDATA}\{MACHINE_SID}\Products\{p}")),
        key(&format!(
            r"HKU\{SID}\Software\Microsoft\Installer\Products\{p}"
        )),
        value(&component_key(SID, C1), &p),
    ] {
        let c = w.get(&Scanner, &target);
        assert!(has_msi_manifest(&c));
        assert_eq!(band(&c), (Band::Safe, true), "{target:?}");
        assert_eq!(guard_check(&w, &target, &gone), None, "{target:?}");
    }
    assert!(
        w.find(&Scanner, &value(&component_key(MACHINE_SID, C1), &p))
            .is_none()
    );
    // A machine product never looks into a user's per-user registration.
    w.fp.msi[0].context = MsiContext::Machine;
    w.fp.msi[0].user_sid = None;
    assert!(
        w.find(
            &Scanner,
            &key(&format!(
                r"HKU\{SID}\Software\Microsoft\Installer\Products\{p}"
            ))
        )
        .is_none()
    );
}

#[test]
fn arp_msi_no_upgrade_code_no_candidate() {
    let mut w = World::new();
    w.fp.msi[0].upgrade_code = None;
    let all = w.run(&Scanner);
    assert!(
        all.iter().all(|c| !matches!(&c.target,
            Target::RegValue { path, .. } | Target::RegKey { path }
                if path.to_ascii_lowercase().contains("upgradecodes"))),
        "{:#?}",
        targets(&all)
    );
    assert_eq!(all.len(), own_targets().len() - 2);
}

#[test]
fn arp_msi_absent_shapes_and_unknown_components_nothing() {
    let mut fx = machine();
    let p = packed(OWN);
    assert!(fx.remove_key(&format!(r"{CLASSES}\Features\{p}")));
    let w = World::with(fx);
    assert!(
        w.find(&Scanner, &key(&format!(r"{CLASSES}\Features\{p}")))
            .is_none()
    );
    assert_eq!(w.run(&Scanner).len(), own_targets().len() - 1);

    // Without the ownership index (the M1a context) no component value is offered.
    let mut w = World::new();
    w.ext = purge_scan::framework::ScanExt::new(Default::default(), Default::default());
    assert_eq!(w.run(&Scanner).len(), own_targets().len() - 2);
}

/// The key-open budget of REG-ARP-MSI: at most 16 per recorded product code beyond what ScanExt holds,
/// plus the reads the sealing's content rule makes of every value candidate (in `build` and in `run`).
#[test]
fn budget_key_opens() {
    let w = World::new();
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
    assert_eq!(out.len(), own_targets().len());
    let values = out
        .iter()
        .filter(|c| matches!(c.target, Target::RegValue { .. }))
        .count() as u64;
    let calls = meter.snapshot();
    let reg_calls: u64 = [
        Op::RegKeyInfo,
        Op::RegSubkeys,
        Op::RegValues,
        Op::RegValue,
        Op::RegOther,
    ]
    .iter()
    .map(|op| calls.get(*op).calls)
    .sum();
    let products = w.fp.msi.len() as u64;
    assert!(
        reg_calls <= 16 * products + 2 * values,
        "{reg_calls} > 16 * {products} + 2 * {values}: {}",
        calls.summary()
    );
    assert_eq!(calls.get(Op::RegSubkeys).calls, 1, "{}", calls.summary());
    assert_eq!(calls.get(Op::RegValues).calls, 0, "{}", calls.summary());
    assert_eq!(calls.get(Op::SysMsiTables).calls, 0);
}
