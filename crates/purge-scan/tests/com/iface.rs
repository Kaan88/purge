//! COM-INTERFACE: `Interface\{IID}` keys that served only the app.

use purge_index::ownership::pack_guid;
use purge_model::{Band, Blocker, EvidenceKind, MsiContext, MsiFacts, MsiRegRow, Tier};

use super::world::*;

const OWN: &str = "{70707070-0000-0000-0000-000000000001}";

/// The app's proxy class `PROXY` (its server gone, or `present`) in both machine views.
fn proxy_world(present: bool) -> World {
    let mut fx = machine();
    for root in [HKLM_CLASSES, HKLM_CLASSES32] {
        class(
            &mut fx,
            root,
            PROXY,
            "InprocServer32",
            &app_file("proxy.dll"),
        );
    }
    if present {
        fx.add_dir(ROOT);
        fx.add_file(&app_file("proxy.dll"), 10);
    }
    let mut world = World::new(fx);
    world.fp.anchors.clsids = vec![PROXY.into()];
    world
}

/// The app's own MSI product with whole-key rows on `keys`.
fn own_msi(keys: &[String]) -> MsiFacts {
    MsiFacts {
        product_code: OWN.into(),
        packed_code: pack_guid(OWN).unwrap(),
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
                row: format!("Iface{i}"),
            })
            .collect(),
        services: Vec::new(),
        source_dirs: Vec::new(),
        custom_actions: 0,
        unresolved_rows: 0,
    }
}

/// The app's whole type library `TLB` (one version, its file gone).
fn own_typelib(world: &mut World) {
    let tl = format!(r"{HKLM_CLASSES}\TypeLib\{TLB}");
    sz(
        &mut world.fixture,
        &format!(r"{tl}\1.0\0\win32"),
        &app_file("app.tlb"),
    );
    world.fp.anchors.typelibs = vec![TLB.into()];
}

/// Hostile (trap `com-isimpledom`): the app registered `ISimpleDOMNode` with its own proxy in both
/// views. The IID is shared by every accessibility client: no view is offered, and the proxy class is
/// protected too.
#[test]
fn iface_isimpledom_shared_iid_protected() {
    let mut world = proxy_world(false);
    for root in [HKLM_CLASSES, HKLM_CLASSES32] {
        interface(&mut world.fixture, root, ISIMPLEDOM, PROXY, None);
    }
    let world = world.ready(&[]);
    let found = world.interfaces();
    assert_eq!(found.len(), 2, "{found:#?}");
    for root in [HKLM_CLASSES, HKLM_CLASSES32] {
        let c = get(&found, &iface_key(root, ISIMPLEDOM));
        assert!(blocked_by(c, |b| *b == Blocker::SharedIid), "{root}");
        assert_eq!(band(c), Band::Blocked);
    }
    let classes = world.classes();
    for root in [HKLM_CLASSES, HKLM_CLASSES32] {
        let c = get(&classes, &clsid_key(root, PROXY));
        assert!(blocked_by(c, |b| *b == Blocker::SharedIid), "{root}");
        assert_eq!(band(c), Band::Blocked);
    }
}

#[test]
fn iface_in_baseline_protected() {
    let mut world = proxy_world(false);
    interface(&mut world.fixture, HKLM_CLASSES, IID_1, PROXY, None);
    let key = iface_key(HKLM_CLASSES, IID_1);
    world.baseline = Some(baseline(&[&key]));
    let found = world.ready(&[]).interfaces();
    let c = get(&found, &key);
    assert!(blocked_by(c, |b| matches!(
        b,
        Blocker::DenyListed { rule } if rule == "com.system-class"
    )));
    assert_eq!(band(c), Band::Blocked);
}

#[test]
fn iface_safe_needs_msi_row_or_owned_typelib() {
    let key = iface_key(HKLM_CLASSES, IID_1);
    // Proxy gone, nothing else: Likely.
    let mut world = proxy_world(false);
    interface(&mut world.fixture, HKLM_CLASSES, IID_1, PROXY, None);
    let found = world.ready(&[]).interfaces();
    let c = get(&found, &key);
    assert!(has(c, EvidenceKind::ChainedRef, Tier::B), "{c:#?}");
    assert_eq!(band(c), Band::Likely);
    // A whole-key row of the app's own MSI: Safe.
    let mut world = proxy_world(false);
    interface(&mut world.fixture, HKLM_CLASSES, IID_1, PROXY, None);
    world.fp.msi.push(own_msi(std::slice::from_ref(&key)));
    let found = world.ready(&[]).interfaces();
    let c = get(&found, &key);
    assert!(has(c, EvidenceKind::DanglingRef, Tier::A), "{c:#?}");
    assert_eq!(band(c), Band::Safe);
    // The app's whole type library: Safe.
    let mut world = proxy_world(false);
    interface(&mut world.fixture, HKLM_CLASSES, IID_1, PROXY, Some(TLB));
    own_typelib(&mut world);
    let found = world.ready(&[]).interfaces();
    assert_eq!(band(get(&found, &key)), Band::Safe);
}

/// An interface marshalled by `oleaut32` says nothing about its registrant through the proxy: only the
/// type library attributes it, and it is never Safe.
#[test]
fn iface_oleaut_proxy_attributed_by_typelib_only() {
    let mut world = proxy_world(false);
    interface(&mut world.fixture, HKLM_CLASSES, IID_1, PSOA, Some(TLB));
    interface(&mut world.fixture, HKLM_CLASSES, IID_2, PSOA, None);
    own_typelib(&mut world);
    // The walk cannot see the type library id: the app's MSI rows name the interfaces.
    world.fp.msi.push(own_msi(&[
        iface_key(HKLM_CLASSES, IID_1),
        iface_key(HKLM_CLASSES, IID_2),
    ]));
    let found = world.ready(&[]).interfaces();
    assert_eq!(found.len(), 1, "{found:#?}");
    let c = get(&found, &iface_key(HKLM_CLASSES, IID_1));
    let chain = c
        .evidence
        .iter()
        .find(|e| e.kind == EvidenceKind::ChainedRef)
        .unwrap();
    let anchor = chain.detail.get("anchor").unwrap_or_default();
    assert_eq!(
        anchor,
        format!(r"{HKLM_CLASSES}\TypeLib\{TLB}"),
        "{chain:?}"
    );
    assert!(c.evidence.iter().all(|e| !format!("{e:?}").contains(PSOA)));
    assert_eq!(band(c), Band::Likely);
}

#[test]
fn iface_other_view_foreign_makes_likely() {
    let mut world = proxy_world(false);
    interface(&mut world.fixture, HKLM_CLASSES, IID_1, PROXY, None);
    // The 32-bit view of the IID is another product's, marshalled by its existing class.
    class(
        &mut world.fixture,
        HKLM_CLASSES32,
        FOREIGN,
        "InprocServer32",
        &format!(r"{OTHER_ROOT}\other.dll"),
    );
    interface(&mut world.fixture, HKLM_CLASSES32, IID_1, FOREIGN, None);
    world
        .fp
        .msi
        .push(own_msi(&[iface_key(HKLM_CLASSES, IID_1)]));
    let found = world.ready(&[]).interfaces();
    let c = get(&found, &iface_key(HKLM_CLASSES, IID_1));
    assert_eq!(band(c), Band::Likely, "{c:#?}");
    // The foreign view itself is not offered.
    assert!(
        find(&found, &iface_key(HKLM_CLASSES32, IID_1)).is_none_or(|c| band(c) == Band::Blocked)
    );
    // With the 32-bit view absent the same interface is Safe.
    let mut world = proxy_world(false);
    interface(&mut world.fixture, HKLM_CLASSES, IID_1, PROXY, None);
    world
        .fp
        .msi
        .push(own_msi(&[iface_key(HKLM_CLASSES, IID_1)]));
    let found = world.ready(&[]).interfaces();
    assert_eq!(
        band(get(&found, &iface_key(HKLM_CLASSES, IID_1))),
        Band::Safe
    );
}

/// R3a S2 (hostile): a sibling product registered the app's type library again, to its own existing
/// file, after the harvest. The interface that names the library (marshalled by `oleaut32`) is in use
/// by that product: no candidate. With the app's own proxy class it is listed, blocked by the other
/// app.
#[test]
fn iface_typelib_reregistered_by_other_product_protected() {
    let reregistered = |world: &mut World| {
        sz(
            &mut world.fixture,
            &format!(r"{HKLM_CLASSES}\TypeLib\{TLB}\1.0\0\win32"),
            &format!(r"{OTHER_ROOT}\other.dll"),
        );
        world.fp.anchors.typelibs = vec![TLB.into()];
    };
    let mut world = proxy_world(false);
    interface(&mut world.fixture, HKLM_CLASSES, IID_1, PSOA, Some(TLB));
    reregistered(&mut world);
    world
        .fp
        .msi
        .push(own_msi(&[iface_key(HKLM_CLASSES, IID_1)]));
    let found = world.ready(&[]).interfaces();
    assert!(
        find(&found, &iface_key(HKLM_CLASSES, IID_1)).is_none(),
        "{found:#?}"
    );

    let mut world = proxy_world(false);
    interface(&mut world.fixture, HKLM_CLASSES, IID_1, PROXY, Some(TLB));
    reregistered(&mut world);
    world
        .fp
        .msi
        .push(own_msi(&[iface_key(HKLM_CLASSES, IID_1)]));
    let found = world.ready(&[]).interfaces();
    let c = get(&found, &iface_key(HKLM_CLASSES, IID_1));
    assert!(
        blocked_by(c, |b| matches!(b, Blocker::ReferencedByOtherApp { .. })),
        "{c:#?}"
    );
    assert_eq!(band(c), Band::Blocked);
    // The type library is not a chain anchor any more.
    assert!(c.evidence.iter().all(|e| e.kind != EvidenceKind::ChainedRef
        || !e.detail.get("anchor").unwrap_or_default().contains(TLB)));
}

/// R3a M7: an interface key with a subkey COM does not define is never Safe.
#[test]
fn iface_unknown_subkey_likely() {
    let key = iface_key(HKLM_CLASSES, IID_1);
    let mut world = proxy_world(false);
    interface(&mut world.fixture, HKLM_CLASSES, IID_1, PROXY, None);
    sz(&mut world.fixture, &format!(r"{key}\VendorData"), "x");
    world.fp.msi.push(own_msi(std::slice::from_ref(&key)));
    let found = world.ready(&[]).interfaces();
    assert_eq!(band(get(&found, &key)), Band::Likely);
}

#[test]
fn iface_proxy_clsid_likely_then_iface_likely() {
    let mut world = proxy_world(true);
    interface(&mut world.fixture, HKLM_CLASSES, IID_1, PROXY, None);
    world
        .fp
        .msi
        .push(own_msi(&[iface_key(HKLM_CLASSES, IID_1)]));
    let world = world.ready(&[]);
    assert_eq!(
        band(get(&world.classes(), &clsid_key(HKLM_CLASSES, PROXY))),
        Band::Likely
    );
    let found = world.interfaces();
    let c = get(&found, &iface_key(HKLM_CLASSES, IID_1));
    assert!(!has_kind(c, EvidenceKind::DanglingRef));
    assert_eq!(band(c), Band::Likely);
}

/// Invariant L5 over a world with two interfaces of the app's proxy (one in the app's type library,
/// one a row of its MSI package): a view below Exact only takes away (`tests/shared/l5.rs`).
#[test]
fn l5_a_view_below_exact_only_takes_away() {
    let make = || {
        let mut world = proxy_world(false);
        interface(&mut world.fixture, HKLM_CLASSES, IID_1, PROXY, Some(TLB));
        interface(&mut world.fixture, HKLM_CLASSES, IID_2, PROXY, None);
        own_typelib(&mut world);
        world
            .fp
            .msi
            .push(own_msi(&[iface_key(HKLM_CLASSES, IID_2)]));
        world
    };
    let none = crate::l5::check("interfaces", &make().fp.os, &|view| {
        let mut world = make();
        world.baseline = view;
        let world = world.ready(&[]);
        let mut found = world.interfaces();
        found.extend(world.classes());
        found
    });
    assert!(none.len() >= 2, "{none:#?}");
}
