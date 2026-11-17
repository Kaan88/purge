//! COM-CLASS: target spelling, AppIDs, type libraries, and the read budgets of both scanners.

use purge_model::{Band, EvidenceKind, Target};
use purge_scan::com_class::ComClass;
use purge_scan::com_interface::ComInterface;
use purge_scan::framework::{AppIdentityView, Scanner};
use purge_source::metered::{Meter, MeteredRegistry, Op};
use purge_source::types::RegData;

use super::world::*;

/// Every view of the app's class, machine and user: each target is spelled through the physical key.
#[test]
fn clsid_target_never_spelled_through_wow6432_link_or_hkcr() {
    let mut fx = machine();
    let user = user_classes();
    let user32 = format!(r"{user}\WOW6432Node");
    for root in [HKLM_CLASSES, HKLM_CLASSES32, user.as_str(), user32.as_str()] {
        class(&mut fx, root, CLS_A, "InprocServer32", &app_file("a.dll"));
    }
    let mut world = World::new(fx);
    world.fp.anchors.clsids = vec![CLS_A.into()];
    let world = world.ready(&[]);
    let found = world.classes();
    assert_eq!(found.len(), 4, "{found:#?}");
    for c in &found {
        let key = key_of(c).to_ascii_uppercase();
        assert!(!key.starts_with("HKCR"), "{key}");
        assert!(!key.contains(r"SOFTWARE\WOW6432NODE\CLASSES"), "{key}");
        assert!(
            !key.contains(r"\SOFTWARE\CLASSES") || key.starts_with("HKLM"),
            "{key}"
        );
        assert_eq!(band(c), Band::Safe, "{key}");
    }
    assert!(find(&found, &clsid_key(HKLM_CLASSES32, CLS_A)).is_some());
    assert!(find(&found, &clsid_key(&user32, CLS_A)).is_some());
}

/// The AppID is the class id (as most servers register it), so the walk sees every class naming it.
fn appid_world(foreign_referrer: bool) -> World {
    let mut fx = machine();
    class(
        &mut fx,
        HKLM_CLASSES,
        CLS_A,
        "LocalServer32",
        &app_file("app.exe"),
    );
    fx.set_value(
        &clsid_key(HKLM_CLASSES, CLS_A),
        "AppID",
        RegData::from_sz(CLS_A),
    );
    sz(&mut fx, &format!(r"{HKLM_CLASSES}\AppID\{CLS_A}"), "App");
    sz(&mut fx, &format!(r"{HKLM_CLASSES}\AppID\{APPID}"), "App");
    fx.set_value(
        &format!(r"{HKLM_CLASSES}\AppID\app.exe"),
        "AppID",
        RegData::from_sz(CLS_A),
    );
    if foreign_referrer {
        class(
            &mut fx,
            HKLM_CLASSES,
            FOREIGN,
            "InprocServer32",
            &format!(r"{OTHER_ROOT}\other.dll"),
        );
        fx.set_value(
            &clsid_key(HKLM_CLASSES, FOREIGN),
            "AppID",
            RegData::from_sz(CLS_A),
        );
    }
    let mut world = World::new(fx);
    world.fp.anchors.clsids = vec![CLS_A.into()];
    world.fp.anchors.appids = vec![CLS_A.into(), APPID.into()];
    world.ready(&[])
}

#[test]
fn appid_only_when_all_referrers_owned() {
    let world = appid_world(false);
    let found = world.classes();
    let appid = get(&found, &format!(r"{HKLM_CLASSES}\AppID\{CLS_A}"));
    assert!(has_kind(appid, EvidenceKind::ComKeyOwnership));
    assert!(has_kind(appid, EvidenceKind::ChainedRef));
    assert!(appid.blockers.is_empty(), "{:?}", appid.blockers);
    let exe = get(&found, &format!(r"{HKLM_CLASSES}\AppID\app.exe"));
    assert!(has_kind(exe, EvidenceKind::ChainedRef));
    // `APPID`, which no class names and the walk cannot see: nothing, though the key is there.
    assert!(find(&found, &format!(r"{HKLM_CLASSES}\AppID\{APPID}")).is_none());
    // Another product's class names the AppID too: neither the AppID nor its exe mapping.
    let world = appid_world(true);
    let found = world.classes();
    assert!(
        find(&found, &format!(r"{HKLM_CLASSES}\AppID\{CLS_A}")).is_none(),
        "{found:#?}"
    );
    assert!(find(&found, &format!(r"{HKLM_CLASSES}\AppID\app.exe")).is_none());
    // The class itself is still offered.
    assert_eq!(
        band(get(&found, &clsid_key(HKLM_CLASSES, CLS_A))),
        Band::Safe
    );
}

/// `TypeLib\{TLB}` with versions 1.0 and 2.0; 2.0's win64 file is `v2`.
fn typelib_world(v2: &str) -> World {
    let mut fx = machine();
    let key = format!(r"{HKLM_CLASSES}\TypeLib\{TLB}");
    sz(&mut fx, &format!(r"{key}\1.0"), "App 1.0 Type Library");
    sz(
        &mut fx,
        &format!(r"{key}\1.0\0\win32"),
        &app_file("app32.tlb"),
    );
    sz(&mut fx, &format!(r"{key}\1.0\FLAGS"), "0");
    sz(&mut fx, &format!(r"{key}\2.0\0\win64"), v2);
    let mut world = World::new(fx);
    world.fp.anchors.typelibs = vec![TLB.into()];
    world.ready(&[])
}

#[test]
fn typelib_version_level_and_whole_key_rule() {
    let key = format!(r"{HKLM_CLASSES}\TypeLib\{TLB}");
    let world = typelib_world(&app_file("app64.tlb"));
    let found = world.classes();
    assert_eq!(found.len(), 3, "{found:#?}");
    let whole = get(&found, &key);
    let v1 = get(&found, &format!(r"{key}\1.0"));
    let v2 = get(&found, &format!(r"{key}\2.0"));
    assert!(whole.children.contains(&v1.id) && whole.children.contains(&v2.id));
    for c in [whole, v1, v2] {
        assert_eq!(band(c), Band::Safe, "{}", key_of(c));
    }
    // A version whose file is another product's: that version stays, and so does the key.
    let world = typelib_world(&format!(r"{OTHER_ROOT}\other.dll"));
    let found = world.classes();
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(find(&found, &format!(r"{key}\1.0")).is_some());
    assert!(find(&found, &key).is_none());
}

/// The key-opening registry reads of one scan, and the candidates it returned.
fn reads(world: &World, scanner: &dyn Scanner) -> (u64, usize) {
    let meter = Meter::new();
    let reg = MeteredRegistry::new(&world.fixture, &meter);
    let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
    let found = scanner.scan(&world.ctx_with(&reg), &app);
    let snap = meter.snapshot();
    let opens = [Op::RegKeyInfo, Op::RegSubkeys, Op::RegValues, Op::RegValue]
        .iter()
        .map(|&op| snap.get(op).calls)
        .sum();
    (opens, found.len())
}

#[test]
fn budget_key_opens() {
    const N: usize = 8;
    let mut fx = machine();
    let mut clsids = Vec::new();
    for i in 0..N {
        let clsid = format!("{{A0A0A0A0-0000-4000-8000-{i:012X}}}");
        for root in [HKLM_CLASSES, HKLM_CLASSES32] {
            let key = clsid_key(root, &clsid);
            class(
                &mut fx,
                root,
                &clsid,
                "InprocServer32",
                &app_file(&format!("a{i}.dll")),
            );
            sz(&mut fx, &format!(r"{key}\ProgID"), "App.Thing");
            sz(&mut fx, &format!(r"{key}\Implemented Categories\{{x}}"), "");
        }
        let iid = format!("{{11111111-0000-4000-8000-{i:012X}}}");
        interface(&mut fx, HKLM_CLASSES, &iid, PROXY, Some(TLB));
        interface(&mut fx, HKLM_CLASSES32, &iid, PROXY, Some(TLB));
        clsids.push(clsid);
    }
    class(
        &mut fx,
        HKLM_CLASSES,
        PROXY,
        "InprocServer32",
        &app_file("proxy.dll"),
    );
    let tl = format!(r"{HKLM_CLASSES}\TypeLib\{TLB}");
    sz(&mut fx, &format!(r"{tl}\1.0\0\win32"), &app_file("app.tlb"));
    sz(&mut fx, &format!(r"{tl}\1.0\0\win64"), &app_file("app.tlb"));
    let mut world = World::new(fx);
    clsids.push(PROXY.into());
    world.fp.anchors.clsids = clsids;
    world.fp.anchors.typelibs = vec![TLB.into()];
    let world = world.ready(&[]);
    let anchors = (world.fp.anchors.clsids.len() + world.fp.anchors.typelibs.len()) as u64;
    let (opens, found) = reads(&world, &ComClass);
    assert!(found >= 2 * N, "{found}");
    assert!(
        opens <= 40 * anchors,
        "COM-CLASS: {opens} opens for {anchors} anchors"
    );
    // COM-INTERFACE: at most 6 per interface; the one proxy class and the one type library are read
    // once each, charged at COM-CLASS's budget.
    let (opens, found) = reads(&world, &ComInterface);
    assert_eq!(found, 2 * N);
    let budget = 6 * N as u64 + 40 * 2;
    assert!(
        opens <= budget,
        "COM-INTERFACE: {opens} opens for {N} interfaces (budget {budget})"
    );
    let all = world.interfaces();
    assert!(
        all.iter()
            .all(|c| matches!(&c.target, Target::RegKey { path } if path.contains(r"\Interface\")))
    );
}
