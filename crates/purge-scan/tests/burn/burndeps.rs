//! SYS-BURNDEPS.

use purge_model::{
    Action, Band, Candidate, Category, EvidenceKind, ManifestKind, MsiContext, Scope, Target, Tier,
    VerifyGone,
};
use purge_scan::framework::OtherApp;
use purge_scan::fs_pkgcache::FsPkgCache;
use purge_scan::sys_burndeps::{SUGGEST_UNINSTALL, SysBurnDeps as Scanner};
use purge_source::metered::{Meter, MeteredFileSystem, MeteredRegistry, MeteredSystem, Op};
use purge_source::types::MsiProductState;

use crate::world::*;

fn run(w: &World) -> Vec<Candidate> {
    w.run(&Scanner)
}

fn dependents_entry(provider: &str) -> Target {
    key(format!(r"{DEPS}\{provider}\Dependents\{BUNDLE}"))
}

fn has_burn_manifest(c: &Candidate, scope: Scope) -> bool {
    c.evidence.iter().any(|e| {
        e.kind == EvidenceKind::InstallerManifest(ManifestKind::Burn)
            && e.tier == Tier::A
            && e.scope == scope
    })
}

/// The ReportOnly suggestions, by their target.
fn suggestions(found: &[Candidate]) -> Vec<&Candidate> {
    found
        .iter()
        .filter(|c| c.action == Action::ReportOnly)
        .collect()
}

fn suggested_name(c: &Candidate) -> Option<&str> {
    c.evidence
        .iter()
        .find_map(|e| e.detail.get(SUGGEST_UNINSTALL))
}

// ---------------------------------------------------------------------------------------------------------
// (a) The bundle's own dependents entries
// ---------------------------------------------------------------------------------------------------------

#[test]
fn dependents_entry_of_gone_bundle_safe() {
    let w = World::new();
    let found = run(&w);
    let c = find(&found, &dependents_entry("AppBundle_Core")).expect("the Core entry");
    assert_eq!(c.action, Action::DeleteKey);
    assert_eq!(c.category, Category::Registration);
    assert_eq!(c.scanner, "SYS-BURNDEPS");
    assert!(has_burn_manifest(c, Scope::Key), "{:?}", c.evidence);
    assert!(c.blockers.is_empty(), "{:?}", c.blockers);
    assert_eq!(band(c), (Band::Safe, true));

    // The entry is offered under every recorded package's provider key, whatever the package's state:
    // the bundle is gone, so its own registration is a leftover.
    for provider in [LAUNCHER, VC_PROVIDER, TRAP_PROVIDER] {
        let c = find(&found, &dependents_entry(provider))
            .unwrap_or_else(|| panic!("the entry under {provider}"));
        assert_eq!(band(c), (Band::Safe, true), "{provider}");
    }
    // Never the entries of another bundle, and never a provider the harvest did not record.
    assert!(
        found
            .iter()
            .all(|c| !format!("{:?}", c.target).contains(OTHER_BUNDLE))
    );
    assert!(
        found
            .iter()
            .all(|c| !format!("{:?}", c.target).contains("Unrelated.Provider"))
    );
}

#[test]
fn bundle_not_gone_nothing() {
    // No observed uninstall.
    let mut w = World::new();
    w.verify_gone = None;
    assert!(run(&w).is_empty());
    assert!(w.run(&FsPkgCache).is_empty());

    // The ARP entry is still there.
    let mut w = World::new();
    w.verify_gone = Some(VerifyGone::new(false, true, true));
    assert!(run(&w).is_empty());
    assert!(w.run(&FsPkgCache).is_empty());

    // The ARP entry went, but the fresh inventory has the bundle under another key (a per-user
    // registration of the same bundle id).
    let mut w = World::new();
    let mut apps = other_apps();
    apps.push(OtherApp {
        name: "App Bundle".into(),
        keys: vec![format!(
            r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Uninstall\{}",
            BUNDLE.to_lowercase()
        )],
        ..OtherApp::default()
    });
    w.other_apps = purge_scan::framework::OtherApps::new(apps);
    assert!(run(&w).is_empty());
    assert!(w.run(&FsPkgCache).is_empty());

    // No bundle in the fingerprint.
    let mut w = World::new();
    w.fp.burn = None;
    assert!(run(&w).is_empty());
}

// ---------------------------------------------------------------------------------------------------------
// (b) Provider keys
// ---------------------------------------------------------------------------------------------------------

#[test]
fn provider_key_only_when_no_dependents_left_and_product_gone() {
    let w = World::new();
    let found = run(&w);
    // Core: product gone, nothing but the bundle depends on it.
    let core = find(&found, &key(format!(r"{DEPS}\AppBundle_Core"))).expect("the Core provider");
    assert_eq!(core.action, Action::DeleteKey);
    assert!(has_burn_manifest(core, Scope::Key));
    assert_eq!(band(core), (Band::Safe, true));
    // The bundle's own provider key: nothing depends on the bundle.
    let own = find(&found, &key(format!(r"{DEPS}\{BUNDLE_PROVIDER}"))).expect("the bundle's key");
    assert_eq!(band(own), (Band::Safe, true));
    // Installed products keep their provider keys.
    for provider in [LAUNCHER, VC_PROVIDER] {
        assert!(find(&found, &key(format!(r"{DEPS}\{provider}"))).is_none());
    }

    // The product is still known to Windows Installer: the provider key stays.
    let mut w = World::new();
    w.fixture
        .set_msi_state(CORE, MsiContext::Machine, MsiProductState::Default);
    let found = run(&w);
    assert!(find(&found, &key(format!(r"{DEPS}\AppBundle_Core"))).is_none());
    assert!(find(&found, &dependents_entry("AppBundle_Core")).is_some());

    // The product state cannot be read: not gone.
    let mut w = World::new();
    w.fixture.set_msi_products(None);
    let found = run(&w);
    assert!(find(&found, &key(format!(r"{DEPS}\AppBundle_Core"))).is_none());

    // Another dependent turned up: the provider key stays, the bundle's entry goes.
    let mut w = World::new();
    w.fixture.add_key(&format!(
        r"{DEPS}\AppBundle_Core\Dependents\{{12345678-0000-0000-0000-000000000000}}"
    ));
    w.reindex();
    let found = run(&w);
    assert!(find(&found, &key(format!(r"{DEPS}\AppBundle_Core"))).is_none());
    assert!(find(&found, &dependents_entry("AppBundle_Core")).is_some());

    // A subkey other than Dependents: the key holds something this scanner cannot account for.
    let mut w = World::new();
    w.fixture.add_key(&format!(r"{DEPS}\AppBundle_Core\Extra"));
    w.reindex();
    assert!(find(&run(&w), &key(format!(r"{DEPS}\AppBundle_Core"))).is_none());

    // A bundle that depends on this bundle keeps the bundle's provider key.
    let mut w = World::new();
    w.fixture.add_key(&format!(
        r"{DEPS}\{BUNDLE_PROVIDER}\Dependents\{OTHER_BUNDLE}"
    ));
    w.reindex();
    assert!(find(&run(&w), &key(format!(r"{DEPS}\{BUNDLE_PROVIDER}"))).is_none());
}

/// Hostile (trap `burn-shared-package`): another bundle registered a dependency on the package after
/// the harvest, so the fingerprint says "no other dependent". The provider key and its other entry stay;
/// only this bundle's entry is offered.
#[test]
fn provider_key_kept_when_other_bundle_depends() {
    let w = World::new();
    assert!(
        w.fp.burn.as_ref().unwrap().packages[3]
            .other_dependents
            .is_empty(),
        "the harvest saw no other dependent"
    );
    let found = run(&w);
    let entry = find(&found, &dependents_entry(TRAP_PROVIDER)).expect("the bundle's own entry");
    assert_eq!(band(entry), (Band::Safe, true));
    assert!(find(&found, &key(format!(r"{DEPS}\{TRAP_PROVIDER}"))).is_none());
    assert!(
        find(
            &found,
            &key(format!(r"{DEPS}\{TRAP_PROVIDER}\Dependents\{OTHER_BUNDLE}"))
        )
        .is_none()
    );
    assert!(
        find(&found, &key(format!(r"{DEPS}\{TRAP_PROVIDER}\Dependents"))).is_none(),
        "never the Dependents key itself"
    );
    // Its cache directory stays too.
    let cached = w.run(&FsPkgCache);
    assert!(find(&cached, &dir(format!(r"{CACHE}\{TRAP_PROVIDER}"))).is_none());

    // Without the ownership index's merged view (each root is still read directly) the answer is the
    // same for the provider key.
    let mut w = World::new();
    w.ext = purge_scan::framework::ScanExt::new(Default::default(), Default::default());
    assert!(find(&run(&w), &key(format!(r"{DEPS}\{TRAP_PROVIDER}"))).is_none());
}

#[test]
fn provider_in_hku_classes_found() {
    let w = World::new();
    let found = run(&w);
    let deps = user_deps();
    let entry = find(
        &found,
        &key(format!(r"{deps}\{USER_PROVIDER}\Dependents\{BUNDLE}")),
    )
    .expect("the user's entry");
    assert!(has_burn_manifest(entry, Scope::Key));
    let provider =
        find(&found, &key(format!(r"{deps}\{USER_PROVIDER}"))).expect("the user's provider key");
    assert_eq!(provider.action, Action::DeleteKey);
    // Nothing of the user's package is looked for in the machine's Classes, and nothing invented there.
    assert!(find(&found, &key(format!(r"{DEPS}\{USER_PROVIDER}"))).is_none());
}

#[test]
fn unreadable_root_offers_no_provider_key() {
    // The user's dependencies cannot be read: the dependents of every provider are unknown, so no
    // provider key and no suggestion is offered; the machine's entries still are.
    let mut w = World::new();
    w.fixture.add_denied(&user_deps());
    let found = run(&w);
    assert!(find(&found, &dependents_entry("AppBundle_Core")).is_some());
    assert!(find(&found, &key(format!(r"{DEPS}\AppBundle_Core"))).is_none());
    assert!(suggestions(&found).is_empty());
}

// ---------------------------------------------------------------------------------------------------------
// (c) Related products
// ---------------------------------------------------------------------------------------------------------

/// The Python Launcher after the last Python: installed, kept by nothing but the removed bundle.
#[test]
fn related_product_suggested_when_orphaned() {
    let w = World::new();
    let found = run(&w);
    let all = suggestions(&found);
    assert_eq!(all.len(), 1, "{all:?}");
    let c = all[0];
    assert_eq!(c.target, key(format!(r"{UNINSTALL}\{LAUNCHER}")));
    assert_eq!(suggested_name(c), Some("Python Launcher"));
    assert_eq!(c.category, Category::Registration);
}

/// Python 3.12 removed while 3.13 is installed: the Launcher is kept by 3.13.
#[test]
fn related_product_not_suggested_when_other_dependent() {
    let mut w = World::new();
    w.fixture
        .add_key(&format!(r"{DEPS}\{LAUNCHER}\Dependents\{OTHER_BUNDLE}"));
    w.reindex();
    let found = run(&w);
    assert!(suggestions(&found).is_empty(), "{found:?}");
    // The bundle's own entry under it still goes.
    assert!(find(&found, &dependents_entry(LAUNCHER)).is_some());
    assert!(find(&found, &key(format!(r"{DEPS}\{LAUNCHER}"))).is_none());

    // The same when the harvest already saw the other dependent and it is only in the user's Classes.
    let mut w = World::new();
    w.fixture.add_key(&format!(
        r"{}\{LAUNCHER}\Dependents\{OTHER_BUNDLE}",
        user_deps()
    ));
    w.reindex();
    assert!(suggestions(&run(&w)).is_empty());
}

/// The VC++ runtime is a shared component: never suggested, even when nothing else keeps it.
#[test]
fn related_product_protected_component_not_suggested() {
    let w = World::new();
    let found = run(&w);
    assert!(
        found
            .iter()
            .all(|c| !format!("{:?}", c.target).contains(VC)),
        "{found:?}"
    );
    assert!(find(&found, &dependents_entry(VC_PROVIDER)).is_some());
    assert!(find(&found, &key(format!(r"{DEPS}\{VC_PROVIDER}"))).is_none());
}

#[test]
fn suggestion_is_report_only() {
    let w = World::new();
    let found = run(&w);
    let arp = key(format!(r"{UNINSTALL}\{LAUNCHER}"));
    let on_arp: Vec<&Candidate> = found.iter().filter(|c| c.target == arp).collect();
    assert_eq!(on_arp.len(), 1);
    let c = on_arp[0];
    assert_eq!(c.action, Action::ReportOnly);
    let (band, preselected) = band(c);
    assert_ne!(band, Band::Safe);
    assert!(!preselected);
    // Nothing of this scanner deletes anything outside the dependency records.
    for c in &found {
        if c.action != Action::ReportOnly {
            let Target::RegKey { path } = &c.target else {
                panic!("only keys: {c:?}");
            };
            let lower = path.to_lowercase();
            assert!(
                lower.contains(r"\installer\dependencies\"),
                "outside the dependency records: {path}"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// Budget
// ---------------------------------------------------------------------------------------------------------

/// SYS-BURNDEPS opens at most 8 keys per recorded provider key beyond what ScanExt holds (budgets).
#[test]
fn budget_key_opens() {
    let w = World::new();
    let providers = {
        let burn = w.fp.burn.as_ref().unwrap();
        burn.packages.len() + usize::from(burn.provider_key.is_some())
    };
    let meter = Meter::new();
    let reg = MeteredRegistry::new(&w.fixture, &meter);
    let fs = MeteredFileSystem::new(&w.fixture, &meter);
    let sys = MeteredSystem::new(&w.fixture, &meter);
    let ctx = purge_scan::framework::ScanCtx {
        reg: &reg,
        fs: &fs,
        sys: &sys,
        ..w.ctx()
    };
    let app = purge_scan::framework::AppIdentityView::from_fingerprint(&w.fp, &w.env);
    let out = ctx.run(&Scanner, &app);
    assert!(out.len() > providers, "{out:?}");
    let calls = meter.snapshot();
    let opens: u64 = [Op::RegKeyInfo, Op::RegSubkeys, Op::RegValues, Op::RegValue]
        .iter()
        .map(|op| calls.get(*op).calls)
        .sum();
    assert!(
        opens <= 8 * providers as u64,
        "{opens} opens for {providers} providers: {}",
        calls.summary()
    );
    assert_eq!(calls.get(Op::RegValues).calls, 0, "{}", calls.summary());
    assert_eq!(calls.get(Op::FsListDir).calls, 0, "{}", calls.summary());

    // One provider alone stays within 8 as well.
    let mut w = World::new();
    {
        let burn = w.burn_mut();
        burn.provider_key = None;
        burn.packages.truncate(1);
    }
    let meter = Meter::new();
    let reg = MeteredRegistry::new(&w.fixture, &meter);
    let ctx = purge_scan::framework::ScanCtx {
        reg: &reg,
        ..w.ctx()
    };
    let app = purge_scan::framework::AppIdentityView::from_fingerprint(&w.fp, &w.env);
    assert!(!ctx.run(&Scanner, &app).is_empty());
    let calls = meter.snapshot();
    let opens: u64 = [Op::RegKeyInfo, Op::RegSubkeys, Op::RegValues, Op::RegValue]
        .iter()
        .map(|op| calls.get(*op).calls)
        .sum();
    assert!(opens <= 8, "{opens}: {}", calls.summary());
}
