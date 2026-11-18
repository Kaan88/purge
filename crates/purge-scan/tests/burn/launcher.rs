//! SYS-BURNDEPS rule (c) for a package without a provider record: the Python Launcher of the real
//! CPython bundles ([`World::python`]). The bundles write only their own dependency record, so the
//! harvest links the Launcher through the kb entry `python-launcher` (`fp.burn.linked`), and the scan
//! suggests it only when it is known that no CPython bundle is left.

use purge_guard::canon::ProfileEnv;
use purge_model::{Action, Band, Candidate, Category, Target, VerifyGone};
use purge_scan::sys_burndeps::{SUGGEST_UNINSTALL, SysBurnDeps as Scanner};
use purge_source::metered::{Meter, MeteredRegistry, Op};

use crate::world::*;

fn run(w: &World) -> Vec<Candidate> {
    w.run(&Scanner)
}

fn launcher_arp() -> Target {
    key(format!(r"{UNINSTALL_32}\{LAUNCHER}"))
}

fn suggestions(found: &[Candidate]) -> Vec<&Candidate> {
    found
        .iter()
        .filter(|c| c.action == Action::ReportOnly)
        .collect()
}

fn detail<'c>(c: &'c Candidate, key: &str) -> Option<&'c str> {
    c.evidence.iter().find_map(|e| e.detail.get(key))
}

/// A dependency record `<root>\<provider>\Dependents\<dependent>`.
fn record(root: &str, provider: &str, dependent: &str) -> String {
    format!(r"{root}\{provider}\Dependents\{dependent}")
}

/// Python 3.12.7 alone, uninstalled (gate K8 "python"): the Launcher is suggested, report-only.
#[test]
fn related_product_suggested_when_orphaned_without_provider_record() {
    let w = World::python();
    assert!(
        w.fp.burn.as_ref().unwrap().packages.is_empty(),
        "the real shape"
    );
    let found = run(&w);
    // Nothing else: the bundle's own provider key went with it, and it has no package record.
    assert_eq!(found.len(), 1, "{found:?}");
    let c = &found[0];
    assert_eq!(c.target, launcher_arp());
    assert_eq!(c.action, Action::ReportOnly);
    assert_eq!(c.category, Category::Registration);
    assert_eq!(detail(c, SUGGEST_UNINSTALL), Some("Python Launcher"));
    assert_eq!(detail(c, "component"), Some("python-launcher"));
    assert_eq!(detail(c, "product"), Some(LAUNCHER));
    let (band, preselected) = band(c);
    assert_ne!(band, Band::Safe);
    assert!(!preselected);

    // A record of this bundle that its uninstall left in its own hive is not another Python.
    let mut w = World::python();
    w.fixture
        .add_key(&record(&user_deps(), PY_PROVIDER, PY_BUNDLE));
    w.reindex();
    let found = run(&w);
    assert_eq!(suggestions(&found).len(), 1, "{found:?}");
    assert_eq!(suggestions(&found)[0].target, launcher_arp());
}

/// Python 3.12.7 removed while 3.13.17 is installed (gate K8 "python312-with-313"), and the other
/// ways another CPython bundle can still be registered: no suggestion.
#[test]
fn related_product_not_suggested_when_another_cpython_bundle_remains() {
    let cases: Vec<(&str, String)> = vec![
        // 3.13 registered in the same user's Classes, as on the VM.
        (
            "another version, same user",
            record(&user_deps(), PY313_PROVIDER, PY313_BUNDLE),
        ),
        // A machine-wide CPython bundle.
        (
            "another version, machine",
            record(
                DEPS,
                "CPython-3.11",
                "{11111111-2222-3333-4444-555555555555}",
            ),
        ),
        // The same bundle installed again elsewhere: its record in the machine's Classes is not this
        // per-user bundle's own.
        (
            "the same bundle in another hive",
            record(DEPS, PY_PROVIDER, PY_BUNDLE),
        ),
        // Another bundle depends on this bundle's provider key.
        (
            "another dependent of the own provider key",
            record(&user_deps(), PY_PROVIDER, PY313_BUNDLE),
        ),
        // The own provider key without any dependent: nobody can tell whose it is.
        (
            "the own provider key without dependents",
            format!(r"{}\{PY_PROVIDER}\Dependents", user_deps()),
        ),
        // Case and spelling of the family do not matter.
        (
            "lower case",
            record(&user_deps(), "cpython-3.13", PY313_BUNDLE),
        ),
    ];
    for (what, planted) in cases {
        let mut w = World::python();
        w.fixture.add_key(&planted);
        w.reindex();
        let found = run(&w);
        assert!(suggestions(&found).is_empty(), "{what}: {found:?}");
    }

    // Uninstalling 3.13.17 while 3.12.7 stays (gate "python313-with-312"): the 3.13 Launcher is kept.
    const LAUNCHER_313: &str = "{8078A005-EBA5-4E1A-9AAF-EC4693A1D7C3}";
    let mut w = World::python();
    {
        let burn = w.burn_mut();
        burn.bundle_id = PY313_BUNDLE.into();
        burn.provider_key = Some(PY313_PROVIDER.into());
        burn.linked[0].product_code = LAUNCHER_313.into();
        burn.linked[0].cache_dir = format!(r"{CACHE}\{LAUNCHER_313}v3.13.17150.0");
    }
    w.fixture.set_msi_state(
        LAUNCHER_313,
        purge_model::MsiContext::Machine,
        purge_source::types::MsiProductState::Default,
    );
    w.other_apps = purge_scan::framework::OtherApps::new(vec![purge_scan::framework::OtherApp {
        name: "Python Launcher".into(),
        keys: vec![format!(r"{UNINSTALL_32}\{LAUNCHER_313}")],
        ..Default::default()
    }]);
    w.fixture
        .add_key(&record(&user_deps(), PY_PROVIDER, PY_BUNDLE));
    w.reindex();
    assert!(suggestions(&run(&w)).is_empty());
    // Without 3.12 the same fingerprint gets its suggestion: the case above is decided by 3.12 alone.
    let mut w2 = World::python();
    w2.fp = w.fp.clone();
    w2.fixture.set_msi_state(
        LAUNCHER_313,
        purge_model::MsiContext::Machine,
        purge_source::types::MsiProductState::Default,
    );
    w2.other_apps = w.other_apps.clone();
    w2.reindex();
    let found = run(&w2);
    assert_eq!(suggestions(&found).len(), 1, "{found:?}");
}

/// Whatever is not known gives no suggestion.
#[test]
fn related_product_not_suggested_on_unreadable_state() {
    // The user's dependency records cannot be read: the index's Burn area is incomplete.
    let mut w = World::python();
    w.fixture.add_denied(&user_deps());
    w.reindex();
    assert!(suggestions(&run(&w)).is_empty());
    assert!(
        !w.ext
            .ownership
            .stats()
            .complete(purge_index::ownership::area::BURN),
        "the index knows it is incomplete"
    );

    // Another profile's hive is not loaded: a CPython bundle of that user would be in it.
    let mut w = World::python();
    w.guard.profiles.push(ProfileEnv {
        sid: "S-1-5-21-1004336348-1177238915-682003330-1002".into(),
        root: r"C:\Users\other".into(),
        appdata: r"C:\Users\other\AppData\Roaming".into(),
        local_appdata: r"C:\Users\other\AppData\Local".into(),
        known_folders: Vec::new(),
        user_content_folders: Vec::new(),
    });
    assert!(suggestions(&run(&w)).is_empty());

    // The machine's profiles are not known.
    let mut w = World::python();
    w.guard.profiles.clear();
    assert!(suggestions(&run(&w)).is_empty());

    // Windows Installer's product list cannot be read (and the index lists no product): not installed
    // is not proven, but installed is not either.
    let mut w = World::python();
    w.fixture.set_msi_products(None);
    assert!(suggestions(&run(&w)).is_empty());

    // The Launcher is gone after all.
    let mut w = World::python();
    w.fixture.set_msi_products(Some(Vec::new()));
    assert!(suggestions(&run(&w)).is_empty());

    // The fresh inventory has no Uninstall key for it.
    let mut w = World::python();
    w.other_apps = purge_scan::framework::OtherApps::new(Vec::new());
    assert!(suggestions(&run(&w)).is_empty());

    // A linked component the kb does not know (or no longer links).
    let mut w = World::python();
    w.burn_mut().linked[0].component = "no-such-component".into();
    assert!(suggestions(&run(&w)).is_empty());
    let mut w = World::python();
    w.burn_mut().linked[0].component = "vcredist".into();
    assert!(suggestions(&run(&w)).is_empty());

    // The bundle is not gone.
    let mut w = World::python();
    w.verify_gone = Some(VerifyGone::new(false, true, true));
    assert!(run(&w).is_empty());
}

/// The linked rule opens no key: the index and the inventory answer it.
#[test]
fn linked_suggestion_budget() {
    let w = World::python();
    let meter = Meter::new();
    let reg = MeteredRegistry::new(&w.fixture, &meter);
    let ctx = purge_scan::framework::ScanCtx {
        reg: &reg,
        ..w.ctx()
    };
    let app = purge_scan::framework::AppIdentityView::from_fingerprint(&w.fp, &w.env);
    assert_eq!(ctx.run(&Scanner, &app).len(), 1);
    let calls = meter.snapshot();
    let opens: u64 = [Op::RegKeyInfo, Op::RegSubkeys, Op::RegValues, Op::RegValue]
        .iter()
        .map(|op| calls.get(*op).calls)
        .sum();
    assert!(opens <= 8, "{opens}: {}", calls.summary());
}
