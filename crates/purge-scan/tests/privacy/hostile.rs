//! REG-PRIVACY: what must never be taken. Traces that name another program, a bare file name, a twin of
//! another installed app, and names decoded through somebody else's profile.

use purge_model::{Band, Blocker, ProgramId, View};
use purge_source::types::RegData;

use super::world::*;

/// Every store, one value named `name` (as each store spells it: `name` plus the MuiCache suffix, ROT13
/// for UserAssist).
fn plant_everywhere(fx: &mut purge_source::fixture::Fixture, sid: &str, path: &str) {
    sz(
        fx,
        &muicache(sid),
        &format!("{path}.FriendlyAppName"),
        "App",
    );
    sz(
        fx,
        &muicache(sid),
        &format!("{path}.ApplicationCompany"),
        "Vendor",
    );
    fx.set_value(&user_assist(sid, UA_EXE), &rot13(path), ua_counters());
    fx.set_value(&pca_store(sid), path, pca_blob());
    fx.set_value(&pca_persisted(sid), path, RegData::from_dword(1));
    sz(fx, &layers(sid), path, "~ HIGHDPIAWARE");
    for store in [
        "AppBadgeUpdated",
        "AppLaunch",
        "AppSwitched",
        "ShowJumpView",
    ] {
        fx.set_value(&feature_usage(sid, store), path, RegData::from_dword(2));
    }
}

/// The number of values [`plant_everywhere`] writes.
const PLANTED: usize = 10;

#[test]
fn bare_exe_name_never() {
    let mut fx = machine();
    for name in [
        "app.exe",
        "App",
        r"bin\helper.exe",
        r".\app.exe",
        r"\Program Files\App\app.exe",
    ] {
        plant_everywhere(&mut fx, SID, name);
        sz(&mut fx, HKLM_LAYERS, name, "~ RUNASADMIN");
    }
    // UNC and device spellings of the root are no drive path either.
    plant_everywhere(&mut fx, SID, r"\\server\share\App\app.exe");
    plant_everywhere(&mut fx, SID, r"\\?\C:\Program Files\App\app.exe");
    assert_none(&World::new(fx).privacy());
}

#[test]
fn userassist_other_app_same_exe_name_elsewhere_ignored() {
    let mut fx = machine();
    let count = user_assist(SID, UA_EXE);
    // Another product's program of the same file name, by known folder and by drive path; a sibling
    // folder whose name starts like the root; the same name in Windows' folder.
    for name in [
        format!(r"{PF_X64}\Other\app.exe"),
        other_file("app.exe"),
        r"C:\Program Files\App2\app.exe".to_owned(),
        r"C:\Program Files\App (old)\app.exe".to_owned(),
        // A spelling that walks out of the root.
        r"C:\Program Files\App\..\Other\app.exe".to_owned(),
        format!(r"{PF_X64}\App\..\Other\app.exe"),
        r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\app.exe".to_owned(),
    ] {
        fx.set_value(&count, &rot13(&name), ua_counters());
    }
    let world = World::new(fx);
    assert_none(&world.privacy());

    // The app's own entry next to them is still found: the test above is not empty by accident.
    let mut fx = world.fixture;
    let own = rot13(&format!(r"{PF_X64}\App\app.exe"));
    fx.set_value(&count, &own, ua_counters());
    let found = World::new(fx).privacy();
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_safe_trace(get(&found, &value_spot(&count, &own)));
}

/// The rig's `privacy-twins` trap (`vm/guest/m1b-traps.ps1`): MuiCache, PCA Store and Layers values
/// named by TrapA's program (the removed app) and the same for TrapB (installed, kept).
#[test]
fn trap_twin_values_of_trapb_untouched() {
    let mut fx = machine();
    let a = app_exe();
    let b = other_file("other.exe");
    for p in [&a, &b] {
        sz(
            &mut fx,
            &muicache(SID),
            &format!("{p}.FriendlyAppName"),
            "PurgeTrap",
        );
        sz(
            &mut fx,
            &muicache(SID),
            &format!("{p}.ApplicationCompany"),
            "PurgeTrap",
        );
        fx.set_value(&pca_store(SID), p, pca_blob());
        sz(&mut fx, &layers(SID), p, "~ HIGHDPIAWARE");
    }
    let found = World::new(fx).privacy();
    assert_eq!(found.len(), 4, "{found:#?}");
    for c in &found {
        assert!(spot(c).contains(&a), "{}", spot(c));
        assert_safe_trace(c);
    }
    assert!(
        found
            .iter()
            .all(|c| !spot(c).to_lowercase().contains(&b.to_lowercase()))
    );
}

/// TrapB installed inside the removed app's folder: its traces lie inside the app's root, and its root
/// blocks them.
#[test]
fn twin_inside_the_root_is_blocked() {
    let nested = app_file(r"plugins\Other");
    let mut fx = machine();
    fx.add_dir(ROOT);
    fx.add_dir(&format!(r"{ROOT}\plugins"));
    fx.add_dir(&nested);
    fx.add_file(&format!(r"{nested}\other.exe"), 10);
    plant_everywhere(&mut fx, SID, &format!(r"{nested}\other.exe"));
    let mut world = World::new(fx);
    world.other_apps =
        purge_scan::framework::OtherApps::new(vec![purge_scan::framework::OtherApp {
            name: OTHER.into(),
            roots: vec![nested.clone()],
            ..Default::default()
        }]);
    let found = world.privacy();
    assert_eq!(found.len(), PLANTED, "{found:#?}");
    for c in &found {
        assert!(
            c.blockers
                .iter()
                .any(|b| matches!(b, Blocker::InsideOtherApp { .. })),
            "{c:#?}"
        );
        assert_eq!(band(c), Band::Blocked, "{}", spot(c));
    }
}

/// Another user's hive: a name that becomes a path only through a profile (the environment, a per-user
/// known folder) would be decoded with the interactive user's profile, not that user's, and is left
/// alone. Plain drive paths are that user's traces of the app and are offered.
#[test]
fn foreign_hive_profile_paths_not_decoded() {
    // The app lives in the interactive user's `%LOCALAPPDATA%\Programs\App`.
    let local_root = r"C:\Users\tester\AppData\Local\Programs\App";
    let mut fx = machine();
    fx.add_key(&format!(r"HKU\{SID2}\Software"));
    fx.add_key(&format!(r"HKU\{SID2}_Classes"));
    fx.add_dir(r"C:\Users\tester\AppData\Local\Programs");
    for sid in [SID, SID2] {
        fx.set_value(
            &user_assist(sid, UA_EXE),
            &rot13(&format!(r"{LOCAL_APPDATA}\Programs\App\app.exe")),
            ua_counters(),
        );
        sz(
            &mut fx,
            &muicache(sid),
            r"%LOCALAPPDATA%\Programs\App\app.exe.FriendlyAppName",
            "App",
        );
        fx.set_value(
            &pca_store(sid),
            &format!(r"{local_root}\app.exe"),
            pca_blob(),
        );
    }
    let mut world = World::new(fx);
    world.fp.roots[0].path = local_root.into();
    world.fp.exes = vec![purge_model::ExeFile {
        path: format!(r"{local_root}\app.exe"),
        main: true,
    }];
    let found = world.ready().privacy();
    let spots: Vec<String> = found.iter().map(spot).collect();
    assert_eq!(found.len(), 4, "{spots:#?}");
    // All three of the interactive user's.
    assert_eq!(
        found
            .iter()
            .filter(|c| spot(c).contains(&format!(r"HKU\{SID}")))
            .count(),
        3,
        "{spots:#?}"
    );
    // Of the other user's only the plain drive path.
    let theirs: Vec<&String> = spots.iter().filter(|s| s.contains(SID2)).collect();
    assert_eq!(
        theirs,
        vec![&value_spot(
            &pca_store(SID2),
            &format!(r"{local_root}\app.exe")
        )]
    );
}

/// A per-user app: only its own user's hive is read; another user's traces of the same path are of that
/// user's own install.
#[test]
fn per_user_app_other_hives_untouched() {
    let mut fx = machine();
    fx.add_key(&format!(r"HKU\{SID2}\Software"));
    fx.add_key(&format!(r"HKU\{SID2}_Classes"));
    plant_everywhere(&mut fx, SID, &app_exe());
    plant_everywhere(&mut fx, SID2, &app_exe());
    let mut world = World::new(fx);
    world.fp.app.program_id = ProgramId::user(SID, View::K64, "App").unwrap();
    let found = world.ready().privacy();
    assert_eq!(found.len(), PLANTED, "{found:#?}");
    assert!(found.iter().all(|c| !spot(c).contains(SID2)));

    // The same machine with a machine-wide app: both users' traces.
    let mut fx = machine();
    fx.add_key(&format!(r"HKU\{SID2}\Software"));
    fx.add_key(&format!(r"HKU\{SID2}_Classes"));
    plant_everywhere(&mut fx, SID, &app_exe());
    plant_everywhere(&mut fx, SID2, &app_exe());
    let found = World::new(fx).privacy();
    assert_eq!(found.len(), 2 * PLANTED, "{found:#?}");
}

/// Service accounts and `.DEFAULT` are not users whose traces are read.
#[test]
fn service_hives_untouched() {
    let mut fx = machine();
    for sid in ["S-1-5-18", "S-1-5-19", ".DEFAULT"] {
        fx.add_key(&format!(r"HKU\{sid}\Software"));
        plant_everywhere(&mut fx, sid, &app_exe());
    }
    assert_none(&World::new(fx).privacy());
}
