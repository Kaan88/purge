//! REG-PRIVACY: the path-keyed stores (MuiCache, UserAssist, PCA, AppCompat layers, FeatureUsage).

use purge_model::{Band, Category, EvidenceKind, Tier};
use purge_source::types::RegData;

use super::world::*;

#[test]
fn muicache_friendlyappname_and_company_values() {
    let mut fx = machine();
    let mui = muicache(SID);
    let exe = app_exe();
    sz(&mut fx, &mui, &format!("{exe}.FriendlyAppName"), "App");
    sz(
        &mut fx,
        &mui,
        &format!("{exe}.ApplicationCompany"),
        "Vendor",
    );
    // The helper's name in another letter case: the suffix is matched ignoring case.
    sz(
        &mut fx,
        &mui,
        &format!(r"{}.friendlyappname", app_file(r"BIN\Helper.exe")),
        "Helper",
    );
    let found = World::new(fx).privacy();
    assert_eq!(found.len(), 3, "{found:#?}");
    for name in [
        format!("{exe}.FriendlyAppName"),
        format!("{exe}.ApplicationCompany"),
        format!(r"{}.friendlyappname", app_file(r"BIN\Helper.exe")),
    ] {
        assert_safe_trace(get(&found, &value_spot(&mui, &name)));
    }
}

#[test]
fn muicache_resource_reference_ignored() {
    let mut fx = machine();
    let mui = muicache(SID);
    let exe = app_exe();
    // Resource references, even into the app's own files, and values that name no path.
    sz(&mut fx, &mui, &format!("@{exe},-101"), "App");
    sz(
        &mut fx,
        &mui,
        &format!("@{exe},-101.FriendlyAppName"),
        "App",
    );
    sz(
        &mut fx,
        &mui,
        r"@%SystemRoot%\system32\shell32.dll,-22000",
        "Shell",
    );
    sz(&mut fx, &mui, "LangID", "0409");
    // The exe path itself, without a MuiCache suffix.
    sz(&mut fx, &mui, &exe, "App");
    assert_none(&World::new(fx).privacy());
}

#[test]
fn muicache_both_classes_spellings_one_candidate() {
    let name = format!("{}.FriendlyAppName", app_exe());
    // A capture that holds the key under both spellings of the user's Classes: one candidate, on the
    // Classes hive's own spelling.
    let mut fx = machine();
    sz(&mut fx, &muicache(SID), &name, "App");
    sz(&mut fx, &muicache_alias(SID), &name, "App");
    let found = World::new(fx).privacy();
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_safe_trace(get(&found, &value_spot(&muicache(SID), &name)));

    // A capture that holds only the `Software\Classes` spelling: the same value, found there.
    let mut fx = machine();
    sz(&mut fx, &muicache_alias(SID), &name, "App");
    let found = World::new(fx).privacy();
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_safe_trace(get(&found, &value_spot(&muicache_alias(SID), &name)));
}

#[test]
fn userassist_rot13_known_folder_path_safe() {
    let mut fx = machine();
    let count = user_assist(SID, UA_EXE);
    // `{FOLDERID_ProgramFilesX64}\App\app.exe` and a plain drive path, both ROT13.
    let by_folder = rot13(&format!(r"{PF_X64}\App\app.exe"));
    let plain = rot13(&app_file(r"bin\helper.exe"));
    fx.set_value(&count, &by_folder, ua_counters());
    fx.set_value(&count, &plain, ua_counters());
    let found = World::new(fx).privacy();
    assert_eq!(found.len(), 2, "{found:#?}");
    assert_safe_trace(get(&found, &value_spot(&count, &by_folder)));
    assert_safe_trace(get(&found, &value_spot(&count, &plain)));
}

#[test]
fn userassist_counter_and_aumid_names_ignored() {
    let mut fx = machine();
    let count = user_assist(SID, UA_EXE);
    let lnk = user_assist(SID, UA_LNK);
    for name in [
        "UEME_CTLSESSION",
        "UEME_CTLCUACount:ctor",
        "Microsoft.Windows.Explorer",
        "Microsoft.WindowsTerminal_8wekyb3d8bbwe!App",
        // The app's own name, an AUMID-like id of it, and a GUID that is no known folder.
        "App",
        "Vendor.App",
        r"{00000000-0000-0000-0000-000000000000}\App\app.exe",
        // Windows' own program through a known folder.
        r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe",
    ] {
        fx.set_value(&count, &rot13(name), ua_counters());
        fx.set_value(&lnk, &rot13(name), ua_counters());
    }
    // A name stored without ROT13 is not decoded into the app's path.
    fx.set_value(&count, &app_exe(), ua_counters());
    let mut world = World::new(fx);
    world.fp.anchors.aumids = vec!["Vendor.App".into()];
    assert_none(&world.privacy());
}

#[test]
fn pca_store_and_persisted() {
    let mut fx = machine();
    let store = pca_store(SID);
    let persisted = pca_persisted(SID);
    let exe = app_exe();
    fx.set_value(&store, &exe, pca_blob());
    fx.set_value(&persisted, &exe, RegData::from_dword(1));
    // PCA's other name forms are not paths.
    fx.set_value(&store, "SIGN.MEDIA=1A2B3C setup.exe", pca_blob());
    let found = World::new(fx).privacy();
    assert_eq!(found.len(), 2, "{found:#?}");
    assert_safe_trace(get(&found, &value_spot(&store, &exe)));
    assert_safe_trace(get(&found, &value_spot(&persisted, &exe)));
}

#[test]
fn layers_hklm_likely_appdata() {
    let mut fx = machine();
    let exe = app_exe();
    sz(&mut fx, HKLM_LAYERS, &exe, "~ RUNASADMIN");
    sz(&mut fx, &layers(SID), &exe, "~ HIGHDPIAWARE");
    let found = World::new(fx).privacy();
    assert_eq!(found.len(), 2, "{found:#?}");

    // The machine's value is a setting: AppData, Tier B, at most Likely, whatever the evidence.
    let machine = get(&found, &value_spot(HKLM_LAYERS, &exe));
    assert_eq!(machine.category, Category::AppData);
    assert!(has(machine, EvidenceKind::PointsIntoInstallRoot, Tier::B));
    assert!(has(machine, EvidenceKind::DanglingRef, Tier::B));
    assert!(
        machine
            .evidence
            .iter()
            .all(|e| e.weight <= 0 || e.tier != Tier::A),
        "{machine:#?}"
    );
    assert_eq!(band(machine), Band::Likely);

    // The user's own choice for the gone program is a trace.
    assert_safe_trace(get(&found, &value_spot(&layers(SID), &exe)));
}

#[test]
fn feature_usage_path_form_only() {
    let mut fx = machine();
    let exe = app_exe();
    for store in [
        "AppBadgeUpdated",
        "AppLaunch",
        "AppSwitched",
        "ShowJumpView",
    ] {
        let key = feature_usage(SID, store);
        fx.set_value(&key, &exe, RegData::from_dword(4));
        // AUMIDs, the app's own among them, are never matched here.
        fx.set_value(&key, "Vendor.App", RegData::from_dword(4));
        fx.set_value(&key, "Microsoft.Windows.Explorer", RegData::from_dword(9));
    }
    // A store of FeatureUsage that is not one of the four is not read.
    fx.set_value(
        &feature_usage(SID, "TrayButtonClicked"),
        &exe,
        RegData::from_dword(1),
    );
    let mut world = World::new(fx);
    world.fp.anchors.aumids = vec!["Vendor.App".into()];
    let found = world.privacy();
    assert_eq!(found.len(), 4, "{found:#?}");
    for store in [
        "AppBadgeUpdated",
        "AppLaunch",
        "AppSwitched",
        "ShowJumpView",
    ] {
        assert_safe_trace(get(&found, &value_spot(&feature_usage(SID, store), &exe)));
    }
}

#[test]
fn file_present_likely() {
    let mut fx = machine();
    // The root and the program are still there (the uninstall left them, or failed).
    fx.add_dir(ROOT);
    fx.add_file(&app_exe(), 10);
    let exe = app_exe();
    let mui = muicache(SID);
    sz(&mut fx, &mui, &format!("{exe}.FriendlyAppName"), "App");
    fx.set_value(&pca_store(SID), &exe, pca_blob());
    let found = World::new(fx).privacy();
    assert_eq!(found.len(), 2, "{found:#?}");
    for c in &found {
        assert!(
            has(c, EvidenceKind::PointsIntoInstallRoot, Tier::A),
            "{c:#?}"
        );
        assert!(!has_kind(c, EvidenceKind::DanglingRef), "{c:#?}");
        assert_eq!(band(c), Band::Likely, "{}", spot(c));
    }

    // The root exists but the program is gone: still no proof of a dangling reference (a part of the
    // app may still be installed), so Likely too.
    let mut fx = machine();
    fx.add_dir(ROOT);
    sz(&mut fx, &mui, &format!("{exe}.FriendlyAppName"), "App");
    let found = World::new(fx).privacy();
    let c = get(&found, &value_spot(&mui, &format!("{exe}.FriendlyAppName")));
    assert!(!has_kind(c, EvidenceKind::DanglingRef), "{c:#?}");
    assert_eq!(band(c), Band::Likely);
}

/// A store that cannot be read offers nothing, and the other stores are still read.
#[test]
fn unreadable_store_offers_nothing() {
    let mut fx = machine();
    let exe = app_exe();
    let mui = muicache(SID);
    sz(&mut fx, &mui, &format!("{exe}.FriendlyAppName"), "App");
    fx.set_value(&pca_store(SID), &exe, pca_blob());
    fx.add_denied(&pca_store(SID));
    let found = World::new(fx).privacy();
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_safe_trace(get(
        &found,
        &value_spot(&mui, &format!("{exe}.FriendlyAppName")),
    ));
}

/// The stores are value containers: whatever they hold, the keys themselves are never offered.
#[test]
fn store_keys_are_never_candidates() {
    let mut fx = machine();
    let exe = app_exe();
    for key in [
        layers(SID),
        pca_store(SID),
        pca_persisted(SID),
        feature_usage(SID, "AppLaunch"),
    ] {
        fx.set_value(&key, &exe, RegData::from_dword(1));
    }
    fx.set_value(&user_assist(SID, UA_EXE), &rot13(&exe), ua_counters());
    sz(
        &mut fx,
        &muicache(SID),
        &format!("{exe}.FriendlyAppName"),
        "App",
    );
    let found = World::new(fx).privacy();
    assert_eq!(found.len(), 6, "{found:#?}");
    // `World::privacy` asserts that every candidate is a single value.
}
