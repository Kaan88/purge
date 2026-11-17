//! REG-DIAG: the RAS tracing keys named after the app's exes.

use purge_model::{Action, AnchorKind, AnchorRef, Band, Category, EvidenceKind, Tier};
use purge_scan::framework::{OtherApp, OtherApps};

use super::world::*;

#[test]
fn tracing_stem_of_app_exe_likely_never_safe() {
    let mut fx = machine();
    fx.add_key(&format!(r"{TRACING}\{MAIN_STEM}_RASAPI32"));
    fx.add_key(&format!(r"{TRACING}\{MAIN_STEM}_RASMANCS"));
    fx.add_key(&format!(r"{TRACING32}\appmain_RASAPI32"));
    let world = World::new(fx).ready();
    let found = world.diag();
    assert_eq!(found.len(), 3, "{:#?}", spots(&found));
    for at in [
        format!(r"{TRACING}\{MAIN_STEM}_RASAPI32"),
        format!(r"{TRACING}\{MAIN_STEM}_RASMANCS"),
        format!(r"{TRACING32}\appmain_RASAPI32"),
    ] {
        let c = get(&found, &at);
        assert_eq!(c.action, Action::DeleteKey);
        assert_eq!(c.category, Category::Registration);
        assert!(c.blockers.is_empty(), "{:?}", c.blockers);
        assert!(
            has(c, EvidenceKind::ChainedRef, Tier::B),
            "{:#?}",
            c.evidence
        );
        assert!(!any_tier_a(c), "name-only evidence is never Tier A");
        assert_eq!(band(c), Band::Likely, "{at}");
    }
    // Windows' own program's keys and the roots are never candidates.
    for never in [
        TRACING.to_owned(),
        TRACING32.to_owned(),
        format!(r"{TRACING}\svchost_RASAPI32"),
    ] {
        assert!(find(&found, &never).is_none(), "{never}");
    }
}

#[test]
fn tracing_generic_stem_not_emitted() {
    // Hostile: every installer's `setup.exe` writes `setup_RASAPI32`; the app ships one too.
    let mut fx = machine();
    fx.add_key(&format!(r"{TRACING}\setup_RASAPI32"));
    fx.add_key(&format!(r"{TRACING}\unins000_RASAPI32"));
    let mut world = World::new(fx);
    world.fp.exes.push(purge_model::ExeFile {
        path: app_file("unins000.exe"),
        main: false,
    });
    let world = world.ready();
    let found = world.diag();
    assert!(found.is_empty(), "{:#?}", spots(&found));
}

#[test]
fn tracing_stem_shared_with_other_app_not_emitted() {
    let mut fx = machine();
    fx.add_key(&format!(r"{TRACING}\{MAIN_STEM}_RASAPI32"));
    fx.add_key(&format!(r"{TRACING}\Viewer_RASAPI32"));
    let mut world = World::new(fx);
    world.fp.exes.push(purge_model::ExeFile {
        path: app_file("Viewer.exe"),
        main: false,
    });
    // Another installed app has an exe of each stem: one by its exe anchor, one by a file its records
    // name.
    world.other_apps = OtherApps::new(vec![
        OtherApp {
            name: OTHER.into(),
            roots: vec![OTHER_ROOT.into()],
            anchors: vec![AnchorRef {
                kind: AnchorKind::Exe,
                text: "appmain.EXE".into(),
            }],
            ..OtherApp::default()
        },
        OtherApp {
            name: "Viewer Suite".into(),
            files: vec![r"C:\Program Files\Viewer Suite\Viewer.exe".into()],
            ..OtherApp::default()
        },
    ]);
    let world = world.ready();
    let found = world.diag();
    assert!(found.is_empty(), "{:#?}", spots(&found));
}

/// R3a S5 (trap, the `python312-with-313` shape): another installed program of the same file name that
/// the other apps' records do not list, found by `App Paths` or by a scheduled task's program. The tracing
/// key is that program's too: not emitted. An `App Paths` entry of the app's own exe is no reason.
#[test]
fn tracing_stem_of_unlisted_other_program_not_emitted() {
    const APP_PATHS: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";
    let key = format!(r"{TRACING}\{MAIN_STEM}_RASAPI32");
    let with = |setup: &dyn Fn(&mut purge_source::fixture::Fixture)| {
        let mut fx = machine();
        fx.add_key(&key);
        setup(&mut fx);
        World::new(fx).ready().diag()
    };
    let exe = format!("{MAIN_STEM}.exe");

    // `App Paths` names another program of that name.
    let found = with(&|fx| {
        fx.set_value(
            &format!(r"{APP_PATHS}\{exe}"),
            "",
            purge_source::types::RegData::from_sz(&format!(r"{OTHER_ROOT}\{exe}")),
        );
    });
    assert!(found.is_empty(), "{:#?}", spots(&found));

    // `App Paths` names the app's own exe: still offered.
    let found = with(&|fx| {
        fx.set_value(
            &format!(r"{APP_PATHS}\{exe}"),
            "",
            purge_source::types::RegData::from_sz(&app_file(&exe)),
        );
    });
    assert_eq!(spots(&found), std::slice::from_ref(&key));

    // A scheduled task of another product runs a program of that name.
    let found = with(&|fx| {
        fx.add_task(purge_source::sysobj::TaskInfo {
            identity: purge_model::object::TaskIdentity {
                path: r"\Other\Run".into(),
                actions: vec![purge_model::object::TaskAction::Exec {
                    path: format!(r"{OTHER_ROOT}\{exe}"),
                    arguments: None,
                    working_dir: None,
                }],
            },
            ..Default::default()
        });
    });
    assert!(found.is_empty(), "{:#?}", spots(&found));
}

#[test]
fn tracing_partial_stem_not_matched() {
    // Hostile: the app is `7zFM.exe`; `7z_RASAPI32` belongs to another `7z.exe`, and `7zFM2_RASAPI32`
    // to yet another program.
    let mut fx = machine();
    fx.add_key(&format!(r"{TRACING}\7z_RASAPI32"));
    fx.add_key(&format!(r"{TRACING}\7zFM2_RASAPI32"));
    fx.add_key(&format!(r"{TRACING}\7zFM_RASAPI32x"));
    fx.add_key(&format!(r"{TRACING}\7zFM_RASAPI32"));
    let mut world = World::new(fx);
    world.fp.exes = vec![purge_model::ExeFile {
        path: app_file("7zFM.exe"),
        main: true,
    }];
    let world = world.ready();
    let found = world.diag();
    assert_eq!(
        spots(&found),
        [format!(r"{TRACING}\7zFM_RASAPI32")],
        "only the whole stem matches"
    );
}

#[test]
fn tracing_key_windows_has_is_not_offered() {
    let mut fx = machine();
    fx.add_key(&format!(r"{TRACING}\{MAIN_STEM}_RASAPI32"));
    let mut world = World::new(fx);
    world.baseline = Some(baseline(&[&format!(r"{TRACING}\{MAIN_STEM}_RASAPI32")]));
    let world = world.ready();
    assert!(world.diag().is_empty());
}
