//! REG-PRIVACY: the shell's shortcut-usage slots, `UFH\SHC`.
//!
//! A slot is offered whole only when every non-empty string in it is a path inside an InstallRoot or a
//! shortcut the harvest recorded for the app. The slot store is a shared place of the framework
//! (`ScanCtx::owns_registration`): Windows reuses a slot for the next program, so the evidence on a slot
//! is Tier B and the value at most Likely (never preselected). See the module documentation of
//! `reg_privacy` and the package report: the design's test name says "safe"; the framework's M1a rule
//! on numbered-slot stores does not allow it.

use purge_model::{
    AppFileOutsideRoot, Band, Category, EvidenceKind, InnoRecord, InnoRecordKind, SourceId, Target,
    Tier,
};

use super::world::*;

const START_MENU: &str = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs";

fn lnk(name: &str) -> String {
    format!(r"{START_MENU}\App\{name}.lnk")
}

/// An Inno record that the installer created `path`.
fn created(path: &str) -> InnoRecord {
    InnoRecord {
        kind: InnoRecordKind::DeleteFile,
        target: Target::Path { path: path.into() },
        view: None,
        user_hive: false,
        existed_before: false,
        shared: false,
        key_create: false,
    }
}

/// A world whose harvest recorded the app's shortcut `App.lnk` (installer log) and `Help.lnk`
/// (declared outside the roots).
fn recorded(fx: purge_source::fixture::Fixture) -> World {
    let mut world = World::new(fx);
    world.fp.inno.push(created(&lnk("App")));
    world.fp.outside_root_files.push(AppFileOutsideRoot {
        path: lnk("Help"),
        source: SourceId::from("inno:unins000.dat"),
    });
    world
}

#[test]
fn ufh_shc_all_strings_owned_offered_likely() {
    let mut fx = machine();
    let key = shc(SID);
    fx.set_value(
        &key,
        "0",
        purge_source::types::RegData::from_multi_sz(&[lnk("App").as_str(), app_exe().as_str()]),
    );
    fx.set_value(
        &key,
        "1",
        purge_source::types::RegData::from_multi_sz(&[
            lnk("Help").as_str(),
            app_file(r"bin\helper.exe").as_str(),
            "",
        ]),
    );
    // Only target strings, all in the root.
    fx.set_value(
        &key,
        "2",
        purge_source::types::RegData::from_multi_sz(&[app_exe().as_str()]),
    );
    let found = recorded(fx).privacy();
    assert_eq!(found.len(), 3, "{found:#?}");
    for slot in ["0", "1", "2"] {
        let c = get(&found, &value_spot(&key, slot));
        assert_eq!(c.category, Category::Privacy);
        // Every named file is gone and the whole root with it: both facts, at Tier B (shared place).
        assert!(
            has(c, EvidenceKind::PointsIntoInstallRoot, Tier::B),
            "{c:#?}"
        );
        assert!(has(c, EvidenceKind::DanglingRef, Tier::B), "{c:#?}");
        assert!(
            c.evidence
                .iter()
                .all(|e| e.weight <= 0 || e.tier != Tier::A)
        );
        assert!(c.blockers.is_empty(), "{:?}", c.blockers);
        assert_eq!(band(c), Band::Likely, "{slot}");
    }
}

/// BL-GATE S1: below Exact (any view, or none at all) and with another Windows' baseline, which slots
/// a profile had before the install is unknown, and a slot is taken as Windows' own: Blocked
/// (`WindowsBaseline`), never offered. The exact baseline of this Windows keeps telling a new slot
/// from one its capture holds.
#[test]
fn ufh_shc_below_exact_is_windows_own() {
    use purge_index::baseline_view::fixture::{self, value_entry};
    let key = shc(SID);
    let make = || {
        let mut fx = machine();
        fx.set_value(
            &key,
            "0",
            purge_source::types::RegData::from_multi_sz(&[app_exe().as_str()]),
        );
        fx.set_value(
            &key,
            "1",
            purge_source::types::RegData::from_multi_sz(&[lnk("App").as_str(), app_exe().as_str()]),
        );
        recorded(fx)
    };
    let os = fingerprint().os;
    let slot0 = value_entry(&key, "0");
    let mut views: Vec<Option<purge_index::baseline_view::BaselineView>> = (0
        ..fixture::BELOW_EXACT)
        .map(|below| fixture::below_exact(below, &os))
        .collect();
    views.push(Some(fixture::local_view(
        &os.edition,
        os.build,
        os.ubr,
        &[&slot0],
    )));
    views.push(Some(fixture::merged_view(
        &os.edition,
        os.build,
        os.ubr,
        &[],
        &[&key],
    )));
    views.push(Some(purge_index::baseline_view::BaselineView::exact(
        fixture::shipped("Enterprise", os.build, os.ubr, &[]),
    )));
    for view in views {
        let what = view.as_ref().map(|v| v.name());
        let mut world = make();
        world.baseline = view;
        let found = world.privacy();
        assert_eq!(found.len(), 2, "{what:?}: {found:#?}");
        for c in &found {
            assert!(
                c.blockers.contains(&purge_model::Blocker::WindowsBaseline),
                "{what:?}: {c:#?}"
            );
            assert_eq!(band(c), Band::Blocked, "{what:?}");
        }
    }
    // The exact baseline of this Windows holds slot 0: slot 1 is new and offered.
    let mut world = make();
    world.baseline = Some(purge_index::baseline_view::BaselineView::exact(
        fixture::shipped(&os.edition, os.build, os.ubr, &[&slot0]),
    ));
    let found = world.privacy();
    assert_eq!(band(get(&found, &value_spot(&key, "0"))), Band::Blocked);
    let new = get(&found, &value_spot(&key, "1"));
    assert!(new.blockers.is_empty(), "{new:#?}");
    assert_eq!(band(new), Band::Likely);
}

#[test]
fn ufh_shc_shortcut_present_no_dangling() {
    let mut fx = machine();
    fx.add_dir(START_MENU);
    fx.add_dir(&format!(r"{START_MENU}\App"));
    fx.add_file(&lnk("App"), 1);
    let key = shc(SID);
    fx.set_value(
        &key,
        "0",
        purge_source::types::RegData::from_multi_sz(&[lnk("App").as_str(), app_exe().as_str()]),
    );
    let found = recorded(fx).privacy();
    let c = get(&found, &value_spot(&key, "0"));
    assert!(
        has(c, EvidenceKind::PointsIntoInstallRoot, Tier::B),
        "{c:#?}"
    );
    assert!(!has_kind(c, EvidenceKind::DanglingRef), "{c:#?}");
    assert_eq!(band(c), Band::Likely);
}

#[test]
fn ufh_shc_mixed_value_nothing() {
    let mut fx = machine();
    let key = shc(SID);
    let slot = |fx: &mut purge_source::fixture::Fixture, name: &str, strings: &[&str]| {
        fx.set_value(
            &key,
            name,
            purge_source::types::RegData::from_multi_sz(strings),
        );
    };
    // The app's shortcut, but the target is another installed product's program.
    slot(&mut fx, "0", &[&lnk("App"), &other_file("other.exe")]);
    // The app's program next to another product's shortcut.
    slot(
        &mut fx,
        "1",
        &[&format!(r"{START_MENU}\Other\Other.lnk"), &app_exe()],
    );
    // The app's shortcut and program, with arguments: not wholly paths, no segment edit here.
    slot(&mut fx, "2", &[&lnk("App"), &app_exe(), "--cd-to-home"]);
    // A shortcut nobody recorded for the app.
    slot(&mut fx, "3", &[&lnk("Unrecorded"), &app_exe()]);
    // A bare program name and a relative path.
    slot(&mut fx, "4", &[&lnk("App"), "app.exe"]);
    slot(&mut fx, "5", &[&lnk("App"), r"App\app.exe"]);
    // Only the recorded shortcut: nothing inside a root.
    slot(&mut fx, "6", &[&lnk("App")]);
    // A program of a sibling folder whose name only starts like the root.
    slot(&mut fx, "7", &[r"C:\Program Files\App2\app.exe"]);
    // Not a REG_MULTI_SZ.
    sz(&mut fx, &key, "8", &app_exe());
    assert_none(&recorded(fx).privacy());
}
