//! Properties every scanner of this package holds on every fixture: nothing emitted lies inside another
//! app's root, and no scanner decides a band.

use purge_guard::prefix;
use purge_model::{Candidate, Fingerprint, InnoRecordKind, Target};
use purge_scan::framework::Scanner;
use purge_scan::fs_appdata::FsAppData;
use purge_scan::fs_installdir::FsInstallDir;
use purge_scan::fs_shortcuts::FsShortcuts;
use purge_scan::fs_uninstaller::FsUninstaller;
use purge_scan::fs_vendorparent::FsVendorParent;
use purge_scan::sys_appx::SysAppx;
use purge_source::fixture::Fixture;
use purge_source::types::ShortcutInfo;

use crate::appdata::firefox_with_thunderbird;
use crate::{COMMON_PROGRAMS, ROAMING, USER_PROGRAMS, World, firefox_fp, inno_path, machine};

fn scanners() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(FsInstallDir),
        Box::new(FsUninstaller),
        Box::new(FsAppData),
        Box::new(FsVendorParent),
        Box::new(FsShortcuts),
        Box::new(SysAppx),
    ]
}

fn scan_all(world: &World) -> Vec<Candidate> {
    scanners()
        .iter()
        .flat_map(|scanner| world.scan(scanner.as_ref()))
        .collect()
}

fn assert_nothing_inside_another_app(world: &World, found: &[Candidate]) {
    for c in found {
        assert!(c.decision.is_none(), "{c:?}");
        let Target::Path { path } = &c.target else {
            continue;
        };
        for other in world.other_apps.apps() {
            for root in &other.roots {
                assert!(
                    !prefix::is_same_or_inside(path, root),
                    "{path} lies in {root} of {}",
                    other.name
                );
            }
        }
    }
}

#[test]
fn firefox_next_to_thunderbird() {
    let world = firefox_with_thunderbird();
    let found = scan_all(&world);
    assert!(!found.is_empty());
    assert_nothing_inside_another_app(&world, &found);
    for c in &found {
        assert!(!format!("{:?}", c.target).contains("Thunderbird"), "{c:?}");
    }
}

/// Firefox's leftovers after its uninstaller, one for every scanner but SYS-APPX, and its fingerprint.
fn firefox_leftovers() -> (Fixture, Fingerprint) {
    let link = |target: &str| ShortcutInfo {
        raw_path: Some(target.to_owned()),
        ..ShortcutInfo::default()
    };
    let firefox = r"C:\Program Files\Mozilla Firefox\firefox.exe";
    let fixture = machine()
        .file(r"C:\Program Files\Mozilla Firefox\uninstall\helper.exe", 1)
        .file(r"C:\Program Files\Mozilla Firefox\browser\omni.ja", 1)
        .file(
            r"C:\Users\tester\AppData\Roaming\Mozilla\Firefox\profiles.ini",
            1,
        )
        .file(r"C:\Users\tester\AppData\Local\Mozilla\Firefox\x.bin", 1)
        .file(r"C:\ProgramData\Mozilla\updates\308046B0AF4A39CB\x.bin", 1)
        .dir(r"C:\Program Files\Mozilla\Shared")
        .shortcut(&format!(r"{COMMON_PROGRAMS}\Firefox.lnk"), link(firefox))
        .shortcut(
            &format!(r"{USER_PROGRAMS}\Mozilla\Firefox.lnk"),
            link(firefox),
        )
        .file(r"C:\Users\tester\AppData\Roaming\Firefox\declared.dat", 1)
        .build();
    let mut fp = firefox_fp();
    fp.inno = vec![inno_path(
        InnoRecordKind::DeleteFile,
        r"C:\Users\tester\AppData\Roaming\Firefox\declared.dat",
    )];
    (fixture, fp)
}

/// Other apps whose roots sit exactly where Firefox's leftovers are: every scanner would have something
/// to offer there, and none may.
#[test]
fn other_apps_on_top_of_every_leftover() {
    let (fixture, fp) = firefox_leftovers();

    // With nobody else installed, every scanner but SYS-APPX finds something.
    let alone = World::new(fixture.clone(), fp.clone());
    for scanner in scanners() {
        let found = alone.scan(scanner.as_ref());
        assert_eq!(
            found.is_empty(),
            scanner.id() == "SYS-APPX",
            "{}",
            scanner.id()
        );
    }

    let world = World::new(fixture, fp)
        .with_other_app("Squatter A", &[r"C:\Program Files\Mozilla Firefox"], &[])
        .with_other_app("Squatter B", &[&format!(r"{ROAMING}\Mozilla")], &[])
        .with_other_app(
            "Squatter C",
            &[r"C:\Users\tester\AppData\Local\Mozilla\Firefox"],
            &[],
        )
        .with_other_app("Squatter D", &[r"C:\ProgramData\Mozilla\updates"], &[])
        .with_other_app("Squatter E", &[r"C:\Program Files\Mozilla"], &[])
        .with_other_app("Squatter F", &[COMMON_PROGRAMS, USER_PROGRAMS], &[])
        .with_other_app("Squatter G", &[&format!(r"{ROAMING}\Firefox")], &[]);
    let found = scan_all(&world);
    assert_nothing_inside_another_app(&world, &found);
}

/// Invariant L5 over the file-system worlds, with each scanner: a view below Exact that holds nothing
/// gives the no-baseline candidates exactly; one that says Windows has the keys and directories
/// preselects nothing new and unblocks nothing (`tests/shared/l5.rs`).
#[test]
fn l5_a_view_below_exact_only_takes_away() {
    let leftovers = || {
        let (fixture, fp) = firefox_leftovers();
        World::new(fixture, fp)
    };
    type Make<'a> = &'a dyn Fn() -> World;
    let worlds: [(&str, Make<'_>); 2] = [
        ("firefox leftovers", &leftovers),
        ("firefox next to thunderbird", &firefox_with_thunderbird),
    ];
    let mut tally = crate::l5::Tally::default();
    for (name, make) in worlds {
        for scanner in scanners() {
            let checked = crate::l5::check(
                &format!("{name}/{}", scanner.id()),
                &make().fp.os,
                &|view| {
                    let mut world = make();
                    world.baseline = view;
                    world.scan(scanner.as_ref())
                },
            );
            tally.add(scanner.id(), &checked);
        }
    }
    // Every file-system scanner offers something in some world, and presence changes it.
    tally.assert_not_vacuous(
        &[(
            "SYS-APPX",
            "these worlds have no package; tests/sys_appx_m1b.rs holds its check",
        )],
        &[],
    );
}
