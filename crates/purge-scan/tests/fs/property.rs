//! Properties every scanner of this package holds on every fixture: nothing emitted lies inside another
//! app's root, and no scanner decides a band.

use purge_guard::prefix;
use purge_model::{Candidate, InnoRecordKind, Target};
use purge_scan::framework::Scanner;
use purge_scan::fs_appdata::FsAppData;
use purge_scan::fs_installdir::FsInstallDir;
use purge_scan::fs_shortcuts::FsShortcuts;
use purge_scan::fs_uninstaller::FsUninstaller;
use purge_scan::fs_vendorparent::FsVendorParent;
use purge_scan::sys_appx::SysAppx;
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

/// Other apps whose roots sit exactly where Firefox's leftovers are: every scanner would have something
/// to offer there, and none may.
#[test]
fn other_apps_on_top_of_every_leftover() {
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
