//! FS-VENDORPARENT.

use purge_model::{Action, Blocker, EvidenceKind, Harm};
use purge_scan::framework::{CHILDREN_KEY, PENDING_KEY, PENDING_VALUE};
use purge_scan::fs_vendorparent::FsVendorParent;

use crate::appdata::firefox_with_thunderbird;
use crate::{
    COMMON_PROGRAMS, LOCAL, LOCAL_LOW, ROAMING, World, by_path, firefox_fp, golden, machine, paths,
};

#[test]
fn mozilla_folders_are_offered_delete_if_empty_only() {
    let world = firefox_with_thunderbird();
    let found = world.scan(&FsVendorParent);
    golden("vendorparent_firefox_tb", &found);
    assert_eq!(
        paths(&found),
        [
            format!(r"{ROAMING}\Mozilla"),
            format!(r"{LOCAL}\Mozilla"),
            format!(r"{LOCAL_LOW}\Mozilla"),
            r"C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38".to_string(),
            r"C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates".to_string(),
        ]
    );
    for c in &found {
        assert_eq!(c.action, Action::RemoveDirIfEmpty);
        assert_eq!(c.harm, Harm::None);
        assert!(c.blockers.is_empty(), "{c:?}");
        let [evidence] = c.evidence.as_slice() else {
            panic!("one piece of evidence: {c:?}");
        };
        assert_eq!(evidence.kind, EvidenceKind::VendorContainer);
        assert_eq!(evidence.detail.get(PENDING_KEY), Some(PENDING_VALUE));
    }
    // The listing names every direct child, directories with a trailing separator.
    let roaming = by_path(&found, &format!(r"{ROAMING}\Mozilla"));
    assert_eq!(
        roaming.evidence[0].detail.get(CHILDREN_KEY),
        Some(r#"["Extensions\\","Firefox\\"]"#)
    );
    assert_eq!(roaming.child_count, Some(2));
    let low = by_path(&found, &format!(r"{LOCAL_LOW}\Mozilla"));
    assert_eq!(low.evidence[0].detail.get(CHILDREN_KEY), Some("[]"));
}

#[test]
fn program_files_and_start_menu_vendor_folders() {
    let fixture = machine()
        .file(r"C:\Program Files\Mozilla\readme.txt", 1)
        .dir(r"C:\Program Files (x86)\Mozilla Corporation")
        .file(
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Mozilla\Firefox.lnk",
            1,
        )
        .dir(r"C:\Program Files\MozillaTools")
        .build();
    let found = World::new(fixture, firefox_fp()).scan(&FsVendorParent);
    golden("vendorparent_program_files", &found);
    assert_eq!(
        paths(&found),
        [
            r"C:\Program Files\Mozilla".to_owned(),
            r"C:\Program Files (x86)\Mozilla Corporation".to_owned(),
            format!(r"{COMMON_PROGRAMS}\Mozilla"),
        ]
    );
}

#[test]
fn vendor_folder_holding_another_app_is_blocked() {
    let fixture = machine()
        .file(r"C:\Program Files\Mozilla\Thunderbird\thunderbird.exe", 1)
        .build();
    let world = World::new(fixture, firefox_fp()).with_other_app(
        "Mozilla Thunderbird",
        &[r"C:\Program Files\Mozilla\Thunderbird"],
        &[],
    );
    let found = world.scan(&FsVendorParent);
    assert_eq!(
        by_path(&found, r"C:\Program Files\Mozilla").blockers,
        [Blocker::ContainsOtherApp {
            app: "Mozilla Thunderbird".into()
        }]
    );
}

#[test]
fn mega_vendor_container_is_never_offered() {
    let mut fp = firefox_fp();
    fp.identity.mega_vendor = true;
    let fixture = machine()
        .dir(r"C:\Users\tester\AppData\Roaming\Mozilla")
        .dir(r"C:\Program Files\Mozilla")
        .build();
    assert!(World::new(fixture, fp).scan(&FsVendorParent).is_empty());
}

#[test]
fn own_root_and_unlistable_folder_are_not_offered() {
    // The app installed straight into the vendor folder: that is FS-INSTALLDIR's.
    let mut fp = firefox_fp();
    fp.roots[0].path = r"C:\Program Files\Mozilla".into();
    let fixture = machine()
        .file(r"C:\Program Files\Mozilla\firefox.exe", 1)
        .dir(r"C:\Users\tester\AppData\Roaming\Mozilla")
        .build();
    let world = World::new(fixture, fp);
    let found = world.scan(&FsVendorParent);
    assert_eq!(paths(&found), [format!(r"{ROAMING}\Mozilla")]);

    // A listing that cannot be complete is not emitted as one.
    let fixture = machine()
        .file(
            r"C:\Users\tester\AppData\Roaming\Mozilla\Firefox\profiles.ini",
            1,
        )
        .denied(r"C:\Users\tester\AppData\Roaming\Mozilla")
        .build();
    assert!(
        World::new(fixture, firefox_fp())
            .scan(&FsVendorParent)
            .is_empty()
    );

    // A junction named like the vendor is not a vendor folder.
    let fixture = machine()
        .reparse_dir(r"C:\Users\tester\AppData\Roaming\Mozilla", 0xA000_0003)
        .build();
    assert!(
        World::new(fixture, firefox_fp())
            .scan(&FsVendorParent)
            .is_empty()
    );
}
