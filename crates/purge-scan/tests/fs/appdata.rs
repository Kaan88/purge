//! FS-APPDATA.

use purge_model::{
    Blocker, Category, EvidenceKind, InnoRecordKind, Root, RootKind, RootSource, SourceTrust, Tier,
};
use purge_scan::fs_appdata::FsAppData;

use crate::{
    FIREFOX_HASH, LOCAL, LOCAL_LOW, ROAMING, SERIAL, World, by_path, fingerprint, firefox_fp,
    golden, inno_path, install_root, machine, npp_fp, paths,
};

/// Firefox uninstalled, Thunderbird still installed: what both leave in the profile and ProgramData.
pub fn firefox_with_thunderbird() -> World {
    let fixture = machine()
        // Firefox.
        .file(
            r"C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Profiles\k3x9.default-release\prefs.js",
            9_000,
        )
        .file(
            r"C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Profiles\k3x9.default-release\places.sqlite",
            5_242_880,
        )
        .file(r"C:\Users\tester\AppData\Roaming\Mozilla\Firefox\profiles.ini", 300)
        .dir(r"C:\Users\tester\AppData\Roaming\Mozilla\Extensions")
        .file(
            r"C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles\k3x9.default-release\cache2\entries\0A1B",
            70_000,
        )
        .dir(r"C:\Users\tester\AppData\LocalLow\Mozilla")
        .file(
            r"C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB\updates\0\update.status",
            12,
        )
        .file(
            r"C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB\update-config.json",
            40,
        )
        .file(
            r"C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\profile_count_308046B0AF4A39CB.json",
            20,
        )
        // Thunderbird, still installed.
        .file(r"C:\Program Files\Mozilla Thunderbird\thunderbird.exe", 600_000)
        .file(
            r"C:\Users\tester\AppData\Roaming\Thunderbird\Profiles\q7.default-release\prefs.js",
            8_000,
        )
        .file(
            r"C:\Users\tester\AppData\Local\Thunderbird\Profiles\q7.default-release\cache2\entries\FF",
            1_000,
        )
        .file(
            r"C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\D78BF5DD33499EC2\update-config.json",
            40,
        )
        // Unrelated neighbours.
        .file(r"C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\x.lnk", 1)
        .file(r"C:\Users\tester\AppData\Local\Temp\firefox\tmp.bin", 1)
        .file(r"C:\ProgramData\Firefoxy\x.bin", 1)
        .build();
    World::new(fixture, firefox_fp()).with_other_app(
        "Mozilla Thunderbird (x64 en-US)",
        &[r"C:\Program Files\Mozilla Thunderbird"],
        &[r"C:\Program Files\Mozilla Thunderbird\uninstall\helper.exe"],
    )
}

#[test]
fn firefox_profile_is_user_data_and_nothing_of_thunderbird_is_listed() {
    let world = firefox_with_thunderbird();
    let found = world.scan(&FsAppData);
    golden("appdata_firefox_tb", &found);

    for path in paths(&found) {
        assert!(!path.contains("Thunderbird"), "{path}");
        assert!(!path.contains("D78BF5DD33499EC2"), "{path}");
    }
    // The vendor folders themselves are FS-VENDORPARENT's.
    for vendor in [
        format!(r"{ROAMING}\Mozilla"),
        format!(r"{LOCAL}\Mozilla"),
        format!(r"{LOCAL_LOW}\Mozilla"),
        r"C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38".to_owned(),
    ] {
        assert!(!paths(&found).contains(&vendor), "{vendor}");
    }
    for profile in [
        format!(r"{ROAMING}\Mozilla\Firefox"),
        format!(r"{LOCAL}\Mozilla\Firefox"),
    ] {
        let c = by_path(&found, &profile);
        assert_eq!(c.category, Category::UserData);
        assert!(c.blockers.contains(&Blocker::UserData));
        assert!(
            c.evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::ProductSubfolderOfVendor)
        );
    }
    // The per-install update directory: only the hash-named folder, with Tier A evidence.
    let updates = by_path(
        &found,
        &format!(
            r"C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\{FIREFOX_HASH}"
        ),
    );
    assert_eq!(updates.category, Category::Cache);
    assert!(updates.blockers.is_empty());
    assert!(
        updates
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::HarvestedToken && e.tier == Tier::A)
    );
    assert_eq!(found.len(), 3);
}

/// The per-install update directory is Safe by the table only with a second observation beside the
/// token (7): its creation time inside the install's window (1). A folder created before the install,
/// or one whose creation time is unknown, stays on the token alone. A last-write time never counts:
/// the uninstaller touches these folders.
#[test]
fn token_folder_counts_its_creation_time_when_it_lies_in_the_window() {
    use purge_source::types::FileTimes;
    let updates = format!(
        r"C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\{FIREFOX_HASH}"
    );
    let times = |created: Option<u64>, modified: Option<u64>| FileTimes {
        created: created.map(purge_model::FileTime),
        modified: modified.map(purge_model::FileTime),
        accessed: None,
    };
    let kinds_at = |when: FileTimes| -> Vec<EvidenceKind> {
        let mut world = firefox_with_thunderbird();
        world.fixture.set_times(&updates, when);
        let found = world.scan(&FsAppData);
        assert!(!paths(&found).iter().any(|p| p.contains("D78BF5DD33499EC2")));
        by_path(&found, &updates)
            .evidence
            .iter()
            .map(|e| e.kind)
            .collect()
    };
    let in_window = crate::T_INSTALL + 5;
    let token_and_time = [EvidenceKind::HarvestedToken, EvidenceKind::TimeWindow];
    let token_only = [EvidenceKind::HarvestedToken];
    assert_eq!(kinds_at(times(Some(in_window), None)), token_and_time);
    // Created long before the install, written during the uninstall: an older folder.
    assert_eq!(
        kinds_at(times(
            Some(crate::T_INSTALL - 3 * 864_000_000_000),
            Some(crate::T_START + 1)
        )),
        token_only
    );
    // No creation time (a snapshot source): the last write inside the window proves nothing.
    assert_eq!(kinds_at(times(None, Some(in_window))), token_only);
    assert_eq!(kinds_at(times(None, None)), token_only);
    assert_eq!(kinds_at(times(Some(crate::T_END + 1), None)), token_only);
}

#[test]
fn token_claimed_by_another_app_attributes_nothing() {
    let mut world = firefox_with_thunderbird();
    let mut apps = world.other_apps.apps().to_vec();
    apps[0].anchors.push(purge_model::AnchorRef {
        kind: purge_model::AnchorKind::Token,
        text: FIREFOX_HASH.to_lowercase(),
    });
    world.other_apps = purge_scan::framework::OtherApps::new(apps);
    let found = world.scan(&FsAppData);
    assert!(!paths(&found).iter().any(|p| p.contains(FIREFOX_HASH)));
}

#[test]
fn notepadpp_folder_with_unsaved_backups_stays_user_data() {
    let fixture = machine()
        .file(
            r"C:\Users\tester\AppData\Roaming\Notepad++\config.xml",
            4_000,
        )
        .file(
            r"C:\Users\tester\AppData\Roaming\Notepad++\backup\new 1@2026-11-11_184512",
            321,
        )
        .file(
            r"C:\Users\tester\AppData\Roaming\Notepad++\plugins\config\x.ini",
            10,
        )
        .file(r"C:\Users\tester\AppData\Roaming\Notepad\notes.txt", 5)
        .file(
            r"C:\Users\tester\AppData\Local\Notepad++ Themes\dark.xml",
            5,
        )
        .build();
    let found = World::new(fixture, npp_fp()).scan(&FsAppData);
    golden("appdata_npp", &found);
    let folder = by_path(&found, &format!(r"{ROAMING}\Notepad++"));
    assert_eq!(folder.category, Category::UserData);
    assert!(folder.blockers.contains(&Blocker::UserData));
    assert!(!paths(&found).contains(&format!(r"{ROAMING}\Notepad")));
}

/// An Inno Setup app whose log names its AppData folder and one cache directory in it.
fn lumen() -> World {
    let mut fp = fingerprint(
        "{6F1D2C3B-0000-4000-8000-1234567890AB}_is1",
        "Lumen Studio",
        &["Lumen Studio"],
        &["Brightwell Software"],
        &["lumen", "studio"],
    );
    fp.roots = vec![install_root(
        r"C:\Program Files\Lumen Studio",
        RootSource::InnoApp,
    )];
    fp.inno = vec![
        inno_path(
            InnoRecordKind::DeleteDirOrFiles,
            r"C:\Users\tester\AppData\Roaming\Lumen Studio",
        ),
        inno_path(
            InnoRecordKind::DeleteDirOrFiles,
            r"C:\Users\tester\AppData\Roaming\Lumen Studio\Cache",
        ),
        inno_path(
            InnoRecordKind::DeleteFile,
            r"C:\ProgramData\Brightwell\licence.dat",
        ),
        // A Start Menu entry is FS-SHORTCUTS' business.
        inno_path(
            InnoRecordKind::DeleteFile,
            r"C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Lumen Studio.lnk",
        ),
        // A file record on a directory owns no tree.
        inno_path(
            InnoRecordKind::DeleteFile,
            r"C:\Users\tester\AppData\Local\LumenShared",
        ),
    ];
    let fixture = machine()
        .file(r"C:\Users\tester\AppData\Roaming\Lumen Studio\settings.json", 800)
        .file(r"C:\Users\tester\AppData\Roaming\Lumen Studio\Cache\data_0", 60_000)
        .file(r"C:\Users\tester\AppData\Roaming\Lumen Studio\GPUCache\index", 9_000)
        .file(r"C:\Users\tester\AppData\Roaming\Lumen Studio\My sketches\holiday.lumen", 77)
        .file(r"C:\ProgramData\Brightwell\licence.dat", 64)
        .file(
            r"C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Lumen Studio.lnk",
            1,
        )
        .file(r"C:\Users\tester\AppData\Local\LumenShared\x.bin", 1)
        .build();
    World::new(fixture, fp)
}

#[test]
fn planted_user_file_keeps_the_folder_user_data_and_only_the_declared_cache_is_cache() {
    let world = lumen();
    let found = world.scan(&FsAppData);
    golden("appdata_inno", &found);

    let folder = by_path(&found, &format!(r"{ROAMING}\Lumen Studio"));
    // Tier A evidence does not make an AppData folder anything but user data.
    assert!(
        folder
            .evidence
            .iter()
            .any(|e| matches!(e.kind, EvidenceKind::InstallerManifest(_)))
    );
    assert_eq!(folder.category, Category::UserData);
    assert!(folder.blockers.contains(&Blocker::UserData));

    let cache = by_path(&found, &format!(r"{ROAMING}\Lumen Studio\Cache"));
    assert_eq!(cache.category, Category::Cache);
    assert!(cache.blockers.is_empty());
    assert_eq!(folder.children, std::slice::from_ref(&cache.id));

    // GPUCache has a cache name but no evidence of its own: it is part of the folder, not an offer.
    assert_eq!(
        paths(&found),
        [
            format!(r"{ROAMING}\Lumen Studio\Cache"),
            format!(r"{ROAMING}\Lumen Studio"),
            r"C:\ProgramData\Brightwell\licence.dat".to_owned(),
        ]
    );
}

#[test]
fn name_attributed_folder_gets_the_negatives() {
    let mut builder = machine()
        .file(
            r"C:\Users\tester\AppData\Local\Lumen Studio\updater.exe",
            1_000,
        )
        .file(
            r"C:\Users\tester\AppData\Local\Lumen Studio\lib\core.dll",
            1_000,
        );
    for i in 0..1_001 {
        builder = builder.file(
            &format!(r"C:\Users\tester\AppData\Local\Lumen Studio\thumbs\{i}.png"),
            1,
        );
    }
    let mut world = lumen();
    world.fixture = builder.build();
    world.fp.inno.clear();
    let found = world.scan(&FsAppData);
    let folder = by_path(&found, &format!(r"{LOCAL}\Lumen Studio"));
    let kinds: Vec<EvidenceKind> = folder.evidence.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        [
            EvidenceKind::ExactFullName,
            EvidenceKind::ExecutablesPresent,
            EvidenceKind::ManyFiles
        ]
    );
    assert_eq!(folder.child_count, Some(1_003));
}

#[test]
fn referenced_data_dir_alone_is_never_a_target() {
    let mut world = lumen();
    world.fp.inno.clear();
    world.fp.roots.push(Root {
        path: r"C:\Users\tester\AppData\Roaming\Renders".into(),
        kind: RootKind::ReferencedDataDir,
        source: RootSource::Referenced,
        trust: SourceTrust::UserWritable,
        volume_serial: Some(SERIAL),
        parent_existed: true,
    });
    world.fp.roots.push(Root {
        path: r"C:\Users\tester\AppData\Roaming\Lumen Studio".into(),
        kind: RootKind::ReferencedDataDir,
        source: RootSource::Referenced,
        trust: SourceTrust::UserWritable,
        volume_serial: Some(SERIAL),
        parent_existed: true,
    });
    world.fixture = machine()
        .file(r"C:\Users\tester\AppData\Roaming\Renders\final.png", 1)
        .file(
            r"C:\Users\tester\AppData\Roaming\Lumen Studio\settings.json",
            1,
        )
        .build();
    let found = world.scan(&FsAppData);
    // The named folder is offered on its name, with the reference as supporting evidence; the folder
    // that is only referenced is not offered.
    assert_eq!(paths(&found), [format!(r"{ROAMING}\Lumen Studio")]);
    let kinds: Vec<EvidenceKind> = found[0].evidence.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        [EvidenceKind::ReferencedByApp, EvidenceKind::ExactFullName]
    );
    assert_eq!(found[0].category, Category::UserData);
}

#[test]
fn virtual_store_copy_of_the_install_root() {
    let mut world = lumen();
    world.fp.inno.clear();
    world.fixture = machine()
        .file(
            r"C:\Users\tester\AppData\Local\VirtualStore\Program Files\Lumen Studio\lumen.ini",
            30,
        )
        .file(
            r"C:\Users\tester\AppData\Local\VirtualStore\Program Files\Other App\other.ini",
            30,
        )
        .build();
    let found = world.scan(&FsAppData);
    assert_eq!(
        paths(&found),
        [format!(r"{LOCAL}\VirtualStore\Program Files\Lumen Studio")]
    );
    assert_eq!(found[0].category, Category::UserData);
}

#[test]
fn folder_inside_another_apps_root_is_not_listed() {
    let fixture = machine()
        .file(r"C:\Users\tester\AppData\Local\Suite\Lumen Studio\x.bin", 1)
        .file(r"C:\Users\tester\AppData\Local\Lumen Studio\x.bin", 1)
        .build();
    let mut world = lumen().with_other_app(
        "Brightwell Suite",
        &[r"C:\Users\tester\AppData\Local\Lumen Studio"],
        &[],
    );
    world.fp.inno.clear();
    world.fixture = fixture;
    assert!(world.scan(&FsAppData).is_empty());
}
