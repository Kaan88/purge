//! FS-SHORTCUTS.

use purge_model::{Category, EvidenceKind, InnoRecordKind, Tier};
use purge_scan::fs_shortcuts::FsShortcuts;
use purge_source::fixture::FixtureBuilder;
use purge_source::types::ShortcutInfo;

use crate::{
    COMMON_PROGRAMS, FIREFOX_HASH, T_INSTALL, USER_PROGRAMS, World, at, by_path, firefox_fp,
    git_fp, golden, inno_path, machine, npp_fp, paths,
};

const DESKTOP: &str = r"C:\Users\tester\Desktop";
const TASKBAR: &str =
    r"C:\Users\tester\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar";

fn link(target: &str) -> ShortcutInfo {
    ShortcutInfo {
        raw_path: Some(target.to_owned()),
        ..ShortcutInfo::default()
    }
}

fn link_args(target: &str, args: &str) -> ShortcutInfo {
    ShortcutInfo {
        raw_path: Some(target.to_owned()),
        args: Some(args.to_owned()),
        ..ShortcutInfo::default()
    }
}

/// A shortcut created at install time.
fn shortcut(builder: FixtureBuilder, path: &str, info: ShortcutInfo) -> FixtureBuilder {
    builder.shortcut(path, info).times(path, at(T_INSTALL))
}

/// Notepad++ uninstalled (its directory is gone), with its shortcuts and Windows' own Notepad link left.
fn npp_machine() -> FixtureBuilder {
    let npp = r"C:\Program Files\Notepad++\notepad++.exe";
    let mut b = machine().file(r"C:\Windows\System32\notepad.exe", 200_000);
    b = shortcut(b, &format!(r"{COMMON_PROGRAMS}\Notepad++.lnk"), link(npp));
    b = shortcut(b, &format!(r"{DESKTOP}\Notepad++.lnk"), link(npp));
    b = shortcut(b, &format!(r"{TASKBAR}\Notepad++.lnk"), link(npp));
    // Windows' own Notepad, in three spellings of the same existing target.
    b = shortcut(
        b,
        &format!(r"{USER_PROGRAMS}\Accessories\Notepad.lnk"),
        link(r"%windir%\system32\notepad.exe"),
    );
    b = shortcut(
        b,
        &format!(r"{DESKTOP}\Notepad.lnk"),
        link(r"C:\Windows\System32\notepad.exe"),
    );
    b = shortcut(
        b,
        &format!(r"{DESKTOP}\Notepad++ notes.lnk"),
        link_args(
            r"%SystemRoot%\system32\notepad.exe",
            r"C:\Users\tester\notes.txt",
        ),
    );
    // A link to a document that is gone, outside every root.
    b = shortcut(
        b,
        &format!(r"{DESKTOP}\Notepad++ cheat sheet.lnk"),
        link(r"C:\Users\tester\Documents\npp-cheatsheet.pdf"),
    );
    // A shell-item link without a path.
    b = shortcut(
        b,
        &format!(r"{DESKTOP}\Notepad++ (store).lnk"),
        ShortcutInfo::default(),
    );
    // Deeper than the desktop itself: not a desktop shortcut.
    shortcut(b, &format!(r"{DESKTOP}\old\Notepad++.lnk"), link(npp))
}

#[test]
fn notepadpp_shortcuts_and_never_notepad_lnk() {
    let world = World::new(npp_machine().build(), npp_fp());
    let found = world.scan(&FsShortcuts);
    golden("shortcuts_npp", &found);
    assert_eq!(
        paths(&found),
        [
            format!(r"{COMMON_PROGRAMS}\Notepad++.lnk"),
            format!(r"{TASKBAR}\Notepad++.lnk"),
            format!(r"{DESKTOP}\Notepad++.lnk"),
        ]
    );
    for path in paths(&found) {
        assert!(!path.ends_with(r"\Notepad.lnk"), "{path}");
    }
}

#[test]
fn notepad_lnk_is_not_offered_even_when_the_install_dir_survives() {
    let fixture = npp_machine()
        .file(r"C:\Program Files\Notepad++\notepad++.exe", 1)
        .build();
    let found = World::new(fixture, npp_fp()).scan(&FsShortcuts);
    assert_eq!(found.len(), 3);
    assert!(paths(&found).iter().all(|p| p.ends_with(r"\Notepad++.lnk")));
}

#[test]
fn unreadable_shortcut_is_offered_only_on_the_installers_record() {
    // A rig snapshot records the files but not what the links say.
    let fixture = machine()
        .file(&format!(r"{COMMON_PROGRAMS}\Git\Git Bash.lnk"), 1_500)
        .file(&format!(r"{COMMON_PROGRAMS}\Git\Git GUI.lnk"), 1_500)
        .file(&format!(r"{COMMON_PROGRAMS}\Git\desktop.ini"), 80)
        .file(&format!(r"{DESKTOP}\Git Bash.lnk"), 1_500)
        .file(&format!(r"{DESKTOP}\Git cheat sheet.lnk"), 900)
        .file(&format!(r"{USER_PROGRAMS}\Git Tool.appref-ms"), 300)
        .with(|f| f.set_unknown_file_facts(true))
        .build();
    let mut fp = git_fp();
    fp.inno = vec![
        inno_path(
            InnoRecordKind::DeleteDirOrFiles,
            &format!(r"{COMMON_PROGRAMS}\Git"),
        ),
        inno_path(
            InnoRecordKind::DeleteFile,
            &format!(r"{COMMON_PROGRAMS}\Git\Git Bash.lnk"),
        ),
        inno_path(
            InnoRecordKind::DeleteFile,
            &format!(r"{COMMON_PROGRAMS}\Git\Git GUI.lnk"),
        ),
        inno_path(
            InnoRecordKind::DeleteFile,
            &format!(r"{DESKTOP}\Git Bash.lnk"),
        ),
    ];
    let found = World::new(fixture, fp).scan(&FsShortcuts);
    golden("shortcuts_git_inno", &found);
    assert_eq!(
        paths(&found),
        [
            format!(r"{COMMON_PROGRAMS}\Git\Git Bash.lnk"),
            format!(r"{COMMON_PROGRAMS}\Git\Git GUI.lnk"),
            format!(r"{DESKTOP}\Git Bash.lnk"),
            format!(r"{COMMON_PROGRAMS}\Git"),
        ]
    );
    for c in &found {
        assert!(
            c.evidence
                .iter()
                .any(|e| matches!(e.kind, EvidenceKind::InstallerManifest(_)) && e.tier == Tier::A),
            "{c:?}"
        );
    }
    let group = by_path(&found, &format!(r"{COMMON_PROGRAMS}\Git"));
    assert_eq!(group.children.len(), 2);
}

#[test]
fn group_with_a_foreign_entry_is_not_offered() {
    let git = r"C:\Program Files\Git\git-bash.exe";
    let mut b = machine().file(r"C:\Windows\System32\cmd.exe", 1);
    b = shortcut(b, &format!(r"{USER_PROGRAMS}\Git\Git Bash.lnk"), link(git));
    b = shortcut(
        b,
        &format!(r"{USER_PROGRAMS}\Git\My console.lnk"),
        link(r"C:\Windows\System32\cmd.exe"),
    );
    let found = World::new(b.build(), git_fp()).scan(&FsShortcuts);
    assert_eq!(
        paths(&found),
        [format!(r"{USER_PROGRAMS}\Git\Git Bash.lnk")]
    );
}

#[test]
fn aumid_startup_squirrel_and_url_shortcuts() {
    let mut fp = firefox_fp();
    fp.roots.push(crate::install_root(
        r"C:\Users\tester\AppData\Local\Firefox Nightly\app-1.2.3",
        purge_model::RootSource::ArpInstallLocation,
    ));
    fp.exes = vec![purge_model::ExeFile {
        path: r"C:\Users\tester\AppData\Local\Firefox Nightly\app-1.2.3\Firefox.exe".into(),
        main: true,
    }];
    let startup = format!(r"{USER_PROGRAMS}\Startup");
    let mut b = machine()
        .file(r"C:\Windows\explorer.exe", 1)
        .file(
            r"C:\Users\tester\AppData\Local\Firefox Nightly\Update.exe",
            1,
        )
        .file(r"C:\Users\tester\AppData\Local\Other\Update.exe", 1);
    // By AUMID property.
    b = shortcut(
        b,
        &format!(r"{USER_PROGRAMS}\Firefox.lnk"),
        ShortcutInfo {
            aumid: Some(FIREFOX_HASH.to_lowercase()),
            ..ShortcutInfo::default()
        },
    );
    // By shell:AppsFolder, ours and somebody else's.
    b = shortcut(
        b,
        &format!(r"{USER_PROGRAMS}\Firefox Private Browsing.lnk"),
        link_args(
            r"C:\Windows\explorer.exe",
            &format!(r"shell:AppsFolder\{FIREFOX_HASH}"),
        ),
    );
    b = shortcut(
        b,
        &format!(r"{USER_PROGRAMS}\Firefox Store.lnk"),
        link(r"shell:AppsFolder\Mozilla.Firefox_n80bbvh6b1yt2!App"),
    );
    // In the Startup folder, into the (missing) install root.
    b = shortcut(
        b,
        &format!(r"{startup}\Firefox.lnk"),
        link(r"C:\Program Files\Mozilla Firefox\firefox.exe"),
    );
    // Squirrel stubs: ours next to the root, and another app's stub with the same exe name.
    b = shortcut(
        b,
        &format!(r"{USER_PROGRAMS}\Firefox Nightly.lnk"),
        link_args(
            r"C:\Users\tester\AppData\Local\Firefox Nightly\Update.exe",
            "--processStart Firefox.exe",
        ),
    );
    b = shortcut(
        b,
        &format!(r"{USER_PROGRAMS}\Firefox clone.lnk"),
        link_args(
            r"C:\Users\tester\AppData\Local\Other\Update.exe",
            "--processStart Firefox.exe",
        ),
    );
    // Internet shortcuts: a local page of the app, its website with the app's icon, and a plain link.
    let help = format!(r"{USER_PROGRAMS}\Firefox Help.url");
    let website = format!(r"{USER_PROGRAMS}\Firefox Website.url");
    let tips = format!(r"{USER_PROGRAMS}\Firefox tips.url");
    let later = format!(r"{USER_PROGRAMS}\Firefox manual.url");
    b = b
        .file_content(
            &help,
            "[InternetShortcut]\r\nURL=file:///C:/Program%20Files/Mozilla%20Firefox/help.htm\r\n",
        )
        .times(&help, at(T_INSTALL))
        .file_content(
            &website,
            "[InternetShortcut]\r\nURL=https://example.org/\r\nIconFile=C:\\Program Files\\Mozilla Firefox\\firefox.exe\r\n",
        )
        .times(&website, at(T_INSTALL))
        .file_content(&tips, "[InternetShortcut]\r\nURL=https://example.org/tips\r\n")
        .times(&tips, at(T_INSTALL))
        // Leads into the root, but was made long after the install and does not carry the app's name:
        // the framework has no evidence kind for "a file that points into the root" (§5.3 records
        // `PointsIntoInstallRoot` for values only), so nothing can be stated and it is not offered.
        .file_content(
            &later,
            "[InternetShortcut]\r\nURL=file:///C:/Program%20Files/Mozilla%20Firefox/manual.htm\r\n",
        )
        .times(&later, at(crate::T_END + 1));
    let found = World::new(b.build(), fp).scan(&FsShortcuts);
    golden("shortcuts_firefox_kinds", &found);
    let mut got = paths(&found);
    got.sort();
    let mut want = vec![
        format!(r"{USER_PROGRAMS}\Firefox.lnk"),
        format!(r"{USER_PROGRAMS}\Firefox Private Browsing.lnk"),
        format!(r"{startup}\Firefox.lnk"),
        format!(r"{USER_PROGRAMS}\Firefox Nightly.lnk"),
        format!(r"{USER_PROGRAMS}\Firefox Help.url"),
        format!(r"{USER_PROGRAMS}\Firefox Website.url"),
    ];
    want.sort();
    assert_eq!(got, want);
    assert_eq!(
        by_path(&found, &format!(r"{startup}\Firefox.lnk")).category,
        Category::Startup
    );
    assert_eq!(
        by_path(&found, &format!(r"{USER_PROGRAMS}\Firefox.lnk")).category,
        Category::AppFiles
    );
}

#[test]
fn shortcut_into_another_apps_root_is_not_listed() {
    // A stale fingerprint root that another app now owns.
    let npp = r"C:\Program Files\Notepad++\notepad++.exe";
    let b = shortcut(machine(), &format!(r"{DESKTOP}\Notepad++.lnk"), link(npp));
    let world = World::new(b.build(), npp_fp()).with_other_app("Desktop Tools", &[DESKTOP], &[]);
    assert!(world.scan(&FsShortcuts).is_empty());
}

#[test]
fn target_that_leaves_the_root_through_dot_segments_is_not_offered() {
    let b = machine().file(r"C:\Windows\System32\notepad.exe", 1);
    let b = shortcut(
        b,
        &format!(r"{DESKTOP}\Notepad++.lnk"),
        link(r"C:\Program Files\Notepad++\..\..\Windows\System32\notepad.exe"),
    );
    assert!(
        World::new(b.build(), npp_fp())
            .scan(&FsShortcuts)
            .is_empty()
    );
}

#[test]
fn app_file_outside_the_roots_counts_only_when_it_is_gone() {
    // The app's installer declared a launcher outside its root (like `py.exe` in `C:\Windows`).
    let launcher = r"C:\Tools\bin\npp-launch.exe";
    let mut fp = npp_fp();
    fp.outside_root_files = vec![purge_model::AppFileOutsideRoot {
        path: launcher.into(),
        source: purge_model::SourceId("inno:unins000.dat".into()),
    }];
    let lnk = format!(r"{DESKTOP}\Notepad++.lnk");
    // Still there (another product may use it): never offered.
    let present = shortcut(machine().file(launcher, 1), &lnk, link(launcher));
    assert!(
        World::new(present.build(), fp.clone())
            .scan(&FsShortcuts)
            .is_empty()
    );
    // Proven gone: the shortcut is a leftover.
    let gone = shortcut(machine().dir(r"C:\Tools\bin"), &lnk, link(launcher));
    assert_eq!(
        paths(&World::new(gone.build(), fp).scan(&FsShortcuts)),
        [lnk]
    );
}

#[test]
fn shortcut_to_a_file_another_app_now_owns_is_not_offered() {
    // The directory was reused: a newer version registered under another ARP entry lives in the root.
    let npp = r"C:\Program Files\Notepad++\notepad++.exe";
    let b = shortcut(
        machine().file(npp, 1),
        &format!(r"{DESKTOP}\Notepad++.lnk"),
        link(npp),
    );
    let fixture = b.build();
    let by_root = World::new(fixture.clone(), npp_fp()).with_other_app(
        "Notepad++ 9",
        &[r"C:\Program Files\Notepad++"],
        &[],
    );
    assert!(by_root.scan(&FsShortcuts).is_empty());
    let by_file = World::new(fixture, npp_fp()).with_other_app("Notepad++ 9", &[], &[npp]);
    assert!(by_file.scan(&FsShortcuts).is_empty());
}
