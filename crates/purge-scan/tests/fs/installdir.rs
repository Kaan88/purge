//! FS-INSTALLDIR.

use purge_model::{Blocker, EvidenceKind, InnoRecordKind, Root, RootKind, RootSource, SourceTrust};
use purge_scan::fs_installdir::FsInstallDir;
use purge_source::fixture::FixtureBuilder;
use purge_source::types::ProcessInfo;

use crate::{SERIAL, T_END, T_INSTALL, World, at, by_path, golden, inno_path, machine};

const GIT: &str = r"C:\Program Files\Git";

/// Git with the uninstall log that names the two files of [`git_leftovers`].
fn git_fp() -> purge_model::Fingerprint {
    let mut fp = crate::git_fp();
    fp.inno = vec![
        inno_path(
            InnoRecordKind::DeleteFile,
            r"C:\Program Files\Git\etc\gitconfig",
        ),
        inno_path(
            InnoRecordKind::DeleteFile,
            r"C:\Program Files\Git\mingw64\bin\libcurl-4.dll",
        ),
    ];
    fp
}

/// What Git's uninstaller left behind: a config file and a locked DLL.
fn git_leftovers() -> FixtureBuilder {
    machine()
        .file(r"C:\Program Files\Git\etc\gitconfig", 120)
        .times(r"C:\Program Files\Git\etc\gitconfig", at(T_INSTALL))
        .file(r"C:\Program Files\Git\mingw64\bin\libcurl-4.dll", 4_096)
        .times(
            r"C:\Program Files\Git\mingw64\bin\libcurl-4.dll",
            at(T_INSTALL),
        )
}

fn process(name: &str, path: Option<&str>) -> ProcessInfo {
    ProcessInfo {
        pid: 4242,
        ppid: None,
        name: name.to_owned(),
        path: path.map(str::to_owned),
        start: None,
        session: Some(1),
        cmd: None,
    }
}

#[test]
fn leftover_install_root_is_offered_whole() {
    let world = World::new(git_leftovers().build(), git_fp());
    let found = world.scan(&FsInstallDir);
    golden("installdir_git", &found);
    let root = by_path(&found, GIT);
    assert!(root.blockers.is_empty());
    assert_eq!((root.size_bytes, root.child_count), (Some(4_216), Some(2)));
}

#[test]
fn root_that_is_gone_yields_nothing() {
    let world = World::new(machine().build(), git_fp());
    assert!(world.scan(&FsInstallDir).is_empty());
}

#[test]
fn running_process_inside_the_root_blocks() {
    let fixture = git_leftovers()
        .process(process("explorer.exe", Some(r"C:\Windows\explorer.exe")))
        .process(process(
            "git-daemon.exe",
            Some(r"C:\Program Files\Git\mingw64\bin\git-daemon.exe"),
        ))
        .build();
    let world = World::new(fixture, git_fp());
    let found = world.scan(&FsInstallDir);
    golden("installdir_git_running", &found);
    let root = by_path(&found, GIT);
    assert!(root.blockers.contains(&Blocker::NotGone));
    assert!(root.blockers.contains(&Blocker::InUse));
    assert!(root.blockers.iter().any(Blocker::is_hard));
}

#[test]
fn process_without_a_readable_path_counts_by_exe_name() {
    let mut fp = git_fp();
    fp.exes = vec![purge_model::ExeFile {
        path: r"C:\Program Files\Git\cmd\git.exe".into(),
        main: true,
    }];
    let fixture = git_leftovers().process(process("GIT.EXE", None)).build();
    let found = World::new(fixture, fp.clone()).scan(&FsInstallDir);
    assert!(by_path(&found, GIT).blockers.contains(&Blocker::NotGone));

    // Another program's process of an unrelated name does not.
    let fixture = git_leftovers()
        .process(process("svchost.exe", None))
        .build();
    let found = World::new(fixture, fp).scan(&FsInstallDir);
    assert!(by_path(&found, GIT).blockers.is_empty());
}

#[test]
fn unreadable_process_list_blocks() {
    let fixture = git_leftovers()
        .with(|f| f.system_mut().processes = None)
        .build();
    let found = World::new(fixture, git_fp()).scan(&FsInstallDir);
    assert_eq!(by_path(&found, GIT).blockers, [Blocker::NotGone]);
}

#[test]
fn needs_verify_gone() {
    let mut world = World::new(git_leftovers().build(), git_fp());
    world.verify_gone = None;
    let found = world.scan(&FsInstallDir);
    assert_eq!(by_path(&found, GIT).blockers, [Blocker::NotGone]);

    world.verify_gone = Some(purge_model::VerifyGone::new(true, true, false));
    let found = world.scan(&FsInstallDir);
    assert_eq!(by_path(&found, GIT).blockers, [Blocker::NotGone]);
}

#[test]
fn file_written_after_the_uninstall_is_a_negative() {
    let fixture = git_leftovers()
        .file(r"C:\Program Files\Git\etc\new.log", 10)
        .times(r"C:\Program Files\Git\etc\new.log", at(T_END + 1))
        .build();
    let world = World::new(fixture, git_fp());
    let found = world.scan(&FsInstallDir);
    golden("installdir_git_modified_after", &found);
    let root = by_path(&found, GIT);
    assert!(
        root.evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::ModifiedAfterUninstall && e.weight < 0)
    );
    assert_eq!(
        root.blockers,
        [Blocker::UnmatchedChildren { n: 1 }, Blocker::UserData]
    );
}

/// VM run x0-git-userstate: the user kept notes and a project in Git's folder, the uninstaller left
/// them, and the folder was offered whole and preselected.
#[test]
fn a_file_the_log_does_not_name_keeps_the_root_unticked() {
    let fixture = git_leftovers()
        .file(r"C:\Program Files\Git\notes\todo.txt", 40)
        .times(r"C:\Program Files\Git\notes\todo.txt", at(T_INSTALL + 5))
        .file(r"C:\Program Files\Git\my-tool.exe", 900)
        .times(r"C:\Program Files\Git\my-tool.exe", at(T_INSTALL + 5))
        .build();
    let mut world = World::new(fixture, git_fp());
    let found = world.scan(&FsInstallDir);
    // The root is listed, not preselected: two files in it are not shown to be Git's, one of them is
    // not a program.
    assert_eq!(
        by_path(&found, GIT).blockers,
        [Blocker::UnmatchedChildren { n: 2 }, Blocker::UserData]
    );
    // What the log names is offered file by file; what it does not name is not offered at all.
    assert_eq!(
        crate::paths(&found),
        [
            GIT,
            r"C:\Program Files\Git\etc\gitconfig",
            r"C:\Program Files\Git\mingw64\bin\libcurl-4.dll",
        ]
    );
    for file in &crate::paths(&found)[1..] {
        let c = by_path(&found, file);
        assert!(c.blockers.is_empty(), "{file}");
        assert!(
            c.evidence
                .iter()
                .any(|e| matches!(e.kind, EvidenceKind::InstallerManifest(_))),
            "{file}"
        );
    }

    // While the app is installed (rig runs f1d-git, f1d-vscode-user: a live scan listed every file
    // of the log, 9,546 Blocked rows) the root says it in one row: nothing is offered file by file
    // before the app is verified gone.
    for not_gone in [None, Some(purge_model::VerifyGone::new(false, true, false))] {
        world.verify_gone = not_gone;
        let found = world.scan(&FsInstallDir);
        assert_eq!(crate::paths(&found), [GIT]);
        assert!(by_path(&found, GIT).blockers.contains(&Blocker::NotGone));
    }
}

/// Only program files are left that the log does not name: still unproven, so still unticked.
#[test]
fn an_unnamed_program_file_keeps_the_root_unticked() {
    let fixture = git_leftovers()
        .file(r"C:\Program Files\Git\rg.exe", 900)
        .build();
    let found = World::new(fixture, git_fp()).scan(&FsInstallDir);
    assert_eq!(
        by_path(&found, GIT).blockers,
        [Blocker::UnmatchedChildren { n: 1 }]
    );
}

/// Without an installer log nothing shows whose the files are (an NSIS or MSI app, or an unreadable
/// log): a root with any file left is never preselected.
#[test]
fn a_root_without_an_installer_log_is_never_preselected() {
    let found = World::new(git_leftovers().build(), crate::git_fp()).scan(&FsInstallDir);
    assert_eq!(crate::paths(&found), [GIT]);
    assert_eq!(
        by_path(&found, GIT).blockers,
        [Blocker::UnmatchedChildren { n: 2 }, Blocker::UserData]
    );
}

/// A record the log flags as older than the install names nothing.
#[test]
fn a_file_that_existed_before_the_install_is_not_the_apps() {
    let mut fp = git_fp();
    fp.inno[0].existed_before = true;
    let found = World::new(git_leftovers().build(), fp).scan(&FsInstallDir);
    assert_eq!(
        by_path(&found, GIT).blockers,
        [Blocker::UnmatchedChildren { n: 1 }, Blocker::UserData]
    );
    assert_eq!(
        crate::paths(&found),
        [GIT, r"C:\Program Files\Git\mingw64\bin\libcurl-4.dll"]
    );
}

/// Empty directories are nobody's files: the root goes whole as before.
#[test]
fn a_root_with_only_empty_directories_is_offered_whole() {
    let fixture = machine().dir(r"C:\Program Files\Git\usr\share").build();
    let found = World::new(fixture, crate::git_fp()).scan(&FsInstallDir);
    assert_eq!(crate::paths(&found), [GIT]);
    assert!(by_path(&found, GIT).blockers.is_empty());
}

#[test]
fn another_apps_uninstaller_inside_the_root_blocks() {
    let world = World::new(git_leftovers().build(), git_fp()).with_other_app(
        "Git LFS",
        &[],
        &[r"C:\Program Files\Git\mingw64\bin\git-lfs-uninstall.exe"],
    );
    let found = world.scan(&FsInstallDir);
    assert_eq!(
        by_path(&found, GIT).blockers,
        [Blocker::ContainsOtherApp {
            app: "Git LFS".into()
        }]
    );
}

#[test]
fn unfinished_walk_is_too_large() {
    let world = World::new(git_leftovers().build(), git_fp());
    let mut ctx = world.ctx();
    ctx.limits.max_walk_entries = 2;
    let app = purge_scan::framework::AppIdentityView::from_fingerprint(&world.fp, &world.env);
    let found = purge_scan::framework::Scanner::scan(&FsInstallDir, &ctx, &app);
    assert_eq!(by_path(&found, GIT).blockers, [Blocker::TooLarge]);
}

#[test]
fn root_that_became_a_link_is_blocked() {
    let fixture = machine()
        .reparse_dir(GIT, 0xA000_0003)
        .file(r"C:\Program Files\Git\somebody-elses.txt", 1)
        .build();
    let found = World::new(fixture, git_fp()).scan(&FsInstallDir);
    let root = by_path(&found, GIT);
    assert!(root.blockers.contains(&Blocker::ReparseMismatch));
    // Nothing behind the link was counted.
    assert_eq!(root.child_count, Some(1));
}

#[test]
fn inferred_root_is_never_offered_whole() {
    let tools = r"C:\Tools\Lumen";
    let mut fp = git_fp();
    fp.roots = vec![Root {
        path: tools.into(),
        kind: RootKind::InferredRoot,
        source: RootSource::DisplayIcon,
        trust: SourceTrust::AdminOnly,
        volume_serial: Some(SERIAL),
        parent_existed: true,
    }];
    fp.inno = vec![
        inno_path(InnoRecordKind::DeleteFile, r"C:\Tools\Lumen\lumen.dll"),
        inno_path(InnoRecordKind::DeleteDirOrFiles, r"C:\Tools\Lumen\plugins"),
        // A file record on what turns out to be a directory owns no tree.
        inno_path(InnoRecordKind::DeleteFile, r"C:\Tools\Lumen\data"),
        // Gone already.
        inno_path(InnoRecordKind::DeleteFile, r"C:\Tools\Lumen\gone.dll"),
        // Not under the root.
        inno_path(InnoRecordKind::DeleteFile, r"C:\Tools\other.dll"),
    ];
    let fixture = machine()
        .file(r"C:\Tools\Lumen\lumen.dll", 500)
        .file(r"C:\Tools\Lumen\plugins\a.dll", 30)
        .file(r"C:\Tools\Lumen\data\notes.txt", 7)
        .file(r"C:\Tools\Lumen\unrelated.txt", 1)
        .file(r"C:\Tools\other.dll", 1)
        .build();
    let mut world = World::new(fixture, fp);
    let found = world.scan(&FsInstallDir);
    golden("installdir_inferred_root", &found);
    assert_eq!(
        crate::paths(&found),
        [r"C:\Tools\Lumen\lumen.dll", r"C:\Tools\Lumen\plugins"]
    );
    // Not before the app is verified gone.
    world.verify_gone = None;
    assert!(world.scan(&FsInstallDir).is_empty());
}

#[test]
fn inferred_root_directory_record_does_not_cover_undeclared_files() {
    let inferred = |inno: Vec<purge_model::InnoRecord>| {
        let mut fp = git_fp();
        fp.roots = vec![Root {
            path: r"C:\Tools\Lumen".into(),
            kind: RootKind::InferredRoot,
            source: RootSource::DisplayIcon,
            trust: SourceTrust::AdminOnly,
            volume_serial: Some(SERIAL),
            parent_existed: true,
        }];
        fp.inno = inno;
        fp
    };
    let fixture = machine()
        .file(r"C:\Tools\Lumen\plugins\a.dll", 30)
        .file(r"C:\Tools\Lumen\plugins\sub\mine.txt", 5)
        .file(r"C:\Tools\other\keep.txt", 1)
        .build();

    // `plugins\sub\mine.txt` is not named by the log: the directory record does not make it the app's
    // (carry-over rule), so the directory is offered unchecked.
    let fp = inferred(vec![
        inno_path(InnoRecordKind::DeleteDirOrFiles, r"C:\Tools\Lumen\plugins"),
        inno_path(InnoRecordKind::DeleteFile, r"C:\Tools\Lumen\plugins\a.dll"),
        // Lexically under the root, really `C:\Tools\other`.
        inno_path(InnoRecordKind::DeleteDirOrFiles, r"C:\Tools\Lumen\..\other"),
    ]);
    let found = World::new(fixture.clone(), fp).scan(&FsInstallDir);
    assert_eq!(
        crate::paths(&found),
        [r"C:\Tools\Lumen\plugins", r"C:\Tools\Lumen\plugins\a.dll"]
    );
    assert_eq!(
        by_path(&found, r"C:\Tools\Lumen\plugins").blockers,
        [Blocker::UnmatchedChildren { n: 1 }]
    );
    assert!(
        by_path(&found, r"C:\Tools\Lumen\plugins\a.dll")
            .blockers
            .is_empty()
    );

    // Every file declared: nothing unmatched.
    let fp = inferred(vec![
        inno_path(InnoRecordKind::DeleteDirOrFiles, r"C:\Tools\Lumen\plugins"),
        inno_path(InnoRecordKind::DeleteFile, r"C:\Tools\Lumen\plugins\a.dll"),
        inno_path(
            InnoRecordKind::DeleteFile,
            r"C:\Tools\Lumen\plugins\sub\mine.txt",
        ),
    ]);
    let found = World::new(fixture, fp).scan(&FsInstallDir);
    assert!(
        by_path(&found, r"C:\Tools\Lumen\plugins")
            .blockers
            .is_empty()
    );
}
