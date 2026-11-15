//! FS-UNINSTALLER.

use purge_model::{Blocker, EvidenceKind, Root, RootKind, RootSource, SourceTrust, Tier};
use purge_scan::fs_uninstaller::FsUninstaller;

use crate::{SERIAL, World, by_path, firefox_fp, golden, machine, paths};

/// Git with its own Inno uninstaller files, as the harvest records them from the `UninstallString`.
fn git_fp() -> purge_model::Fingerprint {
    let mut fp = crate::git_fp();
    fp.uninstallers = vec![
        r"C:\Program Files\Git\unins000.dat".into(),
        r"C:\Program Files\Git\unins000.exe".into(),
        r"C:\Program Files\Git\unins000.msg".into(),
    ];
    fp
}

fn all_tier_b(c: &purge_model::Candidate) -> bool {
    c.evidence.iter().all(|e| e.tier != Tier::A)
}

fn root(path: &str, kind: RootKind, source: RootSource) -> Root {
    Root {
        path: path.into(),
        kind,
        source,
        trust: SourceTrust::AdminOnly,
        volume_serial: Some(SERIAL),
        parent_existed: true,
    }
}

#[test]
fn inno_uninstaller_files() {
    let fixture = machine()
        .file(r"C:\Program Files\Git\unins000.exe", 3_000_000)
        .file(r"C:\Program Files\Git\unins000.dat", 900_000)
        .file(r"C:\Program Files\Git\unins000.msg", 24_000)
        .file(r"C:\Program Files\Git\git-bash.exe", 150_000)
        .file(r"C:\Program Files\Git\uninstall.log", 10)
        .file(r"C:\Program Files\Git\bin\unins000.exe", 1)
        .build();
    let world = World::new(fixture, git_fp());
    let found = world.scan(&FsUninstaller);
    golden("uninstaller_git", &found);
    assert_eq!(
        paths(&found),
        [
            r"C:\Program Files\Git\unins000.dat",
            r"C:\Program Files\Git\unins000.exe",
            r"C:\Program Files\Git\unins000.msg",
        ]
    );
    for c in &found {
        assert!(c.blockers.is_empty(), "{c:?}");
        assert!(
            c.evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::UninstallerArtifact)
        );
    }
}

#[test]
fn uninstaller_directory_inside_the_install_root() {
    let mut fp = firefox_fp();
    fp.roots.push(root(
        r"C:\Program Files\Mozilla Firefox\uninstall",
        RootKind::InferredRoot,
        RootSource::UninstallerDir,
    ));
    fp.uninstallers = vec![r"C:\Program Files\Mozilla Firefox\uninstall\helper.exe".into()];
    let fixture = machine()
        .file(
            r"C:\Program Files\Mozilla Firefox\uninstall\helper.exe",
            1_200_000,
        )
        .file(
            r"C:\Program Files\Mozilla Firefox\uninstall\uninstall.log",
            50_000,
        )
        .file(r"C:\Program Files\Mozilla Firefox\firefox.exe", 700_000)
        .build();
    let world = World::new(fixture, fp);
    let found = world.scan(&FsUninstaller);
    golden("uninstaller_firefox_dir", &found);
    let dir = by_path(&found, r"C:\Program Files\Mozilla Firefox\uninstall");
    assert_eq!(
        (dir.size_bytes, dir.child_count),
        (Some(1_250_000), Some(2))
    );
    assert_eq!(found.len(), 1);
}

#[test]
fn needs_verify_gone() {
    let fixture = machine()
        .file(r"C:\Program Files\Git\unins000.exe", 1)
        .build();
    let mut world = World::new(fixture, git_fp());
    world.verify_gone = None;
    let found = world.scan(&FsUninstaller);
    assert_eq!(
        by_path(&found, r"C:\Program Files\Git\unins000.exe").blockers,
        [Blocker::NotGone]
    );
}

#[test]
fn display_icon_root_is_not_searched() {
    let mut fp = git_fp();
    fp.roots = vec![root(
        r"C:\Tools",
        RootKind::InferredRoot,
        RootSource::DisplayIcon,
    )];
    let fixture = machine().file(r"C:\Tools\uninstall.exe", 1).build();
    assert!(World::new(fixture, fp).scan(&FsUninstaller).is_empty());
}

#[test]
fn uninstaller_dir_root_outside_an_install_root_offers_files_only() {
    let mut fp = git_fp();
    fp.roots = vec![root(
        r"C:\Tools\Lumen",
        RootKind::InferredRoot,
        RootSource::UninstallerDir,
    )];
    let fixture = machine()
        .file(r"C:\Tools\Lumen\Uninstall.exe", 9)
        .file(r"C:\Tools\Lumen\lumen.exe", 9)
        .build();
    let found = World::new(fixture, fp).scan(&FsUninstaller);
    assert_eq!(paths(&found), [r"C:\Tools\Lumen\Uninstall.exe"]);
    // Not under an InstallRoot: the artifact evidence stands alone.
    assert_eq!(found[0].evidence.len(), 1);
}

#[test]
fn another_apps_uninstaller_is_blocked() {
    let fixture = machine()
        .file(r"C:\Program Files\Git\unins000.exe", 1)
        .file(r"C:\Program Files\Git\unins001.exe", 1)
        .build();
    let world = World::new(fixture, git_fp()).with_other_app(
        "Git Extras",
        &[],
        &[r"C:\Program Files\Git\unins001.exe"],
    );
    let found = world.scan(&FsUninstaller);
    assert!(
        by_path(&found, r"C:\Program Files\Git\unins000.exe")
            .blockers
            .is_empty()
    );
    assert_eq!(
        by_path(&found, r"C:\Program Files\Git\unins001.exe").blockers,
        [Blocker::ReferencedByOtherApp {
            app: "Git Extras".into()
        }]
    );
}

/// A shared folder holds other tools with uninstallers of their own, registered or not. A name
/// like `uninstall.exe` in the app's root is the app's only when it is the app's own uninstaller.
#[test]
fn a_file_named_like_an_uninstaller_that_is_not_the_apps_own_is_tier_b() {
    let fixture = machine()
        .file(r"C:\Program Files\Git\unins000.exe", 3_000_000)
        .file(r"C:\Program Files\Git\unins001.exe", 2_000_000)
        .file(r"C:\Program Files\Git\unins001.dat", 1_000)
        .file(r"C:\Program Files\Git\uninstall.exe", 500_000)
        .build();
    let found = World::new(fixture, git_fp()).scan(&FsUninstaller);
    let own = by_path(&found, r"C:\Program Files\Git\unins000.exe");
    assert!(own.evidence.iter().any(|e| e.tier == Tier::A));
    for theirs in ["unins001.exe", "unins001.dat", "uninstall.exe"] {
        let c = by_path(&found, &format!(r"C:\Program Files\Git\{theirs}"));
        assert!(all_tier_b(c), "{theirs}: {c:?}");
        assert!(
            c.evidence
                .iter()
                .all(|e| e.detail.get("unproven").is_some()),
            "{theirs}"
        );
    }
    // A fingerprint that does not name the app's uninstaller (an MSI app, an older fingerprint)
    // proves none of them.
    let fixture = machine()
        .file(r"C:\Program Files\Git\unins000.exe", 3_000_000)
        .build();
    let found = World::new(fixture, crate::git_fp()).scan(&FsUninstaller);
    assert!(all_tier_b(&found[0]));
}

/// `<root>\Uninstall` of another tool in a shared root: nothing in it is the app's uninstaller.
#[test]
fn an_uninstall_directory_that_is_not_the_apps_own_is_not_preselected() {
    let fixture = machine()
        .file(r"C:\Program Files\Git\Uninstall\tool-setup.exe", 400_000)
        .file(r"C:\Program Files\Git\Uninstall\tool.dat", 10)
        .build();
    let found = World::new(fixture, git_fp()).scan(&FsUninstaller);
    let dir = by_path(&found, r"C:\Program Files\Git\Uninstall");
    assert!(all_tier_b(dir), "{dir:?}");
    assert_eq!(dir.blockers, [Blocker::UnmatchedChildren { n: 2 }]);
}

/// A directory in the uninstaller's folder that cannot be read: nothing shows what is in it.
#[test]
fn an_uninstall_directory_that_cannot_be_read_is_not_preselected() {
    let mut fp = firefox_fp();
    fp.uninstallers = vec![r"C:\Program Files\Mozilla Firefox\uninstall\helper.exe".into()];
    let dir = r"C:\Program Files\Mozilla Firefox\uninstall";
    let fixture = machine()
        .file(&format!(r"{dir}\helper.exe"), 1_200_000)
        .file(&format!(r"{dir}\locked\x.bin"), 5)
        .denied(&format!(r"{dir}\locked"))
        .build();
    let found = World::new(fixture, fp).scan(&FsUninstaller);
    let c = by_path(&found, dir);
    assert!(
        c.blockers.contains(&Blocker::UnmatchedChildren { n: 1 }),
        "{:?}",
        c.blockers
    );
}

/// The app's own uninstaller directory with something in it that is not the uninstaller's: the
/// directory is the app's, what it holds is not shown to be.
#[test]
fn the_apps_uninstall_directory_with_other_files_in_it_is_not_preselected() {
    let mut fp = firefox_fp();
    fp.uninstallers = vec![r"C:\Program Files\Mozilla Firefox\uninstall\helper.exe".into()];
    let dir = r"C:\Program Files\Mozilla Firefox\uninstall";
    let fixture = |extra: bool| {
        let mut b = machine()
            .file(&format!(r"{dir}\helper.exe"), 1_200_000)
            .file(&format!(r"{dir}\uninstall.log"), 50_000);
        if extra {
            b = b.file(&format!(r"{dir}\notes\mine.txt"), 5);
        }
        b.build()
    };
    let found = World::new(fixture(false), fp.clone()).scan(&FsUninstaller);
    let c = by_path(&found, dir);
    assert!(c.blockers.is_empty(), "{:?}", c.blockers);
    assert!(c.evidence.iter().any(|e| e.tier == Tier::A));

    let found = World::new(fixture(true), fp).scan(&FsUninstaller);
    let c = by_path(&found, dir);
    assert_eq!(c.blockers, [Blocker::UnmatchedChildren { n: 1 }]);
}
