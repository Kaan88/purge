//! FS-UNINSTALLER.

use purge_model::{Blocker, EvidenceKind, Root, RootKind, RootSource, SourceTrust};
use purge_scan::fs_uninstaller::FsUninstaller;

use crate::{SERIAL, World, by_path, firefox_fp, git_fp, golden, machine, paths};

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
