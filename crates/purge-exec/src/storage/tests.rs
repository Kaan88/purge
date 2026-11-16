//! Temp-dir tests of the store under the relaxed policy. Everything happens below a fresh directory in
//! `%TEMP%` that each test creates and removes; nothing touches `C:\ProgramData\Purge`.

use super::*;
use std::process::Command;

/// A unique scratch directory under `std::env::temp_dir()`, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!(
            "purge-store-{tag}-{}-{:016x}",
            std::process::id(),
            sys::random_u64()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // remove_dir_all removes junctions as links and never enters them.
        let _ = std::fs::remove_dir_all(secure::extended_path(&self.0).unwrap());
    }
}

fn junction(link: &Path, target: &Path) {
    let status = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "mklink /J {}", link.display());
}

/// A target directory with a canary file; [`Canary::intact`] checks nothing was added or changed.
struct Canary(PathBuf);

impl Canary {
    fn new(dir: PathBuf) -> Canary {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("canary.txt"), b"canary").unwrap();
        Canary(dir)
    }

    fn intact(&self) {
        let names: Vec<String> = std::fs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["canary.txt"], "{}", self.0.display());
        assert_eq!(std::fs::read(self.0.join("canary.txt")).unwrap(), b"canary");
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn real_serial(path: &Path) -> u64 {
    purge_win::fs::file_id(path).unwrap().volume_serial
}

/// Asserts an integrity refusal for a reparse point at `path` that was renamed aside, and returns the
/// new name.
fn assert_renamed_reparse(err: &StorageError, path: &Path) -> PathBuf {
    let StorageError::Integrity {
        path: failed,
        failure,
        renamed_to,
        rename_error,
    } = err
    else {
        panic!("expected an integrity refusal, got {err}");
    };
    assert!(
        same_path(failed, path),
        "{} vs {}",
        failed.display(),
        path.display()
    );
    assert!(
        matches!(failure, IntegrityFailure::ReparsePoint { .. }),
        "{failure}"
    );
    assert_eq!(*rename_error, None);
    let to = renamed_to.clone().expect("renamed aside");
    assert_eq!(to.parent(), path.parent());
    let leaf = to.file_name().unwrap().to_string_lossy().into_owned();
    let prefix = format!("{}.rejected-", path.file_name().unwrap().to_string_lossy());
    assert!(leaf.starts_with(&prefix), "{leaf}");
    // The link itself was moved: it is still a reparse point under its new name.
    assert_ne!(purge_win::fs::metadata(&to).unwrap().reparse_tag, 0);
    assert!(!path.exists());
    assert!(err.to_string().contains("renamed aside"), "{err}");
    to
}

/// Volume facts by path prefix; the longest matching prefix wins.
#[derive(Debug)]
struct FakeVolumes(Vec<VolumeFacts>);

impl VolumeProbe for FakeVolumes {
    fn volume(&self, path: &Path) -> Result<VolumeFacts, FsError> {
        let text = format!(r"{}\", plain(path).to_string_lossy().to_lowercase());
        self.0
            .iter()
            .filter(|v| {
                let root = v.root.to_string_lossy().to_lowercase();
                text.starts_with(&format!(r"{}\", root.trim_end_matches('\\')))
            })
            .max_by_key(|v| v.root.as_os_str().len())
            .cloned()
            .ok_or(FsError::NotFound)
    }
}

fn fake_volume(root: &Path, fixed: bool, fs: &str, total: u64) -> VolumeFacts {
    VolumeFacts {
        root: root.to_path_buf(),
        fixed,
        fs_name: fs.to_owned(),
        total_bytes: total,
    }
}

/// A relaxed store at `<scratch>\data`, with the data root on fake volume `<scratch>`, a second fake
/// volume `<scratch>\volb`, a FAT volume and a removable one.
fn fixture(tag: &str) -> (Scratch, StorageRoots) {
    let s = Scratch::new(tag);
    for vol in ["volb", "volfat", "volusb"] {
        std::fs::create_dir(s.path(vol)).unwrap();
    }
    let probe = FakeVolumes(vec![
        fake_volume(&s.0, true, "NTFS", 100 << 30),
        fake_volume(&s.path("volb"), true, "ReFS", 1000 << 30),
        fake_volume(&s.path("volfat"), true, "FAT32", 1 << 30),
        fake_volume(&s.path("volusb"), false, "NTFS", 1 << 30),
    ]);
    let roots = StorageRoots::install_relaxed(&s.path("data"))
        .unwrap()
        .with_volume_probe(Arc::new(probe));
    (s, roots)
}

#[test]
fn constructors_refuse_paths_that_are_not_absolute_drive_paths() {
    for bad in [
        r"relative\data",
        r"C:data",
        r"\\server\share\Purge",
        r"C:\",
        r"C:\a\..\b",
        "",
    ] {
        assert!(
            matches!(
                StorageRoots::new(Path::new(bad)),
                Err(StorageError::InvalidPath(_))
            ),
            "{bad:?}"
        );
    }
    let roots = StorageRoots::new(Path::new(r"\\?\C:\ProgramData\Purge")).unwrap();
    assert_eq!(roots.data_root(), Path::new(r"C:\ProgramData\Purge"));
    assert!(roots.policy().is_strict());
    assert_eq!(
        roots.sessions_path(),
        Path::new(r"C:\ProgramData\Purge\sessions")
    );
    assert_eq!(
        roots.quarantine_path(),
        Path::new(r"C:\ProgramData\Purge\Quarantine")
    );
    assert_eq!(
        roots.index_path(),
        Path::new(r"C:\ProgramData\Purge\sessions\index.json")
    );
    // Only computes the path; nothing is opened.
    let installed = StorageRoots::installed().unwrap();
    assert!(installed.data_root().ends_with("Purge") && installed.policy().is_strict());
}

#[test]
fn relaxed_install_creates_the_installer_layout() {
    let (s, roots) = fixture("layout");
    assert!(!roots.policy().is_strict());
    assert_eq!(names(&s.path("data")), ["Quarantine", "sessions"]);
    assert_eq!(names(&roots.sessions_path()), ["index.json"]);
    assert_eq!(std::fs::read(roots.index_path()).unwrap(), b"{}");
    roots.check().unwrap();
    // A second install over an existing tree is refused, never adopted.
    assert!(StorageRoots::install_relaxed(&s.path("data")).is_err());

    // The descriptors are the constants minus the owner, plus the test user.
    let sddl = |p: &Path| secure::handle_sddl(&secure::open_for_security(p).unwrap()).unwrap();
    let index = sddl(&roots.index_path());
    assert!(
        index.contains("D:P") && index.contains("(A;;FR;;;BU)"),
        "{index}"
    );
    let root = sddl(roots.data_root());
    assert!(root.contains("(A;;0x100020;;;BU)"), "{root}");
    assert!(!sddl(&roots.quarantine_path()).contains(";BU)"));
}

#[test]
fn missing_data_root_is_not_installed_and_missing_children_are_recreated() {
    let s = Scratch::new("missing");
    let roots = StorageRoots::relaxed(&s.path("data")).unwrap();
    assert_eq!(
        roots.check(),
        Err(StorageError::NotInstalled(s.path("data")))
    );
    assert!(matches!(
        roots.create_session(),
        Err(StorageError::NotInstalled(_))
    ));

    let roots = StorageRoots::install_relaxed(&s.path("data")).unwrap();
    std::fs::remove_dir(roots.quarantine_path()).unwrap();
    std::fs::remove_file(roots.index_path()).unwrap();
    std::fs::remove_dir(roots.sessions_path()).unwrap();
    roots.check().unwrap();
    assert_eq!(names(&s.path("data")), ["Quarantine", "sessions"]);
    // A missing index reads as empty.
    assert_eq!(roots.read_index().unwrap(), SessionIndex::default());
}

#[test]
fn strict_policy_refuses_and_renames_aside_a_tree_owned_by_a_user() {
    let (s, relaxed) = fixture("strict");
    drop(relaxed);
    let strict = StorageRoots::new(&s.path("data")).unwrap();
    let err = strict.check().unwrap_err();
    let StorageError::Integrity {
        failure,
        renamed_to,
        ..
    } = &err
    else {
        panic!("{err}");
    };
    // Unelevated, the owner is the test user, never Administrators or SYSTEM.
    assert!(
        matches!(failure, IntegrityFailure::Owner { .. }),
        "{failure}"
    );
    let to = renamed_to.clone().unwrap();
    assert!(!s.path("data").exists());
    // Renamed, not recursed into or deleted: the tree is intact under its new name.
    assert_eq!(names(&to), ["Quarantine", "sessions"]);
    assert_eq!(
        std::fs::read(to.join(r"sessions\index.json")).unwrap(),
        b"{}"
    );
}

#[test]
fn junction_at_the_data_root_is_detected_before_any_write() {
    let s = Scratch::new("jroot");
    let canary = Canary::new(s.path("elsewhere"));
    junction(&s.path("data"), &canary.0);
    let roots = StorageRoots::relaxed(&s.path("data")).unwrap();
    let err = roots.create_session().unwrap_err();
    assert_renamed_reparse(&err, &s.path("data"));
    canary.intact();
    // The next use finds nothing there: not installed.
    assert!(matches!(roots.check(), Err(StorageError::NotInstalled(_))));
}

#[test]
fn junction_at_sessions_or_quarantine_is_detected_before_any_write() {
    for child in [SESSIONS_DIR, QUARANTINE_DIR] {
        let (s, roots) = fixture("jchild");
        let canary = Canary::new(s.path("elsewhere"));
        let path = s.path("data").join(child);
        if child == SESSIONS_DIR {
            std::fs::remove_file(roots.index_path()).unwrap();
        }
        std::fs::remove_dir(&path).unwrap();
        junction(&path, &canary.0);
        let err = roots.create_session().unwrap_err();
        assert_renamed_reparse(&err, &path);
        canary.intact();
        // The next use recreates the directory and works.
        roots.create_session().unwrap();
        canary.intact();
    }
}

#[test]
fn junction_at_a_session_dir_is_detected_on_every_use() {
    let (s, roots) = fixture("jsession");
    let session = roots.create_session().unwrap();
    let id = session.id().clone();
    let canary = Canary::new(s.path("elsewhere"));
    // Swap the session directory for a junction after it was opened.
    let real = session.path().to_path_buf();
    std::fs::rename(&real, s.path("moved-session")).unwrap();
    junction(&real, &canary.0);

    let err = session.create_file(JOURNAL_FILE).unwrap_err();
    let first = assert_renamed_reparse(&err, &real);
    canary.intact();
    assert!(matches!(
        roots.open_session(&id),
        Err(StorageError::SessionNotFound(_))
    ));

    // Planted again, it is caught by open_session and by the listing.
    junction(&real, &canary.0);
    let err = roots.open_session(&id).unwrap_err();
    let second = assert_renamed_reparse(&err, &real);
    assert_ne!(first, second);
    junction(&real, &canary.0);
    let listing = roots.list_sessions().unwrap();
    assert!(listing.sessions.is_empty());
    assert_eq!(listing.rejected.len(), 1);
    assert_renamed_reparse(&listing.rejected[0], &real);
    canary.intact();
}

#[test]
fn session_dir_replaced_by_another_directory_is_refused_without_rename() {
    let (s, roots) = fixture("replaced");
    let session = roots.create_session().unwrap();
    let real = session.path().to_path_buf();
    std::fs::rename(&real, s.path("moved-session")).unwrap();
    // A directory that passes every check, but is not the one opened.
    assert!(roots.make_dir(&real, ObjectKind::Store).unwrap());
    let err = session.recheck().unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Integrity {
                failure: IntegrityFailure::IdentityChanged,
                renamed_to: None,
                ..
            }
        ),
        "{err}"
    );
    assert!(real.exists());
}

#[test]
fn junctions_inside_the_quarantine_are_detected_before_any_move() {
    let (s, roots) = fixture("jquarantine");
    let session = roots.create_session().unwrap();
    let serial = real_serial(&s.0);
    let source = s.path(r"app\file.txt");
    let canary = Canary::new(s.path("elsewhere"));

    // Quarantine\<session> planted before the first op directory.
    let q_session = roots.quarantine_path().join(session.id().as_str());
    junction(&q_session, &canary.0);
    let err = session.create_op_dir(&source, serial, OpId(1)).unwrap_err();
    assert_renamed_reparse(&err, &q_session);
    canary.intact();

    // The op directory itself planted: create-new refuses and renames it aside.
    let op_path = q_session.join(OpId(1).file_stem());
    assert!(roots.make_dir(&q_session, ObjectKind::Store).unwrap());
    junction(&op_path, &canary.0);
    let err = session.create_op_dir(&source, serial, OpId(1)).unwrap_err();
    assert_renamed_reparse(&err, &op_path);
    canary.intact();

    // A fresh op directory works, and a second create of the same op is refused, never adopted.
    let op = session.create_op_dir(&source, serial, OpId(1)).unwrap();
    assert_eq!(op.root(), &QuarantineRoot::DataRoot);
    assert_eq!(op.path(), op_path);
    assert_eq!(op.volume_serial(), serial);
    assert_eq!(
        session.create_op_dir(&source, serial, OpId(1)).unwrap_err(),
        StorageError::OpDirExists(op_path.clone())
    );
    let item = op.item_path("file.txt");
    drop(op);

    // Reopening it for undo checks the chain again; a junction swapped in is caught.
    let (reopened, leaf) = session.open_op_dir(&item, OpId(1), serial).unwrap();
    assert_eq!(
        (reopened.path(), leaf.as_str()),
        (op_path.as_path(), "file.txt")
    );
    drop(reopened);
    std::fs::remove_dir(&op_path).unwrap();
    junction(&op_path, &canary.0);
    let err = session.open_op_dir(&item, OpId(1), serial).unwrap_err();
    assert_renamed_reparse(&err, &op_path);
    canary.intact();
}

#[test]
fn op_dir_receives_a_handle_rename_on_the_same_volume() {
    let (s, roots) = fixture("move");
    let session = roots.create_session().unwrap();
    std::fs::create_dir(s.path("app")).unwrap();
    let source = s.path(r"app\file. ");
    std::fs::write(secure::extended_path(&source).unwrap(), b"payload").unwrap();
    let mover = MoveHandle::open(&source).unwrap();
    let serial = mover.file_id().unwrap().volume_serial;
    let op = session.create_op_dir(&source, serial, OpId(7)).unwrap();
    mover.rename_into(&op, "file. ").unwrap();
    let moved = op.item_path("file. ");
    assert_eq!(
        std::fs::read(secure::extended_path(&moved).unwrap()).unwrap(),
        b"payload"
    );
    assert!(op.path().ends_with(format!(r"{}\000007", session.id())));
    assert!(same_path(Path::new(op.dir().final_path()), op.path()));
}

#[test]
fn wrong_volume_is_detected_by_serial() {
    let (s, roots) = fixture("wrongvol");
    let session = roots.create_session().unwrap();
    let serial = real_serial(&s.0);
    // A source handle that reports another serial than the quarantine directory, on the data
    // root's volume and on another volume.
    for (op, source) in [(1, s.path(r"app\a.txt")), (2, s.path(r"volb\app\a.txt"))] {
        let err = session
            .create_op_dir(&source, serial ^ 1, OpId(op))
            .unwrap_err();
        assert_eq!(
            err,
            StorageError::CannotBackUp {
                path: source.clone(),
                reason: CannotBackUpReason::WrongVolume {
                    source_serial: serial ^ 1,
                    quarantine_serial: serial,
                },
            }
        );
    }
    // A recorded serial that differs on reopen.
    let op = session
        .create_op_dir(&s.path(r"app\b.txt"), serial, OpId(3))
        .unwrap();
    let item = op.item_path("b.txt");
    drop(op);
    assert!(matches!(
        session.open_op_dir(&item, OpId(3), serial ^ 1),
        Err(StorageError::VolumeMismatch { .. })
    ));
}

#[test]
fn unsuitable_volumes_cannot_back_up() {
    let (s, roots) = fixture("unsuitable");
    let session = roots.create_session().unwrap();
    let serial = real_serial(&s.0);
    let reason = |p: &Path| match session.create_op_dir(p, serial, OpId(1)) {
        Err(StorageError::CannotBackUp { reason, .. }) => reason,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        reason(&s.path(r"volfat\x")),
        CannotBackUpReason::FileSystem("FAT32".into())
    );
    assert_eq!(reason(&s.path(r"volusb\x")), CannotBackUpReason::NotFixed);
    // A path on no known volume.
    assert!(matches!(
        reason(Path::new(r"Q:\nowhere\x")),
        CannotBackUpReason::Store(_)
    ));
    assert!(!s.path(r"volfat\.purge-q").exists() && !s.path(r"volusb\.purge-q").exists());
}

#[test]
fn volume_quarantine_is_created_hidden_and_a_precreated_one_is_never_adopted() {
    let (s, roots) = fixture("purgeq");
    let session = roots.create_session().unwrap();
    let serial = real_serial(&s.0);
    let purge_q = s.path(r"volb\.purge-q");
    let source = s.path(r"volb\app\a.txt");
    let inner_error = |err: &StorageError| -> StorageError {
        match err {
            StorageError::CannotBackUp {
                reason: CannotBackUpReason::Store(inner),
                ..
            } => inner.as_ref().clone(),
            other => panic!("{other}"),
        }
    };

    // Pre-created by someone else and held open without delete sharing: it cannot be renamed aside,
    // so the volume is refused, with the step and the Win32 error.
    std::fs::create_dir(&purge_q).unwrap();
    std::fs::write(purge_q.join("planted.txt"), b"x").unwrap();
    let held = open_dir_without_delete_sharing(&purge_q);
    let err = session.create_op_dir(&source, serial, OpId(1)).unwrap_err();
    let inner = inner_error(&err);
    let StorageError::Integrity {
        failure,
        renamed_to: None,
        rename_error: Some(rename_error),
        ..
    } = &inner
    else {
        panic!("{inner}");
    };
    assert_eq!(failure, &IntegrityFailure::UnprotectedDacl);
    assert_eq!(*rename_error, FsError::SharingViolation);
    let text = err.to_string();
    assert!(
        text.contains("renaming it aside failed") && text.contains("Win32 error 32"),
        "{text}"
    );
    drop(held);
    assert_eq!(names(&purge_q), ["planted.txt"]);

    // Once it can be renamed: never adopted, renamed aside with its content, and the store makes its
    // own in its place in the same use.
    let op = session.create_op_dir(&source, serial, OpId(1)).unwrap();
    let aside: Vec<String> = names(&s.path("volb"))
        .into_iter()
        .filter(|n| n.starts_with(".purge-q.rejected-"))
        .collect();
    assert_eq!(aside.len(), 1, "{aside:?}");
    assert_eq!(names(&s.path("volb").join(&aside[0])), ["planted.txt"]);
    assert_eq!(names(&purge_q), [session.id().as_str()]);
    assert_eq!(
        op.path(),
        purge_q.join(session.id().as_str()).join("000001")
    );
    let item = op.item_path("a.txt");
    drop(op);

    // Attributes stripped by someone are restored on the next use.
    MoveHandle::open_with_attribute_write(&purge_q)
        .unwrap()
        .set_attributes(0, VOLUME_QUARANTINE_ATTRIBUTES)
        .unwrap();
    session.create_op_dir(&source, serial, OpId(2)).unwrap();
    let attrs = purge_win::fs::metadata(&purge_q).unwrap().attributes;
    assert_eq!(
        attrs & VOLUME_QUARANTINE_ATTRIBUTES,
        VOLUME_QUARANTINE_ATTRIBUTES
    );

    let (reopened, leaf) = session.open_op_dir(&item, OpId(1), serial).unwrap();
    assert_eq!(leaf, "a.txt");
    assert_eq!(
        reopened.root(),
        &QuarantineRoot::Volume {
            root: s.path("volb")
        }
    );
}

/// A handle on the directory `path` that shares read and write but not delete.
fn open_dir_without_delete_sharing(path: &Path) -> File {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0x1 | 0x2)
        .custom_flags(0x0200_0000)
        .open(path)
        .unwrap()
}

#[test]
fn a_planted_volume_quarantine_junction_is_renamed_aside_and_replaced() {
    let (s, roots) = fixture("purgeqj");
    let session = roots.create_session().unwrap();
    let serial = real_serial(&s.0);
    let purge_q = s.path(r"volb\.purge-q");
    let source = s.path(r"volb\app\a.txt");
    let canary = Canary::new(s.path("elsewhere"));
    junction(&purge_q, &canary.0);

    // The junction is moved aside as a link and a fresh `.purge-q` takes its name: hidden, system,
    // not indexed, nothing written through the link.
    let op = session.create_op_dir(&source, serial, OpId(1)).unwrap();
    assert_eq!(
        op.root(),
        &QuarantineRoot::Volume {
            root: s.path("volb")
        }
    );
    assert_eq!(
        op.path(),
        purge_q.join(session.id().as_str()).join("000001")
    );
    let attrs = purge_win::fs::metadata(&purge_q).unwrap().attributes;
    assert_eq!(
        attrs & VOLUME_QUARANTINE_ATTRIBUTES,
        VOLUME_QUARANTINE_ATTRIBUTES
    );
    assert_eq!(purge_win::fs::metadata(&purge_q).unwrap().reparse_tag, 0);
    canary.intact();
    let aside: Vec<PathBuf> = names(&s.path("volb"))
        .into_iter()
        .filter(|n| n.starts_with(".purge-q.rejected-"))
        .map(|n| s.path("volb").join(n))
        .collect();
    assert_eq!(aside.len(), 1, "{aside:?}");
    assert_ne!(purge_win::fs::metadata(&aside[0]).unwrap().reparse_tag, 0);
    // Opening it for undo finds the store's own.
    let item = op.item_path("a.txt");
    drop(op);
    session.open_op_dir(&item, OpId(1), serial).unwrap();
}

#[test]
fn open_op_dir_accepts_only_this_sessions_quarantine_paths() {
    let (s, roots) = fixture("opshape");
    let session = roots.create_session().unwrap();
    let serial = real_serial(&s.0);
    let op = session
        .create_op_dir(&s.path(r"app\a"), serial, OpId(3))
        .unwrap();
    let good = op.item_path("a");
    drop(op);
    session.open_op_dir(&good, OpId(3), serial).unwrap();
    let other = SessionId::new(sys::now(), 1);
    let q = roots.quarantine_path();
    let id = session.id().as_str();
    for bad in [
        q.join(other.as_str()).join("000003").join("a"),
        q.join(id).join("000004").join("a"),
        q.join(id).join("000003"),
        s.path("app").join(id).join("000003").join("a"),
        s.path(r"volb\app").join(id).join("000003").join("a"),
        PathBuf::from(r"relative\000003\a"),
    ] {
        assert!(
            matches!(
                session.open_op_dir(&bad, OpId(3), serial),
                Err(StorageError::InvalidPath(_))
            ),
            "{}",
            bad.display()
        );
    }
    // Shaped right, but nothing there.
    let missing = q.join(id).join("000009").join("a");
    assert!(matches!(
        session.open_op_dir(&missing, OpId(9), serial),
        Err(StorageError::Io {
            source: FsError::NotFound,
            ..
        })
    ));
}

#[test]
fn session_files_are_created_new_and_checked_on_open() {
    let (_s, roots) = fixture("files");
    let session = roots.create_session().unwrap();
    let started = session.id().started().to_unix_secs();
    assert!((sys::now().to_unix_secs() - started).abs() < 120);
    let mut file = session.create_file(JOURNAL_FILE).unwrap();
    file.write_all(b"{}\n").unwrap();
    let path = file.report_path();
    let created_id = file.file_id();
    drop(file);
    assert_eq!(path, session.path().join(JOURNAL_FILE));
    let mut opened = session.open_file(JOURNAL_FILE).unwrap();
    assert_eq!(opened.report_path(), path);
    assert_eq!(opened.file_id(), created_id);
    assert_eq!(opened.len_at_open(), 3);
    assert_eq!(opened.read_all(16).unwrap(), b"{}\n");
    drop(opened);
    assert!(matches!(
        session.create_file(JOURNAL_FILE),
        Err(StorageError::Io {
            source: FsError::AlreadyExists,
            ..
        })
    ));

    let rel = backup_rel(BackupKind::Registry, OpId(42));
    assert_eq!(rel, r"reg\000042.regbackup.json");
    assert_eq!(
        backup_rel(BackupKind::Definition, OpId(7)),
        r"def\000007.json"
    );
    let backup = session.create_file(&rel).unwrap();
    assert_eq!(
        backup.report_path(),
        session.path().join(r"reg\000042.regbackup.json")
    );
    assert_eq!(backup.rel(), rel);
    drop(backup);
    session.open_file(&rel).unwrap();
    assert!(matches!(
        session.open_file(r"def\000001.json"),
        Err(StorageError::Io {
            source: FsError::NotFound,
            ..
        })
    ));

    for bad in [
        "",
        r"..\index.json",
        r"reg\..\x",
        r"C:\x",
        "a/b",
        r"other\x",
        r"reg\sub\x",
        "x.",
        r"\x",
        "x:stream",
        "na me",
        "reg",
        "def",
    ] {
        assert!(
            matches!(session.create_file(bad), Err(StorageError::InvalidPath(_))),
            "{bad:?}"
        );
        assert!(
            matches!(session.open_file(bad), Err(StorageError::InvalidPath(_))),
            "{bad:?}"
        );
    }

    // A hard link to a session file is refused: a second name could live anywhere.
    std::fs::hard_link(&path, session.path().join(REPORT_FILE)).unwrap();
    let err = session.open_file(REPORT_FILE).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Integrity {
                failure: IntegrityFailure::HardLinked { n_links: 2 },
                renamed_to: Some(_),
                ..
            }
        ),
        "{err}"
    );

    // Sessions list in id order.
    let second = roots.create_session().unwrap();
    let listing = roots.list_sessions().unwrap();
    let mut expected = vec![session.id().clone(), second.id().clone()];
    expected.sort();
    assert_eq!(listing.sessions, expected);
    assert!(listing.rejected.is_empty());
    assert_eq!(
        roots.open_session(session.id()).unwrap().dir().file_id(),
        session.dir().file_id()
    );
}

fn summary(id: SessionId, serial: u64, bytes: u64) -> purge_model::exec::session::SessionSummary {
    use purge_model::exec::session::{Expiry, SessionState, SessionSummary};
    SessionSummary {
        started: id.started(),
        expires: Expiry::from_start(id.started()),
        id,
        app: "app".into(),
        owner: None,
        plan_hash: purge_model::exec::op::Sha256Hex([7; 32]),
        state: SessionState::Committed,
        finished: None,
        counts: Default::default(),
        undone: 0,
        backup_bytes: bytes,
        usage: vec![VolumeUsage {
            serial,
            root: String::new(),
            bytes,
        }],
        purged: Vec::new(),
        pending_reboot: false,
        journal: None,
    }
}

#[test]
fn index_round_trips_and_keeps_its_descriptor() {
    let (_s, roots) = fixture("index");
    assert_eq!(roots.read_index().unwrap(), SessionIndex::default());
    let session = roots.create_session().unwrap();
    let written = roots
        .update_index(|index| index.upsert(summary(session.id().clone(), 5, 1234)))
        .unwrap();
    assert_eq!(roots.read_index().unwrap(), written);
    assert_eq!(written.bytes_on_volume(5), 1234);
    let sec =
        secure::handle_security(&secure::open_for_security(&roots.index_path()).unwrap()).unwrap();
    assert!(
        sec.dacl_protected && sec.sddl.contains("(A;;FR;;;BU)"),
        "{}",
        sec.sddl
    );
    // The index and the session directory; no temporary file stays behind.
    assert_eq!(names(&roots.sessions_path()).len(), 2);

    // A BOM is tolerated; garbage is a typed error, never an empty index.
    let bytes = std::fs::read(roots.index_path()).unwrap();
    std::fs::write(
        roots.index_path(),
        [b"\xEF\xBB\xBF".as_slice(), &bytes].concat(),
    )
    .unwrap();
    assert_eq!(roots.read_index().unwrap(), written);
    std::fs::write(roots.index_path(), b"{\"sessions\":[").unwrap();
    assert!(matches!(
        roots.read_index(),
        Err(StorageError::IndexMalformed { .. })
    ));
    assert!(matches!(
        roots.update_index(|_| {}),
        Err(StorageError::IndexMalformed { .. })
    ));
    std::fs::write(roots.index_path(), b"{\"schema\":\"purge.sessions/9\"}").unwrap();
    assert!(matches!(
        roots.read_index(),
        Err(StorageError::IndexMalformed { .. })
    ));
    roots.write_index(&written).unwrap();
    assert_eq!(roots.read_index().unwrap(), written);
}

#[test]
fn index_survives_a_crash_between_temp_write_and_rename() {
    let (_s, roots) = fixture("atomic");
    let a = SessionId::new(purge_model::FileTime::from_unix_secs(1_794_737_702), 1);
    let b = SessionId::new(purge_model::FileTime::from_unix_secs(1_794_737_703), 2);
    let mut old = SessionIndex::default();
    old.upsert(summary(a, 1, 10));
    roots.write_index(&old).unwrap();
    let mut new = old.clone();
    new.upsert(summary(b, 1, 20));

    // The "crash": the temporary file is complete and flushed, the rename never happens.
    let crash = || StorageError::Io {
        op: "crash",
        path: PathBuf::new(),
        source: FsError::Other(0),
    };
    let err = roots
        .write_index_with(&new, &mut |step| {
            assert_eq!(step, IndexStep::TempWritten);
            Err(crash())
        })
        .unwrap_err();
    assert_eq!(err, crash());
    let temp = roots.sessions_path().join(INDEX_TEMP_FILE);
    assert!(temp.exists());
    // Readers see the old index, whole.
    assert_eq!(roots.read_index().unwrap(), old);
    // The next write removes the leftover and replaces the index.
    roots.write_index(&new).unwrap();
    assert_eq!(roots.read_index().unwrap(), new);
    assert!(!temp.exists());

    // A torn temporary file (a crash in the middle of the write) changes nothing either.
    let mut torn =
        fs_write::create_file_secure(&temp, &roots.policy().sddl_for(ObjectKind::Index)).unwrap();
    torn.write_all(b"{\"schema\":\"purge.sess").unwrap();
    drop(torn);
    assert_eq!(roots.read_index().unwrap(), new);
    roots.write_index(&old).unwrap();
    assert_eq!(roots.read_index().unwrap(), old);

    // A temporary name taken by something that is not Purge's own file refuses the write.
    let canary = Canary::new(roots.data_root().parent().unwrap().join("elsewhere"));
    junction(&temp, &canary.0);
    let err = roots.write_index(&new).unwrap_err();
    assert_renamed_reparse(&err, &temp);
    canary.intact();
    assert_eq!(roots.read_index().unwrap(), old);
}

#[test]
fn planted_index_objects_are_refused_and_renamed_aside() {
    let (s, roots) = fixture("badindex");
    let index = roots.index_path();
    // A directory where the index belongs.
    std::fs::remove_file(&index).unwrap();
    std::fs::create_dir(&index).unwrap();
    let err = roots.read_index().unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Integrity {
                failure: IntegrityFailure::WrongKind {
                    expected_dir: false
                },
                renamed_to: Some(_),
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(roots.read_index().unwrap(), SessionIndex::default());

    // A second name for the index elsewhere: refused, and the outside name is untouched.
    roots.write_index(&SessionIndex::default()).unwrap();
    std::fs::hard_link(&index, s.path("outside.json")).unwrap();
    assert!(matches!(
        roots.write_index(&SessionIndex::default()),
        Err(StorageError::Integrity {
            failure: IntegrityFailure::HardLinked { .. },
            ..
        })
    ));
    assert_eq!(
        std::fs::read(s.path("outside.json")).unwrap(),
        br#"{"schema":"purge.sessions/1","sessions":[]}"#
    );

    // A file written by an ordinary tool (inherited, unprotected DACL).
    std::fs::write(&index, b"{}").unwrap();
    assert!(matches!(
        roots.read_index(),
        Err(StorageError::Integrity {
            failure: IntegrityFailure::UnprotectedDacl,
            ..
        })
    ));
}

#[test]
fn cap_check_uses_the_volume_size() {
    let (s, roots) = fixture("cap");
    let mut index = SessionIndex::default();
    index.upsert(summary(SessionId::new(sys::now(), 3), 9, 4 << 30));
    let planned = |bytes| VolumeUsage {
        serial: 9,
        root: s.0.display().to_string(),
        bytes,
    };
    // The fake data volume has 100 GiB: cap 5 GiB, 4 GiB held.
    roots.check_cap(&index, &[planned(1 << 30)]).unwrap();
    let err = roots
        .check_cap(&index, &[planned((1 << 30) + 1)])
        .unwrap_err();
    let StorageError::Cap(cap) = err else {
        panic!("{err}")
    };
    assert_eq!(
        (cap.held, cap.cap, cap.volume_total),
        (4 << 30, 5 << 30, 100 << 30)
    );
    // On the real temp volume.
    let real = StorageRoots::relaxed(&s.path("data")).unwrap();
    let root = purge_win::fs::volume_info(&s.0).unwrap().root;
    real.check_cap(
        &SessionIndex::default(),
        &[VolumeUsage {
            serial: 1,
            root,
            bytes: 1,
        }],
    )
    .unwrap();
}

#[test]
fn system_volumes_report_the_temp_volume() {
    let temp = std::env::temp_dir();
    let facts = SystemVolumes.volume(&temp).unwrap();
    assert!(facts.fixed, "{facts:?}");
    assert!(facts.quarantine_capable().is_ok(), "{facts:?}");
    assert!(facts.total_bytes > 1 << 30);
    assert!(facts.root.to_string_lossy().ends_with('\\'));
    let ext_form = SystemVolumes
        .volume(&secure::extended_path(&temp).unwrap())
        .unwrap();
    assert_eq!(ext_form.root, facts.root);
}

#[test]
fn layout_names_are_the_guards() {
    // Re-exported from the guard, so `StoreScope` derives the same directories the store creates.
    assert_eq!(SESSIONS_DIR, purge_guard::live::SESSIONS_DIR);
    assert_eq!(QUARANTINE_DIR, purge_guard::live::QUARANTINE_DIR);
    assert_eq!(
        VOLUME_QUARANTINE_DIR,
        purge_guard::live::VOLUME_QUARANTINE_DIR
    );
    assert_eq!(
        [SESSIONS_DIR, QUARANTINE_DIR, VOLUME_QUARANTINE_DIR],
        ["sessions", "Quarantine", ".purge-q"]
    );
}

#[test]
fn store_scope_covers_the_directories_the_store_creates() {
    let (s, roots) = fixture("scope");
    let session = roots.create_session().unwrap();
    let id = session.id().clone();
    let serial = real_serial(&s.0);
    let op = session
        .create_op_dir(&s.path(r"app\a.txt"), serial, OpId(1))
        .unwrap();
    let canonical = |p: &Path| plain(p).to_string_lossy().into_owned();

    // No other volume, or only the data root's own: the session directory and `Quarantine\<id>`.
    for volumes in [Vec::new(), vec![s.0.clone()]] {
        let scope = roots.store_scope(&id, &volumes).unwrap();
        assert_eq!(scope.session(), &id);
        assert!(same_path(Path::new(scope.session_dir()), session.path()));
        assert_eq!(scope.quarantine_dirs().len(), 1);
        assert!(same_path(
            Path::new(&scope.quarantine_dirs()[0]),
            op.path().parent().unwrap()
        ));
        assert!(scope.authorises(&canonical(&op.item_path("a.txt"))));
        assert!(scope.authorises(&canonical(&session.path().join(JOURNAL_FILE))));
        assert!(!scope.authorises(&canonical(&roots.index_path())));
    }

    // Another volume at a drive root: its `.purge-q\<id>` joins the scope (nothing is opened there).
    let scope = roots.store_scope(&id, &[Path::new(r"Z:\")]).unwrap();
    assert_eq!(scope.quarantine_dirs().len(), 2);
    assert!(same_path(
        Path::new(&scope.quarantine_dirs()[1]),
        &Path::new(r"Z:\.purge-q").join(id.as_str())
    ));
    assert!(scope.authorises(&format!(r"Z:\.purge-q\{id}\000001\a.txt")));
    assert!(!scope.authorises(r"Z:\.purge-q\other\000001\a.txt"));

    // A volume mounted in a folder (the fixture's fake volumes are): the guard accepts no
    // `.purge-q` below a drive root, so no scope is built.
    assert!(matches!(
        roots.store_scope(&id, &[s.path("volb")]),
        Err(StorageError::InvalidPath(_))
    ));
}

#[test]
fn path_helpers() {
    assert_eq!(plain(Path::new(r"\\?\C:\a")), Path::new(r"C:\a"));
    assert_eq!(plain(Path::new(r"\\?\UNC\s\x")), Path::new(r"\\s\x"));
    assert_eq!(plain(Path::new(r"C:\a")), Path::new(r"C:\a"));
    assert!(same_path(Path::new(r"\\?\C:\A\b\"), Path::new(r"c:\a\B")));
    assert!(!same_path(Path::new(r"C:\a\b"), Path::new(r"C:\a\bc")));
    for good in ["000001", "journal.jsonl", "x_y-z.json"] {
        assert!(is_store_name(good), "{good}");
    }
    for bad in ["", ".", "..", "a.", "a b", "a:b", "é", "a\\b"] {
        assert!(!is_store_name(bad), "{bad:?}");
    }
}

#[test]
#[ignore = "needs admin rights: creates objects owned by Administrators with the strict constants"]
fn strict_policy_accepts_an_install_shaped_tree() {
    let s = Scratch::new("strict-admin");
    let data = s.path("data");
    let strict = StorageRoots::new(&data).unwrap();
    assert!(strict.make_dir(&data, ObjectKind::DataRoot).unwrap());
    assert!(
        strict
            .make_dir(&strict.sessions_path(), ObjectKind::Sessions)
            .unwrap()
    );
    assert!(
        strict
            .make_dir(&strict.quarantine_path(), ObjectKind::Store)
            .unwrap()
    );
    let session = strict.create_session().unwrap();
    session.create_file(JOURNAL_FILE).unwrap();
    strict.write_index(&SessionIndex::default()).unwrap();
    let sec =
        secure::handle_security(&secure::open_for_security(&strict.index_path()).unwrap()).unwrap();
    assert_eq!(
        sec.owner.as_deref(),
        Some(purge_win::sid::ADMINISTRATORS_SID)
    );
    let serial = real_serial(&data);
    session
        .create_op_dir(&s.path(r"app\a"), serial, OpId(1))
        .unwrap();
}

#[test]
#[ignore = "needs a second fixed NTFS volume: set PURGE_TEST_OTHER_VOLUME_DIR to a writable directory on it (VM only)"]
fn other_volume_gets_its_own_hidden_quarantine() {
    let other = PathBuf::from(std::env::var_os("PURGE_TEST_OTHER_VOLUME_DIR").unwrap());
    let s = Scratch::new("xvol");
    let roots = StorageRoots::install_relaxed(&s.path("data")).unwrap();
    let session = roots.create_session().unwrap();
    let source = other.join(format!("purge-store-xvol-{:016x}.txt", sys::random_u64()));
    std::fs::write(&source, b"x").unwrap();
    let mover = MoveHandle::open(&source).unwrap();
    let serial = mover.file_id().unwrap().volume_serial;
    let op = session.create_op_dir(&source, serial, OpId(1)).unwrap();
    assert!(matches!(op.root(), QuarantineRoot::Volume { .. }));
    mover.rename_into(&op, "moved.txt").unwrap();
    assert!(op.item_path("moved.txt").exists());
    // Only this test's session directory goes; `.purge-q` itself stays.
    let session_q = op.path().parent().unwrap().to_path_buf();
    drop((op, mover));
    std::fs::remove_dir_all(&session_q).unwrap();
}

/// S1: a store file is read and written through the handle that was checked. While it is open, the
/// name cannot be pointed at another file; what is read is what was checked.
#[test]
fn store_files_are_used_through_the_checked_handle() {
    let (s, roots) = fixture("handle");
    let session = roots.create_session().unwrap();
    let rel = backup_rel(BackupKind::Registry, OpId(1));
    let mut file = session.create_file(&rel).unwrap();
    file.write_all(b"checked").unwrap();
    file.sync().unwrap();
    file.sync_dir().unwrap();
    assert_eq!(file.size().unwrap(), 7);
    let path = file.report_path();
    drop(file);

    let mut opened = session.open_file(&rel).unwrap();
    // Swapping the name for another file fails while the checked handle is open.
    std::fs::write(s.path("other.json"), b"planted").unwrap();
    assert!(std::fs::rename(s.path("other.json"), &path).is_err());
    assert!(std::fs::rename(&path, s.path("moved.json")).is_err());
    assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
    assert_eq!(opened.read_all(1 << 10).unwrap(), b"checked");
    drop(opened);

    // The reader's limit is checked before anything is read.
    let mut opened = session.open_file(&rel).unwrap();
    assert!(matches!(
        opened.read_all(6),
        Err(StorageError::TooLarge {
            bytes: 7,
            max: 6,
            ..
        })
    ));
    // Only a file the caller created can be discarded through its handle.
    assert!(matches!(
        opened.discard(),
        Err(StorageError::Io {
            source: FsError::WrongKind,
            ..
        })
    ));
    assert!(path.exists());
    let created = session
        .create_file(&backup_rel(BackupKind::Registry, OpId(2)))
        .unwrap();
    let created_path = created.report_path();
    created.discard().unwrap();
    assert!(!created_path.exists());
    // The name is free again.
    session
        .create_file(&backup_rel(BackupKind::Registry, OpId(2)))
        .unwrap();
}

/// M1: a process holding the index open without the sharing the store needs makes the index
/// busy, never malformed or replaced by an empty one.
#[test]
fn an_index_held_open_by_another_process_is_busy() {
    use std::os::windows::fs::OpenOptionsExt;
    let (_s, roots) = fixture("busy");
    let session = roots.create_session().unwrap();
    let written = roots
        .update_index(|index| index.upsert(summary(session.id().clone(), 5, 10)))
        .unwrap();

    // A reader that shares only reading: the index cannot be replaced.
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(roots.index_path())
        .unwrap();
    let err = roots
        .update_index(|index| index.upsert(summary(session.id().clone(), 5, 20)))
        .unwrap_err();
    assert!(matches!(err, StorageError::IndexBusy { .. }), "{err}");
    assert!(err.is_index_unavailable());
    drop(holder);
    assert_eq!(roots.read_index().unwrap(), written);

    // A holder that shares nothing: the index cannot be read either.
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(roots.index_path())
        .unwrap();
    let err = roots.read_index().unwrap_err();
    assert!(matches!(err, StorageError::IndexBusy { .. }), "{err}");
    drop(holder);
    assert_eq!(roots.read_index().unwrap(), written);
}

/// M2: an index that is missing while sessions exist (rejected and renamed aside, or deleted) is
/// lost, never read as an empty index; writing a rebuilt one ends that.
#[test]
fn a_missing_index_with_sessions_is_lost_not_empty() {
    let (s, roots) = fixture("lost");
    let session = roots.create_session().unwrap();
    let written = roots
        .update_index(|index| index.upsert(summary(session.id().clone(), 5, 10)))
        .unwrap();
    std::fs::hard_link(roots.index_path(), s.path("second-name.json")).unwrap();
    assert!(matches!(
        roots.read_index(),
        Err(StorageError::Integrity {
            failure: IntegrityFailure::HardLinked { .. },
            renamed_to: Some(_),
            ..
        })
    ));
    for _ in 0..2 {
        let err = roots.read_index().unwrap_err();
        assert!(matches!(err, StorageError::IndexLost { .. }), "{err}");
        assert!(err.is_index_unavailable());
    }
    assert!(matches!(
        roots.update_index(|_| {}),
        Err(StorageError::IndexLost { .. })
    ));
    assert!(!roots.index_path().exists());
    roots.write_index(&written).unwrap();
    assert_eq!(roots.read_index().unwrap(), written);

    // Without any session, a missing index is an empty one (a fresh install).
    let (_s, empty) = fixture("lost-empty");
    std::fs::remove_file(empty.index_path()).unwrap();
    assert_eq!(empty.read_index().unwrap(), SessionIndex::default());
}

/// M3: a volume root that is a reparse point is refused before anything is created through it.
#[test]
fn a_volume_root_that_is_a_junction_is_refused() {
    let (s, roots) = fixture("rootjx");
    let canary = Canary::new(s.path("elsewhere"));
    junction(&s.path("voljx"), &canary.0);
    let roots = roots.with_volume_probe(Arc::new(FakeVolumes(vec![
        fake_volume(&s.0, true, "NTFS", 100 << 30),
        fake_volume(&s.path("voljx"), true, "NTFS", 100 << 30),
    ])));
    let session = roots.create_session().unwrap();
    let err = session
        .create_op_dir(&s.path(r"voljx\app\a.txt"), real_serial(&s.0), OpId(1))
        .unwrap_err();
    assert!(
        matches!(
            &err,
            StorageError::CannotBackUp {
                reason: CannotBackUpReason::Store(inner),
                ..
            } if matches!(
                inner.as_ref(),
                StorageError::VolumeRoot {
                    failure: IntegrityFailure::ReparsePoint { .. },
                    ..
                }
            )
        ),
        "{err}"
    );
    canary.intact();
}

/// M4: `.purge-q` is created only at a volume root that nobody but Administrators and SYSTEM can
/// take it away from, and (under the strict policy) only at a drive root.
#[test]
fn a_volume_root_others_could_rearrange_gets_no_quarantine() {
    let (s, roots) = fixture("rootacl");
    let me = purge_win::sid::current_user_sid().unwrap();
    let root = s.path("volbu");
    // Users may delete children of the root: they could rename `.purge-q` away and plant another.
    fs_write::create_dir_secure(
        &secure::extended_path(&root).unwrap(),
        &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{me})(A;;0x100040;;;BU)"),
    )
    .unwrap();
    let roots = roots.with_volume_probe(Arc::new(FakeVolumes(vec![
        fake_volume(&s.0, true, "NTFS", 100 << 30),
        fake_volume(&root, true, "NTFS", 100 << 30),
    ])));
    let session = roots.create_session().unwrap();
    let err = session
        .create_op_dir(&root.join(r"app\a.txt"), real_serial(&s.0), OpId(1))
        .unwrap_err();
    assert!(
        matches!(
            &err,
            StorageError::CannotBackUp {
                reason: CannotBackUpReason::Store(inner),
                ..
            } if matches!(
                inner.as_ref(),
                StorageError::VolumeRoot {
                    failure: IntegrityFailure::ForeignAccess { sid: Some(sid), mask },
                    ..
                } if sid == "S-1-5-32-545" && mask & 0x40 != 0
            )
        ),
        "{err}"
    );
    assert_eq!(names(&root), Vec::<String>::new());

    // Under the strict policy a volume mounted in a folder gets no `.purge-q` at all; nothing on
    // disk is looked at.
    let SessionDir { id, dir, .. } = session;
    let strict = StorageRoots::new(roots.data_root())
        .unwrap()
        .with_volume_probe(Arc::new(FakeVolumes(vec![
            fake_volume(&s.0, true, "NTFS", 100 << 30),
            fake_volume(&s.path("volb"), true, "NTFS", 100 << 30),
        ])));
    let strict_session = SessionDir {
        roots: strict,
        id,
        dir,
    };
    assert_eq!(
        strict_session
            .create_op_dir(&s.path(r"volb\app\a.txt"), real_serial(&s.0), OpId(1))
            .unwrap_err(),
        StorageError::CannotBackUp {
            path: s.path(r"volb\app\a.txt"),
            reason: CannotBackUpReason::MountedFolder,
        }
    );
    assert_eq!(names(&s.path("volb")), Vec::<String>::new());
}

#[test]
fn a_quarantined_item_is_opened_through_the_op_dir_handle() {
    use std::os::windows::fs::OpenOptionsExt;
    let (s, roots) = fixture("openitem");
    let session = roots.create_session().unwrap();
    let serial = real_serial(&s.0);
    std::fs::create_dir(s.path("app")).unwrap();
    let source = s.path(r"app\held. ");
    std::fs::write(secure::extended_path(&source).unwrap(), b"payload").unwrap();
    let op = session.create_op_dir(&source, serial, OpId(7)).unwrap();
    MoveHandle::open(&source)
        .unwrap()
        .rename_into(&op, "held. ")
        .unwrap();
    let moved = op.item_path("held. ");
    let id = purge_win::fs::file_id(&secure::extended_path(&moved).unwrap()).unwrap();

    // Present: the facts come from the handle, which can rename.
    let item = op.open_item("held. ").unwrap().expect("present");
    assert_eq!(item.leaf(), "held. ");
    assert_eq!(item.file_id(), id);
    assert!(!item.is_dir());
    assert_eq!(item.reparse_tag(), 0);
    assert_eq!(item.n_links(), 1);
    assert_eq!(item.size(), 7);
    assert!(same_path(Path::new(item.final_path()), &moved));
    assert!(item.mover().is_some());
    drop(item);

    // Missing, and names that are not one plain component.
    assert!(op.open_item("gone.txt").unwrap().is_none());
    for bad in ["", "..", r"a\b", "a/b", "x:stream"] {
        assert!(
            matches!(op.open_item(bad), Err(StorageError::InvalidPath(_))),
            "{bad:?}"
        );
    }

    // In use without delete sharing: the facts, but no mover.
    let user = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1) // FILE_SHARE_READ
        .open(secure::extended_path(&moved).unwrap())
        .unwrap();
    let item = op.open_item("held. ").unwrap().expect("present");
    assert_eq!(item.file_id(), id);
    assert!(item.mover().is_none());
    assert!(item.into_mover().is_none());
    drop(user);

    // The mover renames the very object it was opened on.
    let mover = op
        .open_item("held. ")
        .unwrap()
        .unwrap()
        .into_mover()
        .unwrap();
    let back = session.create_op_dir(&source, serial, OpId(8)).unwrap();
    mover.rename_into(&back, "held. ").unwrap();
    drop(mover);
    assert!(op.open_item("held. ").unwrap().is_none());
    let renamed = back.open_item("held. ").unwrap().unwrap();
    assert_eq!(renamed.file_id(), id);

    // A directory and a junction are opened themselves, never followed.
    std::fs::create_dir(op.item_path("sub")).unwrap();
    let dir = op.open_item("sub").unwrap().unwrap();
    assert!(dir.is_dir());
    let canary = Canary::new(s.path("elsewhere"));
    junction(&op.item_path("link"), &canary.0);
    let link = op.open_item("link").unwrap().unwrap();
    assert_ne!(link.reparse_tag(), 0);
    assert!(same_path(
        Path::new(link.final_path()),
        &op.item_path("link")
    ));
    drop(link);
    canary.intact();
}

#[test]
fn an_unstarted_session_dir_is_removed_by_handle() {
    let (_s, roots) = fixture("unstarted");
    // Empty.
    let session = roots.create_session().unwrap();
    let path = session.path().to_path_buf();
    let id = session.id().clone();
    session.remove_unstarted().unwrap();
    assert!(!path.exists());
    assert!(roots.list_sessions().unwrap().sessions.is_empty());
    assert!(roots.open_session(&id).is_err());

    // Only the scan copy.
    let session = roots.create_session().unwrap();
    let path = session.path().to_path_buf();
    let mut scan = session.create_file(SCAN_FILE).unwrap();
    scan.write_all(b"{}").unwrap();
    drop(scan);
    session.remove_unstarted().unwrap();
    assert!(!path.exists());

    // The scan copy and a zero-byte journal (a crash before the header's first byte): removed, both
    // files by handle (M2 recovery fix pass; refused before).
    let session = roots.create_session().unwrap();
    let path = session.path().to_path_buf();
    session.create_file(SCAN_FILE).unwrap();
    session.create_file(JOURNAL_FILE).unwrap();
    session.remove_unstarted().unwrap();
    assert!(!path.exists());

    // A zero-byte journal alone: removed too.
    let session = roots.create_session().unwrap();
    let path = session.path().to_path_buf();
    session.create_file(JOURNAL_FILE).unwrap();
    session.remove_unstarted().unwrap();
    assert!(!path.exists());

    // A journal with a byte in it (the run started): refused, nothing deleted.
    let session = roots.create_session().unwrap();
    let path = session.path().to_path_buf();
    session.create_file(SCAN_FILE).unwrap();
    let mut journal = session.create_file(JOURNAL_FILE).unwrap();
    journal.write_all(b"{").unwrap();
    drop(journal);
    let err = session.remove_unstarted().unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Io {
                source: FsError::DirNotEmpty,
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(names(&path), [JOURNAL_FILE, SCAN_FILE]);

    // Any other entry, even without a journal: refused.
    let session = roots.create_session().unwrap();
    let path = session.path().to_path_buf();
    std::fs::write(path.join("stray.txt"), b"x").unwrap();
    assert!(matches!(
        session.remove_unstarted(),
        Err(StorageError::Io {
            source: FsError::DirNotEmpty,
            ..
        })
    ));
    assert_eq!(names(&path), ["stray.txt"]);

    // A scan copy that fails the store file check is renamed aside, not deleted, and the directory
    // stays.
    let session = roots.create_session().unwrap();
    let path = session.path().to_path_buf();
    session.create_file(SCAN_FILE).unwrap();
    std::fs::hard_link(path.join(SCAN_FILE), _s.path("outside.json")).unwrap();
    assert!(matches!(
        session.remove_unstarted(),
        Err(StorageError::Integrity {
            failure: IntegrityFailure::HardLinked { .. },
            ..
        })
    ));
    assert!(path.exists());
    assert!(_s.path("outside.json").exists());
}

#[test]
fn a_backup_file_is_deleted_by_handle() {
    let (s, roots) = fixture("delbackup");
    let session = roots.create_session().unwrap();
    // The `def` directory does not exist yet.
    let def = backup_rel(BackupKind::Definition, OpId(2));
    assert_eq!(session.delete_backup_file(&def).unwrap(), None);

    let rel = backup_rel(BackupKind::Registry, OpId(1));
    let mut file = session.create_file(&rel).unwrap();
    file.write_all(b"0123456789").unwrap();
    drop(file);
    let path = session.path().join(&rel);
    assert_eq!(session.delete_backup_file(&rel).unwrap(), Some(10));
    assert!(!path.exists());
    assert_eq!(session.delete_backup_file(&rel).unwrap(), None);

    let mut file = session.create_file(&def).unwrap();
    file.write_all(b"{}").unwrap();
    drop(file);
    assert_eq!(session.delete_backup_file(&def).unwrap(), Some(2));

    // Only files in `reg` and `def`.
    session.create_file(JOURNAL_FILE).unwrap();
    for bad in [
        JOURNAL_FILE,
        SCAN_FILE,
        REPORT_FILE,
        "",
        "reg",
        r"reg\..\journal.jsonl",
        r"other\x",
        r"reg\sub\x",
    ] {
        assert!(
            matches!(
                session.delete_backup_file(bad),
                Err(StorageError::InvalidPath(_))
            ),
            "{bad:?}"
        );
    }
    assert!(session.path().join(JOURNAL_FILE).exists());

    // A directory at the name fails the store file check: renamed aside, not deleted.
    let dir_rel = backup_rel(BackupKind::Registry, OpId(3));
    std::fs::create_dir(session.path().join(&dir_rel)).unwrap();
    let err = session.delete_backup_file(&dir_rel).unwrap_err();
    let StorageError::Integrity {
        failure: IntegrityFailure::WrongKind {
            expected_dir: false,
        },
        renamed_to: Some(aside),
        ..
    } = &err
    else {
        panic!("{err}");
    };
    assert!(aside.is_dir());

    // A file with a second name elsewhere fails the store file check: renamed aside, not deleted.
    let linked = backup_rel(BackupKind::Registry, OpId(4));
    session.create_file(&linked).unwrap();
    std::fs::hard_link(session.path().join(&linked), s.path("outside.json")).unwrap();
    let err = session.delete_backup_file(&linked).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Integrity {
                failure: IntegrityFailure::HardLinked { n_links: 2 },
                renamed_to: Some(_),
                ..
            }
        ),
        "{err}"
    );
    assert!(s.path("outside.json").exists());
    assert_eq!(std::fs::metadata(s.path("outside.json")).unwrap().len(), 0);
}
