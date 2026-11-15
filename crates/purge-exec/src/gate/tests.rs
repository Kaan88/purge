//! Gate tests on real objects: fresh temp directories and a uniquely named
//! `HKU\<current SID>\Software\PurgeTest-<random>` key, both removed again. Junctions, hard links, swaps,
//! locks and placeholder attributes are built for real; TrustedInstaller ownership and volume types are
//! injected through [`HostFacts`].

use std::os::windows::fs::OpenOptionsExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use purge_guard::canon::{GuardEnv, ProfileEnv};
use purge_guard::live::reason as live_reason;
use purge_win::fs_write::{FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY};
use purge_win::reg::{REG_DWORD, REG_SZ};
use purge_win::sid::current_user_sid;

use super::*;

// ---------------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------------

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "{tag}-{:x}-{:x}-{}",
        std::process::id(),
        nanos,
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// A fresh directory below the temp directory, removed on drop (junctions are removed as links).
struct Scratch {
    root: String,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(unique(&format!("purge-gate-{tag}")));
        std::fs::create_dir(&dir).unwrap();
        let final_path = FileHandle::open(&dir).unwrap().final_path().unwrap();
        Scratch {
            root: strip_verbatim(&final_path).to_owned(),
        }
    }

    fn path(&self, rel: &str) -> String {
        format!(r"{}\{rel}", self.root)
    }

    fn dir(&self, rel: &str) -> String {
        let p = self.path(rel);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn file(&self, rel: &str, data: &[u8]) -> String {
        let p = self.path(rel);
        std::fs::create_dir_all(Path::new(&p).parent().unwrap()).unwrap();
        std::fs::write(&p, data).unwrap();
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Read-only files would stop the removal.
        let _ = Command::new("cmd")
            .args(["/c", "attrib", "-R", "-H", "-O", "/S", "/D"])
            .arg(format!(r"{}\*", self.root))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn junction(link: &str, target: &str) {
    let st = Command::new("cmd")
        .args(["/c", "mklink", "/J", link, target])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "mklink /J {link} {target}");
}

fn attrib(flags: &[&str], path: &str) {
    let st = Command::new("cmd")
        .args(["/c", "attrib"])
        .args(flags)
        .arg(path)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "attrib {flags:?} {path}");
}

fn env_var(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

/// A `GuardEnv` for this machine and user, with `extra_purge_dir` as one of Purge's directories.
fn live_env(extra_purge_dir: Option<&str>) -> GuardEnv {
    let sid = current_user_sid().unwrap();
    let profile = env_var("USERPROFILE");
    let set = purge_win::reg::current_control_set().unwrap();
    let mut purge_dirs = vec![format!(r"{}\Purge", env_var("ProgramData"))];
    purge_dirs.extend(extra_purge_dir.map(str::to_owned));
    GuardEnv {
        system_drive: env_var("SystemDrive"),
        windir: env_var("WINDIR"),
        program_files: env_var("ProgramW6432"),
        program_files_x86: Some(env_var("ProgramFiles(x86)")),
        program_data: env_var("ProgramData"),
        profiles_dir: Path::new(&profile)
            .parent()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        profiles: vec![ProfileEnv {
            sid: sid.clone(),
            root: profile,
            appdata: env_var("APPDATA"),
            local_appdata: env_var("LOCALAPPDATA"),
            ..ProfileEnv::default()
        }],
        current_control_set: set.trim_start_matches("ControlSet").parse().unwrap(),
        loaded_sids: vec![sid],
        purge_dirs,
        ..GuardEnv::default()
    }
}

/// **The one place** the tests build a [`StoreScope`]. Integration note: when it gets private fields and
/// a constructor from the store roots plus a session id, adapt this function alone.
fn store_scope(session_dir: String, quarantine_dirs: Vec<String>) -> StoreScope {
    StoreScope {
        session_dir,
        quarantine_dirs,
    }
}

/// A scope with no store directories: nothing is in this session's store.
fn no_store() -> StoreScope {
    store_scope(String::new(), Vec::new())
}

fn scope_in(s: &Scratch) -> StoreScope {
    store_scope(s.dir(r"store\sessions\S1"), vec![s.dir(r"store\q\S1")])
}

fn ctx_with(selected: &[ExecOp], scope: StoreScope, host: Box<dyn HostFacts>) -> GateCtx {
    GateCtx::with_host(DenyList::compile(&live_env(None)), selected, scope, host).unwrap()
}

fn ctx(selected: &[ExecOp]) -> GateCtx {
    GateCtx::new(DenyList::compile(&live_env(None)), selected, no_store()).unwrap()
}

/// The exemptions of an item read from the file system in long form.
fn long() -> Exemptions {
    Exemptions {
        long_names_resolved: true,
        ..Exemptions::default()
    }
}

fn mv(path: &str) -> ExecOp {
    ExecOp::QuarantineMove {
        path: path.to_owned(),
    }
}

fn rmdir(path: &str) -> ExecOp {
    ExecOp::RemoveDirIfEmpty {
        path: path.to_owned(),
    }
}

fn path_stamp(outcome: &GateOutcome<Validation>) -> PathStamp {
    match outcome {
        GateOutcome::Pass(Validation {
            stamp: Stamp::Path(stamp),
            ..
        }) => *stamp,
        other => panic!("expected a path pass, got {other:?}"),
    }
}

#[track_caller]
fn assert_refused<T: fmt::Debug>(outcome: &GateOutcome<T>, blocker: Blocker, reason: &str) {
    match outcome.refusal() {
        Some(refusal) => {
            assert_eq!(
                (&refusal.blocker, refusal.reason),
                (&blocker, reason),
                "{outcome:?}"
            );
        }
        None => panic!("expected {blocker:?} ({reason}), got {outcome:?}"),
    }
}

/// Validates `op` and runs the act-time gate for it against the stamp.
fn validate_then_act(ctx: &GateCtx, op: &ExecOp) -> GateOutcome<CheckedPath> {
    let item = GateItem::new(op, long());
    let stamp = path_stamp(&validate(ctx, &item));
    open_and_check_path(ctx, &item, &stamp)
}

// ---------------------------------------------------------------------------------------------------
// Files and directories
// ---------------------------------------------------------------------------------------------------

#[test]
fn read_only_hidden_file_passes_and_the_inspected_handle_acts() {
    let s = Scratch::new("plain");
    let f = s.file("data.bin", b"hello");
    attrib(&["+R", "+H"], &f);
    let op = mv(&f);
    let ctx = ctx(std::slice::from_ref(&op));
    let item = GateItem::new(&op, long());

    let validated = validate(&ctx, &item);
    let stamp = path_stamp(&validated);
    // The exemptions the verdict used come back for the journal.
    let GateOutcome::Pass(Validation { exemptions, .. }) = &validated else {
        panic!("{validated:?}");
    };
    assert_eq!(*exemptions, long());
    let Some(ItemFacts::File(facts)) = validated.item_facts() else {
        panic!("{validated:?}");
    };
    assert!(prefix::is_same(&facts.final_path, &f), "{facts:?}");
    assert!(!facts.final_path.starts_with(r"\\?\"));
    assert_eq!((facts.is_dir, facts.n_links, facts.size), (false, 1, 5));
    assert_eq!(
        facts.attributes & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN),
        FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN
    );
    assert_eq!(
        Stamp::from_item_facts(&ItemFacts::File(facts)),
        Some(Stamp::Path(stamp))
    );

    let checked = open_and_check_path(&ctx, &item, &stamp).pass().unwrap();
    assert_eq!(checked.stamp(), stamp);
    assert_eq!(checked.path(), f);
    assert!(checked.security().is_some());
    let id = checked.handle().file_id().unwrap();
    assert_eq!(
        (id.volume_serial, id.id),
        (stamp.identity.volume_serial, stamp.identity.file_id)
    );
    // The handle returned is the acting one: it can rename the very object that was inspected, into a
    // directory held open by handle.
    let dest = s.path("renamed.bin");
    let dir = open_for_security(Path::new(&s.root)).unwrap();
    checked.handle().rename_into(&dir, "renamed.bin").unwrap();
    assert!(!Path::new(&f).exists());
    assert_eq!(
        FileHandle::open(Path::new(&dest))
            .unwrap()
            .file_id()
            .unwrap(),
        id
    );
}

#[test]
fn vanished_items() {
    let s = Scratch::new("vanish");
    let missing = s.path("never-there.txt");
    let op = mv(&missing);
    let ctx = ctx(std::slice::from_ref(&op));
    let outcome = validate(&ctx, &GateItem::new(&op, long()));
    assert!(outcome.is_vanished(), "{outcome:?}");
    assert_eq!(outcome.item_facts(), Some(ItemFacts::Absent));

    let f = s.file("gone.txt", b"x");
    let op = mv(&f);
    let item = GateItem::new(&op, long());
    let stamp = path_stamp(&validate(&ctx, &item));
    std::fs::remove_file(&f).unwrap();
    assert!(open_and_check_path(&ctx, &item, &stamp).is_vanished());
}

#[test]
fn swap_between_validate_and_act_is_changed_since_scan() {
    let s = Scratch::new("swap");
    // A file replaced by another file of the same name.
    let f = s.file("app.dll", b"one");
    let op = mv(&f);
    let ctx = ctx(std::slice::from_ref(&op));
    let item = GateItem::new(&op, long());
    let stamp = path_stamp(&validate(&ctx, &item));
    std::fs::remove_file(&f).unwrap();
    std::fs::write(&f, b"one").unwrap();
    let outcome = open_and_check_path(&ctx, &item, &stamp);
    assert_refused(
        &outcome,
        Blocker::ChangedSinceScan,
        live_reason::IDENTITY_CHANGED,
    );
    assert!(!outcome.refusal().unwrap().is_hard());

    // A directory replaced by another directory.
    let d = s.dir("cache");
    s.file(r"cache\a.txt", b"a");
    let op = mv(&d);
    let item = GateItem::new(&op, long());
    let stamp = path_stamp(&validate(&ctx, &item));
    std::fs::remove_dir_all(&d).unwrap();
    s.dir("cache");
    assert_refused(
        &open_and_check_path(&ctx, &item, &stamp),
        Blocker::ChangedSinceScan,
        live_reason::IDENTITY_CHANGED,
    );

    // A file replaced by a directory.
    let g = s.file("kind.txt", b"g");
    let op = mv(&g);
    let item = GateItem::new(&op, long());
    let stamp = path_stamp(&validate(&ctx, &item));
    std::fs::remove_file(&g).unwrap();
    std::fs::create_dir(&g).unwrap();
    assert_refused(
        &open_and_check_path(&ctx, &item, &stamp),
        Blocker::ChangedSinceScan,
        live_reason::IDENTITY_CHANGED,
    );
}

#[test]
fn junction_as_the_item_is_refused_and_its_target_untouched() {
    let s = Scratch::new("jitem");
    let real = s.dir("real");
    let canary = s.file(r"real\canary.txt", b"keep");
    let link = s.path("link");
    junction(&link, &real);

    let op = mv(&link);
    let ctx = ctx(std::slice::from_ref(&op));
    let item = GateItem::new(&op, long());
    assert_refused(
        &validate(&ctx, &item),
        Blocker::ReparseMismatch,
        live_reason::ITEM_IS_REPARSE_POINT,
    );
    // Even with the stamp of the real directory the act refuses the link.
    let real_op = mv(&real);
    let stamp = path_stamp(&validate(&ctx, &GateItem::new(&real_op, long())));
    assert_refused(
        &open_and_check_path(&ctx, &item, &stamp),
        Blocker::ReparseMismatch,
        live_reason::ITEM_IS_REPARSE_POINT,
    );
    assert_eq!(std::fs::read(&canary).unwrap(), b"keep");
}

#[test]
fn junction_on_the_path_is_refused_also_when_swapped_in_after_validation() {
    let s = Scratch::new("jparent");
    let elsewhere = s.dir("elsewhere");
    s.file(r"elsewhere\app.exe", b"other");
    let via = s.path("via");
    junction(&via, &elsewhere);

    let op = mv(&format!(r"{via}\app.exe"));
    let ctx = ctx(std::slice::from_ref(&op));
    assert_refused(
        &validate(&ctx, &GateItem::new(&op, long())),
        Blocker::ReparseMismatch,
        live_reason::FINAL_DIFFERS,
    );

    // Validated through a plain parent; the parent is then swapped for a junction.
    s.dir("install");
    let target = s.file(r"install\app.exe", b"mine");
    let op = mv(&target);
    let item = GateItem::new(&op, long());
    let stamp = path_stamp(&validate(&ctx, &item));
    std::fs::rename(s.path("install"), s.path("install-moved")).unwrap();
    junction(&s.path("install"), &elsewhere);
    let outcome = open_and_check_path(&ctx, &item, &stamp);
    assert_refused(
        &outcome,
        Blocker::ReparseMismatch,
        live_reason::FINAL_DIFFERS,
    );
    assert_eq!(
        std::fs::read(s.path(r"elsewhere\app.exe")).unwrap(),
        b"other"
    );
}

#[test]
fn hard_link_outside_the_plan_blocks_file_and_tree() {
    let s = Scratch::new("hlink");
    let f = s.file(r"app\shared.dll", b"x");
    let other = s.path(r"outside\shared.dll");
    s.dir("outside");
    std::fs::hard_link(&f, &other).unwrap();

    let op = mv(&f);
    let only_item = ctx(std::slice::from_ref(&op));
    assert_refused(
        &validate(&only_item, &GateItem::new(&op, long())),
        Blocker::HardLinkOutsidePlan,
        live_reason::LINK_OUTSIDE_PLAN,
    );
    let both = [op.clone(), mv(&other)];
    let both_ctx = ctx(&both);
    let outcome = validate_then_act(&both_ctx, &op);
    assert!(matches!(outcome, GateOutcome::Pass(_)), "{outcome:?}");

    // The same file found by the walk below a directory moved whole.
    let dir_op = mv(&s.path("app"));
    let tree_ctx = ctx(std::slice::from_ref(&dir_op));
    assert_refused(
        &validate(&tree_ctx, &GateItem::new(&dir_op, long())),
        Blocker::HardLinkOutsidePlan,
        live_reason::LINK_OUTSIDE_PLAN_IN_TREE,
    );
    let with_outside = [dir_op.clone(), mv(&s.path("outside"))];
    let outcome = validate_then_act(&ctx(&with_outside), &dir_op);
    assert!(matches!(outcome, GateOutcome::Pass(_)), "{outcome:?}");
}

#[test]
fn tree_walk_does_not_traverse_a_junction_and_enforces_the_blast_radius() {
    let s = Scratch::new("tree");
    let big = s.dir("big");
    for i in 0..12 {
        s.file(&format!(r"big\f{i}.txt"), b"0123456789");
    }
    let app = s.dir("app");
    s.file(r"app\a.txt", b"abc");
    s.dir(r"app\sub");
    s.file(r"app\sub\b.txt", b"defg");
    junction(&s.path(r"app\sub\to-big"), &big);

    let op = mv(&app);
    let ctx = ctx(std::slice::from_ref(&op));
    let item = GateItem {
        max_files: 5,
        ..GateItem::new(&op, long())
    };
    let validated = validate(&ctx, &item);
    let Some(ItemFacts::File(facts)) = validated.item_facts() else {
        panic!("{validated:?}");
    };
    // a.txt, sub, sub\b.txt, sub\to-big: the junction is an entry, its target is not walked.
    assert_eq!((facts.tree_entries, facts.tree_bytes), (Some(4), Some(7)));
    let checked = open_and_check_path(&ctx, &item, &path_stamp(&validated));
    assert_eq!(checked.pass().unwrap().file_facts().tree_entries, Some(4));

    // The same limit on a directory with more files than it allows.
    let op = mv(&big);
    let item = GateItem {
        max_files: 5,
        ..GateItem::new(&op, long())
    };
    let outcome = validate(&ctx, &item);
    assert_refused(&outcome, Blocker::TooLarge, reason::BLAST_RADIUS);
    assert!(!outcome.refusal().unwrap().is_hard());
}

#[test]
fn placeholder_attributes_are_refused_on_the_item_and_in_the_tree() {
    let s = Scratch::new("cloud");
    let f = s.file("doc.txt", b"cloud");
    attrib(&["+O"], &f);
    let attributes = FileHandle::open(Path::new(&f))
        .unwrap()
        .metadata()
        .unwrap()
        .attributes;
    assert_ne!(
        attributes & live::FILE_ATTRIBUTE_OFFLINE,
        0,
        "attrib +O did not set FILE_ATTRIBUTE_OFFLINE"
    );
    let op = mv(&f);
    let ctx = ctx(std::slice::from_ref(&op));
    assert_refused(
        &validate(&ctx, &GateItem::new(&op, long())),
        Blocker::SyncRoot,
        live_reason::PLACEHOLDER,
    );

    s.dir("synced");
    let inner = s.file(r"synced\inner.txt", b"cloud");
    attrib(&["+O"], &inner);
    let op = mv(&s.path("synced"));
    assert_refused(
        &validate(&ctx, &GateItem::new(&op, long())),
        Blocker::SyncRoot,
        live_reason::PLACEHOLDER_IN_TREE,
    );
}

/// Live facts, except for the parts a test puts in.
#[derive(Debug, Default)]
struct Injected {
    file_security: Option<SecurityFacts>,
    volume: Option<Option<VolumeFacts>>,
}

impl HostFacts for Injected {
    fn file_security(&self, security: Option<&Security>) -> SecurityFacts {
        self.file_security
            .clone()
            .unwrap_or_else(|| LiveHost.file_security(security))
    }

    fn key_security(&self, key: &WKey) -> SecurityFacts {
        LiveHost.key_security(key)
    }

    fn volume(&self, final_path: &str, volume_serial: u64) -> Option<VolumeFacts> {
        self.volume
            .clone()
            .unwrap_or_else(|| LiveHost.volume(final_path, volume_serial))
    }
}

#[test]
fn injected_trusted_installer_and_volume_facts_are_refused() {
    let s = Scratch::new("inject");
    let f = s.file("x.dll", b"x");
    let op = mv(&f);
    let cases: Vec<(Injected, Blocker, &str)> = vec![
        (
            Injected {
                file_security: Some(SecurityFacts {
                    owner: Some(TRUSTED_INSTALLER_SID.into()),
                    owner_is_ti: Some(true),
                    ti_ace: Some(false),
                }),
                ..Injected::default()
            },
            Blocker::TrustedInstallerOwned,
            live_reason::TI_OWNER,
        ),
        (
            Injected {
                file_security: Some(SecurityFacts {
                    owner: Some("S-1-5-32-544".into()),
                    owner_is_ti: Some(false),
                    ti_ace: Some(true),
                }),
                ..Injected::default()
            },
            Blocker::TrustedInstallerOwned,
            live_reason::TI_ACE,
        ),
        (
            Injected {
                file_security: Some(SecurityFacts::default()),
                ..Injected::default()
            },
            Blocker::TrustedInstallerOwned,
            live_reason::TI_UNKNOWN,
        ),
        (
            Injected {
                volume: Some(Some(VolumeFacts {
                    drive_fixed: false,
                    fs_name: "NTFS".into(),
                })),
                ..Injected::default()
            },
            Blocker::CannotBackUp,
            live_reason::VOLUME_NOT_FIXED,
        ),
        (
            Injected {
                volume: Some(Some(VolumeFacts {
                    drive_fixed: true,
                    fs_name: "FAT32".into(),
                })),
                ..Injected::default()
            },
            Blocker::CannotBackUp,
            live_reason::FILE_SYSTEM,
        ),
        (
            Injected {
                volume: Some(None),
                ..Injected::default()
            },
            Blocker::CannotBackUp,
            live_reason::VOLUME_UNKNOWN,
        ),
    ];
    // The unchanged live facts pass, so each case below is refused for its injected fact alone.
    let plain = ctx_with(
        std::slice::from_ref(&op),
        no_store(),
        Box::<Injected>::default(),
    );
    let stamp = path_stamp(&validate(&plain, &GateItem::new(&op, long())));
    for (host, blocker, reason) in cases {
        let ctx = ctx_with(std::slice::from_ref(&op), no_store(), Box::new(host));
        let item = GateItem::new(&op, long());
        assert_refused(&validate(&ctx, &item), blocker.clone(), reason);
        assert_refused(&open_and_check_path(&ctx, &item, &stamp), blocker, reason);
    }
}

#[test]
fn a_file_held_without_delete_sharing_is_locked() {
    let s = Scratch::new("lock");
    let f = s.file("busy.log", b"busy");
    let op = mv(&f);
    let ctx = ctx(std::slice::from_ref(&op));
    let item = GateItem::new(&op, long());
    let stamp = path_stamp(&validate(&ctx, &item));
    {
        let _held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x1) // FILE_SHARE_READ only
            .open(&f)
            .unwrap();
        match open_and_check_path(&ctx, &item, &stamp) {
            GateOutcome::Locked(locked) => {
                assert_eq!(locked.stamp, stamp);
                assert_eq!(locked.error.code(), FsError::SharingViolation.code());
            }
            other => panic!("expected Locked, got {other:?}"),
        }
    }
    assert!(matches!(
        open_and_check_path(&ctx, &item, &stamp),
        GateOutcome::Pass(_)
    ));
}

#[test]
fn in_use_errors_for_the_locked_file_ladder() {
    assert!(may_be_in_use(FsError::SharingViolation, false));
    assert!(may_be_in_use(FsError::SharingViolation, true));
    // A directory refuses with access denied while something below it is open.
    assert!(may_be_in_use(FsError::AccessDenied, true));
    assert!(!may_be_in_use(FsError::AccessDenied, false));
    assert!(!may_be_in_use(FsError::NotFound, true));
    assert!(!may_be_in_use(FsError::Other(1), true));
}

#[test]
fn a_directory_whose_delete_is_denied_is_locked_not_failed() {
    let s = Scratch::new("dirlock");
    let d = s.dir("held");
    s.file(r"held\inside.txt", b"x");
    let op = mv(&d);
    let ctx = ctx(std::slice::from_ref(&op));
    let item = GateItem::new(&op, long());
    let stamp = path_stamp(&validate(&ctx, &item));
    // Our own deny ACEs: DELETE on the directory and delete-child on its parent (which would grant DELETE
    // otherwise), so the acting open is refused with access denied while a read-only look still works.
    let sid = current_user_sid().unwrap();
    let icacls = |path: &str, args: [String; 2]| {
        let st = Command::new("icacls")
            .arg(path)
            .args(args)
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "icacls {path}");
    };
    // The same denial on a file is a plain failure: a file is never "in use" through access denied.
    let f = s.file("denied.txt", b"x");
    let file_op = mv(&f);
    let file_ctx = GateCtx::new(
        DenyList::compile(&live_env(None)),
        std::slice::from_ref(&file_op),
        no_store(),
    )
    .unwrap();
    let file_item = GateItem::new(&file_op, long());
    let file_stamp = path_stamp(&validate(&file_ctx, &file_item));
    icacls(&d, ["/deny".into(), format!("*{sid}:(DE)")]);
    icacls(&f, ["/deny".into(), format!("*{sid}:(DE)")]);
    icacls(&s.root, ["/deny".into(), format!("*{sid}:(DC)")]);
    let outcome = open_and_check_path(&ctx, &item, &stamp);
    let file_outcome = open_and_check_path(&file_ctx, &file_item, &file_stamp);
    icacls(&s.root, ["/remove:d".into(), format!("*{sid}")]);
    icacls(&f, ["/remove:d".into(), format!("*{sid}")]);
    icacls(&d, ["/remove:d".into(), format!("*{sid}")]);
    match file_outcome {
        GateOutcome::Failed(e) => assert_eq!(e.code(), FsError::AccessDenied.code()),
        other => panic!("expected Failed, got {other:?}"),
    }
    match outcome {
        GateOutcome::Locked(locked) => {
            assert_eq!(locked.stamp, stamp);
            assert_eq!(locked.error.code(), FsError::AccessDenied.code());
        }
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn remove_dir_if_empty_needs_a_directory_and_skips_the_walk() {
    let s = Scratch::new("rmdir");
    let f = s.file("not-a-dir", b"x");
    let ctx = ctx(&[]);
    let op = rmdir(&f);
    assert_refused(
        &validate(&ctx, &GateItem::new(&op, long())),
        Blocker::ChangedSinceScan,
        live_reason::NOT_A_DIRECTORY,
    );
    let d = s.dir("empty");
    let op = rmdir(&d);
    let checked = validate_then_act(&ctx, &op).pass().unwrap();
    assert_eq!(checked.file_facts().tree_entries, None);
    assert!(checked.meta().is_dir);
}

#[test]
fn deny_listed_paths_are_refused_with_the_rule() {
    let s = Scratch::new("deny");
    let store = s.dir("purge-store");
    let f = s.file(r"purge-store\journal.jsonl", b"{}");
    let op = mv(&f);
    let ctx = GateCtx::new(
        DenyList::compile(&live_env(Some(&store))),
        std::slice::from_ref(&op),
        no_store(),
    )
    .unwrap();
    let outcome = validate(&ctx, &GateItem::new(&op, long()));
    let refusal = outcome.refusal().unwrap();
    assert!(
        matches!(&refusal.blocker, Blocker::DenyListed { .. }),
        "{refusal:?}"
    );
    assert_eq!(refusal.reason, live_reason::DENY_LEXICAL);
}

#[test]
fn quarantine_destination_store_item_and_undo_path() {
    let s = Scratch::new("dest");
    let scope = scope_in(&s);
    let q = scope.quarantine_dirs[0].clone();
    let f = s.file(r"src\app.cfg", b"cfg");
    let op = mv(&f);
    let ctx = ctx_with(std::slice::from_ref(&op), scope, Box::new(LiveHost));
    let checked = validate_then_act(&ctx, &op).pass().unwrap();
    let serial = checked.stamp().identity.volume_serial;

    // The op directory must exist and be plain; the destination must be free.
    let op_dir = s.dir(r"store\q\S1\000001");
    let taken = s.file(r"store\q\S1\000001\taken", b"t");
    assert_refused(
        &verdict(check_quarantine_destination(&ctx, &checked, &taken)),
        Blocker::CannotBackUp,
        live_reason::QUARANTINE_OCCUPIED,
    );
    let elsewhere = s.dir("elsewhere");
    junction(&format!(r"{q}\000002"), &elsewhere);
    assert_refused(
        &verdict(check_quarantine_destination(
            &ctx,
            &checked,
            &format!(r"{q}\000002\app.cfg"),
        )),
        Blocker::ReparseMismatch,
        live_reason::QUARANTINE_PARENT,
    );

    let dest_path = format!(r"{op_dir}\app.cfg");
    let dest = check_quarantine_destination(&ctx, &checked, &dest_path).unwrap();
    assert_eq!((dest.leaf(), dest.path()), ("app.cfg", dest_path.as_str()));
    let facts = dest.facts();
    assert_eq!(
        (
            facts.occupied,
            facts.parent_is_dir,
            facts.parent_reparse_tag
        ),
        (Some(false), Some(true), Some(0))
    );
    assert_eq!(facts.parent_volume_serial, Some(serial));
    assert!(prefix::is_same(
        strip_verbatim(facts.parent_final_path.as_deref().unwrap()),
        &op_dir
    ));
    checked
        .handle()
        .rename_into(dest.dir(), dest.leaf())
        .unwrap();
    let stamp = checked.stamp();
    drop(checked);

    // Undo: the quarantined item is the recorded one, the original place is free.
    let item = open_store_item(
        &ctx,
        &dest_path,
        StoreOp::MoveBack,
        Binding::Recheck(&stamp),
        serial,
        false,
    )
    .pass()
    .unwrap();
    let back = check_undo_path(&ctx, &f, serial, long()).unwrap();
    item.handle().rename_into(back.dir(), back.leaf()).unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), b"cfg");
    // Now the original is occupied: a second undo is a conflict.
    assert_refused(
        &verdict(check_undo_path(&ctx, &f, serial, long())),
        Blocker::ChangedSinceScan,
        live_reason::UNDO_OCCUPIED,
    );
    // A store item outside the session's directories is refused.
    assert_refused(
        &open_store_item(
            &ctx,
            &f,
            StoreOp::MoveBack,
            Binding::Recheck(&stamp),
            serial,
            false,
        ),
        Blocker::DenyListed {
            rule: "fs.purge".into(),
        },
        live_reason::OUTSIDE_STORE,
    );
}

/// A destination check as an outcome, for [`assert_refused`].
fn verdict(result: Result<DestDir, Refusal>) -> GateOutcome<()> {
    match result {
        Ok(_) => GateOutcome::Pass(()),
        Err(refusal) => GateOutcome::Refused(refusal),
    }
}

#[test]
fn boot_moves_below_a_user_writable_directory_are_held() {
    let s = Scratch::new("boot");
    let f = s.file("locked.dll", b"x");
    let chain = boot_move_chain(&f);
    // The item, every ancestor and the drive root.
    assert_eq!(chain.len(), prefix::depth(&f));
    assert!(chain.iter().all(|c| c.reparse == Some(false)), "{chain:?}");
    assert_eq!(
        admin_only_ancestors(&f),
        BootMove::Hold("live.boot.user-writable")
    );
}

#[test]
fn validate_all_records_the_stamps() {
    let s = Scratch::new("all");
    let a = s.file("a.txt", b"a");
    let ops = [mv(&a), mv(&s.path("missing.txt")), rmdir(&s.dir("d"))];
    let mut ctx = ctx(&ops);
    let results = validate_all(
        &mut ctx,
        ops.iter()
            .enumerate()
            .map(|(i, op)| (OpId(i as u32 + 1), GateItem::new(op, long()))),
    );
    assert_eq!(results.len(), 3);
    assert!(matches!(ctx.stamp(OpId(1)), Some(Stamp::Path(s)) if !s.is_dir));
    assert!(results[1].1.is_vanished());
    assert_eq!(ctx.stamp(OpId(2)), None);
    assert!(matches!(ctx.stamp(OpId(3)), Some(Stamp::Path(s)) if s.is_dir));
    for (op, outcome) in &results {
        let facts = outcome.item_facts().unwrap();
        assert_eq!(Stamp::from_item_facts(&facts).as_ref(), ctx.stamp(*op));
    }
}

#[test]
fn wrong_stamp_or_op_kind_is_refused() {
    let s = Scratch::new("kind");
    let f = s.file("a.txt", b"a");
    let ctx = ctx(&[]);
    let key_op = ExecOp::DeleteKeyTree {
        key: r"HKLM\SOFTWARE\PurgeNoSuchVendor".into(),
    };
    let stamp = path_stamp(&validate(&ctx, &GateItem::new(&mv(&f), long())));
    assert_refused(
        &open_and_check_path(&ctx, &GateItem::new(&key_op, long()), &stamp),
        Blocker::DenyListed {
            rule: reason::OP_KIND.into(),
        },
        reason::OP_KIND,
    );
    assert_refused(
        &open_and_check_key(&ctx, &GateItem::new(&mv(&f), long()), &Stamp::Key),
        Blocker::DenyListed {
            rule: reason::OP_KIND.into(),
        },
        reason::OP_KIND,
    );
    assert_refused(
        &open_and_check_key(&ctx, &GateItem::new(&key_op, long()), &Stamp::Path(stamp)),
        Blocker::DenyListed {
            rule: reason::STAMP_KIND.into(),
        },
        reason::STAMP_KIND,
    );
}

// ---------------------------------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------------------------------

mod reg_ffi {
    use std::ffi::c_void;

    pub const HKEY_USERS: isize = 0x8000_0003_u32 as i32 as isize;
    pub const REG_OPTION_CREATE_LINK: u32 = 0x2;
    pub const REG_OPTION_OPEN_LINK: u32 = 0x8;
    pub const KEY_ALL_ACCESS: u32 = 0xF_003F;
    pub const KEY_WOW64_64KEY: u32 = 0x100;
    pub const DELETE: u32 = 0x1_0000;
    pub const REG_LINK: u32 = 6;

    #[link(name = "advapi32", kind = "raw-dylib")]
    unsafe extern "system" {
        pub fn RegCreateKeyExW(
            key: isize,
            sub_key: *const u16,
            reserved: u32,
            class: *const u16,
            options: u32,
            sam: u32,
            security: *const c_void,
            out: *mut isize,
            disposition: *mut u32,
        ) -> u32;
        pub fn RegSetValueExW(
            key: isize,
            name: *const u16,
            reserved: u32,
            ty: u32,
            data: *const u8,
            len: u32,
        ) -> u32;
        pub fn RegOpenKeyExW(
            key: isize,
            sub_key: *const u16,
            options: u32,
            sam: u32,
            out: *mut isize,
        ) -> u32;
        pub fn RegCloseKey(key: isize) -> u32;
    }

    #[link(name = "ntdll", kind = "raw-dylib")]
    unsafe extern "system" {
        pub fn NtDeleteKey(key: isize) -> i32;
    }

    pub fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

/// A fresh `HKU\<SID>\Software\PurgeTest-<random>` key, removed on drop (links first, as links).
struct TestKey {
    sid: String,
    name: String,
    links: Vec<String>,
}

impl TestKey {
    fn new() -> TestKey {
        let sid = current_user_sid().unwrap();
        let name = unique("PurgeTest");
        WKey::open(
            RegRoot::Hku,
            &format!(r"{sid}\Software"),
            RegView::K64,
            KeyAccess::CREATE_SUB_KEY,
        )
        .unwrap()
        .create_subkey(&name, "", None, false)
        .unwrap();
        TestKey {
            sid,
            name,
            links: Vec::new(),
        }
    }

    /// The path below `HKU`.
    fn rel(&self, sub: &str) -> String {
        let base = format!(r"{}\Software\{}", self.sid, self.name);
        if sub.is_empty() {
            base
        } else {
            format!(r"{base}\{sub}")
        }
    }

    /// The canonical wire spelling.
    fn wire(&self, sub: &str) -> String {
        format!(r"HKU\{}", self.rel(sub))
    }

    fn open(&self, sub: &str, access: KeyAccess) -> WKey {
        WKey::open(RegRoot::Hku, &self.rel(sub), RegView::K64, access).unwrap()
    }

    /// Creates `sub` (and the keys above it) below the root.
    fn create(&self, sub: &str) {
        let mut at = String::new();
        for part in sub.split('\\') {
            let parent = self.open(&at, KeyAccess::CREATE_SUB_KEY);
            match parent.create_subkey(part, "", None, false) {
                Ok(_) => {}
                Err(e) if e == purge_win::reg_write::ALREADY_EXISTS => {}
                Err(e) => panic!("create {part}: {e:?}"),
            }
            at = if at.is_empty() {
                part.to_owned()
            } else {
                format!(r"{at}\{part}")
            };
        }
    }

    fn set(&self, sub: &str, name: &str, ty: u32, data: &[u8]) {
        self.open(sub, KeyAccess::SET_VALUE)
            .set_value_raw(name, ty, data)
            .unwrap();
    }

    /// Creates the registry link `sub` pointing at the key `target_sub` below the root.
    fn link(&mut self, sub: &str, target_sub: &str) {
        use reg_ffi::*;
        let name = wide(&self.rel(sub));
        let mut key = 0isize;
        // SAFETY: `name` is NUL-terminated; class, security and disposition are null; `key` is a valid
        // out-pointer.
        let rc = unsafe {
            RegCreateKeyExW(
                HKEY_USERS,
                name.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_CREATE_LINK,
                KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                std::ptr::null(),
                &mut key,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "create link key");
        self.links.push(sub.to_owned());
        let target: Vec<u8> = format!(r"\REGISTRY\USER\{}", self.rel(target_sub))
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let value = wide("SymbolicLinkValue");
        // SAFETY: live key; `value` is NUL-terminated; `target` has the stated length.
        let rc = unsafe {
            RegSetValueExW(
                key,
                value.as_ptr(),
                0,
                REG_LINK,
                target.as_ptr(),
                target.len() as u32,
            )
        };
        // SAFETY: `key` came from RegCreateKeyExW and is closed once.
        unsafe { RegCloseKey(key) };
        assert_eq!(rc, 0, "set link target");
    }

    fn remove_link(&self, sub: &str) {
        use reg_ffi::*;
        let name = wide(&self.rel(sub));
        let mut key = 0isize;
        // SAFETY: `name` is NUL-terminated; `key` is a valid out-pointer.
        let rc = unsafe {
            RegOpenKeyExW(
                HKEY_USERS,
                name.as_ptr(),
                REG_OPTION_OPEN_LINK,
                DELETE | KEY_WOW64_64KEY,
                &mut key,
            )
        };
        if rc == 0 {
            // SAFETY: `key` is a live handle with DELETE on the link key itself; closed once.
            unsafe {
                NtDeleteKey(key);
                RegCloseKey(key);
            }
        }
    }

    fn nuke(key: &WKey) {
        for sub in key.subkey_names().unwrap_or_default() {
            if let Ok(child) = key.open_subkey(&sub, KeyAccess::DELETE) {
                Self::nuke(&child);
            }
        }
        let _ = key.delete();
    }
}

impl Drop for TestKey {
    fn drop(&mut self) {
        for link in self.links.iter().rev() {
            self.remove_link(link);
        }
        if let Ok(root) = WKey::open(RegRoot::Hku, &self.rel(""), RegView::K64, KeyAccess::DELETE) {
            Self::nuke(&root);
        }
    }
}

fn value_op(key: &str, name: &str) -> ExecOp {
    ExecOp::DeleteValue {
        key: key.to_owned(),
        name: name.to_owned(),
    }
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[test]
fn value_actions_bind_to_the_validated_data() {
    let k = TestKey::new();
    k.create("App");
    k.set("App", "InstallDir", REG_SZ, &utf16z(r"C:\App"));
    let op = value_op(&k.wire("App"), "InstallDir");
    let ctx = ctx(&[]);
    let item = GateItem::new(&op, long());

    let validated = validate(&ctx, &item);
    let GateOutcome::Pass(Validation {
        stamp: stamp @ Stamp::Value(value),
        facts: ItemFacts::Value(facts),
        exemptions,
    }) = &validated
    else {
        panic!("{validated:?}");
    };
    assert_eq!(*exemptions, long());
    assert_eq!((value.ty, facts.value_type), (REG_SZ, REG_SZ));
    assert_eq!(u64::from(facts.size), value.len);
    assert_eq!(
        Stamp::from_item_facts(&ItemFacts::Value(facts.clone())).as_ref(),
        Some(stamp)
    );

    let checked = open_and_check_key(&ctx, &item, stamp).pass().unwrap();
    assert_eq!(checked.value().unwrap().data, utf16z(r"C:\App"));
    assert_eq!(checked.item_facts(), &ItemFacts::Value(facts.clone()));
    // The handle can act: it was opened for setting values.
    checked
        .key()
        .set_value_raw("Probe", REG_DWORD, &[1, 0, 0, 0])
        .unwrap();
    drop(checked);

    // Same type, other data: changed since the scan.
    k.set("App", "InstallDir", REG_SZ, &utf16z(r"C:\Elsewhere"));
    let outcome = open_and_check_key(&ctx, &item, stamp);
    assert_refused(
        &outcome,
        Blocker::ChangedSinceScan,
        live_reason::VALUE_CHANGED,
    );
    // Same bytes, other type.
    k.set("App", "InstallDir", 2, &utf16z(r"C:\App"));
    assert_refused(
        &open_and_check_key(&ctx, &item, stamp),
        Blocker::ChangedSinceScan,
        live_reason::VALUE_CHANGED,
    );
    // Gone.
    k.open("App", KeyAccess::SET_VALUE)
        .delete_value("InstallDir")
        .unwrap();
    assert!(open_and_check_key(&ctx, &item, stamp).is_vanished());
    assert!(validate(&ctx, &item).is_vanished());

    // A segment edit is gated on its value the same way.
    k.set("App", "Path", 7, &utf16z("a\0b\0"));
    let seg = ExecOp::EditSegment {
        key: k.wire("App"),
        name: "Path".into(),
        segment: "b".into(),
        index: Some(1),
    };
    let seg_item = GateItem::new(&seg, long());
    let stamp = validate(&ctx, &seg_item).pass().unwrap().stamp;
    assert!(matches!(stamp, Stamp::Value(_)));
    assert!(matches!(
        open_and_check_key(&ctx, &seg_item, &stamp),
        GateOutcome::Pass(_)
    ));
}

#[test]
fn key_actions_and_emptiness() {
    let k = TestKey::new();
    k.create(r"Vendor\App\Sub");
    k.set(r"Vendor\App", "v", REG_DWORD, &[1, 0, 0, 0]);
    let ctx = ctx(&[]);
    let sid = current_user_sid().unwrap();

    let tree = ExecOp::DeleteKeyTree {
        key: k.wire(r"Vendor\App"),
    };
    let item = GateItem::new(&tree, long());
    let validated = validate(&ctx, &item).pass().unwrap();
    assert_eq!(validated.stamp, Stamp::Key);
    let ItemFacts::Key(facts) = &validated.facts else {
        panic!("{validated:?}");
    };
    assert_eq!(
        (
            facts.subkeys,
            facts.values,
            facts.is_link,
            facts.owner.as_str()
        ),
        (1, 1, false, sid.as_str())
    );
    let checked = open_and_check_key(&ctx, &item, &Stamp::Key).pass().unwrap();
    assert_eq!(checked.info().n_subkeys, 1);
    assert_eq!(checked.facts().node, KeyNode::Plain);
    assert!(
        checked
            .facts()
            .ancestors
            .iter()
            .all(|a| a.node == KeyNode::Plain)
    );
    drop(checked);

    // Delete-if-empty on a key that is not empty is a soft skip; on an empty one a pass.
    let if_empty = ExecOp::DeleteKeyIfEmpty {
        key: k.wire(r"Vendor\App"),
    };
    assert_refused(
        &validate(&ctx, &GateItem::new(&if_empty, long())),
        Blocker::ChangedSinceScan,
        live_reason::NOT_EMPTY,
    );
    let empty = ExecOp::DeleteKeyIfEmpty {
        key: k.wire(r"Vendor\App\Sub"),
    };
    let empty_item = GateItem::new(&empty, long());
    assert!(matches!(validate(&ctx, &empty_item), GateOutcome::Pass(_)));
    let checked = open_and_check_key(&ctx, &empty_item, &Stamp::Key)
        .pass()
        .unwrap();
    // The handle can act: it was opened with DELETE, and the key really is deleted through it.
    checked.key().delete().unwrap();
    drop(checked);
    assert!(open_and_check_key(&ctx, &empty_item, &Stamp::Key).is_vanished());

    // A key that never existed.
    let missing = ExecOp::DeleteKeyTree {
        key: k.wire("NoSuchKey"),
    };
    assert!(validate(&ctx, &GateItem::new(&missing, long())).is_vanished());
}

#[test]
fn registry_links_at_the_leaf_and_on_the_path_are_refused() {
    let mut k = TestKey::new();
    k.create(r"Real\Sub");
    k.set(r"Real\Sub", "v", REG_DWORD, &[7, 0, 0, 0]);
    k.link("Link", "Real");
    let ctx = ctx(&[]);

    // The link itself as the item.
    let leaf = ExecOp::DeleteKeyTree {
        key: k.wire("Link"),
    };
    let leaf_item = GateItem::new(&leaf, long());
    assert_refused(
        &validate(&ctx, &leaf_item),
        Blocker::RegLink,
        live_reason::KEY_IS_LINK,
    );
    assert_refused(
        &open_and_check_key(&ctx, &leaf_item, &Stamp::Key),
        Blocker::RegLink,
        live_reason::KEY_IS_LINK,
    );

    // A key and a value reached through the link.
    let below = ExecOp::DeleteKeyTree {
        key: k.wire(r"Link\Sub"),
    };
    assert_refused(
        &validate(&ctx, &GateItem::new(&below, long())),
        Blocker::RegLink,
        live_reason::ANCESTOR_IS_LINK,
    );
    let value = value_op(&k.wire(r"Link\Sub"), "v");
    assert_refused(
        &validate(&ctx, &GateItem::new(&value, long())),
        Blocker::RegLink,
        live_reason::ANCESTOR_IS_LINK,
    );

    // Validated through a plain key; that key is then swapped for a link to the same content.
    k.create(r"Plain\Sub");
    let plain = ExecOp::DeleteKeyTree {
        key: k.wire(r"Plain\Sub"),
    };
    let plain_item = GateItem::new(&plain, long());
    assert!(matches!(validate(&ctx, &plain_item), GateOutcome::Pass(_)));
    TestKey::nuke(&k.open("Plain", KeyAccess::DELETE));
    k.link("Plain", "Real");
    assert_refused(
        &open_and_check_key(&ctx, &plain_item, &Stamp::Key),
        Blocker::RegLink,
        live_reason::ANCESTOR_IS_LINK,
    );
    // The real key behind the link is untouched.
    assert_eq!(
        k.open(r"Real\Sub", KeyAccess::READ)
            .value("v")
            .unwrap()
            .unwrap()
            .data,
        vec![7, 0, 0, 0]
    );

    // Undo destinations: below a link refused, a missing key below plain keys allowed.
    let below_link = Target::RegKey {
        path: k.wire(r"Link\New"),
    };
    let refusal = check_undo_key(&ctx, &below_link, &long()).unwrap_err();
    assert_eq!(refusal.blocker, Blocker::RegLink);
    let fresh = Target::RegKey {
        path: k.wire(r"Real\New\Deeper"),
    };
    assert_eq!(check_undo_key(&ctx, &fresh, &long()), Ok(()));
}
