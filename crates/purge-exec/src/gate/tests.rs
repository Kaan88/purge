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
use purge_model::exec::session::SessionId;
use purge_win::fs_write::{FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY};
use purge_win::reg::{REG_DWORD, REG_LINK, REG_SZ};
use purge_win::sid::current_user_sid;

use super::*;
use crate::storage::StorageRoots;

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

/// The session the tests' store scopes belong to.
fn test_session() -> SessionId {
    SessionId::new(FileTime(133_000_000_000_000_000), 0x5eed)
}

/// **The one place** the tests build a [`StoreScope`]: the scope of [`test_session`] in the store at
/// `data_root`, with no quarantine root on another volume.
fn store_scope(data_root: &str) -> StoreScope {
    StoreScope::new::<&str>(data_root, &[], &test_session()).unwrap()
}

/// A scope whose store does not exist: nothing is in this session's store.
fn no_store() -> StoreScope {
    let root = std::env::temp_dir().join(unique("purge-gate-no-store"));
    store_scope(root.to_str().unwrap())
}

/// A session in a relaxed store at `<scratch>\store` (the store creates and checks its op directories),
/// and its scope.
fn relaxed_session(s: &Scratch) -> (crate::storage::SessionDir, StoreScope) {
    let roots = StorageRoots::install_relaxed(Path::new(&s.path("store"))).unwrap();
    let session = roots.create_session().unwrap();
    let scope = roots.store_scope::<&Path>(session.id(), &[]).unwrap();
    (session, scope)
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

/// The journal `validated` record of a passed validation of `item`, as op `id`.
#[track_caller]
fn journal_record(id: OpId, item: &GateItem<'_>, outcome: &GateOutcome<Validation>) -> Validated {
    let GateOutcome::Pass(validation) = outcome else {
        panic!("expected a pass, got {outcome:?}");
    };
    validation.to_journal(id, CandidateId(format!("c-{:03}", id.0)), item.op.target())
}

/// Writes (in memory) the journal record of a passed validation of `item` and records it in `ctx` under
/// a fresh op id, as the execute pipeline does once the record is written. Returns the op id.
#[track_caller]
fn record(ctx: &mut GateCtx, item: &GateItem<'_>, outcome: &GateOutcome<Validation>) -> OpId {
    let id = OpId(u32::try_from(ctx.validated.len()).unwrap() + 1);
    ctx.record(item.op, &journal_record(id, item, outcome), item.max_files)
        .unwrap();
    id
}

/// Validates `item` and records the pass; returns the op id for the act-time gate.
#[track_caller]
fn validate_and_record(ctx: &mut GateCtx, item: &GateItem<'_>) -> OpId {
    let outcome = validate(ctx, item);
    record(ctx, item, &outcome)
}

/// Validates `op`, records the pass and runs the act-time gate for it.
fn validate_then_act(ctx: &mut GateCtx, op: &ExecOp) -> GateOutcome<CheckedPath> {
    let id = validate_and_record(ctx, &GateItem::new(op, long()));
    open_and_check_path(ctx, id)
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
    let mut ctx = ctx(std::slice::from_ref(&op));
    let item = GateItem::new(&op, long());

    let validated = validate(&ctx, &item);
    let stamp = path_stamp(&validated);
    let id = record(&mut ctx, &item, &validated);
    assert_eq!(ctx.stamp(id), Some(&Stamp::Path(stamp)));
    assert_eq!(ctx.exemptions(id), Some(long()));
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

    let checked = open_and_check_path(&ctx, id).pass().unwrap();
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
    let mut ctx = ctx(std::slice::from_ref(&op));
    let outcome = validate(&ctx, &GateItem::new(&op, long()));
    assert!(outcome.is_vanished(), "{outcome:?}");
    assert_eq!(outcome.item_facts(), Some(ItemFacts::Absent));
    // The journal record of an absent item records nothing: the act-time gate refuses its id.
    let absent = Validated {
        op: OpId(40),
        item: CandidateId("c-040".into()),
        target: op.target(),
        facts: ItemFacts::Absent,
        exemptions: exemptions_to_journal(&long()),
    };
    assert_eq!(ctx.record(&op, &absent, 5_000), Ok(()));
    assert_eq!(ctx.stamp(OpId(40)), None);
    assert_refused(
        &open_and_check_path(&ctx, OpId(40)),
        Blocker::DenyListed {
            rule: reason::NOT_VALIDATED.into(),
        },
        reason::NOT_VALIDATED,
    );

    let f = s.file("gone.txt", b"x");
    let op = mv(&f);
    let id = validate_and_record(&mut ctx, &GateItem::new(&op, long()));
    std::fs::remove_file(&f).unwrap();
    assert!(open_and_check_path(&ctx, id).is_vanished());
}

#[test]
fn swap_between_validate_and_act_is_changed_since_scan() {
    let s = Scratch::new("swap");
    // A file replaced by another file of the same name.
    let f = s.file("app.dll", b"one");
    let op = mv(&f);
    let mut ctx = ctx(std::slice::from_ref(&op));
    let id = validate_and_record(&mut ctx, &GateItem::new(&op, long()));
    std::fs::remove_file(&f).unwrap();
    std::fs::write(&f, b"one").unwrap();
    let outcome = open_and_check_path(&ctx, id);
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
    let id = validate_and_record(&mut ctx, &GateItem::new(&op, long()));
    std::fs::remove_dir_all(&d).unwrap();
    s.dir("cache");
    assert_refused(
        &open_and_check_path(&ctx, id),
        Blocker::ChangedSinceScan,
        live_reason::IDENTITY_CHANGED,
    );

    // A file replaced by a directory.
    let g = s.file("kind.txt", b"g");
    let op = mv(&g);
    let id = validate_and_record(&mut ctx, &GateItem::new(&op, long()));
    std::fs::remove_file(&g).unwrap();
    std::fs::create_dir(&g).unwrap();
    assert_refused(
        &open_and_check_path(&ctx, id),
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
    let mut ctx = ctx(std::slice::from_ref(&op));
    let item = GateItem::new(&op, long());
    assert_refused(
        &validate(&ctx, &item),
        Blocker::ReparseMismatch,
        live_reason::ITEM_IS_REPARSE_POINT,
    );
    // Even with a journal record that gives the link the facts of the real directory, the act refuses
    // the link.
    let real_op = mv(&real);
    let real_item = GateItem::new(&real_op, long());
    let mut forged = journal_record(OpId(1), &real_item, &validate(&ctx, &real_item));
    forged.target = op.target();
    ctx.record(&op, &forged, item.max_files).unwrap();
    assert_refused(
        &open_and_check_path(&ctx, OpId(1)),
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
    let mut ctx = ctx(std::slice::from_ref(&op));
    assert_refused(
        &validate(&ctx, &GateItem::new(&op, long())),
        Blocker::ReparseMismatch,
        live_reason::FINAL_DIFFERS,
    );

    // Validated through a plain parent; the parent is then swapped for a junction.
    s.dir("install");
    let target = s.file(r"install\app.exe", b"mine");
    let op = mv(&target);
    let id = validate_and_record(&mut ctx, &GateItem::new(&op, long()));
    std::fs::rename(s.path("install"), s.path("install-moved")).unwrap();
    junction(&s.path("install"), &elsewhere);
    let outcome = open_and_check_path(&ctx, id);
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
    let mut both_ctx = ctx(&both);
    let outcome = validate_then_act(&mut both_ctx, &op);
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
    let outcome = validate_then_act(&mut ctx(&with_outside), &dir_op);
    assert!(matches!(outcome, GateOutcome::Pass(_)), "{outcome:?}");
}

/// The other name of a hard link that lies in this session's quarantine (the first name of a pair, moved
/// earlier in the run) counts as inside the plan; one anywhere else in the store does not.
#[test]
fn a_hard_link_in_this_sessions_quarantine_counts_as_inside_the_plan() {
    let s = Scratch::new("hlinkq");
    let (session, scope) = relaxed_session(&s);
    let f = s.file(r"app\pair.dll", b"x");
    let g = s.file(r"app\journal-link.dll", b"y");
    let op_f = mv(&f);
    let op_g = mv(&g);
    let selected = [op_f.clone(), op_g.clone()];
    let mut ctx = ctx_with(&selected, scope, Box::new(LiveHost));
    let serial = path_stamp(&validate(&ctx, &GateItem::new(&op_f, long())))
        .identity
        .volume_serial;

    // `f`'s other name is in this session's quarantine: it passes, at validation and at the act.
    let q = session
        .create_op_dir(Path::new(&f), serial, OpId(1))
        .unwrap();
    std::fs::hard_link(&f, q.item_path("pair.dll")).unwrap();
    let outcome = validate_then_act(&mut ctx, &op_f);
    assert!(matches!(outcome, GateOutcome::Pass(_)), "{outcome:?}");
    drop(outcome);

    // `g`'s other name is in the session's own directory, not its quarantine: refused.
    std::fs::hard_link(&g, session.path().join("journal-link.dll")).unwrap();
    assert_refused(
        &validate(&ctx, &GateItem::new(&op_g, long())),
        Blocker::HardLinkOutsidePlan,
        live_reason::LINK_OUTSIDE_PLAN,
    );
    // The same for the tree walk below a directory moved whole.
    let dir_op = mv(&s.path("app"));
    let tree_ctx = ctx_with(
        std::slice::from_ref(&dir_op),
        relaxed_scope_of(&session),
        Box::new(LiveHost),
    );
    assert_refused(
        &validate(&tree_ctx, &GateItem::new(&dir_op, long())),
        Blocker::HardLinkOutsidePlan,
        live_reason::LINK_OUTSIDE_PLAN_IN_TREE,
    );
    std::fs::remove_file(session.path().join("journal-link.dll")).unwrap();
    let tree_ctx = ctx_with(
        std::slice::from_ref(&dir_op),
        relaxed_scope_of(&session),
        Box::new(LiveHost),
    );
    let outcome = validate(&tree_ctx, &GateItem::new(&dir_op, long()));
    assert!(matches!(outcome, GateOutcome::Pass(_)), "{outcome:?}");
}

/// The scope of `session` in its store.
fn relaxed_scope_of(session: &crate::storage::SessionDir) -> StoreScope {
    session
        .roots()
        .store_scope::<&Path>(session.id(), &[])
        .unwrap()
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
    let mut ctx = ctx(std::slice::from_ref(&op));
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
    let id = record(&mut ctx, &item, &validated);
    let checked = open_and_check_path(&ctx, id);
    assert_eq!(checked.pass().unwrap().file_facts().tree_entries, Some(4));
    // The act uses the recorded limit: the tree grows past it after validation.
    for i in 0..4 {
        s.file(&format!(r"app\late{i}.txt"), b"x");
    }
    assert_refused(
        &open_and_check_path(&ctx, id),
        Blocker::TooLarge,
        reason::BLAST_RADIUS,
    );

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
    let item = GateItem::new(&op, long());
    let journal = journal_record(OpId(1), &item, &validate(&plain, &item));
    for (host, blocker, reason) in cases {
        let mut ctx = ctx_with(std::slice::from_ref(&op), no_store(), Box::new(host));
        assert_refused(&validate(&ctx, &item), blocker.clone(), reason);
        ctx.record(&op, &journal, item.max_files).unwrap();
        assert_refused(&open_and_check_path(&ctx, OpId(1)), blocker, reason);
    }
}

#[test]
fn a_file_held_without_delete_sharing_is_locked() {
    let s = Scratch::new("lock");
    let f = s.file("busy.log", b"busy");
    let op = mv(&f);
    let mut ctx = ctx(std::slice::from_ref(&op));
    let item = GateItem::new(&op, long());
    let validated = validate(&ctx, &item);
    let stamp = path_stamp(&validated);
    let id = record(&mut ctx, &item, &validated);
    {
        let _held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x1) // FILE_SHARE_READ only
            .open(&f)
            .unwrap();
        match open_and_check_path(&ctx, id) {
            GateOutcome::Locked(locked) => {
                assert_eq!(locked.stamp, stamp);
                assert_eq!(locked.error.code(), FsError::SharingViolation.code());
            }
            other => panic!("expected Locked, got {other:?}"),
        }
    }
    assert!(matches!(
        open_and_check_path(&ctx, id),
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
    // The rename of a directory reports that case with its own variant.
    assert!(may_be_in_use(FsError::DirInUseOrDenied, true));
    assert!(!may_be_in_use(FsError::NotFound, true));
    assert!(!may_be_in_use(FsError::Other(1), true));
}

#[test]
fn a_directory_whose_delete_is_denied_is_locked_not_failed() {
    let s = Scratch::new("dirlock");
    let d = s.dir("held");
    s.file(r"held\inside.txt", b"x");
    let op = mv(&d);
    let mut ctx = ctx(std::slice::from_ref(&op));
    let item = GateItem::new(&op, long());
    let validated = validate(&ctx, &item);
    let stamp = path_stamp(&validated);
    let id = record(&mut ctx, &item, &validated);
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
    let mut file_ctx = GateCtx::new(
        DenyList::compile(&live_env(None)),
        std::slice::from_ref(&file_op),
        no_store(),
    )
    .unwrap();
    let file_id = validate_and_record(&mut file_ctx, &GateItem::new(&file_op, long()));
    icacls(&d, ["/deny".into(), format!("*{sid}:(DE)")]);
    icacls(&f, ["/deny".into(), format!("*{sid}:(DE)")]);
    icacls(&s.root, ["/deny".into(), format!("*{sid}:(DC)")]);
    let outcome = open_and_check_path(&ctx, id);
    let file_outcome = open_and_check_path(&file_ctx, file_id);
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
    let mut ctx = ctx(&[]);
    let op = rmdir(&f);
    assert_refused(
        &validate(&ctx, &GateItem::new(&op, long())),
        Blocker::ChangedSinceScan,
        live_reason::NOT_A_DIRECTORY,
    );
    let d = s.dir("empty");
    let op = rmdir(&d);
    let checked = validate_then_act(&mut ctx, &op).pass().unwrap();
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
    let (session, scope) = relaxed_session(&s);
    let f = s.file(r"src\app.cfg", b"cfg");
    let op = mv(&f);
    let mut ctx = ctx_with(std::slice::from_ref(&op), scope, Box::new(LiveHost));
    let checked = validate_then_act(&mut ctx, &op).pass().unwrap();
    let serial = checked.stamp().identity.volume_serial;
    let op_dir = |n: u32| {
        session
            .create_op_dir(Path::new(&f), serial, OpId(n))
            .unwrap()
    };

    // The destination must be free.
    let q1 = op_dir(1);
    std::fs::write(q1.item_path("taken"), b"t").unwrap();
    assert_refused(
        &verdict(check_quarantine_destination(&ctx, &checked, &q1, "taken")),
        Blocker::CannotBackUp,
        live_reason::QUARANTINE_OCCUPIED,
    );
    // The op directory the store checked, swapped for a junction: the parent is not plain.
    let elsewhere = s.dir("elsewhere");
    let q2 = op_dir(2);
    let q2_path = q2.path().to_str().unwrap().to_owned();
    std::fs::rename(&q2_path, format!("{q2_path}-moved")).unwrap();
    junction(&q2_path, &elsewhere);
    assert_refused(
        &verdict(check_quarantine_destination(&ctx, &checked, &q2, "app.cfg")),
        Blocker::ReparseMismatch,
        live_reason::QUARANTINE_PARENT,
    );

    let op_dir = q1.path().to_str().unwrap().to_owned();
    let dest_path = q1.item_path("app.cfg").to_str().unwrap().to_owned();
    let dest = check_quarantine_destination(&ctx, &checked, &q1, "app.cfg").unwrap();
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

/// Review finding M3 (wave 2): the gate opened the destination's parent by path and never compared it
/// with the store's op directory. Here the op directory the store checked and holds open is renamed away
/// and an ordinary directory takes its path: every fact the guard sees is that of a plain, empty
/// directory in the session's quarantine, so before the fix the destination passed and the move went
/// into a directory the store never checked. Now its file id is compared with the store's handle.
#[test]
fn a_quarantine_dir_replaced_after_the_store_checked_it_is_refused() {
    let s = Scratch::new("destswap");
    let (session, scope) = relaxed_session(&s);
    let f = s.file(r"src\app.cfg", b"cfg");
    let op = mv(&f);
    let mut ctx = ctx_with(std::slice::from_ref(&op), scope, Box::new(LiveHost));
    let checked = validate_then_act(&mut ctx, &op).pass().unwrap();
    let serial = checked.stamp().identity.volume_serial;
    let q = session
        .create_op_dir(Path::new(&f), serial, OpId(1))
        .unwrap();
    let q_path = q.path().to_str().unwrap().to_owned();
    std::fs::rename(&q_path, format!("{q_path}-moved")).unwrap();
    std::fs::create_dir(&q_path).unwrap();
    assert_refused(
        &verdict(check_quarantine_destination(&ctx, &checked, &q, "app.cfg")),
        Blocker::CannotBackUp,
        reason::QUARANTINE_DIR_DIFFERS,
    );
    // Nothing was moved anywhere.
    assert_eq!(std::fs::read(&f).unwrap(), b"cfg");
}

/// The destination check of a locked item (no checked handle on the source, only its path and the
/// volume serial of its stamp): the same rules and the same comparison with the store's op directory.
#[test]
fn the_destination_check_by_source_path_compares_with_the_store_too() {
    let s = Scratch::new("destfor");
    let (session, scope) = relaxed_session(&s);
    let f = s.file(r"src\held.dll", b"held");
    let op = mv(&f);
    let ctx = ctx_with(std::slice::from_ref(&op), scope, Box::new(LiveHost));
    let serial = path_stamp(&validate(&ctx, &GateItem::new(&op, long())))
        .identity
        .volume_serial;

    let q1 = session
        .create_op_dir(Path::new(&f), serial, OpId(1))
        .unwrap();
    let dest = check_quarantine_destination_for(&ctx, &f, serial, &q1, "held.dll").unwrap();
    assert_eq!(
        dest.path(),
        q1.item_path("held.dll").to_str().unwrap(),
        "{dest:?}"
    );
    assert_eq!(dest.facts().parent_volume_serial, Some(serial));
    // Another volume serial than the parent's: refused.
    assert_refused(
        &verdict(check_quarantine_destination_for(
            &ctx,
            &f,
            serial ^ 1,
            &q1,
            "held.dll",
        )),
        Blocker::CannotBackUp,
        live_reason::QUARANTINE_OTHER_VOLUME,
    );
    // A source in the store: refused.
    let in_store = q1.item_path("other.dll");
    assert_refused(
        &verdict(check_quarantine_destination_for(
            &ctx,
            in_store.to_str().unwrap(),
            serial,
            &q1,
            "held.dll",
        )),
        Blocker::DenyListed {
            rule: live_reason::QUARANTINE_OVERLAP.into(),
        },
        live_reason::QUARANTINE_OVERLAP,
    );

    // The op directory replaced after the store checked it.
    let q2 = session
        .create_op_dir(Path::new(&f), serial, OpId(2))
        .unwrap();
    let q2_path = q2.path().to_str().unwrap().to_owned();
    std::fs::rename(&q2_path, format!("{q2_path}-moved")).unwrap();
    std::fs::create_dir(&q2_path).unwrap();
    assert_refused(
        &verdict(check_quarantine_destination_for(
            &ctx, &f, serial, &q2, "held.dll",
        )),
        Blocker::CannotBackUp,
        reason::QUARANTINE_DIR_DIFFERS,
    );
    assert_eq!(std::fs::read(&f).unwrap(), b"held");
}

/// A destination check as an outcome, for [`assert_refused`].
fn verdict(result: Result<CheckedDest, Refusal>) -> GateOutcome<()> {
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

/// `validate_all` records nothing (changed with review finding S5: it used to record each stamp in the
/// context itself); the context takes the records the caller wrote to the journal, and each record's
/// stamp is the one its facts stand for.
#[test]
fn validate_all_leaves_recording_to_the_journal_records() {
    let s = Scratch::new("all");
    let a = s.file("a.txt", b"a");
    let ops = [mv(&a), mv(&s.path("missing.txt")), rmdir(&s.dir("d"))];
    let mut ctx = ctx(&ops);
    let results = validate_all(
        &ctx,
        ops.iter()
            .enumerate()
            .map(|(i, op)| (OpId(i as u32 + 1), GateItem::new(op, long()))),
    );
    assert_eq!(results.len(), 3);
    assert!(results[1].1.is_vanished());
    assert!(ctx.validated.is_empty());
    for ((id, outcome), op) in results.iter().zip(&ops) {
        let record = Validated {
            op: *id,
            item: CandidateId(format!("c-{:03}", id.0)),
            target: op.target(),
            facts: outcome.item_facts().unwrap(),
            exemptions: exemptions_to_journal(&long()),
        };
        ctx.record(op, &record, 5_000).unwrap();
    }
    assert!(matches!(ctx.stamp(OpId(1)), Some(Stamp::Path(s)) if !s.is_dir));
    assert_eq!(ctx.stamp(OpId(2)), None);
    assert!(matches!(ctx.stamp(OpId(3)), Some(Stamp::Path(s)) if s.is_dir));
    for (op, outcome) in &results {
        let facts = outcome.item_facts().unwrap();
        assert_eq!(Stamp::from_item_facts(&facts).as_ref(), ctx.stamp(*op));
    }
}

/// The act-time functions take an op id only. A record must belong to its op and fit it; the wrong gate
/// for an op is refused. (Changed with review finding S5: the old test handed a wrong stamp to the act
/// directly, which the API no longer accepts; the same mismatches are now refused when recorded.)
#[test]
fn wrong_stamp_or_op_kind_is_refused() {
    let s = Scratch::new("kind");
    let f = s.file("a.txt", b"a");
    let k = TestKey::new();
    let mut ctx = ctx(&[]);
    let file_op = mv(&f);
    let key_op = ExecOp::DeleteKeyTree { key: k.wire("") };
    let file_item = GateItem::new(&file_op, long());
    let key_item = GateItem::new(&key_op, long());
    let file_validated = validate(&ctx, &file_item);
    let key_validated = validate(&ctx, &key_item);

    // A record of another target, a second record for one op id, facts of another kind.
    let mut other_target = journal_record(OpId(9), &file_item, &file_validated);
    other_target.target = Target::Path {
        path: s.path("b.txt"),
    };
    let mismatch = rule(reason::VALIDATION_MISMATCH);
    assert_eq!(
        ctx.record(&file_op, &other_target, 5_000),
        Err(mismatch.clone())
    );
    let mut file_facts_for_key = journal_record(OpId(9), &file_item, &file_validated);
    file_facts_for_key.target = key_op.target();
    assert_eq!(
        ctx.record(&key_op, &file_facts_for_key, 5_000),
        Err(rule(reason::STAMP_KIND))
    );
    let file_id = record(&mut ctx, &file_item, &file_validated);
    assert_eq!(
        ctx.record(
            &file_op,
            &journal_record(file_id, &file_item, &file_validated),
            5_000
        ),
        Err(mismatch)
    );
    let key_id = record(&mut ctx, &key_item, &key_validated);

    let op_kind = Blocker::DenyListed {
        rule: reason::OP_KIND.into(),
    };
    assert_refused(
        &open_and_check_path(&ctx, key_id),
        op_kind.clone(),
        reason::OP_KIND,
    );
    assert_refused(&open_and_check_key(&ctx, file_id), op_kind, reason::OP_KIND);
    // An op id that was never recorded.
    assert_refused(
        &open_and_check_key(&ctx, OpId(77)),
        Blocker::DenyListed {
            rule: reason::NOT_VALIDATED.into(),
        },
        reason::NOT_VALIDATED,
    );
}

/// Review finding S5, part 1: the act-time gate took the exemptions (and the stamp) from its caller, so
/// nothing tied them to the journal. Now they come from the `validated` record alone. A file whose name
/// looks like an 8.3 short name passes with `long_names_resolved` and is refused without it: the act
/// follows the journal record, whatever the validation in memory said.
#[test]
fn the_act_takes_its_exemptions_from_the_journal_record() {
    let s = Scratch::new("exempt");
    let f = s.file("ABCDEF~1.TXT", b"x");
    let op = mv(&f);
    let item = GateItem::new(&op, long());
    let validated = validate(&ctx(&[]), &item);
    assert!(matches!(validated, GateOutcome::Pass(_)), "{validated:?}");

    let mut as_journalled = ctx(&[]);
    let id = record(&mut as_journalled, &item, &validated);
    assert!(matches!(
        open_and_check_path(&as_journalled, id),
        GateOutcome::Pass(_)
    ));

    let mut narrower = journal_record(OpId(1), &item, &validated);
    narrower.exemptions.long_names_resolved = false;
    let mut from_journal = ctx(&[]);
    from_journal.record(&op, &narrower, item.max_files).unwrap();
    assert_eq!(
        from_journal.exemptions(OpId(1)),
        Some(Exemptions::default())
    );
    let outcome = open_and_check_path(&from_journal, OpId(1));
    let refusal = outcome.refusal().unwrap();
    assert_eq!(
        (&refusal.blocker, refusal.reason),
        (
            &Blocker::DenyListed {
                rule: "canon.short-name-unresolved".into()
            },
            live_reason::DENY_LEXICAL
        ),
        "{outcome:?}"
    );
}

/// Review finding M5 (wave 2): the walk read a whole directory listing before it tested the limit. The
/// capped listing stops once it holds more than the budget, and the walk refuses a directory with more
/// entries than twice the limit without listing it whole.
#[test]
fn the_tree_walk_never_holds_more_than_its_budget() {
    let s = Scratch::new("capped");
    let d = s.dir("many");
    for i in 0..9 {
        s.file(&format!(r"many\f{i}.txt"), b"x");
    }
    s.dir(r"many\sub");
    let p = ext(&d).unwrap();
    assert_eq!(
        ffi::list_dir_capped(&p, 10).unwrap().map(|e| e.len()),
        Some(10)
    );
    assert_eq!(ffi::list_dir_capped(&p, 9).unwrap().map(|e| e.len()), None);
    assert_eq!(ffi::list_dir_capped(&p, 0).unwrap().map(|e| e.len()), None);
    // The listing is the one `purge-win` gives.
    let mut capped = ffi::list_dir_capped(&p, 100).unwrap().unwrap();
    let mut full = purge_win::fs::list_dir(&p).unwrap();
    capped.sort_by(|a, b| a.name.cmp(&b.name));
    full.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(capped, full);
    // An empty directory.
    let empty = ext(&s.dir("empty")).unwrap();
    assert_eq!(ffi::list_dir_capped(&empty, 0).unwrap(), Some(Vec::new()));

    // 10 entries, limit 4: refused from a listing capped at 8 entries.
    let op = mv(&d);
    let ctx = ctx(std::slice::from_ref(&op));
    let item = GateItem {
        max_files: 4,
        ..GateItem::new(&op, long())
    };
    assert_refused(
        &validate(&ctx, &item),
        Blocker::TooLarge,
        reason::BLAST_RADIUS,
    );
    // Limit 9: 9 files and 1 directory pass.
    let item = GateItem {
        max_files: 9,
        ..GateItem::new(&op, long())
    };
    let validated = validate(&ctx, &item);
    let Some(ItemFacts::File(facts)) = validated.item_facts() else {
        panic!("{validated:?}");
    };
    assert_eq!(facts.tree_entries, Some(10));
}

// ---------------------------------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------------------------------

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
        use crate::test_ffi::*;
        let name = wz(&self.rel(sub));
        let mut key: Hkey = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated; class, security and disposition are null; `key` is a valid
        // out-pointer.
        let rc = unsafe {
            RegCreateKeyExW(
                hkey_users(),
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
        let value = wz("SymbolicLinkValue");
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
        use crate::test_ffi::*;
        let name = wz(&self.rel(sub));
        let mut key: Hkey = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated; `key` is a valid out-pointer.
        let rc = unsafe {
            RegOpenKeyExW(
                hkey_users(),
                name.as_ptr(),
                REG_OPTION_OPEN_LINK,
                DELETE_ACCESS | KEY_WOW64_64KEY,
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
    let mut ctx = ctx(&[]);
    let item = GateItem::new(&op, long());

    let validated = validate(&ctx, &item);
    let id = record(&mut ctx, &item, &validated);
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

    let checked = open_and_check_key(&ctx, id).pass().unwrap();
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
    let outcome = open_and_check_key(&ctx, id);
    assert_refused(
        &outcome,
        Blocker::ChangedSinceScan,
        live_reason::VALUE_CHANGED,
    );
    // Same bytes, other type.
    k.set("App", "InstallDir", 2, &utf16z(r"C:\App"));
    assert_refused(
        &open_and_check_key(&ctx, id),
        Blocker::ChangedSinceScan,
        live_reason::VALUE_CHANGED,
    );
    // Gone.
    k.open("App", KeyAccess::SET_VALUE)
        .delete_value("InstallDir")
        .unwrap();
    assert!(open_and_check_key(&ctx, id).is_vanished());
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
    let seg_id = validate_and_record(&mut ctx, &seg_item);
    assert!(matches!(ctx.stamp(seg_id), Some(Stamp::Value(_))));
    assert!(matches!(
        open_and_check_key(&ctx, seg_id),
        GateOutcome::Pass(_)
    ));
}

#[test]
fn key_actions_and_emptiness() {
    let k = TestKey::new();
    k.create(r"Vendor\App\Sub");
    k.set(r"Vendor\App", "v", REG_DWORD, &[1, 0, 0, 0]);
    let mut ctx = ctx(&[]);
    let sid = current_user_sid().unwrap();

    let tree = ExecOp::DeleteKeyTree {
        key: k.wire(r"Vendor\App"),
    };
    let item = GateItem::new(&tree, long());
    let outcome = validate(&ctx, &item);
    let id = record(&mut ctx, &item, &outcome);
    let validated = outcome.pass().unwrap();
    let ItemFacts::Key(facts) = &validated.facts else {
        panic!("{validated:?}");
    };
    assert_eq!(validated.stamp, Stamp::Key(facts.clone()));
    assert_eq!(
        (
            facts.subkeys,
            facts.values,
            facts.is_link,
            facts.owner.as_str()
        ),
        (1, 1, false, sid.as_str())
    );
    let checked = open_and_check_key(&ctx, id).pass().unwrap();
    assert_eq!(checked.item_facts(), &validated.facts);
    assert_eq!(
        (checked.address().root, checked.address().view),
        (KeyRoot::Hku, View::K64)
    );
    assert!(prefix::is_same(
        &checked.address().path,
        &k.rel(r"Vendor\App")
    ));
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
    let empty_id = validate_and_record(&mut ctx, &empty_item);
    let checked = open_and_check_key(&ctx, empty_id).pass().unwrap();
    // The handle can act: it was opened with DELETE, and the key really is deleted through it.
    checked.key().delete().unwrap();
    drop(checked);
    assert!(open_and_check_key(&ctx, empty_id).is_vanished());

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
    let mut ctx = ctx(&[]);

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
    // Even with a journal record that gives the link the facts of the plain key it points to.
    let real = ExecOp::DeleteKeyTree {
        key: k.wire("Real"),
    };
    let real_item = GateItem::new(&real, long());
    let mut forged = journal_record(OpId(50), &real_item, &validate(&ctx, &real_item));
    forged.target = leaf.target();
    ctx.record(&leaf, &forged, leaf_item.max_files).unwrap();
    assert_refused(
        &open_and_check_key(&ctx, OpId(50)),
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
    let plain_id = validate_and_record(&mut ctx, &plain_item);
    TestKey::nuke(&k.open("Plain", KeyAccess::DELETE));
    k.link("Plain", "Real");
    assert_refused(
        &open_and_check_key(&ctx, plain_id),
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

    // Undo destinations: below a link refused, a missing key below plain keys allowed by the guard.
    let below_link = Target::RegKey {
        path: k.wire(r"Link\New"),
    };
    let refusal = check_undo_key(&ctx, &below_link, &long()).unwrap_err();
    assert_eq!(refusal.blocker, Blocker::RegLink);
    let value_below_link = Target::RegValue {
        path: k.wire(r"Link\Sub"),
        name: "v".into(),
    };
    let refusal = check_undo_key(&ctx, &value_below_link, &long()).unwrap_err();
    assert_eq!(refusal.blocker, Blocker::RegLink);
    let fresh = Target::RegKey {
        path: k.wire(r"Real\New"),
    };
    let parent = check_undo_key(&ctx, &fresh, &long())
        .unwrap()
        .into_parent()
        .unwrap();
    assert_eq!(parent.leaf(), "New");
    assert!(!parent.key_exists());
    // Changed with review finding S4: a missing parent used to pass (`Ok(())`); with no parent to hand
    // out for the re-create, it is now an undo conflict.
    let deeper = Target::RegKey {
        path: k.wire(r"Real\New\Deeper"),
    };
    let refusal = check_undo_key(&ctx, &deeper, &long()).unwrap_err();
    assert_eq!(
        (refusal.blocker, refusal.reason),
        (Blocker::ChangedSinceScan, reason::UNDO_KEY_MISSING)
    );
}

/// Review finding S4: `check_undo_key` returned `()`, so the undo had to open the parent again by path
/// after the check, and a key swapped in between was never checked. Now the check hands out the parent it
/// opened and judged. The parent is replaced after the check (deleted and re-created at the same path):
/// the re-create through the checked handle fails on the deleted key instead of landing in the
/// replacement, which stays untouched.
#[test]
fn the_undo_key_check_hands_out_the_key_it_checked() {
    let k = TestKey::new();
    k.create(r"Vendor\App");
    k.set(r"Vendor\App", "InstallDir", REG_SZ, &utf16z(r"C:\App"));
    let ctx = ctx(&[]);

    // A key to re-create below an existing parent: the parent handle can create it.
    let target = Target::RegKey {
        path: k.wire(r"Vendor\Gone"),
    };
    let parent = check_undo_key(&ctx, &target, &long())
        .unwrap()
        .into_parent()
        .unwrap();
    assert_eq!(parent.leaf(), "Gone");
    assert_eq!(parent.address().root, KeyRoot::Hku);
    assert!(prefix::is_same(
        &parent.address().path,
        &k.rel(r"Vendor\Gone")
    ));
    assert_eq!(parent.facts().node, KeyNode::Missing);
    assert!(
        parent
            .facts()
            .ancestors
            .iter()
            .all(|a| a.node == KeyNode::Plain)
    );
    parent
        .parent()
        .create_subkey(parent.leaf(), "", None, false)
        .unwrap();
    assert!(k.open(r"Vendor\Gone", KeyAccess::READ).info().is_ok());

    // The parent replaced after the check.
    let target = Target::RegKey {
        path: k.wire(r"Vendor\Again"),
    };
    let parent = check_undo_key(&ctx, &target, &long())
        .unwrap()
        .into_parent()
        .unwrap();
    TestKey::nuke(&k.open("Vendor", KeyAccess::DELETE));
    k.create("Vendor");
    assert!(
        parent
            .parent()
            .create_subkey(parent.leaf(), "", None, false)
            .is_err()
    );
    assert_eq!(
        k.open("Vendor", KeyAccess::READ).info().unwrap().n_subkeys,
        0
    );

    // A value goes back into the key itself, opened for setting values.
    k.create(r"Vendor\App");
    let value = Target::RegValue {
        path: k.wire(r"Vendor\App"),
        name: "InstallDir".into(),
    };
    let key = check_undo_key(&ctx, &value, &long())
        .unwrap()
        .into_value_key()
        .unwrap();
    assert_eq!(key.facts().node, KeyNode::Plain);
    key.key()
        .set_value_raw("InstallDir", REG_SZ, &utf16z(r"C:\App"))
        .unwrap();
    assert!(
        k.open(r"Vendor\App", KeyAccess::READ)
            .value("InstallDir")
            .unwrap()
            .is_some()
    );
    // The key of a value that no longer exists: nothing to restore into.
    let orphan = Target::RegValue {
        path: k.wire(r"Vendor\Nowhere"),
        name: "v".into(),
    };
    let refusal = check_undo_key(&ctx, &orphan, &long()).unwrap_err();
    assert_eq!(
        (refusal.blocker, refusal.reason),
        (Blocker::ChangedSinceScan, reason::UNDO_KEY_MISSING)
    );
}

/// Review finding S5, part 2: a key action was re-checked at act time with `Binding::Capture`, so a key
/// that changed after validation passed. Now the act compares the facts of the acting handle with the
/// journal record: a new subkey, a new value, or only a moved last write time (a value set and
/// removed again, counts unchanged) is "changed since the scan".
#[test]
fn a_key_changed_after_validation_is_refused_at_the_act() {
    let k = TestKey::new();
    k.create(r"Vendor\App");
    k.set(r"Vendor\App", "v", REG_DWORD, &[1, 0, 0, 0]);
    let op = ExecOp::DeleteKeyTree {
        key: k.wire(r"Vendor\App"),
    };
    let item = GateItem::new(&op, long());
    let validated = validate(&ctx(&[]), &item);
    let fresh = |validated: &GateOutcome<Validation>| {
        let mut ctx = ctx(&[]);
        let id = record(&mut ctx, &item, validated);
        (ctx, id)
    };
    let (unchanged, id) = fresh(&validated);
    assert!(matches!(
        open_and_check_key(&unchanged, id),
        GateOutcome::Pass(_)
    ));

    let changed = |what: &str| {
        let (ctx, id) = fresh(&validated);
        let outcome = open_and_check_key(&ctx, id);
        assert_refused(&outcome, Blocker::ChangedSinceScan, reason::KEY_CHANGED);
        assert!(!outcome.refusal().unwrap().is_hard(), "{what}");
    };
    // Counts unchanged, last write time moved.
    std::thread::sleep(std::time::Duration::from_millis(20));
    k.set(r"Vendor\App", "w", REG_DWORD, &[2, 0, 0, 0]);
    k.open(r"Vendor\App", KeyAccess::SET_VALUE)
        .delete_value("w")
        .unwrap();
    changed("last write time");
    // A value more.
    let validated_again = validate(&ctx(&[]), &item);
    k.set(r"Vendor\App", "w", REG_DWORD, &[2, 0, 0, 0]);
    let (ctx2, id2) = fresh(&validated_again);
    assert_refused(
        &open_and_check_key(&ctx2, id2),
        Blocker::ChangedSinceScan,
        reason::KEY_CHANGED,
    );
    // A subkey more.
    let validated_again = validate(&ctx(&[]), &item);
    k.create(r"Vendor\App\Late");
    let (ctx3, id3) = fresh(&validated_again);
    assert_refused(
        &open_and_check_key(&ctx3, id3),
        Blocker::ChangedSinceScan,
        reason::KEY_CHANGED,
    );
}

/// Review finding S1, the half the pure guard cannot check: the addresses [`live::key_probe`] hands out
/// for 32-bit and 64-bit machine class keys, and for an ordinary 32-bit key, all open on this machine
/// with `REG_OPTION_OPEN_LINK` on every component, and none of them (key or ancestor) is a link. Before
/// the fix, the walk through `SOFTWARE\WOW6432Node\Classes` met a registry link. Read-only, unelevated.
#[test]
fn class_and_32_bit_keys_open_at_the_probe_addresses_without_a_link() {
    let env = live_env(None);
    let addr = |view: View, path: &str| KeyAddress {
        root: KeyRoot::Hklm,
        view,
        path: path.to_owned(),
    };
    let cases = [
        (
            r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID",
            addr(View::K32, r"SOFTWARE\Classes\CLSID"),
        ),
        (
            r"HKLM\SOFTWARE\Classes\CLSID",
            addr(View::K64, r"SOFTWARE\Classes\CLSID"),
        ),
        (
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion",
            addr(View::K32, r"SOFTWARE\Microsoft\Windows\CurrentVersion"),
        ),
    ];
    let mut failures = Vec::new();
    for (spelling, expected) in cases {
        let target = Target::RegKey {
            path: spelling.to_owned(),
        };
        let probe = match live::key_probe(&target, &env) {
            Ok(probe) => probe,
            Err(refusal) => {
                failures.push(format!("{spelling}: key_probe refused: {refusal:?}"));
                continue;
            }
        };
        if !probe.open.is_same(&expected) {
            failures.push(format!(
                "{spelling}: probe.open is {}, expected {expected}",
                probe.open
            ));
        }
        let depth = prefix::depth(&expected.path);
        if probe.ancestors.len() + 1 != depth {
            failures.push(format!(
                "{spelling}: {} ancestors for a key of depth {depth}",
                probe.ancestors.len()
            ));
        }
        for (what, at) in std::iter::once(("open", &probe.open))
            .chain(probe.ancestors.iter().map(|a| ("ancestor", a)))
        {
            // `open_addr` is `WKey::open(root, path, view, access)` with the one-to-one mapping.
            match open_addr(at, KeyAccess::READ) {
                Ok(key) => {
                    let link = (key.is_link(), key.flags().map(|f| f.link));
                    if link != (Ok(false), Ok(false)) {
                        failures.push(format!("{spelling}: {what} {at}: link state {link:?}"));
                    }
                }
                Err(e) => failures.push(format!("{spelling}: {what} {at}: open failed: {e:?}")),
            }
        }
        // The gate's own probes agree.
        if probe_node(&probe.open) != KeyNode::Plain
            || probe_ancestors(&probe)
                .iter()
                .any(|a| a.node != KeyNode::Plain)
        {
            failures.push(format!("{spelling}: a probed node is not plain"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

// ---------------------------------------------------------------------------------------------------
// Exemptions in the journal
// ---------------------------------------------------------------------------------------------------

#[test]
fn exemptions_survive_the_journal_round_trip() {
    for bits in 0u8..16 {
        let guard = Exemptions {
            proven_owned_skeleton: bits & 1 != 0,
            environment_segment_edit: bits & 2 != 0,
            tier_a_start_menu_entry: bits & 4 != 0,
            long_names_resolved: bits & 8 != 0,
        };
        let journal = exemptions_to_journal(&guard);
        assert_eq!(
            (
                journal.proven_owned_skeleton,
                journal.environment_segment_edit,
                journal.tier_a_start_menu_entry,
                journal.long_names_resolved
            ),
            (
                guard.proven_owned_skeleton,
                guard.environment_segment_edit,
                guard.tier_a_start_menu_entry,
                guard.long_names_resolved
            )
        );
        assert_eq!(exemptions_from_journal(&journal), guard);
        // And through the record's JSON, as undo reads it back.
        let text = serde_json::to_string(&journal).unwrap();
        let read: GateExemptions = serde_json::from_str(&text).unwrap();
        assert_eq!(exemptions_from_journal(&read), guard);
    }
}
