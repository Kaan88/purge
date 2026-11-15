//! Tests of the locked-file ladder: a relaxed store and a real journal in fresh temp directories, the
//! in-memory boot-time move list (no test writes `HKLM`), injected ancestor verdicts, and one real lock
//! in a user-writable temp directory through the real gate, the real ancestor check and Restart Manager.

use std::cell::{Cell, Ref, RefCell};
use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

use purge_guard::canon::{GuardEnv, ProfileEnv};
use purge_guard::deny::{DenyList, Exemptions};
use purge_guard::live::{PathFacts, reason as live_reason};
use purge_model::exec::journal::{GateExemptions, Header, JournalSchema, Record, Validated};
use purge_model::exec::op::FileIdHex;
use purge_model::{ScanMode, Target};
use purge_win::rm::{LockerKind, LockerList};
use purge_win::sid::current_user_sid;

use super::*;
use crate::gate::{GateItem, GateOutcome};
use crate::journal::{JournalWriter, sha256_bytes};
use crate::prepare::RestartManager;
use crate::storage::StorageRoots;

// ---------------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------------

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A fresh directory below the temp directory, in long form, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "purge-lock-{tag}-{:x}-{nanos:x}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let long = FileHandle::open(&extended_path(&dir).unwrap())
            .unwrap()
            .final_path()
            .unwrap();
        Scratch(PathBuf::from(long.trim_start_matches(r"\\?\")))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(extended_path(&self.0).unwrap());
    }
}

fn env_var(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

/// A `GuardEnv` for this machine and user.
fn live_env() -> GuardEnv {
    let sid = current_user_sid().unwrap();
    let profile = env_var("USERPROFILE");
    let set = purge_win::reg::current_control_set().unwrap();
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
        purge_dirs: vec![format!(r"{}\Purge", env_var("ProgramData"))],
        ..GuardEnv::default()
    }
}

fn item(n: u32) -> CandidateId {
    CandidateId(format!("c-{n:03}"))
}

fn mv(path: &str) -> ExecOp {
    ExecOp::QuarantineMove {
        path: path.to_owned(),
    }
}

/// The facts of a real file, as the validated record holds them.
fn facts_of(path: &str) -> FileFacts {
    let handle = FileHandle::open(&extended_path(Path::new(path)).unwrap()).unwrap();
    let meta = handle.metadata().unwrap();
    FileFacts {
        final_path: path.to_owned(),
        file_id: FileIdHex(meta.file_id.id),
        volume_serial: meta.file_id.volume_serial,
        reparse_tag: meta.reparse_tag,
        attributes: meta.attributes,
        n_links: meta.n_links,
        is_dir: meta.is_dir,
        size: if meta.is_dir { 0 } else { meta.size },
        tree_entries: None,
        tree_bytes: None,
    }
}

/// The exemptions of an item whose path is in long form, as journalled.
fn long_names() -> GateExemptions {
    GateExemptions {
        long_names_resolved: true,
        ..GateExemptions::default()
    }
}

/// What the gate hands over for a locked item: the stamp its read-only look saw and the open error.
fn locked_path(seen: PathStamp, error: Win32Error) -> LockedPath {
    LockedPath {
        facts: PathFacts::default(),
        stamp: seen,
        error,
    }
}

fn stamp_of(facts: &FileFacts) -> PathStamp {
    PathStamp {
        identity: FileIdentity {
            volume_serial: facts.volume_serial,
            file_id: facts.file_id.0,
        },
        is_dir: facts.is_dir,
    }
}

/// One plan item of a fixture: a file `app\f<n>.dll` and its quarantine destination.
struct Item {
    source: String,
    facts: FileFacts,
    quarantine: String,
}

/// A session in a fresh relaxed store with a journal whose items are quarantine moves of real files,
/// all validated (each `validated` record written, then handed to the gate context `ctx`, as the
/// executor does), each with its op directory created.
struct Fx {
    session: SessionDir,
    scope: StoreScope,
    journal: RefCell<JournalWriter>,
    ctx: GateCtx,
    items: Vec<Item>,
    /// Last: removed after the journal and the session's handles are closed.
    scratch: Scratch,
}

impl Fx {
    fn new(tag: &str, n: u32) -> Fx {
        Fx::with(tag, n, |_, _| {})
    }

    /// `adjust` may change an item's source (for example to a directory) before it is validated.
    fn with(tag: &str, n: u32, adjust: impl Fn(u32, &Path)) -> Fx {
        let scratch = Scratch::new(tag);
        let roots = StorageRoots::install_relaxed(&scratch.0.join("data")).unwrap();
        let session = roots.create_session().unwrap();
        let scope = roots.store_scope::<&Path>(session.id(), &[]).unwrap();
        std::fs::create_dir(scratch.0.join("app")).unwrap();
        let mut items = Vec::new();
        for i in 1..=n {
            let source = scratch.0.join("app").join(format!("f{i}.dll"));
            std::fs::write(&source, format!("payload {i}")).unwrap();
            adjust(i, &source);
            let source = source.to_str().unwrap().to_owned();
            let facts = facts_of(&source);
            let op_dir = session
                .create_op_dir(Path::new(&source), facts.volume_serial, OpId(i))
                .unwrap();
            let quarantine = op_dir
                .item_path(&format!("f{i}.dll"))
                .to_str()
                .unwrap()
                .to_owned();
            items.push(Item {
                source,
                facts,
                quarantine,
            });
        }
        let header = Header {
            schema: JournalSchema,
            session: session.id().clone(),
            created: FileTime(134_078_121_020_000_000),
            engine_version: "0.1.0".into(),
            app: "vendor-app".into(),
            plan_hash: sha256_bytes(b"plan"),
            selection_hash: sha256_bytes(b"selection"),
            policy_version: "m1a.6".into(),
            mode: ScanMode::Post,
            items: n,
            allow_irreversible: false,
            volumes: Vec::new(),
        };
        let mut journal = JournalWriter::create(&session, header).unwrap();
        let ops: Vec<ExecOp> = items.iter().map(|it| mv(&it.source)).collect();
        let mut ctx = GateCtx::new(DenyList::compile(&live_env()), &ops, scope.clone()).unwrap();
        for (i, it) in items.iter().enumerate() {
            let op = OpId(i as u32 + 1);
            let record = Validated {
                op,
                item: item(op.0),
                target: Target::Path {
                    path: it.source.clone(),
                },
                facts: ItemFacts::File(it.facts.clone()),
                exemptions: long_names(),
            };
            journal.validated(record.clone()).unwrap();
            ctx.record(&ops[i], &record, 5_000).unwrap();
        }
        Fx {
            session,
            scope,
            journal: RefCell::new(journal),
            ctx,
            items,
            scratch,
        }
    }

    fn it(&self, n: u32) -> &Item {
        &self.items[n as usize - 1]
    }

    /// The `validated` record the fixture journalled for op `n`.
    fn record(&self, n: u32) -> Validated {
        let it = self.it(n);
        Validated {
            op: OpId(n),
            item: item(n),
            target: Target::Path {
                path: it.source.clone(),
            },
            facts: ItemFacts::File(it.facts.clone()),
            exemptions: long_names(),
        }
    }

    /// The hand-over for op `n`: locked with a sharing violation, the gate having seen the validated item.
    fn locked(&self, n: u32) -> LockedItem {
        let it = self.it(n);
        let seen = stamp_of(&it.facts);
        let locked = locked_path(seen, Win32Error(32));
        LockedItem::from_gate(&self.ctx, OpId(n), &locked, it.quarantine.clone()).unwrap()
    }

    /// The hand-over as the executor builds it ([`LockedItem::from_gate`]) from a gate context holding
    /// `record` for `exec_op`: a deliberately forged record (other facts or another op than the
    /// journalled one), what the gate saw (`seen`), the open error and the quarantine path.
    fn forged(
        &self,
        exec_op: &ExecOp,
        record: &Validated,
        seen: PathStamp,
        error: Win32Error,
        quarantine: &str,
    ) -> LockedItem {
        let mut ctx = GateCtx::new(
            DenyList::compile(&live_env()),
            std::slice::from_ref(exec_op),
            self.scope.clone(),
        )
        .unwrap();
        ctx.record(exec_op, record, 5_000).unwrap();
        LockedItem::from_gate(&ctx, record.op, &locked_path(seen, error), quarantine).unwrap()
    }

    /// Prepares, journals and acts as the executor does, and journals the result.
    fn run(&self, ladder: &Ladder<'_>, n: u32, store: &mut dyn PendingRenames) -> LockResult {
        let locked = self.locked(n);
        self.run_item(ladder, &locked, store)
    }

    fn run_item(
        &self,
        ladder: &Ladder<'_>,
        locked: &LockedItem,
        store: &mut dyn PendingRenames,
    ) -> LockResult {
        match ladder.prepare(locked, None) {
            LockPrepared::Decided(result) => {
                assert!(result.outcome.allowed_without_intent(), "{result:?}");
                self.journal
                    .borrow_mut()
                    .done_without_intent(locked.op(), result.outcome.clone())
                    .unwrap();
                result
            }
            LockPrepared::Ready(action) => {
                let intent = action.intent_to_write().expect("no intent yet").clone();
                assert!(intent.is_consistent());
                let token = self.journal.borrow_mut().intent(intent).unwrap();
                let result = ladder.act(action, &token, store);
                self.journal
                    .borrow_mut()
                    .done(token, result.outcome.clone())
                    .unwrap();
                result
            }
        }
    }

    fn state(&self) -> Ref<'_, JournalState> {
        Ref::map(self.journal.borrow(), JournalWriter::state)
    }

    fn op(&self, n: u32) -> Ref<'_, OpState> {
        Ref::map(self.state(), |s| s.op(OpId(n)).unwrap())
    }
}

/// Injected facts: the ancestor verdict, and optionally the destination facts and the look at a path
/// (live when `None`).
struct Env {
    ancestors: BootMove,
    destination: Option<DestinationFacts>,
    look: Option<SourceState>,
}

impl Env {
    fn admin_only() -> Env {
        Env {
            ancestors: BootMove::Allowed,
            destination: None,
            look: None,
        }
    }

    fn holding(code: &'static str) -> Env {
        Env {
            ancestors: BootMove::Hold(code),
            ..Env::admin_only()
        }
    }
}

impl LadderEnv for Env {
    fn ancestors(&self, _: &str) -> BootMove {
        self.ancestors
    }

    fn destination(&self, destination: &str) -> DestinationFacts {
        self.destination
            .clone()
            .unwrap_or_else(|| LiveLadder.destination(destination))
    }

    fn look(&self, path: &str) -> SourceState {
        self.look.unwrap_or_else(|| LiveLadder.look(path))
    }
}

/// A Restart Manager stand-in.
#[derive(Default)]
struct FakeRm {
    holders: Vec<purge_win::rm::Locker>,
    fail: bool,
    calls: Cell<u32>,
}

impl LockerQuery for FakeRm {
    fn query(&self, files: &[PathBuf]) -> Result<LockerList, Win32Error> {
        self.calls.set(self.calls.get() + 1);
        assert!(files.iter().all(|f| f.is_absolute()));
        if self.fail {
            return Err(Win32Error::ACCESS_DENIED);
        }
        Ok(LockerList {
            lockers: self.holders.clone(),
            reboot_reasons: RebootReasons(0),
        })
    }
}

fn raw_locker(pid: u32, name: &str) -> purge_win::rm::Locker {
    purge_win::rm::Locker {
        pid,
        start_time: 1,
        app_name: name.to_owned(),
        service_name: None,
        kind: LockerKind::MainWindow,
        restartable: false,
        ts_session: Some(1),
    }
}

fn ladder<'a>(
    fx: &'a Fx,
    env: &'a dyn LadderEnv,
    rm: &'a dyn LockerQuery,
    consent: &'a dyn ConsentCallback,
) -> Ladder<'a> {
    Ladder {
        env,
        scope: &fx.scope,
        lockers: rm,
        consent,
    }
}

/// The NT pair `MoveFileExW` stores for op `n`.
fn nt_pair(fx: &Fx, n: u32) -> PendingPair {
    let it = fx.it(n);
    fs_write::pending_pair(Path::new(&it.source), Path::new(&it.quarantine)).unwrap()
}

fn units(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    push_units(&mut out, s);
    out
}

/// Foreign pairs: a plain move, a delete, a marked entry, and near misses of op 1's pair of `fx`.
fn foreign(fx: &Fx) -> Vec<(String, String)> {
    let ours = nt_pair(fx, 1);
    vec![
        (
            r"\??\C:\Other\setup.tmp".to_owned(),
            r"\??\C:\Other\setup.dll".to_owned(),
        ),
        (r"\??\C:\Other\old.log".to_owned(), String::new()),
        (
            r"*1\??\C:\Other\marked.bin".to_owned(),
            r"!\??\C:\Other\marked.new".to_owned(),
        ),
        (ours.src.clone(), r"\??\C:\Elsewhere\f1.dll".to_owned()),
        (ours.src.to_uppercase(), ours.dst.to_uppercase()),
    ]
}

fn store_of(pairs: &[(String, String)]) -> MemoryPendingRenames {
    let refs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(s, d)| (s.as_str(), d.as_str()))
        .collect();
    MemoryPendingRenames::with_pairs(&refs)
}

fn pending(result: &LockResult) -> (BootMovePair, bool) {
    match &result.outcome {
        ItemOutcome::PendingReboot { pair, confirmed } => (pair.clone(), *confirmed),
        other => panic!("not a pending reboot: {other:?} ({})", result.detail),
    }
}

// ---------------------------------------------------------------------------------------------------
// The ladder
// ---------------------------------------------------------------------------------------------------

/// The real thing, unelevated: a file in a user-writable temp directory, held by another thread without
/// delete sharing, goes through the real gate (`Locked`), the real ancestor check, the real destination
/// facts and Restart Manager. It is held for the next run and no pair is ever registered.
#[test]
fn a_locked_file_in_a_user_writable_temp_dir_never_gets_a_pair() {
    let fx = Fx::new("real", 1);
    let source = fx.it(1).source.clone();
    let op = mv(&source);
    let mut ctx = GateCtx::new(
        DenyList::compile(&live_env()),
        std::slice::from_ref(&op),
        fx.scope.clone(),
    )
    .unwrap();
    let gate_item = GateItem::new(
        &op,
        Exemptions {
            long_names_resolved: true,
            ..Exemptions::default()
        },
    );
    // The executor's flow: validate, journal the record (the fixture did), hand it to the gate.
    let record = match gate::validate(&ctx, &gate_item) {
        GateOutcome::Pass(v) => v.to_journal(OpId(1), item(1), op.target()),
        other => panic!("validate: {other:?}"),
    };
    ctx.record(&op, &record, gate_item.max_files).unwrap();

    // A thread holds the file with read sharing only.
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let held = source.clone();
    let holder = std::thread::spawn(move || {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(0x1) // FILE_SHARE_READ: no delete sharing
            .open(&held)
            .unwrap();
        locked_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        drop(file);
    });
    locked_rx.recv().unwrap();

    let locked = match gate::open_and_check_path(&ctx, OpId(1)) {
        GateOutcome::Locked(locked) => locked,
        other => panic!("expected Locked, got {other:?}"),
    };
    assert_eq!(FsError::from(locked.error), FsError::SharingViolation);
    let item = LockedItem::from_gate(&ctx, OpId(1), &locked, fx.it(1).quarantine.clone()).unwrap();
    assert_eq!(
        item.validated(),
        &match &record.facts {
            ItemFacts::File(facts) => facts.clone(),
            other => panic!("{other:?}"),
        }
    );
    assert_eq!(
        LiveLadder.ancestors(&source),
        BootMove::Hold("live.boot.user-writable"),
        "a temp directory is user-writable"
    );

    let mut store = MemoryPendingRenames::default();
    let rm = RestartManager;
    let live = Ladder::live(&fx.scope, &rm);
    let result = fx.run_item(&live, &item, &mut store);
    release_tx.send(()).unwrap();
    holder.join().unwrap();

    assert_eq!(result.outcome, ItemOutcome::HeldRetry, "{}", result.detail);
    assert_eq!(result.code, Some("live.boot.user-writable"));
    assert!(
        result.lockers.iter().all(|l| l.pid != std::process::id()),
        "this process is never named as a locker: {:?}",
        result.lockers
    );
    assert_eq!(store.registers, 0);
    assert!(store.bytes().is_empty(), "no pair is ever written");
    assert!(Path::new(&source).exists(), "the item stays in place");
    assert_eq!(fx.state().held_retry().count(), 1);
}

#[test]
fn admin_only_ancestors_register_exactly_one_pair_after_the_intent() {
    let fx = Fx::new("register", 1);
    let foreign = foreign(&fx);
    let mut store = store_of(&foreign);
    let before = store.bytes().to_vec();
    let (env, rm) = (Env::admin_only(), FakeRm::default());
    let l = ladder(&fx, &env, &rm, &DenyAll);

    let result = fx.run(&l, 1, &mut store);

    let (pair, confirmed) = pending(&result);
    let expected = nt_pair(&fx, 1);
    assert!(confirmed);
    assert_eq!(pair, model_pair(&expected));
    assert!(!pair.dst.is_empty(), "a boot move, never a boot delete");
    assert_eq!(store.registers, 1);
    // Every foreign byte stays where it was; ours is appended before the terminator.
    let terminator = before.len() - 2;
    let mut want = before[..terminator].to_vec();
    want.extend(units(&expected.src));
    want.extend(units(&expected.dst));
    want.extend_from_slice(&[0, 0]);
    assert_eq!(store.bytes(), want.as_slice());
    // The intent came first, and names the destination the pair moves to.
    let op = fx.op(1);
    let intent = op.intent.as_ref().unwrap();
    assert!(
        matches!(&intent.inverse, Inverse::MoveBack { quarantine_path, .. }
        if *quarantine_path == fx.it(1).quarantine)
    );
    assert_eq!(op.outcome, Some(result.outcome.clone()));
    assert_eq!(fx.state().pending_reboot().count(), 1);
}

#[test]
fn every_failed_boot_move_condition_holds_the_item_and_writes_no_pair() {
    let serial = |fx: &Fx| fx.it(1).facts.volume_serial;
    let plain_dest = |fx: &Fx| LiveLadder.destination(&fx.it(1).quarantine);
    type Case = (&'static str, Box<dyn Fn(&Fx) -> Env>, &'static str);
    let cases: Vec<Case> = vec![
        (
            "user-writable ancestor",
            Box::new(|_| Env::holding("live.boot.user-writable")),
            "live.boot.user-writable",
        ),
        (
            "reparse point on the chain",
            Box::new(|_| Env::holding("live.boot.reparse-point")),
            "live.boot.reparse-point",
        ),
        (
            "unknown ancestor fact",
            Box::new(|_| Env::holding("live.boot.fact-unknown")),
            "live.boot.fact-unknown",
        ),
        (
            "incomplete chain",
            Box::new(|_| Env::holding("live.boot.chain-incomplete")),
            "live.boot.chain-incomplete",
        ),
        (
            "destination parent is a junction",
            Box::new(move |fx| Env {
                destination: Some(DestinationFacts {
                    parent_reparse_tag: Some(0xA000_0003),
                    ..plain_dest(fx)
                }),
                ..Env::admin_only()
            }),
            live_reason::QUARANTINE_PARENT,
        ),
        (
            "destination unknown",
            Box::new(|_| Env {
                destination: Some(DestinationFacts::default()),
                ..Env::admin_only()
            }),
            live_reason::QUARANTINE_OTHER_VOLUME,
        ),
        (
            "destination occupied unknown",
            Box::new(move |fx| Env {
                destination: Some(DestinationFacts {
                    occupied: None,
                    ..plain_dest(fx)
                }),
                ..Env::admin_only()
            }),
            live_reason::QUARANTINE_OCCUPIED,
        ),
        (
            "destination serial 0",
            Box::new(move |fx| Env {
                destination: Some(DestinationFacts {
                    parent_volume_serial: Some(0),
                    ..plain_dest(fx)
                }),
                ..Env::admin_only()
            }),
            live_reason::QUARANTINE_OTHER_VOLUME,
        ),
        (
            "destination on another volume",
            Box::new(move |fx| Env {
                destination: Some(DestinationFacts {
                    parent_volume_serial: Some(serial(fx) ^ 1),
                    ..plain_dest(fx)
                }),
                ..Env::admin_only()
            }),
            live_reason::QUARANTINE_OTHER_VOLUME,
        ),
    ];
    for (name, make_env, code) in cases {
        let fx = Fx::new("hold", 1);
        let mut store = store_of(&foreign(&fx));
        let before = store.bytes().to_vec();
        let env = make_env(&fx);
        let rm = FakeRm::default();
        let l = ladder(&fx, &env, &rm, &DenyAll);
        let result = fx.run(&l, 1, &mut store);
        assert_eq!(result.outcome, ItemOutcome::HeldRetry, "{name}: {result:?}");
        assert_eq!(result.code, Some(code), "{name}");
        assert_eq!(store.registers, 0, "{name}");
        assert_eq!(store.bytes(), before.as_slice(), "{name}");
    }
}

#[test]
fn an_occupied_destination_and_one_outside_the_session_hold_the_item() {
    // Something already at the destination (real file).
    let fx = Fx::new("occupied", 2);
    std::fs::write(&fx.it(1).quarantine, b"planted").unwrap();
    let mut store = MemoryPendingRenames::default();
    let (env, rm) = (Env::admin_only(), FakeRm::default());
    let l = ladder(&fx, &env, &rm, &DenyAll);
    let result = fx.run(&l, 1, &mut store);
    assert_eq!(result.outcome, ItemOutcome::HeldRetry);
    assert_eq!(result.code, Some(live_reason::QUARANTINE_OCCUPIED));

    // A destination outside this session's quarantine directories.
    let elsewhere = fx.scratch.0.join("elsewhere").join("f2.dll");
    let outside = LockedItem::from_gate(
        &fx.ctx,
        OpId(2),
        &locked_path(stamp_of(&fx.it(2).facts), Win32Error(32)),
        elsewhere.to_str().unwrap(),
    )
    .unwrap();
    std::fs::create_dir(fx.scratch.0.join("elsewhere")).unwrap();
    let result = fx.run_item(&l, &outside, &mut store);
    assert_eq!(result.outcome, ItemOutcome::HeldRetry);
    assert_eq!(result.code, Some(live_reason::QUARANTINE_OUTSIDE_STORE));
    assert_eq!(store.registers, 0);
    assert!(store.bytes().is_empty());
}

#[test]
fn serial_zero_and_cross_volume_are_held() {
    // The item's own serial recorded as 0 (the look agrees, so it is still "the same object"): a forged
    // journalled record.
    let fx = Fx::new("serial0", 1);
    let mut facts = fx.it(1).facts.clone();
    facts.volume_serial = 0;
    let record = Validated {
        facts: ItemFacts::File(facts.clone()),
        ..fx.record(1)
    };
    let seen = stamp_of(&facts);
    let locked = fx.forged(
        &mv(&fx.it(1).source),
        &record,
        seen,
        Win32Error(32),
        &fx.it(1).quarantine,
    );
    assert_eq!(locked.validated().volume_serial, 0);
    let env = Env {
        look: Some(SourceState::Present {
            identity: seen.identity,
            is_dir: false,
        }),
        ..Env::admin_only()
    };
    let rm = FakeRm::default();
    let mut store = MemoryPendingRenames::default();
    let l = ladder(&fx, &env, &rm, &DenyAll);
    let result = fx.run_item(&l, &locked, &mut store);
    assert_eq!(result.outcome, ItemOutcome::HeldRetry);
    assert_eq!(result.code, Some(reason::VOLUME_UNKNOWN));

    // Cross-volume: the destination directory reports another serial.
    let fx = Fx::new("xvol", 1);
    let mut dest = LiveLadder.destination(&fx.it(1).quarantine);
    dest.parent_volume_serial = Some(fx.it(1).facts.volume_serial.wrapping_add(7));
    let env = Env {
        destination: Some(dest),
        ..Env::admin_only()
    };
    let l = ladder(&fx, &env, &rm, &DenyAll);
    let result = fx.run(&l, 1, &mut store);
    assert_eq!(result.outcome, ItemOutcome::HeldRetry);
    assert_eq!(result.code, Some(live_reason::QUARANTINE_OTHER_VOLUME));
    assert_eq!(store.registers, 0);
}

#[test]
fn a_directory_is_never_moved_at_boot() {
    let fx = Fx::with("dir", 1, |_, source| {
        std::fs::remove_file(source).unwrap();
        std::fs::create_dir(source).unwrap();
    });
    // A directory's acting handle is refused with access denied when something below it is open (the
    // gate's `LockedPath` carries the Win32 error; `DirInUseOrDenied` reports as `ACCESS_DENIED`).
    assert_eq!(
        FsError::DirInUseOrDenied.code(),
        Win32Error::ACCESS_DENIED.code()
    );
    let locked = LockedItem::from_gate(
        &fx.ctx,
        OpId(1),
        &locked_path(stamp_of(&fx.it(1).facts), Win32Error::ACCESS_DENIED),
        fx.it(1).quarantine.clone(),
    )
    .unwrap();
    let mut store = MemoryPendingRenames::default();
    let (env, rm) = (Env::admin_only(), FakeRm::default());
    let l = ladder(&fx, &env, &rm, &DenyAll);
    let result = fx.run_item(&l, &locked, &mut store);
    assert_eq!(result.outcome, ItemOutcome::HeldRetry);
    assert_eq!(result.code, Some(reason::DIRECTORY));
    assert_eq!(rm.calls.get(), 0, "Restart Manager takes files only");
    assert!(!result.lockers_complete);
    assert_eq!(store.registers, 0);
}

#[test]
fn items_that_are_not_what_was_validated_are_decided_without_an_intent() {
    let fx = Fx::new("decided", 1);
    let rm = FakeRm::default();
    let decide = |env: &Env, locked: &LockedItem| match ladder(&fx, env, &rm, &DenyAll)
        .prepare(locked, None)
    {
        LockPrepared::Decided(result) => {
            assert!(result.outcome.allowed_without_intent());
            result
        }
        LockPrepared::Ready(action) => panic!("expected a decision, got {:?}", action.plan()),
    };
    let base = fx.locked(1);
    let it = fx.it(1);
    let seen = stamp_of(&it.facts);
    let other = FileIdentity {
        volume_serial: base.validated().volume_serial,
        file_id: [9; 16],
    };

    // Changed in meaning: the op comes from the journalled record, and a record of file facts fits only
    // a file op, so "not a move" is now a (forged) remove-dir-if-empty record of the same path.
    let rmdir = ExecOp::RemoveDirIfEmpty {
        path: it.source.clone(),
    };
    let not_a_move = fx.forged(&rmdir, &fx.record(1), seen, Win32Error(32), &it.quarantine);
    let r = decide(&Env::admin_only(), &not_a_move);
    assert_eq!(r.code, Some(reason::NOT_A_MOVE));

    let mut facts = it.facts.clone();
    facts.file_id = FileIdHex([0; 16]);
    let zero_id = Validated {
        facts: ItemFacts::File(facts),
        ..fx.record(1)
    };
    let no_id = fx.forged(
        &mv(&it.source),
        &zero_id,
        seen,
        Win32Error(32),
        &it.quarantine,
    );
    assert_eq!(
        decide(&Env::admin_only(), &no_id).code,
        Some(reason::IDENTITY_INVALID)
    );

    let denied = LockedItem::from_gate(
        &fx.ctx,
        OpId(1),
        &locked_path(seen, Win32Error::ACCESS_DENIED),
        it.quarantine.clone(),
    )
    .unwrap();
    let r = decide(&Env::admin_only(), &denied);
    assert_eq!(r.code, Some(reason::NOT_IN_USE));
    assert!(matches!(
        r.outcome,
        ItemOutcome::Failed {
            code: FailCode::AccessDenied,
            ..
        }
    ));

    let seen_other = LockedItem::from_gate(
        &fx.ctx,
        OpId(1),
        &locked_path(
            PathStamp {
                identity: other,
                is_dir: false,
            },
            Win32Error(32),
        ),
        it.quarantine.clone(),
    )
    .unwrap();
    let r = decide(&Env::admin_only(), &seen_other);
    assert_eq!(
        r.outcome,
        ItemOutcome::Skipped {
            reason: SkipReason::ChangedSinceScan
        }
    );

    let gone = Env {
        look: Some(SourceState::Absent),
        ..Env::admin_only()
    };
    assert_eq!(decide(&gone, &base).outcome, ItemOutcome::Vanished);

    let swapped = Env {
        look: Some(SourceState::Present {
            identity: other,
            is_dir: false,
        }),
        ..Env::admin_only()
    };
    assert_eq!(decide(&swapped, &base).code, Some(reason::CHANGED));

    let unreadable = Env {
        look: Some(SourceState::Unreadable(5)),
        ..Env::admin_only()
    };
    assert!(matches!(
        decide(&unreadable, &base).outcome,
        ItemOutcome::Failed {
            code: FailCode::Os,
            os_error: Some(5),
            ..
        }
    ));
}

#[test]
fn the_consent_callback_defaults_to_deny_and_nothing_is_ever_closed() {
    let own = std::process::id();
    let rm = FakeRm {
        holders: vec![raw_locker(4242, "Holder.exe"), raw_locker(own, "self")],
        ..FakeRm::default()
    };
    let holder = Locker {
        pid: 4242,
        name: "Holder.exe".into(),
        service: None,
    };

    // Default: asked once, denied; the ladder goes on.
    let fx = Fx::new("consent", 3);
    let env = Env::holding("live.boot.user-writable");
    let mut store = MemoryPendingRenames::default();
    let denied = fx.run(&ladder(&fx, &env, &rm, &DenyAll), 1, &mut store);
    assert_eq!(denied.close_consent, ConsentAnswer::Denied);
    assert_eq!(denied.lockers, vec![holder.clone()]);
    assert!(denied.lockers_complete);
    assert_eq!(denied.outcome, ItemOutcome::HeldRetry);

    // Allowed: recorded, but nothing is closed and the outcome is the same.
    let asked = Cell::new(0u32);
    let allow = |request: &ConsentRequest<'_>| {
        asked.set(asked.get() + 1);
        let ConsentRequest::CloseLockers { op, lockers, .. } = request;
        assert_eq!(*op, OpId(2));
        assert_eq!(lockers.len(), 1);
        Consent::Allow
    };
    let allowed = fx.run(&ladder(&fx, &env, &rm, &allow), 2, &mut store);
    assert_eq!(asked.get(), 1);
    assert_eq!(allowed.close_consent, ConsentAnswer::Allowed);
    assert_eq!(allowed.outcome, denied.outcome);
    assert!(
        allowed.detail.contains("nothing was closed"),
        "{}",
        allowed.detail
    );

    // No lockers: not asked.
    let quiet = FakeRm::default();
    let never = |_: &ConsentRequest<'_>| -> Consent { panic!("asked without lockers") };
    let r = fx.run(&ladder(&fx, &env, &quiet, &never), 3, &mut store);
    assert_eq!(r.close_consent, ConsentAnswer::NotAsked);
    assert_eq!(
        DenyAll.ask(&ConsentRequest::CloseLockers {
            op: OpId(1),
            path: "C:\\x",
            lockers: &[],
        }),
        Consent::Deny
    );
}

#[test]
fn a_failed_locker_query_is_reported_and_the_ladder_goes_on() {
    let fx = Fx::new("rmfail", 1);
    let rm = FakeRm {
        fail: true,
        ..FakeRm::default()
    };
    let env = Env::admin_only();
    let mut store = MemoryPendingRenames::default();
    let result = fx.run(&ladder(&fx, &env, &rm, &DenyAll), 1, &mut store);
    assert!(!result.lockers_complete);
    assert!(
        result.detail.contains("Restart Manager"),
        "{}",
        result.detail
    );
    pending(&result);
}

#[test]
fn a_boot_delete_is_never_chosen() {
    let fx = Fx::new("bootdelete", 2);
    let rm = FakeRm {
        holders: vec![raw_locker(4242, "Holder.exe")],
        ..FakeRm::default()
    };
    let allow = |_: &ConsentRequest<'_>| Consent::Allow;
    let mut store = MemoryPendingRenames::default();

    let explicit = request_boot_delete(&fx.locked(1));
    assert_eq!(
        explicit.outcome,
        ItemOutcome::Skipped {
            reason: SkipReason::GateBlocked {
                blocker: Blocker::ReversibilityNone
            }
        }
    );
    assert_eq!(explicit.code, Some(reason::BOOT_DELETE));

    // Even with everything allowed, the ladder registers a move with a destination, or holds.
    let env = Env::admin_only();
    let r = fx.run(&ladder(&fx, &env, &rm, &allow), 1, &mut store);
    let (pair, _) = pending(&r);
    assert!(!pair.dst.is_empty());
    let env = Env::holding("live.boot.user-writable");
    let r = fx.run(&ladder(&fx, &env, &rm, &allow), 2, &mut store);
    assert_eq!(r.outcome, ItemOutcome::HeldRetry);
    assert!(store.list().unwrap().iter().all(|p| !p.dst.is_empty()));
    assert_eq!(store.registers, 1);
}

#[test]
fn the_pair_is_journalled_as_read_back_with_the_marker() {
    let fx = Fx::new("marker", 1);
    let mut store = MemoryPendingRenames::default().with_marker("*1");
    let (env, rm) = (Env::admin_only(), FakeRm::default());
    let result = fx.run(&ladder(&fx, &env, &rm, &DenyAll), 1, &mut store);
    let (pair, confirmed) = pending(&result);
    assert!(confirmed);
    assert_eq!(pair.src, format!("*1{}", nt_pair(&fx, 1).src));
    assert_eq!(store.list().unwrap(), vec![win(&pair)]);
}

fn win(pair: &BootMovePair) -> PendingPair {
    PendingPair {
        src: pair.src.clone(),
        dst: pair.dst.clone(),
    }
}

#[test]
fn a_pair_already_listed_is_adopted_and_never_doubled() {
    let fx = Fx::new("adopt", 2);
    let ours = nt_pair(&fx, 1);
    let mut store = store_of(&[(format!("*2{}", ours.src), ours.dst.clone())]);
    let (env, rm) = (Env::admin_only(), FakeRm::default());
    let l = ladder(&fx, &env, &rm, &DenyAll);
    let result = fx.run(&l, 1, &mut store);
    let (pair, confirmed) = pending(&result);
    assert!(confirmed);
    assert_eq!(pair.src, format!("*2{}", ours.src));
    assert_eq!(store.registers, 0);

    // Listed twice already: nothing is added, the item fails.
    let two = nt_pair(&fx, 2);
    let mut store = store_of(&[
        (two.src.clone(), two.dst.clone()),
        (two.src.clone(), two.dst.clone()),
    ]);
    let result = fx.run(&l, 2, &mut store);
    assert_eq!(result.code, Some(reason::PAIR_COUNT));
    assert!(matches!(
        result.outcome,
        ItemOutcome::Failed {
            code: FailCode::Internal,
            ..
        }
    ));
    assert_eq!(store.registers, 0);
}

/// Fails `register` with access denied (unelevated), lists normally.
struct DenyRegister(MemoryPendingRenames);

impl PendingRenames for DenyRegister {
    fn list(&self) -> Result<Vec<PendingPair>, FsError> {
        self.0.list()
    }
    fn register(&mut self, _: &Path, _: &Path) -> Result<fs_write::BootMove, FsError> {
        Err(FsError::AccessDenied)
    }
    fn remove_exact(&mut self, pair: &PendingPair) -> Result<usize, FsError> {
        self.0.remove_exact(pair)
    }
}

#[test]
fn a_registration_or_list_failure_fails_the_item_and_writes_nothing() {
    let fx = Fx::new("regfail", 2);
    let (env, rm) = (Env::admin_only(), FakeRm::default());
    let l = ladder(&fx, &env, &rm, &DenyAll);
    let mut store = DenyRegister(MemoryPendingRenames::default());
    let result = fx.run(&l, 1, &mut store);
    assert!(matches!(
        result.outcome,
        ItemOutcome::Failed {
            code: FailCode::AccessDenied,
            os_error: Some(5),
            ..
        }
    ));
    assert!(store.0.bytes().is_empty());

    let mut store = MemoryPendingRenames {
        fail: Some(FsError::Other(1450)),
        ..MemoryPendingRenames::default()
    };
    let result = fx.run(&l, 2, &mut store);
    assert_eq!(result.code, Some(reason::LIST_FAILED));
    assert_eq!(store.registers, 0);
}

#[test]
fn an_intent_journalled_by_the_file_action_must_be_the_same() {
    let fx = Fx::new("journalled", 1);
    let (env, rm) = (Env::admin_only(), FakeRm::default());
    let l = ladder(&fx, &env, &rm, &DenyAll);
    let locked = fx.locked(1);
    let same = locked.intent().unwrap();
    match l.prepare(&locked, Some(&same)) {
        LockPrepared::Ready(action) => {
            assert!(action.intent_to_write().is_none());
            assert_eq!(action.intent(), &same);
            assert_eq!(action.plan(), LockPlan::BootMove);
        }
        LockPrepared::Decided(r) => panic!("{r:?}"),
    }
    let mut other = same.clone();
    if let Inverse::MoveBack {
        quarantine_path, ..
    } = &mut other.inverse
    {
        quarantine_path.push_str(".other");
    }
    match l.prepare(&locked, Some(&other)) {
        LockPrepared::Decided(r) => assert_eq!(r.code, Some(reason::INTENT_DIFFERS)),
        LockPrepared::Ready(_) => panic!("a differing intent must not be acted on"),
    }
}

#[test]
fn the_token_of_another_op_registers_nothing() {
    let fx = Fx::new("token", 2);
    let (env, rm) = (Env::admin_only(), FakeRm::default());
    let l = ladder(&fx, &env, &rm, &DenyAll);
    let LockPrepared::Ready(action) = l.prepare(&fx.locked(1), None) else {
        panic!("ready expected");
    };
    let other = fx.locked(2).intent().unwrap();
    let token = fx.journal.borrow_mut().intent(other).unwrap();
    let mut store = MemoryPendingRenames::default();
    let result = l.act(action, &token, &mut store);
    assert_eq!(result.code, Some(reason::FOREIGN_TOKEN));
    assert_eq!(store.registers, 0);
    fx.journal.borrow_mut().done(token, result.outcome).unwrap();
}

#[test]
fn a_held_plan_rechecked_at_act_time_still_writes_nothing() {
    // Prepared as a boot move, but the ancestors turn user-writable before the act.
    let fx = Fx::new("recheck", 1);
    let rm = FakeRm::default();
    let allowed = Env::admin_only();
    let LockPrepared::Ready(action) =
        ladder(&fx, &allowed, &rm, &DenyAll).prepare(&fx.locked(1), None)
    else {
        panic!("ready expected");
    };
    assert_eq!(action.plan(), LockPlan::BootMove);
    let token = fx
        .journal
        .borrow_mut()
        .intent(action.intent().clone())
        .unwrap();
    let now_held = Env::holding("live.boot.user-writable");
    let mut store = MemoryPendingRenames::default();
    let result = ladder(&fx, &now_held, &rm, &DenyAll).act(action, &token, &mut store);
    assert_eq!(result.outcome, ItemOutcome::HeldRetry);
    assert_eq!(store.registers, 0);
    fx.journal.borrow_mut().done(token, result.outcome).unwrap();
}

// ---------------------------------------------------------------------------------------------------
// Undo
// ---------------------------------------------------------------------------------------------------

/// Undoes op `n` as the executor does; returns the outcome.
fn undo(fx: &Fx, n: u32, store: &mut MemoryPendingRenames) -> Option<LockUndo> {
    let plan = undo_locked(&fx.op(n), store);
    if let Some(LockUndo::RemovePair(removal)) = &plan {
        let token = fx.journal.borrow_mut().undo_intent(OpId(n)).unwrap();
        let outcome = remove_boot_move(removal.clone(), &token, store);
        fx.journal
            .borrow_mut()
            .undo_done(token, outcome.clone())
            .unwrap();
        return Some(LockUndo::Done(outcome));
    }
    plan
}

#[test]
fn undo_removes_exactly_our_pairs_and_foreign_pairs_stay_byte_identical() {
    let fx = Fx::new("undo", 2);
    let foreign = foreign(&fx);
    // Foreign pairs before, between and after ours.
    let mut store = store_of(&foreign[..2]);
    let (env, rm) = (Env::admin_only(), FakeRm::default());
    let l = ladder(&fx, &env, &rm, &DenyAll);
    pending(&fx.run(&l, 1, &mut store));
    for (src, dst) in &foreign[2..4] {
        let mut pairs = fs_write::parse_pending_renames(store.bytes());
        pairs.push(PendingPair {
            src: src.clone(),
            dst: dst.clone(),
        });
        store = store_of(
            &pairs
                .into_iter()
                .map(|p| (p.src, p.dst))
                .collect::<Vec<_>>(),
        );
    }
    pending(&fx.run(&l, 2, &mut store));
    let mut pairs = fs_write::parse_pending_renames(store.bytes());
    pairs.push(PendingPair {
        src: foreign[4].0.clone(),
        dst: foreign[4].1.clone(),
    });
    let mut store = store_of(
        &pairs
            .iter()
            .map(|p| (p.src.clone(), p.dst.clone()))
            .collect::<Vec<_>>(),
    );
    let (one, two) = (nt_pair(&fx, 1), nt_pair(&fx, 2));
    let order: Vec<PendingPair> = store.list().unwrap();
    assert_eq!(order.len(), 7);
    assert_eq!(order[2], one);
    assert_eq!(order[5], two);

    assert_eq!(
        undo(&fx, 1, &mut store),
        Some(LockUndo::Done(UndoOutcome::Restored))
    );
    let mut without_one = order.clone();
    without_one.remove(2);
    assert_eq!(
        store.bytes(),
        store_of(
            &without_one
                .iter()
                .map(|p| (p.src.clone(), p.dst.clone()))
                .collect::<Vec<_>>()
        )
        .bytes()
    );
    assert_eq!(
        undo(&fx, 2, &mut store),
        Some(LockUndo::Done(UndoOutcome::Restored))
    );
    assert_eq!(store.bytes(), store_of(&foreign).bytes());
    assert_eq!(store.removals, 2);
    // The undo settled: nothing is pending any more.
    assert_eq!(fx.state().pending_reboot().count(), 0);
}

#[test]
fn undo_refuses_a_pair_listed_twice_and_removes_nothing() {
    let fx = Fx::new("undotwice", 1);
    let (env, rm) = (Env::admin_only(), FakeRm::default());
    let mut store = MemoryPendingRenames::default();
    let (pair, _) = pending(&fx.run(&ladder(&fx, &env, &rm, &DenyAll), 1, &mut store));
    let mut store = store_of(&[
        (pair.src.clone(), pair.dst.clone()),
        (r"\??\C:\Other\a".into(), r"\??\C:\Other\b".into()),
        (pair.src.clone(), pair.dst.clone()),
    ]);
    let before = store.bytes().to_vec();
    let Some(LockUndo::Done(UndoOutcome::Failed { code, .. })) = undo(&fx, 1, &mut store) else {
        panic!("a doubled pair must not be removed");
    };
    assert_eq!(code, FailCode::Internal);
    assert_eq!(store.bytes(), before.as_slice());
    assert_eq!(store.removals, 0);
}

#[test]
fn undo_of_held_items_rebooted_moves_and_other_ops() {
    let fx = Fx::new("undoother", 2);
    let rm = FakeRm::default();
    let mut store = MemoryPendingRenames::default();
    let held = Env::holding("live.boot.user-writable");
    fx.run(&ladder(&fx, &held, &rm, &DenyAll), 1, &mut store);
    assert_eq!(
        undo_locked(&fx.op(1), &store),
        Some(LockUndo::Done(UndoOutcome::NothingToUndo))
    );

    let env = Env::admin_only();
    let (pair, _) = pending(&fx.run(&ladder(&fx, &env, &rm, &DenyAll), 2, &mut store));
    // The restart took the pair away: reconcile decides first.
    store.remove_exact(&win(&pair)).unwrap();
    assert!(matches!(
        undo_locked(&fx.op(2), &store),
        Some(LockUndo::ReconcileFirst { .. })
    ));
    let broken = MemoryPendingRenames {
        fail: Some(FsError::Other(1450)),
        ..MemoryPendingRenames::default()
    };
    assert!(matches!(
        undo_locked(&fx.op(2), &broken),
        Some(LockUndo::ReconcileFirst { .. })
    ));
    // A token of another op removes nothing.
    let mut store = store_of(&[(pair.src.clone(), pair.dst.clone())]);
    let token = fx.journal.borrow_mut().undo_intent(OpId(1)).unwrap();
    let removal = PairRemoval {
        op: OpId(2),
        pair: pair.clone(),
    };
    assert!(matches!(
        remove_boot_move(removal, &token, &mut store),
        UndoOutcome::Failed {
            code: FailCode::Internal,
            ..
        }
    ));
    assert_eq!(store.removals, 0);
    fx.journal
        .borrow_mut()
        .undo_done(token, UndoOutcome::NothingToUndo)
        .unwrap();
}

// ---------------------------------------------------------------------------------------------------
// Reconcile, retry, recovery
// ---------------------------------------------------------------------------------------------------

/// A gate context with no journalled records.
fn gate_ctx(fx: &Fx) -> GateCtx {
    GateCtx::new(DenyList::compile(&live_env()), &[], fx.scope.clone()).unwrap()
}

/// The gate context of a resumed run (reconcile at the next start): every `validated` record read back
/// from the journal and handed to the gate.
fn resumed_ctx(fx: &Fx) -> GateCtx {
    let read = crate::journal::read(&fx.session).unwrap();
    let ops: Vec<ExecOp> = fx.items.iter().map(|it| mv(&it.source)).collect();
    let mut ctx = GateCtx::new(DenyList::compile(&live_env()), &ops, fx.scope.clone()).unwrap();
    for record in &read.records {
        if let Record::Validated(v) = record {
            ctx.record(&ops[v.op.0 as usize - 1], v, 5_000).unwrap();
        }
    }
    ctx
}

fn identity_at(path: &str) -> FileIdentity {
    match LiveLadder.look(path) {
        SourceState::Present { identity, .. } => identity,
        other => panic!("{path}: {other:?}"),
    }
}

#[test]
fn reconcile_state_table() {
    let fx = Fx::new("reconcile", 6);
    let (env, rm) = (Env::admin_only(), FakeRm::default());
    let mut store = MemoryPendingRenames::default();
    let mut pairs = Vec::new();
    for n in 1..=6 {
        let (pair, _) = pending(&fx.run(&ladder(&fx, &env, &rm, &DenyAll), n, &mut store));
        pairs.push(pair);
    }
    // Op 1: still pending. Ops 2-6: the restart consumed the pair.
    for pair in &pairs[1..] {
        assert_eq!(store.remove_exact(&win(pair)).unwrap(), 1);
    }
    let path = |n: u32| (fx.it(n).source.clone(), fx.it(n).quarantine.clone());
    // Op 2: the boot rename happened (a rename keeps the file id).
    let (src, q) = path(2);
    std::fs::rename(&src, &q).unwrap();
    // Op 3: something else reached quarantine; the source path is free.
    let (src, q) = path(3);
    std::fs::remove_file(&src).unwrap();
    std::fs::write(&q, b"planted by someone else").unwrap();
    let planted = identity_at(&q);
    // Op 4: something else reached quarantine, but the source path is taken.
    let (_, q) = path(4);
    std::fs::write(&q, b"planted too").unwrap();
    // Op 5: nothing moved; the item is still in place. Op 6: gone everywhere.
    std::fs::remove_file(&fx.it(6).source).unwrap();

    let ctx = resumed_ctx(&fx);
    let results = reconcile(&fx.state(), &fx.session, &ctx, &LiveLadder, &store);
    let verdicts: Vec<_> = results.iter().map(|r| (r.op.0, r.verdict)).collect();
    assert_eq!(
        verdicts,
        vec![
            (1, ReconcileVerdict::StillPending),
            (2, ReconcileVerdict::Completed),
            (3, ReconcileVerdict::MismatchMovedBack),
            (4, ReconcileVerdict::MismatchKept),
            (5, ReconcileVerdict::NotMoved),
            (6, ReconcileVerdict::Lost),
        ],
        "{results:#?}"
    );
    // The mismatch went back to the source path, by handle, and quarantine is empty.
    let (src, q) = path(3);
    assert_eq!(identity_at(&src), planted);
    assert!(!Path::new(&q).exists());
    let alert = results[2].alert.as_ref().unwrap();
    assert!(alert.moved_back);
    assert_eq!(alert.found, planted);
    assert_eq!(alert.expected, stamp_of(&fx.it(3).facts).identity);
    // The kept mismatch stays, nothing was overwritten.
    let alert = results[3].alert.as_ref().unwrap();
    assert!(!alert.moved_back);
    assert!(Path::new(&fx.it(4).quarantine).exists());
    assert_eq!(
        identity_at(&fx.it(4).source),
        stamp_of(&fx.it(4).facts).identity
    );
    for r in &results[..3] {
        assert!(r.alert.is_none() || r.verdict == ReconcileVerdict::MismatchMovedBack);
    }

    // Journal what the model can hold; the rest stays pending.
    for r in &results {
        if let Some(record) = r.record(FileTime(134_078_200_000_000_000)) {
            fx.journal.borrow_mut().reconcile(record).unwrap();
        }
    }
    let still: Vec<u32> = fx.state().pending_reboot().map(|s| s.op.0).collect();
    assert_eq!(still, vec![1, 4, 5, 6]);
    assert_eq!(
        undo_locked(&fx.op(2), &store),
        None,
        "a completed move is undone by the ordinary move back"
    );
    assert_eq!(
        undo_locked(&fx.op(3), &store),
        Some(LockUndo::Done(UndoOutcome::NothingToUndo))
    );

    // An unreadable list decides nothing.
    let broken = MemoryPendingRenames {
        fail: Some(FsError::Other(1450)),
        ..MemoryPendingRenames::default()
    };
    let results = reconcile(&fx.state(), &fx.session, &ctx, &LiveLadder, &broken);
    assert!(
        results.iter().all(
            |r| r.verdict == ReconcileVerdict::Indeterminate && r.record(FileTime(1)).is_none()
        )
    );
}

/// Changed in meaning: `exemptions_of` is gone. The exemptions reconcile checks with are those of the
/// journalled `validated` records handed to the gate context (here read back from the journal, as a
/// resumed run does); without a record the item gets none (the strictest check). The hand-over to the
/// ladder takes the op, plan item and facts from the same records and refuses an op without one.
#[test]
fn exemptions_and_facts_come_from_the_journalled_records() {
    let fx = Fx::new("exemptions", 2);
    let ctx = resumed_ctx(&fx);
    for n in [1, 2] {
        let ex = ctx.exemptions(OpId(n)).unwrap();
        assert!(ex.long_names_resolved);
        assert_eq!(ex, gate::exemptions_from_journal(&long_names()));
    }
    assert_eq!(gate_ctx(&fx).exemptions(OpId(1)), None);

    let seen = stamp_of(&fx.it(1).facts);
    let locked = LockedItem::from_gate(
        &ctx,
        OpId(1),
        &locked_path(seen, Win32Error(32)),
        fx.it(1).quarantine.clone(),
    )
    .unwrap();
    assert_eq!(locked, fx.locked(1));
    assert_eq!(locked.item(), &item(1));
    assert_eq!(locked.exec_op(), &mv(&fx.it(1).source));
    assert_eq!(locked.validated(), &fx.it(1).facts);
    assert_eq!(locked.quarantine_path(), fx.it(1).quarantine);
    assert!(
        LockedItem::from_gate(
            &gate_ctx(&fx),
            OpId(1),
            &locked_path(seen, Win32Error(32)),
            fx.it(1).quarantine.clone(),
        )
        .is_none(),
        "no journalled record, no hand-over"
    );
}

/// Records what it was given and answers from a script.
struct Mover {
    seen: Vec<(OpId, String)>,
    answers: Vec<RetryAttempt>,
}

impl RetryMove for Mover {
    fn retry(&mut self, op: &OpState, intent: &Intent) -> RetryAttempt {
        let Inverse::MoveBack {
            quarantine_path, ..
        } = &intent.inverse
        else {
            panic!("not a move");
        };
        self.seen.push((op.op, quarantine_path.clone()));
        self.answers.remove(0)
    }
}

#[test]
fn retry_held_passes_the_journalled_destination_and_maps_outcomes() {
    let fx = Fx::new("retry", 3);
    let rm = FakeRm::default();
    let held = Env::holding("live.boot.user-writable");
    let mut store = MemoryPendingRenames::default();
    for n in 1..=3 {
        fx.run(&ladder(&fx, &held, &rm, &DenyAll), n, &mut store);
    }
    let mut mover = Mover {
        seen: Vec::new(),
        answers: vec![
            RetryAttempt::Moved,
            RetryAttempt::StillLocked,
            RetryAttempt::Failed {
                code: FailCode::AccessDenied,
                os_error: Some(5),
            },
        ],
    };
    let retried = retry_held(&fx.state(), &mut mover);
    assert_eq!(
        mover.seen,
        (1..=3)
            .map(|n| (OpId(n), fx.it(n).quarantine.clone()))
            .collect::<Vec<_>>()
    );
    assert_eq!(retried[0].outcome, ItemOutcome::Done);
    assert_eq!(retried[1].outcome, ItemOutcome::HeldRetry);
    assert!(matches!(
        retried[2].outcome,
        ItemOutcome::Failed {
            code: FailCode::AccessDenied,
            ..
        }
    ));
    for r in &retried {
        fx.journal
            .borrow_mut()
            .reconcile(r.record(FileTime(2)))
            .unwrap();
    }
    let held_now: Vec<u32> = fx.state().held_retry().map(|s| s.op.0).collect();
    assert_eq!(held_now, vec![2]);
    assert_eq!(undo_locked(&fx.op(1), &store), None, "moved: ordinary undo");
    assert_eq!(
        undo_locked(&fx.op(2), &store),
        Some(LockUndo::Done(UndoOutcome::NothingToUndo))
    );
    assert_eq!(store.registers, 0, "a retry never registers a boot move");
}

#[test]
fn recovery_finds_a_pair_registered_before_the_crash() {
    let fx = Fx::new("crash", 1);
    let intent = fx.locked(1).intent().unwrap();
    let ours = nt_pair(&fx, 1);
    let store = store_of(&[
        (r"\??\C:\Other\a".into(), r"\??\C:\Other\b".into()),
        (format!("*1{}", ours.src), ours.dst.clone()),
    ]);
    assert_eq!(
        pending_after_crash(&intent, &store),
        Some(ItemOutcome::PendingReboot {
            pair: BootMovePair {
                src: format!("*1{}", ours.src),
                dst: ours.dst.clone(),
            },
            confirmed: true,
        })
    );
    assert_eq!(
        pending_after_crash(&intent, &MemoryPendingRenames::default()),
        None
    );
}

#[test]
fn marker_stripping_matches_only_the_marker() {
    assert_eq!(strip_marker(r"*1\??\C:\a"), r"\??\C:\a");
    assert_eq!(strip_marker(r"*12\??\C:\a"), r"\??\C:\a");
    assert_eq!(strip_marker(r"\??\C:\a"), r"\??\C:\a");
    let ours = BootMovePair {
        src: r"\??\C:\a".into(),
        dst: r"\??\C:\q\a".into(),
    };
    let listed = |src: &str, dst: &str| PendingPair {
        src: src.into(),
        dst: dst.into(),
    };
    assert!(is_ours(&listed(r"*1\??\C:\a", r"\??\C:\q\a"), &ours));
    assert!(!is_ours(&listed(r"\??\C:\A", r"\??\C:\q\a"), &ours));
    assert!(!is_ours(&listed(r"\??\C:\a", r"!\??\C:\q\a"), &ours));
    assert!(!is_ours(&listed(r"\??\C:\a", ""), &ours));
}

/// The real list: register and remove our own pair, foreign pairs untouched. Needs administrative
/// rights (writes `HKLM`); VM only.
#[test]
#[ignore = "writes HKLM PendingFileRenameOperations; run elevated in the VM gate"]
fn system_list_registers_and_removes_only_our_pair_vm() {
    let fx = Fx::new("system", 1);
    let mut store = SystemPendingRenames;
    let before = store.list().unwrap();
    let it = fx.it(1);
    let registered = store
        .register(Path::new(&it.source), Path::new(&it.quarantine))
        .unwrap();
    let pair = model_pair(&registered.pair);
    assert_eq!(occurrences(&store.list().unwrap(), &pair).len(), 1);
    assert_eq!(store.remove_exact(&registered.pair).unwrap(), 1);
    assert_eq!(store.list().unwrap(), before);
}
