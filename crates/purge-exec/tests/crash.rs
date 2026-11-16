//! The crash matrix: for every declared fault point, a child process of this test binary runs the
//! pipeline with `PURGE_FAULT_AT` set and dies there; the parent then recovers the session, once by
//! resume and once by rollback, and compares the machine with an uninterrupted run (resume) or with
//! what it was before the run (rollback). Recovery is run twice each time: the second call must
//! change nothing.
//!
//! Unelevated, on a temp directory and a test-created `HKU\<SID>\Software\PurgeTest-<random>` subtree.
//! The package backend is a marker file, the boot-time move list an in-memory value; the child gets a
//! temp directory of its own inside the scratch directory.

#![cfg(all(feature = "fault-inject", feature = "test-support"))]

mod common;

use std::mem::ManuallyDrop;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use common::*;
use purge_exec::fault;
use purge_exec::journal::{JournalWriter, Phase, UndoState};
use purge_exec::locked::MemoryPendingRenames;
use purge_exec::plan_in::ExecRequest;
use purge_exec::recover::{self, PendingKind, Probe, RecoverMode, RecoverOutput};
use purge_exec::storage::{REPORT_FILE, StorageRoots};
use purge_exec::undo::{UndoError, UndoRequest, UndoSelection, undo};
use purge_model::exec::journal::{AbortReason, ReconcileResult, Record, UndoConflict, UndoOutcome};
use purge_model::exec::op::{BootMovePair, Inverse, ItemOutcome, OpId, SkipReason};
use purge_model::exec::session::{SessionId, SessionState, UndoResult};
use purge_model::{Action, FileTime};
use purge_win::reg::{REG_MULTI_SZ, REG_SZ};

/// Set only in a child process: the scratch directory the child works in.
const CHILD_ROOT: &str = "PURGE_XUNDO_CHILD_ROOT";
/// Set only in a child process: the name of the parent's test key.
const CHILD_KEY: &str = "PURGE_XUNDO_CHILD_KEY";
/// Set only in a child process: what to do (`execute`, `undo`, `bootmove`, `resume` or `rollback`).
const CHILD_MODE: &str = "PURGE_XUNDO_CHILD_MODE";

/// The exit code of a process ended by `std::process::abort` on Windows (`__fastfail`).
const ABORT_CODE: i32 = 0xC000_0409_u32 as i32;

/// The package removal is op 7 of the plan, the last one.
const PACKAGE_OP: OpId = OpId(7);

// ---------------------------------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------------------------------

/// What the crash plan acts on: two files in a directory, a key tree, a value, a list segment, and an
/// installed package.
fn setup(rig: &Rig, k: &TestKey) {
    rig.s.file(r"app\f1.txt", b"one");
    rig.s.file(r"app\f2.txt", b"two");
    k.create(r"Tree\Sub\Leaf");
    k.create(r"Tree\Other");
    k.set("Tree", "Name", REG_SZ, &utf16z("vendor"));
    k.set(r"Tree\Sub", "N", REG_SZ, &utf16z("1"));
    k.set(r"Tree\Sub\Leaf", "L", REG_SZ, &utf16z("leaf"));
    k.set(r"Tree\Other", "O", REG_SZ, &utf16z("other"));
    k.create("Vals");
    k.set("Vals", "Gone", REG_SZ, &utf16z("bye"));
    k.set("Vals", "Stays", REG_SZ, &utf16z("hi"));
    k.create("Seg");
    k.set(
        "Seg",
        "List",
        REG_MULTI_SZ,
        &multi_sz(&["keep", "vendor", "also"]),
    );
    rig.packages.install();
}

/// The crash plan: one item of every kind, the irreversible one last. Built from the scratch
/// directory and the key alone, so the parent and its child build the same plan.
fn crash_plan(s: &Scratch, k: &TestKey) -> ExecRequest {
    let mut request = request(
        vec![
            quarantine("c-f1", &s.path(r"app\f1.txt")),
            quarantine("c-f2", &s.path(r"app\f2.txt")),
            safe("c-key", key(&k.wire("Tree")), Action::DeleteKey),
            safe("c-val", value(&k.wire("Vals"), "Gone"), Action::DeleteValue),
            safe(
                "c-seg",
                segment(&k.wire("Seg"), "List", "vendor"),
                Action::EditSegment,
            ),
            safe("c-app", path(&s.path("app")), Action::RemoveDirIfEmpty),
            package("c-pkg"),
        ],
        Vec::new(),
    );
    request.allow_irreversible = true;
    request
}

/// Everything the plan can change.
#[derive(Debug, Clone, PartialEq, Eq)]
struct World {
    files: Vec<FileSnap>,
    keys: Vec<KeySnap>,
    package: bool,
}

fn world(rig: &Rig, k: &TestKey) -> World {
    World {
        files: without_dir_ids(snap_tree(&rig.s.path("app"))),
        keys: k.snap(),
        package: rig.packages.installed(),
    }
}

/// The machine and the journal's outcomes after an uninterrupted run of the crash plan.
fn reference() -> &'static (World, Vec<Option<ItemOutcome>>) {
    static REFERENCE: OnceLock<(World, Vec<Option<ItemOutcome>>)> = OnceLock::new();
    REFERENCE.get_or_init(|| {
        let mut rig = Rig::new("reference");
        let k = TestKey::new();
        setup(&rig, &k);
        let done = rig.run(crash_plan(&rig.s, &k));
        let outcomes = outcomes(&rig.journal(&done.session));
        assert_eq!(
            outcomes,
            vec![Some(ItemOutcome::Done); 7],
            "{:#?}",
            done.report
        );
        (world(&rig, &k), outcomes)
    })
}

// ---------------------------------------------------------------------------------------------------
// The child
// ---------------------------------------------------------------------------------------------------

/// The child half: does what [`CHILD_MODE`] says in the scratch directory and below the key the
/// parent made, and dies at the fault point the parent set. Does nothing when run as an ordinary
/// test.
#[test]
fn child_scenario() {
    let (Some(root), Ok(key), Ok(mode)) = (
        std::env::var_os(CHILD_ROOT),
        std::env::var(CHILD_KEY),
        std::env::var(CHILD_MODE),
    ) else {
        return;
    };
    let s = Scratch::at(Path::new(&root));
    let roots = StorageRoots::relaxed(Path::new(&s.path("data"))).unwrap();
    // The parent owns the scratch directory and the key.
    let mut rig = ManuallyDrop::new(Rig::with(s, roots));
    let k = TestKey::at(&key);
    match mode.as_str() {
        "execute" => {
            let request = crash_plan(&rig.s, &k);
            rig.run(request);
        }
        "undo" => {
            let [id]: [SessionId; 1] = rig.sessions().try_into().unwrap();
            rig.undo_all(&id);
        }
        "resume" => {
            let [id]: [SessionId; 1] = rig.sessions().try_into().unwrap();
            rig.resume(&id);
        }
        "rollback" => {
            let [id]: [SessionId; 1] = rig.sessions().try_into().unwrap();
            rig.rollback(&id);
        }
        "bootmove" => {
            // The ladder registered the boot-time move of op 1 and is about to journal it.
            let [id]: [SessionId; 1] = rig.sessions().try_into().unwrap();
            let session = rig.session(&id);
            let mut journal = JournalWriter::open_append(&session).unwrap();
            let pair = boot_pair(&rig, &id);
            let token = journal.resume_intent(OpId(1)).unwrap();
            journal
                .done(
                    token,
                    ItemOutcome::PendingReboot {
                        pair,
                        confirmed: true,
                    },
                )
                .unwrap();
        }
        other => panic!("unknown child mode {other}"),
    }
}

/// Runs the child in `mode` with the fault `at` and returns its exit code.
fn spawn(rig: &Rig, k: &TestKey, mode: &str, at: &str) -> Option<i32> {
    let temp = rig.s.dir("child-temp");
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_scenario", "--test-threads=1"])
        .env(CHILD_ROOT, &rig.s.root)
        .env(CHILD_KEY, &k.name)
        .env(CHILD_MODE, mode)
        .env(fault::ENV_AT, at)
        .env_remove(fault::ENV_PAUSE)
        .env("TEMP", &temp)
        .env("TMP", &temp)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .code()
}

/// The pair a boot-time move of op 1 registers, from the op's journalled intent.
fn boot_pair(rig: &Rig, id: &SessionId) -> BootMovePair {
    let read = rig.journal(id);
    let intent = read.state.op(OpId(1)).unwrap().intent.clone().unwrap();
    let Inverse::MoveBack {
        quarantine_path,
        original_path,
        ..
    } = &intent.inverse
    else {
        panic!("{intent:?}");
    };
    let pair =
        purge_win::fs_write::pending_pair(Path::new(original_path), Path::new(quarantine_path))
            .unwrap();
    BootMovePair {
        src: pair.src,
        dst: pair.dst,
    }
}

// ---------------------------------------------------------------------------------------------------
// The scenarios
// ---------------------------------------------------------------------------------------------------

/// How a fault point is reached.
#[derive(Debug, Clone, Copy)]
enum Drive {
    /// The child executes the crash plan and dies on the given hits of the point.
    Execute(&'static [u32]),
    /// The parent executes the plan; the child undoes the session and dies on the given hits.
    Undo(&'static [u32]),
    /// The child executes up to the intent of op 1, and a second child dies journalling its
    /// boot-time move, which the in-memory list then holds.
    BootMove,
    /// Not a state recovery sees; the reason.
    NotDriven(&'static str),
}

/// Every declared point and how the matrix reaches it. The hit counts pick the op the crash lands on:
/// ops 1 and 2 are files, 3 a key tree, 4 a value, 5 a segment, 6 a directory, 7 the package.
fn drive(point: &str) -> Drive {
    match point {
        fault::JOURNAL_HEADER => Drive::Execute(&[1]),
        // Registry backups of ops 3, 4, 5, then the package's definition.
        fault::BACKUP_WRITTEN => Drive::Execute(&[1, 2, 4]),
        fault::BACKUP_VERIFIED => Drive::Execute(&[1, 3, 4]),
        fault::INTENT_FLUSHED => Drive::Execute(&[1, 3, 4, 5, 6, 7]),
        fault::ACT_BEFORE => Drive::Execute(&[2, 3, 4, 5, 6, 7]),
        // Every op. The package removal has no `act.after`.
        fault::ACT_AFTER => Drive::Execute(&[1, 2, 3, 4, 5, 6]),
        fault::DONE_BEFORE => Drive::Execute(&[1, 2, 3, 4, 5, 6, 7]),
        fault::GROUP_END => Drive::Execute(&[1]),
        fault::COMMIT_BEFORE => Drive::Execute(&[1]),
        fault::REGDELETE_MID => Drive::Execute(&[1, 2]),
        fault::INDEX_WRITE => Drive::Execute(&[1]),
        // The undo runs in the exact reverse of the run: the package (decided without an
        // `undo_intent`), then the directory, the segment, the value, the key and the files.
        fault::UNDO_INTENT => Drive::Undo(&[1, 2, 4, 6]),
        fault::UNDO_ACT_AFTER => Drive::Undo(&[1, 3, 4, 5]),
        fault::REGRESTORE_MID => Drive::Undo(&[1]),
        fault::BOOTMOVE_REGISTERED => Drive::BootMove,
        fault::EXPIRY_MID => Drive::NotDriven(
            "expiry is not a run: a crash in its delete walk leaves a finished session, which the \
             next expiry finishes (expiry's own crash test); recovery has no step for it",
        ),
        other => panic!("fault point {other} has no scenario in the crash matrix"),
    }
}

fn recover_with(rig: &mut Rig, id: &SessionId, mode: RecoverMode) -> RecoverOutput {
    match mode {
        RecoverMode::Resume => rig.resume(id),
        RecoverMode::Rollback => rig.rollback(id),
    }
}

/// Runs recovery a second time and checks that neither the store nor the machine changed.
fn assert_idempotent(rig: &mut Rig, k: &TestKey, id: &SessionId, mode: RecoverMode, what: &str) {
    let store = rig.store_files();
    let machine = world(rig, k);
    let pending = rig.pending.clone();
    let again = recover_with(rig, id, mode);
    assert!(
        again.settled.is_empty() && again.undone.is_empty(),
        "{what}: {again:#?}"
    );
    assert!(
        again.retries.is_empty() && again.report.is_none(),
        "{what}: {again:#?}"
    );
    assert_eq!(
        rig.store_files(),
        store,
        "{what}: the second recovery wrote to the store"
    );
    assert_eq!(
        world(rig, k),
        machine,
        "{what}: the second recovery changed the machine"
    );
    assert_eq!(rig.pending.bytes(), pending.bytes(), "{what}");
    assert!(
        recover::pending(&rig.roots).unwrap().sessions.is_empty(),
        "{what}"
    );
}

/// `before` with the package gone when the run removed it (which nothing brings back).
fn before_without_package(before: &World, removed: bool) -> World {
    World {
        package: before.package && !removed,
        ..before.clone()
    }
}

/// A crash while executing, then recovery in `mode`.
fn execute_scenario(point: &str, hit: u32, mode: RecoverMode) {
    let what = format!("{point}:{hit} {mode:?}");
    let mut rig = Rig::new("crash");
    let k = TestKey::new();
    setup(&rig, &k);
    let before = world(&rig, &k);
    let code = spawn(&rig, &k, "execute", &format!("{point}:{hit}"));
    assert_eq!(
        code,
        Some(ABORT_CODE),
        "{what}: the child did not die at the point"
    );

    let [id]: [SessionId; 1] = rig.sessions().try_into().unwrap();
    let crashed = rig.journal(&id);
    let listed = recover::pending(&rig.roots).unwrap();
    assert_eq!(listed.sessions.len(), 1, "{what}: {listed:#?}");
    let finished = crashed.state.is_finished();
    assert_eq!(
        listed.sessions[0].kind,
        if finished {
            PendingKind::Unindexed
        } else {
            PendingKind::Run
        },
        "{what}"
    );
    if !finished {
        // Undo waits for recovery.
        let request = UndoRequest {
            session: id.clone(),
            selection: UndoSelection::All,
            plan_hash: None,
        };
        assert!(
            matches!(
                undo(&request, rig.undo_env()),
                Err(UndoError::NeedsRecovery(_))
            ),
            "{what}"
        );
    }
    let validated = crashed.state.validated_count() == crashed.state.header().items;
    let had_intents = crashed.state.ops().any(|op| op.intent.is_some());

    let out = recover_with(&mut rig, &id, mode);
    assert!(out.index_updated, "{what}: {out:#?}");
    // What recovery found at the one op the crash left open, by where the crash was.
    let open: Vec<_> = crashed.state.open_intents().map(|op| op.op).collect();
    let settled: Vec<_> = out.settled.iter().map(|s| s.op).collect();
    assert_eq!(settled, open, "{what}: {out:#?}");
    match point {
        fault::INTENT_FLUSHED | fault::ACT_BEFORE => {
            assert_eq!(out.settled.len(), 1, "{what}");
            assert_eq!(out.settled[0].probe, Probe::NotDone, "{what}");
        }
        fault::ACT_AFTER | fault::DONE_BEFORE => {
            assert_eq!(out.settled.len(), 1, "{what}");
            assert_eq!(
                out.settled[0].probe,
                Probe::Done(ItemOutcome::Done),
                "{what}"
            );
        }
        fault::REGDELETE_MID => {
            assert_eq!(out.settled.len(), 1, "{what}");
            assert!(
                matches!(out.settled[0].probe, Probe::Partial { missing_keys } if missing_keys > 0),
                "{what}: {out:#?}"
            );
        }
        _ => assert!(out.settled.is_empty(), "{what}: {out:#?}"),
    }
    let read = rig.journal(&id);
    let entry = rig.entry(&id).unwrap();
    assert_eq!(entry.journal, Some(read.state.mark()), "{what}");
    assert_eq!(read.state.open_intents().count(), 0, "{what}");
    let removed =
        read.state.op(PACKAGE_OP).and_then(|op| op.outcome.clone()) == Some(ItemOutcome::Done);
    // Every recovered session has its report (written by the run's end, or by recovery from the
    // journal when the crash came after the end).
    assert!(
        rig.session(&id).open_file(REPORT_FILE).is_ok(),
        "{what}: no report"
    );
    match mode {
        RecoverMode::Resume => {
            // As if the run had never been interrupted, also when it stopped before every item was
            // validated (changed in the M2 recovery fix pass: such a run was ended as cancelled).
            if !validated {
                let records = &read.records;
                let validated_records = records
                    .iter()
                    .filter(|r| matches!(r, Record::Validated(_)))
                    .count();
                assert_eq!(validated_records, 7, "{what}: an item was validated twice");
            }
            let (machine, outcomes_of_a_full_run) = reference();
            assert_eq!(outcomes(&read), *outcomes_of_a_full_run, "{what}: {out:#?}");
            assert_eq!(&world(&rig, &k), machine, "{what}");
            assert_eq!(read.state.phase(), Phase::Committed, "{what}");
            assert_eq!(entry.state, SessionState::Committed, "{what}");
            assert_eq!(out.state, Some(SessionState::Committed), "{what}");
            assert_eq!(entry.counts.done, 7, "{what}");
            for op in [1, 2] {
                assert!(exists(&quarantine_path(&read, op)), "{what}");
            }
            // The run's report: written by the resumed run's end, or, when the run itself had ended
            // and the crash came before its report (index.write), by recovery (changed in the M2
            // recovery fix pass: no report was written then).
            assert!(out.report.is_some(), "{what}");
            assert!(out.report_written, "{what}");
            assert_eq!(
                out.report.as_ref().map(|r| r.state),
                Some(SessionState::Committed),
                "{what}"
            );
        }
        RecoverMode::Rollback if finished => {
            // The run had ended; only its index entry was missing. There is nothing to roll back
            // (undoing a finished session is `undo`).
            assert_eq!(&world(&rig, &k), &reference().0, "{what}");
            assert_eq!(entry.state, SessionState::Committed, "{what}");
            assert!(out.undone.is_empty(), "{what}");
        }
        RecoverMode::Rollback => {
            assert_eq!(
                world(&rig, &k),
                before_without_package(&before, removed),
                "{what}: {out:#?}"
            );
            let expected = if removed {
                SessionState::PartiallyUndone
            } else if had_intents {
                SessionState::Undone
            } else {
                SessionState::Aborted
            };
            assert_eq!(entry.state, expected, "{what}: {out:#?}");
            assert_eq!(out.state, Some(expected), "{what}");
            assert_eq!(
                read.state.aborted().unwrap().reason,
                AbortReason::RolledBack,
                "{what}"
            );
            for op in read.state.ops().filter(|op| op.intent.is_some()) {
                let irreversible = op.op == PACKAGE_OP && removed;
                assert_eq!(
                    op.undo.is_settled(),
                    !irreversible,
                    "{what}: op {} is {:?}",
                    op.op,
                    op.undo
                );
            }
        }
    }
    assert_idempotent(&mut rig, &k, &id, mode, &what);

    // Whatever recovery left done can still be undone: the machine is as before the run, apart from
    // a removed package.
    let undone = rig.undo_all(&id);
    assert_eq!(undone.stopped, None, "{what}");
    assert_eq!(
        world(&rig, &k),
        before_without_package(&before, removed),
        "{what}: {undone:#?}"
    );
}

/// A crash while undoing a committed session, then recovery in `mode`: both modes finish the
/// interrupted undo, the op in progress and the ops its `undo_plan` names that it had not reached
/// (changed in the M2 recovery fix pass: before, only the op in progress was finished and the rest was
/// the user's to ask for again).
fn undo_scenario(point: &str, hit: u32, mode: RecoverMode) {
    let what = format!("{point}:{hit} {mode:?}");
    let mut rig = Rig::new("crash-undo");
    let k = TestKey::new();
    setup(&rig, &k);
    let before = world(&rig, &k);
    let done = rig.run(crash_plan(&rig.s, &k));
    let id = done.session.clone();
    let code = spawn(&rig, &k, "undo", &format!("{point}:{hit}"));
    assert_eq!(
        code,
        Some(ABORT_CODE),
        "{what}: the child did not die at the point"
    );

    let crashed = rig.journal(&id);
    let interrupted: Vec<OpId> = crashed.state.undo_in_progress().map(|op| op.op).collect();
    assert_eq!(interrupted.len(), 1, "{what}");
    // The undo run journalled its plan first: every op of the session, in the exact reverse of the run
    // (changed by M1 of the final M2 review: the directory came first).
    let plan = crashed.state.undo_plan().unwrap_or_default().to_vec();
    assert_eq!(plan, [7, 6, 5, 4, 3, 2, 1].map(OpId), "{what}: {plan:?}");
    // Not reached: every op of the plan after the one in progress (none when that was the last).
    let unreached = crashed.state.undo_unfinished();
    let at = plan.iter().position(|op| *op == interrupted[0]).unwrap();
    assert_eq!(unreached, plan[at + 1..], "{what}");
    // A new undo run would replace the interrupted run's plan: it waits for recovery while ops of
    // that plan are unreached (M10 of the final M2 review).
    if !unreached.is_empty() {
        let request = UndoRequest {
            session: id.clone(),
            selection: UndoSelection::All,
            plan_hash: None,
        };
        assert!(
            matches!(
                undo(&request, rig.undo_env()),
                Err(UndoError::NeedsRecovery(_))
            ),
            "{what}"
        );
        assert_eq!(
            rig.journal(&id).state.mark(),
            crashed.state.mark(),
            "{what}"
        );
    }
    let listed = recover::pending(&rig.roots).unwrap();
    assert_eq!(listed.sessions.len(), 1, "{what}");
    assert_eq!(listed.sessions[0].kind, PendingKind::Undo, "{what}");
    let mut remaining = interrupted.clone();
    remaining.extend(&unreached);
    assert_eq!(listed.sessions[0].undo_in_progress, remaining, "{what}");

    let out = recover_with(&mut rig, &id, mode);
    let read = rig.journal(&id);
    // The op in progress first, then every op the interrupted run had not reached, in plan order.
    let covered: Vec<OpId> = out.undone.iter().map(|item| item.op).collect();
    assert_eq!(covered, remaining, "{what}: {out:#?}");
    assert!(
        matches!(
            out.undone[0].result,
            UndoResult::Finished {
                outcome: UndoOutcome::Restored | UndoOutcome::AlreadyRestored
            }
        ),
        "{what}: {out:#?}"
    );
    assert_eq!(read.state.undo_in_progress().count(), 0, "{what}");
    assert!(read.state.undo_unfinished().is_empty(), "{what}");
    // After recovery the undo is complete: everything but the package is back.
    assert_eq!(
        world(&rig, &k),
        before_without_package(&before, true),
        "{what}: {out:#?}"
    );
    assert!(out.index_updated, "{what}");
    assert_eq!(
        rig.entry(&id).unwrap().journal,
        Some(read.state.mark()),
        "{what}"
    );
    assert_eq!(out.state, Some(SessionState::PartiallyUndone), "{what}");
    assert_idempotent(&mut rig, &k, &id, mode, &what);

    // A further undo finds only the package, which stays irreversible, and changes nothing.
    let rest = rig.undo_all(&id);
    assert_eq!(rest.stopped, None, "{what}");
    assert_eq!(
        world(&rig, &k),
        before_without_package(&before, true),
        "{what}: {rest:#?}"
    );
    let end = rig.journal(&id);
    for op in end.state.ops() {
        if op.op == PACKAGE_OP {
            assert_eq!(
                op.undo,
                UndoState::Conflict(UndoConflict::Irreversible),
                "{what}"
            );
        } else {
            assert!(
                op.undo.is_settled(),
                "{what}: op {} is {:?}",
                op.op,
                op.undo
            );
        }
    }
    assert_eq!(
        rig.entry(&id).unwrap().state,
        SessionState::PartiallyUndone,
        "{what}"
    );
}

/// A crash between registering a boot-time move and journalling it, then recovery in `mode`. The
/// registration is the in-memory list the parent hands to recovery, as the registry would still
/// hold it.
fn boot_move_scenario(mode: RecoverMode) {
    let what = format!("{} {mode:?}", fault::BOOTMOVE_REGISTERED);
    let mut rig = Rig::new("crash-boot");
    let k = TestKey::new();
    setup(&rig, &k);
    let before = world(&rig, &k);
    let code = spawn(&rig, &k, "execute", &format!("{}:1", fault::ACT_BEFORE));
    assert_eq!(code, Some(ABORT_CODE), "{what}");
    let [id]: [SessionId; 1] = rig.sessions().try_into().unwrap();
    let code = spawn(&rig, &k, "bootmove", fault::BOOTMOVE_REGISTERED);
    assert_eq!(
        code,
        Some(ABORT_CODE),
        "{what}: the child did not die at the point"
    );
    let pair = boot_pair(&rig, &id);
    rig.pending = MemoryPendingRenames::with_pairs(&[(pair.src.as_str(), pair.dst.as_str())]);
    let registered = rig.pending.bytes().to_vec();
    assert_eq!(rig.journal(&id).state.open_intents().count(), 1, "{what}");

    let out = recover_with(&mut rig, &id, mode);
    let read = rig.journal(&id);
    let pending_reboot = ItemOutcome::PendingReboot {
        pair,
        confirmed: true,
    };
    assert_eq!(out.settled.len(), 1, "{what}: {out:#?}");
    assert_eq!(
        out.settled[0].probe,
        Probe::Done(pending_reboot.clone()),
        "{what}"
    );
    assert_eq!(
        read.state.op(OpId(1)).unwrap().outcome,
        Some(pending_reboot),
        "{what}"
    );
    match mode {
        RecoverMode::Resume => {
            // The move waits for the restart: the file is still in place, its directory is therefore
            // not empty, and everything else ran.
            let outcomes = outcomes(&read);
            assert_eq!(
                outcomes[5],
                Some(ItemOutcome::Skipped {
                    reason: SkipReason::NoLongerEmpty
                }),
                "{what}"
            );
            for op in [1, 2, 3, 4, 6] {
                assert_eq!(
                    outcomes[op],
                    Some(ItemOutcome::Done),
                    "{what}: op {}",
                    op + 1
                );
            }
            assert!(exists(&rig.s.path(r"app\f1.txt")), "{what}");
            assert_eq!(read.state.phase(), Phase::Committed, "{what}");
            let entry = rig.entry(&id).unwrap();
            assert!(entry.pending_reboot, "{what}");
            assert_eq!(entry.state, SessionState::Committed, "{what}");
            assert_eq!(rig.pending.bytes(), registered, "{what}");
        }
        RecoverMode::Rollback => {
            // The registration is taken back, and only it.
            assert!(rig.pending.bytes().is_empty(), "{what}");
            assert_eq!(rig.pending.removals, 1, "{what}");
            assert_eq!(world(&rig, &k), before, "{what}: {out:#?}");
            assert_eq!(
                read.state.op(OpId(1)).unwrap().undo,
                UndoState::Finished(UndoOutcome::Restored),
                "{what}"
            );
            assert_eq!(
                rig.entry(&id).unwrap().state,
                SessionState::Undone,
                "{what}"
            );
            assert!(!rig.entry(&id).unwrap().pending_reboot, "{what}");
        }
    }
    assert_eq!(rig.pending.registers, 0, "{what}");
    assert_idempotent_boot(&mut rig, &k, &id, mode, &what);

    let undone = rig.undo_all(&id);
    assert_eq!(undone.stopped, None, "{what}");
    assert!(rig.pending.bytes().is_empty(), "{what}");
    let removed = mode == RecoverMode::Resume;
    assert_eq!(
        world(&rig, &k),
        before_without_package(&before, removed),
        "{what}: {undone:#?}"
    );
}

/// As [`assert_idempotent`], for a session that may still wait for a restart (which recovery does
/// not list).
fn assert_idempotent_boot(
    rig: &mut Rig,
    k: &TestKey,
    id: &SessionId,
    mode: RecoverMode,
    what: &str,
) {
    let store = rig.store_files();
    let machine = world(rig, k);
    let pending = rig.pending.bytes().to_vec();
    let again = recover_with(rig, id, mode);
    assert!(
        again.settled.is_empty() && again.undone.is_empty(),
        "{what}: {again:#?}"
    );
    assert_eq!(rig.store_files(), store, "{what}");
    assert_eq!(world(rig, k), machine, "{what}");
    assert_eq!(rig.pending.bytes(), pending, "{what}");
}

// ---------------------------------------------------------------------------------------------------
// The matrix
// ---------------------------------------------------------------------------------------------------

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_else(|| "panicked".to_owned())
}

/// Every scenario of one point; one line per scenario, `Err` with the failure.
fn run_point(point: &'static str) -> Vec<(String, Result<(), String>)> {
    let mut rows = Vec::new();
    let mut scenario = |name: String, run: &(dyn Fn() + std::panic::RefUnwindSafe)| {
        rows.push((name, std::panic::catch_unwind(run).map_err(panic_text)));
    };
    for mode in [RecoverMode::Resume, RecoverMode::Rollback] {
        match drive(point) {
            Drive::Execute(hits) => {
                for &hit in hits {
                    scenario(
                        format!("{point}:{hit} x {mode:?} (crash in execute)"),
                        &|| execute_scenario(point, hit, mode),
                    );
                }
            }
            Drive::Undo(hits) => {
                for &hit in hits {
                    scenario(format!("{point}:{hit} x {mode:?} (crash in undo)"), &|| {
                        undo_scenario(point, hit, mode)
                    });
                }
            }
            Drive::BootMove => scenario(
                format!("{point} x {mode:?} (in-memory boot-time move list)"),
                &|| boot_move_scenario(mode),
            ),
            Drive::NotDriven(_) => {}
        }
    }
    rows
}

/// The scenarios of one point, each with its name and how it ended.
type Rows = Vec<(String, Result<(), String>)>;

#[test]
fn every_fault_point_recovers_by_resume_and_by_rollback() {
    // The reference run is made once, before the points run side by side.
    reference();
    let results: Vec<(&str, Rows)> = std::thread::scope(|scope| {
        let threads: Vec<_> = fault::FAULT_POINTS
            .iter()
            .map(|&point| (point, scope.spawn(move || run_point(point))))
            .collect();
        threads
            .into_iter()
            .map(|(point, thread)| (point, thread.join().unwrap()))
            .collect()
    });
    let mut failures = Vec::new();
    for (point, rows) in &results {
        if let Drive::NotDriven(reason) = drive(point) {
            println!("not driven  {point}: {reason}");
            assert!(rows.is_empty());
            continue;
        }
        assert!(!rows.is_empty(), "{point} has no scenario");
        for (name, result) in rows {
            match result {
                Ok(()) => println!("pass        {name}"),
                Err(e) => {
                    println!("FAIL        {name}");
                    failures.push(format!("{name}: {e}"));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} scenario(s) failed:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

// ---------------------------------------------------------------------------------------------------
// A crash during recovery
// ---------------------------------------------------------------------------------------------------

/// A crash while executing at `first`, then a second crash while recovering it in `child` mode at
/// `second`, then recovery in `mode`. `rolls_back` says whether the end must be the machine as before
/// (a rollback, or a resume that finds a rollback interrupted) or the uninterrupted run.
fn crash_in_recovery(
    first: (&str, u32),
    child: &str,
    second: (&str, u32),
    mode: RecoverMode,
    rolls_back: bool,
) {
    let what = format!(
        "{}:{} then {child} {}:{} then {mode:?}",
        first.0, first.1, second.0, second.1
    );
    let mut rig = Rig::new("crash-again");
    let k = TestKey::new();
    setup(&rig, &k);
    let before = world(&rig, &k);
    let code = spawn(&rig, &k, "execute", &format!("{}:{}", first.0, first.1));
    assert_eq!(code, Some(ABORT_CODE), "{what}: the run did not die");
    let [id]: [SessionId; 1] = rig.sessions().try_into().unwrap();
    let code = spawn(&rig, &k, child, &format!("{}:{}", second.0, second.1));
    assert_eq!(code, Some(ABORT_CODE), "{what}: the recovery did not die");
    let crashed = rig.journal(&id);
    assert!(!crashed.state.is_finished(), "{what}");
    assert_eq!(
        recover::pending(&rig.roots).unwrap().sessions[0].kind,
        PendingKind::Run,
        "{what}"
    );

    let out = recover_with(&mut rig, &id, mode);
    let read = rig.journal(&id);
    assert!(read.state.is_finished(), "{what}: {out:#?}");
    assert_eq!(read.state.open_intents().count(), 0, "{what}");
    assert!(read.state.undo_unfinished().is_empty(), "{what}");
    assert_eq!(read.state.undo_in_progress().count(), 0, "{what}");
    let removed =
        read.state.op(PACKAGE_OP).and_then(|op| op.outcome.clone()) == Some(ItemOutcome::Done);
    if rolls_back {
        assert_eq!(out.mode, RecoverMode::Rollback, "{what}: {out:#?}");
        assert_eq!(
            read.state.aborted().map(|a| a.reason),
            Some(AbortReason::RolledBack),
            "{what}"
        );
        assert_eq!(
            world(&rig, &k),
            before_without_package(&before, removed),
            "{what}: {out:#?}"
        );
        for op in read.state.ops().filter(|op| op.intent.is_some()) {
            let irreversible = op.op == PACKAGE_OP && removed;
            assert_eq!(
                op.undo.is_settled(),
                !irreversible,
                "{what}: op {} is {:?}",
                op.op,
                op.undo
            );
        }
    } else {
        let (machine, outcomes_of_a_full_run) = reference();
        assert_eq!(outcomes(&read), *outcomes_of_a_full_run, "{what}: {out:#?}");
        assert_eq!(&world(&rig, &k), machine, "{what}");
        assert_eq!(read.state.phase(), Phase::Committed, "{what}");
    }
    assert!(out.index_updated, "{what}");
    assert_idempotent(&mut rig, &k, &id, mode, &what);
    let undone = rig.undo_all(&id);
    assert_eq!(undone.stopped, None, "{what}");
    assert_eq!(
        world(&rig, &k),
        before_without_package(&before, removed),
        "{what}: {undone:#?}"
    );
}

/// M2 of the final M2 review: a rollback that dies in its undo phase leaves an unfinished journal with
/// undo records. Resume continues the rollback; before the fix it went forward and committed a session
/// that was neither the plan applied nor the machine as before.
#[test]
fn a_resume_after_an_interrupted_rollback_continues_the_rollback() {
    for second in [(fault::UNDO_ACT_AFTER, 1), (fault::UNDO_INTENT, 2)] {
        for mode in [RecoverMode::Resume, RecoverMode::Rollback] {
            crash_in_recovery((fault::ACT_AFTER, 3), "rollback", second, mode, true);
        }
    }
}

/// A resume that dies while it runs the rest of the plan is resumed, or rolled back, like any run.
#[test]
fn a_crash_while_resuming_is_recovered_again() {
    for second in [(fault::INTENT_FLUSHED, 1), (fault::ACT_AFTER, 2)] {
        crash_in_recovery(
            (fault::ACT_BEFORE, 2),
            "resume",
            second,
            RecoverMode::Resume,
            false,
        );
        crash_in_recovery(
            (fault::ACT_BEFORE, 2),
            "resume",
            second,
            RecoverMode::Rollback,
            true,
        );
    }
}

/// The machine changes between the crash and recovery: the run moved `f1.txt` and died before its
/// `done`; then somebody puts a new `f1.txt` in its place. Neither recovery touches the new file.
#[test]
fn a_file_put_back_by_somebody_else_after_the_crash_is_left_alone() {
    for mode in [RecoverMode::Resume, RecoverMode::Rollback] {
        let what = format!("{mode:?}");
        let mut rig = Rig::new("crash-changed");
        let k = TestKey::new();
        setup(&rig, &k);
        let code = spawn(&rig, &k, "execute", &format!("{}:1", fault::ACT_AFTER));
        assert_eq!(code, Some(ABORT_CODE), "{what}");
        let [id]: [SessionId; 1] = rig.sessions().try_into().unwrap();
        let f1 = rig.s.path(r"app\f1.txt");
        assert!(!exists(&f1), "{what}");
        std::fs::write(ext(&f1), b"somebody else's").unwrap();

        let out = recover_with(&mut rig, &id, mode);
        let read = rig.journal(&id);
        assert_eq!(out.settled.len(), 1, "{what}: {out:#?}");
        assert_eq!(
            out.settled[0].probe,
            Probe::Done(ItemOutcome::Done),
            "{what}: the recorded file is in quarantine, another one at its path"
        );
        assert_eq!(
            std::fs::read(ext(&f1)).unwrap(),
            b"somebody else's",
            "{what}"
        );
        assert_eq!(
            std::fs::read(ext(&quarantine_path(&read, 1))).unwrap(),
            b"one",
            "{what}"
        );
        match mode {
            RecoverMode::Resume => {
                // The directory is not empty any more; the rest of the plan ran.
                assert_eq!(
                    read.state.op(OpId(6)).unwrap().outcome,
                    Some(ItemOutcome::Skipped {
                        reason: SkipReason::NoLongerEmpty
                    }),
                    "{what}"
                );
                assert_eq!(read.state.phase(), Phase::Committed, "{what}");
            }
            RecoverMode::Rollback => {
                // Nothing is overwritten: the move back of op 1 is a conflict, and everything
                // else is back.
                assert_eq!(
                    read.state.op(OpId(1)).unwrap().undo,
                    UndoState::Conflict(UndoConflict::DestinationExists),
                    "{what}"
                );
                assert_eq!(
                    std::fs::read(ext(&rig.s.path(r"app\f2.txt"))).unwrap(),
                    b"two",
                    "{what}"
                );
                assert_eq!(out.state, Some(SessionState::PartiallyUndone), "{what}");
            }
        }
        assert_idempotent(&mut rig, &k, &id, mode, &what);
    }
}

// ---------------------------------------------------------------------------------------------------
// States the fault points do not reach
// ---------------------------------------------------------------------------------------------------

/// S2 of the final M2 review: a retry of a held item that ended `Failed{VerifyFailed}` (here: an
/// interrupted retry whose item is found at its path and in quarantine, two names of one file) may
/// have left the item in quarantine. Undo looks where it is. Before the fix the op was
/// `NothingToUndo`, the session `Undone`, and the file stayed in quarantine for expiry.
#[test]
fn a_retry_that_ended_in_a_failed_verify_is_undone_from_where_the_item_is() {
    let mut rig = Rig::new("retry-verify");
    let busy = rig.s.file(r"app\busy.dll", b"in use");
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(ext(&busy))
        .unwrap();
    let done = rig.run(request(vec![quarantine("c-busy", &busy)], Vec::new()));
    drop(handle);
    let id = done.session.clone();
    let read = rig.journal(&id);
    assert_eq!(outcomes(&read), [Some(ItemOutcome::HeldRetry)]);

    // The retry moved the file and died; the file has a second name at its old place now.
    let _token = JournalWriter::open_append(&rig.session(&id))
        .unwrap()
        .retry_intent(OpId(1), FileTime(1))
        .unwrap();
    let quarantined = quarantine_path(&read, 1);
    std::fs::create_dir_all(ext(&quarantined).parent().unwrap()).unwrap();
    std::fs::rename(ext(&busy), ext(&quarantined)).unwrap();
    std::fs::hard_link(ext(&quarantined), ext(&busy)).unwrap();
    let out = rig.resume(&id);
    assert!(
        matches!(
            out.retries.as_slice(),
            [(
                OpId(1),
                ItemOutcome::Failed {
                    code: purge_model::exec::op::FailCode::VerifyFailed,
                    ..
                }
            )]
        ),
        "{out:#?}"
    );

    // The undo looks: the original path is taken (by the second name), so nothing is overwritten.
    let undone = rig.undo_all(&id);
    assert_eq!(undone.report.items.len(), 1, "{undone:#?}");
    assert!(
        matches!(
            undone.report.items[0].result,
            UndoResult::Conflict {
                conflict: UndoConflict::DestinationExists,
                ..
            }
        ),
        "{undone:#?}"
    );
    assert_eq!(undone.report.state, SessionState::PartiallyUndone);
    assert!(exists(&quarantined));

    // Once the second name is gone, the file comes back from quarantine.
    std::fs::remove_file(ext(&busy)).unwrap();
    let again = rig.undo_all(&id);
    assert_eq!(again.report.counts.restored, 1, "{again:#?}");
    assert_eq!(std::fs::read(ext(&busy)).unwrap(), b"in use");
    assert!(!exists(&quarantined));
    assert_eq!(rig.entry(&id).unwrap().state, SessionState::Undone);
}

#[test]
fn an_interrupted_retry_of_a_held_item_is_ended_from_where_the_item_is() {
    let mut rig = Rig::new("retry");
    let busy = rig.s.file(r"app\busy.dll", b"in use");
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(ext(&busy))
        .unwrap();
    let done = rig.run(request(vec![quarantine("c-busy", &busy)], Vec::new()));
    drop(handle);
    let id = done.session.clone();
    assert_eq!(outcomes(&rig.journal(&id)), [Some(ItemOutcome::HeldRetry)]);
    let retry_intent = |rig: &Rig| {
        // The token is dropped: the process that held it died.
        let _token = JournalWriter::open_append(&rig.session(&id))
            .unwrap()
            .retry_intent(OpId(1), FileTime(1))
            .unwrap();
    };

    // The retry was journalled and never moved the file: it is held again.
    retry_intent(&rig);
    let listed = recover::pending(&rig.roots).unwrap();
    assert_eq!(listed.sessions[0].kind, PendingKind::Retry);
    assert_eq!(listed.sessions[0].retries_in_flight, [OpId(1)]);
    let request = UndoRequest {
        session: id.clone(),
        selection: UndoSelection::All,
        plan_hash: None,
    };
    assert!(matches!(
        undo(&request, rig.undo_env()),
        Err(UndoError::NeedsRecovery(_))
    ));
    let out = rig.resume(&id);
    assert_eq!(out.retries, [(OpId(1), ItemOutcome::HeldRetry)]);
    let read = rig.journal(&id);
    let op = read.state.op(OpId(1)).unwrap();
    assert!(!op.retry_in_flight);
    assert_eq!(
        op.reconciles.last(),
        Some(&ReconcileResult::Retried {
            outcome: ItemOutcome::HeldRetry
        })
    );
    assert!(exists(&busy));
    let store = rig.store_files();
    assert!(rig.resume(&id).retries.is_empty());
    assert_eq!(rig.store_files(), store);

    // The next retry moved the file and died before saying so: the journal learns that it is done.
    retry_intent(&rig);
    let quarantined = quarantine_path(&read, 1);
    std::fs::create_dir_all(ext(&quarantined).parent().unwrap()).unwrap();
    std::fs::rename(ext(&busy), ext(&quarantined)).unwrap();
    let out = rig.rollback(&id);
    assert_eq!(out.retries, [(OpId(1), ItemOutcome::Done)]);
    assert!(recover::pending(&rig.roots).unwrap().sessions.is_empty());

    // And the move can be undone like any other.
    let undone = rig.undo_all(&id);
    assert_eq!(undone.report.counts.restored, 1, "{undone:#?}");
    assert_eq!(std::fs::read(ext(&busy)).unwrap(), b"in use");
    assert_eq!(rig.entry(&id).unwrap().state, SessionState::Undone);
}

#[test]
fn a_session_directory_without_a_journal_is_removed() {
    let mut rig = Rig::new("unstarted");
    let session = rig.roots.create_session().unwrap();
    let id = session.id().clone();
    drop(session);
    let listed = recover::pending(&rig.roots).unwrap();
    assert_eq!(listed.sessions.len(), 1);
    assert_eq!(listed.sessions[0].kind, PendingKind::Unstarted);

    let out = rig.resume(&id);
    assert!(out.removed);
    assert_eq!(out.state, None);
    assert!(rig.sessions().is_empty());
    assert!(recover::pending(&rig.roots).unwrap().sessions.is_empty());
}
