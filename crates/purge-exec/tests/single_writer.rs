//! One writer of the store at a time (DECISIONS 2026-11-22, review R3): every operation that writes
//! the store (execute, undo, recovery, the retry of held items, expiry's purge) holds the store's writer
//! lock for its whole length, so two of them, in two brokers or two threads, never interleave their
//! index rewrites or act on one session together. A writer that cannot get the lock within
//! `WRITER_WAIT` is refused before it reads or writes anything; readers never wait for it.
//!
//! Unelevated, on a temp directory; the lock is a handle that shares nothing, so threads of this
//! process stand for the brokers (the storage unit tests show the same for another process, and that
//! a killed holder releases it).

#![cfg(feature = "test-support")]

mod common;

use std::sync::Barrier;

use common::*;
use purge_exec::execute::{ExecError, execute};
use purge_exec::expiry::{self, PurgeConsent, PurgeError};
use purge_exec::recover::{self, RecoverError, Want};
use purge_exec::storage::StorageError;
use purge_exec::undo::{self, UndoError, UndoRequest, UndoSelection};
use purge_model::exec::session::{SessionId, SessionState};

fn busy(e: &StorageError) -> bool {
    matches!(e, StorageError::WriterBusy { .. })
}

/// One file of the rig's scratch directory, quarantined by a run of its own.
fn one_file_plan(rig: &Rig, name: &str) -> purge_exec::plan_in::ExecRequest {
    let file = rig.s.file(&format!(r"app\{name}.txt"), name.as_bytes());
    request(vec![quarantine(&format!("c-{name}"), &file)], Vec::new())
}

/// While another writer holds the store, a run, an undo, a resume, a rollback, a retry of held items
/// and a purge are each refused with `WriterBusy` and change nothing; the previews, the pending list,
/// the expiry listing and the index still read. Once the holder lets go, the same undo runs.
#[test]
fn every_writer_is_refused_while_another_holds_the_store_and_readers_are_not() {
    let mut rig = Rig::new("single-writer-refused");
    let first = one_file_plan(&rig, "one");
    let session = rig.run(first).session;
    let second = one_file_plan(&rig, "two");
    let before = rig.store_files();
    let index = rig.roots.read_index().unwrap();

    let held = rig.roots.lock_writer().unwrap();

    match execute(second.clone(), rig.exec_env(), FakeRestore) {
        Err(ExecError::Store(e)) if busy(&e) => {}
        other => panic!("execute: {:?}", other.map(|out| out.session)),
    }
    assert!(exists(&rig.s.path(r"app\two.txt")), "the run moved nothing");
    let request = UndoRequest {
        session: session.clone(),
        selection: UndoSelection::All,
        plan_hash: None,
    };
    match undo::undo(&request, rig.undo_env()) {
        Err(UndoError::Store(e)) if busy(&e) => {}
        other => panic!("undo: {:?}", other.map(|out| out.report.counts)),
    }
    for (name, result) in [
        ("resume", recover::resume(&session, rig.recover_env()).err()),
        (
            "rollback",
            recover::rollback(&session, rig.recover_env()).err(),
        ),
    ] {
        assert!(
            matches!(&result, Some(RecoverError::Store(e)) if busy(e)),
            "{name}: {result:?}"
        );
    }
    match recover::retry_held(&session, rig.recover_env()) {
        Err(RecoverError::Store(e)) if busy(&e) => {}
        other => panic!("retry_held: {:?}", other.map(|out| out.retried)),
    }
    match expiry::purge(&rig.roots, &[], &PurgeConsent::naming([]), filetime_now()) {
        Err(PurgeError::Store(e)) if busy(&e) => {}
        other => panic!("purge: {:?}", other.map(|report| report.items.len())),
    }

    // Readers do not wait for the writer.
    assert_eq!(rig.roots.read_index().unwrap(), index);
    assert!(recover::pending(&rig.roots).unwrap().sessions.is_empty());
    let preview = undo::preview(&rig.roots, &session, None).unwrap();
    assert_eq!(preview.put_back.len(), 1);
    assert!(recover::preview(&rig.roots, &session, Want::RetryHeld).is_ok());
    expiry::expiring(&rig.roots, filetime_now()).unwrap();

    drop(held);
    assert_eq!(rig.store_files(), before, "a refused writer wrote nothing");
    let out = undo::undo_expecting(&preview.request, rig.undo_env(), &preview.expect).unwrap();
    assert_eq!(out.report.counts.restored, 1);
    assert!(exists(&rig.s.path(r"app\one.txt")));
}

/// Two runs and an undo started at once on one store (three brokers, one thread each) are
/// serialised: each completes, and the index holds every run's entry and the undo's result. Without
/// the lock the index's read-modify-write lost entries or failed its read-back.
#[test]
fn writers_started_at_once_are_serialised_and_the_index_keeps_every_change() {
    let mut a = Rig::new("single-writer-a");
    let undone = {
        let plan = one_file_plan(&a, "undone");
        a.run(plan).session
    };
    let mut b = Rig::with(Scratch::new("single-writer-b"), a.roots.clone());
    let mut c = Rig::with(Scratch::new("single-writer-c"), a.roots.clone());
    let plan_b = one_file_plan(&b, "b");
    let plan_c = one_file_plan(&c, "c");
    let preview = undo::preview(&a.roots, &undone, None).unwrap();
    let roots = a.roots.clone();

    let start = Barrier::new(3);
    let (run_b, run_c, undo_a) = std::thread::scope(|scope| {
        let start = &start;
        let preview = &preview;
        // The rigs are borrowed, not moved: the first one's scratch directory holds the store.
        let (a, b, c) = (&mut a, &mut b, &mut c);
        let run_b = scope.spawn(move || {
            start.wait();
            execute(plan_b, b.exec_env(), FakeRestore)
                .map(|out| (out.session, out.index_updated))
                .map_err(|e| e.to_string())
        });
        let run_c = scope.spawn(move || {
            start.wait();
            execute(plan_c, c.exec_env(), FakeRestore)
                .map(|out| (out.session, out.index_updated))
                .map_err(|e| e.to_string())
        });
        let undo_a = scope.spawn(move || {
            start.wait();
            undo::undo_expecting(&preview.request, a.undo_env(), &preview.expect)
                .map(|out| (out.report.counts.restored, out.index_updated))
                .map_err(|e| e.to_string())
        });
        (
            run_b.join().unwrap(),
            run_c.join().unwrap(),
            undo_a.join().unwrap(),
        )
    });
    let (session_b, indexed_b) = run_b.unwrap();
    let (session_c, indexed_c) = run_c.unwrap();
    assert!(indexed_b && indexed_c);
    assert_eq!(undo_a.unwrap(), (1, true));

    let index = roots.read_index().unwrap();
    let entry = |id: &SessionId| {
        index
            .get(id)
            .unwrap_or_else(|| panic!("session {id} lost from the index"))
            .clone()
    };
    for id in [&session_b, &session_c] {
        assert_eq!(entry(id).state, SessionState::Committed, "{id}");
        assert_eq!(entry(id).undone, 0, "{id}");
    }
    assert_eq!(
        (entry(&undone).state, entry(&undone).undone),
        (SessionState::Undone, 1),
        "the undo's index update was kept"
    );
    assert_eq!(index.sessions.len(), 3);
    assert!(recover::pending(&roots).unwrap().sessions.is_empty());
}
