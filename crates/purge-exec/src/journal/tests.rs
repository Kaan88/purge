//! Tests of the journal: format, rules, torn tail, corruption, hash chain, groups, hashing and fault
//! points. Every file lives in a temp directory the test creates and removes.

use std::path::PathBuf;

use purge_model::exec::journal::{
    AbortReason, Expire, FileFacts, GateExemptions, Header, Intent, ItemFacts, JournalSchema,
    Reconcile, ReconcileResult, Record, UndoConflict, UndoOutcome, Validated,
};
use purge_model::exec::op::{
    BackupRef, BootMovePair, ExecOp, FailCode, FileIdHex, Inverse, ItemOutcome, OpId,
    OutcomeCounts, SkipReason,
};
use purge_model::exec::session::{RetentionClass, SessionId};
use purge_model::{CandidateId, FileTime, ScanMode, Target};

use super::frame::{CHAIN_SEED, SUFFIX_LEN, frame};
use super::*;

/// A descriptor the unelevated test user can create, write and delete files with.
const SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";

/// A fresh directory under the temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "purge-journal-{tag}-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        TempDir(dir)
    }

    fn journal(&self) -> PathBuf {
        self.0.join(JOURNAL_FILE_NAME)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn header(items: u32) -> Header {
    Header {
        schema: JournalSchema,
        session: SessionId::new(FileTime(134_078_121_020_000_000), 0x9f3a_6c1d_2b7e_4a50),
        created: FileTime(134_078_121_020_000_000),
        engine_version: "0.1.0".into(),
        app: "vendor-app".into(),
        plan_hash: sha256_bytes(b"plan"),
        selection_hash: sha256_bytes(b"selection"),
        policy_version: "m1a.6".into(),
        mode: ScanMode::Post,
        items,
        allow_irreversible: false,
        volumes: Vec::new(),
    }
}

/// The item path of op `n`: with spaces, as the rig's traps use.
fn path_of(n: u32) -> String {
    format!(r"C:\Program Files\Vendor App\file {n}.dat")
}

fn item(n: u32) -> CandidateId {
    CandidateId(format!("c-{n:03}"))
}

fn validated(n: u32) -> Validated {
    Validated {
        op: OpId(n),
        item: item(n),
        target: Target::Path { path: path_of(n) },
        facts: ItemFacts::Absent,
        exemptions: GateExemptions::default(),
    }
}

fn intent(n: u32) -> Intent {
    Intent {
        op: OpId(n),
        item: item(n),
        exec_op: ExecOp::QuarantineMove { path: path_of(n) },
        inverse: Inverse::MoveBack {
            quarantine_path: format!(r"C:\ProgramData\Purge\Quarantine\s\{n:06}\file {n}.dat"),
            original_path: path_of(n),
            file_id: FileIdHex([n as u8; 16]),
            volume_serial: 7,
        },
        definition: None,
        pre: ItemFacts::File(FileFacts {
            final_path: path_of(n),
            file_id: FileIdHex([n as u8; 16]),
            volume_serial: 7,
            reparse_tag: 0,
            attributes: 32,
            n_links: 1,
            is_dir: false,
            size: 0,
            tree_entries: None,
            tree_bytes: None,
        }),
    }
}

/// A registered boot-time move of op `n`'s file.
fn pending_reboot(n: u32) -> ItemOutcome {
    ItemOutcome::PendingReboot {
        pair: BootMovePair {
            src: format!(r"\??\{}", path_of(n)),
            dst: format!(r"\??\C:\ProgramData\Purge\Quarantine\s\{n:06}\file {n}.dat"),
        },
        confirmed: true,
    }
}

/// A journal with `items` validated items.
fn started(dir: &TempDir, items: u32) -> JournalWriter {
    let mut w = JournalWriter::create(&dir.journal(), SDDL, header(items)).unwrap();
    for n in 1..=items {
        w.validated(validated(n)).unwrap();
    }
    w
}

fn failed() -> ItemOutcome {
    ItemOutcome::Failed {
        code: FailCode::AccessDenied,
        os_error: Some(5),
        detail: String::new(),
    }
}

/// A committed session with every kind of record, undone in part, reconciled and expired afterwards.
fn sample_journal(dir: &TempDir) -> Vec<u8> {
    let mut w = started(dir, 4);
    let t1 = w.intent(intent(1)).unwrap();
    w.done(t1, ItemOutcome::Done).unwrap();
    w.done_without_intent(OpId(2), ItemOutcome::Vanished)
        .unwrap();
    let t3 = w.intent(intent(3)).unwrap();
    w.done(t3, pending_reboot(3)).unwrap();
    let t4 = w.intent(intent(4)).unwrap();
    w.done(t4, failed()).unwrap();
    w.commit(FileTime(134_078_121_950_000_000), 4096).unwrap();
    drop(w);

    let mut w = JournalWriter::open_append(&dir.journal()).unwrap();
    let u1 = w.undo_intent(OpId(1)).unwrap();
    w.undo_done(u1, UndoOutcome::Restored).unwrap();
    w.undo_conflict_without_intent(OpId(4), UndoConflict::BackupTampered, "x".into())
        .unwrap();
    w.reconcile(Reconcile {
        at: FileTime(134_078_999_990_000_000),
        op: OpId(3),
        result: ReconcileResult::Completed,
    })
    .unwrap();
    w.expire(Expire {
        at: FileTime(134_104_041_020_000_000),
        op: OpId(3),
        class: RetentionClass::Quarantine,
        bytes: 10,
    })
    .unwrap();
    drop(w);
    std::fs::read(dir.journal()).unwrap()
}

/// Frames record bodies into journal bytes, chaining as the writer does.
fn chained(bodies: &[String]) -> Vec<u8> {
    let mut chain = CHAIN_SEED;
    let mut out = Vec::new();
    for body in bodies {
        let (line, next) = frame(&chain, body);
        out.extend_from_slice(&line);
        chain = next;
    }
    out
}

fn body(record: Record) -> String {
    serde_json::to_string(&record).unwrap()
}

/// The lines of `bytes`, each with its `\n`.
fn lines(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes
        .split_inclusive(|&b| b == b'\n')
        .map(<[u8]>::to_vec)
        .collect()
}

/// The line number and kind of a refusal.
fn corrupt(result: Result<JournalRead, JournalError>) -> (u64, Corruption) {
    match result {
        Err(JournalError::Corrupt { line, kind, .. }) => (line, kind),
        other => panic!("expected a corrupt journal, got {other:?}"),
    }
}

fn refused<T: std::fmt::Debug>(result: Result<T, JournalError>) -> Violation {
    match result {
        Err(JournalError::Refused(v)) => v,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_full_session_reads_back() {
    let dir = TempDir::new("full");
    let bytes = sample_journal(&dir);
    let read = read(&dir.journal()).unwrap();
    assert_eq!(read.torn_tail, 0);
    assert_eq!(read.valid_len, bytes.len() as u64);
    assert_eq!(read.records.len(), 1 + 4 + 3 + 4 + 1 + 1 + 5);
    assert!(matches!(read.records[0], Record::Header(_)));
    assert_eq!(parse(&bytes).unwrap(), read);

    let state = &read.state;
    assert_eq!(state.phase(), Phase::Committed);
    assert_eq!(state.session(), &header(4).session);
    assert_eq!(
        state.counts(),
        OutcomeCounts {
            done: 1,
            vanished: 1,
            pending_reboot: 1,
            failed: 1,
            ..OutcomeCounts::default()
        }
    );
    assert_eq!(state.commit().unwrap().counts, state.counts());
    assert_eq!(state.groups_closed(), 1);
    let op = |n| state.op(OpId(n)).unwrap();
    assert_eq!(op(1).status(), OpStatus::Done(&ItemOutcome::Done));
    assert_eq!(op(1).undo, UndoState::Finished(UndoOutcome::Restored));
    assert_eq!(op(1).undo_attempts, 1);
    assert_eq!(op(2).status(), OpStatus::Done(&ItemOutcome::Vanished));
    assert!(op(2).intent.is_none());
    assert_eq!(op(3).reconciles, [ReconcileResult::Completed]);
    assert_eq!(op(3).pending(), None);
    assert_eq!(op(3).expired, [RetentionClass::Quarantine]);
    assert_eq!(
        op(4).undo,
        UndoState::Conflict(UndoConflict::BackupTampered)
    );
    assert_eq!(state.open_intents().count(), 0);
    assert_eq!(state.pending_reboot().count(), 0);
    assert_eq!(state.undo_in_progress().count(), 0);

    // Every line is one framed record.
    for line in lines(&bytes) {
        assert_eq!(line.last(), Some(&b'\n'));
        assert!(line.starts_with(br#"{"rec":""#));
        let text = std::str::from_utf8(&line).unwrap();
        assert!(text[text.len() - 1 - SUFFIX_LEN..].starts_with(r#","chain":""#));
        assert!(!text.contains('\r'));
    }
    let reopened = JournalWriter::open_append(&dir.journal()).unwrap();
    assert_eq!(reopened.head(), read.head);
    assert_eq!(reopened.len(), bytes.len() as u64);
    assert_eq!(reopened.discarded_tail(), 0);
}

/// The contract the rig's swap helper relies on: the intent line of an item is the first line holding
/// its JSON-escaped path and the word "intent", and only the two intent kinds spell that word.
#[test]
fn intent_line_carries_the_escaped_path_and_the_word() {
    let dir = TempDir::new("swap");
    let bytes = sample_journal(&dir);
    let escaped = serde_json::to_string(&path_of(3)).unwrap();
    let escaped = escaped.trim_matches('"');
    assert!(escaped.contains(r"\\Program Files\\"));
    let all = lines(&bytes);
    let text = |line: &Vec<u8>| String::from_utf8(line.clone()).unwrap();
    let first = all
        .iter()
        .position(|l| {
            let t = text(l);
            t.contains(escaped) && t.to_lowercase().contains("intent")
        })
        .unwrap();
    assert!(text(&all[first]).starts_with(r#"{"rec":"intent","op":3,"#));
    assert!(all[..first].iter().any(|l| text(l).contains(escaped)));
    for line in &all {
        let t = text(line);
        let is_intent =
            t.starts_with(r#"{"rec":"intent""#) || t.starts_with(r#"{"rec":"undo_intent""#);
        assert_eq!(t.to_lowercase().contains("intent"), is_intent, "{t}");
    }
}

#[test]
fn intent_is_flushed_before_the_token_is_returned() {
    let dir = TempDir::new("durable");
    let mut w = started(&dir, 2);
    let before = w.syncs();
    let token = w.intent(intent(1)).unwrap();
    assert_eq!(w.syncs(), before + 1);
    assert_eq!((token.op(), token.item()), (OpId(1), &item(1)));
    // A second reader sees the intent while the writer holds the file.
    let seen = read(&dir.journal()).unwrap();
    assert_eq!(
        seen.state.op(OpId(1)).unwrap().status(),
        OpStatus::IntentOnly
    );
    assert_eq!(seen.state.open_intents().count(), 1);
    // A done is not flushed by itself.
    w.done(token, ItemOutcome::Done).unwrap();
    assert_eq!(w.syncs(), before + 1);
    // A second writer cannot open the file meanwhile.
    assert!(matches!(
        JournalWriter::open_append(&dir.journal()),
        Err(JournalError::Io { .. })
    ));
}

#[test]
fn groups_close_after_64_intents() {
    let dir = TempDir::new("groups");
    let mut w = started(&dir, 130);
    for n in 1..=130 {
        let token = w.intent(intent(n)).unwrap();
        w.done(token, ItemOutcome::Done).unwrap();
    }
    w.commit(FileTime(1), 0).unwrap();
    // Header, one per intent, three group ends, commit.
    assert_eq!(w.syncs(), 1 + 130 + 3 + 1);
    drop(w);

    let read = read(&dir.journal()).unwrap();
    let groups: Vec<(usize, u32, u32)> = read
        .records
        .iter()
        .enumerate()
        .filter_map(|(i, r)| match r {
            Record::GroupEnd(g) => Some((i, g.group, g.ops)),
            _ => None,
        })
        .collect();
    assert_eq!(
        groups.iter().map(|g| (g.1, g.2)).collect::<Vec<_>>(),
        [(1, 64), (2, 64), (3, 2)]
    );
    // The first group ends right after the done of op 64.
    assert!(matches!(&read.records[groups[0].0 - 1], Record::Done(d) if d.op == OpId(64)));
    assert_eq!(read.state.groups_closed(), 3);
    assert_eq!(read.state.counts().done, 130);
}

#[test]
fn a_full_group_closes_before_the_65th_intent_even_with_intents_open() {
    let dir = TempDir::new("groups-open");
    let mut w = started(&dir, 65);
    let mut tokens = Vec::new();
    for n in 1..=65 {
        tokens.push(w.intent(intent(n)).unwrap());
    }
    assert_eq!(w.state().groups_closed(), 1);
    assert_eq!(w.state().open_group_intents(), 1);
    assert_eq!(w.state().open_intent_count(), 65);
    for token in tokens {
        w.done(token, ItemOutcome::Done).unwrap();
    }
    w.commit(FileTime(1), 0).unwrap();
    drop(w);
    let read = read(&dir.journal()).unwrap();
    let names: Vec<&str> = read.records.iter().map(Record::name).collect();
    let first_end = names.iter().position(|&n| n == "group_end").unwrap();
    assert!(matches!(&read.records[first_end + 1], Record::Intent(i) if i.op == OpId(65)));
    assert_eq!(read.state.groups_closed(), 2);
}

#[test]
fn writer_refuses_rule_breaks_and_writes_nothing() {
    let dir = TempDir::new("refuse");
    let mut w = JournalWriter::create(&dir.journal(), SDDL, header(3)).unwrap();
    w.validated(validated(1)).unwrap();
    // The run cannot start before every item is validated.
    assert_eq!(
        refused(w.intent(intent(1))),
        Violation::NotAllValidated {
            items: 3,
            validated: 1
        }
    );
    assert_eq!(
        refused(w.validated(validated(1))),
        Violation::DuplicateValidated(OpId(1))
    );
    assert_eq!(
        refused(w.validated(validated(4))),
        Violation::OpOutOfRange(OpId(4))
    );
    w.validated(validated(2)).unwrap();
    w.validated(validated(3)).unwrap();

    // A done that needs an intent; an intent that does not hang together or names another target.
    assert_eq!(
        refused(w.done_without_intent(OpId(1), ItemOutcome::Done)),
        Violation::DoneWithoutIntent(OpId(1))
    );
    assert_eq!(
        refused(w.done_without_intent(OpId(1), pending_reboot(1))),
        Violation::DoneWithoutIntent(OpId(1))
    );
    let mut wrong = intent(1);
    wrong.inverse = Inverse::None;
    assert_eq!(
        refused(w.intent(wrong)),
        Violation::InconsistentIntent(OpId(1))
    );
    let mut outside = intent(1);
    outside.definition = Some(BackupRef {
        path: r"..\x.json".into(),
        sha256: sha256_bytes(b""),
        bytes: 0,
    });
    assert_eq!(
        refused(w.intent(outside)),
        Violation::InconsistentIntent(OpId(1))
    );
    let mut elsewhere = intent(1);
    elsewhere.exec_op = ExecOp::QuarantineMove { path: path_of(2) };
    assert_eq!(
        refused(w.intent(elsewhere)),
        Violation::TargetMismatch(OpId(1))
    );
    let mut other_item = intent(1);
    other_item.item = item(2);
    assert_eq!(
        refused(w.intent(other_item)),
        Violation::ItemMismatch(OpId(1))
    );
    assert_eq!(refused(w.intent(intent(9))), Violation::UnknownOp(OpId(9)));
    assert!(w.state().ops().all(|s| s.intent.is_none()));

    let t1 = w.intent(intent(1)).unwrap();
    assert_eq!(
        refused(w.intent(intent(1))),
        Violation::DuplicateIntent(OpId(1))
    );
    assert_eq!(
        refused(w.done_without_intent(OpId(1), failed())),
        Violation::TokenRequired(OpId(1))
    );
    assert_eq!(
        refused(w.commit(FileTime(1), 0)),
        Violation::MissingDone(OpId(1))
    );
    w.done(t1, ItemOutcome::Done).unwrap();
    assert!(w.resume_intent(OpId(1)).is_none());
    assert_eq!(
        refused(w.done_without_intent(OpId(1), ItemOutcome::Vanished)),
        Violation::DuplicateDone(OpId(1))
    );
    assert_eq!(
        refused(w.intent(intent(1))),
        Violation::DuplicateIntent(OpId(1))
    );

    // A token from another writer is refused.
    let other_dir = TempDir::new("refuse-other");
    let mut other = started(&other_dir, 2);
    let foreign = other.intent(intent(2)).unwrap();
    assert_eq!(
        refused(w.done(foreign, ItemOutcome::Done)),
        Violation::ForeignToken(OpId(2))
    );

    // Undo and expiry rules.
    assert_eq!(
        refused(w.undo_intent(OpId(2))),
        Violation::UndoNotApplicable(OpId(2))
    );
    assert_eq!(
        refused(w.undo_done_without_intent(OpId(1), UndoOutcome::Restored)),
        Violation::UndoDoneWithoutIntent(OpId(1))
    );
    assert_eq!(
        refused(w.expire(Expire {
            at: FileTime(1),
            op: OpId(1),
            class: RetentionClass::Quarantine,
            bytes: 1
        })),
        Violation::ExpireBeforeFinish(OpId(1))
    );
    assert_eq!(
        refused(w.reconcile(Reconcile {
            at: FileTime(1),
            op: OpId(1),
            result: ReconcileResult::StillPending
        })),
        Violation::NotPending(OpId(1))
    );

    // Nothing refused reached the file: it reads back as the writer's state.
    let len = w.len();
    w.sync().unwrap();
    let read = read(&dir.journal()).unwrap();
    assert_eq!(read.valid_len, len);
    assert_eq!(&read.state, w.state());
    assert!(!w.is_poisoned());
}

#[test]
fn undo_and_reconcile_rules() {
    let dir = TempDir::new("undo");
    let mut w = started(&dir, 3);
    let t1 = w.intent(intent(1)).unwrap();
    w.done(t1, ItemOutcome::Done).unwrap();
    let t2 = w.intent(intent(2)).unwrap();
    w.done(t2, pending_reboot(2)).unwrap();
    let t3 = w.intent(intent(3)).unwrap();
    w.done(t3, ItemOutcome::HeldRetry).unwrap();
    w.commit(FileTime(1), 0).unwrap();
    assert_eq!(
        w.state().pending_reboot().map(|s| s.op).collect::<Vec<_>>(),
        [OpId(2)]
    );
    assert_eq!(
        w.state().held_retry().map(|s| s.op).collect::<Vec<_>>(),
        [OpId(3)]
    );

    // An undo restarted after a crash: a second undo_intent while one is open.
    let first = w.undo_intent(OpId(1)).unwrap();
    assert!(w.resume_undo(OpId(1)).is_some());
    assert_eq!(
        refused(w.undo_done_without_intent(OpId(1), UndoOutcome::NothingToUndo)),
        Violation::TokenRequired(OpId(1))
    );
    let second = w.undo_intent(OpId(1)).unwrap();
    assert_eq!(w.state().undo_in_progress().count(), 1);
    w.undo_done(first, UndoOutcome::Restored).unwrap();
    assert_eq!(
        refused(w.undo_done(second, UndoOutcome::Restored)),
        Violation::UndoNotInProgress(OpId(1))
    );
    assert_eq!(
        refused(w.undo_intent(OpId(1))),
        Violation::UndoSettled(OpId(1))
    );
    assert!(w.resume_undo(OpId(1)).is_none());

    // A conflict found before the intent, then a retry that fails, then one more retry.
    w.undo_conflict_without_intent(OpId(2), UndoConflict::BackupMissing, String::new())
        .unwrap();
    let retry = w.undo_intent(OpId(2)).unwrap();
    w.undo_done(
        retry,
        UndoOutcome::Failed {
            code: FailCode::Os,
            os_error: Some(32),
            detail: String::new(),
        },
    )
    .unwrap();
    let again = w.undo_intent(OpId(2)).unwrap();
    w.undo_conflict(again, UndoConflict::DestinationExists, "taken".into())
        .unwrap();
    assert_eq!(w.state().op(OpId(2)).unwrap().undo_attempts, 2);

    // Reconcile: Retried is for held items, the rest for boot moves.
    let rec = |op, result| Reconcile {
        at: FileTime(2),
        op: OpId(op),
        result,
    };
    assert_eq!(
        refused(w.reconcile(rec(
            2,
            ReconcileResult::Retried {
                outcome: ItemOutcome::Done
            }
        ))),
        Violation::ReconcileMismatch(OpId(2))
    );
    assert_eq!(
        refused(w.reconcile(rec(3, ReconcileResult::Completed))),
        Violation::ReconcileMismatch(OpId(3))
    );
    w.reconcile(rec(2, ReconcileResult::StillPending)).unwrap();
    w.reconcile(rec(2, ReconcileResult::Completed)).unwrap();
    assert_eq!(
        refused(w.reconcile(rec(2, ReconcileResult::StillPending))),
        Violation::NotPending(OpId(2))
    );
    w.reconcile(rec(
        3,
        ReconcileResult::Retried {
            outcome: pending_reboot(3),
        },
    ))
    .unwrap();
    assert_eq!(
        w.state().pending_reboot().map(|s| s.op).collect::<Vec<_>>(),
        [OpId(3)]
    );

    let exp = Expire {
        at: FileTime(3),
        op: OpId(1),
        class: RetentionClass::Backup,
        bytes: 1,
    };
    w.expire(exp).unwrap();
    assert_eq!(refused(w.expire(exp)), Violation::DuplicateExpire(OpId(1)));

    // Nothing of the run after the commit.
    assert_eq!(
        refused(w.abort(FileTime(4), AbortReason::Cancelled, String::new())),
        Violation::AfterFinish("aborted")
    );
    drop(w);
    let read = read(&dir.journal()).unwrap();
    assert_eq!(read.state.op(OpId(2)).unwrap().reconciles.len(), 2);
}

#[test]
fn abort_ends_a_run_and_keeps_open_intents_for_recovery() {
    let dir = TempDir::new("abort");
    let mut w = started(&dir, 3);
    let t1 = w.intent(intent(1)).unwrap();
    w.done(t1, ItemOutcome::Done).unwrap();
    let _held = w.intent(intent(2)).unwrap();
    w.abort(
        FileTime(5),
        AbortReason::BackupWriteFailed,
        "disk full".into(),
    )
    .unwrap();
    drop(w);
    let read = read(&dir.journal()).unwrap();
    assert_eq!(read.state.phase(), Phase::Aborted);
    assert_eq!(
        read.state.aborted().unwrap().reason,
        AbortReason::BackupWriteFailed
    );
    assert_eq!(read.state.groups_closed(), 1);
    assert_eq!(
        read.state.open_intents().map(|s| s.op).collect::<Vec<_>>(),
        [OpId(2)]
    );
    // Once the run ended, no done can be added; the undo of the open intent can.
    let mut w = JournalWriter::open_append(&dir.journal()).unwrap();
    assert!(w.resume_intent(OpId(2)).is_none());
    assert_eq!(
        refused(w.done_without_intent(OpId(3), ItemOutcome::Vanished)),
        Violation::AfterFinish("done")
    );
    let undo = w.undo_intent(OpId(2)).unwrap();
    w.undo_done(undo, UndoOutcome::NothingToUndo).unwrap();
}

#[test]
fn reader_refuses_rule_breaks() {
    let hdr = |items| body(Record::Header(header(items)));
    let v = |n| body(Record::Validated(validated(n)));
    let i = |n| body(Record::Intent(intent(n)));
    let d = |n, outcome| {
        body(Record::Done(purge_model::exec::journal::Done {
            op: OpId(n),
            item: item(n),
            outcome,
        }))
    };
    let ok = |bodies: &[String]| parse(&chained(bodies)).unwrap();

    ok(&[hdr(2), v(1), v(2), i(1), d(1, ItemOutcome::Done)]);
    // Duplicate done.
    assert_eq!(
        corrupt(parse(&chained(&[
            hdr(2),
            v(1),
            v(2),
            i(1),
            d(1, ItemOutcome::Done),
            d(1, ItemOutcome::Done)
        ]))),
        (6, Corruption::Rule(Violation::DuplicateDone(OpId(1))))
    );
    // Done without intent, with an outcome that needs one.
    assert_eq!(
        corrupt(parse(&chained(&[
            hdr(2),
            v(1),
            v(2),
            d(1, ItemOutcome::Done)
        ]))),
        (4, Corruption::Rule(Violation::DoneWithoutIntent(OpId(1))))
    );
    ok(&[
        hdr(2),
        v(1),
        v(2),
        d(1, ItemOutcome::Vanished),
        d(
            2,
            ItemOutcome::Skipped {
                reason: SkipReason::NoVerifiedBackup,
            },
        ),
    ]);
    // Unknown record kind, and records that do not parse.
    for bad in [
        r#"{"rec":"finished"}"#,
        r#"{"rec":"Intent","op":1}"#,
        r#"{"rec":"done","op":1,"item":"c-001"}"#,
        r#"{"op":1,"rec":"group_end"}"#,
    ] {
        let (line, kind) = corrupt(parse(&chained(&[hdr(2), bad.to_owned()])));
        assert_eq!(line, 2, "{bad}");
        assert!(matches!(kind, Corruption::Json(_)), "{bad}: {kind:?}");
    }
    // The header first, and only once; another schema id does not parse.
    assert_eq!(
        corrupt(parse(&chained(&[v(1)]))),
        (1, Corruption::Rule(Violation::HeaderNotFirst))
    );
    assert_eq!(
        corrupt(parse(&chained(&[hdr(1), hdr(1)]))),
        (2, Corruption::Rule(Violation::DuplicateHeader))
    );
    let other_schema = hdr(1).replace("purge.journal/1", "purge.journal/2");
    assert!(matches!(
        corrupt(parse(&chained(&[other_schema]))),
        (1, Corruption::Json(_))
    ));
    // More than 64 intents without a group end.
    let mut bodies = vec![hdr(65)];
    bodies.extend((1..=65).map(v));
    bodies.extend((1..=65).map(i));
    assert_eq!(
        corrupt(parse(&chained(&bodies))),
        (131, Corruption::Rule(Violation::GroupFull(OpId(65))))
    );
    // A group end that miscounts.
    let ge = |group, ops| {
        body(Record::GroupEnd(purge_model::exec::journal::GroupEnd {
            group,
            ops,
        }))
    };
    assert!(matches!(
        corrupt(parse(&chained(&[hdr(1), v(1), i(1), ge(1, 2)]))),
        (4, Corruption::Rule(Violation::GroupMismatch { .. }))
    ));
    assert_eq!(
        corrupt(parse(&chained(&[hdr(1), v(1), ge(1, 1)]))),
        (3, Corruption::Rule(Violation::EmptyGroup))
    );
    // A count of 0 is not a group end at all.
    assert!(matches!(
        corrupt(parse(&chained(&[hdr(1), v(1), ge(1, 0)]))),
        (3, Corruption::Json(_))
    ));
    // A commit with an open group or wrong counts.
    let commit = |counts| {
        body(Record::Commit(purge_model::exec::journal::Commit {
            at: FileTime(1),
            counts,
            backup_bytes: 0,
        }))
    };
    let one_done = OutcomeCounts {
        done: 1,
        ..OutcomeCounts::default()
    };
    assert_eq!(
        corrupt(parse(&chained(&[
            hdr(1),
            v(1),
            i(1),
            d(1, ItemOutcome::Done),
            commit(one_done)
        ]))),
        (5, Corruption::Rule(Violation::OpenGroup))
    );
    assert_eq!(
        corrupt(parse(&chained(&[
            hdr(1),
            v(1),
            i(1),
            d(1, ItemOutcome::Done),
            ge(1, 1),
            commit(OutcomeCounts::default())
        ]))),
        (6, Corruption::Rule(Violation::CountsMismatch))
    );
    ok(&[
        hdr(1),
        v(1),
        i(1),
        d(1, ItemOutcome::Done),
        ge(1, 1),
        commit(one_done),
    ]);
}

/// Cutting a journal at every byte gives the state of its complete lines, or `Empty` before the header
/// line is complete. Never a panic, never a refusal.
#[test]
fn truncation_at_every_byte_gives_the_valid_prefix() {
    let dir = TempDir::new("truncate");
    let bytes = sample_journal(&dir);
    let full = parse(&bytes).unwrap();
    let ends: Vec<usize> = bytes
        .iter()
        .enumerate()
        .filter(|&(_, &b)| b == b'\n')
        .map(|(i, _)| i + 1)
        .collect();
    for cut in 0..=bytes.len() {
        let complete = ends.iter().filter(|&&end| end <= cut).count();
        let valid = if complete == 0 { 0 } else { ends[complete - 1] };
        match parse(&bytes[..cut]) {
            Ok(read) => {
                assert!(complete > 0, "cut {cut}");
                assert_eq!(read.records, full.records[..complete], "cut {cut}");
                assert_eq!(read.valid_len, valid as u64);
                assert_eq!(read.torn_tail, (cut - valid) as u64);
                let expect = parse(&bytes[..valid]).unwrap();
                assert_eq!(read.state, expect.state);
                assert_eq!(read.head, expect.head);
            }
            Err(JournalError::Empty { torn_bytes }) => {
                assert_eq!(complete, 0, "cut {cut}");
                assert_eq!(torn_bytes, cut as u64);
            }
            Err(e) => panic!("cut {cut}: {e}"),
        }
    }
}

/// A flipped bit anywhere in a complete line refuses the journal. Only the last newline is ambiguous: a
/// line without its `\n` reads as a torn tail.
#[test]
fn a_flipped_bit_anywhere_is_refused() {
    let dir = TempDir::new("flip");
    let bytes = sample_journal(&dir);
    let full = parse(&bytes).unwrap();
    for at in 0..bytes.len() {
        for bit in [0x01u8, 0x20, 0x80] {
            let mut changed = bytes.clone();
            changed[at] ^= bit;
            let result = parse(&changed);
            if at == bytes.len() - 1 {
                let read = result.unwrap();
                assert_eq!(read.records, full.records[..full.records.len() - 1]);
                assert!(read.torn_tail > 0);
            } else {
                assert!(
                    matches!(result, Err(JournalError::Corrupt { .. })),
                    "byte {at} ^ {bit:#x}: {result:?}"
                );
            }
        }
    }
}

#[test]
fn the_hash_chain_detects_tampering() {
    let dir = TempDir::new("chain");
    let bytes = sample_journal(&dir);
    let all = lines(&bytes);
    let join = |parts: &[Vec<u8>]| parts.concat();

    // A line removed, duplicated or two lines swapped: refused at the first line out of place.
    let mut removed = all.clone();
    removed.remove(5);
    assert_eq!(
        corrupt(parse(&join(&removed))),
        (6, Corruption::ChainMismatch)
    );
    let mut doubled = all.clone();
    doubled.insert(5, all[5].clone());
    assert_eq!(
        corrupt(parse(&join(&doubled))),
        (7, Corruption::ChainMismatch)
    );
    let mut swapped = all.clone();
    swapped.swap(6, 7);
    assert_eq!(
        corrupt(parse(&join(&swapped))),
        (7, Corruption::ChainMismatch)
    );

    // An edited record keeping its old chain value is refused on its own line; one re-chained alone is
    // refused on the next line.
    let target = all
        .iter()
        .position(|l| l.starts_with(br#"{"rec":"intent""#))
        .unwrap();
    // A change the rules do not look at, so only the chain can catch it.
    let edited_text = String::from_utf8(all[target].clone())
        .unwrap()
        .replace(r#""volume_serial":7"#, r#""volume_serial":8"#);
    assert_ne!(edited_text.as_bytes(), &all[target][..]);
    let mut edited = all.clone();
    edited[target] = edited_text.clone().into_bytes();
    assert_eq!(
        corrupt(parse(&join(&edited))),
        (target as u64 + 1, Corruption::ChainMismatch)
    );
    let prefix = parse(&join(&all[..target])).unwrap();
    let edited_body = format!("{}}}", &edited_text[..edited_text.len() - 1 - SUFFIX_LEN]);
    let (rechained, _) = frame(&prefix.head.0, &edited_body);
    let mut rechained_all = all.clone();
    rechained_all[target] = rechained;
    assert_eq!(
        corrupt(parse(&join(&rechained_all))),
        (target as u64 + 2, Corruption::ChainMismatch)
    );

    // Other line endings or a missing or malformed chain field are not a journal line.
    let crlf: Vec<u8> = String::from_utf8(bytes.clone())
        .unwrap()
        .replace('\n', "\r\n")
        .into_bytes();
    assert_eq!(corrupt(parse(&crlf)), (1, Corruption::NotFramed));
    let upper = String::from_utf8(all[0].clone()).unwrap();
    let digits_at = upper.len() - 1 - 2 - 64;
    let upper = format!(
        "{}{}",
        &upper[..digits_at],
        upper[digits_at..].to_uppercase()
    );
    assert_eq!(corrupt(parse(upper.as_bytes())), (1, Corruption::NotFramed));
    let plain = format!("{}\n", body(Record::Header(header(1))));
    assert_eq!(corrupt(parse(plain.as_bytes())), (1, Corruption::NotFramed));
    assert_eq!(corrupt(parse(b"\n")), (1, Corruption::NotFramed));
}

#[test]
fn open_append_cuts_a_torn_tail_and_continues() {
    let dir = TempDir::new("torn");
    let mut w = started(&dir, 2);
    let _lost = w.intent(intent(1)).unwrap();
    let valid = w.len();
    drop(w);
    // A crash in the middle of the next line.
    let mut bytes = std::fs::read(dir.journal()).unwrap();
    bytes.extend_from_slice(br#"{"rec":"done","op":1,"ite"#);
    bytes.extend_from_slice(&[0, 0, 0]);
    std::fs::write(dir.journal(), &bytes).unwrap();

    let seen = read(&dir.journal()).unwrap();
    assert_eq!((seen.valid_len, seen.torn_tail), (valid, 28));
    let mut w = JournalWriter::open_append(&dir.journal()).unwrap();
    assert_eq!(w.discarded_tail(), 28);
    assert_eq!(std::fs::metadata(dir.journal()).unwrap().len(), valid);
    let token = w.resume_intent(OpId(1)).unwrap();
    assert!(w.resume_intent(OpId(2)).is_none());
    w.done(token, ItemOutcome::Done).unwrap();
    w.done_without_intent(
        OpId(2),
        ItemOutcome::Skipped {
            reason: SkipReason::NotAttempted,
        },
    )
    .unwrap();
    w.commit(FileTime(9), 0).unwrap();
    drop(w);
    let read = read(&dir.journal()).unwrap();
    assert_eq!(read.torn_tail, 0);
    assert_eq!(read.state.phase(), Phase::Committed);
}

#[test]
fn a_corrupt_journal_is_refused_and_left_untouched() {
    let dir = TempDir::new("corrupt");
    let mut bytes = sample_journal(&dir);
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    bytes.extend_from_slice(b"{\"rec\":\"und");
    std::fs::write(dir.journal(), &bytes).unwrap();

    assert!(matches!(
        read(&dir.journal()),
        Err(JournalError::Corrupt { .. })
    ));
    assert!(matches!(
        JournalWriter::open_append(&dir.journal()),
        Err(JournalError::Corrupt { .. })
    ));
    // Not even the torn tail was cut.
    assert_eq!(std::fs::read(dir.journal()).unwrap(), bytes);
}

#[test]
fn a_journal_without_a_complete_header_is_empty() {
    let dir = TempDir::new("empty");
    std::fs::write(dir.journal(), b"").unwrap();
    assert!(matches!(
        read(&dir.journal()),
        Err(JournalError::Empty { torn_bytes: 0 })
    ));
    let partial = &body(Record::Header(header(1)))[..40];
    std::fs::write(dir.journal(), partial).unwrap();
    assert!(matches!(
        JournalWriter::open_append(&dir.journal()),
        Err(JournalError::Empty { torn_bytes: 40 })
    ));
    assert_eq!(std::fs::read(dir.journal()).unwrap(), partial.as_bytes());
}

#[test]
fn create_never_adopts_an_existing_file_and_paths_must_be_plain_files() {
    let dir = TempDir::new("create");
    std::fs::write(dir.journal(), b"planted").unwrap();
    assert!(matches!(
        JournalWriter::create(&dir.journal(), SDDL, header(1)),
        Err(JournalError::Fs { .. })
    ));
    assert_eq!(std::fs::read(dir.journal()).unwrap(), b"planted");

    // A directory is not a journal.
    let sub = dir.0.join("sub");
    std::fs::create_dir(&sub).unwrap();
    assert!(read(&sub).is_err());
    assert!(JournalWriter::open_append(&sub).is_err());

    // A hard link to a journal is refused.
    let real = TempDir::new("create-real");
    drop(started(&real, 1));
    let link = dir.0.join("linked.jsonl");
    std::fs::hard_link(real.journal(), &link).unwrap();
    assert!(matches!(read(&link), Err(JournalError::NotPlainFile)));
    assert!(matches!(
        JournalWriter::open_append(&link),
        Err(JournalError::NotPlainFile)
    ));
    assert!(matches!(
        read(&real.journal()),
        Err(JournalError::NotPlainFile)
    ));
}

#[test]
fn sha256_vectors() {
    let hex = |h: purge_model::exec::op::Sha256Hex| h.to_string();
    assert_eq!(
        hex(sha256_bytes(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(sha256_bytes(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(sha256_bytes(b"test")),
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    );
    let million = vec![b'a'; 1_000_000];
    let expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
    let (h, n) = sha256_reader(&mut std::io::Cursor::new(&million)).unwrap();
    assert_eq!((hex(h), n), (expected.to_owned(), 1_000_000));

    let dir = TempDir::new("sha");
    let file = dir.0.join("big.bin");
    std::fs::write(&file, &million).unwrap();
    let (h, n) = sha256_file(&file).unwrap();
    assert_eq!((hex(h), n), (expected.to_owned(), 1_000_000));
    let empty = dir.0.join("empty.bin");
    std::fs::write(&empty, b"").unwrap();
    assert_eq!(sha256_file(&empty).unwrap(), (sha256_bytes(b""), 0));
    assert!(sha256_file(&dir.0).is_err());
    assert_eq!(
        sha256_file(&dir.0.join("missing")).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
}

#[test]
fn verify_backup_catches_tampering() {
    let dir = TempDir::new("backup");
    std::fs::create_dir(dir.0.join("reg")).unwrap();
    let content = br#"{"schema":"purge.regbackup/1","x":[1,2,3]}"#;
    let path = dir.0.join(r"reg\000002.regbackup.json");
    std::fs::write(&path, content).unwrap();
    let backup = BackupRef {
        path: r"reg\000002.regbackup.json".into(),
        sha256: sha256_bytes(content),
        bytes: content.len() as u64,
    };
    assert_eq!(verify_backup(&dir.0, &backup), Ok(()));

    // One byte changed, same size.
    let mut tampered = content.to_vec();
    tampered[20] ^= 0x01;
    std::fs::write(&path, &tampered).unwrap();
    let err = verify_backup(&dir.0, &backup).unwrap_err();
    assert!(matches!(err, BackupCheckError::HashMismatch { .. }));
    assert_eq!(err.conflict(), UndoConflict::BackupTampered);

    std::fs::write(&path, &content[..10]).unwrap();
    assert_eq!(
        verify_backup(&dir.0, &backup),
        Err(BackupCheckError::SizeMismatch {
            expected: content.len() as u64,
            actual: 10
        })
    );

    std::fs::remove_file(&path).unwrap();
    let err = verify_backup(&dir.0, &backup).unwrap_err();
    assert_eq!(err, BackupCheckError::Missing);
    assert_eq!(err.conflict(), UndoConflict::BackupMissing);

    let outside = BackupRef {
        path: r"..\reg\000002.regbackup.json".into(),
        ..backup.clone()
    };
    assert_eq!(
        verify_backup(&dir.0, &outside),
        Err(BackupCheckError::NotSessionRelative)
    );
    let a_dir = BackupRef {
        path: "reg".into(),
        ..backup
    };
    assert!(matches!(
        verify_backup(&dir.0, &a_dir),
        Err(BackupCheckError::Unreadable(_))
    ));
}

/// Set only in a child process of the test binary: the directory the child writes its journal in.
const CHILD_DIR: &str = "PURGE_TEST_JOURNAL_CHILD_DIR";

/// The child half of the crash tests: a three-item run from header to commit. Does nothing when run as
/// an ordinary test.
#[test]
fn child_journal_scenario() {
    let Some(dir) = std::env::var_os(CHILD_DIR) else {
        return;
    };
    let path = PathBuf::from(dir).join(JOURNAL_FILE_NAME);
    let started = std::time::Instant::now();
    let mut w = JournalWriter::create(&path, SDDL, header(3)).unwrap();
    for n in 1..=3 {
        w.validated(validated(n)).unwrap();
    }
    for n in 1..=3 {
        let token = w.intent(intent(n)).unwrap();
        w.done(token, ItemOutcome::Done).unwrap();
    }
    w.commit(FileTime(1), 0).unwrap();
    // Read by the pause test.
    std::fs::write(
        path.with_file_name("elapsed-ms"),
        started.elapsed().as_millis().to_string(),
    )
    .unwrap();
}

#[cfg(feature = "fault-inject")]
mod crash {
    use super::*;
    use crate::fault;

    /// The exit code of a process ended by `std::process::abort` on Windows (`__fastfail`).
    const ABORT_CODE: i32 = 0xC000_0409_u32 as i32;

    /// Runs [`child_journal_scenario`] with `env`; returns the exit code and the journal it left.
    fn run(dir: &TempDir, env: &[(&str, &str)]) -> (Option<i32>, PathBuf) {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "journal::tests::child_journal_scenario",
                "--test-threads=1",
            ])
            .env(CHILD_DIR, &dir.0)
            .env_remove(fault::ENV_AT)
            .env_remove(fault::ENV_PAUSE)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        for (key, value) in env {
            command.env(key, value);
        }
        (command.status().unwrap().code(), dir.journal())
    }

    fn status(read: &JournalRead, n: u32) -> OpStatus<'_> {
        read.state.op(OpId(n)).unwrap().status()
    }

    #[test]
    fn a_crash_at_each_journal_point_leaves_a_readable_journal() {
        let dir = TempDir::new("crash-header");
        let (code, path) = run(&dir, &[(fault::ENV_AT, fault::JOURNAL_HEADER)]);
        assert_eq!(code, Some(ABORT_CODE));
        let header_only = read(&path).unwrap();
        assert_eq!(header_only.records.len(), 1);
        assert_eq!(header_only.state.phase(), Phase::Validating);

        let dir = TempDir::new("crash-intent");
        let (code, path) = run(&dir, &[(fault::ENV_AT, "intent.flushed:2")]);
        assert_eq!(code, Some(ABORT_CODE));
        let seen = read(&path).unwrap();
        assert_eq!(status(&seen, 1), OpStatus::Done(&ItemOutcome::Done));
        assert_eq!(status(&seen, 2), OpStatus::IntentOnly);
        assert_eq!(status(&seen, 3), OpStatus::Validated);
        // Recovery finishes the run: the probe decided op 2 was done, op 3 never started.
        let mut w = JournalWriter::open_append(&path).unwrap();
        let token = w.resume_intent(OpId(2)).unwrap();
        w.done(token, ItemOutcome::Done).unwrap();
        w.done_without_intent(
            OpId(3),
            ItemOutcome::Skipped {
                reason: SkipReason::NotAttempted,
            },
        )
        .unwrap();
        w.commit(FileTime(2), 0).unwrap();
        drop(w);
        assert_eq!(read(&path).unwrap().state.phase(), Phase::Committed);

        let dir = TempDir::new("crash-done");
        let (code, path) = run(&dir, &[(fault::ENV_AT, fault::DONE_BEFORE)]);
        assert_eq!(code, Some(ABORT_CODE));
        let seen = read(&path).unwrap();
        assert_eq!(status(&seen, 1), OpStatus::IntentOnly);
        assert_eq!(seen.state.open_group_intents(), 1);

        for point in [fault::GROUP_END, fault::COMMIT_BEFORE] {
            let dir = TempDir::new("crash-end");
            let (code, path) = run(&dir, &[(fault::ENV_AT, point)]);
            assert_eq!(code, Some(ABORT_CODE), "{point}");
            let seen = read(&path).unwrap();
            assert_eq!(seen.state.phase(), Phase::Running, "{point}");
            assert_eq!(seen.state.groups_closed(), 1, "{point}");
            assert_eq!(seen.state.counts().done, 3, "{point}");
            assert!(seen.state.commit().is_none());
            // Only the commit is missing.
            let mut w = JournalWriter::open_append(&path).unwrap();
            w.commit(FileTime(2), 0).unwrap();
        }

        // Without a fault the child runs to the end.
        let dir = TempDir::new("crash-none");
        let (code, path) = run(&dir, &[]);
        assert_eq!(code, Some(0));
        assert_eq!(read(&path).unwrap().state.phase(), Phase::Committed);
    }

    #[test]
    fn a_pause_holds_the_writer_after_each_flushed_intent() {
        let dir = TempDir::new("pause");
        let (code, path) = run(&dir, &[(fault::ENV_PAUSE, "intent.flushed:150")]);
        assert_eq!(code, Some(0));
        let elapsed: u64 = std::fs::read_to_string(path.with_file_name("elapsed-ms"))
            .unwrap()
            .parse()
            .unwrap();
        assert!(elapsed >= 450, "{elapsed} ms");
    }
}
