//! Tests of the journal: format, rules, torn tail, corruption, hash chain, groups, hashing and fault
//! points. Every journal lives in a session of a relaxed test store under a temp directory the test
//! creates and removes.

use std::io::Write;
use std::path::{Path, PathBuf};

use purge_model::exec::journal::{
    AbortReason, Expire, FileFacts, GateExemptions, Header, Intent, ItemFacts, JournalSchema,
    Reconcile, ReconcileResult, Record, RestorePointPolicy, RetryIntent, RunSettings, UndoConflict,
    UndoOutcome, Validated,
};
use purge_model::exec::op::{
    BackupRef, BootMovePair, ExecOp, FailCode, FileIdHex, Inverse, ItemOutcome, OpId,
    OutcomeCounts, Sha256Hex, SkipReason,
};
use purge_model::exec::session::{JournalMark, RetentionClass, SessionId};
use purge_model::{CandidateId, FileTime, ScanMode, Target};
use purge_win::fs_write::FsError;

use super::frame::{CHAIN_SEED, SUFFIX_LEN, frame};
use super::*;
use crate::storage::{IntegrityFailure, SessionDir, StorageError, StorageRoots};

/// A relaxed test store under a fresh temp directory with one session; everything is removed on drop.
struct TempDir {
    /// The session the journal belongs to. Declared first, so its handles close before the directory
    /// is removed.
    session: SessionDir,
    roots: StorageRoots,
    scratch: Scratch,
}

/// A fresh directory under the temp dir, removed on drop.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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
        let scratch = Scratch(dir);
        let roots = StorageRoots::install_relaxed(&scratch.0.join("data")).unwrap();
        let session = roots.create_session().unwrap();
        TempDir {
            session,
            roots,
            scratch,
        }
    }

    /// The journal's path, for tests that plant or tamper with bytes; the code never opens it by path.
    fn journal(&self) -> PathBuf {
        self.session.path().join(JOURNAL_FILE_NAME)
    }

    /// A header of this session with `items` items.
    fn header(&self, items: u32) -> Header {
        Header {
            session: self.session.id().clone(),
            ..header(items)
        }
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
        program_roots: Vec::new(),
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
            parent: None,
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
    let mut w = JournalWriter::create(&dir.session, dir.header(items)).unwrap();
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

    let mut w = JournalWriter::open_append(&dir.session).unwrap();
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
    let read = read(&dir.session).unwrap();
    assert_eq!(read.torn_tail, 0);
    assert_eq!(read.valid_len, bytes.len() as u64);
    assert_eq!(read.records.len(), 1 + 4 + 3 + 4 + 1 + 1 + 5);
    assert!(matches!(read.records[0], Record::Header(_)));
    assert_eq!(parse(&bytes).unwrap(), read);

    let state = &read.state;
    assert_eq!(state.phase(), Phase::Committed);
    assert_eq!(state.session(), dir.session.id());
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
    let reopened = JournalWriter::open_append(&dir.session).unwrap();
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
    let seen = read(&dir.session).unwrap();
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
        JournalWriter::open_append(&dir.session),
        Err(JournalError::Store(StorageError::Io {
            source: FsError::SharingViolation,
            ..
        }))
    ));
}

/// S6: the `done` of a registered boot-time move is the only record of the pair, so it is flushed
/// before `done` returns; other outcomes wait for the next flush.
#[test]
fn a_pending_reboot_done_is_flushed_at_once() {
    let dir = TempDir::new("reboot-flush");
    let mut w = started(&dir, 3);
    let t1 = w.intent(intent(1)).unwrap();
    let t2 = w.intent(intent(2)).unwrap();
    let t3 = w.intent(intent(3)).unwrap();
    let before = w.syncs();
    w.done(t1, ItemOutcome::Done).unwrap();
    w.done(t2, ItemOutcome::HeldRetry).unwrap();
    assert_eq!(w.syncs(), before);
    w.done(t3, pending_reboot(3)).unwrap();
    assert_eq!(w.syncs(), before + 1);
    // What a second reader sees now is what survives a power loss: the pair is there.
    let seen = read(&dir.session).unwrap();
    assert_eq!(
        seen.state.op(OpId(3)).unwrap().status(),
        OpStatus::Done(&pending_reboot(3))
    );
}

/// S7: a token is proof that one intent is open; nobody gets a second one for the same op.
#[test]
fn resume_hands_out_one_token_per_open_intent_and_only_after_open_append() {
    let dir = TempDir::new("resume-once");
    let mut w = started(&dir, 3);
    let t1 = w.intent(intent(1)).unwrap();
    // The writer that wrote the intent already handed out its token.
    assert!(w.resume_intent(OpId(1)).is_none());
    w.done(t1, ItemOutcome::Done).unwrap();
    let _lost = w.intent(intent(2)).unwrap();
    let t3 = w.intent(intent(3)).unwrap();
    w.done(t3, ItemOutcome::Done).unwrap();
    drop(w);

    // After a crash: one token for the op left open, once.
    let mut w = JournalWriter::open_append(&dir.session).unwrap();
    assert!(w.resume_intent(OpId(1)).is_none());
    assert!(w.resume_intent(OpId(3)).is_none());
    let token = w.resume_intent(OpId(2)).unwrap();
    assert!(w.resume_intent(OpId(2)).is_none());
    w.done(token, failed()).unwrap();
    w.commit(FileTime(1), 0).unwrap();

    // The same for an undo left in progress.
    let u1 = w.undo_intent(OpId(1)).unwrap();
    assert!(w.resume_undo(OpId(1)).is_none());
    drop((u1, w));
    let mut w = JournalWriter::open_append(&dir.session).unwrap();
    let u1 = w.resume_undo(OpId(1)).unwrap();
    assert!(w.resume_undo(OpId(1)).is_none());
    assert!(w.resume_undo(OpId(3)).is_none());
    w.undo_done(u1, UndoOutcome::Restored).unwrap();
}

/// S7: once expiry deleted an op's data, no undo of it starts; an expiry waits for an undo in
/// progress. The reader applies the same rules.
#[test]
fn undo_is_refused_after_expiry_and_expiry_during_an_undo() {
    let dir = TempDir::new("expired-undo");
    let mut w = started(&dir, 2);
    for n in 1..=2 {
        let t = w.intent(intent(n)).unwrap();
        w.done(t, ItemOutcome::Done).unwrap();
    }
    w.commit(FileTime(1), 0).unwrap();
    let expire = |n, class| Expire {
        at: FileTime(2),
        op: OpId(n),
        class,
        bytes: 1,
    };
    w.expire(expire(1, RetentionClass::Quarantine)).unwrap();
    assert_eq!(
        refused(w.undo_intent(OpId(1))),
        Violation::UndoAfterExpire(OpId(1))
    );
    // What the undo package records instead.
    w.undo_conflict_without_intent(OpId(1), UndoConflict::BackupMissing, "expired".into())
        .unwrap();

    let u2 = w.undo_intent(OpId(2)).unwrap();
    assert_eq!(
        refused(w.expire(expire(2, RetentionClass::Quarantine))),
        Violation::ExpireDuringUndo(OpId(2))
    );
    w.undo_done(u2, UndoOutcome::Restored).unwrap();
    w.expire(expire(2, RetentionClass::Backup)).unwrap();
    drop(w);
    let seen = read(&dir.session).unwrap();
    assert_eq!(
        seen.state.op(OpId(1)).unwrap().undo,
        UndoState::Conflict(UndoConflict::BackupMissing)
    );

    // A journal that holds an undo after an expiry is refused by the reader.
    let bodies: Vec<String> = [
        Record::Header(header(1)),
        Record::Validated(validated(1)),
        Record::Intent(intent(1)),
        Record::Done(purge_model::exec::journal::Done {
            op: OpId(1),
            item: item(1),
            outcome: ItemOutcome::Done,
            detail: String::new(),
        }),
        Record::GroupEnd(purge_model::exec::journal::GroupEnd {
            group: 1,
            ops: 1,
            registry_flushed: true,
        }),
        Record::Commit(purge_model::exec::journal::Commit {
            at: FileTime(1),
            counts: OutcomeCounts {
                done: 1,
                ..OutcomeCounts::default()
            },
            backup_bytes: 0,
        }),
        Record::Expire(expire(1, RetentionClass::Backup)),
        Record::UndoIntent(purge_model::exec::journal::UndoIntent { op: OpId(1) }),
    ]
    .into_iter()
    .map(body)
    .collect();
    assert_eq!(
        corrupt(parse(&chained(&bodies))),
        (8, Corruption::Rule(Violation::UndoAfterExpire(OpId(1))))
    );
}

/// M9: a record whose write fails is not applied, and the writer takes nothing more.
#[test]
fn a_failed_write_poisons_the_writer_and_leaves_the_state_as_the_file() {
    let dir = TempDir::new("poison");
    let mut w = started(&dir, 2);
    let t1 = w.intent(intent(1)).unwrap();
    w.inject_write_failure();
    assert!(matches!(
        w.done(t1, ItemOutcome::Done),
        Err(JournalError::Io { .. })
    ));
    assert!(w.is_poisoned());
    assert_eq!(
        w.state().op(OpId(1)).unwrap().status(),
        OpStatus::IntentOnly
    );
    assert_eq!(w.state().counts(), OutcomeCounts::default());
    assert!(matches!(w.intent(intent(2)), Err(JournalError::Poisoned)));
    let state = w.state().clone();
    drop(w);
    assert_eq!(read(&dir.session).unwrap().state, state);
}

/// S1, M7: the journal is created, read and appended to only through the store, and only as the
/// journal of the session whose directory it is in.
#[test]
fn the_journal_goes_through_the_store_and_belongs_to_its_session() {
    // A header for another session is refused before anything is created.
    let dir = TempDir::new("own-session");
    assert!(matches!(
        JournalWriter::create(&dir.session, header(1)),
        Err(JournalError::WrongSession { .. })
    ));
    assert!(!dir.journal().exists());

    // A journal copied into another session's directory is not that session's journal.
    drop(started(&dir, 1));
    let other = dir.roots.create_session().unwrap();
    std::fs::copy(dir.journal(), other.path().join(JOURNAL_FILE_NAME)).unwrap();
    assert!(matches!(
        read(&other),
        Err(JournalError::WrongSession { header, dir: d })
            if &header == dir.session.id() && &d == other.id()
    ));
    assert!(matches!(
        JournalWriter::open_append(&other),
        Err(JournalError::WrongSession { .. })
    ));

    // The session directory swapped for a junction after it was opened: nothing is written there.
    let dir = TempDir::new("own-junction");
    let elsewhere = dir.scratch.0.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    let real = dir.session.path().to_path_buf();
    std::fs::rename(&real, dir.scratch.0.join("moved")).unwrap();
    let status = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&real)
        .arg(&elsewhere)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(matches!(
        JournalWriter::create(&dir.session, dir.header(1)),
        Err(JournalError::Store(StorageError::Integrity {
            failure: IntegrityFailure::ReparsePoint { .. },
            ..
        }))
    ));
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    assert!(read(&dir.session).is_err());
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

    let read = read(&dir.session).unwrap();
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
    let read = read(&dir.session).unwrap();
    let names: Vec<&str> = read.records.iter().map(Record::name).collect();
    let first_end = names.iter().position(|&n| n == "group_end").unwrap();
    assert!(matches!(&read.records[first_end + 1], Record::Intent(i) if i.op == OpId(65)));
    assert_eq!(read.state.groups_closed(), 2);
}

#[test]
fn writer_refuses_rule_breaks_and_writes_nothing() {
    let dir = TempDir::new("refuse");
    let mut w = JournalWriter::create(&dir.session, dir.header(3)).unwrap();
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
    let read = read(&dir.session).unwrap();
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

    // An undo restarted after a crash: a second undo_intent while one is open. The writer that wrote
    // the first undo_intent hands out no second token for it (S7).
    let first = w.undo_intent(OpId(1)).unwrap();
    assert!(w.resume_undo(OpId(1)).is_none());
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
    let retried_done = rec(
        2,
        ReconcileResult::Retried {
            outcome: ItemOutcome::Done,
        },
    );
    assert_eq!(
        w.state().check(&Record::Reconcile(retried_done.clone())),
        Err(Violation::ReconcileMismatch(OpId(2)))
    );
    // (Changed: the writer refused this with ReconcileMismatch. A `Retried` now ends a retry and needs
    // its token, so the writer refuses it first; the rule above still holds for the reader.)
    assert_eq!(
        refused(w.reconcile(retried_done)),
        Violation::RetryNotInFlight(OpId(2))
    );
    assert_eq!(
        refused(w.retry_intent(OpId(2), FileTime(2)).map(|_| ())),
        Violation::RetryNotHeld(OpId(2))
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
    // (Changed: written with `reconcile` before the retry had its own write-ahead record.)
    let retry = w.retry_intent(OpId(3), FileTime(2)).unwrap();
    w.retried(retry, FileTime(2), pending_reboot(3)).unwrap();
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
    let read = read(&dir.session).unwrap();
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
    let read = read(&dir.session).unwrap();
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
    let mut w = JournalWriter::open_append(&dir.session).unwrap();
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
            detail: String::new(),
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
            registry_flushed: true,
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

    let seen = read(&dir.session).unwrap();
    assert_eq!((seen.valid_len, seen.torn_tail), (valid, 28));
    let mut w = JournalWriter::open_append(&dir.session).unwrap();
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
    let read = read(&dir.session).unwrap();
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
        read(&dir.session),
        Err(JournalError::Corrupt { .. })
    ));
    assert!(matches!(
        JournalWriter::open_append(&dir.session),
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
        read(&dir.session),
        Err(JournalError::Empty { torn_bytes: 0 })
    ));
    let partial = &body(Record::Header(header(1)))[..40];
    std::fs::write(dir.journal(), partial).unwrap();
    assert!(matches!(
        JournalWriter::open_append(&dir.session),
        Err(JournalError::Empty { torn_bytes: 40 })
    ));
    assert_eq!(std::fs::read(dir.journal()).unwrap(), partial.as_bytes());
}

#[test]
fn create_never_adopts_an_existing_file_and_paths_must_be_plain_files() {
    let dir = TempDir::new("create");
    std::fs::write(dir.journal(), b"planted").unwrap();
    assert!(matches!(
        JournalWriter::create(&dir.session, dir.header(1)),
        Err(JournalError::Store(StorageError::Io {
            source: FsError::AlreadyExists,
            ..
        }))
    ));
    assert_eq!(std::fs::read(dir.journal()).unwrap(), b"planted");

    // A directory is not a journal, for the reader or the appender; it is renamed aside.
    for append in [false, true] {
        let dir = TempDir::new("create-dir");
        std::fs::create_dir(dir.journal()).unwrap();
        let result = if append {
            JournalWriter::open_append(&dir.session).map(drop)
        } else {
            read(&dir.session).map(drop)
        };
        assert!(
            matches!(
                result,
                Err(JournalError::Store(StorageError::Integrity {
                    failure: IntegrityFailure::WrongKind {
                        expected_dir: false
                    },
                    renamed_to: Some(_),
                    ..
                }))
            ),
            "{result:?}"
        );
        assert!(!dir.journal().exists());
    }

    // A journal with a second name is refused, and renamed aside.
    let dir = TempDir::new("create-link");
    drop(started(&dir, 1));
    let link = dir.scratch.0.join("linked.jsonl");
    std::fs::hard_link(dir.journal(), &link).unwrap();
    assert!(matches!(
        read(&dir.session),
        Err(JournalError::Store(StorageError::Integrity {
            failure: IntegrityFailure::HardLinked { n_links: 2 },
            ..
        }))
    ));
    assert!(!dir.journal().exists());
    assert!(matches!(
        JournalWriter::open_append(&dir.session),
        Err(JournalError::Store(StorageError::Io {
            source: FsError::NotFound,
            ..
        }))
    ));
}

/// M5: a journal over [`MAX_JOURNAL_BYTES`] is refused before it is read.
#[test]
fn an_oversized_journal_is_refused_unread() {
    let dir = TempDir::new("oversized");
    drop(started(&dir, 1));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.journal())
        .unwrap();
    file.set_len(MAX_JOURNAL_BYTES + 1).unwrap();
    drop(file);
    assert!(matches!(
        read(&dir.session),
        Err(JournalError::TooLarge { bytes, max: MAX_JOURNAL_BYTES }) if bytes == MAX_JOURNAL_BYTES + 1
    ));
    assert!(matches!(
        JournalWriter::open_append(&dir.session),
        Err(JournalError::TooLarge { .. })
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

    // Through a store file, as backups are hashed.
    let dir = TempDir::new("sha");
    let mut file = dir
        .session
        .create_file(r"reg\000001.regbackup.json")
        .unwrap();
    file.write_all(&million).unwrap();
    file.sync().unwrap();
    drop(file);
    let mut file = dir.session.open_file(r"reg\000001.regbackup.json").unwrap();
    let (h, n) = sha256_reader(&mut file).unwrap();
    assert_eq!((hex(h), n), (expected.to_owned(), 1_000_000));
    let mut empty = dir
        .session
        .create_file(r"reg\000002.regbackup.json")
        .unwrap();
    assert_eq!(sha256_reader(&mut empty).unwrap(), (sha256_bytes(b""), 0));
}

#[test]
fn verify_backup_catches_tampering() {
    let dir = TempDir::new("backup");
    let content = br#"{"schema":"purge.regbackup/1","x":[1,2,3]}"#;
    let rel = r"reg\000002.regbackup.json";
    let mut file = dir.session.create_file(rel).unwrap();
    file.write_all(content).unwrap();
    file.sync().unwrap();
    drop(file);
    let path = dir.session.path().join(rel);
    let backup = BackupRef {
        path: rel.into(),
        sha256: sha256_bytes(content),
        bytes: content.len() as u64,
    };
    assert_eq!(verify_backup(&dir.session, &backup), Ok(()));

    // One byte changed, same size.
    let mut tampered = content.to_vec();
    tampered[20] ^= 0x01;
    std::fs::write(&path, &tampered).unwrap();
    let err = verify_backup(&dir.session, &backup).unwrap_err();
    assert!(matches!(err, BackupCheckError::HashMismatch { .. }));
    assert_eq!(err.conflict(), UndoConflict::BackupTampered);

    std::fs::write(&path, &content[..10]).unwrap();
    assert_eq!(
        verify_backup(&dir.session, &backup),
        Err(BackupCheckError::SizeMismatch {
            expected: content.len() as u64,
            actual: 10
        })
    );

    std::fs::remove_file(&path).unwrap();
    let err = verify_backup(&dir.session, &backup).unwrap_err();
    assert_eq!(err, BackupCheckError::Missing);
    assert_eq!(err.conflict(), UndoConflict::BackupMissing);

    let outside = BackupRef {
        path: r"..\reg\000002.regbackup.json".into(),
        ..backup.clone()
    };
    assert_eq!(
        verify_backup(&dir.session, &outside),
        Err(BackupCheckError::NotSessionRelative)
    );
    // A directory name is not a file the store hands out.
    let a_dir = BackupRef {
        path: "reg".into(),
        ..backup.clone()
    };
    assert!(matches!(
        verify_backup(&dir.session, &a_dir),
        Err(BackupCheckError::Store(StorageError::InvalidPath(_)))
    ));
    // A backup that became a hard link is refused by the store, not read.
    std::fs::write(&path, content).unwrap();
    std::fs::hard_link(&path, dir.scratch.0.join("second-name")).unwrap();
    assert!(matches!(
        verify_backup(&dir.session, &backup),
        Err(BackupCheckError::Store(StorageError::Integrity {
            failure: IntegrityFailure::HardLinked { .. },
            ..
        }))
    ));
}

/// Set only in a child process of the test binary: the data root of the store the child's session is
/// in.
const CHILD_ROOT: &str = "PURGE_TEST_JOURNAL_CHILD_ROOT";
/// Set only in a child process of the test binary: the id of the session the child writes its
/// journal in.
const CHILD_SESSION: &str = "PURGE_TEST_JOURNAL_CHILD_SESSION";

/// The child half of the crash tests: a three-item run from header to commit (op 3 ends as a
/// registered boot-time move), then the undo of op 1. Does nothing when run as an ordinary test.
#[test]
fn child_journal_scenario() {
    let (Some(root), Some(id)) = (
        std::env::var_os(CHILD_ROOT),
        std::env::var(CHILD_SESSION).ok(),
    ) else {
        return;
    };
    let roots = StorageRoots::relaxed(Path::new(&root)).unwrap();
    let session = roots.open_session(&id.parse().unwrap()).unwrap();
    let started = std::time::Instant::now();
    let mut w = JournalWriter::create(
        &session,
        Header {
            session: session.id().clone(),
            ..header(3)
        },
    )
    .unwrap();
    for n in 1..=3 {
        w.validated(validated(n)).unwrap();
    }
    for n in 1..=3 {
        let token = w.intent(intent(n)).unwrap();
        let outcome = if n == 3 {
            pending_reboot(3)
        } else {
            ItemOutcome::Done
        };
        w.done(token, outcome).unwrap();
    }
    w.commit(FileTime(1), 0).unwrap();
    let undo = w.undo_intent(OpId(1)).unwrap();
    w.undo_done(undo, UndoOutcome::Restored).unwrap();
    // Read by the pause test.
    std::fs::write(
        session.path().join("elapsed-ms"),
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

    /// Runs [`child_journal_scenario`] in `dir`'s session with `env`; returns the exit code.
    fn run(dir: &TempDir, env: &[(&str, &str)]) -> Option<i32> {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "journal::tests::child_journal_scenario",
                "--test-threads=1",
            ])
            .env(CHILD_ROOT, dir.roots.data_root())
            .env(CHILD_SESSION, dir.session.id().as_str())
            .env_remove(fault::ENV_AT)
            .env_remove(fault::ENV_PAUSE)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        for (key, value) in env {
            command.env(key, value);
        }
        command.status().unwrap().code()
    }

    fn status(read: &JournalRead, n: u32) -> OpStatus<'_> {
        read.state.op(OpId(n)).unwrap().status()
    }

    #[test]
    fn a_crash_at_each_journal_point_leaves_a_readable_journal() {
        let dir = TempDir::new("crash-header");
        let code = run(&dir, &[(fault::ENV_AT, fault::JOURNAL_HEADER)]);
        assert_eq!(code, Some(ABORT_CODE));
        let header_only = read(&dir.session).unwrap();
        assert_eq!(header_only.records.len(), 1);
        assert_eq!(header_only.state.phase(), Phase::Validating);

        let dir = TempDir::new("crash-intent");
        let code = run(&dir, &[(fault::ENV_AT, "intent.flushed:2")]);
        assert_eq!(code, Some(ABORT_CODE));
        let seen = read(&dir.session).unwrap();
        assert_eq!(status(&seen, 1), OpStatus::Done(&ItemOutcome::Done));
        assert_eq!(status(&seen, 2), OpStatus::IntentOnly);
        assert_eq!(status(&seen, 3), OpStatus::Validated);
        // Recovery finishes the run: the probe decided op 2 was done, op 3 never started.
        let mut w = JournalWriter::open_append(&dir.session).unwrap();
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
        assert_eq!(read(&dir.session).unwrap().state.phase(), Phase::Committed);

        let dir = TempDir::new("crash-done");
        let code = run(&dir, &[(fault::ENV_AT, fault::DONE_BEFORE)]);
        assert_eq!(code, Some(ABORT_CODE));
        let seen = read(&dir.session).unwrap();
        assert_eq!(status(&seen, 1), OpStatus::IntentOnly);
        assert_eq!(seen.state.open_group_intents(), 1);

        // M6: a crash right after the boot-time move was registered leaves op 3 open, for recovery
        // to find the pending move. (That its done is flushed at once is checked by
        // a_pending_reboot_done_is_flushed_at_once: a process crash cannot lose written bytes.)
        let dir = TempDir::new("crash-bootmove");
        let code = run(&dir, &[(fault::ENV_AT, fault::BOOTMOVE_REGISTERED)]);
        assert_eq!(code, Some(ABORT_CODE));
        let seen = read(&dir.session).unwrap();
        assert_eq!(status(&seen, 2), OpStatus::Done(&ItemOutcome::Done));
        assert_eq!(status(&seen, 3), OpStatus::IntentOnly);

        for point in [fault::GROUP_END, fault::COMMIT_BEFORE] {
            let dir = TempDir::new("crash-end");
            let code = run(&dir, &[(fault::ENV_AT, point)]);
            assert_eq!(code, Some(ABORT_CODE), "{point}");
            let seen = read(&dir.session).unwrap();
            assert_eq!(seen.state.phase(), Phase::Running, "{point}");
            assert_eq!(seen.state.groups_closed(), 1, "{point}");
            assert_eq!(seen.state.counts().done, 2, "{point}");
            assert_eq!(seen.state.counts().pending_reboot, 1, "{point}");
            assert!(seen.state.commit().is_none());
            // Only the commit is missing.
            let mut w = JournalWriter::open_append(&dir.session).unwrap();
            w.commit(FileTime(2), 0).unwrap();
        }

        // M6: a crash after the undo intent is flushed leaves the undo in progress; the next
        // writer resumes it once.
        let dir = TempDir::new("crash-undo");
        let code = run(&dir, &[(fault::ENV_AT, fault::UNDO_INTENT)]);
        assert_eq!(code, Some(ABORT_CODE));
        let seen = read(&dir.session).unwrap();
        assert_eq!(seen.state.phase(), Phase::Committed);
        assert_eq!(
            seen.state
                .undo_in_progress()
                .map(|s| s.op)
                .collect::<Vec<_>>(),
            [OpId(1)]
        );
        let mut w = JournalWriter::open_append(&dir.session).unwrap();
        let undo = w.resume_undo(OpId(1)).unwrap();
        assert!(w.resume_undo(OpId(1)).is_none());
        w.undo_done(undo, UndoOutcome::Restored).unwrap();

        // Without a fault the child runs to the end.
        let dir = TempDir::new("crash-none");
        let code = run(&dir, &[]);
        assert_eq!(code, Some(0));
        let seen = read(&dir.session).unwrap();
        assert_eq!(seen.state.phase(), Phase::Committed);
        assert_eq!(seen.state.undo_in_progress().count(), 0);
    }

    #[test]
    fn a_pause_holds_the_writer_after_each_flushed_intent() {
        let dir = TempDir::new("pause");
        let code = run(&dir, &[(fault::ENV_PAUSE, "intent.flushed:150")]);
        assert_eq!(code, Some(0));
        let elapsed: u64 = std::fs::read_to_string(dir.session.path().join("elapsed-ms"))
            .unwrap()
            .parse()
            .unwrap();
        assert!(elapsed >= 450, "{elapsed} ms");
    }
}

// ---------------------------------------------------------------------------------------------------
// Run settings, retries of held items, the journalled validation, the index mark
// ---------------------------------------------------------------------------------------------------

fn run_settings() -> RunSettings {
    RunSettings {
        user_sid: Some("S-1-5-21-1-2-3-1001".into()),
        long_names_resolved: true,
        key_limit: 10_000,
        restore_point: RestorePointPolicy::HighRiskOnly,
        selected: Vec::new(),
        gone_msi_products: Vec::new(),
        gone_msi_by_sid: Vec::new(),
        gone_cache_dirs: Vec::new(),
        gone_burn: Vec::new(),
    }
}

/// Appends one record, chained to `head`, to the journal bytes `bytes`.
fn appended(bytes: &[u8], head: &Sha256Hex, record: Record) -> Vec<u8> {
    let (line, _) = frame(head.as_bytes(), &body(record));
    [bytes, &line].concat()
}

#[test]
fn the_run_settings_follow_the_header_once() {
    let dir = TempDir::new("settings");
    let mut w = JournalWriter::create(&dir.session, dir.header(2)).unwrap();
    let syncs = w.syncs();
    w.settings(run_settings()).unwrap();
    assert_eq!(w.syncs(), syncs + 1, "flushed");
    assert_eq!(w.state().settings(), Some(&run_settings()));
    assert_eq!(
        refused(w.settings(run_settings())),
        Violation::SettingsMisplaced
    );
    w.validated(validated(1)).unwrap();
    assert_eq!(
        refused(w.settings(run_settings())),
        Violation::SettingsMisplaced
    );
    drop(w);
    let back = read(&dir.session).unwrap();
    assert_eq!(back.records[1].name(), "settings");
    assert_eq!(back.state.settings(), Some(&run_settings()));

    // The reader holds the same rule: settings after a validated record, or twice, are refused.
    let late = [
        body(Record::Header(header(1))),
        body(Record::Validated(validated(1))),
        body(Record::Settings(run_settings())),
    ];
    assert_eq!(
        corrupt(parse(&chained(&late))),
        (3, Corruption::Rule(Violation::SettingsMisplaced))
    );
    let twice = [
        body(Record::Header(header(1))),
        body(Record::Settings(run_settings())),
        body(Record::Settings(run_settings())),
    ];
    assert_eq!(
        corrupt(parse(&chained(&twice))),
        (3, Corruption::Rule(Violation::SettingsMisplaced))
    );
}

#[test]
fn a_journal_from_before_the_settings_record_still_reads() {
    // Old document: header, validated, intent, done, commit, undo, reconcile, expire, written without
    // a settings record.
    let dir = TempDir::new("old-doc");
    let bytes = sample_journal(&dir);
    assert!(!String::from_utf8_lossy(&bytes).contains(r#""rec":"settings""#));
    let back = parse(&bytes).unwrap();
    assert_eq!(back.state.settings(), None);
    assert_eq!(back.state.ops().count(), 4);
    assert_eq!(back.state.retries_in_flight().count(), 0);
}

/// A journal whose ops 1 and 2 were held and op 3 done, not yet committed.
fn with_held(dir: &TempDir) -> JournalWriter {
    let mut w = started(dir, 3);
    for n in 1..=2 {
        let t = w.intent(intent(n)).unwrap();
        w.done(t, ItemOutcome::HeldRetry).unwrap();
    }
    let t = w.intent(intent(3)).unwrap();
    w.done(t, ItemOutcome::Done).unwrap();
    w
}

#[test]
fn a_held_item_is_retried_under_a_durable_retry_intent() {
    let dir = TempDir::new("retry");
    let mut w = with_held(&dir);
    let at = FileTime(134_078_200_000_000_000);
    // Only after the run ended, and only for a held op.
    assert_eq!(
        refused(w.retry_intent(OpId(1), at).map(|_| ())),
        Violation::RetryNotHeld(OpId(1))
    );
    w.commit(FileTime(134_078_121_950_000_000), 0).unwrap();
    assert_eq!(
        refused(w.retry_intent(OpId(3), at).map(|_| ())),
        Violation::RetryNotHeld(OpId(3))
    );
    assert_eq!(
        refused(w.retry_intent(OpId(9), at).map(|_| ())),
        Violation::UnknownOp(OpId(9))
    );

    let syncs = w.syncs();
    let first = w.retry_intent(OpId(1), at).unwrap();
    assert_eq!(first.op(), OpId(1));
    assert_eq!(
        w.syncs(),
        syncs + 1,
        "the retry intent is flushed before the token"
    );
    let on_disk = read(&dir.session).unwrap();
    assert!(on_disk.state.op(OpId(1)).unwrap().retry_in_flight);

    // One retry in flight per op, and no undo, expire or token-less `Retried` meanwhile.
    assert_eq!(
        refused(w.retry_intent(OpId(1), at).map(|_| ())),
        Violation::RetryInFlight(OpId(1))
    );
    assert_eq!(
        refused(w.undo_intent(OpId(1)).map(|_| ())),
        Violation::RetryInFlight(OpId(1))
    );
    assert_eq!(
        refused(w.undo_done_without_intent(OpId(1), UndoOutcome::NothingToUndo)),
        Violation::RetryInFlight(OpId(1))
    );
    assert_eq!(
        refused(w.undo_conflict_without_intent(
            OpId(1),
            UndoConflict::FileIdMismatch,
            String::new()
        )),
        Violation::RetryInFlight(OpId(1))
    );
    let expire = Expire {
        at,
        op: OpId(1),
        class: RetentionClass::Quarantine,
        bytes: 0,
    };
    assert_eq!(refused(w.expire(expire)), Violation::RetryInFlight(OpId(1)));
    let tokenless = Reconcile {
        at,
        op: OpId(1),
        result: ReconcileResult::Retried {
            outcome: ItemOutcome::Done,
        },
    };
    assert_eq!(
        refused(w.reconcile(tokenless)),
        Violation::RetryNotInFlight(OpId(1))
    );
    assert_eq!(
        w.state().held_retry().map(|s| s.op).collect::<Vec<_>>(),
        [OpId(2)]
    );
    assert_eq!(
        w.state()
            .retries_in_flight()
            .map(|s| s.op)
            .collect::<Vec<_>>(),
        [OpId(1)]
    );

    // Another op may be retried meanwhile. The outcome replaces HeldRetry.
    let second = w.retry_intent(OpId(2), at).unwrap();
    w.retried(first, at, ItemOutcome::Done).unwrap();
    w.retried(second, at, ItemOutcome::HeldRetry).unwrap();
    assert_eq!(w.state().op(OpId(1)).unwrap().pending(), None);
    assert_eq!(
        w.state().held_retry().map(|s| s.op).collect::<Vec<_>>(),
        [OpId(2)]
    );
    // Still held: it may be retried again.
    let again = w.retry_intent(OpId(2), at).unwrap();
    w.retried(again, at, ItemOutcome::Vanished).unwrap();
    assert_eq!(w.state().held_retry().count(), 0);
    assert_eq!(
        refused(w.retry_intent(OpId(2), at).map(|_| ())),
        Violation::RetryNotHeld(OpId(2))
    );
    // Undo and expiry take the op again once its retry ended.
    w.undo_done_without_intent(OpId(2), UndoOutcome::NothingToUndo)
        .unwrap();
    w.expire(expire).unwrap();
    drop(w);

    let back = read(&dir.session).unwrap();
    let names: Vec<&str> = back.records.iter().map(Record::name).collect();
    assert_eq!(
        names[names.len() - 8..],
        [
            "retry_intent",
            "retry_intent",
            "reconcile",
            "reconcile",
            "retry_intent",
            "reconcile",
            "undo_done",
            "expire"
        ]
    );
    assert_eq!(
        back.state.op(OpId(1)).unwrap().reconciles,
        [ReconcileResult::Retried {
            outcome: ItemOutcome::Done
        }]
    );
    assert_eq!(back.state.retries_in_flight().count(), 0);
}

#[test]
fn an_interrupted_retry_is_resumed_once_with_a_token_of_the_new_writer() {
    let dir = TempDir::new("retry-resume");
    let mut w = with_held(&dir);
    w.commit(FileTime(134_078_121_950_000_000), 0).unwrap();
    let stale = w.retry_intent(OpId(1), FileTime(2)).unwrap();
    // The process stops here: the retry is in flight on disk.
    drop(w);

    let mut w = JournalWriter::open_append(&dir.session).unwrap();
    assert!(w.state().op(OpId(1)).unwrap().retry_in_flight);
    assert_eq!(
        w.state().held_retry().map(|s| s.op).collect::<Vec<_>>(),
        [OpId(2)]
    );
    assert!(
        w.resume_retry(OpId(2)).is_none(),
        "op 2 has no retry in flight"
    );
    assert_eq!(
        refused(w.retried(stale, FileTime(3), ItemOutcome::Done)),
        Violation::ForeignToken(OpId(1))
    );
    let token = w.resume_retry(OpId(1)).unwrap();
    assert!(w.resume_retry(OpId(1)).is_none(), "handed out once");
    w.retried(token, FileTime(3), ItemOutcome::Done).unwrap();
    assert_eq!(w.state().retries_in_flight().count(), 0);

    // A created writer has nothing to resume.
    let other = TempDir::new("retry-resume-new");
    let mut created = started(&other, 1);
    assert!(created.resume_retry(OpId(1)).is_none());
}

#[test]
fn a_retried_record_without_a_retry_intent_from_an_older_journal_still_reads() {
    // Old document: a held op ended by a bare `reconcile` `Retried`, as journals were written before
    // the retry had its own write-ahead record.
    let dir = TempDir::new("retry-old");
    let mut w = with_held(&dir);
    w.commit(FileTime(134_078_121_950_000_000), 0).unwrap();
    let head = w.head();
    drop(w);
    let bytes = std::fs::read(dir.journal()).unwrap();
    let legacy = Record::Reconcile(Reconcile {
        at: FileTime(2),
        op: OpId(1),
        result: ReconcileResult::Retried {
            outcome: ItemOutcome::Done,
        },
    });
    let old = appended(&bytes, &head, legacy);
    let back = parse(&old).unwrap();
    let op = back.state.op(OpId(1)).unwrap();
    assert_eq!(op.pending(), None);
    assert!(!op.retry_in_flight);

    // The reader refuses a retry intent for an op that is not held, and a second one in flight.
    let not_held = appended(
        &bytes,
        &head,
        Record::RetryIntent(RetryIntent {
            at: FileTime(2),
            op: OpId(3),
        }),
    );
    let lines_before = lines(&bytes).len() as u64;
    assert_eq!(
        corrupt(parse(&not_held)),
        (
            lines_before + 1,
            Corruption::Rule(Violation::RetryNotHeld(OpId(3)))
        )
    );
    let retry = Record::RetryIntent(RetryIntent {
        at: FileTime(2),
        op: OpId(1),
    });
    let once = appended(&bytes, &head, retry.clone());
    let head_once = parse(&once).unwrap().head;
    let twice = appended(&once, &head_once, retry);
    assert_eq!(
        corrupt(parse(&twice)),
        (
            lines_before + 2,
            Corruption::Rule(Violation::RetryInFlight(OpId(1)))
        )
    );
}

#[test]
fn reconcile_ends_a_boot_move_that_did_not_complete() {
    let dir = TempDir::new("reconcile-end");
    let mut w = started(&dir, 4);
    for n in 1..=3 {
        let t = w.intent(intent(n)).unwrap();
        w.done(t, pending_reboot(n)).unwrap();
    }
    let t = w.intent(intent(4)).unwrap();
    w.done(t, ItemOutcome::HeldRetry).unwrap();
    w.commit(FileTime(134_078_121_950_000_000), 0).unwrap();
    let rec = |op, result| Reconcile {
        at: FileTime(2),
        op: OpId(op),
        result,
    };
    let not_moved = ReconcileResult::NotMoved {
        code: FailCode::VerifyFailed,
        os_error: None,
        detail: String::new(),
    };
    // Only for a boot move, not for a held item.
    assert_eq!(
        refused(w.reconcile(rec(4, not_moved.clone()))),
        Violation::ReconcileMismatch(OpId(4))
    );
    w.reconcile(rec(1, not_moved.clone())).unwrap();
    w.reconcile(rec(
        2,
        ReconcileResult::MismatchKept {
            code: FailCode::Os,
            os_error: Some(183),
            detail: "kept".into(),
        },
    ))
    .unwrap();
    w.reconcile(rec(
        3,
        ReconcileResult::Lost {
            detail: String::new(),
        },
    ))
    .unwrap();
    assert_eq!(w.state().pending_reboot().count(), 0);
    assert_eq!(
        refused(w.reconcile(rec(1, ReconcileResult::StillPending))),
        Violation::NotPending(OpId(1))
    );
    let attention: Vec<OpId> = w.state().needs_attention().map(|s| s.op).collect();
    assert_eq!(attention, [OpId(2), OpId(3)]);
    assert_eq!(w.state().op(OpId(1)).unwrap().attention(), None);
    assert!(matches!(
        w.state().op(OpId(3)).unwrap().attention(),
        Some(ReconcileResult::Lost { .. })
    ));
    w.undo_conflict_without_intent(OpId(3), UndoConflict::QuarantineMissing, String::new())
        .unwrap();
    drop(w);
    let back = read(&dir.session).unwrap();
    assert_eq!(back.state.op(OpId(1)).unwrap().reconciles, [not_moved]);
    assert_eq!(
        back.state
            .needs_attention()
            .map(|s| s.op)
            .collect::<Vec<_>>(),
        [OpId(2), OpId(3)]
    );
}

#[test]
fn op_state_hands_back_the_journalled_validation_with_its_exemptions() {
    let dir = TempDir::new("validated");
    let mut w = JournalWriter::create(&dir.session, dir.header(2)).unwrap();
    let first = Validated {
        exemptions: GateExemptions {
            long_names_resolved: true,
            environment_segment_edit: true,
            ..GateExemptions::default()
        },
        ..validated(1)
    };
    let second = Validated {
        facts: ItemFacts::Refused {
            blocker: Some(purge_model::Blocker::ChangedSinceScan),
            reason: "live.identity-changed".into(),
            os_error: None,
        },
        ..validated(2)
    };
    w.validated(first.clone()).unwrap();
    w.validated(second.clone()).unwrap();
    assert_eq!(w.state().op(OpId(1)).unwrap().validated(), first);
    drop(w);
    let back = read(&dir.session).unwrap();
    let from_records: Vec<Validated> = back
        .records
        .iter()
        .filter_map(|r| match r {
            Record::Validated(v) => Some(v.clone()),
            _ => None,
        })
        .collect();
    let from_state: Vec<Validated> = back.state.ops().map(OpState::validated).collect();
    assert_eq!(from_state, from_records);
    assert_eq!(from_state, [first, second]);
}

#[test]
fn the_index_mark_finds_a_journal_cut_at_a_line_boundary() {
    let dir = TempDir::new("mark");
    let bytes = sample_journal(&dir);
    let whole = read(&dir.session).unwrap();
    let mark = whole.state.mark();
    assert_eq!(mark.records, lines(&bytes).len() as u64);
    assert_eq!(mark.head, whole.head);
    assert_eq!(whole.head_at(mark.records), Some(whole.head));
    assert_eq!(whole.head_at(0), None);
    assert_eq!(whole.head_at(mark.records + 1), None);
    check_mark(&whole, &mark).unwrap();
    read_indexed(&dir.session, Some(&mark)).unwrap();
    read_indexed(&dir.session, None).unwrap();

    // The writer counts as the reader does.
    let mut w = JournalWriter::open_append(&dir.session).unwrap();
    assert_eq!(w.state().mark(), mark);
    // Lines written after the index entry was are fine.
    w.expire(Expire {
        at: FileTime(134_104_041_030_000_000),
        op: OpId(1),
        class: RetentionClass::Quarantine,
        bytes: 1,
    })
    .unwrap();
    let later = w.state().mark();
    assert_eq!(later.records, mark.records + 1);
    assert_eq!(later.head, w.head());
    drop(w);
    read_indexed(&dir.session, Some(&mark)).unwrap();
    read_indexed(&dir.session, Some(&later)).unwrap();

    // Cut at a line boundary: the chain cannot tell, the mark can.
    let all = lines(&bytes);
    std::fs::write(dir.journal(), all[..all.len() - 1].concat()).unwrap();
    let short = read(&dir.session).unwrap();
    assert!(matches!(
        check_mark(&short, &mark),
        Err(JournalError::IndexMismatch {
            index_records,
            journal_records,
        }) if index_records == mark.records && journal_records == mark.records - 1
    ));
    assert!(matches!(
        read_indexed(&dir.session, Some(&mark)),
        Err(JournalError::IndexMismatch { .. })
    ));
    // As many lines as the mark, but another chain value: the journal was replaced.
    let replaced = JournalMark {
        records: mark.records - 1,
        head: mark.head,
    };
    assert!(check_mark(&short, &replaced).is_err());
    // No mark (an entry written before it existed): nothing to check.
    read_indexed(&dir.session, None).unwrap();
}

/// Item 8 of the M2 recovery fix pass: the state keeps the free text of the `undo_conflict` an op's
/// undo stands at, in the writer and when read back, and drops it once the undo moves on.
#[test]
fn the_state_keeps_the_detail_of_an_undo_conflict() {
    let dir = TempDir::new("conflict-detail");
    let mut w = started(&dir, 2);
    for n in 1..=2 {
        let token = w.intent(intent(n)).unwrap();
        w.done(token, ItemOutcome::Done).unwrap();
    }
    w.commit(FileTime(1), 0).unwrap();
    w.undo_conflict_without_intent(
        OpId(1),
        UndoConflict::DestinationExists,
        r"C:\x is taken".into(),
    )
    .unwrap();
    w.undo_conflict_without_intent(OpId(2), UndoConflict::BackupMissing, String::new())
        .unwrap();
    assert_eq!(
        w.state().undo_conflict_detail(OpId(1)),
        Some(r"C:\x is taken")
    );
    assert_eq!(w.state().undo_conflict_detail(OpId(2)), Some(""));
    drop(w);

    let back = read(&dir.session).unwrap();
    assert_eq!(
        back.state.undo_conflict_detail(OpId(1)),
        Some(r"C:\x is taken")
    );
    // A later attempt: in progress, then restored; the old text no longer describes the op.
    let mut w = JournalWriter::open_append(&dir.session).unwrap();
    let again = w.undo_intent(OpId(1)).unwrap();
    assert_eq!(w.state().undo_conflict_detail(OpId(1)), None);
    w.undo_done(again, UndoOutcome::Restored).unwrap();
    assert_eq!(w.state().undo_conflict_detail(OpId(1)), None);
}

/// Item 7 of the M2 recovery fix pass: an `undo_plan` names the ops an undo run is about to undo; the
/// ops it names that got no undo record afterwards are what an interrupted run left. A journal without
/// the record (written before it existed) leaves only the undo in progress.
#[test]
fn an_undo_plan_names_what_an_interrupted_undo_had_not_reached() {
    let dir = TempDir::new("undo-plan");
    let mut w = started(&dir, 3);
    for n in 1..=3 {
        let token = w.intent(intent(n)).unwrap();
        w.done(token, ItemOutcome::Done).unwrap();
    }
    w.commit(FileTime(1), 0).unwrap();

    // As before the record existed: no plan.
    let u3 = w.undo_intent(OpId(3)).unwrap();
    assert_eq!(w.state().undo_plan(), None);
    assert!(w.state().undo_unfinished().is_empty());
    w.undo_done(u3, UndoOutcome::Restored).unwrap();

    // A plan over a settled op and two others; the settled one is never unfinished.
    w.undo_plan(FileTime(2), vec![OpId(3), OpId(2), OpId(1)])
        .unwrap();
    assert_eq!(
        w.state().undo_plan(),
        Some(&[OpId(3), OpId(2), OpId(1)][..])
    );
    assert_eq!(w.state().undo_unfinished(), [OpId(2), OpId(1)]);
    let _interrupted = w.undo_intent(OpId(2)).unwrap();
    assert_eq!(w.state().undo_unfinished(), [OpId(1)]);
    // The crash.
    drop(w);

    let back = read(&dir.session).unwrap();
    assert_eq!(back.state.undo_unfinished(), [OpId(1)]);
    assert_eq!(
        back.state
            .undo_in_progress()
            .map(|op| op.op)
            .collect::<Vec<_>>(),
        [OpId(2)]
    );
    let mut w = JournalWriter::open_append(&dir.session).unwrap();
    let u2 = w.resume_undo(OpId(2)).unwrap();
    w.undo_done(u2, UndoOutcome::Restored).unwrap();
    // A conflict reaches the op too: it is the user's to retry, not recovery's to finish.
    w.undo_conflict_without_intent(OpId(1), UndoConflict::BackupMissing, String::new())
        .unwrap();
    assert!(w.state().undo_unfinished().is_empty());

    // Every op a plan names must be part of the session.
    assert_eq!(
        refused(w.undo_plan(FileTime(3), vec![OpId(1), OpId(9)])),
        Violation::UnknownOp(OpId(9))
    );
    drop(w);
    assert!(
        read(&dir.session)
            .unwrap()
            .state
            .undo_unfinished()
            .is_empty()
    );
}

/// A key in a user hive that is not loaded: the writer's hive flush skips it, so these tests change
/// nothing in the registry.
const UNLOADED_KEY: &str = r"HKU\S-1-5-21-0-0-0-424242\Software\Vendor";

fn reg_validated(n: u32) -> Validated {
    Validated {
        op: OpId(n),
        item: item(n),
        target: Target::RegValue {
            path: UNLOADED_KEY.into(),
            name: format!("v{n}"),
        },
        facts: ItemFacts::Absent,
        exemptions: GateExemptions::default(),
    }
}

/// The intent of a value delete, op `n`.
fn reg_intent(n: u32) -> Intent {
    Intent {
        op: OpId(n),
        item: item(n),
        exec_op: ExecOp::DeleteValue {
            key: UNLOADED_KEY.into(),
            name: format!("v{n}"),
        },
        inverse: Inverse::RestoreValue {
            backup: BackupRef {
                path: format!(r"reg\{n:06}.regbackup.json"),
                sha256: sha256_bytes(b"backup"),
                bytes: 6,
            },
        },
        definition: None,
        pre: ItemFacts::Value(purge_model::exec::journal::ValueFacts {
            value_type: 1,
            size: 0,
            data_sha256: sha256_bytes(b""),
        }),
    }
}

/// Gate case p902: a registry `done` is unconfirmed until a `group_end` marked `registry_flushed`
/// (written after the hives were flushed), `commit` or `aborted` follows it; a journal from before the
/// mark has no such `group_end`, so after an unclean stop all its registry `done` records are.
#[test]
fn registry_dones_are_unconfirmed_until_a_flushed_group_end() {
    let ids = |state: &JournalState| state.unconfirmed().map(|op| op.op).collect::<Vec<_>>();
    let dir = TempDir::new("unconfirmed");
    let mut w = JournalWriter::create(&dir.session, dir.header(4)).unwrap();
    for n in 1..=3 {
        w.validated(reg_validated(n)).unwrap();
    }
    w.validated(validated(4)).unwrap();
    let t1 = w.intent(reg_intent(1)).unwrap();
    w.done(t1, ItemOutcome::Done).unwrap();
    // Only a registry op whose `done` says it changed the registry.
    let t2 = w.intent(reg_intent(2)).unwrap();
    w.done(t2, failed()).unwrap();
    let t4 = w.intent(intent(4)).unwrap();
    w.done(t4, ItemOutcome::Done).unwrap();
    assert_eq!(ids(w.state()), [OpId(1)]);
    assert!(w.state().is_unconfirmed(OpId(1)));
    assert!(w.end_group().unwrap());
    assert!(ids(w.state()).is_empty());
    let t3 = w.intent(reg_intent(3)).unwrap();
    w.done(t3, ItemOutcome::Done).unwrap();
    assert_eq!(ids(w.state()), [OpId(3)]);
    // The run stops here, uncleanly.
    drop(w);

    let read = super::read(&dir.session).unwrap();
    let marks: Vec<bool> = read
        .records
        .iter()
        .filter_map(|r| match r {
            Record::GroupEnd(g) => Some(g.registry_flushed),
            _ => None,
        })
        .collect();
    assert_eq!(marks, [true]);
    assert_eq!(ids(&read.state), [OpId(3)]);

    // Recovery gets one token per unconfirmed op, to make its change again without a second `done`.
    let mut w = JournalWriter::open_append(&dir.session).unwrap();
    assert!(w.reprobe_token(OpId(1)).is_none());
    assert!(w.resume_intent(OpId(3)).is_none());
    let token = w.reprobe_token(OpId(3)).unwrap();
    assert_eq!((token.op(), token.item()), (OpId(3), &item(3)));
    assert!(w.reprobe_token(OpId(3)).is_none());
    w.commit(FileTime(1), 0).unwrap();
    assert!(ids(w.state()).is_empty());
    drop(w);
    let read = super::read(&dir.session).unwrap();
    assert!(ids(&read.state).is_empty());
    let mut w = JournalWriter::open_append(&dir.session).unwrap();
    assert!(w.reprobe_token(OpId(3)).is_none());
    drop(w);

    // A journal from before the mark: its `group_end` vouches for nothing.
    let group_end = |registry_flushed| {
        body(Record::GroupEnd(purge_model::exec::journal::GroupEnd {
            group: 1,
            ops: 1,
            registry_flushed,
        }))
    };
    let journal = |flushed| {
        let mut bodies = vec![body(Record::Header(header(2)))];
        bodies.extend([1, 2].map(|n| body(Record::Validated(reg_validated(n)))));
        for n in [1, 2] {
            bodies.push(body(Record::Intent(reg_intent(n))));
            bodies.push(body(Record::Done(purge_model::exec::journal::Done {
                op: OpId(n),
                item: item(n),
                outcome: ItemOutcome::Done,
                detail: String::new(),
            })));
            if n == 1 {
                bodies.push(group_end(flushed));
            }
        }
        parse(&chained(&bodies)).unwrap()
    };
    assert_eq!(ids(&journal(false).state), [OpId(1), OpId(2)]);
    assert_eq!(ids(&journal(true).state), [OpId(2)]);
    assert!(!body(Record::Header(header(1))).contains("registry_flushed"));
    assert!(group_end(false).ends_with(r#""ops":1}"#));
}

/// Review S3: an unconfirmed registry op that recovery's re-probe did not find done gets a `reconcile`
/// `Retried`, written with the op's reprobe token, whose outcome replaces its `Done`: in the op, in the
/// counts (so the `commit` agrees), and when the journal is read back. Before the fix no record could
/// be written and the op stayed `Done`.
#[test]
fn a_reprobe_correction_replaces_the_done_of_an_unconfirmed_op() {
    let verify = ItemOutcome::Failed {
        code: FailCode::VerifyFailed,
        os_error: None,
        detail: "the value is not the one backed up".to_owned(),
    };
    let dir = TempDir::new("reprobed");
    let mut w = JournalWriter::create(&dir.session, dir.header(3)).unwrap();
    for n in 1..=2 {
        w.validated(reg_validated(n)).unwrap();
    }
    w.validated(validated(3)).unwrap();
    for n in 1..=2 {
        let token = w.intent(reg_intent(n)).unwrap();
        w.done(token, ItemOutcome::Done).unwrap();
    }
    drop(w);

    // Only an outcome that says the change is not (all) there; a refused record writes nothing.
    let mut w = JournalWriter::open_append(&dir.session).unwrap();
    let token = w.reprobe_token(OpId(1)).unwrap();
    let len = w.len();
    assert_eq!(
        refused(w.reprobed(token, FileTime(5), ItemOutcome::Done)),
        Violation::ReconcileMismatch(OpId(1))
    );
    assert_eq!(w.len(), len);
    drop(w);

    let mut w = JournalWriter::open_append(&dir.session).unwrap();
    let token = w.reprobe_token(OpId(1)).unwrap();
    w.reprobed(token, FileTime(5), verify.clone()).unwrap();
    let op = w.state().op(OpId(1)).unwrap();
    assert_eq!(op.outcome, Some(verify.clone()));
    assert_eq!(
        op.reconciles,
        [ReconcileResult::Retried {
            outcome: verify.clone()
        }]
    );
    assert!(!w.state().is_unconfirmed(OpId(1)));
    assert!(w.state().is_unconfirmed(OpId(2)));
    assert_eq!((w.state().counts().done, w.state().counts().failed), (1, 1));
    // A reconcile of an op that is neither pending nor unconfirmed is still refused.
    assert_eq!(
        refused(w.reconcile(Reconcile {
            at: FileTime(6),
            op: OpId(1),
            result: ReconcileResult::Completed,
        })),
        Violation::NotPending(OpId(1))
    );
    let t3 = w.intent(intent(3)).unwrap();
    w.done(t3, ItemOutcome::Done).unwrap();
    let commit = w.commit(FileTime(7), 0).unwrap();
    assert_eq!((commit.counts.done, commit.counts.failed), (2, 1));
    drop(w);

    let read = super::read(&dir.session).unwrap();
    assert_eq!(
        read.state.op(OpId(1)).unwrap().outcome,
        Some(verify.clone())
    );
    assert_eq!(read.state.counts(), commit.counts);
    // Once the run ended, the correction is refused like any other record of the run.
    let mut bodies: Vec<String> = read.records.iter().cloned().map(body).collect();
    bodies.push(body(Record::Reconcile(Reconcile {
        at: FileTime(8),
        op: OpId(2),
        result: ReconcileResult::Retried { outcome: verify },
    })));
    assert!(parse(&chained(&bodies)).is_err());
}

/// Review M6: a registry op whose key is in no hive the writer can flush is refused at its intent,
/// and nothing is written. Before the fix the intent was written and its change never vouched for.
#[test]
fn an_intent_on_a_key_in_no_flushable_hive_is_refused() {
    let dir = TempDir::new("nohive");
    let mut w = JournalWriter::create(&dir.session, dir.header(1)).unwrap();
    let mut validated = reg_validated(1);
    validated.target = Target::RegValue {
        path: r"HKCU\Software\Vendor".into(),
        name: "v1".into(),
    };
    w.validated(validated).unwrap();
    let mut intent = reg_intent(1);
    intent.exec_op = ExecOp::DeleteValue {
        key: r"HKCU\Software\Vendor".into(),
        name: "v1".into(),
    };
    let len = w.len();
    assert_eq!(
        refused(w.intent(intent)),
        Violation::InconsistentIntent(OpId(1))
    );
    assert_eq!(w.len(), len);
    assert!(!w.is_poisoned());
}
