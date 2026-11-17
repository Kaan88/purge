//! Tests of the report: journals written with the real writer into a relaxed store in a fresh temp
//! directory (removed on drop), then read out. Nothing else is touched.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use purge_model::exec::journal::{
    AbortReason, FileFacts, GateExemptions, Header, Intent, JournalSchema, Validated, ValueFacts,
    VolumeRecord,
};
use purge_model::exec::op::{BackupRef, BootMovePair, FileIdHex};
use purge_model::{Action, ScanMode, Target};

use super::*;
use crate::journal::{JournalWriter, sha256_bytes};
use crate::plan_in::tests::{cid, path, safe, scan_doc, value};
use crate::storage::{SessionDir, StorageRoots};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A session in a relaxed store below a fresh temp directory. The directory drops last.
struct Store {
    session: SessionDir,
    _dir: Scratch,
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Store {
    fn new(tag: &str) -> Store {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "purge-report-{tag}-{:x}-{nanos:x}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let roots = StorageRoots::install_relaxed(&dir.join("data")).unwrap();
        Store {
            session: roots.create_session().unwrap(),
            _dir: Scratch(dir),
        }
    }

    /// A journal with one `validated` record per target; `facts` of an op that has none are absent.
    fn journal(&self, targets: &[(&str, Target)]) -> JournalWriter {
        let header = Header {
            schema: JournalSchema,
            session: self.session.id().clone(),
            created: FileTime(134_078_121_020_000_000),
            engine_version: "0.1.0".into(),
            app: "vendor-app".into(),
            plan_hash: sha256_bytes(b"plan"),
            selection_hash: sha256_bytes(b"selection"),
            policy_version: "m1a.6".into(),
            mode: ScanMode::Post,
            items: targets.len() as u32,
            allow_irreversible: false,
            volumes: vec![VolumeRecord {
                root: r"D:\".into(),
                serial: 7,
                file_system: "NTFS".into(),
                quarantine: format!(r"D:\.purge-q\{}", self.session.id()),
            }],
            program_roots: Vec::new(),
        };
        let mut journal = JournalWriter::create(&self.session, header).unwrap();
        for (n, (id, target)) in targets.iter().enumerate() {
            journal
                .validated(Validated {
                    op: OpId(n as u32 + 1),
                    item: cid(id),
                    target: target.clone(),
                    facts: ItemFacts::Absent,
                    exemptions: GateExemptions::default(),
                })
                .unwrap();
        }
        journal
    }
}

const FILE_A: &str = r"D:\Vendor\a.bin";
const FILE_B: &str = r"D:\Vendor\b.bin";
const DIR_C: &str = r"D:\Vendor\tree";
const KEY: &str = r"HKLM\SOFTWARE\Vendor";

fn file_facts(p: &str, n: u8, size: u64, tree_bytes: Option<u64>) -> FileFacts {
    FileFacts {
        final_path: p.to_owned(),
        file_id: FileIdHex([n; 16]),
        volume_serial: 7,
        reparse_tag: 0,
        attributes: 32,
        n_links: 1,
        is_dir: tree_bytes.is_some(),
        size,
        tree_entries: tree_bytes.map(|_| 3),
        tree_bytes,
    }
}

/// The intent of a quarantine move of `p` as op `n`.
fn move_intent(n: u32, id: &str, p: &str, size: u64, tree_bytes: Option<u64>) -> Intent {
    let facts = file_facts(p, n as u8, size, tree_bytes);
    Intent {
        op: OpId(n),
        item: cid(id),
        exec_op: ExecOp::QuarantineMove { path: p.to_owned() },
        inverse: Inverse::MoveBack {
            quarantine_path: format!(r"D:\.purge-q\s\{n:06}\leaf"),
            original_path: p.to_owned(),
            file_id: facts.file_id,
            volume_serial: facts.volume_serial,
            parent: None,
        },
        definition: None,
        pre: ItemFacts::File(facts),
    }
}

/// The intent of a value delete as op `n`, with a backup of `bytes` bytes.
fn value_intent(n: u32, id: &str, bytes: u64) -> Intent {
    Intent {
        op: OpId(n),
        item: cid(id),
        exec_op: ExecOp::DeleteValue {
            key: KEY.into(),
            name: "Run".into(),
        },
        inverse: Inverse::RestoreValue {
            backup: BackupRef {
                path: format!(r"reg\{n:06}.regbackup.json"),
                sha256: sha256_bytes(b"backup"),
                bytes,
            },
        },
        definition: None,
        pre: ItemFacts::Value(ValueFacts {
            value_type: 1,
            size: 8,
            data_sha256: sha256_bytes(b"data"),
        }),
    }
}

fn pending() -> ItemOutcome {
    ItemOutcome::PendingReboot {
        pair: BootMovePair {
            src: format!(r"\??\{FILE_B}"),
            dst: r"\??\D:\.purge-q\s\000002\leaf".into(),
        },
        confirmed: true,
    }
}

fn not_attempted() -> ItemOutcome {
    ItemOutcome::Skipped {
        reason: SkipReason::NotAttempted,
    }
}

/// Five items: two files, a directory tree, a value, and a scheduled task (no executor).
fn plan() -> ScanDoc {
    scan_doc(
        vec![
            safe("c-a", path(FILE_A), Action::Quarantine),
            safe("c-b", path(FILE_B), Action::Quarantine),
            safe("c-c", path(DIR_C), Action::Quarantine),
            safe("c-v", value(KEY, "Run"), Action::DeleteValue),
            safe(
                "c-t",
                Target::Task {
                    path: r"\Vendor\Update".into(),
                },
                Action::Quarantine,
            ),
        ],
        Vec::new(),
    )
}

fn targets(scan: &ScanDoc) -> Vec<(&str, Target)> {
    scan.items
        .iter()
        .map(|c| (c.id.0.as_str(), c.target.clone()))
        .collect()
}

#[test]
fn a_committed_run_is_read_out_item_by_item() {
    let store = Store::new("committed");
    let scan = plan();
    let mut journal = store.journal(&targets(&scan));
    // A file moved, a file registered for the next restart, a tree held, a value deleted, a task skipped.
    let token = journal
        .intent(move_intent(1, "c-a", FILE_A, 100, None))
        .unwrap();
    journal.done(token, ItemOutcome::Done).unwrap();
    let token = journal
        .intent(move_intent(2, "c-b", FILE_B, 40, None))
        .unwrap();
    journal.done(token, pending()).unwrap();
    let token = journal
        .intent(move_intent(3, "c-c", DIR_C, 0, Some(5000)))
        .unwrap();
    journal.done(token, ItemOutcome::HeldRetry).unwrap();
    let token = journal.intent(value_intent(4, "c-v", 300)).unwrap();
    journal.done(token, ItemOutcome::Done).unwrap();
    let skipped = ItemOutcome::Skipped {
        reason: SkipReason::GateBlocked {
            blocker: purge_model::Blocker::CannotBackUp,
        },
    };
    journal.done_without_intent(OpId(5), skipped).unwrap();
    let total = backup_bytes(journal.state());
    assert_eq!(total, 100 + 40 + 300);
    journal
        .commit(FileTime(134_078_121_030_000_000), total)
        .unwrap();
    let state = journal.state().clone();

    let mut notes = RunNotes::default();
    notes.lockers.insert(
        OpId(3),
        vec![Locker {
            pid: 4242,
            name: "vendor.exe".into(),
            service: None,
        }],
    );
    notes
        .details
        .insert(OpId(3), "held: a directory is never moved at boot".into());
    notes
        .details
        .insert(OpId(1), "a success needs no explanation".into());
    notes.details.insert(
        OpId(5),
        "scheduled task: not supported in this version".into(),
    );
    notes.warnings.push("a note about the run".into());
    notes.restore_point = RestorePointOutcome::Throttled;

    let report = build(&state, &scan, &notes, FileTime(1));
    assert_eq!(report.state, SessionState::Committed);
    assert_eq!(report.started, FileTime(134_078_121_020_000_000));
    assert_eq!(report.finished, FileTime(134_078_121_030_000_000));
    assert_eq!(report.restore_point, RestorePointOutcome::Throttled);
    assert!(report.pending_reboot);

    // Five items: the task has no executor op and is listed without one. (Changed: it was left out of
    // the items while `ItemReport.exec_op` was not optional.)
    let listed: Vec<(&str, u32, Option<&str>, u64)> = report
        .items
        .iter()
        .map(|i| {
            let name = i.exec_op.as_ref().map(|op| op.name());
            (i.item.0.as_str(), i.op.0, name, i.backup_bytes)
        })
        .collect();
    assert_eq!(
        listed,
        [
            ("c-a", 1, Some("QuarantineMove"), 100),
            ("c-b", 2, Some("QuarantineMove"), 40),
            // Held: nothing was moved, so nothing is kept for it yet.
            ("c-c", 3, Some("QuarantineMove"), 0),
            ("c-v", 4, Some("DeleteValue"), 300),
            ("c-t", 5, None, 0),
        ]
    );
    assert_eq!(
        report.items[4].outcome,
        ItemOutcome::Skipped {
            reason: SkipReason::GateBlocked {
                blocker: purge_model::Blocker::CannotBackUp,
            },
        }
    );
    assert_eq!(report.items[1].outcome, pending());
    assert_eq!(report.items[2].lockers.len(), 1);
    assert!(report.items[0].lockers.is_empty());
    assert_eq!(report.counts, report.tally());
    assert_eq!(
        (
            report.counts.done,
            report.counts.pending_reboot,
            report.counts.held_retry,
            report.counts.skipped
        ),
        (2, 1, 1, 1)
    );
    // The report counts every journalled op, as the index entry does.
    assert_eq!(report.counts, state.counts());
    assert_eq!(report.backup_bytes, total);

    assert_eq!(report.warnings[0], "a note about the run");
    let warned = |needle: &str| report.warnings.iter().any(|w| w.contains(needle));
    assert!(warned("c-c") && warned("never moved at boot"));
    assert!(warned("c-t") && warned("not supported in this version"));
    assert!(!warned("needs no explanation"));

    // The index entry is the journal's own tally, the task included, and records how far the journal
    // reaches (review M7).
    let data = DataVolume {
        serial: 9,
        root: r"C:\".into(),
    };
    let entry = summary(&state, &scan, Some(&data));
    assert_eq!(entry.state, SessionState::Committed);
    assert_eq!(entry.counts, state.counts());
    assert_eq!(entry.counts.skipped, 1);
    assert_eq!(entry.journal, Some(state.mark()));
    assert_eq!(state.mark().records, 1 + 5 + 4 + 5 + 1 + 1);
    assert_eq!(entry.backup_bytes, total);
    assert!(entry.pending_reboot);
    assert_eq!(entry.finished, Some(FileTime(134_078_121_030_000_000)));
    assert_eq!(entry.owner.as_ref().unwrap().display_name, "Vendor App");
    assert_eq!(
        entry.usage,
        [
            VolumeUsage {
                serial: 7,
                root: r"D:\".into(),
                bytes: 140
            },
            VolumeUsage {
                serial: 9,
                root: r"C:\".into(),
                bytes: 300
            },
        ]
    );
    // Without the data volume only the quarantined bytes can be placed.
    assert_eq!(usage(&state, None).len(), 1);

    // The document round-trips through the model type.
    let text = serde_json::to_string(&report).unwrap();
    let back: ExecReport = serde_json::from_str(&text).unwrap();
    assert_eq!(back, report);
    assert_eq!(serde_json::to_string(&back).unwrap(), text);
    assert!(text.starts_with(r#"{"schema":"purge.exec/1","#));
}

#[test]
fn an_aborted_run_reports_what_was_not_attempted() {
    let store = Store::new("aborted");
    let scan = plan();
    let mut journal = store.journal(&targets(&scan));
    let token = journal
        .intent(move_intent(1, "c-a", FILE_A, 100, None))
        .unwrap();
    journal.done(token, ItemOutcome::Done).unwrap();
    // Op 2 has its intent and no done; ops 3 to 5 were never reached.
    let _open = journal
        .intent(move_intent(2, "c-b", FILE_B, 40, None))
        .unwrap();
    journal
        .abort(
            FileTime(134_078_121_040_000_000),
            AbortReason::JournalWriteFailed,
            "disk full".into(),
        )
        .unwrap();
    let state = journal.state().clone();

    let report = build(&state, &scan, &RunNotes::default(), FileTime(1));
    assert_eq!(report.state, SessionState::Aborted);
    assert_eq!(report.finished, FileTime(134_078_121_040_000_000));
    let outcomes: Vec<&ItemOutcome> = report.items.iter().map(|i| &i.outcome).collect();
    // (Changed: four items while the task, which has no executor op, could not be listed.)
    assert_eq!(outcomes.len(), 5);
    assert_eq!(outcomes[0], &ItemOutcome::Done);
    assert!(matches!(
        outcomes[1],
        ItemOutcome::Failed {
            code: FailCode::Internal,
            ..
        }
    ));
    assert_eq!(outcomes[2], &not_attempted());
    assert_eq!(outcomes[3], &not_attempted());
    assert_eq!(outcomes[4], &not_attempted());
    assert_eq!(report.items[4].exec_op, None);
    assert_eq!(report.counts, report.tally());
    assert_eq!((report.counts.failed, report.counts.skipped), (1, 3));
    // What moved is counted; what only has an intent is not.
    assert_eq!(report.backup_bytes, 100);
    assert!(!report.pending_reboot);
    let warned = |needle: &str| report.warnings.iter().any(|w| w.contains(needle));
    assert!(warned("aborted") && warned("JournalWriteFailed") && warned("disk full"));
    assert!(warned("c-b") && warned("intent and no outcome"));
    assert!(warned("c-t"));

    let entry = summary(&state, &scan, None);
    assert_eq!(entry.state, SessionState::Aborted);
    assert_eq!(entry.counts.done, 1);
    assert_eq!(entry.backup_bytes, 100);
}

#[test]
fn an_unfinished_journal_is_reported_as_open_with_the_time_given() {
    let store = Store::new("open");
    let scan = plan();
    let journal = store.journal(&targets(&scan));
    let state = journal.state().clone();
    assert_eq!(session_state(&state), SessionState::Open);
    let report = build(&state, &scan, &RunNotes::default(), FileTime(77));
    assert_eq!(report.state, SessionState::Open);
    assert_eq!(report.finished, FileTime(77));
    assert!(report.items.iter().all(|i| i.outcome == not_attempted()));
    assert_eq!(summary(&state, &scan, None).finished, None);
    assert_eq!(backup_bytes(&state), 0);
}

/// Review M2 M24: a move whose verification failed may have put its item in quarantine (undo treats it
/// as changed), so its bytes count toward the session and the volume's usage like a move that ended
/// `Done`. A move that failed otherwise does not count.
#[test]
fn a_move_whose_verification_failed_counts_toward_the_volume() {
    let store = Store::new("verifyfailed");
    let scan = plan();
    let mut journal = store.journal(&targets(&scan));
    let token = journal
        .intent(move_intent(1, "c-a", FILE_A, 100, None))
        .unwrap();
    let verify_failed = ItemOutcome::Failed {
        code: FailCode::VerifyFailed,
        os_error: None,
        detail: "the item is at its path and in quarantine".into(),
    };
    journal.done(token, verify_failed).unwrap();
    let token = journal
        .intent(move_intent(2, "c-b", FILE_B, 40, None))
        .unwrap();
    let failed = ItemOutcome::Failed {
        code: FailCode::Internal,
        os_error: None,
        detail: "nothing moved".into(),
    };
    journal.done(token, failed).unwrap();
    let state = journal.state().clone();
    assert_eq!(backup_bytes(&state), 100);
    assert_eq!(held_bytes(&state), 100);
    assert_eq!(
        usage(&state, None),
        [VolumeUsage {
            serial: 7,
            root: r"D:\".into(),
            bytes: 100
        }]
    );
}

#[test]
fn the_owner_is_named_only_when_every_item_shares_it() {
    let store = Store::new("owner");
    let mut scan = plan();
    scan.items[1].owner.display_name = "Other App".into();
    let journal = store.journal(&targets(&scan));
    assert_eq!(summary(journal.state(), &scan, None).owner, None);
}
