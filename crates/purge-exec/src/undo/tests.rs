//! Unit tests of the undo rules that are decided from the journal alone: the order, the dependencies
//! a partial selection pulls in, and the standing of the session. Pure: nothing here touches the
//! system. The round trips on real objects are in `tests/roundtrip.rs`.

use purge_model::exec::journal::{Done, GateExemptions, Intent, ItemFacts};
use purge_model::exec::op::{Inverse, SkipReason};

use super::*;

fn file(path: &str) -> ExecOp {
    ExecOp::QuarantineMove {
        path: path.to_owned(),
    }
}

fn dir(path: &str) -> ExecOp {
    ExecOp::RemoveDirIfEmpty {
        path: path.to_owned(),
    }
}

fn key(key: &str) -> ExecOp {
    ExecOp::DeleteKeyTree {
        key: key.to_owned(),
    }
}

fn value(key: &str) -> ExecOp {
    ExecOp::DeleteValue {
        key: key.to_owned(),
        name: "V".to_owned(),
    }
}

fn item(op: u32) -> CandidateId {
    CandidateId(format!("c-{op}"))
}

/// An intent whose inverse is the kind the op's undo order depends on.
fn intent(op: u32, exec_op: ExecOp) -> Intent {
    let inverse = match &exec_op {
        ExecOp::RemoveDirIfEmpty { path } => Inverse::RecreateDir {
            path: path.clone(),
            attributes: 0x10,
            sddl: String::new(),
            creation_time: None,
            last_write_time: None,
        },
        _ => Inverse::None,
    };
    Intent {
        op: OpId(op),
        item: item(op),
        exec_op,
        inverse,
        definition: None,
        pre: ItemFacts::Absent,
    }
}

fn done(op: u32, outcome: ItemOutcome) -> Record {
    Record::Done(Done {
        op: OpId(op),
        item: item(op),
        outcome,
        detail: String::new(),
    })
}

/// An op as the journal state would hold it, with an intent and `outcome`.
fn op_state(op: u32, exec_op: ExecOp, outcome: Option<ItemOutcome>) -> OpState {
    OpState {
        op: OpId(op),
        item: item(op),
        target: exec_op.target(),
        facts: ItemFacts::Absent,
        exemptions: GateExemptions::default(),
        intent: Some(intent(op, exec_op)),
        outcome,
        reconciles: Vec::new(),
        undo: UndoState::NotStarted,
        undo_attempts: 0,
        expired: Vec::new(),
        retry_in_flight: false,
    }
}

fn ids(ops: &[u32]) -> BTreeSet<OpId> {
    ops.iter().map(|op| OpId(*op)).collect()
}

fn order(records: &[Record], ops: &[u32]) -> Vec<u32> {
    undo_order(records, &ids(ops))
        .into_iter()
        .map(|op| op.0)
        .collect()
}

// ---------------------------------------------------------------------------------------------------
// The order
// ---------------------------------------------------------------------------------------------------

#[test]
fn ops_are_undone_in_the_reverse_order_of_their_done_records_not_of_their_ids() {
    // The done records come in the order 2, 1, 3.
    let records = vec![
        Record::Intent(intent(1, file(r"C:\a\1"))),
        Record::Intent(intent(2, file(r"C:\a\2"))),
        done(2, ItemOutcome::Done),
        done(1, ItemOutcome::Done),
        Record::Intent(intent(3, key(r"HKCU\Software\V"))),
        done(3, ItemOutcome::Done),
    ];
    assert_eq!(order(&records, &[1, 2, 3]), [3, 1, 2]);
}

/// Changed by M1 of the final M2 review: directory recreations no longer come before everything else.
/// The plain reverse already puts every directory back before what was below it.
#[test]
fn directory_recreations_keep_the_plain_reverse_order() {
    let records = vec![
        Record::Intent(intent(1, file(r"C:\app\sub\f"))),
        done(1, ItemOutcome::Done),
        Record::Intent(intent(2, dir(r"C:\app\sub"))),
        done(2, ItemOutcome::Done),
        Record::Intent(intent(3, key(r"HKCU\Software\V"))),
        done(3, ItemOutcome::Done),
        Record::Intent(intent(4, dir(r"C:\app"))),
        done(4, ItemOutcome::Done),
        Record::Intent(intent(5, file(r"C:\other\g"))),
        done(5, ItemOutcome::Done),
    ];
    assert_eq!(order(&records, &[1, 2, 3, 4, 5]), [5, 4, 3, 2, 1]);
}

/// M1 of the final M2 review: an empty directory removed inside a directory that was then quarantined
/// whole. Before the fix the recreation came first and ended `ParentMissing`; a second undo was needed.
#[test]
fn a_directory_moved_whole_comes_back_before_the_directory_removed_inside_it() {
    let records = vec![
        Record::Intent(intent(1, dir(r"C:\app\inner"))),
        done(1, ItemOutcome::Done),
        Record::Intent(intent(2, file(r"C:\app"))),
        done(2, ItemOutcome::Done),
    ];
    assert_eq!(order(&records, &[1, 2]), [2, 1]);
}

#[test]
fn an_op_with_an_intent_and_no_done_counts_at_its_intent() {
    let records = vec![
        Record::Intent(intent(1, file(r"C:\a\1"))),
        done(1, ItemOutcome::Done),
        Record::Intent(intent(2, file(r"C:\a\2"))),
    ];
    assert_eq!(order(&records, &[1, 2]), [2, 1]);
}

#[test]
fn only_the_ops_asked_for_are_ordered_and_an_op_without_a_record_is_left_out() {
    let records = vec![
        Record::Intent(intent(1, file(r"C:\a\1"))),
        done(1, ItemOutcome::Done),
        Record::Intent(intent(2, file(r"C:\a\2"))),
        done(2, ItemOutcome::Done),
        // Op 3 was decided before any intent.
        done(3, ItemOutcome::Vanished),
    ];
    assert_eq!(order(&records, &[1, 3]), [3, 1]);
    // Op 4 was validated and never reached.
    assert_eq!(order(&records, &[2, 4]), [2]);
    assert!(order(&records, &[]).is_empty());
}

// ---------------------------------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------------------------------

fn pulled(ops: &[OpState], selected: &[u32]) -> Vec<u32> {
    let refs: Vec<&OpState> = ops.iter().collect();
    dependencies(&refs, &ids(selected))
        .into_iter()
        .map(|op| op.0)
        .collect()
}

#[test]
fn a_file_pulls_in_every_directory_above_it_that_the_session_removed_or_moved() {
    let ops = vec![
        op_state(1, file(r"C:\app\sub\deep\f.txt"), Some(ItemOutcome::Done)),
        op_state(2, dir(r"C:\app\sub\deep"), Some(ItemOutcome::Done)),
        op_state(3, dir(r"C:\app\sub"), Some(ItemOutcome::Done)),
        // A directory moved whole after its file went separately.
        op_state(4, file(r"C:\app"), Some(ItemOutcome::Done)),
        // Beside it, below it, or merely sharing a name prefix: not above it.
        op_state(5, dir(r"C:\app\sub\other"), Some(ItemOutcome::Done)),
        op_state(6, dir(r"C:\app\sub\deep\f.txt\x"), Some(ItemOutcome::Done)),
        op_state(7, dir(r"C:\app\su"), Some(ItemOutcome::Done)),
        op_state(8, key(r"HKCU\Software\app"), Some(ItemOutcome::Done)),
    ];
    assert_eq!(pulled(&ops, &[1]), [2, 3, 4]);
    // A directory depends on the ones above it in the same way, and never on itself.
    assert_eq!(pulled(&ops, &[2]), [3, 4]);
    assert!(pulled(&ops, &[4]).is_empty());
    // What is selected is not "pulled in".
    assert_eq!(pulled(&ops, &[1, 3]), [2, 4]);
}

/// S1 of the final M2 review: a file op whose item lies below a directory the session removed or
/// moved runs only once that directory's undo settled.
#[test]
fn nothing_is_put_back_below_a_directory_whose_undo_has_not_settled() {
    let mut ops = vec![
        op_state(1, file(r"C:\app\sub\f.txt"), Some(ItemOutcome::Done)),
        op_state(2, dir(r"C:\app\sub"), Some(ItemOutcome::Done)),
        op_state(3, dir(r"C:\APP"), Some(ItemOutcome::Done)),
        // Never removed: no reason to hold anything back.
        op_state(
            4,
            dir(r"C:\app\sub\deeper"),
            Some(ItemOutcome::Skipped {
                reason: SkipReason::NoLongerEmpty,
            }),
        ),
        op_state(5, key(r"HKCU\Software\app"), Some(ItemOutcome::Done)),
    ];
    let above = |ops: &[OpState], n: usize| unrestored_ancestor(ops.iter(), &ops[n]).map(|op| op.0);
    assert_eq!(above(&ops, 0), Some(2));
    assert_eq!(above(&ops, 1), Some(3), "compared without regard to case");
    assert_eq!(above(&ops, 2), None);
    assert_eq!(above(&ops, 4), None, "a registry op has no path");
    // The directory came back in a conflict: still held.
    ops[2].undo = UndoState::Conflict(UndoConflict::DestinationExists);
    assert_eq!(above(&ops, 1), Some(3));
    ops[2].undo = UndoState::Finished(UndoOutcome::Failed {
        code: FailCode::Os,
        os_error: None,
        detail: String::new(),
    });
    assert_eq!(above(&ops, 1), Some(3));
    // Restored, or found as recorded: the way is free, level by level.
    ops[2].undo = UndoState::Finished(UndoOutcome::AlreadyRestored);
    assert_eq!(above(&ops, 1), None);
    assert_eq!(above(&ops, 0), Some(2));
    ops[1].undo = UndoState::Finished(UndoOutcome::Restored);
    assert_eq!(above(&ops, 0), None);
    // Op 4's directory lies below both, which are back now.
    assert_eq!(above(&ops, 3), None);
}

#[test]
fn paths_and_keys_are_compared_without_regard_to_case() {
    let ops = vec![
        op_state(1, file(r"c:\APP\Sub\f.txt"), Some(ItemOutcome::Done)),
        op_state(2, dir(r"C:\app\sub"), Some(ItemOutcome::Done)),
        op_state(
            3,
            value(r"hkcu\software\VENDOR\App"),
            Some(ItemOutcome::Done),
        ),
        op_state(4, key(r"HKCU\Software\Vendor"), Some(ItemOutcome::Done)),
    ];
    assert_eq!(pulled(&ops, &[1, 3]), [2, 4]);
}

#[test]
fn a_value_pulls_in_the_key_holding_it_and_a_key_only_the_keys_above_it() {
    let ops = vec![
        op_state(1, value(r"HKCU\Software\V\App"), Some(ItemOutcome::Done)),
        op_state(2, key(r"HKCU\Software\V\App"), Some(ItemOutcome::Done)),
        op_state(3, key(r"HKCU\Software\V"), Some(ItemOutcome::Done)),
        op_state(
            4,
            key(r"HKCU\Software\V\App\Below"),
            Some(ItemOutcome::Done),
        ),
        op_state(5, key(r"HKCU\Software\Other"), Some(ItemOutcome::Done)),
    ];
    assert_eq!(pulled(&ops, &[1]), [2, 3]);
    assert_eq!(pulled(&ops, &[2]), [3]);
    assert_eq!(pulled(&ops, &[4]), [2, 3]);
    assert!(pulled(&ops, &[5]).is_empty());
}

#[test]
fn only_a_dependency_that_still_stands_changed_is_pulled_in() {
    let skipped = ItemOutcome::Skipped {
        reason: SkipReason::NoLongerEmpty,
    };
    let mut undone = op_state(3, dir(r"C:\app"), Some(ItemOutcome::Done));
    undone.undo = UndoState::Finished(UndoOutcome::Restored);
    let mut conflicted = op_state(4, dir(r"C:\app\a"), Some(ItemOutcome::Done));
    conflicted.undo = UndoState::Conflict(UndoConflict::DestinationExists);
    let mut no_intent = op_state(6, dir(r"C:\app\a\b\c\d"), Some(ItemOutcome::Vanished));
    no_intent.intent = None;
    let ops = vec![
        op_state(1, file(r"C:\app\a\b\c\d\f.txt"), Some(ItemOutcome::Done)),
        // The directory was not empty after all: it is still there.
        op_state(2, dir(r"C:\app\a\b"), Some(skipped)),
        // Already back.
        undone,
        // Tried before and in conflict: tried again with what depends on it.
        conflicted,
        // The run died during its removal: it may be gone.
        op_state(5, dir(r"C:\app\a\b\c"), None),
        no_intent,
    ];
    assert_eq!(pulled(&ops, &[1]), [4, 5]);
}

// ---------------------------------------------------------------------------------------------------
// What an op stands at
// ---------------------------------------------------------------------------------------------------

fn failed(code: FailCode) -> ItemOutcome {
    ItemOutcome::Failed {
        code,
        os_error: None,
        detail: String::new(),
    }
}

fn pending_reboot() -> ItemOutcome {
    ItemOutcome::PendingReboot {
        pair: purge_model::exec::op::BootMovePair {
            src: r"\??\C:\a".to_owned(),
            dst: r"\??\C:\q\a".to_owned(),
        },
        confirmed: true,
    }
}

#[test]
fn an_op_stands_changed_when_its_action_ran_or_may_have_run() {
    let changed = |outcome: Option<ItemOutcome>, reconciles: Vec<ReconcileResult>| {
        let mut op = op_state(1, file(r"C:\a"), outcome);
        op.reconciles = reconciles;
        stands_changed(&op)
    };
    assert!(changed(Some(ItemOutcome::Done), vec![]));
    assert!(changed(None, vec![]));
    assert!(changed(Some(failed(FailCode::VerifyFailed)), vec![]));
    assert!(changed(Some(pending_reboot()), vec![]));
    assert!(!changed(Some(failed(FailCode::AccessDenied)), vec![]));
    assert!(!changed(Some(ItemOutcome::Vanished), vec![]));
    assert!(!changed(Some(ItemOutcome::HeldRetry), vec![]));

    // Reconcile records change where a lock op stands.
    let retried = |outcome| ReconcileResult::Retried { outcome };
    assert!(changed(
        Some(ItemOutcome::HeldRetry),
        vec![retried(ItemOutcome::Done)]
    ));
    assert!(!changed(
        Some(ItemOutcome::HeldRetry),
        vec![retried(ItemOutcome::HeldRetry)]
    ));
    assert!(changed(
        Some(pending_reboot()),
        vec![ReconcileResult::StillPending, ReconcileResult::Completed]
    ));
    assert!(!changed(
        Some(pending_reboot()),
        vec![ReconcileResult::Cancelled]
    ));
    assert!(!changed(
        Some(pending_reboot()),
        vec![ReconcileResult::MismatchMovedBack]
    ));
    assert!(changed(
        Some(pending_reboot()),
        vec![ReconcileResult::Lost {
            detail: String::new()
        }]
    ));

    // Without an intent nothing was ever changed.
    let mut decided = op_state(1, file(r"C:\a"), Some(ItemOutcome::Vanished));
    decided.intent = None;
    assert!(!stands_changed(&decided));
}

#[test]
fn the_effective_outcome_is_the_done_outcome_as_reconcile_changed_it() {
    let mut held = op_state(1, file(r"C:\a"), Some(ItemOutcome::HeldRetry));
    assert_eq!(effective_outcome(&held), Some(ItemOutcome::HeldRetry));
    held.reconciles = vec![
        ReconcileResult::Retried {
            outcome: ItemOutcome::HeldRetry,
        },
        ReconcileResult::Retried {
            outcome: ItemOutcome::Done,
        },
    ];
    assert_eq!(effective_outcome(&held), Some(ItemOutcome::Done));

    let mut boot = op_state(2, file(r"C:\b"), Some(pending_reboot()));
    boot.reconciles = vec![ReconcileResult::StillPending];
    assert_eq!(effective_outcome(&boot), Some(pending_reboot()));
    boot.reconciles.push(ReconcileResult::Completed);
    assert_eq!(effective_outcome(&boot), Some(ItemOutcome::Done));

    assert_eq!(effective_outcome(&op_state(3, file(r"C:\c"), None)), None);
}

// ---------------------------------------------------------------------------------------------------
// The standing of the session
// ---------------------------------------------------------------------------------------------------

#[test]
fn a_session_is_undone_when_nothing_that_stands_changed_is_left() {
    let with_undo = |op: u32, outcome: ItemOutcome, undo: UndoState| {
        let mut state = op_state(op, file(&format!(r"C:\a\{op}")), Some(outcome));
        state.undo = undo;
        state
    };
    let restored = UndoState::Finished(UndoOutcome::Restored);
    let already = UndoState::Finished(UndoOutcome::AlreadyRestored);
    let nothing = UndoState::Finished(UndoOutcome::NothingToUndo);

    // No undo record at all: the session stands where its run left it.
    let untouched = [with_undo(1, ItemOutcome::Done, UndoState::NotStarted)];
    assert_eq!(
        standing(untouched.iter()),
        Standing {
            state: None,
            undone: 0
        }
    );

    // Everything that changed is back; an op that changed nothing does not need an undo record.
    let all = [
        with_undo(1, ItemOutcome::Done, restored.clone()),
        with_undo(2, ItemOutcome::Done, already.clone()),
        with_undo(3, ItemOutcome::Vanished, nothing.clone()),
        with_undo(4, ItemOutcome::Vanished, UndoState::NotStarted),
    ];
    assert_eq!(
        standing(all.iter()),
        Standing {
            state: Some(SessionState::Undone),
            undone: 2
        }
    );

    // One op not selected, one in conflict, one failed, one interrupted: each leaves it partial.
    for left in [
        UndoState::NotStarted,
        UndoState::Conflict(UndoConflict::DestinationExists),
        UndoState::Finished(UndoOutcome::Failed {
            code: FailCode::Os,
            os_error: Some(5),
            detail: String::new(),
        }),
        UndoState::InProgress,
    ] {
        let some = [
            with_undo(1, ItemOutcome::Done, restored.clone()),
            with_undo(2, ItemOutcome::Done, left.clone()),
        ];
        assert_eq!(
            standing(some.iter()),
            Standing {
                state: Some(SessionState::PartiallyUndone),
                undone: 1
            },
            "{left:?}"
        );
    }

    // A conflict alone is an undo record too.
    let only_conflict = [with_undo(
        1,
        ItemOutcome::Done,
        UndoState::Conflict(UndoConflict::Irreversible),
    )];
    assert_eq!(
        standing(only_conflict.iter()).state,
        Some(SessionState::PartiallyUndone)
    );
}

#[test]
fn the_time_is_a_filetime_of_today() {
    // 2020-01-01 and 2100-01-01 as FILETIME ticks.
    let ticks = now().0;
    assert!(ticks > 132_223_104_000_000_000 && ticks < 157_469_184_000_000_000);
}

#[test]
fn the_labels_document_names_its_schema_and_reads_back() {
    let labels = UndoLabels {
        schema: LABELS_SCHEMA.to_owned(),
        session: SessionId::new(FileTime(132_223_104_000_000_000), 7),
        app: "vendor-app".to_owned(),
        plan_hash: journal::sha256_bytes(b"plan"),
        policy_version: "m1a.6".to_owned(),
        at: FileTime(132_223_104_000_000_001),
        labels: vec![UndoLabel {
            op: OpId(3),
            item: item(3),
            target: file(r"C:\a").target(),
            outcome: UndoOutcome::Restored,
        }],
    };
    let text = serde_json::to_string(&labels).unwrap();
    assert!(text.contains(r#""schema":"purge.undo-labels/1""#), "{text}");
    assert_eq!(serde_json::from_str::<UndoLabels>(&text).unwrap(), labels);
}
