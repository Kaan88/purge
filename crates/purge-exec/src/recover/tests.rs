//! Unit tests of the probe tables: what recovery concludes from what it found. Pure: nothing here
//! touches the system. The crash matrix on real objects is in `tests/crash.rs`.

use std::path::Path;

use purge_model::exec::journal::ItemFacts;
use purge_model::exec::op::{BootMovePair, Inverse};

use super::*;
use crate::locked::MemoryPendingRenames;
use crate::regbackup::Change;

fn is_attention(probe: &Probe) -> bool {
    matches!(probe, Probe::Attention { .. })
}

fn done() -> Probe {
    Probe::Done(ItemOutcome::Done)
}

#[test]
fn a_move_is_judged_by_where_the_recorded_item_is() {
    use Seen::{Missing, Other, Recorded, Unknown};
    // Rows: the source path; columns: the quarantine path.
    for source in [Missing, Recorded, Other, Unknown] {
        for quarantine in [Missing, Recorded, Other, Unknown] {
            let probe = probe_move(source, quarantine);
            let expected = match (source, quarantine) {
                // Still in place, and the quarantine does not hold it.
                (Recorded, Missing | Other) => Some(Probe::NotDone),
                // In quarantine, and no longer in place (something new may have taken the path).
                (Missing | Other, Recorded) => Some(done()),
                // Both, neither, or not readable.
                _ => None,
            };
            match expected {
                Some(expected) => assert_eq!(probe, expected, "{source:?} {quarantine:?}"),
                None => assert!(is_attention(&probe), "{source:?} {quarantine:?}: {probe:?}"),
            }
        }
    }
}

#[test]
fn a_directory_removal_is_judged_by_what_is_at_its_path() {
    assert_eq!(probe_remove_dir(Seen::Recorded), Probe::NotDone);
    assert_eq!(probe_remove_dir(Seen::Missing), done());
    assert!(is_attention(&probe_remove_dir(Seen::Other)));
    assert!(is_attention(&probe_remove_dir(Seen::Unknown)));
}

#[test]
fn a_key_delete_is_judged_by_the_tree_next_to_its_backup() {
    assert_eq!(probe_key(&TreeState::Absent), done());
    assert_eq!(probe_key(&TreeState::Intact), Probe::NotDone);
    assert_eq!(
        probe_key(&TreeState::Partial { missing_keys: 3 }),
        Probe::Partial { missing_keys: 3 }
    );
    let diverged = probe_key(&TreeState::Diverged {
        at: "Sub".to_owned(),
        change: Change::ValuesDiffer,
    });
    assert!(
        matches!(&diverged, Probe::Attention { detail } if detail.contains("Sub")),
        "{diverged:?}"
    );
}

#[test]
fn a_value_delete_is_judged_by_type_and_bytes() {
    let backup = (1u32, &b"a\0b\0"[..]);
    assert_eq!(probe_value(None, backup), done());
    assert_eq!(probe_value(Some(backup), backup), Probe::NotDone);
    // Same bytes under another type, and other bytes under the same type.
    assert!(is_attention(&probe_value(Some((2, backup.1)), backup)));
    assert!(is_attention(&probe_value(Some((1, b"a\0c\0")), backup)));
    assert!(is_attention(&probe_value(Some((1, b"")), backup)));
}

#[test]
fn a_segment_edit_is_judged_by_the_hash_of_the_value() {
    let original = sha256_bytes(b"keep;vendor;also");
    let written = sha256_bytes(b"keep;also");
    assert_eq!(probe_segment(Some(b"keep;also"), original, written), done());
    assert_eq!(
        probe_segment(Some(b"keep;vendor;also"), original, written),
        Probe::NotDone
    );
    assert!(is_attention(&probe_segment(
        Some(b"keep;other"),
        original,
        written
    )));
    assert!(is_attention(&probe_segment(None, original, written)));
}

#[test]
fn a_package_removal_is_judged_by_the_listing() {
    assert_eq!(probe_package(Some(false)), done());
    assert_eq!(probe_package(Some(true)), Probe::NotDone);
    assert!(is_attention(&probe_package(None)));
}

#[test]
fn an_interrupted_retry_ends_with_where_the_item_is() {
    assert_eq!(retry_outcome(&done()), ItemOutcome::Done);
    // Still in place: held for the next retry.
    assert_eq!(retry_outcome(&Probe::NotDone), ItemOutcome::HeldRetry);
    for unclear in [
        Probe::attention("neither"),
        Probe::Partial { missing_keys: 1 },
    ] {
        assert!(
            matches!(retry_outcome(&unclear), ItemOutcome::Failed { .. }),
            "{unclear:?}"
        );
    }
    assert!(matches!(
        retry_outcome(&Probe::attention("neither")),
        ItemOutcome::Failed {
            code: FailCode::VerifyFailed,
            ..
        }
    ));
}

#[test]
fn a_registered_boot_move_is_found_before_the_item_is_looked_at() {
    // The intent of a quarantine move whose boot-time move stands in the list exactly once.
    let original = r"C:\Program Files\Vendor\busy.dll";
    let quarantine = r"C:\ProgramData\Purge\Quarantine\S\000001\busy.dll";
    let intent = Intent {
        op: OpId(1),
        item: purge_model::CandidateId("c-1".to_owned()),
        exec_op: ExecOp::QuarantineMove {
            path: original.to_owned(),
        },
        inverse: Inverse::MoveBack {
            quarantine_path: quarantine.to_owned(),
            original_path: original.to_owned(),
            file_id: purge_model::exec::op::FileIdHex([7; 16]),
            volume_serial: 1,
        },
        definition: None,
        pre: ItemFacts::Absent,
    };
    let pair =
        purge_win::fs_write::pending_pair(Path::new(original), Path::new(quarantine)).unwrap();
    let once = MemoryPendingRenames::with_pairs(&[(pair.src.as_str(), pair.dst.as_str())]);
    assert_eq!(
        locked::pending_after_crash(&intent, &once),
        Ok(Some(ItemOutcome::PendingReboot {
            pair: BootMovePair {
                src: pair.src.clone(),
                dst: pair.dst.clone(),
            },
            confirmed: true,
        }))
    );
    // Not listed: the probe falls back to the item itself.
    let empty = MemoryPendingRenames::with_pairs(&[]);
    assert_eq!(locked::pending_after_crash(&intent, &empty), Ok(None));
    // Listed twice, or a list that cannot be read: a restart may still move the item, so nothing may
    // move it by handle now (M7 of the final M2 review; before, both fell back to the item and a
    // `NotDone` probe completed the move by handle with the pair still registered).
    let twice = MemoryPendingRenames::with_pairs(&[
        (pair.src.as_str(), pair.dst.as_str()),
        (pair.src.as_str(), pair.dst.as_str()),
    ]);
    let why = locked::pending_after_crash(&intent, &twice).unwrap_err();
    assert!(why.contains("2 times"), "{why}");
    let mut broken = MemoryPendingRenames::default();
    broken.fail = Some(FsError::Other(1450));
    let why = locked::pending_after_crash(&intent, &broken).unwrap_err();
    assert!(why.contains("cannot be read"), "{why}");
}

#[test]
fn a_missing_journal_is_told_from_a_damaged_one() {
    let not_found = JournalError::Store(StorageError::Io {
        op: "open",
        path: Path::new(r"C:\x\journal.jsonl").to_path_buf(),
        source: FsError::NotFound,
    });
    assert!(journal_missing(&not_found));
    let denied = JournalError::Store(StorageError::Io {
        op: "open",
        path: Path::new(r"C:\x\journal.jsonl").to_path_buf(),
        source: FsError::AccessDenied,
    });
    assert!(!journal_missing(&denied));
    assert!(!journal_missing(&JournalError::Poisoned));
}
