//! Round trips: every action type is done through `execute` and undone through `undo`, and the
//! machine is compared with what it was before, field by field. Unelevated, on a temp directory and
//! a test-created `HKU\<SID>\Software\PurgeTest-<random>` subtree; packages and the boot-time move
//! list are stand-ins.

#![cfg(feature = "test-support")]

mod common;

use std::os::windows::fs::OpenOptionsExt;

use common::*;
use purge_exec::journal::{JournalWriter, UndoState};
use purge_exec::recover;
use purge_exec::storage::{BackupKind, backup_rel};
use purge_exec::undo::{LABELS_SCHEMA, UndoError, UndoLabels, UndoRequest, UndoSelection, undo};
use purge_model::exec::journal::{Expire, UndoConflict, UndoOutcome};
use purge_model::exec::op::{ItemOutcome, OpId};
use purge_model::exec::session::{RetentionClass, SessionState, UndoResult};
use purge_model::{Action, FileTime};
use purge_win::reg::{REG_BINARY, REG_MULTI_SZ, REG_SZ};

const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;

fn set_attributes(path: &str, attributes: u32) {
    use std::os::windows::fs::MetadataExt;
    let now = std::fs::metadata(ext(path)).unwrap().file_attributes();
    let status = std::process::Command::new("attrib")
        .args([
            if attributes & FILE_ATTRIBUTE_READONLY != 0 {
                "+R"
            } else {
                "-R"
            },
            if attributes & FILE_ATTRIBUTE_HIDDEN != 0 {
                "+H"
            } else {
                "-H"
            },
            path,
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let after = std::fs::metadata(ext(path)).unwrap().file_attributes();
    assert_ne!(now, after, "{path}");
}

/// How one op's undo ended, by plan item.
fn result_of<'a>(
    output: &'a purge_exec::undo::UndoOutput,
    read: &purge_exec::journal::JournalRead,
    id: &str,
) -> &'a UndoResult {
    let op = op_of(read, id);
    &output
        .report
        .items
        .iter()
        .find(|item| item.op == op)
        .unwrap_or_else(|| panic!("{id} is not in the undo report"))
        .result
}

fn restored() -> UndoResult {
    UndoResult::Finished {
        outcome: UndoOutcome::Restored,
    }
}

fn conflict(result: &UndoResult) -> &UndoConflict {
    match result {
        UndoResult::Conflict { conflict, .. } => conflict,
        other => panic!("not a conflict: {other:?}"),
    }
}

/// A long directory chain below `root`: the returned file's path is well over `MAX_PATH`.
fn long_file(s: &Scratch) -> String {
    let mut rel = String::from("long");
    for n in 0..5 {
        rel.push('\\');
        rel.push_str(&format!("{n}-{}", "d".repeat(58)));
    }
    let file = s.file(&format!(r"{rel}\deep file.bin"), b"deep");
    assert!(file.len() > 300);
    file
}

// ---------------------------------------------------------------------------------------------------
// Every action type, there and back
// ---------------------------------------------------------------------------------------------------

#[test]
fn every_action_type_round_trips() {
    let mut rig = Rig::new("roundtrip");
    let k = TestKey::new();
    let s = &rig.s;

    // Files: plain, read-only, hidden, with an alternate data stream, over MAX_PATH.
    let plain = s.file(r"app\plain.txt", b"plain");
    let readonly = s.file(r"app\readonly.txt", b"read only");
    set_attributes(&readonly, FILE_ATTRIBUTE_READONLY);
    let hidden = s.file(r"app\hidden.txt", b"hidden");
    set_attributes(&hidden, FILE_ATTRIBUTE_HIDDEN);
    let ads = s.file(r"app\ads.txt", b"main stream");
    std::fs::write(format!("{ads}:extra"), b"second stream").unwrap();
    let long = long_file(s);
    // A whole directory, holding a hard-link pair and a nested directory.
    s.file(r"app\tree\one.bin", b"111");
    s.file(r"app\tree\deep\two.bin", b"2222");
    std::fs::hard_link(
        s.path(r"app\tree\one.bin"),
        s.path(r"app\tree\deep\one-again.bin"),
    )
    .unwrap();
    let tree = s.path(r"app\tree");
    // Empty directories, one inside the other, and the directory everything was in.
    let inner = s.dir(r"app\outer\inner");
    let outer = s.path(r"app\outer");
    let app = s.path("app");

    // A key tree: a class, a security descriptor of its own, values of every awkward shape, and a
    // volatile subkey.
    k.create_with("", "Tree", "VendorClass", None, false);
    k.set("Tree", "Name", REG_SZ, &utf16z("vendor"));
    k.set("Tree", "", REG_SZ, &utf16z("default value"));
    k.set("Tree", "Odd", REG_SZ, &[0x41, 0x00, 0x42]);
    k.set("Tree", "Empty", REG_BINARY, &[]);
    k.set("Tree", "Typeless", 0x1234_5678, &[1, 2, 3, 4, 5]);
    let sddl = format!("D:P(A;CI;KA;;;{})(A;CI;KR;;;WD)", k.sid);
    k.create_with("Tree", "Guarded", "", Some(&sddl), false);
    k.set(r"Tree\Guarded", "N", REG_SZ, &utf16z("1"));
    k.create(r"Tree\Guarded\Leaf");
    k.create_with("Tree", "Volatile", "Gone at reboot", None, true);
    k.set(r"Tree\Volatile", "V", REG_BINARY, &[9, 9, 9]);
    // A value, a segment of a list, and an empty key.
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
    k.create_with("", "EmptyKey", "EmptyClass", None, false);

    let mut tree_item = quarantine("c-tree", &tree);
    tree_item.children = vec![cid("c-tree-1")];
    let absorbed = vec![quarantine("c-tree-1", &s.path(r"app\tree\one.bin"))];
    let items = vec![
        quarantine("c-plain", &plain),
        quarantine("c-readonly", &readonly),
        quarantine("c-hidden", &hidden),
        quarantine("c-ads", &ads),
        quarantine("c-long", &long),
        tree_item,
        safe("c-inner", path(&inner), Action::RemoveDirIfEmpty),
        safe("c-outer", path(&outer), Action::RemoveDirIfEmpty),
        safe("c-app", path(&app), Action::RemoveDirIfEmpty),
        safe("c-key", key(&k.wire("Tree")), Action::DeleteKey),
        safe("c-val", value(&k.wire("Vals"), "Gone"), Action::DeleteValue),
        safe(
            "c-seg",
            segment(&k.wire("Seg"), "List", "vendor"),
            Action::EditSegment,
        ),
        safe(
            "c-emptykey",
            key(&k.wire("EmptyKey")),
            Action::RemoveDirIfEmpty,
        ),
    ];
    let count = items.len();

    let files_before = snap_tree(&app);
    let long_before = snap_tree(&s.path("long"));
    let keys_before = k.snap();
    assert!(files_before.iter().any(|f| f.n_links == 2));
    assert!(files_before.iter().any(|f| !f.streams.is_empty()));

    let done = rig.run(request(items, absorbed));
    let read = rig.journal(&done.session);
    assert_eq!(
        outcomes(&read),
        vec![Some(ItemOutcome::Done); count],
        "{:#?}",
        done.report
    );
    assert!(!exists(&app));
    assert!(!exists(&long));
    assert!(!k.exists("Tree") && !k.exists("EmptyKey"));
    assert_eq!(k.get("Vals", "Gone"), None);
    assert_eq!(k.get("Seg", "List").unwrap().1, multi_sz(&["keep", "also"]));

    let undone = rig.undo_all(&done.session);
    assert_eq!(undone.stopped, None);
    for item in &undone.report.items {
        assert_eq!(item.result, restored(), "{item:?}");
    }
    assert_eq!(undone.report.items.len(), count);
    assert_eq!(undone.report.counts.restored as usize, count);
    assert_eq!(undone.report.counts, undone.report.tally());
    assert_eq!(undone.report.state, SessionState::Undone);
    assert!(undone.pulled_in.is_empty() && undone.already_undone.is_empty());

    // The directories come first (in reverse), then everything else in exact reverse order.
    let order: Vec<OpId> = undone.report.items.iter().map(|item| item.op).collect();
    let op = |id: &str| op_of(&read, id);
    let mut expected = vec![op("c-app"), op("c-outer"), op("c-inner")];
    expected.extend(
        [
            "c-emptykey",
            "c-seg",
            "c-val",
            "c-key",
            "c-tree",
            "c-long",
            "c-ads",
            "c-hidden",
            "c-readonly",
            "c-plain",
        ]
        .map(op),
    );
    assert_eq!(order, expected);

    // Everything is back: bytes, attributes, streams, times, security, file ids (a recreated
    // directory gets a new id), the hard-link pair, key classes, volatility and raw values.
    assert_eq!(
        without_dir_ids(snap_tree(&app)),
        without_dir_ids(files_before.clone())
    );
    let kept_ids = |tree: &[FileSnap]| {
        tree.iter()
            .filter(|f| !f.is_dir || f.rel.starts_with("tree"))
            .map(|f| (f.rel.clone(), f.id))
            .collect::<Vec<_>>()
    };
    assert_eq!(kept_ids(&snap_tree(&app)), kept_ids(&files_before));
    assert_eq!(snap_tree(&rig.s.path("long")), long_before);
    assert_eq!(k.snap(), keys_before);

    // The journal, the index and the labels say so.
    let after = rig.journal(&done.session);
    assert!(
        after
            .state
            .ops()
            .all(|op| op.undo == UndoState::Finished(UndoOutcome::Restored))
    );
    let entry = rig.entry(&done.session).unwrap();
    assert_eq!(entry.state, SessionState::Undone);
    assert_eq!(entry.undone as usize, count);
    assert_eq!(entry.journal, Some(after.state.mark()));
    assert!(undone.index_updated);
    let labels_file = undone.labels_file.clone().unwrap();
    let labels: UndoLabels = serde_json::from_slice(
        &std::fs::read(rig.session(&done.session).path().join(&labels_file)).unwrap(),
    )
    .unwrap();
    assert_eq!(labels.schema, LABELS_SCHEMA);
    assert_eq!(labels.session, done.session);
    assert_eq!(labels.labels.len(), count);
    assert!(recover::pending(&rig.roots).unwrap().sessions.is_empty());

    // A second undo finds nothing to do and writes nothing.
    let store = rig.store_files();
    let again = rig.undo_all(&done.session);
    assert!(again.report.items.is_empty());
    assert_eq!(again.already_undone.len(), count);
    assert_eq!(again.report.state, SessionState::Undone);
    assert_eq!(again.labels_file, None);
    assert_eq!(rig.store_files(), store);
    assert_eq!(k.snap(), keys_before);
}

// ---------------------------------------------------------------------------------------------------
// Partial undo
// ---------------------------------------------------------------------------------------------------

#[test]
fn a_partial_undo_pulls_in_what_its_restores_depend_on() {
    let mut rig = Rig::new("partial");
    let k = TestKey::new();
    let s = &rig.s;
    let a = s.file(r"app\sub\a.txt", b"aaa");
    let b = s.file(r"app\sub\b.txt", b"bbb");
    let other = s.file(r"other\c.txt", b"ccc");
    let sub = s.path(r"app\sub");
    let app = s.path("app");
    k.create(r"Tree\Sub");
    // The value's key is below the key the plan deletes afterwards (a value directly in that key
    // would change it between its validation and its delete).
    k.set(r"Tree\Sub", "Gone", REG_SZ, &utf16z("bye"));
    k.set(r"Tree\Sub", "Stays", REG_SZ, &utf16z("hi"));
    k.create("Unrelated");
    k.set("Unrelated", "V", REG_SZ, &utf16z("v"));

    let items = vec![
        quarantine("c-a", &a),
        quarantine("c-b", &b),
        quarantine("c-other", &other),
        safe("c-sub", path(&sub), Action::RemoveDirIfEmpty),
        safe("c-app", path(&app), Action::RemoveDirIfEmpty),
        safe(
            "c-val",
            value(&k.wire(r"Tree\Sub"), "Gone"),
            Action::DeleteValue,
        ),
        safe("c-key", key(&k.wire("Tree")), Action::DeleteKey),
        safe(
            "c-unrelated",
            value(&k.wire("Unrelated"), "V"),
            Action::DeleteValue,
        ),
    ];
    let files_before = snap_tree(&s.root);
    let keys_before = k.snap();
    let done = rig.run(request(items, Vec::new()));
    let read = rig.journal(&done.session);
    assert_eq!(
        outcomes(&read),
        vec![Some(ItemOutcome::Done); 8],
        "{:#?}",
        done.report
    );
    let op = |id: &str| op_of(&read, id);

    // One file and one value: the directories above the file and the key holding the value come
    // back with them, and nothing else does.
    let partial = rig.undo(
        &done.session,
        UndoSelection::Items(vec![cid("c-a"), cid("c-val")]),
    );
    assert_eq!(
        partial.pulled_in,
        vec![op("c-sub"), op("c-app"), op("c-key")]
    );
    let order: Vec<OpId> = partial.report.items.iter().map(|item| item.op).collect();
    assert_eq!(
        order,
        vec![
            op("c-app"),
            op("c-sub"),
            op("c-key"),
            op("c-val"),
            op("c-a")
        ]
    );
    assert!(
        partial
            .report
            .items
            .iter()
            .all(|item| item.result == restored())
    );
    assert_eq!(partial.report.state, SessionState::PartiallyUndone);
    assert_eq!(
        rig.entry(&done.session).unwrap().state,
        SessionState::PartiallyUndone
    );
    assert_eq!(rig.entry(&done.session).unwrap().undone, 5);
    assert!(exists(&a) && !exists(&b) && !exists(&other));
    assert_eq!(k.get(r"Tree\Sub", "Gone").unwrap().1, utf16z("bye"));
    assert_eq!(k.get("Unrelated", "V"), None);
    // Only what the user asked for is a label.
    let labels: UndoLabels = serde_json::from_slice(
        &std::fs::read(
            rig.session(&done.session)
                .path()
                .join(partial.labels_file.clone().unwrap()),
        )
        .unwrap(),
    )
    .unwrap();
    let labelled: Vec<&str> = labels.labels.iter().map(|l| l.item.0.as_str()).collect();
    assert_eq!(labelled, ["c-val", "c-a"]);

    // The rest follows, and the ops already undone are left alone.
    let rest = rig.undo_all(&done.session);
    assert_eq!(rest.already_undone.len(), 5);
    let order: Vec<OpId> = rest.report.items.iter().map(|item| item.op).collect();
    assert_eq!(order, vec![op("c-unrelated"), op("c-other"), op("c-b")]);
    assert_eq!(rest.report.state, SessionState::Undone);
    assert_eq!(
        without_dir_ids(snap_tree(&rig.s.root))
            .into_iter()
            .filter(|f| !f.rel.starts_with("data") && !f.rel.is_empty())
            .collect::<Vec<_>>(),
        without_dir_ids(files_before)
            .into_iter()
            .filter(|f| !f.rel.starts_with("data") && !f.rel.is_empty())
            .collect::<Vec<_>>()
    );
    assert_eq!(k.snap(), keys_before);
}

/// Item 3 of the M2 recovery fix pass: the index entry follows the undo. After the run it holds the
/// commit's figures; after a partial undo it is `PartiallyUndone` with the undone count and only the
/// bytes still kept (an item moved back no longer counts); after the full undo it is `Undone`, with
/// nothing left in quarantine (the registry backup file stays until expiry and still counts). Before
/// the pass the entry kept the commit's bytes.
#[test]
fn the_index_entry_follows_a_partial_and_a_full_undo() {
    let mut rig = Rig::new("entry-undo");
    let k = TestKey::new();
    let a = rig.s.file(r"app\a.bin", &[1u8; 1000]);
    let b = rig.s.file(r"app\b.bin", &[2u8; 3000]);
    k.create("Vals");
    k.set("Vals", "Gone", REG_SZ, &utf16z("bye"));
    let items = vec![
        quarantine("c-a", &a),
        quarantine("c-b", &b),
        safe("c-val", value(&k.wire("Vals"), "Gone"), Action::DeleteValue),
    ];
    let done = rig.run(request(items, Vec::new()));
    let id = done.session.clone();
    let read = rig.journal(&id);
    assert_eq!(outcomes(&read), vec![Some(ItemOutcome::Done); 3]);
    let committed = read.state.commit().unwrap().backup_bytes;
    let backup_file = read
        .state
        .op(op_of(&read, "c-val"))
        .unwrap()
        .intent
        .as_ref()
        .unwrap()
        .inverse
        .backup()
        .unwrap()
        .bytes;
    assert_eq!(committed, 1000 + 3000 + backup_file);
    let total = |entry: &purge_model::exec::session::SessionSummary| {
        entry.usage.iter().map(|u| u.bytes).sum::<u64>()
    };
    let entry = rig.entry(&id).unwrap();
    assert_eq!(
        (entry.state, entry.undone, entry.backup_bytes),
        (SessionState::Committed, 0, committed)
    );
    assert_eq!(total(&entry), committed);

    // Partial: the 1000-byte file.
    let partial = rig.undo(&id, UndoSelection::Items(vec![cid("c-a")]));
    assert_eq!(partial.report.state, SessionState::PartiallyUndone);
    let entry = rig.entry(&id).unwrap();
    assert_eq!(
        (entry.state, entry.undone, entry.backup_bytes),
        (SessionState::PartiallyUndone, 1, 3000 + backup_file)
    );
    assert_eq!(total(&entry), 3000 + backup_file);
    assert!(exists(&a) && !exists(&b));

    // Full: the rest.
    let rest = rig.undo_all(&id);
    assert_eq!(rest.report.state, SessionState::Undone);
    let entry = rig.entry(&id).unwrap();
    assert_eq!(
        (entry.state, entry.undone, entry.backup_bytes),
        (SessionState::Undone, 3, backup_file)
    );
    assert_eq!(total(&entry), backup_file);
    assert!(exists(&a) && exists(&b));
    assert_eq!(k.get("Vals", "Gone").unwrap().1, utf16z("bye"));
}

// ---------------------------------------------------------------------------------------------------
// Conflicts
// ---------------------------------------------------------------------------------------------------

#[test]
fn conflicts_are_reported_and_never_forced_and_the_other_items_proceed() {
    let mut rig = Rig::new("conflicts");
    let k = TestKey::new();
    let s = &rig.s;
    let taken = s.file(r"app\taken.txt", b"original");
    let expired = s.file(r"app\expired.txt", b"expired");
    let fine = s.file(r"app\fine.txt", b"fine");
    for name in ["Differs", "Tampered", "Missing", "Fine"] {
        k.create(name);
        k.set(name, "N", REG_SZ, &utf16z(name));
    }
    k.create("Vals");
    k.set("Vals", "Changed", REG_SZ, &utf16z("before"));

    let items = vec![
        quarantine("c-taken", &taken),
        quarantine("c-expired", &expired),
        quarantine("c-fine", &fine),
        safe("c-differs", key(&k.wire("Differs")), Action::DeleteKey),
        safe("c-tampered", key(&k.wire("Tampered")), Action::DeleteKey),
        safe("c-missing", key(&k.wire("Missing")), Action::DeleteKey),
        safe("c-finekey", key(&k.wire("Fine")), Action::DeleteKey),
        safe(
            "c-val",
            value(&k.wire("Vals"), "Changed"),
            Action::DeleteValue,
        ),
    ];
    let done = rig.run(request(items, Vec::new()));
    let read = rig.journal(&done.session);
    assert_eq!(
        outcomes(&read),
        vec![Some(ItemOutcome::Done); 8],
        "{:#?}",
        done.report
    );
    let session = rig.session(&done.session);

    // Something else took the file's place; the key and the value came back differently.
    std::fs::write(ext(&taken), b"someone else's").unwrap();
    k.create("Differs");
    k.set("Differs", "N", REG_SZ, &utf16z("another"));
    k.set("Vals", "Changed", REG_SZ, &utf16z("after"));
    // One backup was changed (same length), one is gone, and one op's data expired.
    let tampered = session
        .path()
        .join(backup_rel(BackupKind::Registry, op_of(&read, "c-tampered")));
    let mut bytes = std::fs::read(&tampered).unwrap();
    let at = bytes.iter().position(|b| *b == b'T').unwrap();
    bytes[at] = b'U';
    std::fs::write(&tampered, bytes).unwrap();
    std::fs::remove_file(
        session
            .path()
            .join(backup_rel(BackupKind::Registry, op_of(&read, "c-missing"))),
    )
    .unwrap();
    {
        let mut journal = JournalWriter::open_append(&session).unwrap();
        journal
            .expire(Expire {
                at: FileTime(1),
                op: op_of(&read, "c-expired"),
                class: RetentionClass::Quarantine,
                bytes: 7,
            })
            .unwrap();
    }

    let undone = rig.undo_all(&done.session);
    let of = |id: &str| result_of(&undone, &read, id);
    assert_eq!(conflict(of("c-taken")), &UndoConflict::DestinationExists);
    assert_eq!(conflict(of("c-expired")), &UndoConflict::Expired);
    assert_eq!(conflict(of("c-differs")), &UndoConflict::KeyExists);
    assert_eq!(conflict(of("c-tampered")), &UndoConflict::BackupTampered);
    assert_eq!(conflict(of("c-missing")), &UndoConflict::BackupMissing);
    assert_eq!(conflict(of("c-val")), &UndoConflict::ValueDiffers);
    assert_eq!(of("c-fine"), &restored());
    assert_eq!(of("c-finekey"), &restored());
    assert_eq!(undone.report.counts.conflicts, 6);
    assert_eq!(undone.report.counts.restored, 2);
    assert_eq!(undone.report.state, SessionState::PartiallyUndone);
    assert_eq!(
        rig.entry(&done.session).unwrap().state,
        SessionState::PartiallyUndone
    );

    // Nothing was forced: what stood in the way is untouched, and nothing half restored exists.
    assert_eq!(std::fs::read(ext(&taken)).unwrap(), b"someone else's");
    assert!(exists(&quarantine_path(&read, 1)));
    assert!(!exists(&expired));
    assert_eq!(k.get("Differs", "N").unwrap().1, utf16z("another"));
    assert_eq!(k.get("Vals", "Changed").unwrap().1, utf16z("after"));
    assert!(!k.exists("Tampered") && !k.exists("Missing"));
    assert_eq!(std::fs::read(ext(&fine)).unwrap(), b"fine");
    assert_eq!(k.get("Fine", "N").unwrap().1, utf16z("Fine"));

    // A conflict may be tried again once what stood in the way is gone.
    std::fs::remove_file(ext(&taken)).unwrap();
    k.set("Vals", "Changed", REG_SZ, &utf16z("before"));
    let again = rig.undo(
        &done.session,
        UndoSelection::Items(vec![cid("c-taken"), cid("c-val"), cid("c-fine")]),
    );
    assert_eq!(again.already_undone, vec![op_of(&read, "c-fine")]);
    assert_eq!(result_of(&again, &read, "c-taken"), &restored());
    assert_eq!(
        result_of(&again, &read, "c-val"),
        &UndoResult::Finished {
            outcome: UndoOutcome::AlreadyRestored
        }
    );
    assert_eq!(std::fs::read(ext(&taken)).unwrap(), b"original");
}

// ---------------------------------------------------------------------------------------------------
// What cannot be undone, and what is refused
// ---------------------------------------------------------------------------------------------------

#[test]
fn a_removed_package_is_reported_as_irreversible() {
    let mut rig = Rig::new("package");
    rig.packages.install();
    let file = rig.s.file(r"app\a.txt", b"a");
    let mut request = request(
        vec![quarantine("c-file", &file), package("c-pkg")],
        Vec::new(),
    );
    request.allow_irreversible = true;
    let done = rig.run(request);
    let read = rig.journal(&done.session);
    assert_eq!(
        outcomes(&read),
        vec![Some(ItemOutcome::Done); 2],
        "{:#?}",
        done.report
    );
    assert!(!rig.packages.installed());

    let undone = rig.undo_all(&done.session);
    assert_eq!(
        conflict(result_of(&undone, &read, "c-pkg")),
        &UndoConflict::Irreversible
    );
    assert_eq!(result_of(&undone, &read, "c-file"), &restored());
    assert_eq!(undone.report.state, SessionState::PartiallyUndone);
    assert_eq!(undone.stopped, None);
    // Nothing was installed again, and only the removal itself was ever asked of the backend.
    assert!(!rig.packages.installed());
    assert_eq!(rig.packages.removed.borrow().len(), 1);
    assert!(exists(&file));
}

#[test]
fn undo_is_refused_for_another_plan_an_unknown_item_and_an_unknown_session() {
    let mut rig = Rig::new("refused");
    let file = rig.s.file(r"app\a.txt", b"a");
    let done = rig.run(request(vec![quarantine("c-file", &file)], Vec::new()));
    let store = rig.store_files();
    let plan_hash = rig.journal(&done.session).state.header().plan_hash;

    let wrong_hash = UndoRequest {
        session: done.session.clone(),
        selection: UndoSelection::All,
        plan_hash: Some(purge_exec::journal::sha256_bytes(b"another plan")),
    };
    assert!(matches!(
        undo(&wrong_hash, rig.undo_env()),
        Err(UndoError::PlanMismatch { .. })
    ));
    let unknown_item = UndoRequest {
        session: done.session.clone(),
        selection: UndoSelection::Items(vec![cid("c-nobody")]),
        plan_hash: Some(plan_hash),
    };
    assert!(matches!(
        undo(&unknown_item, rig.undo_env()),
        Err(UndoError::UnknownItem(item)) if item == "c-nobody"
    ));
    let unknown_session = UndoRequest {
        session: "20200101T000000Z-0123456789abcdef".parse().unwrap(),
        selection: UndoSelection::All,
        plan_hash: None,
    };
    assert!(matches!(
        undo(&unknown_session, rig.undo_env()),
        Err(UndoError::Store(_))
    ));
    assert_eq!(rig.store_files(), store);
    assert!(!exists(&file));

    // With the right hash the undo runs.
    let right = UndoRequest {
        session: done.session.clone(),
        selection: UndoSelection::All,
        plan_hash: Some(plan_hash),
    };
    let undone = undo(&right, rig.undo_env()).unwrap();
    assert_eq!(undone.report.counts.restored, 1);
    assert!(exists(&file));
}

#[test]
fn a_journal_cut_behind_its_index_mark_is_refused_as_damaged() {
    let mut rig = Rig::new("cut");
    let a = rig.s.file(r"app\a.txt", b"a");
    let b = rig.s.file(r"app\b.txt", b"b");
    let done = rig.run(request(
        vec![quarantine("c-a", &a), quarantine("c-b", &b)],
        Vec::new(),
    ));
    // Cut the journal at a line boundary: the last line (the commit) goes.
    let journal = rig.session(&done.session).path().join("journal.jsonl");
    let text = std::fs::read_to_string(&journal).unwrap();
    let cut = text.trim_end_matches('\n').rfind('\n').unwrap() + 1;
    std::fs::OpenOptions::new()
        .write(true)
        .share_mode(7)
        .open(&journal)
        .unwrap()
        .set_len(cut as u64)
        .unwrap();

    let request = UndoRequest {
        session: done.session.clone(),
        selection: UndoSelection::All,
        plan_hash: None,
    };
    assert!(matches!(
        undo(&request, rig.undo_env()),
        Err(UndoError::Journal(
            purge_exec::journal::JournalError::IndexMismatch { .. }
        ))
    ));
    assert!(matches!(
        recover::resume(&done.session, rig.recover_env()),
        Err(recover::RecoverError::Journal(_))
    ));
    let pending = recover::pending(&rig.roots).unwrap();
    assert_eq!(pending.sessions.len(), 1);
    assert_eq!(pending.sessions[0].kind, recover::PendingKind::Damaged);
    assert!(!exists(&a) && !exists(&b));
}

/// Item 2 of the M2 recovery fix pass: a finished session whose report was never written (a crash
/// after the end of the run) is listed for recovery, and recovery writes the report from the journal
/// and the scan copy, once. Before the pass such a session was not listed and never got a report.
#[test]
fn a_finished_session_without_its_report_gets_one_from_recovery() {
    let mut rig = Rig::new("no-report");
    let a = rig.s.file(r"app\a.txt", b"a");
    let done = rig.run(request(vec![quarantine("c-a", &a)], Vec::new()));
    let report = rig.session(&done.session).path().join("report.json");
    std::fs::remove_file(&report).unwrap();
    let listed = recover::pending(&rig.roots).unwrap();
    assert_eq!(listed.sessions.len(), 1, "{listed:#?}");
    assert_eq!(listed.sessions[0].kind, recover::PendingKind::Unindexed);
    assert!(listed.sessions[0].detail.contains("report"));

    let out = rig.resume(&done.session);
    assert!(out.report_written, "{out:#?}");
    let written = out.report.unwrap();
    assert_eq!(written.state, SessionState::Committed);
    assert_eq!(written.counts.done, 1);
    let on_disk: purge_model::exec::session::ExecReport =
        serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    assert_eq!(on_disk, written);
    assert!(recover::pending(&rig.roots).unwrap().sessions.is_empty());
    let again = rig.resume(&done.session);
    assert!(again.report.is_none() && !again.report_written);
    assert!(!exists(&a));
}
