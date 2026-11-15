//! Tests of expiry on real objects, unelevated: each test works in its own fresh directory under the
//! temp directory, with a relaxed store and a real journal inside it. Junctions, symbolic links,
//! mount-point-style junctions, hard links, read-only files, long and deep paths and locks are built
//! for real. Canaries outside the store are compared byte for byte after every purge, and every object
//! the walk opened with delete access is checked to lie inside the session's quarantine.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use purge_model::exec::journal::{
    FileFacts, GateExemptions, Header, Intent, ItemFacts, JournalSchema, Reconcile, RegFacts,
    Validated,
};
use purge_model::exec::op::{
    BackupRef, BootMovePair, ExecOp, FileIdHex, Inverse, ItemOutcome, OpId,
};
use purge_model::exec::session::{
    Expiry, RetentionClass, SessionIndex, SessionState, SessionSummary, VolumeUsage,
};
use purge_model::{CandidateId, FileTime, ScanMode, Target};
use purge_win::fs::FileHandle;
use purge_win::fs_write::{FILE_ATTRIBUTE_READONLY, MoveHandle, extended_path};

use super::*;
use crate::journal::{JournalWriter, sha256_bytes};
use crate::storage::{BackupKind, SCAN_FILE, SessionDir, StorageRoots, backup_rel};

// ---------------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------------

static COUNTER: AtomicU32 = AtomicU32::new(0);

const DAY: i64 = 86_400;
/// The start of every test session: 2026-11-15T00:00:00Z.
const START: i64 = 1_794_700_800;

fn at_day(days: i64) -> FileTime {
    FileTime::from_unix_secs(START + days * DAY)
}

/// A fresh directory below the temp directory (its final, long-form path), removed on drop with
/// read-only, hidden and system attributes cleared first; links below it are removed as links.
struct Scratch {
    root: String,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "purge-expiry-{tag}-{:x}-{nanos:x}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let final_path = FileHandle::open(&dir).unwrap().final_path().unwrap();
        Scratch {
            root: final_path
                .strip_prefix(r"\\?\")
                .unwrap_or(&final_path)
                .to_owned(),
        }
    }

    fn path(&self, rel: &str) -> String {
        format!(r"{}\{rel}", self.root)
    }

    fn dir(&self, rel: &str) -> String {
        let p = self.path(rel);
        std::fs::create_dir_all(ext(&p)).unwrap();
        p
    }

    fn file(&self, rel: &str, data: &[u8]) -> String {
        let p = self.path(rel);
        std::fs::create_dir_all(ext(&p).parent().unwrap()).unwrap();
        std::fs::write(ext(&p), data).unwrap();
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = Command::new("cmd")
            .args(["/c", "attrib", "-R", "-H", "-S", "/S", "/D"])
            .arg(format!(r"{}\*", self.root))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = std::fs::remove_dir_all(ext(&self.root));
    }
}

/// The `\\?\` form of an absolute path.
fn ext(path: &str) -> PathBuf {
    extended_path(Path::new(path)).unwrap()
}

fn exists(path: &str) -> bool {
    std::fs::symlink_metadata(ext(path)).is_ok()
}

fn cmd(args: &[&str]) {
    let st = Command::new("cmd")
        .arg("/c")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "{args:?}");
}

fn junction(link: &str, target: &str) {
    cmd(&["mklink", "/J", link, target]);
}

/// `\\?\Volume{...}\` of the volume holding `path`, from `mountvol`.
fn volume_guid_path(path: &str) -> String {
    let out = Command::new("cmd")
        .args(["/c", "mountvol", &path[..3], "/L"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let guid = text.trim().to_owned();
    assert!(guid.starts_with(r"\\?\Volume{"), "mountvol: {guid}");
    guid
}

/// Every file below `dir` with its bytes, by relative path (links are not followed).
fn snapshot(dir: &str) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut todo = vec![PathBuf::from(dir)];
    while let Some(d) = todo.pop() {
        for entry in std::fs::read_dir(extended_path(&d).unwrap()).unwrap() {
            let entry = entry.unwrap();
            let meta = std::fs::symlink_metadata(entry.path()).unwrap();
            let path = d.join(entry.file_name());
            let rel = path
                .strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if meta.is_dir() && !meta.file_type().is_symlink() {
                out.insert(format!("{rel}\\"), Vec::new());
                todo.push(path);
            } else {
                out.insert(rel, std::fs::read(entry.path()).unwrap());
            }
        }
    }
    out
}

fn attributes(path: &str) -> u32 {
    use std::os::windows::fs::MetadataExt;
    std::fs::symlink_metadata(ext(path))
        .unwrap()
        .file_attributes()
}

/// One item to quarantine: its path in the scratch directory and its candidate's category.
struct Planned<'a> {
    source: String,
    category: &'a str,
}

/// A relaxed store in a scratch directory.
struct Fx {
    roots: StorageRoots,
    scratch: Scratch,
}

impl Fx {
    fn new(tag: &str) -> Fx {
        let scratch = Scratch::new(tag);
        let roots = StorageRoots::install_relaxed(Path::new(&scratch.path("data"))).unwrap();
        clear_delete_log();
        Fx { roots, scratch }
    }

    /// `<data>\Quarantine\<session>`.
    fn quarantine_of(&self, session: &SessionId) -> String {
        format!(
            r"{}\{}",
            self.roots.quarantine_path().display(),
            session.as_str()
        )
    }
}

/// A committed session whose items were moved into quarantine for real, with its journal and scan copy.
struct Built {
    session: SessionDir,
    ids: Vec<ExpiryId>,
    quarantined: Vec<String>,
    bytes: Vec<u64>,
}

fn item_id(n: u32) -> CandidateId {
    CandidateId(format!("c-{n:03}"))
}

/// Facts of the object at `source`, from a handle on it, as the run records them.
fn facts_of(mover: &MoveHandle, source: &str, tree_bytes: u64) -> FileFacts {
    let meta = mover.metadata().unwrap();
    FileFacts {
        final_path: source.to_owned(),
        file_id: FileIdHex(meta.file_id.id),
        volume_serial: meta.file_id.volume_serial,
        reparse_tag: meta.reparse_tag,
        attributes: meta.attributes,
        n_links: meta.n_links,
        is_dir: meta.is_dir,
        size: if meta.is_dir { 0 } else { meta.size },
        tree_entries: meta.is_dir.then(|| entries_below(source)),
        tree_bytes: meta.is_dir.then_some(tree_bytes),
    }
}

/// How many entries lie below the directory `dir`, as the gate counts them: every listed entry,
/// descending into plain directories only (never into a reparse point).
fn entries_below(dir: &str) -> u64 {
    use std::os::windows::fs::MetadataExt;
    let mut count = 0;
    let mut todo = vec![ext(dir)];
    while let Some(d) = todo.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let entry = entry.unwrap();
            count += 1;
            let meta = std::fs::symlink_metadata(entry.path()).unwrap();
            let reparse = meta.file_attributes() & 0x400 != 0;
            if meta.is_dir() && !reparse {
                todo.push(entry.path());
            }
        }
    }
    count
}

/// Runs a session that quarantines `items` (op ids 1..), started at `created`; with `with_backup` an
/// extra registry op with a backup reference is journalled (nothing is deleted for it). With
/// `scan_copy` false no `plan.scan.json` is written.
fn build(
    fx: &Fx,
    created: FileTime,
    items: &[Planned<'_>],
    with_backup: bool,
    scan_copy: bool,
) -> Built {
    let session = fx.roots.create_session().unwrap();
    let n_items = items.len() as u32 + u32::from(with_backup);
    let header = Header {
        schema: JournalSchema,
        session: session.id().clone(),
        created,
        engine_version: "0.1.0".into(),
        app: "vendor-app".into(),
        plan_hash: sha256_bytes(b"plan"),
        selection_hash: sha256_bytes(b"selection"),
        policy_version: "test".into(),
        mode: ScanMode::Post,
        items: n_items,
        allow_irreversible: false,
        volumes: Vec::new(),
    };
    let mut w = JournalWriter::create(&session, header).unwrap();
    let movers: Vec<(MoveHandle, FileFacts)> = items
        .iter()
        .map(|p| {
            let mover = MoveHandle::open(&ext(&p.source)).unwrap();
            let facts = facts_of(&mover, &p.source, 4096);
            (mover, facts)
        })
        .collect();
    for (i, (p, (_, facts))) in items.iter().zip(&movers).enumerate() {
        let n = i as u32 + 1;
        w.validated(Validated {
            op: OpId(n),
            item: item_id(n),
            target: Target::Path {
                path: p.source.clone(),
            },
            facts: ItemFacts::File(facts.clone()),
            exemptions: GateExemptions::default(),
        })
        .unwrap();
    }
    let key = r"HKU\S-1-5-21-1-2-3-1001\Software\VendorApp".to_owned();
    if with_backup {
        w.validated(Validated {
            op: OpId(n_items),
            item: item_id(n_items),
            target: Target::RegKey { path: key.clone() },
            facts: ItemFacts::Key(reg_facts()),
            exemptions: GateExemptions::default(),
        })
        .unwrap();
    }
    let mut quarantined = Vec::new();
    let mut bytes = Vec::new();
    for (i, (p, (mover, facts))) in items.iter().zip(movers).enumerate() {
        let n = i as u32 + 1;
        let op_dir = session
            .create_op_dir(Path::new(&p.source), facts.volume_serial, OpId(n))
            .unwrap();
        let leaf = Path::new(&p.source)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let qpath = op_dir.item_path(&leaf).to_string_lossy().into_owned();
        let token = w
            .intent(Intent {
                op: OpId(n),
                item: item_id(n),
                exec_op: ExecOp::QuarantineMove {
                    path: p.source.clone(),
                },
                inverse: Inverse::MoveBack {
                    quarantine_path: qpath.clone(),
                    original_path: p.source.clone(),
                    file_id: facts.file_id,
                    volume_serial: facts.volume_serial,
                },
                definition: None,
                pre: ItemFacts::File(facts.clone()),
            })
            .unwrap();
        mover.rename_into(&op_dir, &leaf).unwrap();
        w.done(token, ItemOutcome::Done).unwrap();
        bytes.push(if facts.is_dir {
            facts.tree_bytes.unwrap()
        } else {
            facts.size
        });
        quarantined.push(qpath);
    }
    if with_backup {
        let token = w
            .intent(Intent {
                op: OpId(n_items),
                item: item_id(n_items),
                exec_op: ExecOp::DeleteKeyTree { key: key.clone() },
                inverse: Inverse::RestoreKeyTree {
                    backup: BackupRef {
                        path: backup_rel(BackupKind::Registry, OpId(n_items)),
                        sha256: sha256_bytes(b"backup"),
                        bytes: 6,
                    },
                },
                definition: None,
                pre: ItemFacts::Key(reg_facts()),
            })
            .unwrap();
        w.done(token, ItemOutcome::Done).unwrap();
    }
    w.commit(FileTime(created.0 + 1), bytes.iter().sum())
        .unwrap();
    drop(w);
    if scan_copy {
        write_scan_copy(&session, items);
    }
    let ids = (1..=items.len() as u32)
        .map(|n| ExpiryId {
            session: session.id().clone(),
            op: OpId(n),
        })
        .collect();
    Built {
        session,
        ids,
        quarantined,
        bytes,
    }
}

fn reg_facts() -> RegFacts {
    RegFacts {
        subkeys: 0,
        values: 1,
        is_link: false,
        owner: "S-1-5-32-544".into(),
        last_write_time: FileTime(1),
        tree_sha256: None,
    }
}

/// Writes the session's scan copy with one candidate per item, in the item's category.
fn write_scan_copy(session: &SessionDir, items: &[Planned<'_>]) {
    let candidates: Vec<serde_json::Value> = items
        .iter()
        .enumerate()
        .map(|(i, p)| {
            serde_json::json!({
                "id": item_id(i as u32 + 1).0,
                "target": {"type": "Path", "path": p.source},
                "action": "Quarantine",
                "owner": {"program_id": "HKLM|64|Vendor_is1", "display_name": "Vendor"},
                "origin": "Scanner", "scanner": "REF-ANY", "category": p.category,
                "harm": "Low", "reversibility": "Full",
                "size_bytes": null, "child_count": null, "decision": null
            })
        })
        .collect();
    let doc = serde_json::json!({
        "schema": "purge.scan/0", "app": "vendor-app", "tool": "purge", "mode": "post",
        "policy_version": "test", "plan_hash": "h", "items": candidates
    });
    let bytes = serde_json::to_vec(&doc).unwrap();
    // The fixture must produce a copy the module can read, or every item would count as user data.
    serde_json::from_slice::<purge_plan::emit::ScanDoc>(&bytes).unwrap();
    let mut file = session.create_file(SCAN_FILE).unwrap();
    file.write_all(&bytes).unwrap();
    file.sync().unwrap();
}

fn app<'a>(source: String) -> Planned<'a> {
    Planned {
        source,
        category: "AppData",
    }
}

fn clear_delete_log() {
    DELETE_OPENS.with(|log| log.borrow_mut().clear());
}

/// Asserts that every object opened with delete access lies strictly inside `quarantine` and returns
/// how many there were.
fn assert_deletes_inside(quarantine: &str) -> usize {
    let prefix = format!("{}\\", quarantine.to_lowercase());
    DELETE_OPENS.with(|log| {
        let log = log.borrow();
        for path in log.iter() {
            let plain = path.strip_prefix(r"\\?\").unwrap_or(path).to_lowercase();
            assert!(
                plain.starts_with(&prefix),
                "opened for delete outside the quarantine: {path}"
            );
        }
        log.len()
    })
}

fn set_hook(hook: impl FnMut(&str) + 'static) {
    AFTER_LISTING.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
}

fn clear_hook() {
    AFTER_LISTING.with(|h| *h.borrow_mut() = None);
}

fn expire_records(session: &SessionDir) -> Vec<(OpId, RetentionClass)> {
    journal::read(session)
        .unwrap()
        .state
        .ops()
        .flat_map(|op| op.expired.iter().map(move |c| (op.op, *c)))
        .collect()
}

fn outcome_of<'a>(report: &'a PurgeReport, id: &ExpiryId) -> &'a PurgeOutcome {
    &report
        .items
        .iter()
        .find(|r| &r.id == id)
        .unwrap_or_else(|| panic!("no result for {id}"))
        .outcome
}

fn all(ids: &[ExpiryId]) -> PurgeConsent {
    PurgeConsent::naming(ids.iter().cloned())
}

/// A canary directory outside the store with a few files.
fn canary(scratch: &Scratch, name: &str) -> String {
    scratch.file(&format!(r"{name}\keep.txt"), b"canary keep");
    scratch.file(&format!(r"{name}\sub\deep.bin"), &[7u8; 300]);
    scratch.path(name)
}

// ---------------------------------------------------------------------------------------------------
// Ids and consent
// ---------------------------------------------------------------------------------------------------

#[test]
fn expiry_ids_round_trip_and_refuse_other_shapes() {
    let session: SessionId = "20261115T101502Z-9f3a6c1d2b7e4a50".parse().unwrap();
    let id = ExpiryId {
        session,
        op: OpId(42),
    };
    let text = id.to_string();
    assert_eq!(text, "20261115T101502Z-9f3a6c1d2b7e4a50/42");
    assert_eq!(text.parse::<ExpiryId>().unwrap(), id);
    for bad in [
        "20261115T101502Z-9f3a6c1d2b7e4a50/0",
        "20261115T101502Z-9f3a6c1d2b7e4a50/042",
        "20261115T101502Z-9f3a6c1d2b7e4a50/+4",
        "20261115T101502Z-9f3a6c1d2b7e4a50",
        "x/1",
        "20261115T101502Z-9f3a6c1d2b7e4a50/1/2",
    ] {
        assert!(bad.parse::<ExpiryId>().is_err(), "{bad}");
    }
}

#[test]
fn a_consent_that_does_not_name_every_item_refuses_the_whole_request() {
    let fx = Fx::new("consent");
    let a = fx.scratch.file(r"src\a.txt", b"aaa");
    let b = fx.scratch.file(r"src\b.txt", b"bbb");
    let built = build(&fx, at_day(0), &[app(a), app(b)], false, true);
    let consent = PurgeConsent::naming([built.ids[0].clone()]);
    let err = purge(&fx.roots, &built.ids, &consent, at_day(31)).unwrap_err();
    assert_eq!(err, PurgeError::NotConsented(vec![built.ids[1].clone()]));
    assert!(exists(&built.quarantined[0]) && exists(&built.quarantined[1]));
    assert!(expire_records(&built.session).is_empty());
    assert_eq!(
        assert_deletes_inside(&fx.quarantine_of(built.session.id())),
        0
    );

    // A user-data confirmation the consent does not name counts for nothing.
    let mut consent = PurgeConsent::default();
    consent.confirm_user_data(built.ids[0].clone());
    assert!(!consent.names(&built.ids[0]) && !consent.confirms_user_data(&built.ids[0]));
}

#[test]
fn user_data_is_purged_only_when_confirmed_one_by_one() {
    let fx = Fx::new("userdata");
    let saves = fx.scratch.file(r"src\saves\slot1.sav", b"progress");
    let settings = fx.scratch.file(r"src\settings.ini", b"[x]");
    let built = build(
        &fx,
        at_day(0),
        &[
            Planned {
                source: fx.scratch.path(r"src\saves"),
                category: "UserData",
            },
            app(settings),
        ],
        false,
        true,
    );
    let _ = saves;
    let listing = expiring(&fx.roots, at_day(30)).unwrap();
    let flags: Vec<bool> = listing.items.iter().map(|i| i.user_data).collect();
    assert_eq!(flags, [true, false]);

    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30)).unwrap();
    assert_eq!(
        outcome_of(&report, &built.ids[0]),
        &PurgeOutcome::Excluded(Exclusion::UserDataNotConfirmed)
    );
    assert_eq!(outcome_of(&report, &built.ids[1]), &PurgeOutcome::Purged);
    assert!(exists(&built.quarantined[0]) && !exists(&built.quarantined[1]));

    let mut consent = all(&built.ids[..1]);
    consent.confirm_user_data(built.ids[0].clone());
    let report = purge(&fx.roots, &built.ids[..1], &consent, at_day(30)).unwrap();
    assert_eq!(outcome_of(&report, &built.ids[0]), &PurgeOutcome::Purged);
    assert!(!exists(&built.quarantined[0]));
    assert_deletes_inside(&fx.quarantine_of(built.session.id()));
}

#[test]
fn without_a_scan_copy_every_item_counts_as_user_data() {
    let fx = Fx::new("noscan");
    let a = fx.scratch.file(r"src\a.txt", b"aaa");
    let built = build(&fx, at_day(0), &[app(a)], false, false);
    let listing = expiring(&fx.roots, at_day(30)).unwrap();
    assert!(listing.items[0].user_data);
    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30)).unwrap();
    assert_eq!(
        outcome_of(&report, &built.ids[0]),
        &PurgeOutcome::Excluded(Exclusion::UserDataNotConfirmed)
    );
    assert!(exists(&built.quarantined[0]));
}

// ---------------------------------------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------------------------------------

#[test]
fn the_retention_table_is_counted_from_the_journal_start() {
    let fx = Fx::new("retention");
    let a = fx.scratch.file(r"src\a.txt", b"aaa");
    let built = build(&fx, at_day(0), &[app(a)], true, true);
    let second = |d: i64| FileTime::from_unix_secs(START + d * DAY - 1);
    // (now, quarantined item listed, backup class due, journal class due)
    let table = [
        (second(30), false, false, false),
        (at_day(30), true, false, false),
        (second(180), true, false, false),
        (at_day(180), true, true, false),
        (second(365), true, true, false),
        (at_day(365), true, true, true),
    ];
    for (now, item, backup, journal_due) in table {
        let listing = expiring(&fx.roots, now).unwrap();
        assert!(listing.problems.is_empty(), "{:?}", listing.problems);
        assert_eq!(!listing.items.is_empty(), item, "items at {now:?}");
        let due = |class| listing.due.iter().any(|d| d.class == class);
        assert_eq!(due(RetentionClass::Backup), backup, "backup at {now:?}");
        assert_eq!(
            due(RetentionClass::Journal),
            journal_due,
            "journal at {now:?}"
        );
        if item {
            let it = &listing.items[0];
            assert_eq!(it.id, built.ids[0]);
            assert_eq!(it.expires, at_day(30));
            assert_eq!(it.quarantine_path, built.quarantined[0]);
            assert!(!it.unfinished && !it.is_dir && it.bytes == 3);
        }
    }
    let expiry = Expiry::from_start(at_day(0));
    assert_eq!(expiry.quarantine, at_day(30));
    assert_eq!(expiry.backups, at_day(180));
    assert_eq!(expiry.journal, at_day(365));

    // Listing changed nothing; a purge before the end of retention is refused for the item.
    assert!(exists(&built.quarantined[0]));
    let report = purge(&fx.roots, &built.ids, &all(&built.ids), second(30)).unwrap();
    assert_eq!(
        outcome_of(&report, &built.ids[0]),
        &PurgeOutcome::Excluded(Exclusion::NotExpired {
            expires: at_day(30)
        })
    );
    assert!(exists(&built.quarantined[0]));
    assert!(expire_records(&built.session).is_empty());
    assert_eq!(report.index, IndexUpdate::NotNeeded);
}

// ---------------------------------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------------------------------

#[test]
fn an_item_with_another_identity_is_refused_with_an_alert() {
    let fx = Fx::new("identity");
    let a = fx.scratch.file(r"src\a.txt", b"aaa");
    let b = fx.scratch.file(r"src\b.txt", b"bbb");
    let built = build(&fx, at_day(0), &[app(a), app(b)], false, true);
    // Something else now has the item's name in the quarantine.
    std::fs::remove_file(ext(&built.quarantined[0])).unwrap();
    std::fs::write(ext(&built.quarantined[0]), b"planted").unwrap();

    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30)).unwrap();
    assert!(matches!(
        outcome_of(&report, &built.ids[0]),
        PurgeOutcome::Refused(Refused::IdentityMismatch { .. })
    ));
    assert_eq!(report.alerts.len(), 1);
    assert_eq!(report.alerts[0].id, built.ids[0]);
    assert_eq!(
        std::fs::read(ext(&built.quarantined[0])).unwrap(),
        b"planted"
    );
    // The other item went on.
    assert_eq!(outcome_of(&report, &built.ids[1]), &PurgeOutcome::Purged);
    assert!(!exists(&built.quarantined[1]));
    assert_eq!(
        expire_records(&built.session),
        [(OpId(2), RetentionClass::Quarantine)]
    );
    assert_deletes_inside(&fx.quarantine_of(built.session.id()));
}

#[test]
fn the_item_replaced_by_a_junction_is_refused_and_its_target_untouched() {
    let fx = Fx::new("rootjunction");
    let target = canary(&fx.scratch, "canary");
    let before = snapshot(&target);
    fx.scratch.file(r"src\dir\x.txt", b"x");
    let built = build(
        &fx,
        at_day(0),
        &[app(fx.scratch.path(r"src\dir"))],
        false,
        true,
    );
    std::fs::rename(ext(&built.quarantined[0]), ext(&fx.scratch.path("away"))).unwrap();
    junction(&built.quarantined[0], &target);

    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30)).unwrap();
    assert!(matches!(
        outcome_of(&report, &built.ids[0]),
        PurgeOutcome::Refused(Refused::IdentityMismatch { .. })
    ));
    assert_eq!(report.alerts.len(), 1);
    assert_eq!(snapshot(&target), before);
    assert!(exists(&built.quarantined[0]));
    assert!(expire_records(&built.session).is_empty());
    assert_eq!(
        assert_deletes_inside(&fx.quarantine_of(built.session.id())),
        0
    );
}

// ---------------------------------------------------------------------------------------------------
// Links
// ---------------------------------------------------------------------------------------------------

#[test]
fn links_of_every_kind_inside_the_tree_are_deleted_as_links_and_their_targets_kept() {
    let fx = Fx::new("links");
    let c1 = canary(&fx.scratch, "canary1");
    let c2 = canary(&fx.scratch, "canary2");
    let c3 = canary(&fx.scratch, "canary3");
    let c4 = canary(&fx.scratch, "canary4");
    let before: Vec<_> = [&c1, &c2, &c3, &c4].iter().map(|c| snapshot(c)).collect();

    let item = fx.scratch.dir(r"src\item");
    fx.scratch.file(r"src\item\top.txt", b"top");
    fx.scratch.file(r"src\item\a\b\c\leaf.txt", b"leaf");
    // A junction at depth 1, a mount-point-style junction (volume GUID path) at depth 2, a directory
    // symbolic link at depth 3 and a file symbolic link at depth 4.
    junction(&fx.scratch.path(r"src\item\j1"), &c1);
    let guid = volume_guid_path(&c2);
    let c2_on_volume = format!("{guid}{}", &c2[3..]);
    junction(&fx.scratch.path(r"src\item\a\mount"), &c2_on_volume);
    let symlinks =
        std::os::windows::fs::symlink_dir(ext(&c3), ext(&fx.scratch.path(r"src\item\a\b\dirlink")))
            .and_then(|()| {
                std::os::windows::fs::symlink_file(
                    ext(&format!(r"{c4}\keep.txt")),
                    ext(&fx.scratch.path(r"src\item\a\b\c\filelink")),
                )
            });
    if let Err(e) = &symlinks {
        // Symbolic links need Developer Mode or the privilege when unelevated; the junction kinds
        // still run.
        eprintln!("symbolic links not available here: {e}");
    }
    let built = build(&fx, at_day(0), &[app(item)], false, true);

    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30)).unwrap();
    let result = &report.items[0];
    assert_eq!(result.outcome, PurgeOutcome::Purged, "{report:?}");
    assert!(result.expire_recorded && result.op_dir_removed);
    assert!(!exists(&built.quarantined[0]));
    assert!(!exists(
        &Path::new(&built.quarantined[0])
            .parent()
            .unwrap()
            .to_string_lossy()
    ));
    for (c, b) in [&c1, &c2, &c3, &c4].iter().zip(&before) {
        assert_eq!(&snapshot(c), b, "canary {c} changed");
    }
    // Files top, leaf; links j1, mount (+ dirlink, filelink); dirs item, a, b, c.
    let links = if symlinks.is_ok() { 4 } else { 2 };
    assert_eq!(result.entries_deleted, 2 + links + 4);
    let opened = assert_deletes_inside(&fx.quarantine_of(built.session.id()));
    assert_eq!(
        opened as u64,
        result.entries_deleted + 1,
        "plus the op directory"
    );
}

#[test]
fn a_junction_swapped_in_between_listing_and_open_is_deleted_as_a_link() {
    let fx = Fx::new("swap");
    let target = canary(&fx.scratch, "canary");
    let before = snapshot(&target);
    let item = fx.scratch.dir(r"src\item");
    fx.scratch.file(r"src\item\sub\inner.txt", b"inner");
    fx.scratch.file(r"src\item\z.txt", b"z");
    let built = build(&fx, at_day(0), &[app(item)], false, true);
    let root = built.quarantined[0].clone();
    let away = fx.scratch.path("moved-away");
    let (sub, swap_target, swap_away) = (format!(r"{root}\sub"), target.clone(), away.clone());
    let mut swapped = false;
    set_hook(move |dir| {
        // After the item's root was listed, before `sub` is opened: move `sub` out of the
        // quarantine and plant a junction to the canary under its name.
        if !swapped && dir.eq_ignore_ascii_case(&root) {
            swapped = true;
            std::fs::rename(ext(&sub), ext(&swap_away)).unwrap();
            junction(&sub, &swap_target);
        }
    });
    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30));
    clear_hook();
    let report = report.unwrap();
    assert_eq!(report.items[0].outcome, PurgeOutcome::Purged, "{report:?}");
    assert!(!exists(&built.quarantined[0]));
    assert_eq!(
        snapshot(&target),
        before,
        "the junction's target is untouched"
    );
    // What was moved out of the quarantine is outside the walk's reach and stays.
    assert_eq!(
        std::fs::read(ext(&format!(r"{away}\inner.txt"))).unwrap(),
        b"inner"
    );
    assert_deletes_inside(&fx.quarantine_of(built.session.id()));
}

#[test]
fn a_hard_link_whose_other_name_is_outside_keeps_that_name_its_content_and_attributes() {
    let fx = Fx::new("hardlink");
    let outside = fx.scratch.file(r"canary\shared.dat", b"shared bytes");
    let item = fx.scratch.dir(r"src\item");
    let inside = fx.scratch.path(r"src\item\shared.dat");
    std::fs::hard_link(ext(&outside), ext(&inside)).unwrap();
    cmd(&["attrib", "+R", &outside]);
    let built = build(&fx, at_day(0), &[app(item)], false, true);

    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30)).unwrap();
    assert_eq!(report.items[0].outcome, PurgeOutcome::Purged, "{report:?}");
    assert!(!exists(&built.quarantined[0]));
    assert_eq!(std::fs::read(ext(&outside)).unwrap(), b"shared bytes");
    assert_ne!(
        attributes(&outside) & FILE_ATTRIBUTE_READONLY,
        0,
        "read-only of the outside name"
    );
    let handle = FileHandle::open(&ext(&outside)).unwrap();
    assert_eq!(handle.metadata().unwrap().n_links, 1);
    // A multi-name file frees no bytes.
    assert_eq!(report.items[0].bytes_deleted, 0);
    assert_deletes_inside(&fx.quarantine_of(built.session.id()));
}

// ---------------------------------------------------------------------------------------------------
// Attributes, size, depth, locks
// ---------------------------------------------------------------------------------------------------

#[test]
fn read_only_hidden_and_system_entries_are_deleted() {
    let fx = Fx::new("attrs");
    let item = fx.scratch.dir(r"src\item");
    let ro = fx.scratch.file(r"src\item\ro.txt", b"ro");
    let hidden = fx.scratch.file(r"src\item\hidden.txt", b"hidden");
    let sys = fx.scratch.file(r"src\item\rodir\sys.txt", b"sys");
    let rodir = fx.scratch.path(r"src\item\rodir");
    cmd(&["attrib", "+R", &ro]);
    cmd(&["attrib", "+H", &hidden]);
    cmd(&["attrib", "+S", "+R", "+H", &sys]);
    cmd(&["attrib", "+R", &rodir]);
    // A read-only file as the item itself.
    let single = fx.scratch.file(r"src\single.txt", b"single");
    cmd(&["attrib", "+R", &single]);
    let built = build(&fx, at_day(0), &[app(item), app(single)], false, true);

    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30)).unwrap();
    for id in &built.ids {
        assert_eq!(outcome_of(&report, id), &PurgeOutcome::Purged, "{report:?}");
    }
    assert!(!exists(&built.quarantined[0]) && !exists(&built.quarantined[1]));
    assert_eq!(report.items[0].bytes_deleted, 2 + 6 + 3);
    assert_deletes_inside(&fx.quarantine_of(built.session.id()));
}

#[test]
fn a_directory_larger_than_one_listing_batch_is_emptied() {
    let fx = Fx::new("flat");
    let item = fx.scratch.dir(r"src\item");
    for i in 0..2500 {
        fx.scratch.file(
            &format!(r"src\item\file-with-a-longish-name-{i:05}.txt"),
            b"x",
        );
    }
    let built = build(&fx, at_day(0), &[app(item)], false, true);
    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30)).unwrap();
    assert_eq!(report.items[0].outcome, PurgeOutcome::Purged, "{report:?}");
    assert_eq!(report.items[0].entries_deleted, 2501);
    assert!(!exists(&built.quarantined[0]));
}

#[test]
fn long_and_deep_paths_are_deleted_without_recursion() {
    let fx = Fx::new("deep");
    let item = fx.scratch.dir(r"src\item");
    let long_name = "n".repeat(200);
    fx.scratch.file(
        &format!(r"src\item\{long_name}\{long_name}\long.txt"),
        b"long",
    );
    // 1500 levels: far beyond MAX_PATH, and deep enough that a recursive walk with a large frame
    // would be at risk on a test thread's stack.
    let deep: String = (0..1500).map(|_| r"\d").collect();
    let deepest = format!(r"{item}{deep}");
    std::fs::create_dir_all(ext(&deepest)).unwrap();
    std::fs::write(ext(&format!(r"{deepest}\bottom.txt")), b"bottom").unwrap();
    let built = build(&fx, at_day(0), &[app(item)], false, true);

    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30)).unwrap();
    assert_eq!(report.items[0].outcome, PurgeOutcome::Purged, "{report:?}");
    // item, 2 long dirs, long.txt, 1500 d's, bottom.txt.
    assert_eq!(report.items[0].entries_deleted, 1 + 2 + 1 + 1500 + 1);
    assert!(!exists(&built.quarantined[0]));
    assert_deletes_inside(&fx.quarantine_of(built.session.id()));
}

#[test]
fn a_locked_file_fails_the_item_keeps_the_rest_and_a_later_run_completes_it() {
    let fx = Fx::new("locked");
    let item = fx.scratch.dir(r"src\item");
    fx.scratch.file(r"src\item\a.txt", b"a");
    fx.scratch.file(r"src\item\m-locked.txt", b"locked content");
    fx.scratch.file(r"src\item\z\z.txt", b"z");
    let other = fx.scratch.file(r"src\other.txt", b"other");
    let built = build(&fx, at_day(0), &[app(item), app(other)], false, true);
    let locked_path = format!(r"{}\m-locked.txt", built.quarantined[0]);
    // Held open without delete sharing, as an application would.
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0x1)
        .open(ext(&locked_path))
        .unwrap();

    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30)).unwrap();
    match outcome_of(&report, &built.ids[0]) {
        PurgeOutcome::Failed(Failure::Walk(WalkFailure { at, error })) => {
            assert!(at.eq_ignore_ascii_case(&locked_path), "{at}");
            assert_eq!(error, &WalkError::Fs(FsError::SharingViolation));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(outcome_of(&report, &built.ids[1]), &PurgeOutcome::Purged);
    assert_eq!(std::fs::read(ext(&locked_path)).unwrap(), b"locked content");
    assert!(exists(&built.quarantined[0]));
    // The expiry is recorded (write-ahead), so the op can no longer be undone and is listed as
    // unfinished until it is gone.
    assert_eq!(
        expire_records(&built.session),
        [
            (OpId(1), RetentionClass::Quarantine),
            (OpId(2), RetentionClass::Quarantine)
        ]
    );
    let listing = expiring(&fx.roots, at_day(30)).unwrap();
    assert_eq!(listing.items.len(), 1);
    assert!(listing.items[0].unfinished && listing.items[0].id == built.ids[0]);

    drop(holder);
    let report = purge(&fx.roots, &built.ids[..1], &all(&built.ids), at_day(31)).unwrap();
    assert_eq!(report.items[0].outcome, PurgeOutcome::Purged, "{report:?}");
    assert!(!report.items[0].expire_recorded, "no second expire record");
    assert!(!exists(&built.quarantined[0]));
    assert!(expiring(&fx.roots, at_day(31)).unwrap().items.is_empty());
    assert_eq!(expire_records(&built.session).len(), 2);
    assert_deletes_inside(&fx.quarantine_of(built.session.id()));
}

/// S3 of the final M2 review: names the path canonicaliser refuses (DOS device names with and without
/// an extension, a trailing dot or space, an unpaired surrogate) are ordinary entries inside a
/// quarantined tree; the quarantine move took them whole. Before the fix the walk stopped at the first
/// of them with `WalkError::Gate` (or `NameNotRepresentable`) after the expire record, on every run.
#[test]
fn entries_with_reserved_or_odd_names_below_the_item_are_deleted() {
    use std::os::windows::ffi::OsStringExt;

    let fx = Fx::new("oddnames");
    let item = fx.scratch.dir(r"src\item");
    let odd = |name: std::ffi::OsString| ext(&item).join(name);
    for name in ["nul", "aux.h", "COM1.log", "name.", "name ", "CON"] {
        std::fs::write(odd(name.into()), name.as_bytes()).unwrap();
    }
    // A directory with a device name, holding another one.
    std::fs::create_dir(odd("aux".into())).unwrap();
    std::fs::write(odd("aux".into()).join("prn.txt"), b"prn").unwrap();
    std::fs::create_dir(odd("dir. ".into())).unwrap();
    std::fs::write(odd("dir. ".into()).join("lpt1"), b"lpt1").unwrap();
    // An unpaired high surrogate.
    let surrogate = std::ffi::OsString::from_wide(&[u16::from(b's'), 0xD800, u16::from(b'x')]);
    std::fs::write(odd(surrogate), b"surrogate").unwrap();
    let ok = fx.scratch.file(r"src\item\ok.txt", b"ok");
    let _ = ok;
    let built = build(&fx, at_day(0), &[app(item)], false, true);
    let q = fx.quarantine_of(built.session.id());

    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30)).unwrap();
    assert_eq!(report.items[0].outcome, PurgeOutcome::Purged, "{report:?}");
    // 6 files, aux + prn.txt, `dir. ` + lpt1, the surrogate name, ok.txt, the item.
    assert_eq!(report.items[0].entries_deleted, 6 + 2 + 2 + 1 + 1 + 1);
    assert!(!exists(&built.quarantined[0]));
    assert!(report.items[0].op_dir_removed);
    assert!(expiring(&fx.roots, at_day(30)).unwrap().items.is_empty());
    assert_deletes_inside(&q);
}

/// M14 of the final M2 review: a directory moved whole keeps its DACL, so its former owner may add to
/// it in quarantine. More entries than the validation counted refuse the item before the expire record,
/// on every run, with nothing deleted; something added while the walk runs stops the walk before the
/// extra entry is opened. Before the fix the walk deleted all of it.
#[test]
fn an_item_that_grew_in_quarantine_is_not_deleted() {
    let fx = Fx::new("grown");
    let item = fx.scratch.dir(r"src\item");
    fx.scratch.file(r"src\item\a.txt", b"a");
    fx.scratch.file(r"src\item\b\c.txt", b"c");
    let built = build(&fx, at_day(0), &[app(item)], false, true);
    let q = &built.quarantined[0];
    let planted = format!(r"{q}\b\planted.txt");
    std::fs::write(ext(&planted), b"planted").unwrap();
    for day in [30, 31] {
        let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(day)).unwrap();
        assert_eq!(
            report.items[0].outcome,
            PurgeOutcome::Refused(Refused::MoreEntriesThanCounted { counted: 3 }),
            "{report:?}"
        );
        assert_eq!(report.alerts.len(), 1, "{report:?}");
        assert_eq!(report.items[0].entries_deleted, 0);
        assert!(expire_records(&built.session).is_empty(), "still undoable");
        for left in ["a.txt", r"b\c.txt", r"b\planted.txt"] {
            assert!(exists(&format!(r"{q}\{left}")), "{left}");
        }
    }

    // Added after the count, while the walk runs: the walk stops at the extra entry.
    std::fs::remove_file(ext(&planted)).unwrap();
    let (root, late) = (q.clone(), format!(r"{q}\z-late.txt"));
    let late_in_hook = late.clone();
    let mut planted_late = false;
    set_hook(move |dir| {
        if !planted_late && dir.eq_ignore_ascii_case(&root) {
            planted_late = true;
            std::fs::write(ext(&late_in_hook), b"late").unwrap();
        }
    });
    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(32));
    clear_hook();
    let report = report.unwrap();
    match &report.items[0].outcome {
        PurgeOutcome::Failed(Failure::Walk(WalkFailure { at, error })) => {
            assert!(at.eq_ignore_ascii_case(&late), "{at}");
            assert_eq!(error, &WalkError::MoreEntriesThanCounted { counted: 3 });
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(report.alerts.len(), 1, "{report:?}");
    assert_eq!(std::fs::read(ext(&late)).unwrap(), b"late");
    assert_deletes_inside(&fx.quarantine_of(built.session.id()));
}

/// S3, index half: the session index loses an item's bytes only once the item is gone. Before the fix
/// they were subtracted when the expire record was written, also when the walk then stopped.
#[test]
fn the_index_loses_an_items_bytes_only_once_it_is_gone() {
    let fx = Fx::new("indexwalk");
    let item = fx.scratch.dir(r"src\item");
    fx.scratch.file(r"src\item\a.txt", b"a");
    fx.scratch.file(r"src\item\m-locked.txt", b"locked");
    let built = build(&fx, at_day(0), &[app(item)], false, true);
    let mut index = SessionIndex::default();
    index.upsert(summary(&built, 10_000));
    fx.roots.write_index(&index).unwrap();
    let locked_path = format!(r"{}\m-locked.txt", built.quarantined[0]);
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0x1)
        .open(ext(&locked_path))
        .unwrap();

    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30)).unwrap();
    assert!(
        matches!(
            outcome_of(&report, &built.ids[0]),
            PurgeOutcome::Failed(Failure::Walk(_))
        ),
        "{report:?}"
    );
    assert!(report.items[0].expire_recorded);
    let s = fx.roots.read_index().unwrap().sessions[0].clone();
    assert_eq!(s.backup_bytes, 10_000, "the item is still there");
    assert_eq!(s.usage[0].bytes, 10_000);
    assert!(s.purged.is_empty());

    drop(holder);
    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(31)).unwrap();
    assert_eq!(report.items[0].outcome, PurgeOutcome::Purged, "{report:?}");
    assert!(!report.items[0].expire_recorded, "no second expire record");
    assert_eq!(report.index, IndexUpdate::Updated);
    let s = fx.roots.read_index().unwrap().sessions[0].clone();
    assert_eq!(s.backup_bytes, 10_000 - built.bytes[0]);
    assert_eq!(s.usage[0].bytes, 10_000 - built.bytes[0]);
    assert_eq!(s.purged, [RetentionClass::Quarantine]);

    // A third run finds nothing and subtracts nothing again.
    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(32)).unwrap();
    assert_eq!(report.items[0].outcome, PurgeOutcome::AlreadyGone);
    assert!(!report.items[0].expire_recorded);
    assert_eq!(report.index, IndexUpdate::NotNeeded);
    let s = fx.roots.read_index().unwrap().sessions[0].clone();
    assert_eq!(s.backup_bytes, 10_000 - built.bytes[0]);
}

// ---------------------------------------------------------------------------------------------------
// Journal state
// ---------------------------------------------------------------------------------------------------

#[test]
fn a_session_being_undone_is_not_expired() {
    let fx = Fx::new("undo");
    let a = fx.scratch.file(r"src\a.txt", b"aaa");
    let b = fx.scratch.file(r"src\b.txt", b"bbb");
    let built = build(&fx, at_day(0), &[app(a), app(b)], false, true);
    let mut w = JournalWriter::open_append(&built.session).unwrap();
    let _token = w.undo_intent(OpId(1)).unwrap();
    drop(w);

    let listing = expiring(&fx.roots, at_day(40)).unwrap();
    assert!(listing.items.is_empty());
    assert_eq!(listing.held.len(), 2);
    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(40)).unwrap();
    for id in &built.ids {
        assert!(
            matches!(
                outcome_of(&report, id),
                PurgeOutcome::Excluded(Exclusion::Held(HoldReason::SessionUndoInProgress))
            ),
            "{report:?}"
        );
    }
    assert!(exists(&built.quarantined[0]) && exists(&built.quarantined[1]));
    assert!(expire_records(&built.session).is_empty());
}

/// M15 of the final M2 review: an undo run that died between two ops leaves no undo in progress, but
/// the ops its plan had not reached are still to be undone. Before the fix they were purged.
#[test]
fn a_session_whose_undo_run_stopped_between_two_ops_is_not_expired() {
    let fx = Fx::new("undoplan");
    let a = fx.scratch.file(r"src\a.txt", b"aaa");
    let b = fx.scratch.file(r"src\b.txt", b"bbb");
    let built = build(&fx, at_day(0), &[app(a), app(b)], false, true);
    let mut w = JournalWriter::open_append(&built.session).unwrap();
    w.undo_plan(at_day(1), vec![OpId(2), OpId(1)]).unwrap();
    let token = w.undo_intent(OpId(2)).unwrap();
    w.undo_done(token, UndoOutcome::Restored).unwrap();
    assert_eq!(w.state().undo_in_progress().count(), 0);
    assert_eq!(w.state().undo_unfinished(), [OpId(1)]);
    drop(w);

    let listing = expiring(&fx.roots, at_day(40)).unwrap();
    assert!(listing.items.is_empty(), "{listing:?}");
    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(40)).unwrap();
    assert_eq!(
        outcome_of(&report, &built.ids[0]),
        &PurgeOutcome::Excluded(Exclusion::Held(HoldReason::SessionUndoInProgress)),
        "{report:?}"
    );
    assert!(exists(&built.quarantined[0]));
    assert!(expire_records(&built.session).is_empty());
}

/// The journal header of a test session with `items` items, started at day 0.
fn header_of(session: &SessionDir, items: u32) -> Header {
    Header {
        schema: JournalSchema,
        session: session.id().clone(),
        created: at_day(0),
        engine_version: "0.1.0".into(),
        app: "vendor-app".into(),
        plan_hash: sha256_bytes(b"plan"),
        selection_hash: sha256_bytes(b"selection"),
        policy_version: "test".into(),
        mode: ScanMode::Post,
        items,
        allow_irreversible: false,
        volumes: Vec::new(),
    }
}

/// A committed session with one quarantine op that was held (`HeldRetry`) by its run and retried
/// afterwards: the retry moved the item into quarantine for real and journalled `retried`, followed by
/// `reconciles`.
fn build_retried(
    fx: &Fx,
    source: String,
    retried: ItemOutcome,
    reconciles: &[ReconcileResult],
) -> Built {
    let session = fx.roots.create_session().unwrap();
    let mut w = JournalWriter::create(&session, header_of(&session, 1)).unwrap();
    let mover = MoveHandle::open(&ext(&source)).unwrap();
    let facts = facts_of(&mover, &source, 0);
    w.validated(Validated {
        op: OpId(1),
        item: item_id(1),
        target: Target::Path {
            path: source.clone(),
        },
        facts: ItemFacts::File(facts.clone()),
        exemptions: GateExemptions::default(),
    })
    .unwrap();
    let op_dir = session
        .create_op_dir(Path::new(&source), facts.volume_serial, OpId(1))
        .unwrap();
    let leaf = Path::new(&source)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let qpath = op_dir.item_path(&leaf).to_string_lossy().into_owned();
    let token = w
        .intent(Intent {
            op: OpId(1),
            item: item_id(1),
            exec_op: ExecOp::QuarantineMove {
                path: source.clone(),
            },
            inverse: Inverse::MoveBack {
                quarantine_path: qpath.clone(),
                original_path: source.clone(),
                file_id: facts.file_id,
                volume_serial: facts.volume_serial,
            },
            definition: None,
            pre: ItemFacts::File(facts.clone()),
        })
        .unwrap();
    w.done(token, ItemOutcome::HeldRetry).unwrap();
    w.commit(at_day(0), 0).unwrap();
    let retry = w.retry_intent(OpId(1), at_day(1)).unwrap();
    mover.rename_into(&op_dir, &leaf).unwrap();
    w.retried(retry, at_day(1), retried).unwrap();
    for result in reconciles {
        w.reconcile(Reconcile {
            at: at_day(2),
            op: OpId(1),
            result: result.clone(),
        })
        .unwrap();
    }
    drop(w);
    write_scan_copy(&session, &[app(source)]);
    Built {
        ids: vec![ExpiryId {
            session: session.id().clone(),
            op: OpId(1),
        }],
        session,
        quarantined: vec![qpath],
        bytes: vec![facts.size],
    }
}

/// M16 of the final M2 review: expiry reads an op's records the way undo does. A retry whose verify
/// failed may have left the item in quarantine; a retry that registered a boot-time move which then
/// completed has it there. Before the fix the first was "not in quarantine" and the second "held" for
/// ever; both are purgeable now, and a retry still waiting for its restart is held.
#[test]
fn retried_ops_are_read_as_undo_reads_them() {
    let fx = Fx::new("retried");
    let verify_failed = ItemOutcome::Failed {
        code: FailCode::VerifyFailed,
        os_error: None,
        detail: "after the move the item is not where it should be".into(),
    };
    let pair = |n: u32| ItemOutcome::PendingReboot {
        pair: BootMovePair {
            src: format!(r"\??\C:\src\{n}"),
            dst: format!(r"\??\C:\q\{n}"),
        },
        confirmed: true,
    };
    let failed = build_retried(
        &fx,
        fx.scratch.file(r"src\failed.txt", b"failed"),
        verify_failed,
        &[],
    );
    let completed = build_retried(
        &fx,
        fx.scratch.file(r"src\completed.txt", b"completed"),
        pair(1),
        &[ReconcileResult::Completed],
    );
    let waiting = build_retried(
        &fx,
        fx.scratch.file(r"src\waiting.txt", b"waiting"),
        pair(2),
        &[ReconcileResult::StillPending],
    );
    for built in [&failed, &completed] {
        let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(40)).unwrap();
        assert_eq!(report.items[0].outcome, PurgeOutcome::Purged, "{report:?}");
        assert!(!exists(&built.quarantined[0]));
    }
    let report = purge(&fx.roots, &waiting.ids, &all(&waiting.ids), at_day(40)).unwrap();
    assert_eq!(
        report.items[0].outcome,
        PurgeOutcome::Excluded(Exclusion::Held(HoldReason::PendingReboot)),
        "{report:?}"
    );
    assert!(exists(&waiting.quarantined[0]));
}

/// A volume probe that answers "not found" for one drive, as for a volume that is not attached.
#[derive(Debug)]
struct Detached(&'static str);

impl crate::storage::VolumeProbe for Detached {
    fn volume(&self, path: &Path) -> Result<crate::storage::VolumeFacts, FsError> {
        let text = path.to_string_lossy();
        let plain = text.strip_prefix(r"\\?\").unwrap_or(&text);
        if plain
            .get(..2)
            .is_some_and(|drive| drive.eq_ignore_ascii_case(self.0))
        {
            return Err(FsError::NotFound);
        }
        crate::storage::SystemVolumes.volume(path)
    }
}

/// M17 of the final M2 review: an item on a volume that is not attached is not "already gone". Before
/// the fix the purge wrote its expire record and subtracted its bytes; when the volume came back the
/// item was there and could no longer be undone.
#[test]
fn an_item_on_a_volume_that_is_not_attached_is_not_taken_as_gone() {
    let fx = Fx::new("detached");
    let roots = fx
        .roots
        .clone()
        .with_volume_probe(std::sync::Arc::new(Detached("Q:")));
    let session = roots.create_session().unwrap();
    let mut w = JournalWriter::create(&session, header_of(&session, 1)).unwrap();
    let source = r"Q:\Vendor\gone.bin".to_owned();
    let pre = FileFacts {
        final_path: source.clone(),
        file_id: FileIdHex([5; 16]),
        volume_serial: 0x5151,
        reparse_tag: 0,
        attributes: 32,
        n_links: 1,
        is_dir: false,
        size: 77,
        tree_entries: None,
        tree_bytes: None,
    };
    w.validated(Validated {
        op: OpId(1),
        item: item_id(1),
        target: Target::Path {
            path: source.clone(),
        },
        facts: ItemFacts::File(pre.clone()),
        exemptions: GateExemptions::default(),
    })
    .unwrap();
    let qpath = format!(r"Q:\.purge-q\{}\000001\gone.bin", session.id().as_str());
    let token = w
        .intent(Intent {
            op: OpId(1),
            item: item_id(1),
            exec_op: ExecOp::QuarantineMove {
                path: source.clone(),
            },
            inverse: Inverse::MoveBack {
                quarantine_path: qpath,
                original_path: source.clone(),
                file_id: FileIdHex([5; 16]),
                volume_serial: 0x5151,
            },
            definition: None,
            pre: ItemFacts::File(pre),
        })
        .unwrap();
    w.done(token, ItemOutcome::Done).unwrap();
    w.commit(at_day(0), 77).unwrap();
    drop(w);
    write_scan_copy(&session, &[app(source)]);
    let ids = [ExpiryId {
        session: session.id().clone(),
        op: OpId(1),
    }];

    let report = purge(&roots, &ids, &all(&ids), at_day(40)).unwrap();
    assert!(
        matches!(
            &report.items[0].outcome,
            PurgeOutcome::Failed(Failure::Store(StorageError::Io {
                source: FsError::NotFound,
                ..
            }))
        ),
        "{report:?}"
    );
    assert!(!report.items[0].expire_recorded);
    assert!(
        expire_records(&session).is_empty(),
        "the op can still be undone"
    );
    assert_eq!(report.index, IndexUpdate::NotNeeded);
}

#[test]
fn the_own_directories_of_an_item_are_told_from_the_rest_of_its_path() {
    let q = r"C:\ProgramData\Purge\Quarantine\20261115T101502Z-9f3a6c1d2b7e4a50\000001\a.txt";
    let own = |p: &str| is_own_dir_of(q, Path::new(p));
    assert!(own(
        r"C:\ProgramData\Purge\Quarantine\20261115T101502Z-9f3a6c1d2b7e4a50\000001"
    ));
    assert!(own(
        r"\\?\c:\programdata\purge\quarantine\20261115T101502Z-9F3A6C1D2B7E4A50"
    ));
    assert!(!own(r"C:\ProgramData\Purge\Quarantine"));
    assert!(!own(r"C:\"));
    assert!(!own(q));
    assert!(!own(r"Q:\.purge-q"));
}

#[test]
fn undone_open_and_pending_ops_are_not_expired() {
    let fx = Fx::new("states");
    // An op that was undone has nothing in the quarantine.
    let a = fx.scratch.file(r"src\a.txt", b"aaa");
    let built = build(&fx, at_day(0), &[app(a)], false, true);
    let mut w = JournalWriter::open_append(&built.session).unwrap();
    let token = w.undo_intent(OpId(1)).unwrap();
    w.undo_done(token, UndoOutcome::Restored).unwrap();
    drop(w);
    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(40)).unwrap();
    assert_eq!(
        outcome_of(&report, &built.ids[0]),
        &PurgeOutcome::Excluded(Exclusion::NotInQuarantine)
    );
    assert!(
        exists(&built.quarantined[0]),
        "untouched (the fixture did not move it back)"
    );

    // A session whose run has not ended.
    let open_id = one_op_session(&fx, None);
    let report = purge(
        &fx.roots,
        std::slice::from_ref(&open_id),
        &all(std::slice::from_ref(&open_id)),
        at_day(40),
    )
    .unwrap();
    assert_eq!(
        outcome_of(&report, &open_id),
        &PurgeOutcome::Excluded(Exclusion::Held(HoldReason::SessionOpen))
    );

    // A committed session whose item waits for a boot-time move that was never reconciled.
    let pending_id = one_op_session(&fx, Some(at_day(0)));
    let report = purge(
        &fx.roots,
        std::slice::from_ref(&pending_id),
        &all(std::slice::from_ref(&pending_id)),
        at_day(40),
    )
    .unwrap();
    assert_eq!(
        outcome_of(&report, &pending_id),
        &PurgeOutcome::Excluded(Exclusion::Held(HoldReason::PendingReboot))
    );

    let listing = expiring(&fx.roots, at_day(40)).unwrap();
    assert!(listing.items.is_empty(), "{listing:?}");
    let held: Vec<_> = listing
        .held
        .iter()
        .map(|(id, why)| (id.clone(), why.clone()))
        .collect();
    assert!(
        held.contains(&(open_id.clone(), HoldReason::SessionOpen)),
        "{held:?}"
    );
    assert!(
        held.contains(&(pending_id.clone(), HoldReason::PendingReboot)),
        "{held:?}"
    );
    for id in [&open_id, &pending_id] {
        assert_eq!(assert_deletes_inside(&fx.quarantine_of(&id.session)), 0);
    }
}

/// A session with one quarantine op whose item never existed on disk. With `committed` the op ends
/// as a registered boot-time move and the run is committed at that time; without it the run is left
/// open after the intent.
fn one_op_session(fx: &Fx, committed: Option<FileTime>) -> ExpiryId {
    let session = fx.roots.create_session().unwrap();
    let mut w = JournalWriter::create(
        &session,
        Header {
            schema: JournalSchema,
            session: session.id().clone(),
            created: at_day(0),
            engine_version: "0.1.0".into(),
            app: "vendor-app".into(),
            plan_hash: sha256_bytes(b"plan"),
            selection_hash: sha256_bytes(b"selection"),
            policy_version: "test".into(),
            mode: ScanMode::Post,
            items: 1,
            allow_irreversible: false,
            volumes: Vec::new(),
        },
    )
    .unwrap();
    let path = fx.scratch.path(r"src\never.txt");
    let pre = FileFacts {
        final_path: path.clone(),
        file_id: FileIdHex([5; 16]),
        volume_serial: 9,
        reparse_tag: 0,
        attributes: 32,
        n_links: 1,
        is_dir: false,
        size: 1,
        tree_entries: None,
        tree_bytes: None,
    };
    w.validated(Validated {
        op: OpId(1),
        item: item_id(1),
        target: Target::Path { path: path.clone() },
        facts: ItemFacts::File(pre.clone()),
        exemptions: GateExemptions::default(),
    })
    .unwrap();
    let quarantine_path = format!(r"{}\000001\never.txt", fx.quarantine_of(session.id()));
    let token = w
        .intent(Intent {
            op: OpId(1),
            item: item_id(1),
            exec_op: ExecOp::QuarantineMove { path: path.clone() },
            inverse: Inverse::MoveBack {
                quarantine_path: quarantine_path.clone(),
                original_path: path.clone(),
                file_id: FileIdHex([5; 16]),
                volume_serial: 9,
            },
            definition: None,
            pre: ItemFacts::File(pre),
        })
        .unwrap();
    if let Some(at) = committed {
        let pending = ItemOutcome::PendingReboot {
            pair: BootMovePair {
                src: format!(r"\??\{path}"),
                dst: format!(r"\??\{quarantine_path}"),
            },
            confirmed: true,
        };
        w.done(token, pending).unwrap();
        w.commit(at, 0).unwrap();
    }
    drop(w);
    ExpiryId {
        session: session.id().clone(),
        op: OpId(1),
    }
}

// ---------------------------------------------------------------------------------------------------
// Index
// ---------------------------------------------------------------------------------------------------

fn summary(built: &Built, bytes: u64) -> SessionSummary {
    let serial = FileHandle::open(&ext(&built.quarantined[0]))
        .unwrap()
        .file_id()
        .unwrap()
        .volume_serial;
    SessionSummary {
        id: built.session.id().clone(),
        app: "vendor-app".into(),
        owner: None,
        plan_hash: sha256_bytes(b"plan"),
        state: SessionState::Committed,
        started: at_day(0),
        finished: Some(at_day(0)),
        counts: Default::default(),
        undone: 0,
        backup_bytes: bytes,
        usage: vec![VolumeUsage {
            serial,
            root: r"C:\".into(),
            bytes,
        }],
        expires: Expiry::from_start(at_day(0)),
        purged: Vec::new(),
        pending_reboot: false,
        journal: None,
    }
}

#[test]
fn the_index_is_updated_through_the_store() {
    let fx = Fx::new("index");
    let a = fx.scratch.file(r"src\a.txt", b"0123456789");
    let b = fx.scratch.file(r"src\b.txt", b"01234");
    let built = build(&fx, at_day(0), &[app(a), app(b)], false, true);
    let mut index = SessionIndex::default();
    index.upsert(summary(&built, 1000));
    fx.roots.write_index(&index).unwrap();

    let report = purge(&fx.roots, &built.ids[..1], &all(&built.ids), at_day(30)).unwrap();
    assert_eq!(report.index, IndexUpdate::Updated);
    let s = fx.roots.read_index().unwrap().sessions[0].clone();
    assert_eq!(s.backup_bytes, 1000 - built.bytes[0]);
    assert_eq!(s.usage[0].bytes, 1000 - built.bytes[0]);
    assert!(s.purged.is_empty(), "one quarantined op is left");

    let report = purge(&fx.roots, &built.ids[1..], &all(&built.ids), at_day(30)).unwrap();
    assert_eq!(report.index, IndexUpdate::Updated);
    let s = fx.roots.read_index().unwrap().sessions[0].clone();
    assert_eq!(s.backup_bytes, 1000 - 10 - 5);
    assert_eq!(s.purged, [RetentionClass::Quarantine]);
}

#[test]
fn a_busy_index_is_reported_and_not_guessed() {
    let fx = Fx::new("busyindex");
    let a = fx.scratch.file(r"src\a.txt", b"aaa");
    let built = build(&fx, at_day(0), &[app(a)], false, true);
    let mut index = SessionIndex::default();
    index.upsert(summary(&built, 3));
    fx.roots.write_index(&index).unwrap();
    let written = std::fs::read(ext(&fx.roots.index_path().to_string_lossy())).unwrap();
    // Another process holds the index without any sharing.
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(ext(&fx.roots.index_path().to_string_lossy()))
        .unwrap();

    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30)).unwrap();
    assert_eq!(report.items[0].outcome, PurgeOutcome::Purged);
    assert!(
        matches!(&report.index, IndexUpdate::Unavailable(e) if e.is_index_unavailable()),
        "{:?}",
        report.index
    );
    drop(holder);
    assert_eq!(
        std::fs::read(ext(&fx.roots.index_path().to_string_lossy())).unwrap(),
        written
    );
}

// ---------------------------------------------------------------------------------------------------
// The journal against its index entry
// ---------------------------------------------------------------------------------------------------

/// Writes an index whose only entry is `built`'s session with the journal mark `mark`.
fn index_with_mark(fx: &Fx, built: &Built, mark: Option<JournalMark>) {
    let mut index = SessionIndex::default();
    index.upsert(SessionSummary {
        journal: mark,
        ..summary(built, 3)
    });
    fx.roots.write_index(&index).unwrap();
}

#[test]
fn a_journal_cut_or_replaced_since_its_index_entry_is_a_problem_and_never_purged() {
    let fx = Fx::new("mark");
    let a = fx.scratch.file(r"src\a.txt", b"aaa");
    let built = build(&fx, at_day(0), &[app(a)], false, true);
    let read = journal::read(&built.session).unwrap();
    let lines = read.line_heads.len() as u64;
    let real = JournalMark {
        records: lines,
        head: read.head,
    };
    let cut = JournalMark {
        records: lines + 1,
        head: read.head,
    };
    let replaced = JournalMark {
        records: lines,
        head: purge_model::exec::op::Sha256Hex([9; 32]),
    };

    for (what, mark) in [("cut", cut), ("replaced", replaced)] {
        index_with_mark(&fx, &built, Some(mark));
        let listing = expiring(&fx.roots, at_day(30)).unwrap();
        assert_eq!(listing.problems.len(), 1, "{what}");
        assert_eq!(
            listing.problems[0].session.as_ref(),
            Some(built.session.id())
        );
        assert!(listing.items.is_empty() && listing.due.is_empty(), "{what}");

        let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30)).unwrap();
        assert!(
            matches!(
                outcome_of(&report, &built.ids[0]),
                PurgeOutcome::Refused(Refused::JournalMismatch(_))
            ),
            "{what}: {report:?}"
        );
        assert_eq!(report.alerts.len(), 1, "{what}");
        assert_eq!(report.index, IndexUpdate::NotNeeded);
        assert!(exists(&built.quarantined[0]));
        assert!(expire_records(&built.session).is_empty());
    }
    assert_eq!(
        assert_deletes_inside(&fx.quarantine_of(built.session.id())),
        0
    );

    // The journal its index entry records (later lines are allowed): read and purged as usual.
    index_with_mark(&fx, &built, Some(real));
    let listing = expiring(&fx.roots, at_day(30)).unwrap();
    assert!(listing.problems.is_empty(), "{:?}", listing.problems);
    assert_eq!(listing.items.len(), 1);
    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30)).unwrap();
    assert_eq!(outcome_of(&report, &built.ids[0]), &PurgeOutcome::Purged);
    assert!(!exists(&built.quarantined[0]));
}

// ---------------------------------------------------------------------------------------------------
// Backup files
// ---------------------------------------------------------------------------------------------------

/// A session whose ops kept backup files that exist in the session.
struct Backups {
    session: SessionDir,
    /// Op 1: a key tree with its registry backup; op 2: a package removal with its definition.
    ids: Vec<ExpiryId>,
    /// The file of each op, as its intent names it.
    files: Vec<String>,
}

/// Runs a session started at `created` with the two ops of [`Backups`], writing each backup file for
/// real. Committed unless `committed` is false (the run then has not ended). With `scan_copy` the
/// candidates are app data; without it every op counts as user data.
fn build_backups(fx: &Fx, created: FileTime, committed: bool, scan_copy: bool) -> Backups {
    let session = fx.roots.create_session().unwrap();
    let header = Header {
        schema: JournalSchema,
        session: session.id().clone(),
        created,
        engine_version: "0.1.0".into(),
        app: "vendor-app".into(),
        plan_hash: sha256_bytes(b"plan"),
        selection_hash: sha256_bytes(b"selection"),
        policy_version: "test".into(),
        mode: ScanMode::Post,
        items: 2,
        allow_irreversible: true,
        volumes: Vec::new(),
    };
    let mut w = JournalWriter::create(&session, header).unwrap();
    let key = r"HKU\S-1-5-21-1-2-3-1001\Software\VendorApp".to_owned();
    let ops = [
        (
            ExecOp::DeleteKeyTree { key },
            ItemFacts::Key(reg_facts()),
            backup_rel(BackupKind::Registry, OpId(1)),
        ),
        (
            ExecOp::RemovePackage {
                full_name: "Vendor.App_1.0.0.0_x64__abcdefghjkmnp".into(),
            },
            ItemFacts::Package,
            backup_rel(BackupKind::Definition, OpId(2)),
        ),
    ];
    for (i, (exec_op, pre, _)) in ops.iter().enumerate() {
        let n = i as u32 + 1;
        w.validated(Validated {
            op: OpId(n),
            item: item_id(n),
            target: exec_op.target(),
            facts: pre.clone(),
            exemptions: GateExemptions::default(),
        })
        .unwrap();
    }
    let mut files = Vec::new();
    for (i, (exec_op, pre, rel)) in ops.into_iter().enumerate() {
        let n = i as u32 + 1;
        let mut file = session.create_file(&rel).unwrap();
        file.write_all(b"backup").unwrap();
        file.sync().unwrap();
        drop(file);
        let backup = BackupRef {
            path: rel.clone(),
            sha256: sha256_bytes(b"backup"),
            bytes: 6,
        };
        let (inverse, definition) = match &exec_op {
            ExecOp::RemovePackage { .. } => (Inverse::None, Some(backup)),
            _ => (Inverse::RestoreKeyTree { backup }, None),
        };
        let token = w
            .intent(Intent {
                op: OpId(n),
                item: item_id(n),
                exec_op,
                inverse,
                definition,
                pre,
            })
            .unwrap();
        w.done(token, ItemOutcome::Done).unwrap();
        files.push(rel);
    }
    if committed {
        w.commit(FileTime(created.0 + 1), 12).unwrap();
    }
    drop(w);
    if scan_copy {
        write_scan_copy(&session, &[app("x".into()), app("y".into())]);
    }
    let ids = (1..=2)
        .map(|n| ExpiryId {
            session: session.id().clone(),
            op: OpId(n),
        })
        .collect();
    Backups {
        session,
        ids,
        files,
    }
}

/// A consent naming every op of `b` and each op's file.
fn naming_files(b: &Backups) -> PurgeConsent {
    let mut consent = all(&b.ids);
    for (id, file) in b.ids.iter().zip(&b.files) {
        consent.name_files(id.clone(), [file.clone()]);
    }
    consent
}

fn backup_exists(b: &Backups, rel: &str) -> bool {
    exists(&b.session.path().join(rel).to_string_lossy())
}

#[test]
fn backup_files_are_purged_only_when_due_and_every_file_is_named() {
    let fx = Fx::new("backups");
    let b = build_backups(&fx, at_day(0), true, true);
    let serial = b.session.dir().volume_serial();
    let mut index = SessionIndex::default();
    index.upsert(SessionSummary {
        id: b.session.id().clone(),
        app: "vendor-app".into(),
        owner: None,
        plan_hash: sha256_bytes(b"plan"),
        state: SessionState::Committed,
        started: at_day(0),
        finished: Some(at_day(0)),
        counts: Default::default(),
        undone: 0,
        backup_bytes: 12,
        usage: vec![VolumeUsage {
            serial,
            root: r"C:\".into(),
            bytes: 12,
        }],
        expires: Expiry::from_start(at_day(0)),
        purged: Vec::new(),
        pending_reboot: false,
        journal: None,
    });
    fx.roots.write_index(&index).unwrap();
    let before_due = FileTime::from_unix_secs(START + 180 * DAY - 1);

    // Listed per op from the day the class is due, with every file.
    assert!(expiring(&fx.roots, before_due).unwrap().backups.is_empty());
    let listing = expiring(&fx.roots, at_day(180)).unwrap();
    assert!(listing.problems.is_empty(), "{:?}", listing.problems);
    let listed: Vec<(ExpiryId, Vec<String>, u64, bool, bool)> = listing
        .backups
        .iter()
        .map(|e| {
            assert_eq!(e.expires, at_day(180));
            (
                e.id.clone(),
                e.files.clone(),
                e.bytes,
                e.user_data,
                e.unfinished,
            )
        })
        .collect();
    assert_eq!(
        listed,
        [
            (b.ids[0].clone(), vec![b.files[0].clone()], 6, false, false),
            (b.ids[1].clone(), vec![b.files[1].clone()], 6, false, false),
        ]
    );

    // Not before the class is due: the op can still be undone from them.
    let report = purge(&fx.roots, &b.ids, &naming_files(&b), before_due).unwrap();
    for id in &b.ids {
        assert_eq!(
            outcome_of(&report, id),
            &PurgeOutcome::Excluded(Exclusion::NotExpired {
                expires: at_day(180)
            })
        );
    }
    // Not with a consent that names the ops but not their files, or another file.
    let mut other = all(&b.ids);
    other.name_files(b.ids[0].clone(), [b.files[1].clone()]);
    let report = purge(&fx.roots, &b.ids, &other, at_day(180)).unwrap();
    assert_eq!(
        outcome_of(&report, &b.ids[0]),
        &PurgeOutcome::Excluded(Exclusion::FilesNotNamed {
            files: vec![b.files[0].clone()]
        })
    );
    assert_eq!(
        outcome_of(&report, &b.ids[1]),
        &PurgeOutcome::Excluded(Exclusion::FilesNotNamed {
            files: vec![b.files[1].clone()]
        })
    );
    // A file named for an op the consent does not name counts for nothing.
    let mut stray = PurgeConsent::default();
    stray.name_files(b.ids[0].clone(), [b.files[0].clone()]);
    assert!(!stray.names_file(&b.ids[0], &b.files[0]));
    assert!(b.files.iter().all(|f| backup_exists(&b, f)));
    assert!(expire_records(&b.session).is_empty());

    // Due and named: the expire record, then the files.
    let report = purge(&fx.roots, &b.ids, &naming_files(&b), at_day(180)).unwrap();
    for result in &report.items {
        assert_eq!(result.outcome, PurgeOutcome::Purged, "{report:?}");
        assert!(result.expire_recorded);
        assert_eq!((result.entries_deleted, result.bytes_deleted), (1, 6));
    }
    assert!(b.files.iter().all(|f| !backup_exists(&b, f)));
    assert_eq!(
        expire_records(&b.session),
        [
            (OpId(1), RetentionClass::Backup),
            (OpId(2), RetentionClass::Backup)
        ]
    );
    assert_eq!(report.index, IndexUpdate::Updated);
    let s = fx.roots.read_index().unwrap().sessions[0].clone();
    assert_eq!((s.backup_bytes, s.usage[0].bytes), (0, 0));
    assert_eq!(s.purged, [RetentionClass::Backup]);
    // The op is not undone any more.
    let mut w = JournalWriter::open_append(&b.session).unwrap();
    assert!(w.undo_intent(OpId(1)).is_err());
    drop(w);

    // Nothing is listed any more, and a second purge finds nothing to do.
    let listing = expiring(&fx.roots, at_day(200)).unwrap();
    assert!(listing.backups.is_empty());
    assert!(
        !listing
            .due
            .iter()
            .any(|d| d.class == RetentionClass::Backup)
    );
    let report = purge(&fx.roots, &b.ids, &naming_files(&b), at_day(200)).unwrap();
    assert!(
        report
            .items
            .iter()
            .all(|r| r.outcome == PurgeOutcome::AlreadyGone && !r.expire_recorded)
    );
    assert_eq!(expire_records(&b.session).len(), 2);
}

#[test]
fn user_data_backups_and_held_sessions_are_left_alone() {
    let fx = Fx::new("backups-held");
    // Without a scan copy every op counts as user data: confirmed one by one.
    let b = build_backups(&fx, at_day(0), true, false);
    let report = purge(&fx.roots, &b.ids, &naming_files(&b), at_day(180)).unwrap();
    for id in &b.ids {
        assert_eq!(
            outcome_of(&report, id),
            &PurgeOutcome::Excluded(Exclusion::UserDataNotConfirmed)
        );
    }
    let mut consent = naming_files(&b);
    consent.confirm_user_data(b.ids[0].clone());
    let report = purge(&fx.roots, &b.ids, &consent, at_day(180)).unwrap();
    assert_eq!(outcome_of(&report, &b.ids[0]), &PurgeOutcome::Purged);
    assert!(!backup_exists(&b, &b.files[0]) && backup_exists(&b, &b.files[1]));

    // A run that has not ended: held, listed as such.
    let open = build_backups(&fx, at_day(0), false, true);
    let listing = expiring(&fx.roots, at_day(200)).unwrap();
    for id in &open.ids {
        assert!(
            listing
                .held
                .contains(&(id.clone(), HoldReason::SessionOpen))
        );
        assert!(!listing.backups.iter().any(|e| e.id == *id));
    }
    let report = purge(&fx.roots, &open.ids, &naming_files(&open), at_day(200)).unwrap();
    for id in &open.ids {
        assert_eq!(
            outcome_of(&report, id),
            &PurgeOutcome::Excluded(Exclusion::Held(HoldReason::SessionOpen))
        );
    }
    assert!(open.files.iter().all(|f| backup_exists(&open, f)));
    assert!(expire_records(&open.session).is_empty());
}

#[test]
fn an_unfinished_backup_purge_is_continued_without_a_second_record() {
    let fx = Fx::new("backups-resume");
    let b = build_backups(&fx, at_day(0), true, true);
    // An earlier purge wrote op 1's record and stopped before deleting.
    let mut w = JournalWriter::open_append(&b.session).unwrap();
    w.expire(Expire {
        at: at_day(180),
        op: OpId(1),
        class: RetentionClass::Backup,
        bytes: 6,
    })
    .unwrap();
    drop(w);

    let listing = expiring(&fx.roots, at_day(181)).unwrap();
    let unfinished: Vec<(OpId, bool)> = listing
        .backups
        .iter()
        .map(|e| (e.id.op, e.unfinished))
        .collect();
    assert_eq!(unfinished, [(OpId(1), true), (OpId(2), false)]);

    let report = purge(&fx.roots, &b.ids[..1], &naming_files(&b), at_day(181)).unwrap();
    assert_eq!(report.items[0].outcome, PurgeOutcome::Purged);
    assert!(!report.items[0].expire_recorded);
    // Changed by S3 of the final M2 review: the bytes leave the index when the files are gone, so
    // the run that finishes the op updates it (the run that wrote the record and stopped did not).
    assert_eq!(report.index, IndexUpdate::Updated);
    assert!(!backup_exists(&b, &b.files[0]) && backup_exists(&b, &b.files[1]));
    assert_eq!(
        expire_records(&b.session),
        [(OpId(1), RetentionClass::Backup)]
    );
}

// ---------------------------------------------------------------------------------------------------
// A crash in the middle of the walk
// ---------------------------------------------------------------------------------------------------

/// Set only in a child process of the test binary: the data root of the child's store.
const CHILD_ROOT: &str = "PURGE_TEST_EXPIRY_CHILD_ROOT";
/// Set only in a child process of the test binary: the id of the item the child purges.
const CHILD_ITEM: &str = "PURGE_TEST_EXPIRY_CHILD_ITEM";

/// The child half of the crash test: purges one item 30 days after the session start. Does nothing
/// when run as an ordinary test.
#[test]
fn child_expiry_scenario() {
    let (Some(root), Some(id)) = (std::env::var_os(CHILD_ROOT), std::env::var(CHILD_ITEM).ok())
    else {
        return;
    };
    let roots = StorageRoots::relaxed(Path::new(&root)).unwrap();
    let id: ExpiryId = id.parse().unwrap();
    let ids = [id];
    let report = purge(&roots, &ids, &all(&ids), at_day(30)).unwrap();
    assert_eq!(report.items[0].outcome, PurgeOutcome::Purged);
}

#[cfg(feature = "fault-inject")]
#[test]
fn a_crash_in_the_middle_of_the_walk_is_finished_by_the_next_run() {
    /// The exit code of a process ended by `std::process::abort` on Windows (`__fastfail`).
    const ABORT_CODE: i32 = 0xC000_0409_u32 as i32;

    let fx = Fx::new("crash");
    let target = canary(&fx.scratch, "canary");
    let before = snapshot(&target);
    let item = fx.scratch.dir(r"src\item");
    fx.scratch.file(r"src\item\a.txt", b"a");
    fx.scratch.file(r"src\item\sub\b.txt", b"b");
    fx.scratch.file(r"src\item\sub\c.txt", b"c");
    junction(&fx.scratch.path(r"src\item\sub\link"), &target);
    let built = build(&fx, at_day(0), &[app(item)], false, true);

    // The second listing is the one of `sub`: `a.txt` is gone by then, `sub` is not.
    let code = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "expiry::tests::child_expiry_scenario",
            "--test-threads=1",
        ])
        .env(CHILD_ROOT, fx.roots.data_root())
        .env(CHILD_ITEM, built.ids[0].to_string())
        .env(fault::ENV_AT, format!("{}:2", fault::EXPIRY_MID))
        .env_remove(fault::ENV_PAUSE)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .code();
    assert_eq!(code, Some(ABORT_CODE));
    let root = &built.quarantined[0];
    assert!(!exists(&format!(r"{root}\a.txt")));
    assert!(exists(&format!(r"{root}\sub\b.txt")));
    assert_eq!(
        expire_records(&built.session),
        [(OpId(1), RetentionClass::Quarantine)],
        "the expiry was recorded before the walk"
    );
    let listing = expiring(&fx.roots, at_day(30)).unwrap();
    assert_eq!(listing.items.len(), 1);
    assert!(listing.items[0].unfinished);

    let report = purge(&fx.roots, &built.ids, &all(&built.ids), at_day(30)).unwrap();
    assert_eq!(report.items[0].outcome, PurgeOutcome::Purged, "{report:?}");
    assert!(!report.items[0].expire_recorded);
    assert!(!exists(root));
    assert_eq!(snapshot(&target), before);
    assert_eq!(expire_records(&built.session).len(), 1);
    assert_deletes_inside(&fx.quarantine_of(built.session.id()));
}
