//! Tests of the file actions on real objects: each test works in its own fresh temp directory, with a
//! relaxed store and a real journal inside it, and touches nothing outside it. Junctions, hard links,
//! alternate data streams, long paths and locks are built for real. A second volume is simulated (a
//! volume probe that reports the source volume as unusable, and the pure serial and rename checks); the
//! real cross-volume case is an `#[ignore]`d test that needs `PURGE_TEST_OTHER_VOLUME_DIR`.

use std::collections::BTreeMap;
use std::os::windows::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use purge_guard::canon::{GuardEnv, ProfileEnv};
use purge_guard::deny::DenyList;
use purge_model::exec::journal::{Header, JournalSchema, Validated};
use purge_model::{ScanMode, Target};
use purge_win::fs::list_dir;
use purge_win::fs_write::{FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY, list_streams};
use purge_win::secure::{handle_security, open_for_security};
use purge_win::sid::current_user_sid;

use super::*;
use crate::gate::{GateItem, Validation, exemptions_to_journal, validate_all};
use crate::journal::{JournalWriter, sha256_bytes};
use crate::storage::{StorageRoots, SystemVolumes, VolumeFacts as StoreVolumeFacts, VolumeProbe};

// ---------------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------------

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A fresh directory below the temp directory (its final, long-form path), removed on drop. Junctions
/// below it are removed as links; read-only attributes are cleared first.
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
            "purge-fs-{tag}-{:x}-{nanos:x}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let final_path = FileHandle::open(&dir).unwrap().final_path().unwrap();
        Scratch {
            root: strip_verbatim(&final_path).to_owned(),
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
    !matches!(look_at(path), PathNow::Missing)
}

fn junction(link: &str, target: &str) {
    let st = Command::new("cmd")
        .args(["/c", "mklink", "/J", link, target])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "mklink /J {link} {target}");
}

fn attrib(flags: &[&str], path: &str) {
    let st = Command::new("cmd")
        .args(["/c", "attrib"])
        .args(flags)
        .arg(path)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "attrib {flags:?} {path}");
}

fn env_var(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

/// A `GuardEnv` for this machine and user, with the test store's data root as one of Purge's directories.
fn live_env(data_root: &str) -> GuardEnv {
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
        purge_dirs: vec![
            format!(r"{}\Purge", env_var("ProgramData")),
            data_root.to_owned(),
        ],
        ..GuardEnv::default()
    }
}

/// Exemptions of an item whose path is in long form.
fn long() -> Exemptions {
    Exemptions {
        long_names_resolved: true,
        ..Exemptions::default()
    }
}

fn mv(path: &str) -> ExecOp {
    ExecOp::QuarantineMove {
        path: path.to_owned(),
    }
}

fn rmdir(path: &str) -> ExecOp {
    ExecOp::RemoveDirIfEmpty {
        path: path.to_owned(),
    }
}

fn item(n: u32) -> CandidateId {
    CandidateId(format!("c-{n:03}"))
}

/// Retries without sleeping.
fn no_wait() -> Retry {
    Retry::with(RETRY_DELAYS.to_vec(), |_| {})
}

/// A relaxed store at `<scratch>\data`.
fn store(s: &Scratch) -> StorageRoots {
    StorageRoots::install_relaxed(Path::new(&s.path("data"))).unwrap()
}

/// How one op's run ended.
#[derive(Debug)]
enum Ran {
    /// Decided before any intent.
    Decided(FsResult),
    /// Locked when the handle was opened.
    LockedAtOpen(Box<LockedItem>),
    /// Acted (after a durable intent) and verified.
    Acted(FsResult),
    /// Locked at the act, after the intent.
    LockedAtAct(Box<LockedItem>),
}

impl Ran {
    fn result(self) -> FsResult {
        match self {
            Ran::Decided(r) | Ran::Acted(r) => r,
            other => panic!("expected a result, got {other:?}"),
        }
    }
}

/// One session: a scratch directory, a relaxed store and a journal, with every op validated.
struct Env {
    session: SessionDir,
    ctx: GateCtx,
    journal: JournalWriter,
    ops: Vec<ExecOp>,
    validations: Vec<GateOutcome<Validation>>,
    intents: BTreeMap<u32, Intent>,
    dones: BTreeMap<u32, ItemOutcome>,
    // Dropped last: everything above lives inside it.
    s: Scratch,
}

impl Env {
    fn new(s: Scratch, ops: Vec<ExecOp>) -> Env {
        let roots = store(&s);
        Env::with_roots(s, roots, ops)
    }

    fn with_roots(s: Scratch, roots: StorageRoots, ops: Vec<ExecOp>) -> Env {
        let data_root = roots.data_root().to_str().unwrap().to_owned();
        Env::with_guard(s, roots, ops, live_env(&data_root))
    }

    /// [`Env::with_roots`] with the deny-list compiled from `guard`.
    fn with_guard(s: Scratch, roots: StorageRoots, ops: Vec<ExecOp>, guard: GuardEnv) -> Env {
        let session = roots.create_session().unwrap();
        let scope = roots.store_scope::<&Path>(session.id(), &[]).unwrap();
        let mut ctx = GateCtx::new(DenyList::compile(&guard), &ops, scope).unwrap();
        let validations: Vec<_> = validate_all(
            &ctx,
            ops.iter()
                .enumerate()
                .map(|(i, op)| (OpId(i as u32 + 1), GateItem::new(op, long()))),
        )
        .into_iter()
        .map(|(_, outcome)| outcome)
        .collect();
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
            items: ops.len() as u32,
            allow_irreversible: false,
            volumes: Vec::new(),
        };
        let mut journal = JournalWriter::create(&session, header).unwrap();
        // As the executor does: write each `validated` record, then hand the written record to the
        // gate, the only source of what the act is gated with.
        for (i, (op, outcome)) in ops.iter().zip(&validations).enumerate() {
            let record = Validated {
                op: OpId(i as u32 + 1),
                item: item(i as u32 + 1),
                target: op.target(),
                facts: outcome.item_facts().unwrap_or(ItemFacts::Absent),
                exemptions: exemptions_to_journal(&long()),
            };
            journal.validated(record.clone()).unwrap();
            if matches!(outcome, GateOutcome::Pass(_)) {
                ctx.record(op, &record, GateItem::new(op, long()).max_files)
                    .unwrap();
            }
        }
        Env {
            session,
            ctx,
            journal,
            ops,
            validations,
            intents: BTreeMap::new(),
            dones: BTreeMap::new(),
            s,
        }
    }

    fn validation(&self, n: u32) -> &Validation {
        match &self.validations[n as usize - 1] {
            GateOutcome::Pass(v) => v,
            other => panic!("op {n} did not validate: {other:?}"),
        }
    }

    fn prepare(&self, n: u32, retry: &Retry) -> FsPrepared {
        prepare_fs(&self.ctx, &self.session, OpId(n), retry).unwrap()
    }

    /// The executor's sequence for op `n`, journalled. A locked item is journalled as `Failed{InUse}` (the
    /// ladder is another package).
    fn run_with(&mut self, n: u32, retry: &Retry) -> Ran {
        let locked_outcome = || ItemOutcome::Failed {
            code: FailCode::InUse,
            os_error: None,
            detail: String::new(),
        };
        match self.prepare(n, retry) {
            FsPrepared::Decided(result) => {
                self.journal
                    .done_without_intent(OpId(n), result.outcome.clone())
                    .unwrap();
                self.dones.insert(n, result.outcome.clone());
                Ran::Decided(result)
            }
            FsPrepared::Locked(locked) => {
                self.journal
                    .done_without_intent(OpId(n), locked_outcome())
                    .unwrap();
                self.dones.insert(n, locked_outcome());
                Ran::LockedAtOpen(locked)
            }
            FsPrepared::Ready(action) => {
                let intent = action.intent().clone();
                assert!(intent.is_consistent(), "{intent:?}");
                let token = self.journal.intent(intent.clone()).unwrap();
                self.intents.insert(n, intent);
                fault::point(fault::ACT_BEFORE);
                match act_fs(action, &token, retry) {
                    FsActed::Finished(result) => {
                        self.journal.done(token, result.outcome.clone()).unwrap();
                        self.dones.insert(n, result.outcome.clone());
                        Ran::Acted(result)
                    }
                    FsActed::Locked(locked) => {
                        self.journal.done(token, locked_outcome()).unwrap();
                        self.dones.insert(n, locked_outcome());
                        Ran::LockedAtAct(locked)
                    }
                }
            }
        }
    }

    fn run(&mut self, n: u32) -> FsResult {
        self.run_with(n, &no_wait()).result()
    }

    /// Writes op `n`'s intent and returns its token, without acting (a crash after the intent).
    fn intent_only(&mut self, n: u32) -> (Box<FsAction>, IntentToken) {
        let FsPrepared::Ready(action) = self.prepare(n, &no_wait()) else {
            panic!("op {n} is not ready");
        };
        let token = self.journal.intent(action.intent().clone()).unwrap();
        self.intents.insert(n, action.intent().clone());
        (action, token)
    }

    /// The undo driver's sequence for op `n`, journalled.
    fn undo(&mut self, n: u32) -> FsUndo {
        self.undo_intent_as(n, None)
    }

    /// [`Env::undo`] with the op's intent replaced by `intent` (a journal read back with other facts).
    fn undo_intent_as(&mut self, n: u32, intent: Option<Intent>) -> FsUndo {
        let intent = intent.unwrap_or_else(|| self.intents[&n].clone());
        // The undo is gated with the exemptions of the op's journalled `validated` record, which the
        // fixture handed to `ctx` (`long()`).
        match plan_undo_fs(&intent, self.dones.get(&n)).unwrap() {
            FsUndoPlan::Decided(undo) => {
                match &undo {
                    FsUndo::Done { outcome, .. } => self
                        .journal
                        .undo_done_without_intent(OpId(n), outcome.clone())
                        .unwrap(),
                    FsUndo::Conflict {
                        conflict, detail, ..
                    } => self
                        .journal
                        .undo_conflict_without_intent(OpId(n), conflict.clone(), detail.clone())
                        .unwrap(),
                }
                undo
            }
            FsUndoPlan::Run(job) => {
                assert_eq!(job.op(), OpId(n));
                let token = self.journal.undo_intent(OpId(n)).unwrap();
                let undo = undo_fs(&self.ctx, &self.session, job, &no_wait(), &token).unwrap();
                match &undo {
                    FsUndo::Done { outcome, .. } => {
                        self.journal.undo_done(token, outcome.clone()).unwrap()
                    }
                    FsUndo::Conflict {
                        conflict, detail, ..
                    } => self
                        .journal
                        .undo_conflict(token, conflict.clone(), detail.clone())
                        .unwrap(),
                }
                undo
            }
        }
    }

    /// The path op `n`'s item has in quarantine.
    fn quarantine_path(&self, n: u32) -> String {
        match &self.intents[&n].inverse {
            Inverse::MoveBack {
                quarantine_path, ..
            } => quarantine_path.clone(),
            other => panic!("{other:?}"),
        }
    }

    /// `<data root>\Quarantine\<session>\<op>`.
    fn op_dir(&self, n: u32) -> PathBuf {
        self.session
            .roots()
            .quarantine_path()
            .join(self.session.id().as_str())
            .join(OpId(n).file_stem())
    }
}

#[track_caller]
fn assert_done(result: &FsResult) {
    assert_eq!(result.outcome, ItemOutcome::Done, "{result:?}");
}

#[track_caller]
fn assert_restored(undo: &FsUndo) {
    assert!(
        matches!(
            undo,
            FsUndo::Done {
                outcome: UndoOutcome::Restored,
                ..
            }
        ),
        "{undo:?}"
    );
}

#[track_caller]
fn assert_skipped(result: &FsResult, reason: SkipReason) {
    assert_eq!(
        result.outcome,
        ItemOutcome::Skipped { reason },
        "{}",
        result.detail
    );
}

// ---------------------------------------------------------------------------------------------------
// Snapshots: what a round trip must preserve
// ---------------------------------------------------------------------------------------------------

/// Everything a do + undo must give back for one object.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Snap {
    is_dir: bool,
    reparse_tag: u32,
    attributes: u32,
    n_links: u32,
    size: u64,
    identity: (u64, [u8; 16]),
    creation_time: u64,
    last_write_time: u64,
    sddl: String,
    /// Every data stream (`::$DATA`, `:name:$DATA`) with its content.
    streams: Vec<(String, Vec<u8>)>,
}

fn snap_one(path: &str) -> Snap {
    let p = ext(path);
    let handle = FileHandle::open(&p).unwrap();
    let meta = handle.metadata().unwrap();
    let sddl = handle_security(&open_for_security(&p).unwrap())
        .unwrap()
        .sddl;
    let streams = if meta.reparse_tag != 0 {
        Vec::new()
    } else {
        list_streams(&p)
            .unwrap()
            .into_iter()
            .map(|s| {
                // `::$DATA` is the main stream, `:name:$DATA` the stream `name`.
                let suffix = s.name.strip_suffix(":$DATA").unwrap().trim_end_matches(':');
                let data = std::fs::read(format!("{}{suffix}", p.display())).unwrap();
                (s.name, data)
            })
            .collect()
    };
    Snap {
        is_dir: meta.is_dir,
        reparse_tag: meta.reparse_tag,
        attributes: meta.attributes,
        n_links: meta.n_links,
        size: if meta.is_dir { 0 } else { meta.size },
        identity: (meta.file_id.volume_serial, meta.file_id.id),
        creation_time: meta.creation_time,
        last_write_time: meta.last_write_time,
        sddl,
        streams,
    }
}

/// The snapshot of `root` and of everything below it (relative names), never descending into a reparse
/// point.
fn snap_tree(root: &str) -> BTreeMap<String, Snap> {
    let mut out = BTreeMap::new();
    let mut stack = vec![String::new()];
    while let Some(rel) = stack.pop() {
        let path = if rel.is_empty() {
            root.to_owned()
        } else {
            format!(r"{root}\{rel}")
        };
        let snap = snap_one(&path);
        if snap.is_dir && snap.reparse_tag == 0 {
            for entry in list_dir(&ext(&path)).unwrap() {
                stack.push(if rel.is_empty() {
                    entry.name
                } else {
                    format!(r"{rel}\{}", entry.name)
                });
            }
        }
        out.insert(rel, snap);
    }
    out
}

// ---------------------------------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------------------------------

#[test]
fn a_read_only_hidden_file_with_streams_comes_back_unchanged() {
    let s = Scratch::new("file");
    let f = s.file(r"src\app.dll", b"main content");
    std::fs::write(format!("{f}:Zone.Identifier"), b"[ZoneTransfer]").unwrap();
    std::fs::write(format!("{f}:second"), b"another stream").unwrap();
    attrib(&["+R", "+H"], &f);
    let before = snap_one(&f);
    assert_eq!(before.streams.len(), 3, "{before:?}");
    assert_eq!(
        before.attributes & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN),
        FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN
    );

    let mut env = Env::new(s, vec![mv(&f)]);
    assert_done(&env.run(1));
    // The intent recorded the item and its quarantine place.
    let intent = env.intents[&1].clone();
    let Inverse::MoveBack {
        quarantine_path,
        original_path,
        file_id,
        volume_serial,
        ..
    } = &intent.inverse
    else {
        panic!("{intent:?}");
    };
    assert_eq!(original_path, &f);
    assert_eq!(
        (*volume_serial, file_id.0),
        (before.identity.0, before.identity.1)
    );
    assert!(
        prefix::is_same(
            quarantine_path,
            env.op_dir(1).join("app.dll").to_str().unwrap()
        ),
        "{quarantine_path}"
    );
    assert!(!exists(&f));
    // In quarantine it is the same object with everything it had.
    assert_eq!(snap_one(quarantine_path), before);

    assert_restored(&env.undo(1));
    assert_eq!(snap_one(&f), before);
    assert!(!exists(quarantine_path));
}

#[test]
fn a_directory_moves_whole_with_streams_hard_links_and_a_junction_inside() {
    let s = Scratch::new("tree");
    let d = s.dir(r"src\App");
    s.file(r"src\App\bin\app.exe", b"exe");
    s.file(r"src\App\bin\readme.txt", b"read me");
    let a = s.file(r"src\App\data\a.dat", b"linked data");
    std::fs::hard_link(&a, s.path(r"src\App\data\b.dat")).unwrap();
    std::fs::write(format!("{d}:dirstream"), b"on the directory").unwrap();
    attrib(&["+H"], &s.path(r"src\App\data"));
    // A junction inside the tree to a directory outside it: moved as a link, its target never touched.
    let outside = s.dir("outside");
    let canary = s.file(r"outside\canary.txt", b"do not touch");
    junction(&s.path(r"src\App\link"), &outside);
    let outside_before = snap_tree(&outside);
    let before = snap_tree(&d);
    assert_eq!(before["data\\a.dat"].n_links, 2);
    assert_ne!(before["link"].reparse_tag, 0);

    let mut env = Env::new(s, vec![mv(&d)]);
    let ItemFacts::File(facts) = &env.validation(1).facts else {
        panic!()
    };
    assert_eq!(facts.tree_entries, Some(7), "{facts:?}");
    assert_done(&env.run(1));
    assert!(!exists(&d));
    let q = env.quarantine_path(1);
    assert_eq!(snap_tree(&q), before);
    assert_eq!(snap_tree(&outside), outside_before);
    assert_eq!(std::fs::read(&canary).unwrap(), b"do not touch");

    assert_restored(&env.undo(1));
    assert_eq!(snap_tree(&d), before);
    assert_eq!(snap_tree(&outside), outside_before);
}

#[test]
fn a_long_path_round_trip() {
    let s = Scratch::new("long");
    let mut rel = String::from("src");
    while rel.len() < 300 {
        rel.push_str(r"\a-rather-long-directory-name-0123456789");
    }
    let f = s.file(&format!(r"{rel}\leftover.cfg"), b"long");
    assert!(f.len() > 260, "{}", f.len());
    let before = snap_one(&f);
    let mut env = Env::new(s, vec![mv(&f)]);
    assert_done(&env.run(1));
    assert!(!exists(&f));
    assert_restored(&env.undo(1));
    assert_eq!(snap_one(&f), before);
}

#[test]
fn trailing_dot_and_space_names_are_refused_and_left_alone() {
    let s = Scratch::new("dots");
    let dot = s.file(r"src\name.", b"dot");
    let space = s.file(r"src\name ", b"space");
    let env = Env::new(s, vec![mv(&dot), mv(&space)]);
    for (n, path) in [(1, &dot), (2, &space)] {
        let outcome = &env.validations[n - 1];
        let refusal = outcome.refusal().unwrap_or_else(|| panic!("{outcome:?}"));
        assert!(
            matches!(&refusal.blocker, Blocker::DenyListed { rule } if rule.starts_with("canon.")),
            "{refusal:?}"
        );
        let result = gate_result(outcome).unwrap();
        assert_skipped(
            &result,
            SkipReason::GateBlocked {
                blocker: refusal.blocker.clone(),
            },
        );
        assert!(exists(path));
    }
    assert_eq!(std::fs::read(ext(&dot)).unwrap(), b"dot");
}

// ---------------------------------------------------------------------------------------------------
// Nested delete (§10.1)
// ---------------------------------------------------------------------------------------------------

#[test]
fn nested_delete_child_then_empty_parent_and_undo_parent_first() {
    let s = Scratch::new("nested");
    let p = s.dir(r"src\Vendor");
    let c = s.file(r"src\Vendor\settings.ini", b"[a]\nb=1\n");
    attrib(&["+H"], &p);
    let parent_before = snap_one(&p);
    let child_before = snap_one(&c);

    let mut env = Env::new(s, vec![mv(&c), rmdir(&p)]);
    assert_done(&env.run(1));
    assert_done(&env.run(2));
    assert!(!exists(&p));
    let Inverse::RecreateDir {
        attributes, sddl, ..
    } = &env.intents[&2].inverse
    else {
        panic!()
    };
    assert_eq!(
        (*attributes, sddl.as_str()),
        (parent_before.attributes, parent_before.sddl.as_str())
    );

    // The child cannot go back while its parent is missing; nothing is created for it. (Changed: the
    // conflict was `GateBlocked{DenyListed{act_fs.undo-parent-missing}}` until the model had
    // `UndoConflict::ParentMissing`.)
    let early = env.undo(1);
    assert!(
        matches!(
            &early,
            FsUndo::Conflict {
                conflict: UndoConflict::ParentMissing,
                ..
            }
        ),
        "{early:?}"
    );
    assert!(!exists(&p));
    assert!(exists(&env.quarantine_path(1)));

    // The driver's order: RecreateDir first, then the move back.
    assert_restored(&env.undo(2));
    assert_restored(&env.undo(1));
    let parent_after = snap_one(&p);
    // Attributes, creation time and the whole descriptor (owner, group, the DACL's control flags
    // including `AI`, every ACE) come back. The last-write time is the recorded one until the child is
    // moved back in, which changes it again (the round trip below without a child compares it too).
    assert_eq!(
        (
            parent_after.attributes,
            parent_after.creation_time,
            parent_after.sddl.as_str()
        ),
        (
            parent_before.attributes,
            parent_before.creation_time,
            parent_before.sddl.as_str()
        )
    );
    assert!(
        parent_before.sddl.contains("D:AI"),
        "{}",
        parent_before.sddl
    );
    assert_eq!(snap_one(&c), child_before);
}

#[test]
fn a_recreated_directory_has_its_recorded_times_attributes_and_whole_descriptor() {
    let s = Scratch::new("rmdirtimes");
    let p = s.dir(r"src\Empty");
    attrib(&["+H", "+R"], &p);
    let before = snap_one(&p);
    let mut env = Env::new(s, vec![rmdir(&p)]);
    assert_done(&env.run(1));
    assert!(!exists(&p));
    let undo = env.undo(1);
    assert_restored(&undo);
    let FsUndo::Done { detail, .. } = &undo else {
        panic!()
    };
    assert!(detail.is_empty(), "{detail}");
    let after = snap_one(&p);
    assert_ne!(after.identity, before.identity, "a new directory");
    assert_eq!(
        (
            after.attributes,
            after.creation_time,
            after.last_write_time,
            after.sddl.as_str()
        ),
        (
            before.attributes,
            before.creation_time,
            before.last_write_time,
            before.sddl.as_str()
        )
    );
    assert!(before.sddl.contains("D:AI"), "{}", before.sddl);
}

#[test]
fn nested_delete_parent_with_an_unowned_child_stays() {
    let s = Scratch::new("unowned");
    let p = s.dir(r"src\Vendor");
    let c = s.file(r"src\Vendor\owned.log", b"owned");
    let u = s.file(r"src\Vendor\user-notes.txt", b"not ours");
    let parent_before = snap_one(&p);
    let child_before = snap_one(&c);

    let mut env = Env::new(s, vec![mv(&c), rmdir(&p)]);
    assert_done(&env.run(1));
    assert_skipped(&env.run(2), SkipReason::NoLongerEmpty);
    assert_eq!(snap_one(&p).identity, parent_before.identity);
    assert_eq!(std::fs::read(&u).unwrap(), b"not ours");

    // Undo: the skipped removal has nothing to undo, the child goes back into its parent.
    assert!(matches!(
        env.undo(2),
        FsUndo::Done {
            outcome: UndoOutcome::NothingToUndo,
            ..
        }
    ));
    assert_restored(&env.undo(1));
    assert_eq!(snap_one(&c), child_before);
    assert_eq!(std::fs::read(&u).unwrap(), b"not ours");
}

#[test]
fn a_directory_that_gained_an_entry_after_the_intent_is_no_longer_empty() {
    let s = Scratch::new("gained");
    let p = s.dir(r"src\Empty");
    let mut env = Env::new(s, vec![rmdir(&p)]);
    let (action, token) = env.intent_only(1);
    std::fs::write(format!(r"{p}\new.txt"), b"new").unwrap();
    let FsActed::Finished(result) = act_fs(action, &token, &no_wait()) else {
        panic!()
    };
    env.journal.done(token, result.outcome.clone()).unwrap();
    assert_skipped(&result, SkipReason::NoLongerEmpty);
    assert!(exists(&format!(r"{p}\new.txt")));
}

// ---------------------------------------------------------------------------------------------------
// Refusals and changes
// ---------------------------------------------------------------------------------------------------

#[test]
fn a_junction_as_the_item_is_never_moved_or_traversed() {
    let s = Scratch::new("junction");
    let target = s.dir("target");
    let canary = s.file(r"target\canary.txt", b"canary");
    let j = s.path(r"src\Link");
    s.dir("src");
    junction(&j, &target);
    let env = Env::new(s, vec![mv(&j)]);
    let refusal = env.validations[0].refusal().unwrap();
    assert_eq!(refusal.blocker, Blocker::ReparseMismatch, "{refusal:?}");
    assert_skipped(
        &gate_result(&env.validations[0]).unwrap(),
        SkipReason::GateBlocked {
            blocker: Blocker::ReparseMismatch,
        },
    );
    assert_ne!(snap_one(&j).reparse_tag, 0);
    assert_eq!(std::fs::read(&canary).unwrap(), b"canary");
}

#[test]
fn a_junction_swapped_in_after_validation_is_changed_since_scan() {
    let s = Scratch::new("swap");
    let d = s.dir(r"src\App");
    s.file(r"src\App\x.txt", b"x");
    let target = s.dir("target");
    let canary = s.file(r"target\canary.txt", b"canary");
    let mut env = Env::new(s, vec![mv(&d)]);
    std::fs::rename(&d, env.s.path(r"src\App.old")).unwrap();
    junction(&d, &target);
    let result = env.run(1);
    assert_skipped(&result, SkipReason::ChangedSinceScan);
    assert_ne!(snap_one(&d).reparse_tag, 0);
    assert_eq!(std::fs::read(&canary).unwrap(), b"canary");
    // No quarantine directory was made for it.
    assert!(!env.op_dir(1).exists());
}

#[test]
fn a_file_replaced_after_validation_is_changed_since_scan_and_a_missing_one_vanished() {
    let s = Scratch::new("changed");
    let f = s.file(r"src\a.txt", b"first");
    let g = s.file(r"src\b.txt", b"there");
    let mut env = Env::new(s, vec![mv(&f), mv(&g)]);
    std::fs::remove_file(&f).unwrap();
    std::fs::write(&f, b"second").unwrap();
    std::fs::remove_file(&g).unwrap();
    assert_skipped(&env.run(1), SkipReason::ChangedSinceScan);
    assert_eq!(std::fs::read(&f).unwrap(), b"second");
    assert_eq!(env.run(2).outcome, ItemOutcome::Vanished);
    // Neither changed anything, so neither has anything to undo.
    for n in [1, 2] {
        assert!(matches!(
            plan_undo_fs(
                &Intent {
                    op: OpId(n),
                    item: item(n),
                    exec_op: env.ops[n as usize - 1].clone(),
                    inverse: Inverse::None,
                    definition: None,
                    pre: ItemFacts::Absent,
                },
                env.dones.get(&n),
            ),
            Some(FsUndoPlan::Decided(FsUndo::Done {
                outcome: UndoOutcome::NothingToUndo,
                ..
            }))
        ));
    }
}

#[test]
fn both_names_of_a_hard_link_pair_move_and_come_back_and_an_outside_link_is_refused() {
    let s = Scratch::new("links");
    let a = s.file(r"src\a.dll", b"shared");
    let outside = s.path(r"elsewhere\a-link.dll");
    s.dir("elsewhere");
    std::fs::hard_link(&a, &outside).unwrap();
    let b = s.file(r"src\pair\one.bin", b"pair");
    let c = s.path(r"src\pair\two.bin");
    std::fs::hard_link(&b, &c).unwrap();

    let mut env = Env::new(s, vec![mv(&a), mv(&b), mv(&c)]);
    // A link whose other name is truly outside the plan is refused and stays.
    let refusal = env.validations[0].refusal().unwrap();
    assert_eq!(refusal.blocker, Blocker::HardLinkOutsidePlan);
    assert!(exists(&a) && exists(&outside));
    // Both names of the pair are in the plan, so the first one moves; the file keeps both links.
    let before_b = snap_one(&b);
    let before_c = snap_one(&c);
    assert_eq!(before_b.n_links, 2);
    assert_done(&env.run(2));
    assert_eq!(snap_one(&env.quarantine_path(2)).n_links, 2);
    // The second name now has its other link in this session's quarantine, the same file: it counts as
    // inside the plan and moves too.
    assert_done(&env.run(3));
    assert!(!exists(&b) && !exists(&c));
    let q3 = snap_one(&env.quarantine_path(3));
    assert_eq!((q3.n_links, q3.identity), (2, before_b.identity));

    // Undo in reverse order: both names come back as the one file, with its content.
    assert_restored(&env.undo(3));
    assert_restored(&env.undo(2));
    let after_b = snap_one(&b);
    let after_c = snap_one(&c);
    assert_eq!(after_b, before_b);
    assert_eq!(after_c, before_c);
    assert_eq!(after_b.identity, after_c.identity);
    assert_eq!(after_b.n_links, 2);
    assert_eq!(std::fs::read(&c).unwrap(), b"pair");
}

// ---------------------------------------------------------------------------------------------------
// Undo conflicts
// ---------------------------------------------------------------------------------------------------

#[test]
fn an_occupied_original_path_on_undo_is_a_conflict_and_nothing_is_overwritten() {
    let s = Scratch::new("occupied");
    let f = s.file(r"src\app.cfg", b"quarantined");
    let p = s.dir(r"src\Cache");
    let q = s.dir(r"src\Logs");
    let mut env = Env::new(s, vec![mv(&f), rmdir(&p), rmdir(&q)]);
    for n in 1..=3 {
        assert_done(&env.run(n));
    }
    std::fs::write(&f, b"new owner").unwrap();
    std::fs::write(&p, b"a file now").unwrap();
    std::fs::create_dir(&q).unwrap();

    assert!(matches!(
        env.undo(1),
        FsUndo::Conflict {
            conflict: UndoConflict::DestinationExists,
            ..
        }
    ));
    assert_eq!(std::fs::read(&f).unwrap(), b"new owner");
    assert_eq!(
        std::fs::read(env.quarantine_path(1)).unwrap(),
        b"quarantined"
    );
    assert!(matches!(
        env.undo(2),
        FsUndo::Conflict {
            conflict: UndoConflict::DestinationExists,
            ..
        }
    ));
    assert_eq!(std::fs::read(&p).unwrap(), b"a file now");
    assert!(matches!(
        env.undo(3),
        FsUndo::Done {
            outcome: UndoOutcome::AlreadyRestored,
            ..
        }
    ));

    // Once the place is free again, a later undo attempt restores it.
    std::fs::remove_file(&f).unwrap();
    assert_restored(&env.undo(1));
    assert_eq!(std::fs::read(&f).unwrap(), b"quarantined");
}

#[test]
fn another_item_in_quarantine_is_a_file_id_mismatch_and_a_missing_one_quarantine_missing() {
    let s = Scratch::new("mismatch");
    let f = s.file(r"src\a.txt", b"a");
    let g = s.file(r"src\b.txt", b"b");
    let mut env = Env::new(s, vec![mv(&f), mv(&g)]);
    assert_done(&env.run(1));
    assert_done(&env.run(2));
    let qa = env.quarantine_path(1);
    std::fs::remove_file(&qa).unwrap();
    std::fs::write(&qa, b"impostor").unwrap();
    assert!(matches!(
        env.undo(1),
        FsUndo::Conflict {
            conflict: UndoConflict::FileIdMismatch,
            ..
        }
    ));
    assert!(!exists(&f));
    std::fs::remove_file(env.quarantine_path(2)).unwrap();
    assert!(matches!(
        env.undo(2),
        FsUndo::Conflict {
            conflict: UndoConflict::QuarantineMissing,
            ..
        }
    ));
}

#[test]
fn undo_after_a_crash_between_intent_and_done() {
    let s = Scratch::new("crash");
    let f = s.file(r"src\never-moved.txt", b"stays");
    let g = s.file(r"src\moved.txt", b"moves");
    let mut env = Env::new(s, vec![mv(&f), mv(&g)]);
    // Op 1: the intent is durable, the act never ran: the item is still in place.
    let (action, token) = env.intent_only(1);
    drop(action);
    drop(token);
    assert!(matches!(
        env.undo(1),
        FsUndo::Done {
            outcome: UndoOutcome::AlreadyRestored,
            ..
        }
    ));
    // Op 2: the act ran, the done was never written: the item is moved back.
    let (action, token) = env.intent_only(2);
    let FsActed::Finished(result) = act_fs(action, &token, &no_wait()) else {
        panic!()
    };
    assert_done(&result);
    drop(token);
    assert_restored(&env.undo(2));
    assert_eq!(std::fs::read(&g).unwrap(), b"moves");
}

#[test]
fn a_recorded_owner_the_token_cannot_assign_falls_back_to_the_default_owner() {
    let s = Scratch::new("owner");
    let p = s.dir(r"src\Owned");
    let mut env = Env::new(s, vec![rmdir(&p)]);
    assert_done(&env.run(1));
    let mut intent = env.intents[&1].clone();
    let Inverse::RecreateDir { sddl, .. } = &mut intent.inverse else {
        panic!()
    };
    let dacl = sddl[sddl.find("D:").unwrap()..].to_owned();
    // SYSTEM as owner: an unelevated token cannot assign it.
    *sddl = format!("O:SYG:SY{dacl}");
    let undo = env.undo_intent_as(1, Some(intent));
    let FsUndo::Done {
        outcome: UndoOutcome::Restored,
        detail,
    } = &undo
    else {
        panic!("{undo:?}");
    };
    assert!(
        detail.contains("1307") || detail.contains("1308"),
        "{detail}"
    );
    let after = snap_one(&p);
    assert!(after.is_dir);
    // The token's default owner, the recorded DACL with its control flags (`AI`) and every ACE; Purge
    // took no ownership.
    let after_dacl = &after.sddl[after.sddl.find("D:").unwrap()..];
    assert_eq!(after_dacl, dacl, "{}", after.sddl);
    let me = current_user_sid().unwrap();
    assert!(
        after.sddl.starts_with(&format!("O:{me}")) || after.sddl.starts_with("O:BA"),
        "{}",
        after.sddl
    );
}

/// S1 of the final M2 review: a directory standing where a removed one is to be recreated is adopted
/// as `AlreadyRestored` only when its owner and DACL are the recorded ones. Before the fix any plain
/// directory was `AlreadyRestored`, whoever had created it and whoever may write to it.
#[test]
fn an_existing_directory_counts_as_restored_only_with_the_recorded_owner_and_dacl() {
    let s = Scratch::new("adopt");
    let p = s.dir(r"src\Shared");
    let mut env = Env::new(s, vec![rmdir(&p)]);
    assert_done(&env.run(1));
    // Created again by somebody else, the way the original was: same owner, same inherited DACL.
    std::fs::create_dir(&p).unwrap();
    let Inverse::RecreateDir { sddl, .. } = env.intents[&1].inverse.clone() else {
        panic!()
    };
    let at = sddl.find("D:").unwrap();
    let dacl = &sddl[at..];
    let with_sddl = |env: &mut Env, sddl: String| {
        let mut intent = env.intents[&1].clone();
        let Inverse::RecreateDir { sddl: recorded, .. } = &mut intent.inverse else {
            panic!()
        };
        *recorded = sddl;
        env.undo_intent_as(1, Some(intent))
    };

    // The recorded DACL had one more ACE than the directory now has (or, read the other way, the
    // directory now lets fewer or other principals in): not the recorded directory.
    let more = format!("{}{dacl}(A;OICI;FA;;;WD)", &sddl[..at]);
    let undo = with_sddl(&mut env, more);
    let FsUndo::Conflict {
        conflict: UndoConflict::DestinationExists,
        detail,
    } = &undo
    else {
        panic!("{undo:?}");
    };
    assert!(
        detail.contains("DACL") && !detail.contains("owner"),
        "{detail}"
    );
    // Another recorded owner.
    let undo = with_sddl(&mut env, format!("O:SYG:SY{dacl}"));
    let FsUndo::Conflict {
        conflict: UndoConflict::DestinationExists,
        detail,
    } = &undo
    else {
        panic!("{undo:?}");
    };
    assert!(detail.contains("owner"), "{detail}");

    // An extra ACE on the directory standing there (Everyone, full control): a conflict.
    let status = Command::new("icacls")
        .args([p.as_str(), "/grant", "*S-1-1-0:(OI)(CI)F", "/q"])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(matches!(
        env.undo(1),
        FsUndo::Conflict {
            conflict: UndoConflict::DestinationExists,
            ..
        }
    ));
    assert!(exists(&p), "a conflict changes nothing");

    // Created again with the inherited descriptor only: the recorded owner and DACL, adopted.
    std::fs::remove_dir(&p).unwrap();
    std::fs::create_dir(&p).unwrap();
    assert!(matches!(
        env.undo(1),
        FsUndo::Done {
            outcome: UndoOutcome::AlreadyRestored,
            ..
        }
    ));
}

/// F1 of the M2 fix-round review: the directory a quarantined file was in is removed by something
/// other than the session and created again by somebody else. The file goes back only into a
/// directory with the recorded owner and DACL; before the fix it went into any plain directory there.
#[test]
fn a_move_back_goes_only_into_a_parent_with_the_recorded_owner_and_dacl() {
    let s = Scratch::new("parent");
    let f = s.file(r"src\App\helper.exe", b"helper");
    let keep = s.file(r"src\App\keep.txt", b"not the session's");
    let app = s.path(r"src\App");
    let mut env = Env::new(s, vec![mv(&f)]);
    assert_done(&env.run(1));
    let Inverse::MoveBack {
        parent: Some(parent),
        ..
    } = &env.intents[&1].inverse
    else {
        panic!("{:?}", env.intents[&1].inverse);
    };
    assert!(parent.sddl.contains("D:"), "{}", parent.sddl);

    // Something else removes the directory; somebody creates it again and lets Everyone write to it.
    std::fs::remove_file(&keep).unwrap();
    std::fs::remove_dir(&app).unwrap();
    std::fs::create_dir(&app).unwrap();
    let status = Command::new("icacls")
        .args([app.as_str(), "/grant", "*S-1-1-0:(OI)(CI)F", "/q"])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let undo = env.undo(1);
    let FsUndo::Conflict {
        conflict: UndoConflict::DestinationExists,
        detail,
    } = &undo
    else {
        panic!("{undo:?}");
    };
    assert!(detail.contains("DACL"), "{detail}");
    assert!(!exists(&f), "a conflict moves nothing");
    assert_eq!(std::fs::read(env.quarantine_path(1)).unwrap(), b"helper");

    // Created again with the inherited descriptor only: the recorded owner and DACL, so it goes back.
    std::fs::remove_dir(&app).unwrap();
    std::fs::create_dir(&app).unwrap();
    assert_restored(&env.undo(1));
    assert_eq!(std::fs::read(&f).unwrap(), b"helper");

    // An owner no standard user can set passes in place of the recorded one (what undo's own
    // recreate leaves when SYSTEM cannot be assigned); a user's does not.
    assert!(admin_only_owner("BA") && admin_only_owner("SY") && admin_only_owner("S-1-5-18"));
    assert!(!admin_only_owner(&current_user_sid().unwrap()) && !admin_only_owner("BU"));
}

#[test]
fn sddl_parts_are_cut_at_the_next_part() {
    let full = "O:S-1-5-21-1-2-3-1001G:S-1-5-21-1-2-3-513D:AI(A;OICIID;FA;;;SY)S:(ML;;NW;;;LW)";
    assert_eq!(sddl_part(full, b'O'), Some("S-1-5-21-1-2-3-1001"));
    assert_eq!(sddl_part(full, b'G'), Some("S-1-5-21-1-2-3-513"));
    assert_eq!(sddl_part(full, b'D'), Some("AI(A;OICIID;FA;;;SY)"));
    assert_eq!(sddl_part(full, b'S'), Some("(ML;;NW;;;LW)"));
    assert_eq!(sddl_part("O:BAG:SYD:P(A;;FA;;;BA)", b'O'), Some("BA"));
    assert_eq!(
        sddl_part("O:BAG:SYD:P(A;;FA;;;BA)", b'D'),
        Some("P(A;;FA;;;BA)")
    );
    assert_eq!(sddl_part("D:(A;;FA;;;WD)", b'O'), None);
}

#[test]
fn owner_and_group_are_cut_from_an_sddl() {
    assert_eq!(
        without_owner_and_group("O:S-1-5-21-1-2-3-1001G:S-1-5-21-1-2-3-513D:AI(A;OICIID;FA;;;SY)"),
        "D:AI(A;OICIID;FA;;;SY)"
    );
    assert_eq!(
        without_owner_and_group("O:BAG:SYD:P(A;;FA;;;BA)S:(ML;;NW;;;LW)"),
        "D:P(A;;FA;;;BA)S:(ML;;NW;;;LW)"
    );
    assert_eq!(without_owner_and_group("D:(A;;FA;;;WD)"), "D:(A;;FA;;;WD)");
}

// ---------------------------------------------------------------------------------------------------
// Locks and retries
// ---------------------------------------------------------------------------------------------------

/// A thread that holds `path` open with `share` until released.
struct Locker {
    release: mpsc::Sender<()>,
    thread: thread::JoinHandle<()>,
}

impl Locker {
    fn hold(path: &str, share: u32) -> Locker {
        let path = path.to_owned();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel::<()>();
        let thread = thread::spawn(move || {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .share_mode(share)
                .open(ext(&path))
                .unwrap();
            ready_tx.send(()).unwrap();
            let _ = release_rx.recv();
            drop(file);
        });
        ready_rx.recv().unwrap();
        Locker { release, thread }
    }

    fn release(self) {
        let _ = self.release.send(());
        self.thread.join().unwrap();
    }
}

/// `FILE_SHARE_READ` only: no delete sharing.
const SHARE_READ: u32 = 0x1;
/// Read, write and delete sharing.
const SHARE_ALL: u32 = 0x7;

/// A retry policy with the standard delays that records each wait instead of sleeping, and runs `on_wait`
/// at the first one.
fn recording(on_first_wait: Option<Locker>) -> (Retry, Arc<Mutex<Vec<Duration>>>) {
    let waits = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&waits);
    let locker = Mutex::new(on_first_wait);
    let retry = Retry::with(RETRY_DELAYS.to_vec(), move |delay| {
        seen.lock().unwrap().push(delay);
        if let Some(locker) = locker.lock().unwrap().take() {
            locker.release();
        }
    });
    (retry, waits)
}

#[test]
fn a_file_held_without_delete_sharing_is_retried_three_times_then_locked() {
    let s = Scratch::new("locked");
    let f = s.file(r"src\busy.log", b"busy");
    let mut env = Env::new(s, vec![mv(&f)]);
    let locker = Locker::hold(&f, SHARE_READ);
    let (retry, waits) = recording(None);
    let ran = env.run_with(1, &retry);
    locker.release();
    let Ran::LockedAtOpen(locked) = ran else {
        panic!("{ran:?}");
    };
    assert_eq!(*waits.lock().unwrap(), RETRY_DELAYS.to_vec());
    assert_eq!(locked.attempts, 4);
    assert_eq!(locked.stage, LockedStage::Open);
    assert!(!locked.intent_written());
    assert_eq!(
        (locked.op, &locked.item, &locked.path, &locked.exec_op),
        (OpId(1), &item(1), &f, &mv(&f))
    );
    assert_eq!(locked.locked.error.code(), FsError::SharingViolation.code());
    assert_eq!(
        locked.locked.stamp,
        match env.validation(1).stamp {
            Stamp::Path(stamp) => stamp,
            _ => panic!(),
        }
    );
    assert_eq!(locked.quarantine_path, None);
    // Nothing was made or moved.
    assert!(!env.op_dir(1).exists());
    assert_eq!(std::fs::read(&f).unwrap(), b"busy");
}

#[test]
fn a_file_released_during_the_retries_is_moved() {
    let s = Scratch::new("released");
    let f = s.file(r"src\busy.log", b"busy");
    let mut env = Env::new(s, vec![mv(&f)]);
    let (retry, waits) = recording(Some(Locker::hold(&f, SHARE_READ)));
    assert_done(&env.run_with(1, &retry).result());
    assert_eq!(*waits.lock().unwrap(), vec![RETRY_DELAYS[0]]);
    assert!(!exists(&f));
}

#[test]
fn a_directory_with_an_open_file_below_is_locked_at_the_rename() {
    let s = Scratch::new("dirbusy");
    let d = s.dir(r"src\App");
    let inner = s.file(r"src\App\open.dat", b"open");
    let mut env = Env::new(s, vec![mv(&d)]);
    // Even full sharing below a directory stops its rename.
    let locker = Locker::hold(&inner, SHARE_ALL);
    let (retry, waits) = recording(None);
    let ran = env.run_with(1, &retry);
    locker.release();
    let Ran::LockedAtAct(locked) = ran else {
        panic!("{ran:?}");
    };
    assert_eq!(*waits.lock().unwrap(), RETRY_DELAYS.to_vec());
    assert_eq!(locked.stage, LockedStage::Act);
    assert!(locked.intent_written());
    assert_eq!(locked.attempts, 4);
    assert_eq!(
        locked.quarantine_path.as_deref(),
        Some(env.quarantine_path(1).as_str())
    );
    assert!(exists(&d));
    assert_eq!(std::fs::read(&inner).unwrap(), b"open");
    // A directory is never moved at boot: the empty op directory this call made is gone again.
    assert!(!env.op_dir(1).exists());
    // Journalled as failed: nothing to undo.
    assert!(matches!(
        env.undo(1),
        FsUndo::Done {
            outcome: UndoOutcome::NothingToUndo,
            ..
        }
    ));
}

// ---------------------------------------------------------------------------------------------------
// Op directories
// ---------------------------------------------------------------------------------------------------

#[test]
fn a_refusal_after_the_op_directory_was_made_removes_it_again() {
    let s = Scratch::new("overlap");
    let roots = store(&s);
    let data_root = roots.data_root().to_str().unwrap().to_owned();
    let stray = s.file(r"data\stray.txt", b"stray");
    // A deny-list that does not name the store's data root, so only the destination check sees that the
    // item lies in the store.
    let guard = GuardEnv {
        purge_dirs: vec![format!(r"{}\Purge", env_var("ProgramData"))],
        ..live_env(&data_root)
    };
    let mut env = Env::with_guard(s, roots, vec![mv(&stray)], guard);
    let result = env.run(1);
    assert!(
        matches!(&result.outcome, ItemOutcome::Skipped { .. })
            && result
                .detail
                .contains(purge_guard::live::reason::QUARANTINE_OVERLAP),
        "{result:?}"
    );
    assert_eq!(std::fs::read(&stray).unwrap(), b"stray");
    assert!(!env.op_dir(1).exists());
}

#[test]
fn an_empty_op_directory_left_by_a_crash_is_adopted_and_a_full_one_is_kept() {
    let s = Scratch::new("adopt");
    let f = s.file(r"src\a.txt", b"a");
    let g = s.file(r"src\b.txt", b"b");
    let mut env = Env::new(s, vec![mv(&f), mv(&g)]);
    let serial = match env.validation(1).stamp {
        Stamp::Path(stamp) => stamp.identity.volume_serial,
        _ => panic!(),
    };
    // A crash between the op directory's creation and the intent left it empty.
    for (n, path) in [(1, &f), (2, &g)] {
        drop(
            env.session
                .create_op_dir(Path::new(path), serial, OpId(n))
                .unwrap(),
        );
        assert!(env.op_dir(n).is_dir());
    }
    assert_done(&env.run(1));
    assert_eq!(std::fs::read(env.quarantine_path(1)).unwrap(), b"a");
    assert_restored(&env.undo(1));
    assert_eq!(std::fs::read(&f).unwrap(), b"a");

    // One with anything in it is never adopted: the store failure stands and nothing changes.
    let kept = env.op_dir(2).join("keep.txt");
    std::fs::write(&kept, b"keep").unwrap();
    let prepared = prepare_fs(&env.ctx, &env.session, OpId(2), &no_wait());
    assert!(
        matches!(&prepared, Err(StorageError::OpDirExists(_))),
        "{prepared:?}"
    );
    assert_eq!(std::fs::read(&kept).unwrap(), b"keep");
    assert_eq!(std::fs::read(&g).unwrap(), b"b");
}

// ---------------------------------------------------------------------------------------------------
// Volumes
// ---------------------------------------------------------------------------------------------------

#[test]
fn volume_serial_zero_is_unknown_and_other_volumes_are_never_copied() {
    // Serial 0 never proves anything, not even against 0.
    for (a, b) in [(0, 0), (0, 7), (7, 0)] {
        let err = same_volume(a, b).unwrap_err();
        assert_skipped(
            &err,
            SkipReason::GateBlocked {
                blocker: Blocker::CannotBackUp,
            },
        );
        assert!(err.detail.contains(reason::SERIAL_UNKNOWN), "{err:?}");
    }
    assert_skipped(
        &same_volume(7, 8).unwrap_err(),
        SkipReason::GateBlocked {
            blocker: Blocker::CannotBackUp,
        },
    );
    assert!(same_volume(7, 7).is_ok());
    // A rename the system refuses as cross-volume changed nothing.
    assert_skipped(
        &rename_failure(FsError::NotSameDevice, r"C:\x"),
        SkipReason::GateBlocked {
            blocker: Blocker::CannotBackUp,
        },
    );

    // An intent with serial 0 (a journal written by something else) is never undone.
    let pre = FileFacts {
        final_path: r"C:\x\a.txt".into(),
        file_id: FileIdHex([1; 16]),
        volume_serial: 0,
        reparse_tag: 0,
        attributes: 0x20,
        n_links: 1,
        is_dir: false,
        size: 1,
        tree_entries: None,
        tree_bytes: None,
    };
    let moved = Intent {
        op: OpId(1),
        item: item(1),
        exec_op: mv(r"C:\x\a.txt"),
        inverse: Inverse::MoveBack {
            quarantine_path: r"C:\ProgramData\Purge\Quarantine\s\000001\a.txt".into(),
            original_path: r"C:\x\a.txt".into(),
            file_id: FileIdHex([1; 16]),
            volume_serial: 0,
            parent: None,
        },
        definition: None,
        pre: ItemFacts::File(pre.clone()),
    };
    let removed = Intent {
        op: OpId(2),
        item: item(2),
        exec_op: rmdir(r"C:\x\d"),
        inverse: Inverse::RecreateDir {
            path: r"C:\x\d".into(),
            attributes: 0x10,
            sddl: "D:(A;;FA;;;WD)".into(),
            creation_time: None,
            last_write_time: None,
        },
        definition: None,
        pre: ItemFacts::File(FileFacts {
            is_dir: true,
            final_path: r"C:\x\d".into(),
            ..pre
        }),
    };
    for intent in [&moved, &removed] {
        assert!(intent.is_consistent());
        let plan = plan_undo_fs(intent, Some(&ItemOutcome::Done));
        assert!(
            matches!(
                &plan,
                Some(FsUndoPlan::Decided(FsUndo::Conflict {
                    conflict: UndoConflict::GateBlocked {
                        blocker: Blocker::CannotBackUp
                    },
                    ..
                }))
            ),
            "{plan:?}"
        );
    }
    // An intent whose inverse addresses another item is refused, not acted on.
    let mut skewed = moved.clone();
    skewed.inverse = Inverse::MoveBack {
        quarantine_path: r"C:\q\a.txt".into(),
        original_path: r"C:\Windows\a.txt".into(),
        file_id: FileIdHex([1; 16]),
        volume_serial: 5,
        parent: None,
    };
    assert!(matches!(
        plan_undo_fs(&skewed, Some(&ItemOutcome::Done)),
        Some(FsUndoPlan::Decided(FsUndo::Conflict {
            conflict: UndoConflict::GateBlocked { .. },
            ..
        }))
    ));
}

/// Volume facts as the system reports them, except that the volume of any path below `unusable` is a
/// removable drive.
#[derive(Debug)]
struct UnusableBelow {
    unusable: String,
}

impl VolumeProbe for UnusableBelow {
    fn volume(&self, path: &Path) -> Result<StoreVolumeFacts, FsError> {
        let mut facts = SystemVolumes.volume(path)?;
        if prefix::is_same_or_inside(strip_verbatim(path.to_str().unwrap()), &self.unusable) {
            facts.fixed = false;
        }
        Ok(facts)
    }
}

#[test]
fn a_source_volume_the_store_cannot_use_is_cannot_back_up() {
    let s = Scratch::new("novolume");
    let f = s.file(r"src\a.txt", b"stays");
    let roots = store(&s).with_volume_probe(Arc::new(UnusableBelow {
        unusable: s.path("src"),
    }));
    let mut env = Env::with_roots(s, roots, vec![mv(&f)]);
    let result = env.run(1);
    assert_skipped(
        &result,
        SkipReason::GateBlocked {
            blocker: Blocker::CannotBackUp,
        },
    );
    assert_eq!(std::fs::read(&f).unwrap(), b"stays");
}

/// Volume facts as the system reports them, with every file system called ReFS.
#[derive(Debug)]
struct AllRefs;

impl VolumeProbe for AllRefs {
    fn volume(&self, path: &Path) -> Result<StoreVolumeFacts, FsError> {
        let mut facts = SystemVolumes.volume(path)?;
        facts.fs_name = "ReFS".to_owned();
        Ok(facts)
    }
}

/// Review M5: a change on the journal's own volume is left to the journal's next flush only because
/// NTFS commits its log in order. With the data root on ReFS the change is flushed by itself, as one on
/// another volume is. Before the fix only the volume serial was compared.
#[test]
fn a_change_on_a_journal_volume_that_is_not_ntfs_is_flushed_by_itself() {
    let s = Scratch::new("refs");
    let ntfs = store(&s);
    let serial = crate::report::volume_serial(ntfs.data_root()).unwrap();
    let session = ntfs.create_session().unwrap();
    assert!(!off_journal_volume(&session, serial));
    assert!(off_journal_volume(&session, serial ^ 1));
    drop(session);
    let refs = StorageRoots::relaxed(Path::new(&s.path("data")))
        .unwrap()
        .with_volume_probe(Arc::new(AllRefs));
    let session = refs.create_session().unwrap();
    assert!(off_journal_volume(&session, serial));
}

/// Review M4: an undo that finds its item back already (here: the act never ran) may stand on a move
/// back of an earlier, interrupted undo that is not on disk yet, so off the journal's log it is flushed
/// before its `undo_done` as a restore is. Before the fix only `Restored` was flushed.
#[test]
fn an_item_found_back_already_is_flushed_before_its_undo_done() {
    let s = Scratch::new("found-back");
    let f = s.file(r"src\never-moved.txt", b"stays");
    let g = s.file(r"src\moved.txt", b"moves");
    let roots = store(&s).with_volume_probe(Arc::new(AllRefs));
    let mut env = Env::with_roots(s, roots, vec![mv(&f), mv(&g)]);
    let flushes = || RESTORE_FLUSHES.with(std::cell::Cell::get);
    let (action, token) = env.intent_only(1);
    drop(action);
    drop(token);
    let before = flushes();
    assert!(matches!(
        env.undo(1),
        FsUndo::Done {
            outcome: UndoOutcome::AlreadyRestored,
            ..
        }
    ));
    assert_eq!(flushes(), before + 1);
    // And a restore, as before.
    let (action, token) = env.intent_only(2);
    let FsActed::Finished(result) = act_fs(action, &token, &no_wait()) else {
        panic!()
    };
    assert_done(&result);
    drop(token);
    assert_restored(&env.undo(2));
    assert_eq!(flushes(), before + 2);
}

/// Real cross-volume: `PURGE_TEST_OTHER_VOLUME_DIR` names an empty directory on another fixed NTFS volume.
/// The store's volume probe is told the source is on the data root's volume, so the op directory is
/// made in the data root's quarantine; the serials then differ and the item is skipped, never copied.
#[test]
#[ignore = "needs PURGE_TEST_OTHER_VOLUME_DIR on a second fixed NTFS volume"]
fn an_item_on_another_volume_is_never_copied() {
    let Ok(other) = std::env::var("PURGE_TEST_OTHER_VOLUME_DIR") else {
        return;
    };
    let s = Scratch::new("othervol");
    let dir = Path::new(&other).join(format!("purge-fs-othervol-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let f = dir.join("a.txt");
    std::fs::write(&f, b"far").unwrap();
    let f = f.to_str().unwrap().to_owned();

    #[derive(Debug)]
    struct SameAsData(PathBuf);
    impl VolumeProbe for SameAsData {
        fn volume(&self, _path: &Path) -> Result<StoreVolumeFacts, FsError> {
            SystemVolumes.volume(&self.0)
        }
    }
    let data = PathBuf::from(s.path("data"));
    let roots = store(&s).with_volume_probe(Arc::new(SameAsData(data)));
    let mut env = Env::with_roots(s, roots, vec![mv(&f)]);
    let result = env.run(1);
    let _ = std::fs::remove_file(&f);
    let _ = std::fs::remove_dir(&dir);
    assert_skipped(
        &result,
        SkipReason::GateBlocked {
            blocker: Blocker::CannotBackUp,
        },
    );
}

// ---------------------------------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------------------------------

#[test]
fn the_token_of_another_op_acts_on_nothing() {
    let s = Scratch::new("token");
    let f = s.file(r"src\a.txt", b"a");
    let g = s.file(r"src\b.txt", b"b");
    let mut env = Env::new(s, vec![mv(&f), mv(&g)]);
    let FsPrepared::Ready(first) = env.prepare(1, &no_wait()) else {
        panic!()
    };
    let (second, token) = env.intent_only(2);
    let FsActed::Finished(result) = act_fs(first, &token, &no_wait()) else {
        panic!()
    };
    assert!(
        matches!(
            result.outcome,
            ItemOutcome::Failed {
                code: FailCode::Internal,
                ..
            }
        ),
        "{result:?}"
    );
    assert!(exists(&f));
    let FsActed::Finished(result) = act_fs(second, &token, &no_wait()) else {
        panic!()
    };
    assert_done(&result);
    env.journal.done(token, result.outcome).unwrap();
}

#[test]
fn non_file_ops_are_not_this_modules() {
    let op = ExecOp::DeleteValue {
        key: r"HKLM\SOFTWARE\V".into(),
        name: "x".into(),
    };
    let intent = Intent {
        op: OpId(1),
        item: item(1),
        exec_op: op,
        inverse: Inverse::None,
        definition: None,
        pre: ItemFacts::Absent,
    };
    assert!(plan_undo_fs(&intent, Some(&ItemOutcome::Done)).is_none());
    // Changed in meaning: `prepare_fs` takes no op or validation from the caller any more. A registry op
    // journalled as validated (a forged record of a value) reaches it only through the gate's record,
    // and is refused there.
    let s = Scratch::new("nonfile");
    let mut env = Env::new(s, Vec::new());
    let forged = Validated {
        op: OpId(1),
        item: item(1),
        target: intent.exec_op.target(),
        facts: ItemFacts::Value(purge_model::exec::journal::ValueFacts {
            value_type: 1,
            size: 2,
            data_sha256: sha256_bytes(b"\0\0"),
        }),
        exemptions: exemptions_to_journal(&long()),
    };
    env.ctx.record(&intent.exec_op, &forged, 5_000).unwrap();
    let internal = |prepared: &FsPrepared| {
        matches!(
            prepared,
            FsPrepared::Decided(FsResult {
                outcome: ItemOutcome::Failed {
                    code: FailCode::Internal,
                    ..
                },
                ..
            })
        )
    };
    let prepared = prepare_fs(&env.ctx, &env.session, OpId(1), &no_wait()).unwrap();
    assert!(internal(&prepared), "{prepared:?}");
    // An op id without a journalled record is never acted on.
    let prepared = prepare_fs(&env.ctx, &env.session, OpId(2), &no_wait()).unwrap();
    assert!(internal(&prepared), "{prepared:?}");
}

#[test]
fn an_undo_without_a_journalled_record_changes_nothing() {
    // The undo is gated with the exemptions of the op's `validated` record from the gate context; an
    // undo context that was not handed the record refuses the op.
    let s = Scratch::new("undonorecord");
    let f = s.file(r"src\a.txt", b"a");
    let mut env = Env::new(s, vec![mv(&f)]);
    assert_done(&env.run(1));
    let FsUndoPlan::Run(job) = plan_undo_fs(&env.intents[&1], env.dones.get(&1)).unwrap() else {
        panic!("a done move is undone");
    };
    let scope = env
        .session
        .roots()
        .store_scope::<&Path>(env.session.id(), &[])
        .unwrap();
    let data_root = env.session.roots().data_root().to_str().unwrap().to_owned();
    let bare = GateCtx::new(DenyList::compile(&live_env(&data_root)), &env.ops, scope).unwrap();
    let token = env.journal.undo_intent(OpId(1)).unwrap();
    let undo = undo_fs(&bare, &env.session, job, &no_wait(), &token).unwrap();
    assert!(
        matches!(
            &undo,
            FsUndo::Conflict {
                conflict: UndoConflict::GateBlocked {
                    blocker: Blocker::DenyListed { rule }
                },
                ..
            } if rule == gate::reason::NOT_VALIDATED
        ),
        "{undo:?}"
    );
    assert!(!exists(&f));
    assert!(exists(&env.quarantine_path(1)));
}

#[test]
fn the_standard_retry_is_three_waits_of_100_300_and_1000_ms() {
    assert_eq!(
        Retry::standard().delays(),
        &[
            Duration::from_millis(100),
            Duration::from_millis(300),
            Duration::from_millis(1000)
        ]
    );
}

#[test]
fn intent_targets_match_the_validated_ones() {
    // The journal refuses an intent whose op differs from the validated target; the Env journals both.
    let s = Scratch::new("target");
    let f = s.file(r"src\a.txt", b"a");
    let mut env = Env::new(s, vec![mv(&f)]);
    assert_done(&env.run(1));
    assert_eq!(
        env.intents[&1].exec_op.target(),
        Target::Path { path: f.clone() }
    );
}
