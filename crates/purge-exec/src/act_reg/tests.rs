//! Tests of the registry actions against the live registry, unelevated. Every test writes only below its
//! own fresh `HKU\<current SID>\Software\PurgeTest-<random>` key, which it removes on drop (links first,
//! as links), and into a relaxed store in a fresh temp directory with a real journal. The few machine keys
//! the tests name (32-bit views, containers, deny-listed keys) are only probed, never written.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use purge_guard::canon::{GuardEnv, ProfileEnv};
use purge_guard::deny::DenyList;
use purge_guard::live::StoreScope;
use purge_model::exec::journal::{
    Header, ItemFacts, JournalSchema, Record, RegFacts, UndoConflict, UndoOutcome, Validated,
};
use purge_model::exec::op::{ExecOp, FailCode, Inverse, ItemOutcome, OpId, SkipReason};
use purge_model::exec::regbackup::{RegBackup, RegBackupBody, RegTree, WideB64};
use purge_model::exec::session::SessionId;
use purge_model::{Blocker, CandidateId, FileTime, ScanMode};
use purge_win::reg::{
    REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ, RegRoot, RegView,
};
use purge_win::reg_write::{KeyAccess, WKey};
use purge_win::sid::current_user_sid;

use super::*;
use crate::gate::{self, GateCtx, GateItem, GateOutcome};
use crate::journal::{JournalWriter, read, sha256_bytes};
use crate::regbackup;
use crate::storage::{BackupKind, SessionDir, StorageRoots, backup_rel};

// ---------------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------------

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "{tag}-{:x}-{:x}-{}",
        std::process::id(),
        nanos,
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// A scratch directory under the temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(unique(&format!("purge-actreg-{tag}")));
        std::fs::create_dir(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(purge_win::secure::extended_path(&self.0).unwrap());
    }
}

fn env_var(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

/// A `GuardEnv` for this machine and user.
fn live_env() -> GuardEnv {
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
        purge_dirs: vec![format!(r"{}\Purge", env_var("ProgramData"))],
        ..GuardEnv::default()
    }
}

/// A store scope whose store does not exist (the registry ops never look at it).
fn no_store() -> StoreScope {
    let root = std::env::temp_dir().join(unique("purge-actreg-no-store"));
    StoreScope::new::<&str>(
        root.to_str().unwrap(),
        &[],
        &SessionId::new(FileTime(133_000_000_000_000_000), 0x5eed),
    )
    .unwrap()
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// A fresh `HKU\<SID>\Software\PurgeTest-<random>` key, removed on drop (links first, as links).
struct TestKey {
    sid: String,
    name: String,
    links: Vec<String>,
}

impl TestKey {
    fn new() -> TestKey {
        let sid = current_user_sid().unwrap();
        let name = unique("PurgeTest");
        WKey::open(
            RegRoot::Hku,
            &format!(r"{sid}\Software"),
            RegView::K64,
            KeyAccess::CREATE_SUB_KEY,
        )
        .unwrap()
        .create_subkey(&name, "", None, false)
        .unwrap();
        TestKey {
            sid,
            name,
            links: Vec::new(),
        }
    }

    /// The path below `HKU`.
    fn rel(&self, sub: &str) -> String {
        let base = format!(r"{}\Software\{}", self.sid, self.name);
        if sub.is_empty() {
            base
        } else {
            format!(r"{base}\{sub}")
        }
    }

    /// The canonical wire spelling.
    fn wire(&self, sub: &str) -> String {
        format!(r"HKU\{}", self.rel(sub))
    }

    fn try_open(&self, sub: &str, access: KeyAccess) -> Result<WKey, Win32Error> {
        WKey::open(RegRoot::Hku, &self.rel(sub), RegView::K64, access)
    }

    fn open(&self, sub: &str, access: KeyAccess) -> WKey {
        self.try_open(sub, access).unwrap()
    }

    fn exists(&self, sub: &str) -> bool {
        match self.try_open(sub, KeyAccess::READ) {
            Ok(_) => true,
            Err(e) if e.is_not_found() => false,
            Err(e) => panic!("open {sub}: {e:?}"),
        }
    }

    /// Creates `sub` (and the keys above it) below the root.
    fn create(&self, sub: &str) {
        let mut at = String::new();
        for part in sub.split('\\') {
            let parent = self.open(&at, KeyAccess::CREATE_SUB_KEY);
            match parent.create_subkey(part, "", None, false) {
                Ok(_) => {}
                Err(e) if e == purge_win::reg_write::ALREADY_EXISTS => {}
                Err(e) => panic!("create {part}: {e:?}"),
            }
            at = if at.is_empty() {
                part.to_owned()
            } else {
                format!(r"{at}\{part}")
            };
        }
    }

    /// Creates the key `parent\name` with a class, a security descriptor and a volatility.
    fn create_with(
        &self,
        parent: &str,
        name: &str,
        class: &str,
        sddl: Option<&str>,
        volatile: bool,
    ) {
        self.open(parent, KeyAccess::CREATE_SUB_KEY)
            .create_subkey(name, class, sddl, volatile)
            .unwrap();
    }

    fn set(&self, sub: &str, name: &str, ty: u32, data: &[u8]) {
        self.open(sub, KeyAccess::SET_VALUE)
            .set_value_raw(name, ty, data)
            .unwrap();
    }

    /// Type and raw bytes of a value, `None` when it is absent.
    fn get(&self, sub: &str, name: &str) -> Option<(u32, Vec<u8>)> {
        self.open(sub, KeyAccess::READ)
            .value(name)
            .unwrap()
            .map(|v| (v.ty, v.data))
    }

    /// Creates the registry link `sub` pointing at the key `target_sub` below the root.
    fn link(&mut self, sub: &str, target_sub: &str) {
        use crate::test_ffi::*;
        let name = wz(&self.rel(sub));
        let mut key: Hkey = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated; class, security and disposition are null; `key` is a valid
        // out-pointer.
        let rc = unsafe {
            RegCreateKeyExW(
                hkey_users(),
                name.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_CREATE_LINK,
                KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                std::ptr::null(),
                &mut key,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "create link key");
        self.links.push(sub.to_owned());
        let target: Vec<u8> = format!(r"\REGISTRY\USER\{}", self.rel(target_sub))
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let value = wz("SymbolicLinkValue");
        // SAFETY: live key; `value` is NUL-terminated; `target` has the stated length.
        let rc = unsafe {
            RegSetValueExW(
                key,
                value.as_ptr(),
                0,
                purge_win::reg::REG_LINK,
                target.as_ptr(),
                target.len() as u32,
            )
        };
        // SAFETY: `key` came from RegCreateKeyExW and is closed once.
        unsafe { RegCloseKey(key) };
        assert_eq!(rc, 0, "set link target");
    }

    /// Whether `sub` is (still) a registry link key.
    fn is_link(&self, sub: &str) -> bool {
        self.open(sub, KeyAccess::READ).is_link().unwrap()
    }

    fn remove_link(&self, sub: &str) {
        use crate::test_ffi::*;
        let name = wz(&self.rel(sub));
        let mut key: Hkey = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated; `key` is a valid out-pointer.
        let rc = unsafe {
            RegOpenKeyExW(
                hkey_users(),
                name.as_ptr(),
                REG_OPTION_OPEN_LINK,
                DELETE_ACCESS | KEY_WOW64_64KEY,
                &mut key,
            )
        };
        if rc == 0 {
            // SAFETY: `key` is a live handle with DELETE on the link key itself; closed once.
            unsafe {
                NtDeleteKey(key);
                RegCloseKey(key);
            }
        }
    }

    /// Deletes `sub` with everything below it (no links below it).
    fn remove(&self, sub: &str) {
        Self::nuke(&self.open(sub, KeyAccess::DELETE));
    }

    fn nuke(key: &WKey) {
        for sub in key.subkey_names().unwrap_or_default() {
            if let Ok(child) = key.open_subkey(&sub, KeyAccess::DELETE) {
                Self::nuke(&child);
            }
        }
        let _ = key.delete();
    }

    /// The tree at `sub` as a backup records it.
    fn capture(&self, sub: &str) -> RegBackup {
        regbackup::capture_tree(&self.open(sub, KeyAccess::READ), &self.wire(sub), 10_000).unwrap()
    }
}

impl Drop for TestKey {
    fn drop(&mut self) {
        for link in self.links.iter().rev() {
            self.remove_link(link);
        }
        if let Ok(root) = WKey::open(RegRoot::Hku, &self.rel(""), RegView::K64, KeyAccess::DELETE) {
            Self::nuke(&root);
        }
    }
}

/// The comparable content of a captured tree: every key's parent, name, class, security, volatility and
/// values (type and raw bytes), in capture order. Last write times are left out.
fn shape(doc: &RegBackup) -> RegTree {
    let mut tree = doc.tree().expect("a tree backup").clone();
    for key in &mut tree.keys {
        key.last_write_time = FileTime(0);
    }
    tree
}

fn tree_op(key: String) -> ExecOp {
    ExecOp::DeleteKeyTree { key }
}

fn empty_op(key: String) -> ExecOp {
    ExecOp::DeleteKeyIfEmpty { key }
}

fn value_op(key: String, name: &str) -> ExecOp {
    ExecOp::DeleteValue {
        key,
        name: name.to_owned(),
    }
}

fn segment_op(key: String, name: &str, segment: &str, index: Option<u32>) -> ExecOp {
    ExecOp::EditSegment {
        key,
        name: name.to_owned(),
        segment: segment.to_owned(),
        index,
    }
}

fn cid(n: u32) -> CandidateId {
    CandidateId(format!("c-{n:03}"))
}

fn skipped(reason: SkipReason) -> ItemOutcome {
    ItemOutcome::Skipped { reason }
}

fn blocked(blocker: Blocker) -> ItemOutcome {
    skipped(SkipReason::GateBlocked { blocker })
}

/// A run: a relaxed store with one session and its journal, a gate context, and ops 1..=n validated
/// against the live registry as the executor validates them (a pass records its stamp; every op gets
/// its `validated` record). The executor's sequence per op is [`Run::run_with`]; undo is [`Run::undo`].
struct Run {
    session: SessionDir,
    journal: JournalWriter,
    ctx: GateCtx,
    ops: Vec<ExecOp>,
    /// The intent and the done outcome of every op that has an intent.
    log: BTreeMap<u32, (Intent, Option<ItemOutcome>)>,
    /// Last: removed after the journal and the session's handles are closed.
    _scratch: Scratch,
}

impl Run {
    fn new(tag: &str, ops: Vec<ExecOp>) -> Run {
        let scratch = Scratch::new(tag);
        let roots = StorageRoots::install_relaxed(&scratch.0.join("data")).unwrap();
        let session = roots.create_session().unwrap();
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
        let mut ctx = GateCtx::new(DenyList::compile(&live_env()), &ops, no_store()).unwrap();
        // As the executor does before the validate pass: the run's ops with their ids.
        ctx.set_run_ops(
            ops.iter()
                .enumerate()
                .map(|(i, op)| (OpId(i as u32 + 1), op.clone())),
        );
        for (i, op) in ops.iter().enumerate() {
            let n = i as u32 + 1;
            let mut facts = ItemFacts::Absent;
            let mut passed = false;
            if op.is_registry() {
                let outcome = gate::validate(&ctx, &GateItem::new(op, Exemptions::default()));
                facts = outcome.item_facts().unwrap_or(ItemFacts::Absent);
                passed = matches!(outcome, GateOutcome::Pass(_));
            }
            let record = Validated {
                op: OpId(n),
                item: cid(n),
                target: op.target(),
                facts,
                exemptions: gate::exemptions_to_journal(&Exemptions::default()),
            };
            journal.validated(record.clone()).unwrap();
            // As the executor does: the written record of a pass goes to the gate, the only source of
            // what the act is gated with.
            if passed {
                ctx.record(
                    op,
                    &record,
                    GateItem::new(op, Exemptions::default()).max_files,
                )
                .unwrap();
            }
        }
        Run {
            _scratch: scratch,
            session,
            journal,
            ctx,
            ops,
            log: BTreeMap::new(),
        }
    }

    fn validated(&self, n: u32) -> bool {
        self.ctx.stamp(OpId(n)).is_some()
    }

    fn prepare(&self, n: u32) -> Result<RegPrepared, BackupWriteError> {
        prepare_reg(
            &self.ctx,
            &self.session,
            OpId(n),
            regbackup::DEFAULT_KEY_LIMIT,
        )
    }

    /// Hands op `n` a deliberately forged `validated` record of a key (as if the plan had carried and
    /// validated it), so that the act-time path runs for an op the validation did not pass. The journal
    /// keeps what the fixture wrote: the gate is given what the journal does not hold.
    fn forge_key_record(&mut self, n: u32) {
        let op = self.ops[n as usize - 1].clone();
        let forged = Validated {
            op: OpId(n),
            item: cid(n),
            target: op.target(),
            facts: ItemFacts::Key(RegFacts {
                subkeys: 0,
                values: 0,
                is_link: false,
                owner: "S-1-5-32-544".into(),
                last_write_time: FileTime(133_000_000_000_000_000),
                tree_sha256: None,
            }),
            exemptions: gate::exemptions_to_journal(&Exemptions::default()),
        };
        self.ctx.record(&op, &forged, 5_000).unwrap();
    }

    /// Journals a `validated` record for op `n` with the key's facts as they are now and no tree digest:
    /// what the validate pass would refuse, to reach the act's own checks.
    fn forge_key_record_as_seen(&mut self, n: u32) {
        let op = self.ops[n as usize - 1].clone();
        let facts =
            gate::key_facts_without_tree(&self.ctx, &GateItem::new(&op, Exemptions::default()))
                .unwrap();
        let forged = Validated {
            op: OpId(n),
            item: cid(n),
            target: op.target(),
            facts,
            exemptions: gate::exemptions_to_journal(&Exemptions::default()),
        };
        self.ctx.record(&op, &forged, 5_000).unwrap();
    }

    fn run(&mut self, n: u32) -> RegResult {
        self.run_with(n, || {})
    }

    /// The executor's sequence for op `n`, with `between` run after the intent is durable and before the
    /// action.
    fn run_with(&mut self, n: u32, between: impl FnOnce()) -> RegResult {
        match self.prepare(n).unwrap() {
            RegPrepared::Decided(result) => {
                assert!(result.outcome.allowed_without_intent(), "{result:?}");
                self.journal
                    .done_without_intent(OpId(n), result.outcome.clone())
                    .unwrap();
                result
            }
            RegPrepared::Ready(action) => {
                let intent = action.intent().clone();
                assert!(intent.is_consistent(), "{intent:?}");
                assert_eq!(intent.inverse.backup(), Some(action.backup()));
                let token = self.journal.intent(intent.clone()).unwrap();
                between();
                fault::point(fault::ACT_BEFORE);
                let result = act_reg(action, &token);
                self.journal.done(token, result.outcome.clone()).unwrap();
                // As the executor does after each done: the op's effect on its key is the run's own.
                self.ctx
                    .note_done(self.journal.state().op(OpId(n)).unwrap());
                self.log.insert(n, (intent, Some(result.outcome.clone())));
                result
            }
        }
    }

    /// A gate context made again from the journal alone, as a resumed run makes it: the run's ops, every
    /// `validated` record of a passed validation, and the effects of the completed ops
    /// (`GateCtx::note_journal`). Replaces the context the run had.
    fn reopen_ctx(&mut self) {
        let mut ctx = GateCtx::new(DenyList::compile(&live_env()), &self.ops, no_store()).unwrap();
        ctx.set_run_ops(
            self.ops
                .iter()
                .enumerate()
                .map(|(i, op)| (OpId(i as u32 + 1), op.clone())),
        );
        let state = self.journal.state().clone();
        for op_state in state.ops() {
            let op = &self.ops[op_state.op.0 as usize - 1];
            ctx.record(op, &op_state.validated(), 5_000).unwrap();
        }
        ctx.note_journal(&state);
        self.ctx = ctx;
    }

    /// Prepares op `n` and journals its intent, then stops as a crash during the action would.
    fn intent_only(&mut self, n: u32) {
        let RegPrepared::Ready(action) = self.prepare(n).unwrap() else {
            panic!("op {n} was decided");
        };
        let intent = action.intent().clone();
        // The token is dropped unused: no done follows, as after a crash.
        let _token = self.journal.intent(intent.clone()).unwrap();
        self.log.insert(n, (intent, None));
    }

    /// The undo of op `n` as the executor runs it, journalled.
    fn undo(&mut self, n: u32) -> RegUndoResult {
        self.undo_with(n, || {})
    }

    /// [`Run::undo`] with `between` run after the undo gate checked the destination and the undo intent
    /// is durable, before the inverse runs.
    fn undo_with(&mut self, n: u32, between: impl FnOnce()) -> RegUndoResult {
        let (intent, done) = self.log.get(&n).cloned().expect("op has an intent");
        let op = OpId(n);
        // The undo is gated with the exemptions of the op's journalled record in `ctx`.
        let prepared = prepare_undo_reg(&self.ctx, &self.session, &intent, done.as_ref())
            .expect("a registry op");
        match prepared {
            RegUndoPrepared::Decided(result) => {
                match &result {
                    RegUndoResult::Done { outcome, .. } => {
                        assert_eq!(*outcome, UndoOutcome::NothingToUndo);
                        self.journal
                            .undo_done_without_intent(op, outcome.clone())
                            .unwrap();
                    }
                    RegUndoResult::Conflict { conflict, detail } => self
                        .journal
                        .undo_conflict_without_intent(op, conflict.clone(), detail.clone())
                        .unwrap(),
                }
                result
            }
            RegUndoPrepared::Ready(inverse) => {
                assert_eq!(inverse.op(), op);
                let token = self.journal.undo_intent(op).unwrap();
                between();
                let result = run_undo_reg(inverse, &token);
                match &result {
                    RegUndoResult::Done { outcome, .. } => {
                        self.journal.undo_done(token, outcome.clone()).unwrap()
                    }
                    RegUndoResult::Conflict { conflict, detail } => self
                        .journal
                        .undo_conflict(token, conflict.clone(), detail.clone())
                        .unwrap(),
                }
                result
            }
        }
    }

    fn backup_path(&self, n: u32) -> PathBuf {
        self.session
            .path()
            .join(backup_rel(BackupKind::Registry, OpId(n)))
    }

    fn records(&self) -> Vec<Record> {
        read(&self.session).unwrap().records
    }
}

#[track_caller]
fn assert_outcome(result: &RegResult, expected: ItemOutcome) {
    assert_eq!(result.outcome, expected, "{}", result.detail);
}

#[track_caller]
fn assert_undo(result: &RegUndoResult, expected: UndoOutcome) {
    match result {
        RegUndoResult::Done { outcome, detail } => assert_eq!(*outcome, expected, "{detail}"),
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

#[track_caller]
fn assert_conflict(result: &RegUndoResult, expected: UndoConflict) {
    match result {
        RegUndoResult::Conflict { conflict, detail } => {
            assert_eq!(*conflict, expected, "{detail}")
        }
        other => panic!("expected the conflict {expected:?}, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------------
// Round trips: do, verify, undo, compare
// ---------------------------------------------------------------------------------------------------

/// `App`: class, explicit owner and protected DACL, every common value type including an odd-length
/// string and the default value, a subkey with a value, a volatile subkey with a value.
fn rich_app(k: &TestKey) {
    let sid = &k.sid;
    let sddl = format!("O:{sid}G:{sid}D:P(A;;KA;;;{sid})(A;;KR;;;BA)");
    k.create_with("", "App", "AppClass", Some(&sddl), false);
    for (name, ty, data) in [
        ("", REG_SZ, vec![0x41, 0x00, 0x42]),
        ("sz", REG_SZ, utf16z("text")),
        ("expand", REG_EXPAND_SZ, utf16z(r"%SystemRoot%\x")),
        ("multi", REG_MULTI_SZ, utf16z("a\0\0b\0")),
        ("bin-empty", REG_BINARY, Vec::new()),
        ("bin", REG_BINARY, vec![0, 1, 2, 255]),
        ("dword", REG_DWORD, 0xdead_beefu32.to_le_bytes().to_vec()),
        ("qword", REG_QWORD, 42u64.to_le_bytes().to_vec()),
        ("custom", 0x4000_0001, vec![1]),
    ] {
        k.set("App", name, ty, &data);
    }
    k.create_with("App", "Sub", "SubClass", None, false);
    k.set(r"App\Sub", "deep", REG_SZ, &utf16z("deep"));
    k.create_with("App", "Vol", "", None, true);
    k.set(r"App\Vol", "v", REG_DWORD, &[3, 0, 0, 0]);
}

#[test]
fn delete_key_tree_round_trips_exactly() {
    let k = TestKey::new();
    rich_app(&k);
    let before = k.capture("App");
    assert_eq!(before.tree().unwrap().keys.len(), 3);
    assert!(before.tree().unwrap().keys.iter().any(|key| key.volatile));
    let mut run = Run::new("tree", vec![tree_op(k.wire("App"))]);

    let result = run.run(1);
    assert_outcome(&result, ItemOutcome::Done);
    assert!(!k.exists("App"));
    // The intent named the backup, which holds the tree as it was.
    let (intent, _) = run.log[&1].clone();
    let Inverse::RestoreKeyTree { backup } = &intent.inverse else {
        panic!("{intent:?}");
    };
    assert_eq!(
        run.session.path().join(&backup.path),
        run.backup_path(1),
        "the backup is reg\\<op>.regbackup.json"
    );
    let on_disk = regbackup::read_verified(&run.session, backup).unwrap();
    assert_eq!(shape(on_disk.doc()), shape(&before));
    assert!(matches!(intent.pre, ItemFacts::Key(_)));

    let undone = run.undo(1);
    assert_undo(&undone, UndoOutcome::Restored);
    assert_eq!(shape(&k.capture("App")), shape(&before));
    assert_eq!(k.get("App", ""), Some((REG_SZ, vec![0x41, 0x00, 0x42])));

    // The journal holds validated, intent, done, undo_intent, undo_done for the op.
    let kinds: Vec<&str> = run
        .records()
        .iter()
        .filter_map(|r| match r {
            Record::Validated(_) => Some("validated"),
            Record::Intent(_) => Some("intent"),
            Record::Done(_) => Some("done"),
            Record::UndoIntent(_) => Some("undo_intent"),
            Record::UndoDone(_) => Some("undo_done"),
            _ => None,
        })
        .collect();
    assert_eq!(
        kinds,
        ["validated", "intent", "done", "undo_intent", "undo_done"]
    );
}

#[test]
fn delete_key_if_empty_round_trips_and_skips_keys_that_filled_up() {
    let k = TestKey::new();
    let sid = &k.sid;
    k.create_with(
        "",
        "Empty",
        "EmptyClass",
        Some(&format!("O:{sid}G:{sid}D:P(A;;KA;;;{sid})")),
        false,
    );
    k.create("GotSubkey");
    k.create("GotValue");
    let mut run = Run::new(
        "empty",
        vec![
            empty_op(k.wire("Empty")),
            empty_op(k.wire("GotSubkey")),
            empty_op(k.wire("GotValue")),
        ],
    );
    assert!((1..=3).all(|n| run.validated(n)));
    let before = k.capture("Empty");

    assert_outcome(&run.run(1), ItemOutcome::Done);
    assert!(!k.exists("Empty"));
    assert!(matches!(run.log[&1].0.inverse, Inverse::RecreateKey { .. }));
    assert_undo(&run.undo(1), UndoOutcome::Restored);
    assert_eq!(shape(&k.capture("Empty")), shape(&before));

    // A subkey appeared after validation: the act-time gate sees it.
    k.create(r"GotSubkey\Child");
    assert_outcome(&run.run(2), skipped(SkipReason::NoLongerEmpty));
    assert!(k.exists(r"GotSubkey\Child"));

    // A value appeared after the backup, before the delete.
    let result = run.run_with(3, || k.set("GotValue", "late", REG_DWORD, &[1, 0, 0, 0]));
    assert_outcome(&result, skipped(SkipReason::NoLongerEmpty));
    assert_eq!(
        k.get("GotValue", "late"),
        Some((REG_DWORD, vec![1, 0, 0, 0]))
    );
    // Nothing changed, so there is nothing to undo.
    assert_undo(&run.undo(3), UndoOutcome::NothingToUndo);
    assert_eq!(
        k.get("GotValue", "late"),
        Some((REG_DWORD, vec![1, 0, 0, 0]))
    );
}

#[test]
fn delete_value_round_trips_type_and_raw_bytes() {
    let k = TestKey::new();
    k.create("App");
    k.set("App", "odd", REG_SZ, &[0x41, 0x00, 0x42]);
    k.set("App", "", REG_EXPAND_SZ, &utf16z(r"%TEMP%\x"));
    k.set("App", "empty", REG_BINARY, &[]);
    k.set("App", "keep", REG_DWORD, &[9, 0, 0, 0]);
    let mut run = Run::new(
        "value",
        vec![
            value_op(k.wire("App"), "odd"),
            value_op(k.wire("App"), ""),
            value_op(k.wire("App"), "empty"),
        ],
    );
    let before: Vec<_> = ["odd", "", "empty"]
        .iter()
        .map(|name| k.get("App", name))
        .collect();

    for n in 1..=3 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
        assert!(matches!(
            run.log[&n].0.inverse,
            Inverse::RestoreValue { .. }
        ));
    }
    for name in ["odd", "", "empty"] {
        assert_eq!(k.get("App", name), None, "{name:?}");
    }
    assert_eq!(k.get("App", "keep"), Some((REG_DWORD, vec![9, 0, 0, 0])));

    for n in 1..=3 {
        assert_undo(&run.undo(n), UndoOutcome::Restored);
    }
    let after: Vec<_> = ["odd", "", "empty"]
        .iter()
        .map(|name| k.get("App", name))
        .collect();
    assert_eq!(after, before);
    assert_eq!(after[0], Some((REG_SZ, vec![0x41, 0x00, 0x42])));
}

#[test]
fn delete_value_that_vanished_or_changed_is_left_alone() {
    let k = TestKey::new();
    k.create("App");
    for name in ["gone", "changed", "late", "racy"] {
        k.set("App", name, REG_SZ, &utf16z("v"));
    }
    let mut run = Run::new(
        "value-skip",
        vec![
            value_op(k.wire("App"), "gone"),
            value_op(k.wire("App"), "changed"),
            value_op(k.wire("App"), "late"),
            value_op(k.wire("App"), "racy"),
            value_op(k.wire("App"), "never"),
        ],
    );
    assert!((1..=4).all(|n| run.validated(n)));
    assert!(!run.validated(5));

    k.open("App", KeyAccess::SET_VALUE)
        .delete_value("gone")
        .unwrap();
    assert_outcome(&run.run(1), ItemOutcome::Vanished);

    k.set("App", "changed", REG_SZ, &utf16z("other"));
    assert_outcome(&run.run(2), skipped(SkipReason::ChangedSinceScan));
    assert_eq!(k.get("App", "changed"), Some((REG_SZ, utf16z("other"))));

    // Changed after the backup, before the delete.
    let result = run.run_with(3, || k.set("App", "late", REG_EXPAND_SZ, &utf16z("v")));
    assert_outcome(&result, skipped(SkipReason::ChangedSinceScan));
    assert_eq!(k.get("App", "late"), Some((REG_EXPAND_SZ, utf16z("v"))));

    // Deleted after the backup, before the delete.
    let result = run.run_with(4, || {
        k.open("App", KeyAccess::SET_VALUE)
            .delete_value("racy")
            .unwrap()
    });
    assert_outcome(&result, ItemOutcome::Vanished);
    assert_undo(&run.undo(4), UndoOutcome::NothingToUndo);
    assert_eq!(k.get("App", "racy"), None);

    // Never validated (it never existed): not acted on.
    let result = run.run(5);
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
}

#[test]
fn edit_segment_round_trips_and_keeps_the_type() {
    let k = TestKey::new();
    k.create("Env");
    let path = utf16z(r"C:\a;%X%\b;;C:\c");
    let list = utf16z("one\0two\0three\0");
    k.set("Env", "Path", REG_EXPAND_SZ, &path);
    k.set("Env", "List", REG_MULTI_SZ, &list);
    let mut run = Run::new(
        "segment",
        vec![
            segment_op(k.wire("Env"), "Path", r"%X%\b", Some(1)),
            segment_op(k.wire("Env"), "List", "two", None),
        ],
    );

    assert_outcome(&run.run(1), ItemOutcome::Done);
    assert_eq!(
        k.get("Env", "Path"),
        Some((REG_EXPAND_SZ, utf16z(r"C:\a;;C:\c")))
    );
    assert_outcome(&run.run(2), ItemOutcome::Done);
    assert_eq!(
        k.get("Env", "List"),
        Some((REG_MULTI_SZ, utf16z("one\0three\0")))
    );
    let Inverse::ReinsertSegment { index, backup, .. } = &run.log[&1].0.inverse else {
        panic!("{:?}", run.log[&1].0.inverse);
    };
    assert_eq!(*index, 1);
    assert!(backup.is_some());

    assert_undo(&run.undo(1), UndoOutcome::Restored);
    assert_undo(&run.undo(2), UndoOutcome::Restored);
    assert_eq!(k.get("Env", "Path"), Some((REG_EXPAND_SZ, path)));
    assert_eq!(k.get("Env", "List"), Some((REG_MULTI_SZ, list)));
}

/// A segment edit is one read-modify-write of the value as it is at the act, and its backup is that
/// value: the act-time gate binds it to the value's type only (review S5 follow-up, item 4), and
/// whether the segment is there is decided on the gated handle.
#[test]
fn edit_segment_follows_a_changed_value_while_the_segment_is_there() {
    let k = TestKey::new();
    k.create("Env");
    for name in ["Grown", "Gone", "Moved", "Dword"] {
        k.set("Env", name, REG_SZ, &utf16z("a;b;c"));
    }
    let mut run = Run::new(
        "segment-changed",
        vec![
            segment_op(k.wire("Env"), "Grown", "b", Some(1)),
            segment_op(k.wire("Env"), "Gone", "b", Some(1)),
            segment_op(k.wire("Env"), "Moved", "b", Some(1)),
            segment_op(k.wire("Env"), "Dword", "b", Some(1)),
            segment_op(k.wire("Env"), "Missing", "b", None),
        ],
    );
    assert!((1..=4).all(|n| run.validated(n)));

    // Changed since validation, segment still at its place: the edit is made on the value as it is.
    k.set("Env", "Grown", REG_SZ, &utf16z("a;b;c;d"));
    assert_outcome(&run.run(1), ItemOutcome::Done);
    assert_eq!(k.get("Env", "Grown"), Some((REG_SZ, utf16z("a;c;d"))));
    // The backup is the value the edit was made on.
    assert_undo(&run.undo(1), UndoOutcome::Restored);
    assert_eq!(k.get("Env", "Grown"), Some((REG_SZ, utf16z("a;b;c;d"))));

    // The segment is gone: vanished, the value untouched.
    k.set("Env", "Gone", REG_SZ, &utf16z("a;x;c"));
    assert_outcome(&run.run(2), ItemOutcome::Vanished);
    assert_eq!(k.get("Env", "Gone"), Some((REG_SZ, utf16z("a;x;c"))));

    // The segment moved away from the recorded position.
    k.set("Env", "Moved", REG_SZ, &utf16z("b;a;c"));
    assert_outcome(&run.run(3), skipped(SkipReason::ChangedSinceScan));
    assert_eq!(k.get("Env", "Moved"), Some((REG_SZ, utf16z("b;a;c"))));

    // No longer a list.
    k.set("Env", "Dword", REG_DWORD, &[1, 0, 0, 0]);
    assert_outcome(&run.run(4), skipped(SkipReason::ChangedSinceScan));
    assert_eq!(k.get("Env", "Dword"), Some((REG_DWORD, vec![1, 0, 0, 0])));
}

/// The cases a segment edit skips or reports as vanished: a value of another type than validated (a
/// list still, `REG_SZ` turned `REG_EXPAND_SZ`: the gate's segment binding), a value that never held
/// the segment, and a segment that is not at the plan's recorded index although the value is
/// unchanged. The model's `Inverse::undoes` requires the inverse's index to be the plan's, so a
/// segment found at another index stays a skip.
#[test]
fn edit_segment_skips_another_type_or_another_index() {
    let k = TestKey::new();
    k.create("Env");
    k.set("Env", "Typed", REG_SZ, &utf16z("a;b;c"));
    k.set("Env", "Absent", REG_SZ, &utf16z("a;x;c"));
    k.set("Env", "Elsewhere", REG_SZ, &utf16z("b;a;c"));
    let mut run = Run::new(
        "segment-skips",
        vec![
            segment_op(k.wire("Env"), "Typed", "b", Some(1)),
            segment_op(k.wire("Env"), "Absent", "b", None),
            segment_op(k.wire("Env"), "Elsewhere", "b", Some(1)),
        ],
    );
    assert!((1..=3).all(|n| run.validated(n)));

    // Same data, another type since validation: skipped at the gate, nothing written.
    k.set("Env", "Typed", REG_EXPAND_SZ, &utf16z("a;b;c"));
    assert_outcome(&run.run(1), skipped(SkipReason::ChangedSinceScan));
    assert_eq!(
        k.get("Env", "Typed"),
        Some((REG_EXPAND_SZ, utf16z("a;b;c")))
    );
    // Decided before any intent: no backup was written.
    assert!(!run.backup_path(1).exists());

    // Unchanged since validation, but the value never held the segment: vanished, untouched.
    assert_outcome(&run.run(2), ItemOutcome::Vanished);
    assert_eq!(k.get("Env", "Absent"), Some((REG_SZ, utf16z("a;x;c"))));

    // Unchanged since validation, but the segment is not at the plan's recorded position.
    assert_outcome(&run.run(3), skipped(SkipReason::ChangedSinceScan));
    assert_eq!(k.get("Env", "Elsewhere"), Some((REG_SZ, utf16z("b;a;c"))));
}

#[test]
fn edit_segment_changed_between_backup_and_write_is_not_written() {
    let k = TestKey::new();
    k.create("Env");
    k.set("Env", "Path", REG_SZ, &utf16z("a;b;c"));
    let mut run = Run::new(
        "segment-race",
        vec![segment_op(k.wire("Env"), "Path", "b", None)],
    );
    let result = run.run_with(1, || k.set("Env", "Path", REG_SZ, &utf16z("a;b;c;new")));
    assert_outcome(&result, skipped(SkipReason::ChangedSinceScan));
    assert_eq!(k.get("Env", "Path"), Some((REG_SZ, utf16z("a;b;c;new"))));
    assert_undo(&run.undo(1), UndoOutcome::NothingToUndo);
}

// ---------------------------------------------------------------------------------------------------
// Execute-time refusal
// ---------------------------------------------------------------------------------------------------

#[test]
fn a_key_missing_at_open_is_vanished() {
    let k = TestKey::new();
    k.create(r"Gone\Sub");
    k.create("GoneEmpty");
    let mut run = Run::new(
        "missing",
        vec![tree_op(k.wire("Gone")), empty_op(k.wire("GoneEmpty"))],
    );
    assert!(run.validated(1) && run.validated(2));
    k.remove("Gone");
    k.remove("GoneEmpty");
    assert_outcome(&run.run(1), ItemOutcome::Vanished);
    assert_outcome(&run.run(2), ItemOutcome::Vanished);
    // No backup was written for a decided op.
    assert!(!run.backup_path(1).exists());
}

#[test]
fn a_key_deleted_after_the_backup_is_vanished_and_has_nothing_to_undo() {
    let k = TestKey::new();
    k.create(r"Racy\Sub");
    let mut run = Run::new("racy", vec![tree_op(k.wire("Racy"))]);
    let result = run.run_with(1, || k.remove("Racy"));
    assert_outcome(&result, ItemOutcome::Vanished);
    assert_undo(&run.undo(1), UndoOutcome::NothingToUndo);
    assert!(!k.exists("Racy"));
}

#[test]
fn structural_containers_and_deny_listed_keys_are_refused_even_when_planned() {
    let sid = current_user_sid().unwrap();
    let cv = r"Software\Microsoft\Windows\CurrentVersion";
    // Structural containers the deny-list does not name: only the container rule stands in the way.
    let containers = vec![
        tree_op(format!(r"HKU\{sid}\{cv}\ApplicationAssociationToasts")),
        empty_op(format!(
            r"HKU\{sid}\{cv}\Explorer\FileExts\.purgetest\OpenWithList"
        )),
        tree_op(format!(r"HKLM\{cv}\ApplicationAssociationToasts")),
        tree_op(
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts"
                .into(),
        ),
    ];
    // Containers the deny-list names too, and a deny-listed key.
    let denied = vec![
        tree_op(format!(r"HKU\{sid}\{cv}\Run")),
        empty_op(format!(r"HKU\{sid}\{cv}\RunOnce")),
        tree_op(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run".into()),
        tree_op(format!(r"HKU\{sid}\Environment")),
        tree_op(r"HKLM\SYSTEM\CurrentControlSet\Services\PurgeTestNoSuchService".into()),
    ];
    let n_containers = containers.len() as u32;
    let ops: Vec<ExecOp> = containers.into_iter().chain(denied).collect();
    let n_ops = ops.len() as u32;
    let mut run = Run::new("containers", ops);
    // As if the plan had carried and validated them: forged journalled records.
    for n in 1..=n_ops {
        assert!(!run.validated(n), "op {n} passed validation");
        run.forge_key_record(n);
    }
    for n in 1..=n_ops {
        let result = run.run(n);
        if n <= n_containers {
            assert_outcome(&result, blocked(Blocker::StructuralContainer));
        } else {
            assert!(
                matches!(
                    &result.outcome,
                    ItemOutcome::Skipped {
                        reason: SkipReason::GateBlocked {
                            blocker: Blocker::DenyListed { .. }
                        }
                    }
                ),
                "op {n}: {result:?}"
            );
        }
        assert!(!run.backup_path(n).exists());
    }
    // The user's keys are still there.
    for rel in [format!(r"{sid}\{cv}\Run"), format!(r"{sid}\Environment")] {
        assert!(WKey::open(RegRoot::Hku, &rel, RegView::K64, KeyAccess::READ).is_ok());
    }
}

#[test]
fn a_link_as_the_item_is_refused_and_its_target_untouched() {
    let mut k = TestKey::new();
    k.create(r"Real\Sub");
    k.set(r"Real\Sub", "v", REG_DWORD, &[7, 0, 0, 0]);
    k.create("Item");
    k.set(r"Real\Sub", "p", REG_SZ, &utf16z("a;b"));
    k.create("Holder");
    k.set("Holder", "v", REG_SZ, &utf16z("x"));
    k.create("SegHolder");
    k.set("SegHolder", "p", REG_SZ, &utf16z("a;b"));
    k.create(r"Via\Sub");
    k.set(r"Via\Sub", "v", REG_DWORD, &[7, 0, 0, 0]);
    let mut run = Run::new(
        "link-item",
        vec![
            tree_op(k.wire("Item")),
            value_op(k.wire("Holder"), "v"),
            segment_op(k.wire("SegHolder"), "p", "b", Some(1)),
            value_op(k.wire(r"Via\Sub"), "v"),
        ],
    );
    assert!((1..=4).all(|n| run.validated(n)));
    // Swapped for links after validation: the keys themselves, and an ancestor of a value's key.
    k.remove("Item");
    k.link("Item", "Real");
    k.remove("Holder");
    k.link("Holder", r"Real\Sub");
    k.remove("SegHolder");
    k.link("SegHolder", r"Real\Sub");
    k.remove("Via");
    k.link("Via", "Real");

    for n in 1..=4 {
        assert_outcome(&run.run(n), blocked(Blocker::RegLink));
    }
    assert!(k.is_link("Item") && k.is_link("Holder") && k.is_link("SegHolder"));
    assert_eq!(k.get(r"Real\Sub", "v"), Some((REG_DWORD, vec![7, 0, 0, 0])));
    assert_eq!(k.get(r"Real\Sub", "p"), Some((REG_SZ, utf16z("a;b"))));
    assert!(k.exists(r"Real\Sub"));
}

#[test]
fn a_link_below_the_tree_is_refused_and_its_target_untouched() {
    let mut k = TestKey::new();
    k.create(r"Real\Sub");
    k.set(r"Real\Sub", "v", REG_DWORD, &[7, 0, 0, 0]);
    k.create(r"Tree\Plain");
    k.link(r"Tree\Link", "Real");
    let mut run = Run::new("link-below", vec![tree_op(k.wire("Tree"))]);
    // Refused when it is validated: the validate pass reads the whole tree for its digest.
    let outcome = gate::validate(
        &run.ctx,
        &GateItem::new(&tree_op(k.wire("Tree")), Exemptions::default()),
    );
    assert_eq!(
        outcome.refusal().map(|r| (r.blocker.clone(), r.reason)),
        Some((Blocker::RegLink, gate::reason::TREE_NOT_READ))
    );
    assert!(!run.validated(1));
    // And at the act, had a record been journalled: the capture refuses it before any backup.
    run.forge_key_record_as_seen(1);
    let result = run.run(1);
    assert_outcome(&result, blocked(Blocker::RegLink));
    assert!(k.exists(r"Tree\Plain") && k.is_link(r"Tree\Link"));
    assert_eq!(k.get(r"Real\Sub", "v"), Some((REG_DWORD, vec![7, 0, 0, 0])));
    assert!(!run.backup_path(1).exists());
}

#[test]
fn a_link_swapped_in_after_the_backup_is_refused_and_the_tree_put_back() {
    let mut k = TestKey::new();
    k.create(r"Real\Inner");
    k.set(r"Real\Inner", "v", REG_DWORD, &[7, 0, 0, 0]);
    k.create(r"Tree\A\Deep");
    k.set(r"Tree\A\Deep", "d", REG_SZ, &utf16z("deep"));
    k.create(r"Tree\Z");
    let real_before = k.capture("Real");
    let mut run = Run::new("link-swap", vec![tree_op(k.wire("Tree"))]);
    let result = run.run_with(1, || {
        k.remove(r"Tree\Z");
        k.link(r"Tree\Z", "Real");
    });
    assert_outcome(&result, blocked(Blocker::RegLink));
    assert!(k.is_link(r"Tree\Z"));
    assert_eq!(shape(&k.capture("Real")), shape(&real_before));
    // Whatever was deleted before the link was met is back.
    assert_eq!(k.get(r"Tree\A\Deep", "d"), Some((REG_SZ, utf16z("deep"))));
    assert_undo(&run.undo(1), UndoOutcome::NothingToUndo);
}

#[test]
fn a_tree_changed_after_the_backup_is_skipped_and_put_back() {
    let k = TestKey::new();
    k.create(r"Tree\A\Deep");
    k.set(r"Tree\A\Deep", "d", REG_SZ, &utf16z("deep"));
    k.create(r"Tree\B");
    let mut run = Run::new("tree-changed", vec![tree_op(k.wire("Tree"))]);
    let result = run.run_with(1, || k.set("Tree", "late", REG_DWORD, &[1, 0, 0, 0]));
    assert_outcome(&result, skipped(SkipReason::ChangedSinceScan));
    assert_eq!(k.get(r"Tree\A\Deep", "d"), Some((REG_SZ, utf16z("deep"))));
    assert!(k.exists(r"Tree\B"));
    assert_eq!(k.get("Tree", "late"), Some((REG_DWORD, vec![1, 0, 0, 0])));
}

#[test]
fn the_32_bit_views_are_addressed_explicitly() {
    // Read-only: an unelevated user cannot write a 32-bit view (HKLM is not writable, and
    // `HKU\<SID>\Software` is shared between the views). Keys that do not exist must come out as
    // vanished, not as links: the walk to them opens the logical 32-bit path with KEY_WOW64_32KEY and
    // never meets the `SOFTWARE\WOW6432Node\Classes` link.
    let sid = current_user_sid().unwrap();
    let guid = format!("{{{}}}", unique("00000000-PurgeTest"));
    let ops = vec![
        tree_op(format!(r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{guid}")),
        tree_op(format!(r"HKLM\SOFTWARE\Classes\CLSID\{guid}")),
        tree_op(format!(
            r"HKLM\SOFTWARE\WOW6432Node\{}",
            unique("PurgeTest")
        )),
        empty_op(format!(r"HKU\{sid}_Classes\WOW6432Node\CLSID\{guid}")),
    ];
    let mut run = Run::new("views", ops);
    for n in 1..=4 {
        assert!(!run.validated(n), "op {n} exists?");
        run.forge_key_record(n);
        let result = run.run(n);
        assert_outcome(&result, ItemOutcome::Vanished);
    }
}

/// Keys `HKU\<SID>\Software\Classes\PurgeTest-<random>-<n>` (stored at `HKU\<SID>_Classes\...`, the
/// key the alias names), each with a value and a subkey with a value; removed on drop.
struct ClassesKeys {
    classes: WKey,
    names: Vec<String>,
}

/// A [`ClassesKeys`] key's own value data and its subkey's, each if present.
type OwnAndSub = (Option<Vec<u8>>, Option<Vec<u8>>);

impl ClassesKeys {
    fn new(count: usize) -> ClassesKeys {
        let sid = current_user_sid().unwrap();
        let classes = WKey::open(
            RegRoot::Hku,
            &format!("{sid}_Classes"),
            RegView::K64,
            KeyAccess::CREATE_SUB_KEY,
        )
        .unwrap();
        let names: Vec<String> = (0..count).map(|_| unique("PurgeTest")).collect();
        for name in &names {
            let key = classes
                .create_subkey(name, "", None, false)
                .unwrap()
                .into_key();
            key.set_value_raw("own", REG_DWORD, &[1, 0, 0, 0]).unwrap();
            key.create_subkey("Sub", "", None, false)
                .unwrap()
                .set_value_raw("v", REG_SZ, &utf16z("x"))
                .unwrap();
        }
        ClassesKeys { classes, names }
    }

    /// The key `n` read at its storage address, if it exists: its own value and its subkey's.
    fn read(&self, n: usize) -> Option<OwnAndSub> {
        let key = self
            .classes
            .open_subkey(&self.names[n], KeyAccess::READ)
            .ok()?;
        let sub = key.open_subkey("Sub", KeyAccess::READ).ok();
        Some((
            key.value("own").unwrap().map(|v| v.data),
            sub.and_then(|sub| sub.value("v").unwrap().map(|v| v.data)),
        ))
    }
}

impl Drop for ClassesKeys {
    fn drop(&mut self) {
        for name in &self.names {
            if let Ok(key) = self.classes.open_subkey(name, KeyAccess::DELETE) {
                if let Ok(sub) = key.open_subkey("Sub", KeyAccess::DELETE) {
                    let _ = sub.delete();
                }
                let _ = key.delete();
            }
        }
    }
}

/// Review S3/S4: a key spelled through an alias is deleted and undone at the canonical address the
/// gate resolves, by delete and by undo (no second route to the key). `Software\Classes` of a user is
/// stored as `<SID>_Classes`; `WOW6432Node` below it names the 32-bit view, where a top-level name such
/// as these is shared with the 64-bit view. Machine aliases (`CurrentControlSet`) need HKLM write
/// access and are only probed, read-only.
#[test]
fn keys_spelled_through_an_alias_are_deleted_and_undone_at_their_address() {
    let sid = current_user_sid().unwrap();
    let keys = ClassesKeys::new(3);
    let classes = format!(r"HKU\{sid}\Software\Classes");
    let mut run = Run::new(
        "alias",
        vec![
            tree_op(format!(r"{classes}\{}", keys.names[0])),
            tree_op(format!(r"{classes}\WOW6432Node\{}", keys.names[1])),
            value_op(format!(r"{classes}\WOW6432Node\{}", keys.names[2]), "own"),
        ],
    );
    assert!((1..=3).all(|n| run.validated(n)));
    let before: Vec<_> = (0..3).map(|n| keys.read(n)).collect();
    assert_eq!(before[0], Some((Some(vec![1, 0, 0, 0]), Some(utf16z("x")))));

    assert_outcome(&run.run(1), ItemOutcome::Done);
    assert_outcome(&run.run(2), ItemOutcome::Done);
    assert_outcome(&run.run(3), ItemOutcome::Done);
    assert_eq!(keys.read(0), None);
    assert_eq!(keys.read(1), None);
    assert_eq!(keys.read(2), Some((None, Some(utf16z("x")))));

    for n in 1..=3 {
        assert_undo(&run.undo(n), UndoOutcome::Restored);
    }
    let after: Vec<_> = (0..3).map(|n| keys.read(n)).collect();
    assert_eq!(after, before);

    // `CurrentControlSet`: all of `HKLM\SYSTEM` is deny-listed, so a key spelled through that alias
    // is refused before anything is opened (its address is checked in `regbackup`'s probe test).
    let ccs = format!(
        r"HKLM\SYSTEM\CurrentControlSet\Control\{}",
        unique("PurgeTest")
    );
    let mut machine = Run::new("alias-hklm", vec![tree_op(ccs)]);
    assert!(!machine.validated(1));
    machine.forge_key_record(1);
    assert_outcome(
        &machine.run(1),
        blocked(Blocker::DenyListed {
            rule: "reg.hklm.system".into(),
        }),
    );
}

// ---------------------------------------------------------------------------------------------------
// Undo conflicts
// ---------------------------------------------------------------------------------------------------

#[test]
fn undo_never_overwrites_a_key_that_came_back_different() {
    let k = TestKey::new();
    k.create(r"Taken\Sub");
    k.set("Taken", "v", REG_SZ, &utf16z("mine"));
    k.create(r"Empty\Sub");
    k.set(r"Empty\Sub", "v", REG_SZ, &utf16z("mine"));
    let mut run = Run::new(
        "undo-key",
        vec![tree_op(k.wire("Taken")), tree_op(k.wire("Empty"))],
    );
    let before = k.capture("Empty");
    assert_outcome(&run.run(1), ItemOutcome::Done);
    assert_outcome(&run.run(2), ItemOutcome::Done);

    // Someone else created the key again, with content.
    k.create("Taken");
    k.set("Taken", "v", REG_SZ, &utf16z("theirs"));
    assert_conflict(&run.undo(1), UndoConflict::KeyExists);
    assert_eq!(k.get("Taken", "v"), Some((REG_SZ, utf16z("theirs"))));
    assert!(!k.exists(r"Taken\Sub"));

    // Created again empty: the tree goes back into it.
    k.create("Empty");
    assert_undo(&run.undo(2), UndoOutcome::Restored);
    let after = k.capture("Empty");
    assert_eq!(after.tree().unwrap().keys.len(), 2);
    assert_eq!(k.get(r"Empty\Sub", "v"), Some((REG_SZ, utf16z("mine"))));
    assert_eq!(shape(&after).keys[1].values, shape(&before).keys[1].values);
}

#[test]
fn undo_of_a_value_conflicts_when_it_differs_and_is_already_restored_when_equal() {
    let k = TestKey::new();
    k.create("App");
    k.set("App", "a", REG_SZ, &utf16z("one"));
    k.set("App", "b", REG_SZ, &utf16z("two"));
    let mut run = Run::new(
        "undo-value",
        vec![value_op(k.wire("App"), "a"), value_op(k.wire("App"), "b")],
    );
    assert_outcome(&run.run(1), ItemOutcome::Done);
    assert_outcome(&run.run(2), ItemOutcome::Done);

    k.set("App", "a", REG_SZ, &utf16z("someone else's"));
    assert_conflict(&run.undo(1), UndoConflict::ValueDiffers);
    assert_eq!(k.get("App", "a"), Some((REG_SZ, utf16z("someone else's"))));

    k.set("App", "b", REG_SZ, &utf16z("two"));
    assert_undo(&run.undo(2), UndoOutcome::AlreadyRestored);
}

#[test]
fn undo_of_a_segment_follows_the_conflict_table() {
    let k = TestKey::new();
    k.create("Env");
    for name in ["Back", "Elsewhere", "Present", "Deleted", "NotList"] {
        k.set("Env", name, REG_SZ, &utf16z("a;b;c"));
    }
    let ops = ["Back", "Elsewhere", "Present", "Deleted", "NotList"]
        .iter()
        .map(|name| segment_op(k.wire("Env"), name, "b", Some(1)))
        .collect();
    let mut run = Run::new("undo-segment", ops);
    for n in 1..=5 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    // Put back by hand already.
    k.set("Env", "Back", REG_SZ, &utf16z("a;b;c"));
    assert_undo(&run.undo(1), UndoOutcome::AlreadyRestored);
    // Changed since, segment missing: inserted at the recorded position.
    k.set("Env", "Elsewhere", REG_SZ, &utf16z("x;a;c"));
    assert_undo(&run.undo(2), UndoOutcome::Restored);
    assert_eq!(k.get("Env", "Elsewhere"), Some((REG_SZ, utf16z("x;b;a;c"))));
    // Changed since, segment present.
    k.set("Env", "Present", REG_SZ, &utf16z("b;z"));
    assert_undo(&run.undo(3), UndoOutcome::AlreadyRestored);
    assert_eq!(k.get("Env", "Present"), Some((REG_SZ, utf16z("b;z"))));
    // Gone, or no longer a list.
    k.open("Env", KeyAccess::SET_VALUE)
        .delete_value("Deleted")
        .unwrap();
    assert_conflict(&run.undo(4), UndoConflict::ValueChanged);
    assert_eq!(k.get("Env", "Deleted"), None);
    k.set("Env", "NotList", REG_BINARY, &[1]);
    assert_conflict(&run.undo(5), UndoConflict::ValueChanged);
    assert_eq!(k.get("Env", "NotList"), Some((REG_BINARY, vec![1])));
}

#[test]
fn undo_with_a_tampered_or_missing_backup_changes_nothing() {
    let k = TestKey::new();
    k.create("One");
    k.create("Two");
    k.create("Val");
    k.set("Val", "v", REG_SZ, &utf16z("x"));
    let mut run = Run::new(
        "undo-backup",
        vec![
            tree_op(k.wire("One")),
            tree_op(k.wire("Two")),
            value_op(k.wire("Val"), "v"),
        ],
    );
    for n in 1..=3 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    let path = run.backup_path(1);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(b' ');
    std::fs::write(&path, bytes).unwrap();
    assert_conflict(&run.undo(1), UndoConflict::BackupTampered);
    assert!(!k.exists("One"));

    std::fs::remove_file(run.backup_path(2)).unwrap();
    assert_conflict(&run.undo(2), UndoConflict::BackupMissing);
    assert!(!k.exists("Two"));

    // Same size, other bytes.
    let path = run.backup_path(3);
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] = b' ';
    std::fs::write(&path, bytes).unwrap();
    assert_conflict(&run.undo(3), UndoConflict::BackupTampered);
    assert_eq!(k.get("Val", "v"), None);
}

#[test]
fn undo_into_a_parent_that_became_a_link_is_refused() {
    let mut k = TestKey::new();
    k.create("Real");
    k.create(r"Parent\Item\Sub");
    let mut run = Run::new("undo-link", vec![tree_op(k.wire(r"Parent\Item"))]);
    assert_outcome(&run.run(1), ItemOutcome::Done);
    k.remove("Parent");
    k.link("Parent", "Real");
    assert_conflict(
        &run.undo(1),
        UndoConflict::GateBlocked {
            blocker: Blocker::RegLink,
        },
    );
    assert!(!k.exists(r"Real\Item"));
}

#[test]
fn undo_after_an_intent_without_done_completes_the_tree() {
    let k = TestKey::new();
    for name in ["Partial", "Untouched"] {
        k.create(&format!(r"{name}\A\Deep"));
        k.set(&format!(r"{name}\A\Deep"), "d", REG_SZ, &utf16z("deep"));
        k.create(&format!(r"{name}\B"));
    }
    let before = k.capture("Partial");
    let mut run = Run::new(
        "resume",
        vec![tree_op(k.wire("Partial")), tree_op(k.wire("Untouched"))],
    );
    // The run stopped during op 1 after deleting part of the tree, and before op 2 acted.
    run.intent_only(1);
    k.remove(r"Partial\A");
    run.intent_only(2);

    assert_undo(&run.undo(1), UndoOutcome::Restored);
    assert_eq!(shape(&k.capture("Partial")), shape(&before));
    assert_undo(&run.undo(2), UndoOutcome::AlreadyRestored);
    assert!(k.exists(r"Untouched\A\Deep"));
}

/// Review S2 through undo: the run stopped in a tree delete, and a key that was not deleted changed
/// afterwards. Undo puts back the keys Purge deleted and leaves the changed key as it is (reported),
/// instead of refusing and leaving the tree half deleted.
#[test]
fn undo_after_an_intent_without_done_puts_back_what_is_missing_beside_a_change() {
    let k = TestKey::new();
    k.create(r"Partial\A\Deep");
    k.set(r"Partial\A\Deep", "d", REG_SZ, &utf16z("deep"));
    k.create(r"Partial\B");
    k.set(r"Partial\B", "v", REG_SZ, &utf16z("before"));
    let before = k.capture(r"Partial\A");
    let mut run = Run::new("resume-changed", vec![tree_op(k.wire("Partial"))]);
    run.intent_only(1);
    k.remove(r"Partial\A");
    k.set(r"Partial\B", "v", REG_SZ, &utf16z("theirs"));

    let undone = run.undo(1);
    assert_undo(&undone, UndoOutcome::Restored);
    let RegUndoResult::Done { detail, .. } = &undone else {
        unreachable!()
    };
    assert!(detail.contains("differs from the backup"), "{detail}");
    assert_eq!(shape(&k.capture(r"Partial\A")), shape(&before));
    assert_eq!(k.get(r"Partial\B", "v"), Some((REG_SZ, utf16z("theirs"))));
}

#[test]
fn nothing_to_undo_for_an_op_that_changed_nothing() {
    let k = TestKey::new();
    k.create("Item");
    let run = Run::new("nothing", vec![tree_op(k.wire("Item"))]);
    let RegPrepared::Ready(action) = run.prepare(1).unwrap() else {
        panic!("decided");
    };
    let intent = action.intent().clone();
    drop(action);
    for done in [
        ItemOutcome::Vanished,
        skipped(SkipReason::ChangedSinceScan),
        ItemOutcome::Failed {
            code: FailCode::AccessDenied,
            os_error: Some(5),
            detail: String::new(),
        },
    ] {
        let prepared = prepare_undo_reg(&run.ctx, &run.session, &intent, Some(&done));
        assert!(
            matches!(
                prepared,
                Some(RegUndoPrepared::Decided(RegUndoResult::Done {
                    outcome: UndoOutcome::NothingToUndo,
                    ..
                }))
            ),
            "{prepared:?}"
        );
    }
    // A failed verify may have changed the system: the inverse runs.
    let failed_verify = ItemOutcome::Failed {
        code: FailCode::VerifyFailed,
        os_error: None,
        detail: String::new(),
    };
    assert!(matches!(
        prepare_undo_reg(&run.ctx, &run.session, &intent, Some(&failed_verify)),
        Some(RegUndoPrepared::Ready(_))
    ));
    // Not a registry op.
    let mut other = intent.clone();
    other.exec_op = ExecOp::RemovePackage {
        full_name: "Vendor.App_1.0.0.0_x64__abcdefghjkmnp".into(),
    };
    assert!(prepare_undo_reg(&run.ctx, &run.session, &other, None).is_none());
    // An inverse that does not undo the op.
    let mut wrong = intent.clone();
    wrong.exec_op = tree_op(k.wire("Elsewhere"));
    assert!(matches!(
        prepare_undo_reg(&run.ctx, &run.session, &wrong, None),
        Some(RegUndoPrepared::Decided(RegUndoResult::Conflict {
            conflict: UndoConflict::BackupTampered,
            ..
        }))
    ));
    // An undo context that was not handed the op's journalled record: a conflict, nothing opened.
    let bare = GateCtx::new(DenyList::compile(&live_env()), &run.ops, no_store()).unwrap();
    assert!(matches!(
        prepare_undo_reg(&bare, &run.session, &intent, Some(&failed_verify)),
        Some(RegUndoPrepared::Decided(RegUndoResult::Conflict {
            conflict: UndoConflict::GateBlocked {
                blocker: Blocker::DenyListed { ref rule }
            },
            ..
        })) if rule == gate::reason::NOT_VALIDATED
    ));
    assert!(k.exists("Item"));
}

// ---------------------------------------------------------------------------------------------------
// Items of one run that depend on each other
// ---------------------------------------------------------------------------------------------------

/// [`shape`] with every key's values in name order: a value restored by its own undo is appended to its
/// key, so a chain undone in reverse puts the same values back in another enumeration order.
fn sorted_shape(doc: &RegBackup) -> RegTree {
    let mut tree = shape(doc);
    for key in &mut tree.keys {
        key.values.sort_by(|a, b| a.name_b64.0.cmp(&b.name_b64.0));
    }
    tree
}

/// Longer than one tick of the registry's write clock: a write after it is later than any time the gate
/// noted before it.
fn past_a_clock_tick() {
    std::thread::sleep(std::time::Duration::from_millis(50));
}

/// Case (a): `App` with two values and a subkey (with a value of its own); the run removes both values,
/// the subkey's tree, then `App` if empty.
fn emptied_app(k: &TestKey) -> Vec<ExecOp> {
    k.create(r"App\Sub");
    k.set("App", "a", REG_SZ, &utf16z("a"));
    k.set("App", "b", REG_DWORD, &[2, 0, 0, 0]);
    k.set(r"App\Sub", "s", REG_SZ, &utf16z("s"));
    vec![
        value_op(k.wire("App"), "a"),
        value_op(k.wire("App"), "b"),
        tree_op(k.wire(r"App\Sub")),
        empty_op(k.wire("App")),
    ]
}

#[track_caller]
fn undo_all_in_reverse(run: &mut Run, last: u32) {
    for n in (1..=last).rev() {
        assert_undo(&run.undo(n), UndoOutcome::Restored);
    }
}

#[test]
fn a_key_the_earlier_items_empty_is_deleted_and_undone_in_reverse_order() {
    let k = TestKey::new();
    let ops = emptied_app(&k);
    let before = k.capture("App");
    let mut run = Run::new("dep-empty", ops);
    // Not empty when the run starts, and still validated: everything in it is an earlier item. The
    // journal records its counts as they were.
    assert!((1..=4).all(|n| run.validated(n)));
    assert!(
        matches!(run.ctx.stamp(OpId(4)), Some(gate::Stamp::Key(facts)) if (facts.values, facts.subkeys) == (2, 1))
    );

    for n in 1..=4 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    assert!(!k.exists("App"));
    assert!(matches!(run.log[&4].0.inverse, Inverse::RecreateKey { .. }));

    // Undo in reverse op order: the key first (re-created empty), then what was in it.
    undo_all_in_reverse(&mut run, 4);
    assert_eq!(sorted_shape(&k.capture("App")), sorted_shape(&before));
}

#[test]
fn a_key_the_earlier_items_empty_is_still_refused_after_outside_changes() {
    // A value added by someone else: not empty at the act.
    let k = TestKey::new();
    let ops = emptied_app(&k);
    let mut run = Run::new("dep-empty-added", ops);
    for n in 1..=3 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    k.set("App", "late", REG_SZ, &utf16z("late"));
    assert_outcome(&run.run(4), skipped(SkipReason::NoLongerEmpty));
    assert_eq!(k.get("App", "late"), Some((REG_SZ, utf16z("late"))));
    drop(run);
    drop(k);

    // A subkey added by someone else before the run's own items (review M2 final: the outside change
    // made before the own ops, not only after them).
    let k = TestKey::new();
    let ops = emptied_app(&k);
    let mut run = Run::new("dep-empty-early", ops);
    k.create(r"App\Early");
    for n in 1..=3 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    assert_outcome(&run.run(4), skipped(SkipReason::NoLongerEmpty));
    assert!(k.exists(r"App\Early"));
    drop(run);
    drop(k);

    // Replaced by another empty key after the run's own items.
    let k = TestKey::new();
    let ops = emptied_app(&k);
    let mut run = Run::new("dep-empty-replaced", ops);
    for n in 1..=3 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    past_a_clock_tick();
    k.remove("App");
    k.create("App");
    assert_outcome(&run.run(4), skipped(SkipReason::ChangedSinceScan));
    assert!(k.exists("App"));
    drop(run);
    drop(k);

    // Replaced by a link.
    let mut k = TestKey::new();
    k.create("Real");
    let ops = emptied_app(&k);
    let mut run = Run::new("dep-empty-link", ops);
    for n in 1..=3 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    k.remove("App");
    k.link("App", "Real");
    assert_outcome(&run.run(4), blocked(Blocker::RegLink));
    assert!(k.is_link("App") && k.exists("Real"));
}

#[test]
fn a_key_after_its_own_value_and_segment_items_is_deleted_and_undone_in_reverse_order() {
    let k = TestKey::new();
    k.create("Env");
    k.set("Env", "Path", REG_EXPAND_SZ, &utf16z(r"C:\a;C:\b"));
    k.set("Env", "gone", REG_SZ, &utf16z("g"));
    k.set("Env", "keep", REG_DWORD, &[1, 0, 0, 0]);
    let before = k.capture("Env");
    let mut run = Run::new(
        "dep-value",
        vec![
            segment_op(k.wire("Env"), "Path", r"C:\b", None),
            value_op(k.wire("Env"), "Path"),
            value_op(k.wire("Env"), "gone"),
            tree_op(k.wire("Env")),
        ],
    );
    assert!((1..=4).all(|n| run.validated(n)));

    assert_outcome(&run.run(1), ItemOutcome::Done);
    assert_eq!(k.get("Env", "Path"), Some((REG_EXPAND_SZ, utf16z(r"C:\a"))));
    // The value the edit rewrote is deleted as the edit left it; the key after both values.
    for n in 2..=4 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    assert!(!k.exists("Env"));

    // The tree comes back with `keep`, the value as the edit left it, then the segment.
    undo_all_in_reverse(&mut run, 4);
    assert_eq!(sorted_shape(&k.capture("Env")), sorted_shape(&before));
    assert_eq!(
        k.get("Env", "Path"),
        Some((REG_EXPAND_SZ, utf16z(r"C:\a;C:\b")))
    );
}

#[test]
fn a_key_after_its_own_value_items_is_still_refused_after_outside_changes() {
    let k = TestKey::new();
    k.create("Env");
    k.set("Env", "Path", REG_EXPAND_SZ, &utf16z(r"C:\a;C:\b"));
    k.set("Env", "gone", REG_SZ, &utf16z("g"));
    let ops = vec![
        segment_op(k.wire("Env"), "Path", r"C:\b", None),
        value_op(k.wire("Env"), "Path"),
        value_op(k.wire("Env"), "gone"),
        tree_op(k.wire("Env")),
    ];
    let mut run = Run::new("dep-value-outside", ops.clone());
    assert_outcome(&run.run(1), ItemOutcome::Done);
    // Someone else rewrites the value the edit wrote: not deleted.
    k.set("Env", "Path", REG_EXPAND_SZ, &utf16z(r"C:\theirs"));
    assert_outcome(&run.run(2), skipped(SkipReason::ChangedSinceScan));
    assert_eq!(
        k.get("Env", "Path"),
        Some((REG_EXPAND_SZ, utf16z(r"C:\theirs")))
    );
    assert_outcome(&run.run(3), ItemOutcome::Done);
    // ... and adds a value: the key holds one value more than the run's items leave.
    k.set("Env", "late", REG_SZ, &utf16z("late"));
    assert_outcome(&run.run(4), skipped(SkipReason::ChangedSinceScan));
    assert!(k.exists("Env"));
    assert_eq!(k.get("Env", "late"), Some((REG_SZ, utf16z("late"))));
    drop(run);
    drop(k);

    // Someone else rewrites a value no item touches before the run's own items, keeping its size
    // (review M2 final S4: the counts balance and the last write time is the own ops' after them).
    let k = TestKey::new();
    k.create("Env");
    k.set("Env", "Path", REG_EXPAND_SZ, &utf16z(r"C:\a;C:\b"));
    k.set("Env", "gone", REG_SZ, &utf16z("g"));
    k.set("Env", "keep", REG_DWORD, &[1, 0, 0, 0]);
    let ops = vec![
        segment_op(k.wire("Env"), "Path", r"C:\b", None),
        value_op(k.wire("Env"), "Path"),
        value_op(k.wire("Env"), "gone"),
        tree_op(k.wire("Env")),
    ];
    let mut run = Run::new("dep-value-early", ops);
    k.set("Env", "keep", REG_DWORD, &[2, 0, 0, 0]);
    for n in 1..=3 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    assert_outcome(&run.run(4), skipped(SkipReason::ChangedSinceScan));
    assert_eq!(k.get("Env", "keep"), Some((REG_DWORD, vec![2, 0, 0, 0])));
    drop(run);
    drop(k);

    // Replaced by a key with the same values after the run's own items.
    let k = TestKey::new();
    k.create("Env");
    k.set("Env", "Path", REG_EXPAND_SZ, &utf16z(r"C:\a;C:\b"));
    k.set("Env", "gone", REG_SZ, &utf16z("g"));
    let ops: Vec<ExecOp> = vec![
        segment_op(k.wire("Env"), "Path", r"C:\b", None),
        value_op(k.wire("Env"), "gone"),
        tree_op(k.wire("Env")),
    ];
    let mut run = Run::new("dep-value-replaced", ops);
    for n in 1..=2 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    past_a_clock_tick();
    k.remove("Env");
    k.create("Env");
    k.set("Env", "Path", REG_EXPAND_SZ, &utf16z(r"C:\a"));
    assert_outcome(&run.run(3), skipped(SkipReason::ChangedSinceScan));
    assert_eq!(k.get("Env", "Path"), Some((REG_EXPAND_SZ, utf16z(r"C:\a"))));
}

/// Case (c): `App` holds a value and two subkeys besides the run's items.
fn tree_with_items(k: &TestKey) -> Vec<ExecOp> {
    k.create(r"App\Sub\Deep");
    k.create(r"App\Other");
    k.set("App", "a", REG_SZ, &utf16z("a"));
    k.set("App", "keep", REG_DWORD, &[1, 0, 0, 0]);
    k.set(r"App\Sub", "s", REG_SZ, &utf16z("s"));
    vec![
        tree_op(k.wire(r"App\Sub")),
        value_op(k.wire("App"), "a"),
        tree_op(k.wire("App")),
    ]
}

#[test]
fn a_tree_after_items_inside_it_is_deleted_and_undone_in_reverse_order() {
    let k = TestKey::new();
    let ops = tree_with_items(&k);
    let before = k.capture("App");
    let mut run = Run::new("dep-tree", ops);
    assert!((1..=3).all(|n| run.validated(n)));
    for n in 1..=3 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    assert!(!k.exists("App"));
    // The tree's backup holds the key as it was at its own act: without the run's earlier items.
    let (intent, _) = run.log[&3].clone();
    let doc = regbackup::read_verified(&run.session, intent.inverse.backup().unwrap()).unwrap();
    let keys = &doc.doc().tree().unwrap().keys;
    assert_eq!(keys.len(), 2, "App and App\\Other");
    assert_eq!(keys[0].values.len(), 1, "only keep");

    undo_all_in_reverse(&mut run, 3);
    assert_eq!(sorted_shape(&k.capture("App")), sorted_shape(&before));
}

#[test]
fn a_tree_after_items_inside_it_is_still_refused_after_outside_changes() {
    // A subkey added by someone else.
    let k = TestKey::new();
    let ops = tree_with_items(&k);
    let mut run = Run::new("dep-tree-added", ops);
    for n in 1..=2 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    k.create(r"App\Late");
    assert_outcome(&run.run(3), skipped(SkipReason::ChangedSinceScan));
    assert!(k.exists(r"App\Late") && k.exists(r"App\Other"));
    drop(run);
    drop(k);

    // Before the run's own items, someone else rewrites a value of the key (same size) or adds one to a
    // subkey no item touches (review M2 final S4, S5).
    type Change = fn(&TestKey);
    let early: [Change; 2] = [
        |k| k.set("App", "keep", REG_DWORD, &[2, 0, 0, 0]),
        |k| k.set(r"App\Other", "late", REG_SZ, &utf16z("late")),
    ];
    for change in early {
        let k = TestKey::new();
        let ops = tree_with_items(&k);
        let mut run = Run::new("dep-tree-early", ops);
        change(&k);
        let after = k.capture("App");
        for n in 1..=2 {
            assert_outcome(&run.run(n), ItemOutcome::Done);
        }
        assert_outcome(&run.run(3), skipped(SkipReason::ChangedSinceScan));
        assert!(k.exists(r"App\Other"));
        assert_eq!(
            k.get("App", "keep"),
            after
                .tree()
                .and_then(|t| t.keys[0]
                    .values
                    .iter()
                    .find(|v| v.name_b64 == WideB64::from("keep")))
                .map(|v| (v.value_type, v.data_b64.0.clone()))
        );
    }

    // Replaced by a link.
    let mut k = TestKey::new();
    k.create(r"Real\Kept");
    let ops = tree_with_items(&k);
    let mut run = Run::new("dep-tree-link", ops);
    for n in 1..=2 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    k.remove("App");
    k.link("App", "Real");
    assert_outcome(&run.run(3), blocked(Blocker::RegLink));
    assert!(k.is_link("App") && k.exists(r"Real\Kept"));
}

/// Review M2 final S4: a change by someone else made between the validation and the run's own op on the
/// same key (here a value rewritten to data of the same size, so the counts still balance) was taken for
/// the run's own and the key deleted. The tree is now bound to its validated digest with exactly what
/// the own ops changed put back: refused, also with a context rebuilt from the journal, and the key and
/// the changed value are left as they are.
#[test]
fn a_change_by_someone_else_before_an_own_op_on_the_key_is_refused() {
    for rebuilt in [false, true] {
        let k = TestKey::new();
        k.create("App");
        k.set("App", "a", REG_SZ, &utf16z("a"));
        k.set("App", "keep", REG_DWORD, &[1, 0, 0, 0]);
        let ops = vec![value_op(k.wire("App"), "a"), tree_op(k.wire("App"))];
        let mut run = Run::new("own-before", ops);
        assert!(run.validated(1) && run.validated(2));
        k.set("App", "keep", REG_DWORD, &[2, 0, 0, 0]);
        assert_outcome(&run.run(1), ItemOutcome::Done);
        if rebuilt {
            run.reopen_ctx();
        }
        assert_outcome(&run.run(2), skipped(SkipReason::ChangedSinceScan));
        assert_eq!(k.get("App", "keep"), Some((REG_DWORD, vec![2, 0, 0, 0])));
        assert!(!run.backup_path(2).exists(), "no backup, no intent");
    }

    // Without the change the same chain is deleted.
    let k = TestKey::new();
    k.create("App");
    k.set("App", "a", REG_SZ, &utf16z("a"));
    k.set("App", "keep", REG_DWORD, &[1, 0, 0, 0]);
    let mut run = Run::new(
        "own-before-none",
        vec![value_op(k.wire("App"), "a"), tree_op(k.wire("App"))],
    );
    for n in 1..=2 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    assert!(!k.exists("App"));
}

/// Review M2 final S5: a tree delete was bound to the facts of its root key only; a change anywhere
/// below it after the validation was backed up and deleted with it. Each change below is refused now,
/// with the tree left whole.
#[test]
fn a_change_below_the_root_after_validation_is_refused() {
    type Change = fn(&TestKey);
    // Below the root key's own level: none of these moves the root's counts or last write time.
    let changes: [(&str, Change); 4] = [
        ("a value below rewritten (same size)", |k| {
            k.set(r"App\Sub\Deep", "d", REG_SZ, &utf16z("e"));
        }),
        ("a value added below", |k| {
            k.set(r"App\Sub\Deep", "late", REG_SZ, &utf16z("late"));
        }),
        ("a key created below the deepest key", |k| {
            k.create(r"App\Sub\Deep\Leaf\Deeper");
        }),
        ("a key two levels down removed", |k| {
            k.remove(r"App\Sub\Deep\Leaf");
        }),
    ];
    for (what, change) in changes {
        let k = TestKey::new();
        k.create(r"App\Sub\Deep\Leaf");
        k.set(r"App\Sub", "s", REG_SZ, &utf16z("s"));
        k.set(r"App\Sub\Deep", "d", REG_SZ, &utf16z("d"));
        let mut run = Run::new("below", vec![tree_op(k.wire(r"App\Sub"))]);
        assert!(run.validated(1));
        change(&k);
        let after = k.capture("App");
        let result = run.run(1);
        assert_outcome(&result, skipped(SkipReason::ChangedSinceScan));
        assert!(
            result.detail.contains(gate::reason::TREE_CHANGED),
            "{what}: {result:?}"
        );
        assert_eq!(shape(&k.capture("App")), shape(&after), "{what}");
        assert!(!run.backup_path(1).exists(), "{what}");
    }
}

/// Review M2 final S6: a key spelled with a trailing backslash validated, was deleted, and its backup was
/// then refused by undo (the writer and the reader took the leaf in two ways). Such a spelling (and a
/// doubled backslash) is refused at validation and at the act, and the key stays.
#[test]
fn a_key_spelled_with_an_empty_segment_is_refused_and_never_deleted() {
    let k = TestKey::new();
    k.create(r"Item\Sub");
    k.create(r"Other\Sub");
    let spelled = [
        tree_op(format!(r"{}\", k.wire("Item"))),
        tree_op(k.wire("Other").replace(r"\Other", r"\\Other")),
    ];
    let mut run = Run::new("spelling", spelled.to_vec());
    for n in 1..=2 {
        assert!(!run.validated(n), "op {n}");
        // Had a record been journalled, the act refuses it too.
        run.forge_key_record(n);
        assert_outcome(
            &run.run(n),
            blocked(Blocker::DenyListed {
                rule: purge_guard::live::EMPTY_SEGMENT_RULE.into(),
            }),
        );
        assert!(!run.backup_path(n).exists());
    }
    assert!(k.exists(r"Item\Sub") && k.exists(r"Other\Sub"));
}

/// Review M2 final S6 and M11: before the backup is written, and again on the file as read back, the
/// document must be the backup of this op as the gate opened it: the op's key text leading to the
/// gate's address, a tree rooted at the address's leaf, a value equal to the one the gate read on the
/// acting handle (the value is no longer read a second time for its backup).
#[test]
fn a_backup_that_is_not_the_ops_backup_is_refused() {
    let k = TestKey::new();
    k.create("Item");
    k.create("Other");
    k.set("Item", "v", REG_DWORD, &[1, 0, 0, 0]);
    let tree = tree_op(k.wire("Item"));
    let value = value_op(k.wire("Item"), "v");
    let run = Run::new("not-ops", vec![tree.clone(), value.clone()]);

    let tree_key = gate::open_and_check_key(&run.ctx, OpId(1)).pass().unwrap();
    let doc = regbackup::capture_tree(tree_key.key(), &k.wire("Item"), 10).unwrap();
    assert_eq!(backup_for_op(&run.ctx, &doc, &tree, &tree_key), Ok(()));
    // Another key's text.
    let other = RegBackup {
        key: k.wire("Other"),
        ..doc.clone()
    };
    assert!(backup_for_op(&run.ctx, &other, &tree, &tree_key).is_err());
    // The op's text, a tree rooted at another name.
    let mut renamed = doc.clone();
    if let RegBackupBody::Tree(tree) = &mut renamed.body {
        tree.keys[0].name_b64 = WideB64::from("Other");
    }
    assert!(backup_for_op(&run.ctx, &renamed, &tree, &tree_key).is_err());
    drop(tree_key);

    let value_key = gate::open_and_check_key(&run.ctx, OpId(2)).pass().unwrap();
    let read = value_key.value().unwrap().clone();
    let doc = regbackup::value_backup(&k.wire("Item"), read.clone()).unwrap();
    assert_eq!(backup_for_op(&run.ctx, &doc, &value, &value_key), Ok(()));
    let changed = regbackup::value_backup(
        &k.wire("Item"),
        purge_win::reg::RegValue {
            data: vec![2, 0, 0, 0],
            ..read
        },
    )
    .unwrap();
    assert!(backup_for_op(&run.ctx, &changed, &value, &value_key).is_err());
}

/// A run stopped in the middle of a chain continues with a context rebuilt from the journal alone: the
/// effects of the completed ops come from their journalled intents and `done` records.
#[test]
fn a_chain_continues_with_a_context_rebuilt_from_the_journal() {
    let k = TestKey::new();
    let ops = emptied_app(&k);
    let before = k.capture("App");
    let mut run = Run::new("dep-resume", ops);
    for n in 1..=3 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    run.reopen_ctx();
    assert_outcome(&run.run(4), ItemOutcome::Done);
    assert!(!k.exists("App"));
    undo_all_in_reverse(&mut run, 4);
    assert_eq!(sorted_shape(&k.capture("App")), sorted_shape(&before));
    drop(run);
    drop(k);

    // Rebuilt between two items of the chain, then changed by someone else: refused as before.
    let k = TestKey::new();
    let ops = tree_with_items(&k);
    let mut run = Run::new("dep-resume-changed", ops);
    assert_outcome(&run.run(1), ItemOutcome::Done);
    run.reopen_ctx();
    assert_outcome(&run.run(2), ItemOutcome::Done);
    run.reopen_ctx();
    k.set("App", "late", REG_SZ, &utf16z("late"));
    assert_outcome(&run.run(3), skipped(SkipReason::ChangedSinceScan));
    assert!(k.exists("App"));
}

/// Item 2: a restore whose key (or parent key) is still gone is `ParentMissing`, changes nothing, and
/// succeeds once the op that removed that key is undone.
#[test]
fn undo_into_a_key_that_is_still_gone_is_parent_missing_until_its_own_undo() {
    let k = TestKey::new();
    let ops = emptied_app(&k);
    let before = k.capture("App");
    let mut run = Run::new("dep-undo-order", ops);
    for n in 1..=4 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    // Forward order: a value and a subkey of a key that is not back yet.
    assert_conflict(&run.undo(1), UndoConflict::ParentMissing);
    assert_conflict(&run.undo(3), UndoConflict::ParentMissing);
    assert!(!k.exists("App"));
    // The key's own undo, then the others again.
    assert_undo(&run.undo(4), UndoOutcome::Restored);
    for n in [3, 1, 2] {
        assert_undo(&run.undo(n), UndoOutcome::Restored);
    }
    assert_eq!(sorted_shape(&k.capture("App")), sorted_shape(&before));
}

/// Item 2: the key a restore goes into (the parent of a key, the key of a value) deleted after the undo
/// gate opened it, before anything was created.
#[test]
fn a_key_deleted_after_the_undo_gate_is_parent_missing() {
    let k = TestKey::new();
    k.create(r"Parent\Item\Sub");
    k.create("Holder");
    k.set("Holder", "v", REG_SZ, &utf16z("v"));
    let mut run = Run::new(
        "undo-gone",
        vec![
            tree_op(k.wire(r"Parent\Item")),
            value_op(k.wire("Holder"), "v"),
        ],
    );
    for n in 1..=2 {
        assert_outcome(&run.run(n), ItemOutcome::Done);
    }
    let result = run.undo_with(1, || k.remove("Parent"));
    assert_conflict(&result, UndoConflict::ParentMissing);
    assert!(!k.exists("Parent"));
    let result = run.undo_with(2, || k.remove("Holder"));
    assert_conflict(&result, UndoConflict::ParentMissing);
    assert!(!k.exists("Holder"));
}

// ---------------------------------------------------------------------------------------------------
// Tokens and backup files
// ---------------------------------------------------------------------------------------------------

#[test]
fn a_token_of_another_op_acts_on_nothing() {
    let k = TestKey::new();
    k.create("One");
    k.create("Two");
    let mut run = Run::new(
        "token",
        vec![tree_op(k.wire("One")), tree_op(k.wire("Two"))],
    );
    let RegPrepared::Ready(one) = run.prepare(1).unwrap() else {
        panic!("decided");
    };
    let RegPrepared::Ready(two) = run.prepare(2).unwrap() else {
        panic!("decided");
    };
    let token = run.journal.intent(one.intent().clone()).unwrap();
    let result = act_reg(two, &token);
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
    assert!(k.exists("Two"));
    let result = act_reg(one, &token);
    assert_outcome(&result, ItemOutcome::Done);
    run.journal.done(token, result.outcome).unwrap();
    assert!(!k.exists("One"));
}

/// The store file id of the op's registry backup.
fn backup_file_id(session: &SessionDir, op: u32) -> purge_win::fs::FileId {
    session
        .open_file(&backup_rel(BackupKind::Registry, OpId(op)))
        .unwrap()
        .file_id()
}

/// Changed in meaning (M2 recovery fix pass): a backup file of an op that has no intent can only be
/// one a crash left between the backup and the intent. One that does not verify is deleted through
/// the store (`SessionDir::delete_backup_file`) and the backup written anew; the item is acted on only
/// after its own verified backup. Before the pass the op was skipped (`NoVerifiedBackup`) for good.
#[test]
fn a_backup_file_a_crash_left_that_does_not_verify_is_written_anew() {
    let k = TestKey::new();
    k.create("Item");
    let run = Run::new("existing", vec![tree_op(k.wire("Item"))]);
    let rel = backup_rel(BackupKind::Registry, OpId(1));
    let mut file = run.session.create_file(&rel).unwrap();
    let path = file.report_path();
    std::io::Write::write_all(&mut file, b"left by a crash").unwrap();
    drop(file);

    let RegPrepared::Ready(action) = run.prepare(1).unwrap() else {
        panic!("decided");
    };
    assert_ne!(std::fs::read(&path).unwrap(), b"left by a crash");
    let reference = action.intent().inverse.backup().unwrap().clone();
    assert_eq!(reference.path, rel);
    let backup = regbackup::read_verified(&run.session, &reference).unwrap();
    backup.doc().validate_for(&tree_op(k.wire("Item"))).unwrap();
    assert!(k.exists("Item"));
}

/// A backup a crash left that verifies and equals a fresh capture of the key is adopted: the file is
/// not written again (same store file id) and the intent names it.
#[test]
fn a_backup_file_a_crash_left_that_matches_is_adopted() {
    let k = TestKey::new();
    k.create("Item");
    k.set("Item", "v", REG_DWORD, &1u32.to_le_bytes());
    let run = Run::new("adopt", vec![tree_op(k.wire("Item"))]);
    let RegPrepared::Ready(first) = run.prepare(1).unwrap() else {
        panic!("decided");
    };
    let first_ref = first.intent().inverse.backup().unwrap().clone();
    // The crash: the backup is written, the intent never was.
    drop(first);
    let id = backup_file_id(&run.session, 1);
    // A later capture carries a later time; the adopted file keeps its own.
    std::thread::sleep(std::time::Duration::from_millis(30));

    let RegPrepared::Ready(second) = run.prepare(1).unwrap() else {
        panic!("decided");
    };
    assert_eq!(second.intent().inverse.backup(), Some(&first_ref));
    let again = backup_file_id(&run.session, 1);
    assert_eq!((again.volume_serial, again.id), (id.volume_serial, id.id));

    // A leftover that verifies but is not a capture of this key (here: another key's backup) is
    // deleted through the store and written anew, never adopted.
    drop(second);
    k.create("Other");
    k.set("Other", "w", REG_DWORD, &2u32.to_le_bytes());
    let other = Run::new("adopt-other", vec![tree_op(k.wire("Other"))]);
    let RegPrepared::Ready(foreign) = other.prepare(1).unwrap() else {
        panic!("decided");
    };
    let foreign_ref = foreign.intent().inverse.backup().unwrap().clone();
    let rel = backup_rel(BackupKind::Registry, OpId(1));
    let mut file = other.session.open_file(&rel).unwrap();
    let foreign_bytes = file.read_all(1 << 20).unwrap();
    drop(file);
    run.session.delete_backup_file(&rel).unwrap();
    let mut file = run.session.create_file(&rel).unwrap();
    std::io::Write::write_all(&mut file, &foreign_bytes).unwrap();
    drop(file);
    let leftover = backup_file_id(&run.session, 1);

    let RegPrepared::Ready(third) = run.prepare(1).unwrap() else {
        panic!("decided");
    };
    let third_ref = third.intent().inverse.backup().unwrap().clone();
    assert_ne!(third_ref.sha256, foreign_ref.sha256);
    let now = backup_file_id(&run.session, 1);
    assert_ne!(now.id, leftover.id);
    let backup = regbackup::read_verified(&run.session, &third_ref).unwrap();
    backup.doc().validate_for(&tree_op(k.wire("Item"))).unwrap();
}

/// Changed in meaning: the op reaches `prepare_reg` only through its journalled record. Without one it
/// is an internal failure; with a (forged) record of a package it is one too, as not a registry op.
#[test]
fn a_non_registry_op_is_an_internal_failure() {
    let package = ExecOp::RemovePackage {
        full_name: "Vendor.App_1.0.0.0_x64__abcdefghjkmnp".into(),
    };
    let mut run = Run::new("not-reg", vec![package.clone()]);
    let internal = |run: &Run| {
        let RegPrepared::Decided(result) = run.prepare(1).unwrap() else {
            panic!("not decided");
        };
        matches!(
            result.outcome,
            ItemOutcome::Failed {
                code: FailCode::Internal,
                ..
            }
        )
    };
    assert!(internal(&run), "an op without a journalled record");
    let forged = Validated {
        op: OpId(1),
        item: cid(1),
        target: package.target(),
        facts: ItemFacts::Package,
        exemptions: gate::exemptions_to_journal(&Exemptions::default()),
    };
    run.ctx.record(&package, &forged, 5_000).unwrap();
    assert!(internal(&run), "a package op");
}

// ---------------------------------------------------------------------------------------------------
// Smoke run M2
// ---------------------------------------------------------------------------------------------------

/// Smoke run M2: a delete-if-empty key that held a foreign value already when it was validated was
/// reported `Skipped{ChangedSinceScan}`. It did not change, it is not empty: `Skipped{NoLongerEmpty}`,
/// also for an item the validate pass refused (the executor reports it through [`gate_result`]).
#[test]
fn a_key_not_empty_at_validation_is_no_longer_empty_not_changed() {
    let empty = ExecOp::DeleteKeyIfEmpty {
        key: r"HKLM\SOFTWARE\Vendor\NotEmptyKey".into(),
    };
    let tree = ExecOp::DeleteKeyTree {
        key: r"HKLM\SOFTWARE\Vendor\NotEmptyKey".into(),
    };
    let not_empty = GateOutcome::<()>::Refused(purge_guard::live::Refusal {
        blocker: Blocker::ChangedSinceScan,
        reason: purge_guard::live::reason::NOT_EMPTY,
    });
    let changed = GateOutcome::<()>::Refused(purge_guard::live::Refusal {
        blocker: Blocker::ChangedSinceScan,
        reason: gate::reason::KEY_CHANGED,
    });
    let link = GateOutcome::<()>::Refused(purge_guard::live::Refusal {
        blocker: Blocker::RegLink,
        reason: purge_guard::live::reason::KEY_IS_LINK,
    });
    let reason = |outcome: &GateOutcome<()>, op: &ExecOp| {
        gate_result(outcome, op).map(|result| result.outcome)
    };
    let skipped = |reason| Some(ItemOutcome::Skipped { reason });
    assert_eq!(
        reason(&not_empty, &empty),
        skipped(SkipReason::NoLongerEmpty)
    );
    assert_eq!(
        reason(&changed, &empty),
        skipped(SkipReason::ChangedSinceScan)
    );
    assert_eq!(
        reason(&not_empty, &tree),
        skipped(SkipReason::ChangedSinceScan)
    );
    assert_eq!(
        reason(&link, &empty),
        skipped(SkipReason::GateBlocked {
            blocker: Blocker::RegLink
        })
    );
    assert_eq!(
        reason(&GateOutcome::<()>::Vanished, &empty),
        Some(ItemOutcome::Vanished)
    );
    assert_eq!(reason(&GateOutcome::Pass(()), &empty), None);
    assert!(matches!(
        reason(
            &GateOutcome::<()>::Failed(Win32Error::ACCESS_DENIED),
            &empty
        ),
        Some(ItemOutcome::Failed {
            code: FailCode::AccessDenied,
            ..
        })
    ));
}

/// Smoke run M2: a restored key whose owner or DACL reads back other than recorded is not accepted as
/// `Restored`: the undo says the verify failed and why. Differences of an existing key that was merged
/// into keep the outcome.
#[test]
fn a_restore_that_could_not_put_security_back_is_not_restored() {
    let report = |kind: DifferenceKind| RestoreReport {
        outcome: RestoreOutcome::Restored,
        keys_created: 2,
        differences: vec![Difference {
            at: "Sub1".into(),
            kind,
        }],
    };
    let owner = restore_result(
        Ok(report(DifferenceKind::OwnerNotRestored {
            recorded_owner: "SY".into(),
        })),
        "HKLM\\SOFTWARE\\Vendor",
    );
    match owner {
        RegUndoResult::Done {
            outcome:
                UndoOutcome::Failed {
                    code: FailCode::VerifyFailed,
                    ..
                },
            detail,
        } => assert!(detail.contains("Sub1: owner SY not restored"), "{detail}"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        restore_result(Ok(report(DifferenceKind::SecurityDiffers)), "k"),
        RegUndoResult::Done {
            outcome: UndoOutcome::Failed {
                code: FailCode::VerifyFailed,
                ..
            },
            ..
        }
    ));
    assert!(matches!(
        restore_result(Ok(report(DifferenceKind::RootSecurityKept)), "k"),
        RegUndoResult::Done {
            outcome: UndoOutcome::Restored,
            ..
        }
    ));

    // The put-back of a stopped delete that lost security is a change, not a skip.
    let stopped = DeleteError {
        at: String::new(),
        failure: DeleteFailure::Changed(Change::ValuesDiffer),
        rollback: Rollback::Done {
            keys: 1,
            differences: vec![Difference {
                at: "Sub1".into(),
                kind: DifferenceKind::SecurityDiffers,
            }],
        },
    };
    assert!(matches!(
        delete_stopped(&stopped, "k", false).outcome,
        ItemOutcome::Failed {
            code: FailCode::VerifyFailed,
            ..
        }
    ));
    let clean = DeleteError {
        rollback: Rollback::Done {
            keys: 1,
            differences: Vec::new(),
        },
        ..stopped
    };
    assert_eq!(
        delete_stopped(&clean, "k", false).outcome,
        ItemOutcome::Skipped {
            reason: SkipReason::ChangedSinceScan
        }
    );
}

/// F3 of the M2 fix-round review: recovery's resumed key delete that stopped and put keys back with
/// another owner or DACL ends `Failed{VerifyFailed}`, as an ordinary run's does, whether the rollback or
/// the put-back of the keys an interrupted run had deleted lost it. Before the fix it ended `Skipped`,
/// which undo reads as nothing to undo.
#[test]
fn a_resumed_delete_whose_put_back_lost_security_is_not_a_skip() {
    let lost = |kind| {
        vec![Difference {
            at: "Sub1".into(),
            kind,
        }]
    };
    let stopped = |rollback| DeleteError {
        at: String::new(),
        failure: DeleteFailure::Changed(Change::ValuesDiffer),
        rollback,
    };
    let verify_failed = |result: RegResult| {
        matches!(
            result.outcome,
            ItemOutcome::Failed {
                code: FailCode::VerifyFailed,
                ..
            }
        )
    };

    // The rollback alone made the key whole, with a key whose owner could not be assigned.
    let rolled_back = stopped(Rollback::Done {
        keys: 1,
        differences: lost(DifferenceKind::OwnerNotRestored {
            recorded_owner: "SY".into(),
        }),
    });
    let result = completion_stopped(&rolled_back, None);
    assert!(
        result.detail.contains("Sub1: owner SY not restored"),
        "{result:?}"
    );
    assert!(verify_failed(result));

    // The keys an interrupted run had deleted came back with other security.
    let partial = stopped(Rollback::PartialBefore {
        missing: 2,
        keys: 1,
        differences: Vec::new(),
    });
    let put_back = RestoreReport {
        outcome: RestoreOutcome::Restored,
        keys_created: 2,
        differences: lost(DifferenceKind::SecurityDiffers),
    };
    assert!(verify_failed(completion_stopped(
        &partial,
        Some(Ok(put_back))
    )));

    // Whole and exact: the change stopped the delete, a skip as before.
    let exact = RestoreReport {
        outcome: RestoreOutcome::Restored,
        keys_created: 2,
        differences: lost(DifferenceKind::RootSecurityKept),
    };
    assert_eq!(
        completion_stopped(&partial, Some(Ok(exact))).outcome,
        ItemOutcome::Skipped {
            reason: SkipReason::ChangedSinceScan
        }
    );
    // Not whole: as before.
    assert!(verify_failed(completion_stopped(
        &partial,
        Some(Err(RestoreError::Conflict(
            regbackup::RestoreConflict::Link
        )))
    )));
}
